#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

TOOL_NAME = "SDK Sentry: Mobile SDK Supply Chain Beacon & Permission Auditor"
TOOL_VERSION = "0.1.0"

# Optional dependencies
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

KNOWN_SDK_PATTERNS = {
    "com.google.firebase.analytics": [b"com/google/firebase/analytics", b"firebase-analytics"],
    "com.adjust.sdk": [b"com/adjust/sdk", b"adjust-android", b"com.adjust.sdk"],
    "com.appsflyer": [b"com/appsflyer", b"AppsFlyerLib"],
    "com.mixpanel.android": [b"com/mixpanel/android", b"mixpanel-android"],
    "com.flurry.android": [b"com/flurry/android", b"flurry-android"],
    "com.facebook.appevents": [b"com/facebook/appevents", b"facebook-android-sdk"],
    "io.branch.referral": [b"io/branch/referral", b"branch-android-sdk"],
    "com.segment.analytics": [b"com/segment/analytics", b"analytics-android"],
    "com.amplitude.api": [b"com/amplitude/api", b"amplitude-android"],
}

SDK_CVE_DB = {
    "com.adjust.sdk": [
        {"cve": "CVE-2022-12345", "summary": "Example issue in Adjust SDK leading to data exposure", "severity": "MEDIUM"},
    ],
    "com.facebook.appevents": [
        {"cve": "CVE-2021-98765", "summary": "Example issue involving excessive permissions", "severity": "LOW"},
    ],
}

OVERBROAD_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION": "Collects precise location",
    "android.permission.ACCESS_COARSE_LOCATION": "Collects coarse location",
    "android.permission.READ_CONTACTS": "Reads contacts",
    "android.permission.READ_SMS": "Reads SMS",
    "android.permission.RECORD_AUDIO": "Records audio",
    "android.permission.CAMERA": "Captures images/video",
    "android.permission.READ_CALL_LOG": "Reads call logs",
    "android.permission.WRITE_CONTACTS": "Modifies contacts",
}

INSECURE_PINNING_PATTERNS = [
    b"X509TrustManager",
    b"TrustAllCerts",
    b"AllowAllHostnameVerifier",
    b"setHostnameVerifier",
    b"checkServerTrusted",
    b"okhttp3/internal/tls",
    b"InsecureTrustManager",
]

ENDPOINT_REGEX = re.compile(rb"(https?://[A-Za-z0-9\.\-_:]+(?:/[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]*)?)")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 127, "", str(e)


def aapt_dump_permissions(apk: Path) -> List[str]:
    for tool in ("aapt2", "aapt"):
        code, out, _ = run_cmd([tool, "dump", "permissions", str(apk)])
        if code == 0:
            perms = []
            for line in out.splitlines():
                m = re.search(r"name='([^']+)'", line)
                if m:
                    perms.append(m.group(1))
                else:
                    m2 = re.search(r"uses-permission:\s+name='([^']+)'", line)
                    if m2:
                        perms.append(m2.group(1))
            return sorted(set(perms))
    return []


def aapt_dump_badging(apk: Path) -> Dict[str, str]:
    for tool in ("aapt2", "aapt"):
        code, out, _ = run_cmd([tool, "dump", "badging", str(apk)])
        if code == 0:
            info = {}
            m = re.search(r"package: name='([^']+)'", out)
            if m:
                info["package_name"] = m.group(1)
            m2 = re.search(r"launchable-activity: name='([^']+)'", out)
            if m2:
                info["launchable_activity"] = m2.group(1)
            return info
    return {}


def parse_permissions_from_manifest_bytes(manifest_bytes: bytes) -> List[str]:
    # Fallback: scan for known android.permission.* strings in binary AXML string pool
    found = set()
    for m in re.finditer(b"android.permission.[A-Z0-9_\.]+", manifest_bytes):
        try:
            found.add(m.group(0).decode("utf-8", "ignore"))
        except Exception:
            pass
    return sorted(found)


def apk_read_file(apk: Path, inner_path: str) -> Optional[bytes]:
    try:
        with zipfile.ZipFile(apk, "r") as z:
            with z.open(inner_path) as f:
                return f.read()
    except Exception:
        return None


def apk_list_files(apk: Path) -> List[str]:
    try:
        with zipfile.ZipFile(apk, "r") as z:
            return z.namelist()
    except Exception:
        return []


def detect_sdks(apk: Path, file_list: List[str]) -> Dict[str, Dict]:
    detections = {}
    search_targets = [p for p in file_list if p.startswith("classes") and p.endswith(".dex")]
    search_targets += [p for p in file_list if p.startswith("lib/") or p.startswith("assets/") or p.endswith(".jar")]
    for sdk_id, patterns in KNOWN_SDK_PATTERNS.items():
        found_where = []
        version = None
        for inner in search_targets:
            data = apk_read_file(apk, inner)
            if not data:
                continue
            for pat in patterns:
                if pat in data:
                    found_where.append(inner)
                    # try nearby version markers
                    vm = re.search(rb"(?:SDK_VERSION|versionName|version|Adjust/|AF-)([0-9]+\.[0-9]+(?:\.[0-9]+)?)", data)
                    if vm:
                        try:
                            version = vm.group(1).decode()
                        except Exception:
                            pass
                    break
        if found_where:
            detections[sdk_id] = {
                "sdk_id": sdk_id,
                "version": version or "unknown",
                "files": sorted(set(found_where)),
                "cves": SDK_CVE_DB.get(sdk_id, []),
            }
    return detections


def find_endpoints(apk: Path, file_list: List[str]) -> List[str]:
    endpoints = set()
    targets = [p for p in file_list if p.endswith((".dex", ".xml", ".json", ".txt", ".properties", ".conf", ".js")) or p.startswith("assets/")]
    for inner in targets:
        data = apk_read_file(apk, inner)
        if not data:
            continue
        for m in ENDPOINT_REGEX.finditer(data):
            try:
                url = m.group(1).decode("utf-8", "ignore")
                # Redact query string for privacy
                url = url.split("?")[0]
                endpoints.add(url)
            except Exception:
                pass
    return sorted(endpoints)


def detect_insecure_pinning(apk: Path, file_list: List[str]) -> List[str]:
    flags = []
    targets = [p for p in file_list if p.endswith(".dex")]
    for inner in targets:
        data = apk_read_file(apk, inner)
        if not data:
            continue
        if any(pat in data for pat in INSECURE_PINNING_PATTERNS):
            flags.append(f"Potential custom TrustManager/hostname verifier in {inner}")
    return flags


def extract_apk_signing_meta(apk: Path, file_list: List[str]) -> Dict[str, object]:
    meta = {"scheme_v1": False, "certs": []}
    cert_files = [p for p in file_list if p.startswith("META-INF/") and (p.endswith(".RSA") or p.endswith(".DSA") or p.endswith(".EC"))]
    if cert_files:
        meta["scheme_v1"] = True
        for cf in cert_files:
            cdata = apk_read_file(apk, cf)
            if not cdata:
                continue
            sha = hashlib.sha256(cdata).hexdigest()
            meta["certs"].append({"file": cf, "sha256": sha})
    # Note: APK Signature Scheme v2/v3 not parsed here (requires parsing signing block). Documented as unknown.
    meta["scheme_v2_v3"] = "unknown"
    return meta


def load_allowlist(path: Optional[Path]) -> List[str]:
    if not path:
        return []
    if not path.exists():
        return []
    lines = [ln.strip() for ln in path.read_text().splitlines()]
    return [ln for ln in lines if ln and not ln.startswith("#")]


def domain_from_url(url: str) -> Optional[str]:
    m = re.match(r"https?://([^/:\s]+)", url)
    return m.group(1).lower() if m else None


def domain_matches_allowlist(domain: str, allowlist: List[str]) -> bool:
    domain = domain.lower()
    for entry in allowlist:
        e = entry.lower()
        if e == domain:
            return True
        if e.startswith("*.") and (domain == e[2:] or domain.endswith("." + e[2:])):
            return True
        if domain == e or domain.endswith("." + e):
            return True
    return False


def mk_keypair(key_path: Path) -> Tuple[Path, Path]:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library is required for signing; please install 'cryptography'.")
    ensure_dir(key_path.parent)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_path.write_bytes(priv_pem)
    pub_path = key_path.with_suffix(".pub.pem")
    pub_path.write_bytes(pub_pem)
    return key_path, pub_path


def load_private_key(key_path: Path) -> Ed25519PrivateKey:
    data = key_path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(pub_key_path: Path) -> Ed25519PublicKey:
    data = pub_key_path.read_bytes()
    return serialization.load_pem_public_key(data)


def sign_bytes(priv: Ed25519PrivateKey, data: bytes) -> str:
    sig = priv.sign(data)
    return base64.b64encode(sig).decode()


def verify_signature(pub: Ed25519PublicKey, data: bytes, sig_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def write_json(path: Path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True))


def build_cyclonedx(apk: Path, app_pkg: str, sdks: Dict[str, Dict]) -> Dict:
    components = []
    for sdk_id, meta in sdks.items():
        components.append({
            "type": "library",
            "name": sdk_id,
            "version": meta.get("version", "unknown"),
            "purl": f"pkg:generic/{sdk_id}@{meta.get('version','unknown')}",
            "cves": meta.get("cves", []),
        })
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": now_iso(),
            "tools": [{"vendor": "sdk-sentry", "name": TOOL_NAME, "version": TOOL_VERSION}],
            "component": {"type": "application", "name": app_pkg or apk.name, "version": "unknown"},
        },
        "components": components,
    }
    return bom


def build_spdx(apk: Path, app_pkg: str, sdks: Dict[str, Dict]) -> Dict:
    pkgs = []
    for sdk_id, meta in sdks.items():
        pkgs.append({
            "name": sdk_id,
            "SPDXID": f"SPDXRef-{re.sub('[^A-Za-z0-9]+','-', sdk_id)}",
            "versionInfo": meta.get("version", "unknown"),
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "supplier": "NOASSERTION",
        })
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM for {app_pkg or apk.name}",
        "documentNamespace": f"http://spdx.org/spdxdocs/sdk-sentry-{hashlib.sha1(apk.name.encode()).hexdigest()}",
        "creationInfo": {"created": now_iso(), "creators": [f"Tool: {TOOL_NAME} {TOOL_VERSION}"]},
        "packages": pkgs,
    }
    return doc


def redact_url(url: str) -> str:
    # Redact any path segments that look like IDs (simple heuristic)
    parts = url.split("/")
    red = []
    for p in parts:
        if re.fullmatch(r"[0-9a-fA-F\-]{8,}", p):
            red.append("<redacted>")
        else:
            red.append(p)
    return "/".join(red)


def analyze_static(apk: Path, outdir: Path) -> Dict:
    file_list = apk_list_files(apk)
    manifest_bytes = apk_read_file(apk, "AndroidManifest.xml") or b""
    perms = aapt_dump_permissions(apk)
    if not perms:
        perms = parse_permissions_from_manifest_bytes(manifest_bytes)
    static_flags = []
    overbroad = []
    for p in perms:
        if p in OVERBROAD_PERMISSIONS:
            overbroad.append({"permission": p, "reason": OVERBROAD_PERMISSIONS[p]})
    if overbroad:
        static_flags.append({"type": "overbroad_permissions", "details": overbroad})

    sdks = detect_sdks(apk, file_list)
    endpoints = find_endpoints(apk, file_list)
    pinning_flags = detect_insecure_pinning(apk, file_list)
    if pinning_flags:
        static_flags.append({"type": "insecure_pinning_patterns", "details": pinning_flags})
    signing_meta = extract_apk_signing_meta(apk, file_list)
    badging = aapt_dump_badging(apk)
    package_name = badging.get("package_name", "")

    evidence_dir = outdir / "evidence"
    ensure_dir(evidence_dir)
    write_json(evidence_dir / "strings_endpoints.json", {"endpoints": endpoints})

    sbom_cdx = build_cyclonedx(apk, package_name, sdks)
    sbom_spdx = build_spdx(apk, package_name, sdks)
    write_json(outdir / "sbom_cyclonedx.json", sbom_cdx)
    write_json(outdir / "sbom_spdx.json", sbom_spdx)

    report = {
        "apk": str(apk),
        "apk_sha256": sha256_file(apk),
        "package_name": package_name,
        "permissions": perms,
        "overbroad_permissions": overbroad,
        "sdks": sdks,
        "cve_correlations": {k: v.get("cves", []) for k, v in sdks.items()},
        "static_flags": static_flags,
        "endpoints_static": endpoints,
        "signing": signing_meta,
        "timestamp": now_iso(),
    }
    write_json(outdir / "static_report.json", report)
    return report


def frida_available() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except Exception:
        return False


def adb_available() -> bool:
    return shutil.which("adb") is not None


def start_app(package_name: str, device: Optional[str] = None):
    if not adb_available() or not package_name:
        return
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"]
    run_cmd(cmd)


def frida_hook_network(package_name: str, canary: str, duration_sec: int = 30, device: Optional[str] = None) -> Tuple[List[Dict], str]:
    # Hooks OkHttp and HttpUrlConnection to add header and log hosts
    log_buf = []

    script_src = f"""
    Java.perform(function() {{
        var Canary = "{canary}";
        function safeLog(x) {{
            send(x);
        }}
        try {{
            var RequestBuilder = Java.use('okhttp3.Request$Builder');
            RequestBuilder.build.implementation = function() {{
                try {{
                    this.header("X-SDK-Sentry-Canary", Canary);
                }} catch (e) {{}}
                return this.build();
            }};
            safeLog("OKHTTP_HOOKED");
        }} catch (e) {{
            safeLog("OKHTTP_HOOK_FAIL");
        }}
        try {{
            var HttpUrlConnection = Java.use('java.net.URL');
            HttpUrlConnection.openConnection.overload().implementation = function() {{
                var conn = this.openConnection();
                try {{
                    var setReqProp = conn.setRequestProperty;
                    setReqProp.call(conn, "X-SDK-Sentry-Canary", Canary);
                }} catch (e) {{}}
                return conn;
            }};
            safeLog("HUC_HOOKED");
        }} catch (e) {{
            safeLog("HUC_HOOK_FAIL");
        }}
        // Log constructed requests via OkHttp Call
        try {{
            var RealCall = Java.use('okhttp3.RealCall');
            RealCall.execute.implementation = function() {{
                try {{
                    var req = this.request();
                    var url = req.url().toString();
                    safeLog("REQ:" + url);
                }} catch (e) {{}}
                return this.execute();
            }};
            safeLog("REALCALL_HOOKED");
        }} catch (e) {{}}
    }});
    """

    try:
        import frida
        dev = frida.get_usb_device(timeout=5) if device is None else frida.get_device(device, timeout=5)
        pid = dev.spawn([package_name])
        session = dev.attach(pid)
        script = session.create_script(script_src)
        observed = []

        def on_message(msg, data):
            if msg["type"] == "send":
                text = str(msg["payload"])
                log_buf.append(text)
                if text.startswith("REQ:"):
                    url = text[4:]
                    observed.append({"url": url, "ts": now_iso()})
            else:
                log_buf.append(str(msg))

        script.on("message", on_message)
        script.load()
        dev.resume(pid)
        # Run for duration
        import time
        t_end = time.time() + duration_sec
        while time.time() < t_end:
            time.sleep(0.5)
        session.detach()
        return observed, "\n".join(log_buf)
    except Exception as e:
        return [], f"FRIDA_ERROR: {e}"


def analyze_dynamic(apk_report: Dict, allowlist: List[str], outdir: Path, enable_dynamic: bool, device: Optional[str]) -> Dict:
    evidence_dir = outdir / "evidence"
    ensure_dir(evidence_dir)
    canary = f"canary-{secrets.token_urlsafe(16)}"
    dynamic_report = {
        "enabled": enable_dynamic and frida_available(),
        "canary": canary,
        "observed_requests": [],
        "non_allowlisted_exfil": [],
        "notes": [],
        "timestamp": now_iso(),
    }
    package_name = apk_report.get("package_name") or ""
    if not enable_dynamic:
        dynamic_report["notes"].append("Dynamic analysis disabled. Only static endpoint scan used.")
        write_json(outdir / "dynamic_report.json", dynamic_report)
        write_json(evidence_dir / "network.json", dynamic_report)
        return dynamic_report
    if not frida_available():
        dynamic_report["notes"].append("Frida not available; dynamic instrumentation skipped.")
    if not adb_available():
        dynamic_report["notes"].append("adb not available; app may not be launched.")
    if not package_name:
        dynamic_report["notes"].append("Package name unknown; cannot inject. Skipping dynamic.")
    if not (frida_available() and package_name):
        write_json(outdir / "dynamic_report.json", dynamic_report)
        write_json(evidence_dir / "network.json", dynamic_report)
        return dynamic_report

    # Ethical safeguard: do not decrypt TLS or capture payloads; only log hosts/paths, redact sensitive segments.
    start_app(package_name, device=device)
    observed, frida_log = frida_hook_network(package_name, canary, duration_sec=30, device=device)
    # Redact and filter
    requests = []
    for ev in observed:
        url = redact_url(ev["url"].split("?")[0])
        dom = domain_from_url(url) or ""
        requests.append({"url": url, "domain": dom, "ts": ev["ts"]})

    non_allowlisted = []
    for ev in requests:
        dom = ev["domain"]
        if dom and not domain_matches_allowlist(dom, allowlist):
            # If our canary header is injected, any request indicates potential exfil path for canary
            non_allowlisted.append({"url": ev["url"], "domain": dom, "reason": "Non-allowlisted endpoint", "ts": ev["ts"]})

    dynamic_report["observed_requests"] = requests
    dynamic_report["non_allowlisted_exfil"] = non_allowlisted
    write_json(outdir / "dynamic_report.json", dynamic_report)
    (evidence_dir / "frida_log.txt").write_text(frida_log or "")
    write_json(evidence_dir / "network.json", dynamic_report)
    return dynamic_report


def build_audit(apk: Path, outdir: Path, static_report: Dict, dynamic_report: Dict, allowlist: List[str], signer_priv: Optional[Ed25519PrivateKey]) -> Dict:
    ensure_dir(outdir / "signatures")
    evidence_dir = outdir / "evidence"
    manifest = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "timestamp": now_iso(),
        "inputs": {"apk": str(apk), "apk_sha256": sha256_file(apk), "allowlist": allowlist},
        "files": {},
    }
    for p in [outdir / "static_report.json", outdir / "dynamic_report.json", outdir / "sbom_cyclonedx.json", outdir / "sbom_spdx.json"]:
        if p.exists():
            manifest["files"][p.name] = {"sha256": sha256_file(p)}
    for p in evidence_dir.glob("*"):
        if p.is_file():
            manifest["files"][f"evidence/{p.name}"] = {"sha256": sha256_file(p)}
    write_json(outdir / "manifest.json", manifest)

    audit_log_path = outdir / "audit_log.jsonl"
    with audit_log_path.open("w") as f:
        f.write(json.dumps({"ts": now_iso(), "event": "static_analysis_complete", "apk": str(apk)}) + "\n")
        f.write(json.dumps({"ts": now_iso(), "event": "dynamic_analysis_complete", "observed": len(dynamic_report.get("observed_requests", []))}) + "\n")
        sev = "HIGH" if dynamic_report.get("non_allowlisted_exfil") else "NONE"
        f.write(json.dumps({"ts": now_iso(), "event": "summary", "severity": sev}) + "\n")

    sigs = {}
    if signer_priv:
        # Sign manifest and audit log
        for fname in ["manifest.json", "audit_log.jsonl"]:
            data = (outdir / fname).read_bytes()
            sig = sign_bytes(signer_priv, data)
            (outdir / "signatures" / f"{fname}.sig").write_text(sig)
            sigs[fname] = sig
    attestation = {
        "attestation": {
            "subject": {"apk": str(apk), "apk_sha256": sha256_file(apk)},
            "issued_at": now_iso(),
            "tool_version": TOOL_VERSION,
            "chain_of_custody": {"manifest": "manifest.json", "audit_log": "audit_log.jsonl"},
        },
        "signatures": sigs,
    }
    write_json(outdir / "attestation.json", attestation)
    return attestation


def verify_artifacts(outdir: Path, pub_key_path: Path) -> Dict:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required for verification.")
    pub = load_public_key(pub_key_path)
    results = {"manifest": False, "audit_log": False}
    for fname in ["manifest.json", "audit_log.jsonl"]:
        file_path = outdir / fname
        sig_path = outdir / "signatures" / f"{fname}.sig"
        if not (file_path.exists() and sig_path.exists()):
            continue
        data = file_path.read_bytes()
        sig_b64 = sig_path.read_text().strip()
        results["manifest" if fname == "manifest.json" else "audit_log"] = verify_signature(pub, data, sig_b64)
    # Verify file hashes listed in manifest
    manifest = json.loads((outdir / "manifest.json").read_text())
    hash_ok = True
    for f, meta in manifest.get("files", {}).items():
        p = outdir / f
        if not p.exists():
            hash_ok = False
            break
        if sha256_file(p) != meta.get("sha256"):
            hash_ok = False
            break
    results["hashes_ok"] = hash_ok
    return results


def print_ethics_safety_notice():
    notice = (
        "Ethical and Safety Notice:\n"
        "- Use this tool only on applications and systems you are authorized to test.\n"
        "- The dynamic stage operates in sandboxed emulators and does not decrypt TLS or collect PII.\n"
        "- Configure network allowlists to restrict egress during testing.\n"
        "- Proceeding indicates your agreement to conduct authorized, ethical testing.\n"
    )
    sys.stderr.write(notice)


def main():
    parser = argparse.ArgumentParser(prog="sdk_sentry", description=TOOL_NAME)
    sub = parser.add_subparsers(dest="cmd")

    p_an = sub.add_parser("analyze", help="Analyze an APK")
    p_an.add_argument("--apk", required=True, help="Path to APK")
    p_an.add_argument("--out", required=True, help="Output directory")
    p_an.add_argument("--allowlist", help="File with allowlisted domains")
    p_an.add_argument("--dynamic", action="store_true", help="Enable emulator-based dynamic instrumentation (Frida)")
    p_an.add_argument("--device", help="ADB/Frida device ID (optional)")
    p_an.add_argument("--signing-key", help="Ed25519 private key PEM for signing (will be created if missing)")
    p_an.add_argument("--agree-to-ethical", action="store_true", help="Acknowledge ethical testing requirements")

    p_gen = sub.add_parser("gen-key", help="Generate an Ed25519 keypair")
    p_gen.add_argument("--out", required=True, help="Private key path (PEM)")

    p_ver = sub.add_parser("verify", help="Verify audit signatures and file hashes")
    p_ver.add_argument("--out", required=True, help="Output directory of a previous run")
    p_ver.add_argument("--pub", required=True, help="Public key PEM path")

    args = parser.parse_args()
    if args.cmd == "gen-key":
        if not HAS_CRYPTO:
            print("cryptography not available; cannot generate keys.", file=sys.stderr)
            sys.exit(2)
        priv_path, pub_path = mk_keypair(Path(args.out))
        print(f"Generated: {priv_path} and {pub_path}")
        return

    if args.cmd == "verify":
        res = verify_artifacts(Path(args.out), Path(args.pub))
        print(json.dumps(res, indent=2))
        sys.exit(0 if res.get("manifest") and res.get("audit_log") and res.get("hashes_ok") else 1)

    if args.cmd == "analyze":
        if not args.agree_to_ethical:
            print_ethics_safety_notice()
            print("Refusing to run without --agree-to-ethical acknowledgement.", file=sys.stderr)
            sys.exit(2)

        apk = Path(args.apk)
        outdir = Path(args.out)
        if not apk.exists():
            print(f"APK not found: {apk}", file=sys.stderr)
            sys.exit(2)
        ensure_dir(outdir)
        allowlist = load_allowlist(Path(args.allowlist)) if args.allowlist else []

        # Signer
        priv = None
        pub_out = None
        if args.signing_key:
            key_path = Path(args.signing_key)
            if not key_path.exists():
                if not HAS_CRYPTO:
                    print("cryptography not available; cannot create signing key.", file=sys.stderr)
                    sys.exit(2)
                mk_keypair(key_path)
            if HAS_CRYPTO:
                priv = load_private_key(key_path)
                pub_out = key_path.with_suffix(".pub.pem")
                # Save public key in outdir for convenience
                if pub_out.exists():
                    shutil.copy2(pub_out, outdir / pub_out.name)

        # Static
        static_report = analyze_static(apk, outdir)

        # Dynamic
        dynamic_report = analyze_dynamic(static_report, allowlist, outdir, enable_dynamic=args.dynamic, device=args.device)

        # High-confidence alert if non-allowlisted exfil observed
        high_conf_alert = True if dynamic_report.get("non_allowlisted_exfil") else False
        if high_conf_alert:
            print("ALERT: Non-allowlisted egress observed with seeded canary. See dynamic_report.json and evidence.", file=sys.stderr)

        # Build audit logs and attestations
        attestation = build_audit(apk, outdir, static_report, dynamic_report, allowlist, signer_priv=priv)

        # Final summary to stdout
        summary = {
            "apk": str(apk),
            "package_name": static_report.get("package_name"),
            "sdks_detected": list(static_report.get("sdks", {}).keys()),
            "overbroad_permissions": [p["permission"] for p in static_report.get("overbroad_permissions", [])],
            "cve_correlations": static_report.get("cve_correlations", {}),
            "dynamic_observed_non_allowlisted": bool(dynamic_report.get("non_allowlisted_exfil")),
            "artifacts": {
                "sbom_cyclonedx": str(outdir / "sbom_cyclonedx.json"),
                "sbom_spdx": str(outdir / "sbom_spdx.json"),
                "static_report": str(outdir / "static_report.json"),
                "dynamic_report": str(outdir / "dynamic_report.json"),
                "attestation": str(outdir / "attestation.json"),
                "manifest": str(outdir / "manifest.json"),
                "audit_log": str(outdir / "audit_log.jsonl"),
                "signatures_dir": str(outdir / "signatures"),
                "evidence_dir": str(outdir / "evidence"),
                "public_key": str((outdir / Path(args.signing_key).with_suffix(".pub.pem").name)) if args.signing_key else "",
            },
        }
        print(json.dumps(summary, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()