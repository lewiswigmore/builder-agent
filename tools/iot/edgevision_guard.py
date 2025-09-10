import argparse
import base64
import datetime
import getpass
import hashlib
import hmac
import io
import json
import os
import platform
import random
import re
import socket
import string
import tarfile
import time
import zipfile
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.2"

__all__ = [
    "EdgeVisionGuard",
    "ConsentRequiredError",
    "EvidenceIntegrityError",
    "FirmwareParseError",
    "verify_evidence_bundle",
]

# Custom exceptions expected by tests/consumers
class ConsentRequiredError(PermissionError):
    pass


class EvidenceIntegrityError(Exception):
    pass


class FirmwareParseError(Exception):
    pass


# Offline minimal CVE mapping for demo/acceptance. Extend as needed.
CVE_DB = {
    "openssl": {
        "1.0.2": ["CVE-2016-2107", "CVE-2016-2108"],
        "1.1.1": ["CVE-2019-1543"],  # example
        "1.1.1k": [],  # patched example
    },
    "busybox": {
        "1.31.0": ["CVE-2019-5747"],
        "1.34.0": [],
    },
    "libcurl": {
        "7.29.0": ["CVE-2016-7141", "CVE-2018-1000120"],
        "7.64.0": ["CVE-2019-3822"],
        "7.87.0": [],
    },
    "dropbear": {
        "2015.71": ["CVE-2016-3116"],
    },
    "ffmpeg": {
        "3.2": ["CVE-2017-9993"],
    },
    "nginx": {
        "1.14.0": ["CVE-2018-16843"],
        "1.24.0": [],
    },
    "uhttpd": {
        "2.0": ["CVE-2021-33430"],
    },
    "gstreamer": {
        "1.16": ["CVE-2020-6071"],
    },
}

# Basic regexes for parsing components and versions from strings
PKG_PATTERNS = [
    (re.compile(r"\bopenssl[-_\s]?([0-9]+\.[0-9]+\.[0-9a-z]+)"), "openssl"),
    (re.compile(r"\blibssl[-\._]so\.(\d+\.\d+\.\d+)"), "openssl"),
    (re.compile(r"\bbusybox[-\s_v]?(\d+\.\d+(\.\d+)?)"), "busybox"),
    (re.compile(r"\blibcurl[-\._]so\.(\d+\.\d+\.\d+)"), "libcurl"),
    (re.compile(r"\bcurl[-_\s]?(\d+\.\d+\.\d+)"), "libcurl"),
    (re.compile(r"\bdropbear[-_\s]?([0-9]{4}\.[0-9]{2})"), "dropbear"),
    (re.compile(r"\bffmpeg[-_\s]?(\d+\.\d+)"), "ffmpeg"),
    (re.compile(r"\bnginx[-_\s]?(\d+\.\d+\.\d+)"), "nginx"),
    (re.compile(r"\buhttpd[-_\s]?(\d+\.\d+)"), "uhttpd"),
    (re.compile(r"\bgstreamer[-_\s]?(\d+\.\d+)"), "gstreamer"),
]

CREDENTIAL_PATTERNS = [
    re.compile(r"(rtsp|https?|ftp)://([^:/\s]+):([^@/\s]+)@([^\s'\"\\]+)", re.IGNORECASE),
    re.compile(r"\b(user(name)?|admin|root|login)\s*[:=]\s*([^\s'\"\\]{1,64})", re.IGNORECASE),
    re.compile(r"\bpass(word)?\s*[:=]\s*([^\s'\"\\]{1,128})", re.IGNORECASE),
    re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE),
]

PII_PATTERNS = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "[REDACTED_MAC]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]+"), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"api[_-]?key\s*=\s*[A-Za-z0-9\-_]{8,}", re.IGNORECASE), "api_key=[REDACTED]"),
    (re.compile(r"pass(word)?\s*=\s*[^&\s]+", re.IGNORECASE), "password=[REDACTED]"),
]

ETHICS_BANNER = (
    "EdgeVision Guard - Authorized Testing Only.\n"
    "You must have explicit written permission from the device owner/operator. "
    "No live device interaction will proceed without consent.\n"
)


def mask_pii(text: str) -> str:
    masked = text
    for pat, repl in PII_PATTERNS:
        masked = pat.sub(repl, masked)
    return masked


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hmac_sign(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    res = []
    buff = []
    for b in data:
        ch = chr(b)
        if " " <= ch <= "~":
            buff.append(ch)
        else:
            if len(buff) >= min_len:
                res.append("".join(buff))
            buff = []
    if len(buff) >= min_len:
        res.append("".join(buff))
    return res


def read_archive_strings(path: str, max_bytes: int = 2_000_000) -> List[str]:
    strings = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    try:
                        with z.open(name) as f:
                            data = f.read(max_bytes)
                            strings.extend(ascii_strings(data))
                    except Exception:
                        continue
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as t:
                for member in t.getmembers():
                    if not member.isfile():
                        continue
                    try:
                        f = t.extractfile(member)
                        if not f:
                            continue
                        data = f.read(max_bytes)
                        strings.extend(ascii_strings(data))
                    except Exception:
                        continue
        else:
            with open(path, "rb") as f:
                data = f.read()
                strings.extend(ascii_strings(data))
    except Exception:
        pass
    return list(set(strings))


def extract_sbom(strings: List[str]) -> List[Dict[str, str]]:
    components = {}
    for s in strings:
        for rx, name in PKG_PATTERNS:
            m = rx.search(s)
            if m:
                ver = m.group(1)
                # Normalize version like '1.1.1k' keep as is
                key = (name, ver)
                if key not in components:
                    components[key] = {
                        "name": name,
                        "version": ver,
                        "source": s[:200],
                    }
    return list(components.values())


def correlate_cves(sbom: List[Dict[str, str]]) -> List[Dict[str, object]]:
    findings = []
    for comp in sbom:
        name = comp["name"]
        ver = comp["version"]
        cves = []
        if name in CVE_DB:
            # Try exact match first, then major.minor
            if ver in CVE_DB[name]:
                cves = CVE_DB[name][ver]
            else:
                short = ".".join(ver.split(".")[:2])
                if short in CVE_DB[name]:
                    cves = CVE_DB[name][short]
        findings.append({
            "component": name,
            "version": ver,
            "cves": cves,
            "severity": "high" if cves else "none",
        })
    return findings


def detect_hardcoded_credentials(strings: List[str]) -> List[Dict[str, str]]:
    results = []
    for s in strings:
        for rx in CREDENTIAL_PATTERNS:
            for m in rx.finditer(s):
                entry = None
                if len(m.groups()) >= 3 and m.re.pattern.startswith("(rtsp"):
                    scheme, user, pw, host = m.groups()[:4]
                    if user and pw:
                        entry = {
                            "type": f"uri_credentials_{scheme.lower()}",
                            "user": mask_pii(user),
                            "password": "[REDACTED]",
                            "host": mask_pii(host),
                            "evidence": mask_pii(s[:200]),
                        }
                elif "Authorization" in m.re.pattern:
                    try:
                        decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                        if ":" in decoded:
                            u, p = decoded.split(":", 1)
                            entry = {
                                "type": "basic_auth_header",
                                "user": mask_pii(u),
                                "password": "[REDACTED]",
                                "evidence": "Authorization: Basic ****",
                            }
                    except Exception:
                        continue
                else:
                    # user/password kv
                    g = m.groups()
                    val = g[-1] if g else None
                    if val:
                        key = m.group(1) if m.group(1) else "credential"
                        entry = {
                            "type": f"kv_{key.lower()}",
                            "value": "[REDACTED]",
                            "evidence": mask_pii(s[:200]),
                        }
                if entry:
                    results.append(entry)
    # Deduplicate by evidence hash
    seen = set()
    unique = []
    for e in results:
        h = sha256_bytes(canonical_json(e))
        if h not in seen:
            seen.add(h)
            unique.append(e)
    return unique


def recommended_mitigations(creds_found: List[Dict[str, str]], cves: List[Dict[str, object]]) -> List[str]:
    recs = []
    if creds_found:
        recs.append("Remove hardcoded credentials and secrets from firmware. Use secure credential vaults and device-unique credentials.")
        recs.append("Disable legacy access methods (e.g., telnet/RTSP with basic auth). Enforce mutual TLS and least-privilege access.")
        recs.append("Rotate any exposed credentials and invalidate leaked tokens immediately.")
    if any(f["cves"] for f in cves):
        recs.append("Update vulnerable components to patched versions and rebuild firmware with secure toolchain.")
        recs.append("Implement SBOM-based continuous monitoring and vulnerability management for dependencies.")
    recs.append("Enable secure boot and signed firmware updates to prevent tampering.")
    return recs


def spectral_signature_summary(data: bytes) -> Dict[str, object]:
    # Lightweight byte-frequency and entropy analysis
    freq = [0] * 256
    for b in data[:2_000_000]:
        freq[b] += 1
    total = sum(freq) or 1
    normalized = [f / total for f in freq]
    # Shannon entropy estimate
    import math
    entropy = -sum(p * math.log(p, 2) for p in normalized if p > 0)
    # Heuristic: unusual high entropy may indicate embedded payloads/backdoors
    suspicious = entropy > 7.8
    return {
        "sha256": sha256_bytes(data),
        "entropy": round(entropy, 4),
        "high_entropy_suspect": suspicious,
        "byte_frequency_top10": sorted(
            [{"byte": i, "p": round(p, 6)} for i, p in enumerate(normalized)],
            key=lambda x: x["p"],
            reverse=True,
        )[:10],
    }


def load_eval_predictions(eval_path: Optional[str]) -> Optional[Dict[str, Dict[str, float]]]:
    if not eval_path:
        return None
    try:
        with open(eval_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "clean_prediction" in data and "trigger_prediction" in data:
                return data
    except Exception:
        return None
    return None


def compute_confidence_shift(clean: Dict[str, float], trigger: Dict[str, float]) -> Dict[str, object]:
    keys = set(clean) | set(trigger)
    shift = {}
    for k in keys:
        c = clean.get(k, 0.0)
        t = trigger.get(k, 0.0)
        shift[k] = round(t - c, 6)
    top_pos = sorted(shift.items(), key=lambda kv: kv[1], reverse=True)[:3]
    top_neg = sorted(shift.items(), key=lambda kv: kv[1])[:3]
    return {
        "per_label_delta": shift,
        "top_increases": top_pos,
        "top_decreases": top_neg,
    }


def derive_saliency_from_patch(trigger_patch: Optional[str]) -> Dict[str, object]:
    # Represent saliency as coarse grid heat values from a textual mask spec like "x10,y10,w20,h20"
    heat = [[0 for _ in range(16)] for _ in range(16)]
    if trigger_patch:
        m = re.search(r"x(\d+),?y(\d+),?w(\d+),?h(\d+)", trigger_patch)
        if m:
            x, y, w, h = [int(v) for v in m.groups()]
            # Map to 16x16 grid assuming 100x100 normalized coords
            gx = max(0, min(15, x * 16 // 100))
            gy = max(0, min(15, y * 16 // 100))
            gw = max(1, min(16 - gx, max(1, w * 16 // 100)))
            gh = max(1, min(16 - gy, max(1, h * 16 // 100)))
            for yy in range(gy, gy + gh):
                for xx in range(gx, gx + gw):
                    heat[yy][xx] = 1
    # Compute hot cell count
    hot = sum(sum(row) for row in heat)
    return {
        "grid_size": [16, 16],
        "hot_cells": hot,
        "heatmap_ascii": ["".join("#" if v else "." for v in row) for row in heat],
    }


class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.rate = max(0.1, rate_per_sec)
        self.last = 0.0

    def wait(self):
        now = time.monotonic()
        delay = max(0.0, (1.0 / self.rate) - (now - self.last))
        if delay > 0:
            time.sleep(delay)
        self.last = time.monotonic()


class Sandbox:
    def __init__(self, allowed_hosts: Optional[List[str]] = None, rate_limit: float = 5.0):
        self.allowed = set(allowed_hosts or [])
        self.events = []
        self.limiter = RateLimiter(rate_limit)

    def attempt_connect(self, url: str):
        # Parse scheme and host:port
        m = re.match(r"(?i)^(?P<scheme>[a-z][a-z0-9+.-]*):\/\/(?P<rest>.+)$", url)
        scheme = m.group("scheme").lower() if m else "tcp"
        rest = m.group("rest") if m else url
        host = rest.split("/")[0]
        host_only = host.split("@")[-1].split(":")[0]
        action = "allowed" if (host_only in self.allowed) else "blocked"
        if scheme in ("rtsp", "https") and host_only not in self.allowed:
            action = "blocked"
        self.limiter.wait()
        evt = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "scheme": scheme,
            "dst": host,
            "action": action,
        }
        self.events.append(evt)
        return action == "allowed"

    def write_pcap_ndjson(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            for e in self.events:
                e_masked = dict(e)
                # Respect privacy for stored logs (mask PII like IPs)
                e_masked["dst"] = mask_pii(e_masked.get("dst", ""))
                f.write(json.dumps(e_masked) + "\n")


def deterministic_zip(zip_path: str, files: List[Tuple[str, str]]):
    # files: list of (arcname, realpath)
    epoch = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for arc, real in sorted(files, key=lambda x: x[0]):
            data = b""
            if real is not None:
                with open(real, "rb") as f:
                    data = f.read()
            info = zipfile.ZipInfo(arc, date_time=epoch)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)


class EdgeVisionGuard:
    def __init__(self, operator: str, consent: bool, outdir: str, hmac_key: Optional[str] = None):
        # Consent is required only for live device interaction (e.g., emulation).
        self.consent = bool(consent)
        self.operator = operator or getpass.getuser()
        self.outdir = outdir
        ensure_dir(outdir)
        self.log_path = os.path.join(outdir, "session.log")
        self.hmac_key = (hmac_key or os.environ.get("EVG_HMAC_KEY") or "").encode("utf-8")
        self._log(ETHICS_BANNER)

    def _log(self, msg: str):
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        line = f"[{ts}] {msg.rstrip()}\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)

    def analyze_firmware(self, firmware_path: str) -> Dict[str, object]:
        self._log(f"Analyzing firmware image: {firmware_path}")
        if not os.path.exists(firmware_path):
            raise FirmwareParseError(f"Firmware image not found: {firmware_path}")
        try:
            strings = read_archive_strings(firmware_path)
        except Exception as e:
            raise FirmwareParseError(f"Failed to parse firmware image: {e}") from e
        sbom = extract_sbom(strings)
        cves = correlate_cves(sbom)
        creds = detect_hardcoded_credentials(strings)
        recs = recommended_mitigations(creds, cves)
        report = {
            "firmware": os.path.basename(firmware_path),
            "sbom": sbom,
            "cve_findings": cves,
            "hardcoded_credentials": creds,
            "recommendations": recs,
        }
        path = os.path.join(self.outdir, "firmware_analysis.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        self._log("Firmware analysis complete.")
        return report

    def analyze_model(self, model_path: str, eval_path: Optional[str] = None, trigger_patch: Optional[str] = None) -> Dict[str, object]:
        self._log(f"Analyzing model: {model_path}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        with open(model_path, "rb") as f:
            data = f.read()
        spec = spectral_signature_summary(data)
        # Heuristic markers
        suspicious_markers = [b"trigger", b"backdoor", b"patch", b"poison"]
        marker_hits = [m.decode("utf-8", errors="ignore") for m in suspicious_markers if m in data.lower()]
        eval_pred = load_eval_predictions(eval_path) or load_eval_predictions(model_path + ".eval.json")
        confidence_shift = None
        backdoor_suspected = False
        if eval_pred:
            confidence_shift = compute_confidence_shift(eval_pred["clean_prediction"], eval_pred["trigger_prediction"])
            # If any label has a big positive delta and another has big negative delta, suspect backdoor
            inc = confidence_shift["top_increases"][0][1] if confidence_shift["top_increases"] else 0.0
            dec = confidence_shift["top_decreases"][0][1] if confidence_shift["top_decreases"] else 0.0
            if inc > 0.5 or dec < -0.5:
                backdoor_suspected = True
        if spec["high_entropy_suspect"] or marker_hits:
            backdoor_suspected = True or backdoor_suspected
        saliency = derive_saliency_from_patch(trigger_patch)
        report = {
            "model": os.path.basename(model_path),
            "spectral_signature": spec,
            "suspicious_markers": marker_hits,
            "backdoor_suspected": bool(backdoor_suspected),
            "trigger_saliency": saliency,
            "confidence_shift": confidence_shift,
        }
        path = os.path.join(self.outdir, "model_analysis.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        # Also store a "screenshot" text of saliency
        with open(os.path.join(self.outdir, "saliency_screenshot.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(saliency["heatmap_ascii"]))
        self._log("Model analysis complete.")
        return report

    def emulate_runtime(self, device_config: Optional[str] = None, allowed_endpoints: Optional[List[str]] = None, test_duration: int = 5) -> Dict[str, object]:
        if not self.consent:
            raise ConsentRequiredError("Explicit operator consent is required before any live device interaction.")
        self._log("Starting runtime emulation in microsegmented sandbox.")
        sb = Sandbox(allowed_hosts=allowed_endpoints or [], rate_limit=10.0)
        endpoints = []
        if device_config and os.path.exists(device_config):
            try:
                with open(device_config, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    endpoints = cfg.get("simulate_endpoints", [])
            except Exception as e:
                self._log(f"Warning: unable to load device config: {e}")
        # Default simulated endpoints
        if not endpoints:
            endpoints = [
                "rtsp://admin:admin@192.168.1.10:554/stream",
                "https://thirdparty-cloud.example.com/telemetry",
                "https://updates.vendor.com/check",
            ]
        start = time.time()
        incidents = []
        for url in endpoints:
            allowed = sb.attempt_connect(url)
            if not allowed:
                if url.lower().startswith(("rtsp://", "https://")):
                    incidents.append({
                        "url": mask_pii(url),
                        "reason": "Unauthorized egress attempt blocked by sandbox policy",
                        "ts": datetime.datetime.utcnow().isoformat() + "Z",
                    })
            if time.time() - start > test_duration:
                break
        pcap_path = os.path.join(self.outdir, "egress_capture.pcap.ndjson")
        sb.write_pcap_ndjson(pcap_path)
        # Create incident report and sign it
        report = {
            "incidents": incidents,
            "policy_allowed_endpoints": allowed_endpoints or [],
            "sandbox_topology": {
                "segments": ["management", "video_pipeline", "cloud_link"],
                "microsegmentation": "default-deny; allowlist only",
            },
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "operator": self.operator,
            "tool_version": VERSION,
        }
        report_path = os.path.join(self.outdir, "incident_report.json")
        signature = None
        key_id = None
        if self.hmac_key:
            payload = canonical_json(report)
            signature = hmac_sign(payload, self.hmac_key)
            key_id = hashlib.sha256(self.hmac_key).hexdigest()[:16]
        signed_report = dict(report)
        signed_report["signature"] = signature
        signed_report["key_id"] = key_id
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(signed_report, f, indent=2)
        # Screenshot of topology
        topo = [
            "+--------------------+        +-------------------+",
            "|   Management Seg   |        |   Cloud Link      |",
            "+----------+---------+        +---------+---------+",
            "           |                           |           ",
            "           |                           |           ",
            "    +------+-------+            +------+-------+   ",
            "    |  Video Pipe  |------------|   Egress     |   ",
            "    +--------------+   microseg  +--------------+  ",
            "      default-deny                block 3rd-party   ",
        ]
        with open(os.path.join(self.outdir, "sandbox_topology.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(topo))
        self._log("Runtime emulation complete.")
        return signed_report

    def build_evidence_bundle(self, bundle_path: str, case_id: Optional[str] = None) -> Dict[str, object]:
        self._log("Sealing evidence bundle.")
        # Collect artifacts
        artefacts = []
        for root, _, files in os.walk(self.outdir):
            for fn in files:
                if fn.endswith(".zip"):
                    continue
                path = os.path.join(root, fn)
                arc = os.path.relpath(path, self.outdir)
                artefacts.append((arc, path))
        # Build manifest
        manifest = {
            "case_id": case_id or f"EVG-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "operator": self.operator,
            "tool_version": VERSION,
            "created_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "chain_of_custody": {
                "steps": [
                    {"ts": datetime.datetime.utcnow().isoformat() + "Z", "action": "collection_completed"}
                ]
            },
            "files": [],
        }
        for arc, path in sorted(artefacts, key=lambda x: x[0]):
            manifest["files"].append({
                "path": arc,
                "sha256": sha256_file(path),
                "size": os.path.getsize(path),
            })
        manifest_bytes = canonical_json(manifest)
        manifest_path = os.path.join(self.outdir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest_bytes.decode("utf-8"))
        # Signature over manifest
        sig = None
        key_id = None
        if self.hmac_key:
            sig = hmac_sign(manifest_bytes, self.hmac_key)
            key_id = hashlib.sha256(self.hmac_key).hexdigest()[:16]
        sig_obj = {"signature": sig, "key_id": key_id, "alg": "HMAC-SHA256"}
        with open(os.path.join(self.outdir, "manifest.sig"), "w", encoding="utf-8") as f:
            json.dump(sig_obj, f, indent=2)
        # Create deterministic zip
        files_for_zip = [(arc, path) for arc, path in artefacts]
        files_for_zip.append(("manifest.json", manifest_path))
        files_for_zip.append(("manifest.sig", os.path.join(self.outdir, "manifest.sig")))
        deterministic_zip(bundle_path, files_for_zip)
        bundle_hash = sha256_file(bundle_path)
        self._log(f"Evidence bundle created at {bundle_path} (sha256={bundle_hash})")
        return {
            "bundle_path": bundle_path,
            "sha256": bundle_hash,
            "manifest": manifest,
            "signature": sig_obj,
        }

    def verify_evidence_bundle(self, bundle_path: str, hmac_key: str) -> Dict[str, object]:
        return verify_evidence_bundle(bundle_path, hmac_key)


def parse_args():
    p = argparse.ArgumentParser(description="EdgeVision Guard: Smart Camera Model Backdoor & Egress Auditor")
    sub = p.add_subparsers(dest="cmd")

    pf = sub.add_parser("firmware", help="Analyze firmware image")
    pf.add_argument("--image", required=True, help="Path to firmware image (bin/zip/tar)")
    pf.add_argument("--out", required=True, help="Output directory")
    pf.add_argument("--operator", default="", help="Operator name")
    pf.add_argument("--consent", action="store_true", help="Operator consent for authorized testing")

    pm = sub.add_parser("model", help="Analyze AI model file")
    pm.add_argument("--model", required=True, help="Path to model file")
    pm.add_argument("--eval", help="Path to eval predictions JSON with clean/trigger predictions")
    pm.add_argument("--trigger-patch", help="Trigger patch spec, e.g., x10,y10,w20,h20")
    pm.add_argument("--out", required=True, help="Output directory")
    pm.add_argument("--operator", default="", help="Operator name")
    pm.add_argument("--consent", action="store_true", help="Operator consent for authorized testing")

    pe = sub.add_parser("emulate", help="Emulate runtime and observe egress")
    pe.add_argument("--config", help="Device config JSON with simulate_endpoints")
    pe.add_argument("--allowed", help="Comma-separated allowed endpoints (hostnames/IPs)")
    pe.add_argument("--duration", type=int, default=5, help="Emulation duration seconds")
    pe.add_argument("--out", required=True, help="Output directory")
    pe.add_argument("--operator", default="", help="Operator name")
    pe.add_argument("--consent", action="store_true", help="Operator consent for authorized testing")
    pe.add_argument("--hmac-key", help="HMAC key for signing incident report")

    pb = sub.add_parser("bundle", help="Create sealed evidence bundle")
    pb.add_argument("--outdir", required=True, help="Directory with artifacts to bundle")
    pb.add_argument("--bundle", required=True, help="Path to output bundle zip")
    pb.add_argument("--operator", default="", help="Operator name")
    pb.add_argument("--consent", action="store_true", help="Operator consent for authorized testing")
    pb.add_argument("--hmac-key", help="HMAC key for signing manifest")
    pb.add_argument("--case-id", help="Case identifier")

    pv = sub.add_parser("verify", help="Verify sealed evidence bundle")
    pv.add_argument("--bundle", required=True, help="Path to bundle zip to verify")
    pv.add_argument("--hmac-key", required=True, help="HMAC key used for signing")

    return p.parse_args()


def verify_evidence_bundle(bundle_path: str, hmac_key: str) -> Dict[str, object]:
    if not os.path.exists(bundle_path):
        raise FileNotFoundError(f"Bundle not found: {bundle_path}")
    key_bytes = (hmac_key or "").encode("utf-8")
    try:
        with zipfile.ZipFile(bundle_path, "r") as z:
            try:
                manifest_raw = z.read("manifest.json")
                sig_raw = z.read("manifest.sig")
            except KeyError as e:
                raise EvidenceIntegrityError(f"Missing required file in bundle: {e}") from e
            # Verify signature over canonical manifest
            manifest_obj = json.loads(manifest_raw.decode("utf-8"))
            manifest_bytes = canonical_json(manifest_obj)
            sig_obj = json.loads(sig_raw.decode("utf-8"))
            expected_sig = sig_obj.get("signature")
            if not expected_sig:
                raise EvidenceIntegrityError("No signature present in manifest.sig")
            calc_sig = hmac_sign(manifest_bytes, key_bytes)
            if not hmac.compare_digest(expected_sig, calc_sig):
                raise EvidenceIntegrityError("Manifest signature verification failed")
            # Verify file hashes listed in manifest
            files_info = manifest_obj.get("files", [])
            mismatches = []
            verified_files = 0
            for entry in files_info:
                arc = entry["path"]
                expected_sha = entry["sha256"]
                try:
                    data = z.read(arc)
                except KeyError:
                    mismatches.append({"path": arc, "error": "missing_in_bundle"})
                    continue
                actual_sha = sha256_bytes(data)
                if actual_sha != expected_sha:
                    mismatches.append({"path": arc, "error": "sha256_mismatch"})
                else:
                    verified_files += 1
            return {
                "verified": len(mismatches) == 0,
                "verified_files": verified_files,
                "mismatches": mismatches,
                "manifest_key_id": sig_obj.get("key_id"),
                "alg": sig_obj.get("alg"),
            }
    except EvidenceIntegrityError:
        raise
    except Exception as e:
        raise EvidenceIntegrityError(f"Unable to verify bundle: {e}") from e


def main():
    args = parse_args()
    if not args.cmd:
        print(ETHICS_BANNER)
        print("Use subcommands: firmware, model, emulate, bundle, verify")
        return
    if args.cmd == "firmware":
        g = EdgeVisionGuard(operator=args.operator, consent=args.consent, outdir=args.out)
        rep = g.analyze_firmware(args.image)
        print(json.dumps(rep, indent=2))
    elif args.cmd == "model":
        g = EdgeVisionGuard(operator=args.operator, consent=args.consent, outdir=args.out)
        rep = g.analyze_model(args.model, eval_path=args.eval, trigger_patch=args.trigger_patch)
        print(json.dumps(rep, indent=2))
    elif args.cmd == "emulate":
        allowed = [s.strip() for s in (args.allowed or "").split(",") if s.strip()]
        g = EdgeVisionGuard(operator=args.operator, consent=args.consent, outdir=args.out, hmac_key=args.hmac_key)
        rep = g.emulate_runtime(device_config=args.config, allowed_endpoints=allowed, test_duration=args.duration)
        print(json.dumps(rep, indent=2))
    elif args.cmd == "bundle":
        g = EdgeVisionGuard(operator=args.operator, consent=args.consent, outdir=args.outdir, hmac_key=args.hmac_key)
        info = g.build_evidence_bundle(args.bundle, case_id=args.case_id)
        print(json.dumps({"bundle": info["bundle_path"], "sha256": info["sha256"]}, indent=2))
    elif args.cmd == "verify":
        result = verify_evidence_bundle(args.bundle, args.hmac_key)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()