#!/usr/bin/env python3
import argparse
import base64
import datetime
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

ETHICAL_WARNING = (
    "ETHICAL NOTICE: Use this tool only on systems and codebases you own or are authorized to test. "
    "Unauthorized probing or scanning may violate laws or policies. Proceed responsibly."
)

WEAK_ALGO_PATTERNS = [
    (re.compile(r"\bsha[-_]?1\b", re.IGNORECASE), "SHA-1", "critical", "Replace with SHA-256 or SHA-512."),
    (re.compile(r"\bmd5\b", re.IGNORECASE), "MD5", "critical", "Replace with SHA-256 or SHA-512."),
    (re.compile(r"\brc4\b", re.IGNORECASE), "RC4", "high", "Use AES-GCM or ChaCha20-Poly1305."),
    (re.compile(r"\b3des\b|\bdes[-_]?ede3\b|\btriple[-_]?des\b", re.IGNORECASE), "3DES", "high", "Use AES-256-GCM."),
    (re.compile(r"\bdes\b", re.IGNORECASE), "DES", "high", "Use AES-256-GCM."),
    (re.compile(r"\bdsa\b", re.IGNORECASE), "DSA", "medium", "Use ECDSA P-256 or Ed25519."),
    (re.compile(r"\brsa\b.*\b1024\b", re.IGNORECASE), "RSA-1024", "high", "Increase to RSA-3072 or use ECDSA P-256/Ed25519."),
    (re.compile(r"\brsa_generate\w*\s*\(\s*1024\b", re.IGNORECASE), "RSA-1024", "high", "Increase to RSA-3072 or use ECDSA P-256/Ed25519."),
    (re.compile(r"\bRSAKeyPairGenerator\W*1024\b", re.IGNORECASE), "RSA-1024", "high", "Increase to RSA-3072 or use ECDSA P-256/Ed25519."),
    (re.compile(r"\bmodulusLength\b\s*[:=]\s*1024\b", re.IGNORECASE), "RSA-1024", "high", "Increase to RSA-3072 or use ECDSA P-256/Ed25519."),
    (re.compile(r"\bhmac[-_]?sha1\b", re.IGNORECASE), "HMAC-SHA1", "medium", "Use HMAC-SHA256 or HMAC-SHA512."),
    (re.compile(r"\bPKCS#?1\s*v?1\.5\b|\bpkcs1_v1_5\b", re.IGNORECASE), "RSA-PKCS1v1.5", "medium", "Use RSA-PSS for signatures and RSA-OAEP for encryption."),
    (re.compile(r"\bpbkdf2\b.*\b(iterations|rounds)\b\s*[:=]\s*[1-5]\d{0,3}\b", re.IGNORECASE), "Weak PBKDF2 iterations", "medium", "Use >= 310000 iterations and a strong hash."),
    (re.compile(r"\baes[-_]?cbc\b", re.IGNORECASE), "AES-CBC", "medium", "Prefer AEAD modes: AES-GCM or ChaCha20-Poly1305."),
]

PQ_GROUP_CANDIDATES = [
    "x25519_kyber768", "p256_kyber768", "x25519kyber768", "p256kyber768", "kyber768",
    "x25519_kyber512", "p256_kyber512", "kyber512", "x25519_kyber1024", "kyber1024",
]
PQ_SIG_ALGOS = ["dilithium2", "dilithium3", "dilithium5", "falcon512", "falcon1024"]
SEVERITY_SCORE = {"critical": 100, "high": 80, "medium": 50, "low": 20}


def is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data[:1024])
    ratio = printable / max(1, min(1024, len(data)))
    return ratio > 0.85


def read_text_safe(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            data = f.read()
        if is_probably_text(data):
            try:
                return data.decode("utf-8", errors="ignore")
            except Exception:
                return data.decode("latin-1", errors="ignore")
        return None
    except Exception:
        return None


def extract_ascii_strings(buf: bytes, min_len: int = 4) -> List[str]:
    out, current = [], bytearray()
    for b in buf:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= min_len:
                out.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= min_len:
        out.append(current.decode("ascii", errors="ignore"))
    return out


def file_language(path: Path) -> str:
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java", ".go": "go",
        ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".rs": "rust", ".rb": "ruby",
        ".php": "php", ".cs": "csharp", ".swift": "swift", ".kt": "kotlin"
    }.get(path.suffix.lower(), "unknown")


def severity_priority(sev: str) -> int:
    return SEVERITY_SCORE.get(sev, 10)


def now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


class SimulatedKMS:
    def __init__(self, key_dir: Path):
        self.key_dir = key_dir
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.priv_path = self.key_dir / "sigstore_sim_key"
        self.pub_path = self.key_dir / "sigstore_sim_key.pub"

    def _load_or_create_ed25519(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        if self.priv_path.exists():
            with open(self.priv_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            key = Ed25519PrivateKey.generate()
            priv_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(self.priv_path, "wb") as f:
                f.write(priv_pem)
            pub = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            with open(self.pub_path, "wb") as f:
                f.write(base64.b64encode(pub))
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return key, pub

    def _load_or_create_hmac(self):
        if self.priv_path.exists():
            with open(self.priv_path, "rb") as f:
                key = f.read()
        else:
            key = os.urandom(32)
            with open(self.priv_path, "wb") as f:
                f.write(key)
            with open(self.pub_path, "wb") as f:
                f.write(base64.b64encode(key))
        return key, key

    def sign(self, data: bytes) -> Dict[str, Any]:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa
            key, pub = self._load_or_create_ed25519()
            sig = key.sign(data)
            return {"algorithm": "Ed25519", "public_key": base64.b64encode(pub).decode(), "signature": base64.b64encode(sig).decode()}
        except Exception:
            import hmac, hashlib
            key, pub = self._load_or_create_hmac()
            sig = hmac.new(key, data, hashlib.sha256).digest()
            return {"algorithm": "HMAC-SHA256", "public_key": base64.b64encode(pub).decode(), "signature": base64.b64encode(sig).decode()}

    @staticmethod
    def verify_any(data: bytes, signature: Dict[str, Any]) -> bool:
        try:
            alg = signature.get("algorithm")
            pub = base64.b64decode(signature.get("public_key", ""))
            sig = base64.b64decode(signature.get("signature", ""))
            if alg == "Ed25519":
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
                return True
            if alg == "HMAC-SHA256":
                import hmac, hashlib
                expected = hmac.new(pub, data, hashlib.sha256).digest()
                return hmac.compare_digest(expected, sig)
        except Exception:
            return False
        return False


class TransparencyLog:
    def __init__(self, path: Path):
        self.path = path

    def _last_entry(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if not self.path.exists():
            return None, None
        last = None
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                last = json.loads(line)
        if last is None:
            return None, None
        return last, last.get("entry_hash")

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        import hashlib
        _, prev_hash = self._last_entry()
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        h = hashlib.sha256()
        if prev_hash:
            h.update(prev_hash.encode())
        h.update(payload)
        entry_hash = h.hexdigest()
        wrapped = {
            "entry": entry,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "timestamp": now_iso(),
            "kind": "pq_migrate_readiness",
            "version": 1,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(wrapped, sort_keys=True) + "\n")
        return wrapped

    def verify(self) -> Dict[str, Any]:
        import hashlib
        result = {"ok": True, "entries": 0, "error": None}
        prev_hash = None
        if not self.path.exists():
            return result
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    wrapped = json.loads(line)
                    entry = wrapped["entry"]
                    payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
                    h = hashlib.sha256()
                    if prev_hash:
                        h.update(prev_hash.encode())
                    h.update(payload)
                    calc = h.hexdigest()
                    if calc != wrapped["entry_hash"]:
                        result["ok"] = False
                        result["error"] = "Hash chain mismatch"
                        return result
                    if wrapped.get("prev_hash") != prev_hash:
                        result["ok"] = False
                        result["error"] = "Prev hash mismatch linkage"
                        return result
                    prev_hash = wrapped["entry_hash"]
                    result["entries"] += 1
        except Exception as e:
            result["ok"] = False
            result["error"] = str(e)
        return result


class PQMigrateAuditor:
    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if self.state_file and self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self):
        if not self.state_file:
            return
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, sort_keys=True)
        except Exception:
            pass

    def scan_repo(self, path: Path) -> Dict[str, Any]:
        print(ETHICAL_WARNING, file=sys.stderr)
        findings: List[Dict[str, Any]] = []
        inventory: Dict[str, Dict[str, Any]] = {}
        binary_hits: List[Dict[str, Any]] = []
        total_files = 0
        for root, _, files in os.walk(path):
            for fn in files:
                fp = Path(root) / fn
                total_files += 1
                try:
                    text = read_text_safe(fp)
                    if text is not None:
                        lang = file_language(fp)
                        for lineno, line in enumerate(text.splitlines(), start=1):
                            for regex, label, severity, remediation in WEAK_ALGO_PATTERNS:
                                if regex.search(line):
                                    fnd = {
                                        "file": str(fp),
                                        "line": lineno,
                                        "algorithm": label,
                                        "severity": severity,
                                        "priority": severity_priority(severity),
                                        "snippet": line.strip()[:400],
                                        "language": lang,
                                        "remediation": remediation,
                                    }
                                    findings.append(fnd)
                                    inv = inventory.setdefault(label, {"count": 0, "files": set()})
                                    inv["count"] += 1
                                    inv["files"].add(str(fp))
                    else:
                        try:
                            with open(fp, "rb") as f:
                                buf = f.read(1024 * 512)
                            strings = extract_ascii_strings(buf, min_len=4)
                            hits = []
                            for label in ["SHA1", "MD5", "RC4", "DES", "3DES", "rsaEncryption", "kyber", "dilithium"]:
                                if any(label.lower() in s.lower() for s in strings):
                                    hits.append(label)
                            if hits:
                                binary_hits.append({"file": str(fp), "hits": sorted(set(hits))})
                                for label in hits:
                                    inv = inventory.setdefault(label, {"count": 0, "files": set()})
                                    inv["count"] += 1
                                    inv["files"].add(str(fp))
                        except Exception:
                            pass
                except Exception:
                    continue
        inventory_out = {k: {"count": v["count"], "files": sorted(list(v["files"]))} for k, v in inventory.items()}
        prioritized = sorted(findings, key=lambda x: (-x["priority"], x["algorithm"], x["file"], x["line"]))
        summary = {"scanned_files": total_files, "weak_findings_count": len(prioritized), "inventory": inventory_out}
        remediation_plan = self._build_remediation_plan(prioritized)
        report = {"timestamp": now_iso(), "path": str(path), "summary": summary, "findings": prioritized, "binary_hits": binary_hits, "remediation_plan": remediation_plan}
        self.state.setdefault("last_scan", report)
        self._save_state()
        return report

    def _build_remediation_plan(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        plan: List[Dict[str, Any]] = []
        for f in findings:
            safer = f.get("remediation", "Replace with modern, PQ-ready alternatives.")
            if f["algorithm"] in ("SHA-1", "HMAC-SHA1"):
                safer = "Switch to SHA-256/512; e.g., hashlib.sha256 in Python, MessageDigest.getInstance('SHA-256') in Java."
            elif f["algorithm"] == "MD5":
                safer = "Replace with SHA-256/512; avoid MD5 for any security property."
            elif f["algorithm"] == "RSA-1024":
                safer = "Use RSA 3072+ or ECDSA P-256/Ed25519. For RSA generation, set modulusLength=3072."
            elif f["algorithm"] in ("DES", "3DES", "RC4"):
                safer = "Use AEAD ciphers: AES-256-GCM or ChaCha20-Poly1305."
            elif f["algorithm"] == "RSA-PKCS1v1.5":
                safer = "Use RSA-PSS (sign) and RSA-OAEP (encrypt) with SHA-256."
            elif "AES-CBC" in f["algorithm"]:
                safer = "Use AES-GCM or ChaCha20-Poly1305; CBC requires careful padding/oracle mitigations."
            plan.append({
                "priority": f["priority"], "severity": f["severity"], "file": f["file"], "line": f["line"],
                "issue": f["algorithm"], "snippet": f["snippet"], "recommended_fix": safer
            })
        return plan

    def probe_tls_endpoints(self, targets: List[str], timeout: int = 10) -> Dict[str, Any]:
        print(ETHICAL_WARNING, file=sys.stderr)
        results: Dict[str, Any] = {}
        for tgt in targets:
            host, port = self._parse_target(tgt)
            res = {
                "host": host, "port": port, "tls_version": None, "cipher": None, "certificate_sigalg": None,
                "pq_kem_supported": [], "errors": [], "recommendations": [], "config_templates": {}
            }
            try:
                res.update(self._tls_basic_info(host, port, timeout))
            except Exception as e:
                res["errors"].append(f"TLS handshake failed: {e}")
            pq_supported = []
            for group in PQ_GROUP_CANDIDATES:
                try:
                    ok, _ = self._openssl_probe_group(host, port, group, timeout=timeout)
                    if ok:
                        pq_supported.append(group)
                except Exception as e:
                    res["errors"].append(f"Probe error for group {group}: {e}")
            res["pq_kem_supported"] = sorted(set(pq_supported))
            if not res["pq_kem_supported"]:
                res["recommendations"].append(
                    "Hybrid PQ KEM not detected. Upgrade to OpenSSL 3.2+ with OQS provider or use a PQ-ready TLS terminator. "
                    "Enable hybrid groups (e.g., X25519+Kyber-768) with classical fallbacks."
                )
            else:
                res["recommendations"].append(
                    f"Detected hybrid KEM support: {', '.join(res['pq_kem_supported'])}. Ensure fallback to classical groups remains enabled."
                )
            res["config_templates"] = self._config_templates(host, port, res["pq_kem_supported"])
            results[f"{host}:{port}"] = res
        self.state.setdefault("last_probe", {"timestamp": now_iso(), "results": results})
        self._save_state()
        return {"timestamp": now_iso(), "results": results}

    def _parse_target(self, target: str) -> Tuple[str, int]:
        if ":" in target:
            host, port_s = target.rsplit(":", 1)
            return host.strip(), int(port_s)
        return target.strip(), 443

    def _tls_basic_info(self, host: str, port: int, timeout: int) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["tls_version"] = ssock.version()
                info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                try:
                    pem = ssl.get_server_certificate((host, port))
                    sigalg = None
                    try:
                        from cryptography import x509
                        cert = x509.load_pem_x509_certificate(pem.encode())
                        sigalg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
                    except Exception:
                        sigalg = None
                    info["certificate_sigalg"] = sigalg
                except Exception:
                    info["certificate_sigalg"] = None
        return info

    def _openssl_probe_group(self, host: str, port: int, group: str, timeout: int = 10) -> Tuple[bool, str]:
        openssl = self._which("openssl")
        if not openssl:
            return False, "OpenSSL not available on PATH"
        cmd = [openssl, "s_client", "-connect", f"{host}:{port}", "-groups", group, "-tls1_3", "-brief"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input="", check=False)
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        out = p.stdout + "\n" + p.stderr
        if p.returncode == 0 and ("Protocol is TLSv1.3" in out or "Protocol  : TLSv1.3" in out or "SSL-Session:" in out):
            if re.search(group, out, re.IGNORECASE) or "Shared" in out or "Server Temp Key" in out:
                return True, "Negotiated"
            return False, "Handshake without explicit group evidence"
        return False, "Handshake failed"

    def _which(self, prog: str) -> Optional[str]:
        for p in os.environ.get("PATH", "").split(os.pathsep):
            cand = Path(p) / prog
            if os.name == "nt":
                if cand.with_suffix(".exe").exists():
                    return str(cand.with_suffix(".exe"))
            if cand.exists():
                return str(cand)
        return None

    def _config_templates(self, host: str, port: int, pq_groups: List[str]) -> Dict[str, str]:
        groups_str = ":".join(["X25519", "P-256"] + ([pq_groups[0]] if pq_groups else ["x25519_kyber768"]))
        return {
            "openssl.cnf": f"""
# OpenSSL 3.x with OQS provider example (requires oqsprovider installed)
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect
[provider_sect]
default = default_sect
oqsprovider = oqs_sect
[default_sect]
activate = 1
[oqs_sect]
activate = 1
[ssl_sect]
system_default = tls_sect
[tls_sect]
Curves = {groups_str}
Options = ServerPreference,PrioritizeChaCha
""".strip(),
            "nginx.conf": f"""
# NGINX example (requires OpenSSL linked with OQS provider for hybrid groups)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_conf_command Curves {groups_str};
# Fallback to classical curves ensured by leading X25519,P-256
# server_name {host};
# listen {port} ssl;
""".strip(),
            "haproxy.cfg": f"""
# HAProxy example (build with OpenSSL supporting hybrid groups)
global
    tune.ssl.default-dh-param 2048
frontend https-in
    bind *:{port} ssl crt /path/to/cert.pem curves {groups_str}
    default_backend app
backend app
    server s1 127.0.0.1:8080
""".strip(),
            "policy-as-code.yaml": f"""
apiVersion: pqc.security/v1
kind: TLSPolicy
metadata:
  name: enable-hybrid-kem
spec:
  targetHosts:
    - {host}:{port}
  tls13:
    groups:
      - X25519
      - P-256
      - x25519_kyber768
    requireHybridIfSupported: true
  fallbacks:
    allowClassical: true
  rollout:
    strategy: canary
    maxUnavailable: 0
    steps:
      - weight: 1
        pauseSeconds: 600
      - weight: 10
        pauseSeconds: 900
      - weight: 50
        pauseSeconds: 1800
      - weight: 100
        pauseSeconds: 0
""".strip(),
        }

    def canary_plan(self, targets: List[str]) -> Dict[str, Any]:
        plan = {
            "timestamp": now_iso(),
            "strategy": "staged-canary",
            "ethics": ETHICAL_WARNING,
            "steps": [
                {"stage": "Prepare", "actions": [
                    "Back up current TLS config.",
                    "Deploy OpenSSL 3.2+ with oqsprovider to staging.",
                    "Generate PQ-ready certificates if required (classical signatures acceptable; PQ signatures optional).",
                    "Ensure monitoring (latency, error rate, handshake failures) and alerting are in place.",
                ]},
                {"stage": "Stage 1", "traffic_percent": 1, "duration_minutes": 10, "actions": [
                    "Enable hybrid KEM groups alongside X25519/P-256.",
                    "Monitor handshake failures, CPU, and latency.",
                ]},
                {"stage": "Stage 2", "traffic_percent": 10, "duration_minutes": 15, "actions": [
                    "Expand to 10% traffic. Continue monitoring.",
                ]},
                {"stage": "Stage 3", "traffic_percent": 50, "duration_minutes": 30, "actions": [
                    "Expand to 50% traffic. Verify compatibility with major clients.",
                ]},
                {"stage": "Stage 4", "traffic_percent": 100, "duration_minutes": 0, "actions": [
                    "Full rollout. Retain classical fallbacks.",
                    "Document changes and update policy-as-code repository.",
                ]},
                {"stage": "Post-Rollout", "actions": [
                    "Re-run PQ-Migrate Auditor probe to confirm hybrid support.",
                    "Create a signed readiness report and append to transparency log.",
                ]},
            ],
            "targets": targets,
        }
        self.state.setdefault("last_canary_plan", plan)
        self._save_state()
        return plan

    def generate_report(self, scan_report: Dict[str, Any], probe_report: Dict[str, Any]) -> Dict[str, Any]:
        readiness = {
            "timestamp": now_iso(),
            "readiness_level": self._assess_readiness(scan_report, probe_report),
            "summary": {
                "weak_findings": scan_report["summary"]["weak_findings_count"],
                "pq_tls_supported_targets": sum(1 for r in probe_report["results"].values() if r["pq_kem_supported"]),
                "total_targets": len(probe_report["results"]),
            },
            "scan": scan_report,
            "probe": probe_report,
            "ethics": ETHICAL_WARNING,
        }
        self.state.setdefault("last_readiness_report", readiness)
        self._save_state()
        return readiness

    def _assess_readiness(self, scan: Dict[str, Any], probe: Dict[str, Any]) -> str:
        weak = scan["summary"]["weak_findings_count"]
        pq_targets = sum(1 for r in probe["results"].values() if r["pq_kem_supported"])
        if weak == 0 and pq_targets == len(probe["results"]) and pq_targets > 0:
            return "ready"
        if weak < 5 and pq_targets >= max(1, len(probe["results"]) // 2):
            return "progressing"
        return "needs-remediation"

    def sign_and_log_report(self, readiness_report: Dict[str, Any], log_path: Path, key_dir: Path) -> Dict[str, Any]:
        kms = SimulatedKMS(key_dir)
        payload_bytes = json.dumps(readiness_report, sort_keys=True).encode()
        signature = kms.sign(payload_bytes)
        entry = {"report": readiness_report, "signature": signature, "signing_method": "sigstore-simulated"}
        wrapped = TransparencyLog(log_path).append(entry)
        return wrapped

    def verify_transparency_log(self, log_path: Path) -> Dict[str, Any]:
        tlog = TransparencyLog(log_path)
        chain_result = tlog.verify()
        result = {"hash_chain_ok": chain_result["ok"], "entries": chain_result["entries"], "signature_checks": []}
        if not chain_result["ok"]:
            result["error"] = chain_result["error"]
            return result
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    wrapped = json.loads(line)
                    entry = wrapped.get("entry", {})
                    signature = entry.get("signature", {})
                    report = entry.get("report", {})
                    payload_bytes = json.dumps(report, sort_keys=True).encode()
                    ok = SimulatedKMS.verify_any(payload_bytes, signature)
                    result["signature_checks"].append({"timestamp": wrapped.get("timestamp"), "ok": ok})
        except Exception as e:
            result["error"] = str(e)
        return result


def parse_targets_arg(arg: str) -> List[str]:
    if not arg:
        return []
    p = Path(arg)
    if p.exists() and p.is_file():
        with open(p, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return [x.strip() for x in arg.split(",") if x.strip()]


def main():
    parser = argparse.ArgumentParser(prog="pq-migrate-auditor", description="PQ-Migrate Auditor: Post-Quantum Readiness Scanner & TLS Hybrid Probe")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Static and binary analysis of a repository or path")
    p_scan.add_argument("--path", required=True, help="Path to repository root")
    p_scan.add_argument("--state-file", help="State file to track changes")
    p_scan.add_argument("--out", help="Write scan report JSON to file")

    p_probe = sub.add_parser("probe", help="Probe TLS endpoints for PQ/hybrid KEM support")
    p_probe.add_argument("--targets", required=True, help="Comma-separated host:port list or file path")
    p_probe.add_argument("--state-file", help="State file to track changes")
    p_probe.add_argument("--out", help="Write probe report JSON to file")

    p_canary = sub.add_parser("canary-plan", help="Generate a staged canary rollout plan")
    p_canary.add_argument("--targets", required=True, help="Comma-separated host:port list or file path")
    p_canary.add_argument("--state-file", help="State file to track changes")
    p_canary.add_argument("--out", help="Write canary plan JSON to file")

    p_report = sub.add_parser("report", help="Generate and sign a PQ-readiness report and append to a transparency log")
    p_report.add_argument("--path", required=True, help="Path to repository root")
    p_report.add_argument("--targets", required=True, help="Comma-separated host:port list or file path")
    p_report.add_argument("--log", required=True, help="Path to transparency log JSONL file")
    p_report.add_argument("--state-file", help="State file to track changes")
    p_report.add_argument("--key-dir", help="Directory for simulated KMS keys (default ~/.pq_migrate_auditor)")
    p_report.add_argument("--out", help="Write readiness report JSON to file")

    p_verify = sub.add_parser("verify-log", help="Verify transparency log integrity and signatures")
    p_verify.add_argument("--log", required=True, help="Path to transparency log JSONL file")

    args = parser.parse_args()

    state_file = Path(args.state_file) if getattr(args, "state_file", None) else None
    auditor = PQMigrateAuditor(state_file=state_file)

    if args.cmd == "scan":
        path = Path(args.path).resolve()
        rep = auditor.scan_repo(path)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(rep, f, indent=2)
        else:
            print(json.dumps(rep, indent=2))
    elif args.cmd == "probe":
        targets = parse_targets_arg(args.targets)
        rep = auditor.probe_tls_endpoints(targets)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(rep, f, indent=2)
        else:
            print(json.dumps(rep, indent=2))
    elif args.cmd == "canary-plan":
        targets = parse_targets_arg(args.targets)
        plan = auditor.canary_plan(targets)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(plan, f, indent=2)
        else:
            print(json.dumps(plan, indent=2))
    elif args.cmd == "report":
        path = Path(args.path).resolve()
        targets = parse_targets_arg(args.targets)
        scan = auditor.scan_repo(path)
        probe = auditor.probe_tls_endpoints(targets)
        readiness = auditor.generate_report(scan, probe)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(readiness, f, indent=2)
        else:
            print(json.dumps(readiness, indent=2))
        key_dir = Path(args.key_dir) if args.key_dir else (Path.home() / ".pq_migrate_auditor")
        log_path = Path(args.log)
        wrapped = auditor.sign_and_log_report(readiness, log_path, key_dir)
        print(json.dumps({"transparency_log_entry": wrapped}, indent=2))
    elif args.cmd == "verify-log":
        log_path = Path(args.log)
        result = auditor.verify_transparency_log(log_path)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        sys.exit(130)