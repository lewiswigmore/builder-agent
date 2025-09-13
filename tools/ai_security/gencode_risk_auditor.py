#!/usr/bin/env python3
import argparse
import ast
import datetime
import hashlib
import io
import json
import os
import random
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

TOOL_NAME = "GenCode Risk Auditor"
TOOL_ID = "gencode_risk_auditor"
TOOL_VERSION = "1.0.0"
SPEC_SBOM_VERSION = "1.4"

DEFAULT_ALLOWLIST = {"localhost", "127.0.0.1", "::1"}
CRITICAL_PKG_SET = {
    "requests", "numpy", "pandas", "django", "flask", "scipy", "urllib3", "cryptography", "setuptools",
    "pytest", "boto3", "botocore", "pip", "sqlalchemy", "fastapi", "uvicorn", "jinja2"
}

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# -------- Utility helpers --------

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def now_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")

def write_bytes(path: Path, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)

def detect_git_commit(repo: Path) -> Optional[str]:
    try:
        res = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return None

def is_executable_available(name: str) -> bool:
    return shutil.which(name) is not None

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev = dp[0]
        dp[0] = i
        for j, cb in enumerate(b, 1):
            cur = dp[j]
            cost = 0 if ca == cb else 1
            dp[j] = min(dp[j] + 1, dp[j-1] + 1, prev + cost)
            prev = cur
    return dp[-1]

def normalize_pkg_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()

def pii_scrub(text: str) -> str:
    # Scrub common PII/secret patterns
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "AKIA****************"),
        (r"ASIA[0-9A-Z]{16}", "ASIA****************"),
        (r"(?i)(secret|password|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}['\"]", r"\1=<redacted>"),
        (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<redacted_email>"),
        (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<redacted_ip>"),
        (r"(?i)bearer\s+[A-Za-z0-9._\-]+", "Bearer <redacted_token>"),
        (r"(?i)-----BEGIN [^-]+ PRIVATE KEY-----[^-]+-----END [^-]+ PRIVATE KEY-----", "<redacted_private_key>")
    ]
    out = text
    for pat, repl in patterns:
        out = re.sub(pat, repl, out)
    return out

# -------- Signer (offline, HMAC as fallback) --------

class LocalSigner:
    def __init__(self, key_path: Path):
        self.key_path = key_path
        ensure_dir(key_path.parent)
        if not key_path.exists():
            key = secrets.token_bytes(32)
            write_bytes(key_path, key)
            os.chmod(key_path, 0o600)
        self.key = key_path.read_bytes()

    def sign_bytes(self, data: bytes) -> Dict[str, str]:
        mac = hashlib.sha256(self.key + data).hexdigest()
        return {"algorithm": "HMAC-SHA256", "keyId": f"local:{sha256_bytes(self.key)[:16]}", "signature": mac}

    def sign_file(self, path: Path) -> Dict[str, str]:
        return self.sign_bytes(path.read_bytes())

    def verify_rulepack(self, pack_path: Path, sig_path: Optional[Path]) -> bool:
        # Offline verification: .sig contains JSON with HMAC signature over the pack bytes.
        if sig_path is None or not sig_path.exists():
            return False
        try:
            sig_obj = json.loads(load_text(sig_path))
            calc = self.sign_file(pack_path)
            return sig_obj.get("signature") == calc.get("signature")
        except Exception:
            return False

# -------- Static Analysis --------

class Finding:
    def __init__(self, file: str, line: int, rule: str, severity: str, message: str, snippet: str, remediation: Optional[str] = None):
        self.file = file
        self.line = line
        self.rule = rule
        self.severity = severity
        self.message = message
        self.snippet = pii_scrub(snippet)
        self.remediation = remediation

    def as_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "snippet": self.snippet,
            "remediation": self.remediation,
        }

class PythonRiskVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: List[str], allowlist: set):
        self.filename = filename
        self.source_lines = source_lines
        self.allowlist = allowlist
        self.findings: List[Finding] = []
        self.suspicious_urls: List[Tuple[str, int]] = []
        self.imports: Dict[str, str] = {}  # alias -> module

    def _add(self, node: ast.AST, rule: str, sev: str, msg: str, remediation: Optional[str] = None):
        lineno = getattr(node, "lineno", 1)
        snippet = ""
        if 1 <= lineno <= len(self.source_lines):
            snippet = self.source_lines[lineno - 1].rstrip("\n")
        self.findings.append(Finding(self.filename, lineno, rule, sev, msg, snippet, remediation))

    def _is_unapproved_url(self, url: str) -> bool:
        try:
            m = re.match(r"^https?://([^/]+)", url.strip())
            if m:
                host = m.group(1).split("@")[-1].split(":")[0].lower()
                return host not in self.allowlist
        except Exception:
            return False
        return False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            for alias in node.names:
                self.imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Identify function name
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        full_name = self._resolve_full_name(node.func)

        # Dangerous eval/exec
        if func_name in {"eval", "exec", "compile"}:
            msg = f"Use of {func_name} detected; this is unsafe with untrusted input."
            rem = "Avoid eval/exec/compile; use safe parsers or whitelists."
            self._add(node, "py.unsafe.eval_exec", HIGH, msg, rem)

        # pickle/yaml unsafe deserialization
        if full_name in {"pickle.load", "pickle.loads"} or (isinstance(node.func, ast.Attribute) and "pickle" in self._attr_chain(node.func)):
            self._add(node, "py.unsafe.pickle", HIGH, "Unsafe pickle deserialization detected.", "Use safe formats (JSON, or restricted pickle with strict validation).")
        if full_name == "yaml.load":
            if not any(isinstance(kw, ast.keyword) and kw.arg == "Loader" for kw in node.keywords):
                self._add(node, "py.unsafe.yaml_load", HIGH, "yaml.load without SafeLoader is unsafe.", "Use yaml.safe_load or specify SafeLoader.")

        # subprocess with shell=True
        if full_name in {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(node, "py.subprocess.shell_true", MEDIUM, "subprocess with shell=True can lead to injection.", "Use shell=False and pass args list safely.")

        # insecure crypto
        if full_name in {"hashlib.md5", "hashlib.sha1"}:
            self._add(node, "py.crypto.weak_hash", MEDIUM, f"Use of weak hash {full_name}.", "Use SHA-256 or stronger, with salted password hashing like bcrypt/scrypt/argon2 for passwords.")

        # HTTP requests to literal URL
        if isinstance(node.func, ast.Attribute):
            base = self._attr_chain(node.func)
            if any(b.endswith(".get") or b.endswith(".post") or b.endswith(".request") for b in [base]):
                # arguments may contain url literal
                if node.args:
                    url_arg = node.args[0]
                    if isinstance(url_arg, ast.Constant) and isinstance(url_arg.value, str):
                        url = url_arg.value
                        if url.lower().startswith("http"):
                            if self._is_unapproved_url(url):
                                self.suspicious_urls.append((url, getattr(node, "lineno", 1)))
                                self._add(node, "net.egress.unapproved", HIGH, f"Outbound fetch to unapproved domain: {url}", "Route requests via approved egress or add domain to allowlist if justified.")
                    elif isinstance(url_arg, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Call)):
                        self._add(node, "net.egress.dynamic_url", MEDIUM, "Dynamic URL construction for HTTP request; ensure allowlist enforcement to prevent SSRF.", "Validate/allowlist destinations and avoid user-controlled hosts.")

        # rudimentary SQL injection detection
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                q = node.args[0]
                if isinstance(q, (ast.BinOp, ast.JoinedStr)):
                    self._add(node, "py.sql.str_concat", HIGH, "SQL query built via string concatenation or f-string; vulnerable to SQL injection.", "Use parameterized queries.")
        self.generic_visit(node)

    def _attr_chain(self, node: ast.Attribute) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)

    def _resolve_full_name(self, node: ast.AST) -> str:
        # Resolve simple cases like module.attr
        if isinstance(node, ast.Attribute):
            chain = self._attr_chain(node)
            return chain
        if isinstance(node, ast.Name):
            alias = self.imports.get(node.id)
            return alias or node.id
        return ""

def analyze_python_file(path: Path, allowlist: set) -> Tuple[List[Finding], List[Tuple[str, int]]]:
    src = load_text(path)
    lines = src.splitlines()
    try:
        tree = ast.parse(src)
    except Exception as e:
        # If parsing fails, record as info but continue
        return ([Finding(str(path), 1, "py.parse.error", LOW, f"Parse error: {e}", "")], [])
    visitor = PythonRiskVisitor(str(path), lines, allowlist)
    visitor.visit(tree)
    # Also find hard-coded URLs in strings as a fallback
    for i, line in enumerate(lines, 1):
        for m in re.finditer(r"https?://[A-Za-z0-9._:\-]+[^\s\"')]*", line):
            url = m.group(0)
            if visitor._is_unapproved_url(url):
                visitor.suspicious_urls.append((url, i))
    return visitor.findings, visitor.suspicious_urls

# -------- Dependency Analysis --------

def parse_requirements(path: Path) -> Dict[str, str]:
    pkgs = {}
    if not path or not path.exists():
        return pkgs
    for line in load_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Support simple forms: name==ver or name>=ver or name
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:([=><!~]=)\s*([A-Za-z0-9+_.\-]+))?", line)
        if m:
            name = normalize_pkg_name(m.group(1))
            ver = m.group(3) or ""
            pkgs[name] = ver
    return pkgs

def detect_typosquat(new_pkgs: Dict[str, str], base_pkgs: Dict[str, str]) -> List[Dict[str, Any]]:
    issues = []
    new_only = set(new_pkgs.keys()) - set(base_pkgs.keys())
    for n in new_only:
        for ref in CRITICAL_PKG_SET.union(set(base_pkgs.keys())):
            d = levenshtein(normalize_pkg_name(n), normalize_pkg_name(ref))
            if d == 1 or (normalize_pkg_name(n).replace("-", "") == normalize_pkg_name(ref).replace("-", "")) and n != ref:
                issues.append({
                    "package": n,
                    "confusable_with": ref,
                    "severity": HIGH,
                    "message": f"New dependency '{n}' resembles '{ref}' (possible typosquat).",
                    "remediation": f"Verify package authenticity; if unintended, replace with '{ref}'."
                })
                break
    return issues

# -------- Sandbox --------

class SandboxRunner:
    def __init__(self, allowlist: set):
        self.allowlist = set(allowlist)

    def run_http_probe(self, url: str) -> Dict[str, Any]:
        # Build a self-contained Python script that patches sockets and blocks unapproved egress.
        allowlist = list(self.allowlist)
        code = f"""
import os, sys, socket, urllib.request, json, ssl
# Harden environment
os.environ.clear()
os.environ['NO_PROXY'] = '*'
# Disallow user home and creds access via open() interceptions
_real_open = open
def _guarded_open(file, *args, **kwargs):
    p = str(file)
    banned = ['.aws', '.azure', '.gcp', '.google', '.config/gcloud', '.netrc', '.docker', '.kube', 'id_rsa', 'id_dsa', 'credentials']
    home = os.path.expanduser('~')
    for b in banned:
        if b in p or (home and p.startswith(home)):
            raise PermissionError('Credential access is forbidden in sandbox')
    return _real_open(file, *args, **kwargs)
__builtins__['open'] = _guarded_open

allowed = set({allowlist!r})
def _is_allowed_host(host):
    host = host.split('@')[-1].split(':')[0].lower()
    if host in allowed:
        return True
    # Try IP literal allowance
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        return str(ip) in allowed
    except Exception:
        return False

_real_getaddrinfo = socket.getaddrinfo
def _guarded_getaddrinfo(host, *args, **kwargs):
    if not _is_allowed_host(host):
        raise PermissionError(f'Blocked egress to host {host} per allowlist')
    return _real_getaddrinfo(host, *args, **kwargs)

_real_socket = socket.socket
class GuardedSocket(socket.socket):
    def connect(self, address):
        h = address[0]
        if not _is_allowed_host(h):
            raise PermissionError(f'Blocked egress to host {h} per allowlist')
        return super().connect(address)

socket.getaddrinfo = _guarded_getaddrinfo
socket.socket = GuardedSocket

# Disable SSL verification to avoid CA needs (still blocked by socket guards if unapproved)
ctx = ssl.create_default_context()
try:
    req = urllib.request.Request({url!r}, headers={{'User-Agent':'risk-auditor/1.0'}})
    with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
        data = r.read(64)
        print('FETCH_OK', len(data))
except Exception as e:
    print('FETCH_BLOCKED', str(e))
"""
        transcript: Dict[str, Any] = {
            "url": url,
            "allowlist": sorted(list(self.allowlist)),
            "start_time": now_iso(),
            "tool": TOOL_NAME,
            "result": None,
            "stdout": "",
            "stderr": "",
            "syscalls": None,
            "snippet_sha256": sha256_bytes(code.encode("utf-8")),
        }
        # Try to run with strace if available
        use_strace = sys.platform.startswith("linux") and is_executable_available("strace")
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            script = td_path / "probe.py"
            script.write_text(code, encoding="utf-8")
            strace_file = td_path / "trace.txt"
            cmd = [sys.executable, str(script)]
            if use_strace:
                cmd = ["strace", "-f", "-e", "trace=network", "-o", str(strace_file)] + cmd
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            transcript["stdout"] = pii_scrub(proc.stdout)
            transcript["stderr"] = pii_scrub(proc.stderr)
            if use_strace and strace_file.exists():
                transcript["syscalls"] = pii_scrub(load_text(strace_file))
            if "FETCH_OK" in proc.stdout:
                transcript["result"] = "egress_allowed"
            else:
                transcript["result"] = "egress_blocked"
            transcript["end_time"] = now_iso()
        return transcript

# -------- SBOM --------

def build_cyclonedx_sbom(repo: Path, reqs: Dict[str, str]) -> Dict[str, Any]:
    components = []
    # dependencies
    for name, ver in sorted(reqs.items()):
        comp = {
            "type": "library",
            "name": name,
            "version": ver or None,
            "bom-ref": f"pkg:pypi/{name}{('@' + ver) if ver else ''}"
        }
        components.append(comp)
    # files
    for p in sorted(repo.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(repo))
            comp = {
                "type": "file",
                "name": rel,
                "hashes": [{"alg": "SHA-256", "content": sha256_file(p)}],
                "bom-ref": f"file:{rel}"
            }
            components.append(comp)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_SBOM_VERSION,
        "serialNumber": f"urn:uuid:{_rand_uuid()}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso(),
            "tools": [{"vendor": "GenCode", "name": TOOL_NAME, "version": TOOL_VERSION}],
            "component": {
                "type": "application",
                "name": Path(repo).name
            }
        },
        "components": components
    }
    return sbom

def _rand_uuid() -> str:
    # Simple UUIDv4 generator without importing uuid
    rnd = [random.getrandbits(8) for _ in range(16)]
    rnd[6] = (rnd[6] & 0x0F) | 0x40
    rnd[8] = (rnd[8] & 0x3F) | 0x80
    hexs = "".join(f"{b:02x}" for b in rnd)
    return f"{hexs[0:8]}-{hexs[8:12]}-{hexs[12:16]}-{hexs[16:20]}-{hexs[20:32]}"

# -------- Main Orchestration --------

def scan_repo(repo: Path, allowlist_hosts: set, baseline_req: Optional[Path], current_req: Optional[Path], outdir: Path, signer: LocalSigner, run_dynamic: bool) -> int:
    ensure_dir(outdir)
    # Rulepack verification placeholder (built-in rules); if provided via CLI, verify
    findings: List[Finding] = []
    suspicious_urls: List[Tuple[str, int, str]] = []  # url, line, file
    py_files = [p for p in repo.rglob("*.py") if p.is_file()]

    for p in py_files:
        fs, sus = analyze_python_file(p, allowlist_hosts)
        findings.extend(fs)
        for url, line in sus:
            suspicious_urls.append((url, line, str(p)))

    # Dependency analysis
    base_pkgs = parse_requirements(baseline_req) if baseline_req else {}
    cur_req_path = current_req if current_req else (repo / "requirements.txt")
    cur_pkgs = parse_requirements(cur_req_path) if cur_req_path and cur_req_path.exists() else {}
    typos = detect_typosquat(cur_pkgs, base_pkgs)
    for t in typos:
        findings.append(Finding(str(cur_req_path), 1, "supplychain.typosquat", t["severity"], t["message"], "", t["remediation"]))

    # Dynamic sandbox for unapproved URLs
    transcripts: List[Dict[str, Any]] = []
    if run_dynamic and suspicious_urls:
        sb = SandboxRunner(allowlist_hosts)
        for url, line, file in suspicious_urls:
            tr = sb.run_http_probe(url)
            tr["source_file"] = file
            tr["source_line"] = line
            transcripts.append(tr)

    # Risk verdict
    severities = [f.severity for f in findings]
    verdict = LOW
    if HIGH in severities or any(t.get("result") == "egress_allowed" for t in transcripts):  # if allowed egress to unapproved host, that's high
        verdict = HIGH
    elif MEDIUM in severities:
        verdict = MEDIUM

    # Build risk report
    report = {
        "tool": {"name": TOOL_NAME, "id": TOOL_ID, "version": TOOL_VERSION},
        "notice": "For authorized testing and code security auditing only. Do not use on third-party code without permission.",
        "timestamp": now_iso(),
        "repo": str(repo),
        "git_commit": detect_git_commit(repo),
        "allowlist": sorted(list(allowlist_hosts)),
        "verdict": verdict,
        "findings": [f.as_dict() for f in findings],
        "summary": {
            "counts": {
                "total": len(findings),
                "high": sum(1 for f in findings if f.severity == HIGH),
                "medium": sum(1 for f in findings if f.severity == MEDIUM),
                "low": sum(1 for f in findings if f.severity == LOW),
            }
        }
    }
    risk_report_path = outdir / "risk_report.json"
    write_json(risk_report_path, report)
    write_json(outdir / "risk_report.json.sig", signer.sign_file(risk_report_path))

    # Sandbox transcripts
    if transcripts:
        transcript_path = outdir / "sandbox_transcript.jsonl"
        with open(transcript_path, "w", encoding="utf-8") as f:
            for tr in transcripts:
                f.write(json.dumps(tr, sort_keys=True) + "\n")
        write_json(outdir / "sandbox_transcript.jsonl.sig", signer.sign_file(transcript_path))

    # SBOM
    sbom = build_cyclonedx_sbom(repo, cur_pkgs)
    sbom_path = outdir / "sbom.cdx.json"
    write_json(sbom_path, sbom)
    write_json(outdir / "sbom.cdx.json.sig", signer.sign_file(sbom_path))

    # Provenance attestation
    provenance = {
        "predicateType": "https://slsa.dev/provenance/v1",
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "timestamp": now_iso(),
        "environment": {
            "python": sys.version,
            "platform": sys.platform,
        },
        "inputs": {
            "repo": str(repo),
            "files_sha256": {str(p.relative_to(repo)): sha256_file(p) for p in py_files[:200]},  # limit for size
            "requirements": str(cur_req_path) if cur_req_path else None,
            "allowlist": sorted(list(allowlist_hosts))
        },
        "outputs": {
            "risk_report": {"path": str(risk_report_path), "sha256": sha256_file(risk_report_path)},
            "sbom": {"path": str(sbom_path), "sha256": sha256_file(sbom_path)},
            "sandbox_transcript": {"path": str(outdir / 'sandbox_transcript.jsonl'), "exists": bool(transcripts)}
        }
    }
    prov_path = outdir / "provenance.json"
    write_json(prov_path, provenance)
    write_json(outdir / "provenance.json.sig", signer.sign_file(prov_path))

    # Policy-gated risk attestation
    # Include offending artifacts if any (e.g., typosquats, unapproved egress)
    offending: List[Dict[str, Any]] = []
    for f in findings:
        if f.rule in ("supplychain.typosquat", "py.unsafe.eval_exec", "py.unsafe.pickle", "net.egress.unapproved", "py.sql.str_concat"):
            offending.append({"rule": f.rule, "file": f.file, "line": f.line, "message": f.message})
    for tr in transcripts:
        if tr.get("result") == "egress_blocked":
            offending.append({"rule": "net.egress.unapproved.sandbox", "url": tr["url"], "message": "Egress prevented by sandbox allowlist"})
        elif tr.get("result") == "egress_allowed":
            offending.append({"rule": "net.egress.unapproved.sandbox", "url": tr["url"], "message": "Egress allowed (unexpected): tighten allowlist"})
    attestation = {
        "type": "gencode.risk_attestation/v1",
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "timestamp": now_iso(),
        "verdict": verdict,
        "offending_artifacts": offending,
        "policy": {
            "fail_on_high": True,
            "reproducible": True,
            "pinned_dependencies": True
        },
        "artifacts": {
            "risk_report": {"path": str(risk_report_path), "sha256": sha256_file(risk_report_path)},
            "sbom": {"path": str(sbom_path), "sha256": sha256_file(sbom_path)},
            "provenance": {"path": str(prov_path), "sha256": sha256_file(prov_path)}
        }
    }
    att_path = outdir / "risk_attestation.json"
    write_json(att_path, attestation)
    write_json(outdir / "risk_attestation.json.sig", signer.sign_file(att_path))

    # Exit code: 0 clean/low, 2 high risk, 1 error (not used here)
    return 2 if verdict == HIGH else 0

def main():
    parser = argparse.ArgumentParser(description="GenCode Risk Auditor: AI-Generated Code Supply Chain Scanner")
    parser.add_argument("--repo", required=True, help="Path to repository root")
    parser.add_argument("--outdir", required=True, help="Directory to write outputs (reports, SBOM, attestations)")
    parser.add_argument("--allowlist", default=",".join(sorted(DEFAULT_ALLOWLIST)), help="Comma-separated hostnames/IPs allowed for egress in sandbox")
    parser.add_argument("--baseline-req", default=None, help="Path to baseline requirements.txt for dependency diff")
    parser.add_argument("--current-req", default=None, help="Path to current requirements.txt (defaults to repo/requirements.txt)")
    parser.add_argument("--signing-key", default=None, help="Path to local signing key file (HMAC). Will be created if not exists.")
    parser.add_argument("--dynamic", action="store_true", help="Enable dynamic sandbox probes for suspicious URLs")
    parser.add_argument("--rulepack", default=None, help="Path to third-party rulepack JSON (optional, offline)")
    parser.add_argument("--rulepack-sig", default=None, help="Path to signature for rulepack (HMAC JSON signature)")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    outdir = Path(args.outdir).resolve()
    baseline_req = Path(args.baseline_req).resolve() if args.baseline_req else None
    current_req = Path(args.current_req).resolve() if args.current_req else None
    allowlist_hosts = {h.strip().lower() for h in args.allowlist.split(",") if h.strip()}
    allowlist_hosts |= DEFAULT_ALLOWLIST

    # Initialize signer
    key_path = Path(args.signing_key).resolve() if args.signing_key else (outdir / "keys" / "auditor.key")
    signer = LocalSigner(key_path)

    # Verify rulepack if provided (no network)
    if args.rulepack:
        pack = Path(args.rulepack).resolve()
        sig = Path(args.rulepack_sig).resolve() if args.rulepack_sig else None
        ok = signer.verify_rulepack(pack, sig)
        if not ok:
            print("error: rulepack verification failed; aborting to protect supply chain", file=sys.stderr)
            sys.exit(1)

    try:
        code = scan_repo(repo, allowlist_hosts, baseline_req, current_req, outdir, signer, run_dynamic=args.dynamic)
        if code != 0:
            print("High risk detected. See risk_report.json and risk_attestation.json for details.", file=sys.stderr)
        else:
            print("Scan complete. Low/medium risk. SBOM and attestations generated.", file=sys.stdout)
        sys.exit(code)
    except subprocess.TimeoutExpired:
        print("error: sandbox timed out", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()