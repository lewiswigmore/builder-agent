#!/usr/bin/env python3
import argparse
import contextlib
import datetime
import hashlib
import io
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from typing import Dict, Iterable, List, Optional

ETHICAL_WARNING = (
    "Ethical use notice: This tool is intended for authorized security testing and research on firmware "
    "images that you own or have explicit permission to analyze. Unauthorized analysis may violate laws or "
    "terms of service. Use responsibly and comply with all applicable laws and regulations."
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

VULN_PATTERNS = [
    {"name": "OpenSSL Heartbleed", "regex": r"(OpenSSL\s*1\.0\.1[a-f]?|libssl\.so\.1\.0\.1|libcrypto\.so\.1\.0\.1)", "cves": ["CVE-2014-0160"], "severity": "high", "description": "Detected OpenSSL 1.0.1 which is affected by Heartbleed."},
    {"name": "BusyBox outdated", "regex": r"BusyBox\s*v?1\.(0|[0-1]?[0-9])(\.[0-9]+)?", "cves": ["Multiple CVEs"], "severity": "medium", "description": "Outdated BusyBox version detected; may include known vulnerabilities."},
    {"name": "uClibc outdated", "regex": r"uClibc\s*0\.(9\.(2[0-9]|3[0-1]))", "cves": ["Multiple CVEs"], "severity": "medium", "description": "Outdated uClibc version detected; may include known vulnerabilities."},
    {"name": "Dropbear outdated", "regex": r"Dropbear\b.*\b(201[0-6]|20(0[0-9]|1[0-6]))", "cves": ["Multiple CVEs"], "severity": "medium", "description": "Older Dropbear SSH versions may contain known vulnerabilities."},
]

INSECURE_FUNCTIONS = ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf(", "sscanf(", "system(", "popen(", "mktemp("]

SECRET_PATTERNS = [
    {"type": "private_key", "regex": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "severity": "critical", "description": "Private key material found in filesystem."},
    {"type": "aws_access_key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "high", "description": "AWS Access Key ID format detected."},
    {"type": "aws_secret_key", "regex": r"(?i)aws_secret_access_key[^A-Za-z0-9+/=]{0,3}([A-Za-z0-9/+=]{35,40})", "severity": "high", "description": "Potential AWS secret found."},
    {"type": "password_assignment", "regex": r"(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*([^\s\"']{3,})", "severity": "high", "description": "Hardcoded password assignment found."},
    {"type": "shadow_hash", "regex": r"^[a-zA-Z0-9_\-]+:\$[0-9]\$[^\n\r]{10,}$", "flags": re.MULTILINE, "severity": "high", "description": "Password hash entry (shadow-like) in file."},
    {"type": "default_creds", "regex": r"\b(admin|root)\s*[:=]\s*(admin|root|1234|12345|password)\b", "severity": "high", "description": "Common default credentials found."},
    {"type": "jwt_secret", "regex": r"(?i)\b(jwt_secret|secret_key|app_secret)\b\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"]", "severity": "medium", "description": "Potential application secret key found."},
]

SUSPICIOUS_SERVICE_PATTERNS = [
    {"name": "Telnet service", "regex": r"\b(telnetd|busybox\s+telnetd)\b.*(-l\s*/bin/sh|/bin/sh|/bin/ash|/bin/bash)?", "severity": "high", "description": "Telnet service invocation in init/startup scripts."},
    {"name": "Netcat shell", "regex": r"\b(nc|netcat)\b\s+(-l|--listen)\b.*(-e\s*/bin/sh|/bin/sh|/bin/ash|/bin/bash)", "severity": "critical", "description": "Netcat backdoor shell listener detected."},
    {"name": "Reverse shell", "regex": r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d{2,5}", "severity": "critical", "description": "Reverse shell pattern detected in scripts."},
    {"name": "Suspicious port", "regex": r"\b(31337|1337|2323|2222|5555)\b", "severity": "medium", "description": "Service uses non-standard or commonly abused backdoor port."},
    {"name": "Backdoor keyword", "regex": r"(?i)\bbackdoor\b", "severity": "medium", "description": "Backdoor keyword appears in configuration or script."},
    {"name": "Dropbear on unusual port", "regex": r"\bdropbear\b.*(-p\s*(1337|2323|2222|5555))", "severity": "medium", "description": "Dropbear configured on non-standard port may indicate hidden access."},
]

TEXT_FILE_EXTS = {".txt", ".conf", ".cfg", ".ini", ".sh", ".rc", ".service", ".json", ".xml", ".yaml", ".yml"}
STARTUP_PATH_HINTS = ["etc/init.d", "etc/rc.d", "etc/rcS.d", "etc/rc.local", "etc/inittab", "etc/inetd.conf", "etc/services", "etc/systemd", "init", "sbin/init", "etc/profile", "etc/rcS", "etc/rc.boot"]

MAX_FILE_SIZE_SCAN = 15 * 1024 * 1024
DEFAULT_MAX_SCAN_FILES = 20000

def safe_makedirs(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def readable_strings(data: bytes, min_len: int = 4) -> List[str]:
    s, buf = [], []
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13): buf.append(chr(b))
        else:
            if len(buf) >= min_len: s.append("".join(buf))
            buf = []
    if len(buf) >= min_len: s.append("".join(buf))
    return s

def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f: return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def is_text_file(path: str) -> bool:
    try:
        with open(path, "rb") as f: data = f.read(2048)
        if not data: return True
        printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        return printable / max(1, len(data)) > 0.9
    except Exception:
        return False

def copytree(src: str, dst: str) -> None:
    if os.path.abspath(src) == os.path.abspath(dst): return
    if os.path.isdir(src):
        if not os.path.exists(dst): safe_makedirs(dst)
        for root, dirs, files in os.walk(src):
            rel = os.path.relpath(root, src); out_dir = os.path.join(dst, rel if rel != "." else ""); safe_makedirs(out_dir)
            for d in dirs: safe_makedirs(os.path.join(out_dir, d))
            for f in files:
                src_f = os.path.join(root, f); dst_f = os.path.join(out_dir, f)
                try: shutil.copy2(src_f, dst_f)
                except Exception:
                    with contextlib.suppress(Exception): shutil.copyfile(src_f, dst_f)
    else:
        safe_makedirs(os.path.dirname(dst)); shutil.copy2(src, dst)

def is_gzip(path: str) -> bool:
    try:
        with open(path, "rb") as f: return f.read(2) == b"\x1f\x8b"
    except Exception:
        return False

def gunzip_bytes(data: bytes) -> bytes:
    import gzip
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz: return gz.read()

def try_external_binwalk_extract(fw_path: str, out_dir: str) -> Optional[str]:
    binwalk = shutil.which("binwalk")
    if not binwalk: return None
    tmpdir = tempfile.mkdtemp(prefix="binwalk_")
    try:
        cmd = [binwalk, "-e", "--directory", tmpdir, fw_path]
        logging.info("Attempting external extraction with binwalk: %s", " ".join(cmd))
        sp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
        if sp.returncode != 0:
            logging.warning("binwalk extraction failed: %s", sp.stderr.strip()); return None
        extracted = None
        for name in os.listdir(tmpdir):
            if name.endswith("_extracted"): extracted = os.path.join(tmpdir, name); break
        if not extracted or not os.path.isdir(extracted):
            candidates = [os.path.join(tmpdir, d) for d in os.listdir(tmpdir) if os.path.isdir(os.path.join(tmpdir, d))]
            if candidates: extracted = candidates[0]
        if extracted and os.path.isdir(extracted):
            dest = os.path.join(out_dir, "unpacked"); copytree(extracted, dest); return dest
    except Exception as e:
        logging.warning("External binwalk extraction error: %s", e)
    finally:
        with contextlib.suppress(Exception): shutil.rmtree(tmpdir, ignore_errors=True)
    return None

def extract_zip(fw_path: str, out_dir: str) -> Optional[str]:
    if not zipfile.is_zipfile(fw_path): return None
    dest = os.path.join(out_dir, "unpacked")
    with zipfile.ZipFile(fw_path, "r") as zf: zf.extractall(dest)
    return dest

def extract_tar(fw_path: str, out_dir: str) -> Optional[str]:
    if not tarfile.is_tarfile(fw_path): return None
    dest = os.path.join(out_dir, "unpacked")
    with tarfile.open(fw_path, "r:*") as tf: tf.extractall(dest)
    return dest

def detect_cpio_newc(data: bytes) -> bool:
    return data.startswith(b"070701")

def extract_cpio_newc_bytes(data: bytes, out_dir: str) -> str:
    pos = 0; safe_makedirs(out_dir)
    while True:
        if pos + 110 > len(data): break
        header = data[pos:pos+110]; magic = header[0:6]
        if magic != b"070701": break
        def parse_field(off, ln): return int(data[pos+off:pos+off+ln], 16)
        mode = parse_field(14, 8); mtime = parse_field(46, 8); filesize = parse_field(54, 8); namesize = parse_field(94, 8)
        pos += 110; name = data[pos:pos+namesize]; pos += namesize
        if pos % 4 != 0: pos += (4 - (pos % 4))
        name = name.rstrip(b"\x00").decode(errors="ignore")
        if name == "TRAILER!!!": break
        file_data = data[pos:pos+filesize]; pos += filesize
        if pos % 4 != 0: pos += (4 - (pos % 4))
        out_path = os.path.join(out_dir, name.lstrip("./"))
        if stat.S_ISDIR(mode) or name.endswith("/"):
            safe_makedirs(out_path)
        elif stat.S_ISLNK(mode):
            target = file_data.decode(errors="ignore"); safe_makedirs(os.path.dirname(out_path))
            with contextlib.suppress(Exception):
                if os.path.lexists(out_path): os.unlink(out_path)
            try: os.symlink(target, out_path)
            except Exception:
                with open(out_path + ".symlink", "w") as f: f.write(f"SYMLINK -> {target}\n")
        else:
            safe_makedirs(os.path.dirname(out_path))
            with open(out_path, "wb") as f: f.write(file_data)
            with contextlib.suppress(Exception): os.chmod(out_path, mode & 0o7777)
            with contextlib.suppress(Exception): ts = int(mtime); os.utime(out_path, (ts, ts))
    return out_dir

def try_extract_cpio(fw_path: str, out_dir: str) -> Optional[str]:
    try:
        with open(fw_path, "rb") as f: data = f.read()
        if is_gzip(fw_path):
            with contextlib.suppress(Exception): data = gunzip_bytes(data)
        if detect_cpio_newc(data):
            dest = os.path.join(out_dir, "unpacked"); extract_cpio_newc_bytes(data, dest); return dest
    except Exception as e:
        logging.debug("CPIO extraction error: %s", e)
    return None

def find_rootfs_candidate(base_dir: str) -> str:
    candidates = []
    for root, dirs, _ in os.walk(base_dir):
        if "etc" in dirs or "bin" in dirs or "sbin" in dirs: candidates.append(root)
    if not candidates: return base_dir
    candidates.sort(key=lambda p: (("etc" not in os.listdir(p)), len(p)))
    return candidates[0]

def walk_files(root: str, max_files: Optional[int] = None) -> Iterable[str]:
    if max_files is None: max_files = DEFAULT_MAX_SCAN_FILES
    count = 0
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name); yield path; count += 1
            if count >= max_files: return

def limit_size(path: str, max_size: int = MAX_FILE_SIZE_SCAN) -> bool:
    try: return os.path.getsize(path) <= max_size
    except Exception: return False

def scan_secrets(root: str) -> List[Dict]:
    findings = []; compiled = [(p, re.compile(p["regex"], p.get("flags", 0))) for p in SECRET_PATTERNS]
    for path in walk_files(root):
        try:
            if not limit_size(path): continue
            ext = os.path.splitext(path)[1].lower(); should_read_text = is_text_file(path) or (ext in TEXT_FILE_EXTS)
            if should_read_text:
                with open(path, "r", errors="ignore") as f: content = f.read()
                for meta, cre in compiled:
                    for m in cre.finditer(content):
                        snippet = content[max(0, m.start()-40): m.end()+40]
                        findings.append({"type": meta["type"], "file": path, "match": m.group(0)[:200], "severity": meta["severity"], "description": meta["description"], "context": snippet[:300]})
            else:
                with open(path, "rb") as f: data = f.read()
                for meta, cre in compiled:
                    if meta["type"] == "private_key" and cre.search(data.decode(errors="ignore")):
                        findings.append({"type": meta["type"], "file": path, "match": "BEGIN PRIVATE KEY", "severity": meta["severity"], "description": meta["description"]})
        except Exception as e:
            logging.debug("Secret scan error on %s: %s", path, e)
    for etc_file in ("etc/passwd", "etc/shadow"):
        candidate = os.path.join(root, etc_file)
        if os.path.exists(candidate) and limit_size(candidate):
            try:
                with open(candidate, "r", errors="ignore") as f: content = f.read()
                if "root:" in content:
                    findings.append({"type": "account_file", "file": candidate, "match": "root entry present", "severity": "info", "description": f"Found {etc_file} file with root entry."})
                if etc_file.endswith("passwd"):
                    lines = [l.strip() for l in content.splitlines() if ":" in l]
                    for l in lines:
                        parts = l.split(":")
                        if len(parts) >= 2 and parts[0] == "root" and (parts[1] == "" or parts[1] == "*"):
                            findings.append({"type": "weak_auth", "file": candidate, "match": l, "severity": "high", "description": "Root account with empty or disabled password entry."})
            except Exception: pass
    return findings

def analyze_binary_strings(path: str, data: Optional[bytes] = None) -> Dict:
    if data is None:
        with open(path, "rb") as f: data = f.read()
    strings = readable_strings(data, min_len=4)
    susp_funcs = []
    for f in INSECURE_FUNCTIONS:
        for s in strings:
            if f in s: susp_funcs.append(f); break
    vulns = []
    for pattern in VULN_PATTERNS:
        cre = re.compile(pattern["regex"]); matches = [s for s in strings if cre.search(s)]
        if matches:
            vulns.append({"name": pattern["name"], "severity": pattern["severity"], "description": pattern["description"], "cves": pattern["cves"], "evidence": matches[:5]})
    base = os.path.basename(path)
    for pattern in VULN_PATTERNS:
        if re.search(pattern["regex"], base):
            vulns.append({"name": pattern["name"], "severity": pattern["severity"], "description": pattern["description"], "cves": pattern["cves"], "evidence": [base]})
    return {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "insecure_functions": sorted(set(susp_funcs)), "vulnerabilities": vulns}

def analyze_binaries(root: str) -> List[Dict]:
    findings = []
    for path in walk_files(root):
        try:
            if not limit_size(path): continue
            if is_elf(path):
                with open(path, "rb") as f: data = f.read()
                info = analyze_binary_strings(path, data)
                if info["insecure_functions"] or info["vulnerabilities"]: findings.append(info)
            else:
                base = os.path.basename(path)
                if base.endswith(".so") or ".so." in base:
                    info = analyze_binary_strings(path)
                    if info["vulnerabilities"]: findings.append(info)
        except Exception as e:
            logging.debug("Binary analysis error on %s: %s", path, e)
    return findings

def emulate_and_detect(root: str, timeout: int = 10) -> List[Dict]:
    findings = []; compiled = [(p, re.compile(p["regex"])) for p in SUSPICIOUS_SERVICE_PATTERNS]; target_files = []
    for hint in STARTUP_PATH_HINTS:
        p = os.path.join(root, hint)
        if os.path.exists(p):
            if os.path.isdir(p):
                for dirpath, _, filenames in os.walk(p):
                    for name in filenames: target_files.append(os.path.join(dirpath, name))
            else: target_files.append(p)
    for path in walk_files(root):
        ext = os.path.splitext(path)[1].lower()
        if ext in (".sh", ".rc") or any(seg in path for seg in ("init.d", "rc.d", "rcS", "inittab")): target_files.append(path)
    seen = set()
    for path in target_files:
        if path in seen: continue
        seen.add(path)
        try:
            if not limit_size(path): continue
            with open(path, "r", errors="ignore") as f: content = f.read()
            for meta, cre in compiled:
                for m in cre.finditer(content):
                    snippet = content[max(0, m.start()-80): m.end()+80]
                    findings.append({"type": "runtime_service", "name": meta["name"], "file": path, "severity": meta["severity"], "description": meta["description"], "evidence": snippet[:400]})
        except Exception as e:
            logging.debug("Emulation scan error on %s: %s", path, e)
    return findings

class FirmwareAnalyzer:
    def __init__(self, input_path: str, output_dir: str, emulate: bool = True):
        self.input_path = os.path.abspath(input_path); self.output_dir = os.path.abspath(output_dir); self.emulate = emulate
        self.session_dir = os.path.join(self.output_dir, f"analysis_{int(time.time())}"); safe_makedirs(self.session_dir)
        self.unpacked_dir: Optional[str] = None

    def unpack_firmware(self) -> str:
        logging.info("Unpacking firmware: %s", self.input_path)
        dest = os.path.join(self.session_dir, "unpacked")
        if os.path.isdir(self.input_path):
            copytree(self.input_path, dest); self.unpacked_dir = find_rootfs_candidate(dest); return self.unpacked_dir
        for extractor in (extract_zip, extract_tar, try_extract_cpio):
            res = extractor(self.input_path, self.session_dir)
            if res: self.unpacked_dir = find_rootfs_candidate(res); return self.unpacked_dir
        res = try_external_binwalk_extract(self.input_path, self.session_dir)
        if res: self.unpacked_dir = find_rootfs_candidate(res); return self.unpacked_dir
        try:
            with open(self.input_path, "rb") as f: data = f.read()
            idx = data.find(b"070701")
            if idx != -1:
                logging.info("Found embedded cpio newc header at offset %d", idx)
                resdir = os.path.join(self.session_dir, "unpacked"); extract_cpio_newc_bytes(data[idx:], resdir)
                self.unpacked_dir = find_rootfs_candidate(resdir); return self.unpacked_dir
        except Exception: pass
        raise RuntimeError("Failed to unpack firmware. Unsupported format or missing external tools.")

    def analyze(self) -> Dict:
        if not self.unpacked_dir: self.unpack_firmware()
        root = self.unpacked_dir or self.session_dir
        logging.info("Analyzing files in %s", root)
        metas = {"input": self.input_path, "session_dir": self.session_dir, "unpacked_root": root, "timestamp": datetime.datetime.utcnow().isoformat() + "Z", "ethical_warning": ETHICAL_WARNING}
        stats = self._collect_stats(root); secrets = scan_secrets(root); binaries = analyze_binaries(root); emu = emulate_and_detect(root) if self.emulate else []
        report = {"metadata": metas, "stats": stats, "unpack_success": True, "findings": {"secrets": secrets, "binaries": binaries, "runtime": emu}, "summary": self._summarize(secrets, binaries, emu)}
        with open(os.path.join(self.session_dir, "report.json"), "w") as f: json.dump(report, f, indent=2)
        with open(os.path.join(self.session_dir, "report.txt"), "w") as f: f.write(self.format_text_report(report))
        logging.info("Analysis complete. Reports written to %s", self.session_dir)
        return report

    def _collect_stats(self, root: str) -> Dict:
        total_files = 0; total_size = 0; dirs = 0
        for dirpath, dnames, fnames in os.walk(root):
            dirs += len(dnames)
            for f in fnames:
                total_files += 1
                with contextlib.suppress(Exception): total_size += os.path.getsize(os.path.join(dirpath, f))
        return {"total_files": total_files, "total_dirs": dirs, "total_size_bytes": total_size}

    def _summarize(self, secrets: List[Dict], binaries: List[Dict], runtime: List[Dict]) -> Dict:
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        def bump(sev: str):
            sev = sev.lower(); risk_counts.setdefault(sev, 0); risk_counts[sev] += 1
        for s in secrets: bump(s.get("severity", "info"))
        for b in binaries:
            for v in b.get("vulnerabilities", []): bump(v.get("severity", "info"))
            if b.get("insecure_functions"): bump("medium")
        for r in runtime: bump(r.get("severity", "info"))
        return {"risk_counts": risk_counts, "total_findings": sum(risk_counts.values()), "notable": {"secrets": len(secrets), "binaries_with_issues": len(binaries), "runtime_indicators": len(runtime)}}

    def format_text_report(self, report: Dict) -> str:
        lines = []; meta = report.get("metadata", {})
        lines += ["IoT Device Firmware Analyzer Report", f"Input: {meta.get('input')}", f"Session: {meta.get('session_dir')}", f"Unpacked root: {meta.get('unpacked_root')}", f"Timestamp: {meta.get('timestamp')}", "", "Ethical use notice:", ETHICAL_WARNING, ""]
        stats = report.get("stats", {}); lines.append(f"Files: {stats.get('total_files', 0)}, Dirs: {stats.get('total_dirs', 0)}, Size: {stats.get('total_size_bytes', 0)} bytes"); lines.append("")
        summary = report.get("summary", {}); lines.append("Summary of risks:")
        for k, v in summary.get("risk_counts", {}).items(): lines.append(f"- {k}: {v}")
        lines.append("")
        secrets = report["findings"].get("secrets", []); lines.append(f"Secrets findings ({len(secrets)}):")
        for s in secrets[:50]: lines.append(f"- [{s.get('severity')}] {s.get('type')} in {s.get('file')}: {s.get('match')}")
        if len(secrets) > 50: lines.append(f"... and {len(secrets) - 50} more")
        lines.append("")
        binaries = report["findings"].get("binaries", []); lines.append(f"Binary findings ({len(binaries)}):")
        for b in binaries[:50]:
            lines.append(f"- {b.get('path')}:")
            if b.get("insecure_functions"): lines.append(f"  insecure functions: {', '.join(b.get('insecure_functions'))}")
            for v in b.get("vulnerabilities", [])[:3]: lines.append(f"  vuln: [{v.get('severity')}] {v.get('name')} - {v.get('description')} ({', '.join(v.get('cves', []))})")
        if len(binaries) > 50: lines.append(f"... and {len(binaries) - 50} more")
        lines.append("")
        runtime = report["findings"].get("runtime", []); lines.append(f"Runtime indicators ({len(runtime)}):")
        for r in runtime[:50]: lines.append(f"- [{r.get('severity')}] {r.get('name')} in {r.get('file')}")
        if len(runtime) > 50: lines.append(f"... and {len(runtime) - 50} more")
        lines.append(""); return "\n".join(lines)

def main():
    global DEFAULT_MAX_SCAN_FILES
    parser = argparse.ArgumentParser(prog="firmware_analyzer", description="IoT Device Firmware Analyzer - unpack, analyze, and report on IoT firmware images.")
    parser.add_argument("-i", "--input", required=True, help="Path to firmware image file or directory.")
    parser.add_argument("-o", "--output", required=False, default="fw_analysis_output", help="Output directory for analysis.")
    parser.add_argument("--no-emulate", action="store_true", help="Skip runtime/emulation analysis.")
    parser.add_argument("--json", action="store_true", help="Output report JSON to stdout.")
    parser.add_argument("--text", action="store_true", help="Output text summary to stdout.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_SCAN_FILES, help="Maximum number of files to scan.")
    args = parser.parse_args()

    print(ETHICAL_WARNING, file=sys.stderr); safe_makedirs(args.output)
    analyzer = FirmwareAnalyzer(args.input, args.output, emulate=not args.no_emulate)
    DEFAULT_MAX_SCAN_FILES = args.max_files
    try:
        report = analyzer.analyze()
    except Exception as e:
        logging.error("Analysis failed: %s", e)
        print(json.dumps({"metadata": {"input": os.path.abspath(args.input), "timestamp": datetime.datetime.utcnow().isoformat() + "Z", "ethical_warning": ETHICAL_WARNING}, "unpack_success": False, "error": str(e)}, indent=2))
        sys.exit(2)
    if args.json: print(json.dumps(report, indent=2))
    if args.text: print(analyzer.format_text_report(report))
    sys.exit(0)

if __name__ == "__main__":
    main()