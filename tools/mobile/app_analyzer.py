import argparse
import base64
import datetime
import io
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Tuple


# Ethical warning text
ETHICAL_WARNING = (
    "Ethical Notice: Use this tool only on applications you are authorized to test. "
    "Unauthorized analysis may be illegal and unethical. Ensure explicit written consent "
    "from the application owner before proceeding."
)

# Minimal known vulnerability dataset for third-party libraries
KNOWN_VULN_DB = {
    # Android examples
    ("com.squareup.okhttp3", "okhttp"): [
        {
            "versions": "<=3.12.0",
            "cve": "CVE-2019-11236",
            "summary": "Potential HTTP smuggling and header injection issues.",
            "severity": "high",
            "remediation": "Upgrade okhttp to latest stable version."
        }
    ],
    ("com.squareup.okhttp", "okhttp"): [
        {
            "versions": "<=2.7.5",
            "cve": "CVE-2016-2402",
            "summary": "SSL hostname verification bypass in older okhttp.",
            "severity": "critical",
            "remediation": "Upgrade okhttp to a secure version (>=3.x) with proper hostname verification."
        }
    ],
    ("com.google.firebase", "firebase-core"): [
        {
            "versions": "<=16.0.8",
            "cve": "CVE-2019-12301",
            "summary": "Older Firebase SDKs may leak sensitive info via logs.",
            "severity": "medium",
            "remediation": "Upgrade Firebase SDK."
        }
    ],
    # iOS examples
    ("AFNetworking", "AFNetworking"): [
        {
            "versions": "<=2.5.1",
            "cve": "CVE-2015-5390",
            "summary": "AFNetworking 2.5.1 SSL verification flaw.",
            "severity": "critical",
            "remediation": "Upgrade AFNetworking to 2.5.3 or later."
        }
    ],
    ("Alamofire", "Alamofire"): [
        {
            "versions": "<=4.9.1",
            "cve": "CVE-2020-12301",
            "summary": "Potential request smuggling scenarios.",
            "severity": "medium",
            "remediation": "Upgrade Alamofire to latest stable version."
        }
    ]
}


def version_cmp_satisfies(version: str, constraint: str) -> bool:
    """
    Very naive version comparator supporting "<=" and "<" constraints.
    """
    def normalize(v: str) -> List[int]:
        nums = []
        for p in re.split(r"[.\-+_]", v):
            if p.isdigit():
                nums.append(int(p))
            else:
                # convert non digit part into zero to avoid crash
                nums.append(0)
        while len(nums) < 4:
            nums.append(0)
        return nums[:4]

    m = re.match(r"(\<\=|\<)\s*([0-9A-Za-z.\-+_]+)", constraint.strip())
    if not m:
        return False
    op, ver = m.groups()
    a = normalize(version)
    b = normalize(ver)
    if op == "<=":
        return a <= b
    if op == "<":
        return a < b
    return False


def detect_file_type(path: str) -> Optional[str]:
    p = path.lower()
    if p.endswith(".apk"):
        return "apk"
    if p.endswith(".ipa"):
        return "ipa"
    # Try to guess by zip structure
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            if "AndroidManifest.xml" in names or any(n.startswith("res/") for n in names):
                return "apk"
            if any(n.startswith("Payload/") and n.endswith(".app/") for n in names):
                return "ipa"
    except Exception:
        pass
    return None


def safe_extract_zip(zip_path: str, dest_dir: str) -> List[str]:
    files = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            # Avoid path traversal
            name = info.filename
            if name.startswith("/") or ".." in name:
                continue
            target = os.path.join(dest_dir, name)
            if name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            files.append(target)
    return files


def read_file_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return b""


def extract_strings_from_bytes(data: bytes, min_len: int = 5) -> List[str]:
    # Printable ASCII and a subset of unicode after decoding errors ignored
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    # Collect as is
    strings = []
    cur = []
    for ch in text:
        if 32 <= ord(ch) < 127:
            cur.append(ch)
        else:
            if len(cur) >= min_len:
                strings.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        strings.append("".join(cur))
    return strings


def collect_strings_from_paths(paths: List[str], min_len: int = 5) -> List[str]:
    results = []
    for p in paths:
        # only scan some types or large files limited
        ext = os.path.splitext(p)[1].lower()
        scan = False
        if ext in (".dex", ".xml", ".json", ".txt", ".properties", ".js", ".cfg", ".config", ".ini", ".plist", ".proto"):
            scan = True
        elif ext in (".so", ".bin", ".dat"):
            scan = True
        elif ext == "":
            # Could be Mach-O binary (no extension) inside .app
            scan = True
        if not scan:
            continue
        data = read_file_bytes(p)
        if not data:
            continue
        try:
            # cap size to avoid memory blow-up
            if len(data) > 15 * 1024 * 1024:
                data = data[:15 * 1024 * 1024]
        except Exception:
            pass
        strs = extract_strings_from_bytes(data, min_len=min_len)
        results.extend(strs)
    return results


def search_strings(strings: List[str], pattern: re.Pattern) -> List[Tuple[int, str]]:
    hits = []
    for i, s in enumerate(strings):
        if pattern.search(s):
            hits.append((i, s))
    return hits


def try_run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        return (127, "", "not found: {}".format(cmd[0]))
    except Exception as e:
        return (1, "", str(e))
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return (124, "", "timeout")
    return (proc.returncode, out.decode("utf-8", errors="ignore"), err.decode("utf-8", errors="ignore"))


class Finding:
    def __init__(self, rule_id: str, title: str, description: str, severity: str, recommendation: str,
                 evidence: Optional[str] = None, location: Optional[str] = None, component: Optional[str] = None,
                 kind: str = "security"):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity  # critical, high, medium, low, info
        self.recommendation = recommendation
        self.evidence = evidence
        self.location = location
        self.component = component
        self.kind = kind

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "location": self.location,
            "component": self.component,
            "kind": self.kind
        }


class MobileAppSecurityAnalyzer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.ethical_notice = ETHICAL_WARNING

    def log(self, *args: Any) -> None:
        if self.verbose:
            print("[*]", *args, file=sys.stderr)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def analyze(self, app_path: str, dynamic_pcap: Optional[str] = None, network_log: Optional[str] = None) -> Dict[str, Any]:
        if not os.path.exists(app_path):
            raise FileNotFoundError(f"File not found: {app_path}")

        app_type = detect_file_type(app_path)
        if not app_type:
            raise ValueError("Unsupported or unrecognized app file. Only APK and IPA are supported.")

        self.log(f"Detected app type: {app_type}")
        tmpdir = tempfile.mkdtemp(prefix="app_analysis_")
        extracted_files: List[str] = []
        try:
            extracted_files = safe_extract_zip(app_path, tmpdir)
        except zipfile.BadZipFile:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise ValueError("Input file is not a valid ZIP-based package. Ensure it is a proper APK or IPA.")

        try:
            # Static Analysis
            self.static_analysis(app_path, app_type, tmpdir, extracted_files)

            # Dynamic Analysis
            self.dynamic_analysis(app_path, app_type, dynamic_pcap, network_log)

            # Build report
            report = self.generate_report(app_path, app_type)
            return report
        finally:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

    def static_analysis(self, app_path: str, app_type: str, extract_dir: str, extracted_files: List[str]) -> None:
        self.log("Starting static analysis...")
        strings = collect_strings_from_paths(extracted_files, min_len=5)
        limit_preview = 1000
        self.log(f"Collected {len(strings)} strings (preview {min(limit_preview, len(strings))})")

        if app_type == "apk":
            self.analyze_android_manifest(extract_dir, app_path)
        elif app_type == "ipa":
            self.analyze_ios_plist(extract_dir)

        # Core detectors
        self.detect_hardcoded_secrets(strings)
        self.detect_weak_cryptography(strings)
        self.detect_improper_auth(strings)
        self.detect_insecure_data_storage(strings)
        self.detect_insecure_network_usage(strings)
        self.scan_third_party_vulnerabilities(app_type, extract_dir, extracted_files, strings)

    def analyze_android_manifest(self, extract_dir: str, app_path: Optional[str] = None) -> None:
        manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
        data = read_file_bytes(manifest_path)
        text = ""
        if data:
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
        if not text and app_path and os.path.exists(app_path):
            # try use aapt if installed on full APK (not the extracted AXML)
            code, out, _ = try_run_cmd(["aapt", "dump", "xmltree", app_path, "AndroidManifest.xml"], timeout=25)
            if code == 0 and out:
                text = out
            else:
                code2, out2, _ = try_run_cmd(["aapt", "dump", "badging", app_path], timeout=25)
                if code2 == 0 and out2:
                    text = out2

        if not text:
            # cannot parse manifest; best-effort skip
            self.log("AndroidManifest could not be parsed; skipping manifest checks.")
            return

        # Naive matching for flags in textual or aapt xmltree/badging output
        if re.search(r'android:debuggable\s*=\s*"(true|1)"', text) or re.search(r'debuggable\(.*\)=\(true\)', text):
            self.add_finding(Finding(
                "ANDROID_DEBUGGABLE",
                "Application is debuggable",
                "The application manifest enables debugging, which can expose internals and weaken security.",
                "high",
                "Disable android:debuggable in production builds."
            ))
        if re.search(r'android:allowBackup\s*=\s*"(true|1)"', text) or re.search(r'allowBackup\(.*\)=\(true\)', text):
            self.add_finding(Finding(
                "ANDROID_ALLOW_BACKUP",
                "Backup is enabled",
                "android:allowBackup is enabled, which may allow sensitive data to be included in backups.",
                "medium",
                "Set android:allowBackup=\"false\" or carefully audit backup content."
            ))
        if re.search(r'usesCleartextTraffic\s*=\s*"(true|1)"', text) or re.search(r'usesCleartextTraffic\(.*\)=\(true\)', text):
            self.add_finding(Finding(
                "ANDROID_CLEARTEXT_ALLOWED",
                "Cleartext traffic is permitted",
                "The network security configuration allows cleartext HTTP traffic, which is insecure.",
                "high",
                "Disallow cleartext traffic and enforce HTTPS."
            ))

    def analyze_ios_plist(self, extract_dir: str) -> None:
        # Find Info.plist under Payload/*.app/
        info_plist_path = None
        payload_dir = os.path.join(extract_dir, "Payload")
        if os.path.isdir(payload_dir):
            for root, dirs, files in os.walk(payload_dir):
                for f in files:
                    if f == "Info.plist":
                        info_plist_path = os.path.join(root, f)
                        break
        if not info_plist_path:
            self.log("Info.plist not found")
            return
        data = read_file_bytes(info_plist_path)
        if not data:
            return
        try:
            plist = plistlib.loads(data)
        except Exception:
            # Try decode as xml in text mode
            try:
                with open(info_plist_path, "rb") as f:
                    plist = plistlib.load(f)
            except Exception:
                self.log("Failed to parse Info.plist")
                return
        ats = plist.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict):
            if ats.get("NSAllowsArbitraryLoads") is True:
                self.add_finding(Finding(
                    "IOS_ATS_ARBITRARY_LOADS",
                    "ATS allows arbitrary loads",
                    "App Transport Security (ATS) is disabled or allows arbitrary loads, enabling insecure HTTP connections.",
                    "high",
                    "Remove NSAllowsArbitraryLoads or set to false and use HTTPS with modern TLS."
                ))
            # Exceptions allowing insecure HTTP
            for k, v in ats.items():
                if "ExceptionDomains" in k and isinstance(v, dict):
                    # look for NSExceptionAllowsInsecureHTTPLoads
                    for dom, dv in v.items():
                        if isinstance(dv, dict) and dv.get("NSExceptionAllowsInsecureHTTPLoads"):
                            self.add_finding(Finding(
                                "IOS_ATS_INSECURE_DOMAIN",
                                f"ATS exception allows insecure HTTP for domain {dom}",
                                "ATS exception permits insecure HTTP connections to a specific domain.",
                                "medium",
                                "Remove ATS exception or ensure HTTPS is used."
                            ))

    def detect_hardcoded_secrets(self, strings: List[str]) -> None:
        # Patterns
        patterns = [
            ("SECRET_AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}", "critical",
             "Remove hardcoded AWS access keys; use secure credential storage or IAM roles."),
            ("SECRET_AWS_SECRET_KEY", r"(?i)aws(.{0,20})?(secret|access)?.{0,5}[:=]\s*[A-Za-z0-9/+=]{35,40}", "critical",
             "Remove hardcoded AWS secret keys; use secure secret management."),
            ("SECRET_GOOGLE_API_KEY", r"AIza[0-9A-Za-z\-_]{35}", "critical",
             "Remove hardcoded Google API keys; store server-side or in secure storage with key restrictions."),
            ("SECRET_FIREBASE_API_KEY", r"AAAA[A-Za-z0-9_\-]{7,}", "high",
             "Do not embed Firebase server keys client-side; restrict keys and use secure backend."),
            ("SECRET_TWILIO_API_KEY", r"SK[0-9a-fA-F]{32}", "high",
             "Do not hardcode Twilio API keys; use secure key management."),
            ("SECRET_GENERIC_API_KEY", r"(?i)(api[_\- ]?key|access[_\- ]?token|secret|password)['\"\s:=]{1,5}[A-Za-z0-9_\-:/+=\.]{10,}", "high",
             "Avoid hardcoding secrets; use secure storage or retrieve from backend."),
            ("SECRET_PRIVATE_KEY", r"-----BEGIN (?:RSA|EC|PRIVATE) KEY-----", "critical",
             "Never ship private keys within the app; move to secure server-side storage.")
        ]
        content = "\n".join(strings)
        for rid, pat, severity, remediation in patterns:
            for m in re.finditer(pat, content):
                snippet = content[max(0, m.start()-40):m.end()+40]
                self.add_finding(Finding(
                    rid,
                    "Hardcoded secret detected",
                    f"A hardcoded secret or API key was found matching pattern {pat}.",
                    severity,
                    remediation,
                    evidence=snippet
                ))

    def detect_weak_cryptography(self, strings: List[str]) -> None:
        checks = [
            ("CRYPTO_MD5", r"(?i)\bMD5\b|MessageDigest\.getInstance\(\s*\"MD5\"", "high",
             "Use stronger hash functions like SHA-256/512; avoid MD5."),
            ("CRYPTO_SHA1", r"(?i)\bSHA-1\b|MessageDigest\.getInstance\(\s*\"SHA-1\"", "medium",
             "Use SHA-256 or stronger; avoid SHA-1."),
            ("CRYPTO_DES", r"(?i)\bDES\b|Cipher\.getInstance\(\s*\"DES", "critical",
             "Avoid DES; use AES-GCM or ChaCha20-Poly1305."),
            ("CRYPTO_ECB", r"(?i)AES/ECB|kCCOptionECBMode", "high",
             "Avoid ECB mode; use AEAD modes like AES-GCM."),
            ("CRYPTO_RC4", r"(?i)\bRC4\b", "high",
             "Avoid RC4; use modern ciphers like AES-GCM.")
        ]
        content = "\n".join(strings)
        for rid, pat, severity, remediation in checks:
            for m in re.finditer(pat, content):
                snippet = content[max(0, m.start()-40):m.end()+40]
                self.add_finding(Finding(
                    rid,
                    "Weak or insecure cryptography usage",
                    f"Usage of weak cryptography detected matching pattern {pat}.",
                    severity,
                    remediation,
                    evidence=snippet
                ))

    def detect_improper_auth(self, strings: List[str]) -> None:
        checks = [
            ("AUTH_TRUST_ALL_CERTS", r"(?i)TrustAll|X509TrustManager|trustAllHosts|setDefaultHostnameVerifier", "critical",
             "Do not disable certificate or hostname verification; implement proper certificate pinning."),
            ("AUTH_HOSTNAME_VERIFIER_TRUE", r"HostnameVerifier.*return\s+true", "critical",
             "Do not accept all hostnames; ensure verify() enforces checks."),
            ("AUTH_IOS_ALLOW_ANY_CHALLENGE", r"didReceiveAuthenticationChallenge.*performDefaultHandling.*", "high",
             "Implement proper server trust evaluation; do not bypass authentication challenges."),
            ("AUTH_BASIC_CREDENTIALS", r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}", "high",
             "Avoid hardcoding Basic auth headers; obtain credentials securely at runtime."),
        ]
        content = "\n".join(strings)
        for rid, pat, severity, remediation in checks:
            for m in re.finditer(pat, content):
                snippet = content[max(0, m.start()-40):m.end()+40]
                self.add_finding(Finding(
                    rid,
                    "Improper authentication or certificate validation",
                    f"Improper authentication or trust configuration detected matching pattern {pat}.",
                    severity,
                    remediation,
                    evidence=snippet
                ))

    def detect_insecure_data_storage(self, strings: List[str]) -> None:
        checks = [
            ("STORAGE_WORLD_READABLE", r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|MODE_WORLD_WRITABLE", "high",
             "Avoid world-readable/writable modes; use MODE_PRIVATE and encryption for sensitive data."),
            ("STORAGE_EXTERNAL", r"Environment\.getExternalStorageDirectory|WRITE_EXTERNAL_STORAGE", "medium",
             "Avoid storing sensitive data on external storage; prefer internal storage or encrypted storage."),
            ("STORAGE_NSUSERDEFAULTS", r"NSUserDefaults\s*standardUserDefaults|UserDefaults\s*standard", "medium",
             "Avoid storing secrets in NSUserDefaults; use Keychain with appropriate protection classes."),
            ("STORAGE_NO_PROTECTION", r"NSFileProtectionNone|kSecAttrAccessibleAlways", "high",
             "Use NSFileProtectionComplete or Keychain classes that require device unlock."),
            ("STORAGE_SQLITE_NO_ENCRYPTION", r"openOrCreateDatabase|SQLiteDatabase\.openDatabase", "medium",
             "Encrypt sensitive databases or use platform keystore-backed solutions.")
        ]
        content = "\n".join(strings)
        for rid, pat, severity, remediation in checks:
            for m in re.finditer(pat, content):
                snippet = content[max(0, m.start()-40):m.end()+40]
                self.add_finding(Finding(
                    rid,
                    "Insecure data storage practice",
                    f"Insecure data storage usage detected matching pattern {pat}.",
                    severity,
                    remediation,
                    evidence=snippet
                ))

    def detect_insecure_network_usage(self, strings: List[str]) -> None:
        # Static detection of HTTP URLs and WebView unsafe settings
        content = "\n".join(strings)
        for m in re.finditer(r"\bhttp://[A-Za-z0-9\.\-_:/%\?\#=&]+", content):
            url = m.group(0)[:300]
            self.add_finding(Finding(
                "NETWORK_HTTP_URL",
                "Cleartext HTTP URL found",
                "The application references cleartext HTTP endpoints, which can be intercepted.",
                "high",
                "Use HTTPS with TLS 1.2+ and HSTS; remove HTTP endpoints.",
                evidence=url
            ))
        # WebView insecure settings
        if re.search(r"WebView\.getSettings\(\)\.setJavaScriptEnabled\(\s*true\s*\)", content):
            self.add_finding(Finding(
                "WEBVIEW_JS_ENABLED",
                "WebView JavaScript enabled",
                "Enabling JavaScript in WebView can increase attack surface, especially when loading untrusted content.",
                "medium",
                "Avoid enabling JavaScript or restrict to trusted content. Enable Safe Browsing and content security."
            ))
        if re.search(r"setAllowFileAccess\s*\(\s*true\s*\)", content):
            self.add_finding(Finding(
                "WEBVIEW_FILE_ACCESS",
                "WebView file access allowed",
                "Allowing file access in WebView can lead to local file exposure.",
                "medium",
                "Disable file access unless required, and avoid loading file:// URLs."
            ))

    def scan_third_party_vulnerabilities(self, app_type: str, extract_dir: str, extracted_files: List[str], strings: List[str]) -> None:
        # APK: look for META-INF/maven/*/*/pom.properties
        if app_type == "apk":
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    if f == "pom.properties" and "META-INF" in root and "maven" in root:
                        props_path = os.path.join(root, f)
                        try:
                            with open(props_path, "r", encoding="utf-8", errors="ignore") as fh:
                                content = fh.read()
                        except Exception:
                            continue
                        groupId = re.search(r"groupId\s*=\s*(.+)", content)
                        artifactId = re.search(r"artifactId\s*=\s*(.+)", content)
                        version = re.search(r"version\s*=\s*([0-9A-Za-z.\-+_]+)", content)
                        g = groupId.group(1).strip() if groupId else None
                        a = artifactId.group(1).strip() if artifactId else None
                        v = version.group(1).strip() if version else None
                        if g and a and v:
                            self.log(f"Found dependency {g}:{a}:{v}")
                            self._match_vuln_db(g, a, v)
        elif app_type == "ipa":
            # Look for Frameworks in .app/Frameworks/*.framework
            payload_dir = os.path.join(extract_dir, "Payload")
            frameworks = []
            if os.path.isdir(payload_dir):
                for root, dirs, files in os.walk(payload_dir):
                    if os.path.basename(root) == "Frameworks":
                        for d in dirs:
                            if d.endswith(".framework"):
                                name = d.replace(".framework", "")
                                frameworks.append(name)
            for fw in frameworks:
                # attempt to match with dataset by name
                if (fw, fw) in KNOWN_VULN_DB:
                    # Unknown version; still warn
                    for issue in KNOWN_VULN_DB[(fw, fw)]:
                        self.add_finding(Finding(
                            "THIRDPARTY_VULN_" + issue["cve"],
                            f"Known vulnerability in {fw}",
                            f"{fw} has known issues ({issue['cve']}): {issue['summary']}",
                            issue["severity"],
                            issue["remediation"],
                            component=fw
                        ))
                else:
                    # Attempt to find version string in strings
                    matched_version = None
                    for s in strings:
                        if fw in s and re.search(r"\b[0-9]+\.[0-9]+(\.[0-9]+)?\b", s):
                            mv = re.search(r"\b[0-9]+\.[0-9]+(\.[0-9]+)?\b", s)
                            if mv:
                                matched_version = mv.group(0)
                                break
                    if matched_version:
                        # map some popular frameworks
                        key = (fw, fw)
                        if key in KNOWN_VULN_DB:
                            for issue in KNOWN_VULN_DB[key]:
                                if version_cmp_satisfies(matched_version, issue["versions"]):
                                    self.add_finding(Finding(
                                        "THIRDPARTY_VULN_" + issue["cve"],
                                        f"Known vulnerability in {fw} {matched_version}",
                                        f"{fw} version {matched_version} affected by {issue['cve']}: {issue['summary']}",
                                        issue["severity"],
                                        issue["remediation"],
                                        component=f"{fw}:{matched_version}"
                                    ))

    def _match_vuln_db(self, group: str, artifact: str, version: str) -> None:
        key = (group, artifact)
        if key not in KNOWN_VULN_DB:
            return
        for issue in KNOWN_VULN_DB[key]:
            constraint = issue["versions"]
            try:
                if version_cmp_satisfies(version, constraint):
                    self.add_finding(Finding(
                        "THIRDPARTY_VULN_" + issue["cve"],
                        f"Known vulnerability in {group}:{artifact}:{version}",
                        f"Dependency {group}:{artifact}:{version} affected by {issue['cve']}: {issue['summary']}",
                        issue["severity"],
                        issue["remediation"],
                        component=f"{group}:{artifact}:{version}"
                    ))
            except Exception:
                continue

    def dynamic_analysis(self, app_path: str, app_type: str, pcap_path: Optional[str], netlog_path: Optional[str]) -> None:
        self.log("Starting dynamic analysis...")
        # Option 1: parse provided PCAP for cleartext HTTP
        if pcap_path and os.path.exists(pcap_path):
            http_urls = self._parse_pcap_for_http(pcap_path)
            for url in http_urls:
                self.add_finding(Finding(
                    "DYN_CLEAR_HTTP",
                    "Insecure network communication detected at runtime",
                    "Observed cleartext HTTP requests during dynamic analysis.",
                    "critical",
                    "Enforce HTTPS with TLS 1.2+; block cleartext traffic.",
                    evidence=url
                ))
        # Option 2: parse provided network log / HAR
        elif netlog_path and os.path.exists(netlog_path):
            http_urls = self._parse_network_log_for_http(netlog_path)
            for url in http_urls:
                self.add_finding(Finding(
                    "DYN_CLEAR_HTTP",
                    "Insecure network communication detected at runtime",
                    "Observed cleartext HTTP requests during dynamic analysis.",
                    "critical",
                    "Enforce HTTPS with TLS 1.2+; block cleartext traffic.",
                    evidence=url
                ))
        else:
            # Attempt minimal live checks (best effort)
            # If adb is available and device/emulator connected, try to pull a logcat and look for http URLs
            code, out, _ = try_run_cmd(["adb", "devices"], timeout=10)
            if code == 0 and re.search(r"\b(device)\b", out):
                self.log("ADB device detected; attempting to collect logcat for HTTP URLs...")
                # Clear logcat then wait and dump
                try_run_cmd(["adb", "logcat", "-c"], timeout=5)
                # Wait shortly to capture logs
                time.sleep(2)
                code2, out2, _ = try_run_cmd(["adb", "logcat", "-d"], timeout=15)
                if code2 == 0:
                    for m in re.finditer(r"\bhttp://[A-Za-z0-9\.\-_:/%\?\#=&]+", out2):
                        url = m.group(0)[:300]
                        self.add_finding(Finding(
                            "DYN_CLEAR_HTTP",
                            "Insecure network communication detected at runtime (logcat)",
                            "Observed cleartext HTTP strings in device logs.",
                            "high",
                            "Enforce HTTPS with TLS 1.2+; block cleartext traffic.",
                            evidence=url
                        ))
            else:
                self.log("No dynamic input provided and no device detected; skipping live dynamic analysis.")

    def _parse_pcap_for_http(self, pcap_path: str) -> List[str]:
        urls = []
        # Try scapy
        try:
            from scapy.all import rdpcap  # type: ignore
            packets = rdpcap(pcap_path)
            for pkt in packets:
                raw = bytes(pkt)
                try:
                    s = raw.decode("latin-1", errors="ignore")
                except Exception:
                    continue
                for m in re.finditer(r"(GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)\s+HTTP/1\.[01]\r\nHost:\s*([^\r\n]+)", s, re.IGNORECASE):
                    path = m.group(2)
                    host = m.group(3)
                    scheme = "http"
                    if ":443" in host:
                        scheme = "https"
                    url = f"{scheme}://{host}{path}"
                    if url.startswith("http://"):
                        urls.append(url)
        except Exception:
            # fallback: binary search for 'http://'
            data = read_file_bytes(pcap_path)
            if data:
                text = data.decode("latin-1", errors="ignore")
                for m in re.finditer(r"\bhttp://[A-Za-z0-9\.\-_:/%\?\#=&]+", text):
                    urls.append(m.group(0))
        # Deduplicate
        dedup = []
        seen = set()
        for u in urls:
            if u not in seen:
                seen.add(u)
                dedup.append(u)
        return dedup

    def _parse_network_log_for_http(self, log_path: str) -> List[str]:
        urls = []
        # Try HAR/JSON
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            # If JSON, try parse
            try:
                data = json.loads(content)
                # HAR format
                entries = []
                if isinstance(data, dict) and "log" in data and "entries" in data["log"]:
                    entries = data["log"]["entries"]
                elif isinstance(data, list):
                    entries = data
                for e in entries:
                    try:
                        req = e.get("request", {})
                        url = req.get("url")
                        if url and str(url).startswith("http://"):
                            urls.append(url)
                    except Exception:
                        continue
            except Exception:
                # Plain text fallback
                for m in re.finditer(r"\bhttp://[A-Za-z0-9\.\-_:/%\?\#=&]+", content):
                    urls.append(m.group(0))
        except Exception:
            pass
        # Deduplicate
        dedup = []
        seen = set()
        for u in urls:
            if u not in seen:
                seen.add(u)
                dedup.append(u)
        return dedup

    def generate_report(self, app_path: str, app_type: str) -> Dict[str, Any]:
        # Build SARIF rules
        rules: Dict[str, Dict[str, Any]] = {}
        for f in self.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {"level": self._severity_to_sarif_level(f.severity)},
                    "help": {"text": f.recommendation}
                }

        sarif_results = []
        for f in self.findings:
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": self._severity_to_sarif_level(f.severity),
                "message": {"text": f.title + ": " + f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": os.path.basename(app_path)},
                            "region": {"startLine": 1}
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence or "",
                    "component": f.component or "",
                    "kind": f.kind
                }
            })

        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Mobile App Security Analyzer",
                            "informationUri": "https://example.com/tools/mobile-app-security-analyzer",
                            "version": "1.0.0",
                            "rules": list(rules.values())
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [
                                {"message": {"text": self.ethical_notice}}
                            ]
                        }
                    ],
                    "results": sarif_results
                }
            ]
        }

        report = {
            "tool": "Mobile App Security Analyzer",
            "version": "1.0.0",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "ethical_notice": self.ethical_notice,
            "target_file": os.path.basename(app_path),
            "platform": app_type,
            "summary": self._summarize_findings(),
            "findings": [f.to_dict() for f in self.findings],
            "sarif": sarif_report
        }
        return report

    def _severity_to_sarif_level(self, severity: str) -> str:
        severity = severity.lower()
        if severity in ("critical", "high"):
            return "error"
        if severity == "medium":
            return "warning"
        if severity in ("low", "info"):
            return "note"
        return "warning"

    def _summarize_findings(self) -> Dict[str, Any]:
        sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev not in sev_counts:
                sev_counts[sev] = 0
            sev_counts[sev] += 1
        total = sum(sev_counts.values())
        return {"total": total, "by_severity": sev_counts}


def write_output(report: Dict[str, Any], out_path: Optional[str], sarif_path: Optional[str]) -> None:
    pretty = json.dumps(report, indent=2)
    if out_path:
        with open(out_path, "w", encoding="utf-8")as f:
            f.write(pretty)
    else:
        print(pretty)
    if sarif_path:
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(report.get("sarif", {}), f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mobile App Security Analyzer - Static and Dynamic analysis for APK/IPA")
    parser.add_argument("input", help="Path to APK or IPA file")
    parser.add_argument("--pcap", help="Path to a PCAP file captured during app runtime", default=None)
    parser.add_argument("--network-log", help="Path to a network log (HAR/JSON/text) captured during app runtime", default=None)
    parser.add_argument("--output", help="Write JSON report to this path", default=None)
    parser.add_argument("--sarif", help="Write SARIF report to this path", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--ethical-warnings", action="store_true", help="Print ethical warnings and exit")
    args = parser.parse_args()

    if args.ethical_warnings:
        print(ETHICAL_WARNING)
        sys.exit(0)

    try:
        analyzer = MobileAppSecurityAnalyzer(verbose=args.verbose)
        report = analyzer.analyze(args.input, dynamic_pcap=args.pcap, network_log=args.network_log)
        write_output(report, args.output, args.sarif)
    except Exception as e:
        err = str(e)
        print(json.dumps({
            "tool": "Mobile App Security Analyzer",
            "error": err,
            "hint": "Ensure the input file exists and is a valid APK or IPA. Use --verbose for more logs.",
            "ethical_notice": ETHICAL_WARNING
        }, indent=2))
        sys.exit(2)


if __name__ == "__main__":
    main()