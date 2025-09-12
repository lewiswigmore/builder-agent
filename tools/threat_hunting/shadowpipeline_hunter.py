import asyncio
import contextlib
import dataclasses
import fnmatch
import hashlib
import json
import os
import random
import re
import shutil
import string
import sys
import time
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Ethical usage reminder
ETHICAL_WARNING = (
    "ShadowPipeline Hunter must be used only on assets you are authorized to test. "
    "Unauthorized testing may be unlawful and unethical. Proceed only with explicit permission."
)

# Optional signing backends
_SIGNING_BACKENDS = {}

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    def _ed25519_generate():
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return priv, pub_pem

    def _ed25519_sign(priv, data: bytes) -> bytes:
        return priv.sign(data)

    _SIGNING_BACKENDS["ed25519"] = ("ed25519", _ed25519_generate, _ed25519_sign)
except Exception:
    pass

try:
    import hmac

    def _hmac_generate():
        # HMAC fallback (not asymmetric). For lab/testing only.
        key = os.urandom(32)
        return key, b"HMAC-SHA256"

    def _hmac_sign(key, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    _SIGNING_BACKENDS["hmac"] = ("hmac", _hmac_generate, _hmac_sign)
except Exception:
    pass


KNOWN_CDNS = [
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "fonts.gstatic.com",
    "fonts.googleapis.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "maxcdn.bootstrapcdn.com",
    "code.jquery.com",
    "www.googletagmanager.com",
    "www.google-analytics.com",
    "connect.facebook.net",
    "static.cloudflareinsights.com",
]

DEFAULT_TIMEOUT = 35

@dataclasses.dataclass
class Finding:
    type: str
    severity: str
    description: str
    evidence: Dict[str, Any]

@dataclasses.dataclass
class RequestRecord:
    ts: float
    method: str
    url: str
    headers: Dict[str, str]
    post_data: Optional[str]
    resource_type: Optional[str]
    req_id: str

@dataclasses.dataclass
class ResponseRecord:
    ts: float
    url: str
    status: int
    status_text: str
    headers: Dict[str, str]
    body_hash: str
    body_len: int
    req_id: str

class FuzzyDomainMatcher:
    @staticmethod
    def levenshtein(a: str, b: str) -> int:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i]
            for j, cb in enumerate(b, 1):
                ins = prev[j] + 1
                dele = cur[j - 1] + 1
                sub = prev[j - 1] + (ca != cb)
                cur.append(min(ins, dele, sub))
            prev = cur
        return prev[-1]

    @staticmethod
    def suspicious(domain: str, corpus: List[str], threshold: int = 2) -> Optional[str]:
        d = domain.lower()
        best = None
        best_dist = 999
        for c in corpus:
            cc = c.lower()
            dist = FuzzyDomainMatcher.levenshtein(d, cc)
            if dist < best_dist:
                best_dist, best = dist, cc
        if best is not None and best_dist <= threshold and best != d:
            return best
        return None

def sha256_b64(data: bytes) -> str:
    # Returns hex digest of SHA-256 for integrity logging (name kept for compatibility)
    return hashlib.sha256(data).hexdigest()

def sri_hashes(data: bytes) -> Dict[str, str]:
    import base64
    return {
        "sha256": "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode(),
        "sha384": "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode(),
        "sha512": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode(),
    }

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def random_token(n=16) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def parse_csp(header: str) -> Dict[str, List[str]]:
    # Minimal CSP parse
    res = {}
    if not header:
        return res
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        segs = part.split()
        if not segs:
            continue
        k = segs[0].lower()
        res[k] = segs[1:]
    return res

def domain_allowed(domain: str, allowlist: List[str]) -> bool:
    for pat in allowlist:
        if fnmatch.fnmatch(domain, pat):
            return True
    return False

class EvidenceBundle:
    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        self.files: List[Tuple[str, str]] = []  # (relative_path, abs_path)
        self.manifest: Dict[str, Any] = {
            "tool": "ShadowPipeline Hunter",
            "category": "threat_hunting",
            "version": "1.0",
            "generated_at": now_iso(),
            "ethical_warning": ETHICAL_WARNING,
            "files": [],
            "hashes": {},
            "findings": [],
            "signing": {},
        }
        os.makedirs(out_dir, exist_ok=True)

    def add_text(self, rel_path: str, content: str):
        abs_path = os.path.join(self.out_dir, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        self.files.append((rel_path, abs_path))

    def add_bytes(self, rel_path: str, data: bytes):
        abs_path = os.path.join(self.out_dir, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "wb") as f:
            f.write(data)
        self.files.append((rel_path, abs_path))

    def add_json(self, rel_path: str, obj: Any):
        self.add_text(rel_path, json.dumps(obj, indent=2, sort_keys=True))

    def seal(self, findings: List[Finding], sign_algo: Optional[str] = None) -> str:
        # Compute hashes
        for rel, path in self.files:
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            self.manifest["hashes"][rel] = h
            self.manifest["files"].append(rel)
        # Add findings
        self.manifest["findings"] = [dataclasses.asdict(f) for f in findings]
        # Write manifest
        manifest_rel = "manifest.json"
        manifest_path = os.path.join(self.out_dir, manifest_rel)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, indent=2, sort_keys=True)
        self.files.append((manifest_rel, manifest_path))

        # Sign manifest
        chosen = None
        if sign_algo and sign_algo in _SIGNING_BACKENDS:
            chosen = _SIGNING_BACKENDS[sign_algo]
        elif "ed25519" in _SIGNING_BACKENDS:
            chosen = _SIGNING_BACKENDS["ed25519"]
        elif "hmac" in _SIGNING_BACKENDS:
            chosen = _SIGNING_BACKENDS["hmac"]

        if chosen:
            algo_name, gen, sign = chosen
            sk, pub = gen()
            with open(manifest_path, "rb") as f:
                data = f.read()
            sig = sign(sk, data)
            self.add_bytes("signature.sig", sig)
            # For HMAC, this file indicates method; for ed25519 it's actual public key
            self.add_bytes("public_key.pem", pub)
            self.manifest["signing"] = {
                "algorithm": algo_name,
                "signature_file": "signature.sig",
                "public_key_file": "public_key.pem",
            }

        # Archive
        archive = os.path.abspath(self.out_dir.rstrip("/")) + ".zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for rel, path in self.files:
                z.write(path, arcname=rel)
        return archive

class ShadowPipelineHunter:
    def __init__(self, url: str, out_dir: str, allowlist: Optional[List[str]] = None,
                 max_time: int = DEFAULT_TIMEOUT, constrained_egress: bool = True):
        self.url = url
        self.out_dir = out_dir
        self.allowlist = allowlist or []
        self.max_time = max_time
        self.constrained_egress = constrained_egress
        self.console_logs: List[Dict[str, Any]] = []
        self.request_logs: List[RequestRecord] = []
        self.response_logs: List[ResponseRecord] = []
        self.responses_body_map: Dict[str, bytes] = {}
        self.findings: List[Finding] = []
        self.canary_token = f"canary_{random_token(12)}@example.com"
        self.canary_hits: List[Dict[str, Any]] = []
        self.script_sri_map: Dict[str, Optional[str]] = {}
        self.script_html_map: Dict[str, str] = {}
        self.blocklist_enforce: List[str] = []

    async def run(self):
        print(ETHICAL_WARNING, file=sys.stderr)
        try:
            from playwright.async_api import async_playwright, TimeoutError as PWTimeout  # noqa: F401
        except Exception as e:
            raise RuntimeError("Playwright is required. Install with 'pip install playwright' and run 'playwright install'") from e

        # Analysis pass
        await self._browse(async_playwright, enforce_policy=False)

        # Validate CSP and SRI
        self._validate_csp()
        await self._validate_sri()

        # Typosquat detection
        self._check_typosquat()

        # Determine enforcement list for mismatched SRI
        self.blocklist_enforce = [u for u, integ in self.script_sri_map.items() if integ == "__SRI_MISMATCH__"]
        if self.blocklist_enforce:
            # Enforcement pass (block mismatched)
            await self._browse(async_playwright, enforce_policy=True)

        # Build evidence bundle
        bundle = EvidenceBundle(self.out_dir)
        bundle.add_text("console.log", "\n".join([json.dumps(x) for x in self._console_to_jsonlines()]))
        # Combine request/response logs into a single NDJSON stream
        pcap_lines = [json.dumps(dataclasses.asdict(r)) for r in self.request_logs] + [json.dumps(dataclasses.asdict(r)) for r in self.response_logs]
        bundle.add_text("pcap.ndjson", "\n".join(pcap_lines))
        dom_snapshot = self._dom_snapshot if hasattr(self, "_dom_snapshot") else ""
        bundle.add_text("dom_snapshot.html", dom_snapshot)
        scripts_dump = "\n<!-- scripts dump -->\n".join([f"<!-- {u} -->\n{self.script_html_map.get(u,'')}" for u in self.script_html_map])
        bundle.add_text("scripts_dump.html", scripts_dump)
        # Findings as text for quick glance
        bundle.add_text("findings.txt", "\n".join([f"{f.severity} {f.type}: {f.description}" for f in self.findings]))
        archive = bundle.seal(self.findings)
        print(f"Evidence bundle sealed and archived at: {archive}")

    async def _browse(self, async_playwright, enforce_policy: bool = False):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--disable-web-security", "--no-sandbox"])
            context = await browser.new_context(java_script_enabled=True, ignore_https_errors=False)
            page = await context.new_page()
            # Event capture
            page.on("console", lambda msg: self.console_logs.append({
                "ts": time.time(),
                "type": msg.type(),
                "text": msg.text()
            }))

            # Canary init script to expose minimal telemetry
            await page.add_init_script("""
                (function(){
                  try {
                    window.__shadowpipeline = { scripts: [] };
                    const origCreate = document.createElement.bind(document);
                    document.createElement = function(name){
                      const el = origCreate(name);
                      return el;
                    };
                  } catch(e) {}
                })();
            """)

            # Route handler for constrained egress and SRI enforcement pass
            async def route_handler(route, request):
                url = request.url
                parsed = urlparse(url)
                host = parsed.hostname or ""
                rtype = request.resource_type
                ts = time.time()
                # Egress control
                if self.constrained_egress:
                    # Allow target host and allowlist only
                    target_host = urlparse(self.url).hostname or ""
                    allowed = [target_host] + self.allowlist
                    if not domain_allowed(host, allowed):
                        # log blocked request
                        try:
                            self.request_logs.append(RequestRecord(ts=ts, method=request.method, url=url, headers=request.headers, post_data=request.post_data or None, resource_type=rtype, req_id=str(id(request))))
                        except Exception:
                            self.request_logs.append(RequestRecord(ts=ts, method=request.method, url=url, headers={}, post_data=None, resource_type=rtype, req_id=str(id(request))))
                        self.findings.append(Finding(
                            type="egress_block",
                            severity="info",
                            description=f"Blocked egress to {host} due to constrained policy",
                            evidence={"url": url}
                        ))
                        # synthesize a blocked response record for integrity trail
                        self.response_logs.append(ResponseRecord(ts=time.time(), url=url, status=0, status_text="BLOCKED (egress)", headers={}, body_hash=sha256_b64(b""), body_len=0, req_id=str(id(request))))
                        return await route.abort()

                # Enforcement pass: block known mismatched SRI scripts
                if enforce_policy and rtype == "script":
                    for blocked in self.blocklist_enforce:
                        if url.startswith(blocked):
                            await route.fulfill(status=200, headers={"Content-Type": "text/javascript"},
                                                body=b"/* Blocked by ShadowPipeline Hunter: SRI mismatch */")
                            self.findings.append(Finding(
                                type="sri_block",
                                severity="high",
                                description=f"Blocked script due to SRI mismatch: {url}",
                                evidence={"url": url}
                            ))
                            # log request and synthetic response
                            try:
                                self.request_logs.append(RequestRecord(ts=ts, method=request.method, url=url, headers=request.headers, post_data=request.post_data or None, resource_type=rtype, req_id=str(id(request))))
                            except Exception:
                                self.request_logs.append(RequestRecord(ts=ts, method=request.method, url=url, headers={}, post_data=None, resource_type=rtype, req_id=str(id(request))))
                            self.response_logs.append(ResponseRecord(ts=time.time(), url=url, status=200, status_text="OK (blocked)", headers={"Content-Type":"text/javascript"}, body_hash=sha256_b64(b""), body_len=0, req_id=str(id(request))))
                            return

                # Proceed and capture
                try:
                    self.request_logs.append(RequestRecord(ts=ts, method=request.method, url=url, headers=request.headers, post_data=request.post_data or None, resource_type=rtype, req_id=str(id(request))))
                except Exception:
                    self.request_logs.append(RequestRecord(ts=ts, method=request.method, url=url, headers={}, post_data=None, resource_type=rtype, req_id=str(id(request))))
                await route.continue_()

            await context.route("**/*", route_handler)

            # Response handling
            async def on_response(response):
                try:
                    req = response.request
                    url = response.url
                    ts = time.time()
                    status = response.status
                    status_text = response.status_text or ""
                    headers = response.headers
                    body = b""
                    # Try to capture bodies for scripts and documents and xhr/fetch
                    if req.resource_type in ("script", "document", "xhr", "fetch"):
                        with contextlib.suppress(Exception):
                            body = await response.body()
                            if body:
                                self.responses_body_map[url] = body
                    body_hash = sha256_b64(body)
                    self.response_logs.append(ResponseRecord(ts=ts, url=url, status=status, status_text=status_text, headers=headers, body_hash=body_hash, body_len=len(body or b""), req_id=str(id(req))))
                    # Canary detection: if request or response contains canary token (exfil on request is relevant)
                    pdata = req.post_data or ""
                    if self.canary_token in (pdata or "") or self.canary_token in url:
                        self.canary_hits.append({
                            "ts": ts,
                            "url": url,
                            "method": req.method,
                            "resource_type": req.resource_type,
                            "headers": req.headers,
                            "post_data_snippet": (pdata[:200] if pdata else None),
                            "status": status,
                        })
                except Exception as e:
                    self.console_logs.append({"ts": time.time(), "type": "error", "text": f"response handling error: {e}"})
            context.on("response", lambda r: asyncio.create_task(on_response(r)))

            # Navigate and interact
            try:
                await page.goto(self.url, wait_until="domcontentloaded", timeout=self.max_time * 1000)
            except Exception as e:
                self.findings.append(Finding(
                    type="navigation_error",
                    severity="high",
                    description=f"Failed to navigate: {e}",
                    evidence={"url": self.url}
                ))

            # Inject canary field into all forms
            await self._inject_canary(page)

            # Wait some time to allow scripts to run
            await page.wait_for_timeout(min(5000, self.max_time * 1000))

            # DOM snapshot and script metadata
            with contextlib.suppress(Exception):
                self._dom_snapshot = await page.content()

            # Collect script tag info
            try:
                scripts_info = await page.evaluate("""
                    () => {
                      return Array.from(document.scripts || []).map(s => ({
                        src: s.src || null,
                        integrity: s.integrity || null,
                        async: !!s.async,
                        defer: !!s.defer,
                        type: s.type || null,
                        html: s.outerHTML || null
                      }));
                    }
                """)
            except Exception:
                scripts_info = []

            for s in scripts_info:
                src = s.get("src")
                integ = s.get("integrity")
                html = s.get("html") or ""
                if src:
                    self.script_html_map[src] = html
                    if src not in self.script_sri_map:
                        self.script_sri_map[src] = integ or None

            # Close
            await context.close()
            await browser.close()

            # Analyze canary exfil
            await self._analyze_canary()

    async def _inject_canary(self, page):
        # Add canary hidden field to all forms and an unobtrusive fake value
        token = self.canary_token
        script = f"""
            (function() {{
              try {{
                const forms = Array.from(document.querySelectorAll('form'));
                for (const f of forms) {{
                  const inp = document.createElement('input');
                  inp.type = 'hidden';
                  inp.name = 'email';
                  inp.value = '{token}';
                  f.appendChild(inp);
                }}
                // simulate user typing on common fields to trigger skimmers that hook events
                const common = document.querySelector('input[type="email"], input[name*="email"]');
                if (common) {{
                   common.value = '{token}';
                   const ev = new Event('input', {{ bubbles: true }});
                   common.dispatchEvent(ev);
                }}
              }} catch(e) {{}}
            }})();
        """
        with contextlib.suppress(Exception):
            await page.evaluate(script)

    async def _analyze_canary(self):
        if self.canary_hits:
            for hit in self.canary_hits:
                host = urlparse(hit["url"]).hostname or ""
                allowed = [urlparse(self.url).hostname or ""] + self.allowlist
                sev = "high" if not domain_allowed(host, allowed) else "medium"
                self.findings.append(Finding(
                    type="magecart_exfil",
                    severity=sev,
                    description=f"Canary token exfiltration detected to {host}",
                    evidence=hit
                ))

    def _validate_csp(self):
        # Look for CSP headers in response logs for the main document
        doc_resps = [r for r in self.response_logs if r.url.startswith(self.url) and r.status == 200]
        if not doc_resps:
            return
        # The latest response headers for main document
        main_headers = {}
        for r in doc_resps:
            main_headers = r.headers
        csp_header = None
        for k, v in main_headers.items():
            if k.lower() == "content-security-policy":
                csp_header = v
                break
        policy = parse_csp(csp_header or "")
        issues = []
        script_src = policy.get("script-src", [])
        if not script_src:
            issues.append("Missing script-src directive.")
        else:
            if "'unsafe-inline'" in script_src or "*" in script_src or "'unsafe-eval'" in script_src:
                issues.append(f"Weak script-src policy: {script_src}")
        if "require-sri-for" not in policy:
            issues.append("Missing 'require-sri-for' directive for scripts.")
        if issues:
            self.findings.append(Finding(
                type="csp_policy_issue",
                severity="medium",
                description="; ".join(issues),
                evidence={"csp": csp_header or ""}
            ))

    async def _validate_sri(self):
        # For each script with integrity, compare computed hash
        for src, integ in list(self.script_sri_map.items()):
            if not integ:
                continue
            body = self.responses_body_map.get(src)
            if not body:
                # might be redirect or blocked, skip
                continue
            # Compute hashes and compare
            hashes = sri_hashes(body)
            tokens = [t.strip() for t in integ.split()] if integ else []
            match = any(hashes.get(t.split("-")[0]) == t for t in tokens if "-" in t)
            if not match:
                self.script_sri_map[src] = "__SRI_MISMATCH__"
                self.findings.append(Finding(
                    type="sri_mismatch",
                    severity="high",
                    description=f"SRI hash mismatch for {src}",
                    evidence={"declared": integ, "observed_hashes": hashes}
                ))

    def _check_typosquat(self):
        # Check domains of script requests
        seen_domains = set()
        for r in self.request_logs:
            if r.resource_type == "script":
                d = urlparse(r.url).hostname or ""
                if not d:
                    continue
                if d in seen_domains:
                    continue
                seen_domains.add(d)
                sus = FuzzyDomainMatcher.suspicious(d, KNOWN_CDNS, threshold=2)
                if sus:
                    self.findings.append(Finding(
                        type="typosquat_cdn",
                        severity="medium",
                        description=f"Domain {d} similar to known CDN {sus}",
                        evidence={"domain": d, "nearest": sus}
                    ))

    def _console_to_jsonlines(self) -> List[Dict[str, Any]]:
        return self.console_logs

def main():
    import argparse
    parser = argparse.ArgumentParser(description="ShadowPipeline Hunter: Client-Side Supply Chain Beacon Detector")
    parser.add_argument("--url", required=True, help="Target URL (authorized testing only)")
    parser.add_argument("--out", required=True, help="Output evidence directory (will be created)")
    parser.add_argument("--allow", default="", help="Comma-separated allowed egress host patterns (e.g., cdn.jsdelivr.net,*.gstatic.com)")
    parser.add_argument("--no-constrain", action="store_true", help="Disable constrained network egress (not recommended)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Max time per pass (seconds)")
    parser.add_argument("--sign", default=None, help="Signing algorithm to use (ed25519|hmac); default tries ed25519 then hmac")
    args = parser.parse_args()

    allowlist = [a.strip() for a in args.allow.split(",") if a.strip()]
    hunter = ShadowPipelineHunter(url=args.url, out_dir=args.out, allowlist=allowlist,
                                  max_time=args.timeout, constrained_egress=(not args.no_constrain))
    try:
        asyncio.run(hunter.run())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()