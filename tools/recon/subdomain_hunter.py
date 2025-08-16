#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import os
import random
import re
import socket
import string
import sys
import threading
import time
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional, Set, Tuple

BANNER = """\
Subdomain Hunter - Intelligent subdomain enumeration (DNS, CT logs, search engines)
Use responsibly. Authorized testing only. Obtain explicit permission before scanning.
"""

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "common.txt")
USER_AGENT = "SubdomainHunter/1.0 (+https://security.local) Python-urllib"

# ------------- Utilities -------------


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def is_subdomain_of(host: str, base: str) -> bool:
    host = host.lower().strip(".")
    base = base.lower().strip(".")
    return host != base and host.endswith("." + base)


def valid_label(label: str) -> bool:
    # RFC-compliant label: 1-63 chars, letters/digits/hyphen, cannot start/end with hyphen
    if not (1 <= len(label) <= 63):
        return False
    if not re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", label):
        return False
    return True


def valid_hostname(host: str) -> bool:
    host = host.strip(".")
    if len(host) > 253:
        return False
    labels = host.split(".")
    return all(valid_label(lbl) for lbl in labels)


def normalize_host(h: str) -> str:
    return h.lower().strip().strip(".")


def extract_subdomains(text: str, base_domain: str) -> Set[str]:
    base = re.escape(base_domain.lower().strip("."))
    # Match hostnames ending with .base_domain
    pattern = re.compile(r"(?i)(?:^|[^A-Za-z0-9_-])((?:[A-Za-z0-9-]+\.)+" + base + r")\b")
    found: Set[str] = set()
    for m in pattern.finditer(text or ""):
        host = normalize_host(m.group(1))
        if is_subdomain_of(host, base_domain) and valid_hostname(host):
            found.add(host)
    return found


def fetch_url(url: str, timeout: float = 10.0, headers: Optional[Dict[str, str]] = None) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace")
    except Exception as e:
        eprint(f"[!] HTTP error fetching {url}: {e}")
        return ""


def fetch_json(url: str, timeout: float = 10.0) -> Optional[object]:
    txt = fetch_url(url, timeout=timeout)
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception as e:
        eprint(f"[!] JSON parse error for {url}: {e}")
        return None


def chunked(iterable: Iterable, size: int):
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# ------------- DNS Resolver -------------


def resolve_host(host: str) -> Set[str]:
    # Use system resolver via getaddrinfo in a worker thread
    ips: Set[str] = set()
    try:
        # getaddrinfo may return IPv6 and IPv4
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            if ip:
                ips.add(ip)
    except Exception:
        pass
    return ips


# ------------- Hunter Core -------------


class SubdomainHunter:
    def __init__(
        self,
        domain: str,
        wordlist_path: Optional[str] = None,
        threads: int = 32,
        dns_workers: int = 64,
        request_timeout: float = 10.0,
        dns_timeout: float = 5.0,
        max_engine_results: int = 100,
        quiet: bool = False,
    ):
        self.domain = normalize_host(domain)
        self.wordlist_path = wordlist_path or DEFAULT_WORDLIST
        self.threads = max(1, threads)
        self.dns_workers = max(1, dns_workers)
        self.request_timeout = max(1.0, request_timeout)
        self.dns_timeout = max(1.0, dns_timeout)
        self.max_engine_results = max(1, max_engine_results)
        self.quiet = quiet
        self._wildcard_ips: Set[str] = set()
        self._wildcard_detected: bool = False
        self._lock = threading.Lock()

    def banner(self):
        if not self.quiet:
            print(BANNER)

    def detect_wildcard(self, attempts: int = 4) -> Tuple[bool, Set[str]]:
        rnds = []
        for _ in range(attempts):
            token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            rnds.append(f"{token}.{self.domain}")
        if not self.quiet:
            eprint("[*] Detecting wildcard DNS ...")
        ips_union: Set[str] = set()
        resolved_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(attempts, self.dns_workers)) as ex:
            futures = {ex.submit(resolve_host, host): host for host in rnds}
            for fut in concurrent.futures.as_completed(futures, timeout=self.dns_timeout * attempts + 2):
                try:
                    ips = fut.result(timeout=self.dns_timeout)
                except Exception:
                    ips = set()
                if ips:
                    resolved_count += 1
                    ips_union.update(ips)
        self._wildcard_detected = resolved_count >= 2 or (resolved_count >= 1 and len(ips_union) >= 1)
        self._wildcard_ips = ips_union
        if not self.quiet:
            if self._wildcard_detected:
                eprint(f"[!] Wildcard detected. IPs: {', '.join(sorted(self._wildcard_ips)) or 'unknown'}")
            else:
                eprint("[*] No wildcard detected.")
        return self._wildcard_detected, set(self._wildcard_ips)

    def read_wordlist(self) -> List[str]:
        words: List[str] = []
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip()
                    if not w or w.startswith("#"):
                        continue
                    if re.match(r"^[A-Za-z0-9-_.]+$", w):
                        words.append(w)
        except Exception as e:
            eprint(f"[!] Failed to read wordlist '{self.wordlist_path}': {e}")
        return words

    def brute_force(self, words: List[str]) -> Set[str]:
        if not words:
            return set()
        candidates: Set[str] = set()
        for w in words:
            # allow nested entries like "dev.api"
            host = normalize_host(f"{w}.{self.domain}")
            if is_subdomain_of(host, self.domain) and valid_hostname(host):
                candidates.add(host)
        if not self.quiet:
            eprint(f"[*] Brute force candidates: {len(candidates)}")
        return self.verify_subdomains(candidates)

    def verify_subdomains(self, hosts: Set[str]) -> Set[str]:
        if not hosts:
            return set()
        verified: Set[str] = set()
        ipmap: Dict[str, Set[str]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.dns_workers) as ex:
            futures = {ex.submit(resolve_host, h): h for h in hosts}
            for fut in concurrent.futures.as_completed(futures, timeout=self.dns_timeout * len(hosts) + 5):
                host = futures[fut]
                try:
                    ips = fut.result(timeout=self.dns_timeout)
                except Exception:
                    ips = set()
                if ips:
                    ipmap[host] = ips
        # Wildcard filtering
        for host, ips in ipmap.items():
            if self._wildcard_detected and ips and ips.issubset(self._wildcard_ips):
                continue
            verified.add(host)
        return verified

    def from_crt_sh(self) -> Set[str]:
        q = urllib.parse.quote(f"%.{self.domain}")
        url = f"https://crt.sh/?q={q}&output=json"
        if not self.quiet:
            eprint("[*] Querying crt.sh ...")
        data = fetch_json(url, timeout=self.request_timeout)
        results: Set[str] = set()
        if isinstance(data, list):
            for entry in data:
                name_val = entry.get("name_value") if isinstance(entry, dict) else None
                if not name_val:
                    continue
                for line in str(name_val).splitlines():
                    host = normalize_host(line.replace("*.", ""))
                    if is_subdomain_of(host, self.domain) and valid_hostname(host):
                        results.add(host)
        else:
            # Sometimes HTML is returned; try extracting from text
            txt = fetch_url(url, timeout=self.request_timeout)
            results |= extract_subdomains(txt, self.domain)
        return results

    def from_certspotter(self) -> Set[str]:
        url = (
            "https://api.certspotter.com/v1/issuances?"
            + urllib.parse.urlencode(
                {
                    "domain": self.domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                }
            )
        )
        if not self.quiet:
            eprint("[*] Querying Cert Spotter ...")
        data = fetch_json(url, timeout=self.request_timeout)
        results: Set[str] = set()
        if isinstance(data, list):
            for entry in data:
                names = entry.get("dns_names") if isinstance(entry, dict) else None
                if not names:
                    continue
                for n in names:
                    host = normalize_host(str(n).replace("*.", ""))
                    if is_subdomain_of(host, self.domain) and valid_hostname(host):
                        results.add(host)
        return results

    def from_search_engines(self, pages: int = 3) -> Set[str]:
        # Use DuckDuckGo and Bing HTML. Respect gentle limits, handle errors/timeouts.
        results: Set[str] = set()
        headers = {"Accept-Language": "en-US,en;q=0.9"}
        ddg_base = "https://duckduckgo.com/html/"
        bing_base = "https://www.bing.com/search"
        q = f"site:{self.domain} -www.{self.domain}"
        per_page = max(1, min(50, self.max_engine_results // 2))
        if not self.quiet:
            eprint("[*] Dorking search engines (DDG, Bing) ...")
        # DuckDuckGo
        for i in range(pages):
            params = {"q": q, "s": str(i * 50)}
            url = f"{ddg_base}?{urllib.parse.urlencode(params)}"
            html = fetch_url(url, timeout=self.request_timeout, headers=headers)
            results |= extract_subdomains(html, self.domain)
            if len(results) >= self.max_engine_results:
                break
        # Bing
        for i in range(pages):
            params = {"q": q, "first": str(i * 10 + 1)}
            url = f"{bing_base}?{urllib.parse.urlencode(params)}"
            html = fetch_url(url, timeout=self.request_timeout, headers=headers)
            results |= extract_subdomains(html, self.domain)
            if len(results) >= self.max_engine_results:
                break
        # Trim to limit
        if len(results) > self.max_engine_results:
            results = set(list(results)[: self.max_engine_results])
        return results

    def run(self) -> Set[str]:
        self.banner()
        if not re.match(r"^[A-Za-z0-9.-]+$", self.domain) or self.domain.count(".") < 1:
            eprint("[!] Invalid domain provided.")
            return set()

        # Wildcard detection
        self.detect_wildcard()

        # Collect candidates
        candidates: Set[str] = set()
        # Certificate Transparency sources
        try:
            candidates |= self.from_crt_sh()
        except Exception as e:
            eprint(f"[!] crt.sh error: {e}")
        try:
            candidates |= self.from_certspotter()
        except Exception as e:
            eprint(f"[!] Cert Spotter error: {e}")
        # Search Engines
        try:
            candidates |= self.from_search_engines()
        except Exception as e:
            eprint(f"[!] Search engine error: {e}")
        # Wordlist brute force
        words = self.read_wordlist()
        try:
            brute_verified = self.brute_force(words)
            candidates |= brute_verified
        except Exception as e:
            eprint(f"[!] Brute force error: {e}")

        # Validate and verify all candidates (final)
        candidates = {h for h in candidates if is_subdomain_of(h, self.domain) and valid_hostname(h)}
        final = self.verify_subdomains(candidates)

        # Output
        if not self.quiet:
            eprint(f"[*] Discovered subdomains (filtered): {len(final)}")
        for h in sorted(final):
            print(h)
        return final


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Subdomain Hunter - Intelligent subdomain enumeration (DNS, CT logs, search engines)"
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain (authorized testing only)")
    p.add_argument(
        "-w",
        "--wordlist",
        default=DEFAULT_WORDLIST,
        help=f"Wordlist for DNS brute force (default: {DEFAULT_WORDLIST})",
    )
    p.add_argument("-t", "--threads", type=int, default=32, help="Worker threads for HTTP tasks (unused placeholder)")
    p.add_argument("--dns-workers", type=int, default=64, help="Concurrent DNS worker threads")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout (seconds)")
    p.add_argument("--dns-timeout", type=float, default=5.0, help="DNS resolve wait per task (seconds)")
    p.add_argument("--engine-limit", type=int, default=100, help="Maximum subdomains to extract from search engines")
    p.add_argument("--quiet", action="store_true", help="Suppress banner and progress to stderr")
    return p


def main():
    args = build_arg_parser().parse_args()
    hunter = SubdomainHunter(
        domain=args.domain,
        wordlist_path=args.wordlist,
        threads=args.threads,
        dns_workers=args.dns_workers,
        request_timeout=args.timeout,
        dns_timeout=args.dns_timeout,
        max_engine_results=args.engine_limit,
        quiet=args.quiet,
    )
    try:
        hunter.run()
    except KeyboardInterrupt:
        eprint("\n[!] Interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()