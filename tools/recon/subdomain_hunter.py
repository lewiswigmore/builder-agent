#!/usr/bin/env python3
"""
Subdomain Hunter - Intelligent subdomain enumeration using multiple techniques.

Features:
- DNS brute force with common wordlists
- Certificate transparency (CT) log searching
- Search engine dorking for subdomains
- Wildcard detection and filtering
- Concurrent processing for speed

Ethical notice:
- Use this tool only on domains you are authorized to test.
- Unauthorized enumeration can be illegal and unethical.
- Respect target rate limits and terms of service for third-party providers.

Author: Security Engineering
License: For authorized testing and educational purposes only.
"""

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
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# -------------------------
# Utilities and Validation
# -------------------------

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
)

DEFAULT_WORDS = [
    # Common
    "www", "mail", "mx", "smtp", "imap", "pop", "autodiscover", "owa", "webmail",
    "ftp", "ssh", "vpn", "remote", "gateway", "status", "ns1", "ns2", "ns3",
    "cdn", "static", "assets", "img", "images", "media", "files", "uploads",
    "app", "apps", "api", "api2", "auth", "sso", "login", "portal", "admin",
    "intranet", "extranet", "internal", "proxy", "cache", "db", "sql", "mysql",
    "postgres", "backup", "dev", "dev1", "dev2", "test", "test1", "test2",
    "stage", "staging", "beta", "qa", "uat", "sandbox", "demo", "preview",
    "docs", "help", "support", "blog", "shop", "store", "payments", "pay",
    "jira", "confluence", "git", "gitlab", "bitbucket", "ci", "cd", "jenkins",
    "build", "repo", "download", "downloads", "m", "mobile", "cms", "news",
    "events", "careers", "jobs", "statuspage", "monitor", "metrics", "grafana",
    "prometheus", "kibana", "elk", "graylog", "sentry",
    # Cloud-ish
    "api-dev", "api-staging", "api-beta", "cdn1", "cdn2", "img1", "img2",
    "assets1", "assets2",
]

VALID_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def warn(msg: str) -> None:
    print(msg, file=sys.stderr)


def is_valid_hostname(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if len(host) == 0 or len(host) > 253:
        return False
    labels = host.split(".")
    return all(VALID_LABEL_RE.match(label or "") for label in labels)


def is_subdomain_of(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host.endswith("." + domain) or host == domain


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def parse_wordlist(path: Optional[str]) -> List[str]:
    words: List[str] = []
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip().lower()
                    if not w or w.startswith("#"):
                        continue
                    # label must be valid DNS label
                    if VALID_LABEL_RE.match(w):
                        words.append(w)
        except FileNotFoundError:
            warn(f"[!] Wordlist not found: {path}, using built-in defaults.")
        except Exception as e:
            warn(f"[!] Failed to read wordlist '{path}': {e}. Using built-in defaults.")
    if not words:
        words = list(dict.fromkeys(DEFAULT_WORDS))
    return words


# -------------------------
# DNS Resolution
# -------------------------

def _getaddrinfo_threadsafe(host: str) -> List[Tuple]:
    # Do not set global default timeout; wrap in thread with timeout instead
    return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)


def resolve_host(host: str, timeout: float = 3.0) -> Set[str]:
    """
    Resolve a host to a set of IP addresses (IPv4/IPv6). Returns empty set if not resolvable.
    Handles timeouts gracefully.
    """
    host = normalize_host(host)
    ips: Set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_getaddrinfo_threadsafe, host)
        try:
            infos = fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return set()
        except Exception:
            return set()
    for family, _stype, _proto, _canonname, sockaddr in infos:
        try:
            if family == socket.AF_INET:
                ips.add(sockaddr[0])
            elif family == socket.AF_INET6:
                # normalize IPv6
                ips.add(sockaddr[0])
        except Exception:
            continue
    return ips


def detect_wildcard(domain: str, tries: int = 5, timeout: float = 3.0) -> Tuple[bool, Set[str]]:
    """
    Attempt to detect wildcard DNS configuration by resolving random subdomains.
    Returns (is_wildcard, wildcard_ips)
    """
    domain = normalize_host(domain)
    ips_union: Set[str] = set()
    success = 0
    for _ in range(tries):
        label = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        host = f"{label}.{domain}"
        ips = resolve_host(host, timeout=timeout)
        if ips:
            success += 1
            ips_union.update(ips)
        # short sleep to avoid hammering resolvers
        time.sleep(0.05)
    # heuristic: wildcard if >= 2 random labels resolved
    is_wild = success >= 2
    return is_wild, ips_union


def dns_bruteforce(domain: str, words: Iterable[str], concurrency: int = 100,
                   timeout: float = 3.0, wildcard_ips: Optional[Set[str]] = None) -> Set[str]:
    """
    Brute force DNS for subdomains using concurrent resolution.
    Filters out wildcard matches if wildcard_ips given.
    """
    domain = normalize_host(domain)
    results: Set[str] = set()
    lock = threading.Lock()

    def worker(label: str) -> Optional[str]:
        label = label.strip().lower()
        if not VALID_LABEL_RE.match(label):
            return None
        host = f"{label}.{domain}"
        ips = resolve_host(host, timeout=timeout)
        if not ips:
            return None
        if wildcard_ips:
            # If all resolved IPs are within wildcard IPs, likely wildcard hit; skip.
            if ips and ips.issubset(wildcard_ips):
                return None
        return host

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(concurrency))) as ex:
        futures = {ex.submit(worker, w): w for w in words}
        for fut in concurrent.futures.as_completed(futures):
            try:
                host = fut.result()
            except Exception:
                host = None
            if host:
                with lock:
                    results.add(host)
    return results


# -------------------------
# Certificate Transparency
# -------------------------

def fetch_ct_subdomains(domain: str, timeout: float = 10.0) -> Set[str]:
    """
    Query crt.sh for subdomains using its JSON interface.
    """
    domain = normalize_host(domain)
    out: Set[str] = set()
    # encode "%.{domain}" as q parameter
    url = f"https://crt.sh/?{urlencode({'q': f'%.{domain}', 'output': 'json'})}"
    req = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except Exception as e:
        warn(f"[!] CT fetch failed: {e}")
        return out
    # crt.sh may return multiple JSON objects without being wrapped; handle that
    # Attempt to decode as JSON list first, else try to split on }{ boundaries.
    text = ""
    try:
        text = data.decode("utf-8", errors="ignore")
        parsed = json.loads(text)
        items = parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        # Fallback: split concatenated JSON
        parts = re.split(r"}\s*{", text.strip().strip("\n"))
        if not parts:
            return out
        # reconstruct each JSON with braces
        items = []
        for i, part in enumerate(parts):
            if not part:
                continue
            jtxt = part
            if not part.startswith("{"):
                jtxt = "{" + jtxt
            if not part.endswith("}"):
                jtxt = jtxt + "}"
            try:
                items.append(json.loads(jtxt))
            except Exception:
                continue
    for item in items:
        name_val = item.get("name_value") if isinstance(item, dict) else None
        if not name_val:
            continue
        for raw in str(name_val).split("\n"):
            host = str(raw).strip().lower().rstrip(".")
            # filter wildcard entries like *.example.com
            host = host.lstrip("*.").lstrip("*.").lstrip("%.")
            if not host:
                continue
            if not is_subdomain_of(host, domain):
                continue
            if not is_valid_hostname(host):
                continue
            out.add(host)
    return out


# -------------------------
# Search Engine Dorking
# -------------------------

def extract_hosts_from_text(text: str, domain: str) -> Set[str]:
    """
    Extract domain-like strings from arbitrary text for a given domain suffix.
    """
    domain = re.escape(normalize_host(domain))
    # match labels followed by the target domain
    pattern = re.compile(rf"\b([a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{domain}\b", re.IGNORECASE)
    found = set(m.group(0).lower().rstrip(".") for m in pattern.finditer(text or ""))
    # filter invalid labels if any
    return set(h for h in found if is_valid_hostname(h))


def http_get(url: str, timeout: float = 8.0, headers: Optional[dict] = None) -> str:
    req = Request(url, headers=headers or {"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            data = resp.read()
            # Decode based on charset if present
            charset = "utf-8"
            m = re.search(r"charset=([A-Za-z0-9_\-]+)", content_type)
            if m:
                charset = m.group(1)
            return data.decode(charset, errors="ignore")
    except Exception as e:
        warn(f"[!] HTTP GET failed for {url}: {e}")
        return ""


def search_duckduckgo(domain: str, pages: int = 3, timeout: float = 8.0) -> Set[str]:
    """
    Use DuckDuckGo HTML endpoint for site dorking. Parses resulting HTML for subdomains.
    """
    domain = normalize_host(domain)
    # Query attempts to find subdomains; avoid direct scraping heavy patterns
    # We'll search for "site:domain -www.domain"
    out: Set[str] = set()
    base = "https://duckduckgo.com/html/"
    for i in range(pages):
        q = f"site:{domain} -www.{domain}"
        params = {"q": q, "s": str(i * 50)}
        url = base + "?" + urlencode(params)
        html = http_get(url, timeout=timeout)
        if not html:
            continue
        hosts = extract_hosts_from_text(html, domain)
        out.update(hosts)
        # be nice
        time.sleep(0.5)
    return out


def search_bing(domain: str, pages: int = 3, timeout: float = 8.0) -> Set[str]:
    """
    Use Bing as a secondary search engine for site dorking.
    """
    domain = normalize_host(domain)
    out: Set[str] = set()
    base = "https://www.bing.com/search"
    for i in range(pages):
        q = f"site:{domain} -www.{domain}"
        params = {"q": q, "first": str(i * 10 + 1)}
        url = base + "?" + urlencode(params)
        html = http_get(url, timeout=timeout)
        if not html:
            continue
        hosts = extract_hosts_from_text(html, domain)
        out.update(hosts)
        time.sleep(0.5)
    return out


def fetch_search_engine_subdomains(domain: str, timeout: float = 8.0, pages: int = 3) -> Set[str]:
    out = set()
    # Run in parallel to reduce time
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futs = [
            ex.submit(search_duckduckgo, domain, pages, timeout),
            ex.submit(search_bing, domain, pages, timeout),
        ]
        for fut in concurrent.futures.as_completed(futs):
            try:
                out.update(fut.result())
            except Exception as e:
                warn(f"[!] Search engine fetch failed: {e}")
    return out


# -------------------------
# Orchestration
# -------------------------

def enumerate_subdomains(
    domain: str,
    wordlist_path: Optional[str] = None,
    threads: int = 100,
    timeout: float = 3.0,
    use_dns: bool = True,
    use_ct: bool = True,
    use_se: bool = True,
    limit: Optional[int] = None,
    quiet: bool = False,
) -> Tuple[Set[str], dict]:
    """
    Main enumeration routine. Returns (subdomains, meta).
    meta includes keys: wildcard_detected, wildcard_ips, sources
    """
    domain = normalize_host(domain)
    results: Set[str] = set()
    sources: dict = {"dns": False, "ct": False, "se": False}

    # Ethical notice
    if not quiet:
        warn("== Subdomain Hunter ==")
        warn("For authorized security testing only. Ensure you have permission.")
        warn("")

    # wildcard detection
    wildcard_detected, wildcard_ips = detect_wildcard(domain, tries=5, timeout=timeout)
    if wildcard_detected:
        warn(f"[i] Wildcard DNS appears to be enabled. Filtering by IPs: {', '.join(sorted(wildcard_ips)) or 'unknown'}")
    else:
        warn("[i] No wildcard DNS detected.")

    # Prepare wordlist
    words = parse_wordlist(wordlist_path)
    if limit is not None and limit > 0:
        words = words[:limit]

    # Launch CT and SE in parallel to DNS brute
    ct_result: Set[str] = set()
    se_result: Set[str] = set()

    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        if use_ct:
            tasks.append(("ct", ex.submit(fetch_ct_subdomains, domain)))
        if use_se:
            tasks.append(("se", ex.submit(fetch_search_engine_subdomains, domain)))
        # DNS brute after we might learn candidates from CT/SE (merge later)
        dns_result: Set[str] = set()
        if use_dns:
            dns_result = dns_bruteforce(
                domain,
                words=words,
                concurrency=threads,
                timeout=timeout,
                wildcard_ips=wildcard_ips if wildcard_detected else None,
            )
            sources["dns"] = True
            results.update(dns_result)
        # collect CT/SE
        for tag, fut in tasks:
            try:
                data = fut.result(timeout=30.0)
            except concurrent.futures.TimeoutError:
                warn(f"[!] Source '{tag}' timed out.")
                data = set()
            except Exception as e:
                warn(f"[!] Source '{tag}' failed: {e}")
                data = set()
            if tag == "ct":
                ct_result = set(data)
                sources["ct"] = True
            elif tag == "se":
                se_result = set(data)
                sources["se"] = True

    # Post-process CT/SE results: filter and remove wildcard
    for src_set in (ct_result, se_result):
        for host in src_set:
            h = normalize_host(host)
            if not is_subdomain_of(h, domain):
                continue
            if not is_valid_hostname(h):
                continue
            if wildcard_detected and resolve_host(h, timeout=timeout).issubset(wildcard_ips):
                continue
            results.add(h)

    # De-duplicate and ensure unique valid subdomains only
    valid_results = set(h for h in results if is_subdomain_of(h, domain) and is_valid_hostname(h))

    meta = {
        "domain": domain,
        "count": len(valid_results),
        "wildcard_detected": wildcard_detected,
        "wildcard_ips": sorted(list(wildcard_ips)),
        "sources": sources,
        "timestamps": {"completed": int(time.time())},
    }

    return valid_results, meta


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Hunter - Intelligent subdomain enumeration (authorized use only)."
    )
    parser.add_argument("domain", help="Target domain (authorized only), e.g., example.com")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for DNS brute force", default=None)
    parser.add_argument("-t", "--threads", help="Concurrent DNS workers", type=int, default=100)
    parser.add_argument("--timeout", help="Per-request timeout (seconds)", type=float, default=3.0)
    parser.add_argument("--no-dns", help="Disable DNS brute force", action="store_true")
    parser.add_argument("--no-ct", help="Disable Certificate Transparency search", action="store_true")
    parser.add_argument("--no-se", help="Disable search engine dorking", action="store_true")
    parser.add_argument("--limit", help="Limit number of wordlist entries for DNS brute", type=int, default=None)
    parser.add_argument("--json", help="Output JSON (metadata + subdomains)", action="store_true")
    parser.add_argument("--quiet", help="Quiet mode: print only subdomains to stdout", action="store_true")

    args = parser.parse_args()

    # Gracefully handle invalid domain
    domain = normalize_host(args.domain)
    if "." not in domain or not is_valid_hostname(domain):
        warn(f"[!] Invalid domain: {args.domain}")
        sys.exit(2)

    try:
        subs, meta = enumerate_subdomains(
            domain=domain,
            wordlist_path=args.wordlist,
            threads=args.threads,
            timeout=args.timeout,
            use_dns=not args.no_dns,
            use_ct=not args.no_ct,
            use_se=not args.no_se,
            limit=args.limit,
            quiet=args.quiet,
        )
    except KeyboardInterrupt:
        warn("\n[!] Aborted by user.")
        sys.exit(130)
    except Exception as e:
        warn(f"[!] Fatal error: {e}")
        sys.exit(1)

    # Output
    if args.json:
        out = {"meta": meta, "subdomains": sorted(list(subs))}
        print(json.dumps(out, indent=2))
    else:
        # print only subdomains to stdout; warnings and info to stderr
        for s in sorted(subs):
            print(s)


if __name__ == "__main__":
    main()