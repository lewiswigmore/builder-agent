#!/usr/bin/env python3
import argparse
import concurrent.futures
import contextlib
import json
import logging
import os
import random
import re
import socket
import string
import sys
import time
from typing import Iterable, List, Optional, Set, Tuple, Dict
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen

ETHICAL_WARNING = (
    "WARNING: This tool is intended for authorized security testing and reconnaissance "
    "on systems and domains you own or have explicit permission to test. "
    "Unauthorized use may be illegal and unethical. Proceed responsibly."
)

DEFAULT_WORDLIST_REL = os.path.join(os.path.dirname(__file__), "wordlists", "common.txt")

USER_AGENT = (
    "Mozilla/5.0 (compatible; SubdomainHunter/1.0; +https://example.com/security) "
    "Python-urllib/3.x"
)

# Compile regexes once
HOST_IN_TEXT_RE = re.compile(
    r"(?:(?:https?://)|(?:[>\s\(\['\"]))(?:[a-z0-9\-\_]+\.)*([a-z0-9\-\_]+\.[a-z0-9\.\-]+)",
    re.IGNORECASE,
)
VALID_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def read_wordlist(path: str) -> List[str]:
    words: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if not w or w.startswith("#"):
                    continue
                words.append(w)
    except Exception as e:
        logging.error("Failed to read wordlist %s: %s", path, e)
    return words


def normalize_domain(domain: str) -> str:
    d = domain.strip().strip(".").lower()
    # Remove scheme if provided accidentally
    d = re.sub(r"^[a-z]+://", "", d)
    # Remove paths
    d = d.split("/")[0]
    return d


def is_valid_domain_name(domain: str) -> bool:
    if len(domain) > 253:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if not VALID_LABEL_RE.match(label):
            return False
    return True


def is_subdomain(name: str, parent_domain: str) -> bool:
    n = name.strip(".").lower()
    p = parent_domain.strip(".").lower()
    return n.endswith("." + p) and n != p


def unique_subdomains_from_text(text: str, domain: str) -> Set[str]:
    found: Set[str] = set()
    for match in HOST_IN_TEXT_RE.finditer(text):
        host = match.group(1)
        host = host.strip("'>\"),(").lower()
        host = host.strip(".")
        # Remove trailing punctuation that sometimes gets included
        host = re.sub(r"[^\w\.\-]+$", "", host)
        if is_subdomain(host, domain) and is_valid_domain_name(host):
            found.add(host)
    return found


class DNSResolver:
    def __init__(self, timeout: float = 3.0, use_dnspython: Optional[bool] = None):
        self.timeout = timeout
        self._use_dnspython = use_dnspython
        self._dnspython_available = False
        self._init_backend()

    def _init_backend(self):
        if self._use_dnspython is False:
            self._dnspython_available = False
            socket.setdefaulttimeout(self.timeout)
            return
        try:
            import dns.resolver  # type: ignore
            self._dnspython_available = True
            self._dnsresolver = dns.resolver.Resolver()
            self._dnsresolver.lifetime = self.timeout
            self._dnsresolver.timeout = self.timeout
        except Exception:
            self._dnspython_available = False
            socket.setdefaulttimeout(self.timeout)

    def resolve_ips(self, host: str) -> Set[str]:
        host = host.strip(".")
        ips: Set[str] = set()
        if self._dnspython_available:
            try:
                import dns.resolver  # type: ignore

                for rtype in ("A", "AAAA"):
                    try:
                        answers = self._dnsresolver.resolve(host, rtype, lifetime=self.timeout)
                        for rdata in answers:
                            ip = rdata.to_text().strip()
                            if ip:
                                ips.add(ip)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                        continue
                    except Exception as e:
                        logging.debug("dnspython resolve error for %s (%s): %s", host, rtype, e)
                        continue
            except Exception as e:
                logging.debug("dnspython resolve fatal: %s; falling back to socket", e)
        if not ips:
            # Fallback: socket
            try:
                infos = socket.getaddrinfo(host, None, 0, 0, 0)
                for info in infos:
                    sockaddr = info[4]
                    ip = sockaddr[0]
                    if ip:
                        ips.add(ip)
            except socket.gaierror as e:
                # Name resolution failure, NXDOMAIN or similar
                logging.debug("socket resolve error for %s: %s", host, e)
            except Exception as e:
                logging.debug("socket resolve exception for %s: %s", host, e)
        return ips


def http_get(url: str, timeout: float = 5.0, headers: Optional[Dict[str, str]] = None, retries: int = 2, backoff: float = 1.5) -> Optional[bytes]:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    last_exc = None
    for attempt in range(retries + 1):
        try:
            req = Request(url, headers=hdrs)
            with contextlib.closing(urlopen(req, timeout=timeout)) as resp:
                # Basic status handling; urllib raises on HTTP errors via HTTPError
                content = resp.read(2 * 1024 * 1024)
                return content
        except Exception as e:
            last_exc = e
            logging.debug("HTTP GET failed (%s) attempt %d: %s", url, attempt + 1, e)
            time.sleep(backoff * (attempt + 1))
    logging.warning("HTTP GET failed for %s: %s", url, last_exc)
    return None


class SubdomainHunter:
    def __init__(
        self,
        domain: str,
        wordlist: Optional[str] = None,
        threads: int = 20,
        timeout: float = 3.0,
        use_ct: bool = True,
        use_search: bool = True,
        use_bruteforce: bool = True,
        skip_brute_on_wildcard: bool = False,
    ):
        self.domain = normalize_domain(domain)
        self.threads = max(1, threads)
        self.timeout = timeout
        self.use_ct = use_ct
        self.use_search = use_search
        self.use_bruteforce = use_bruteforce
        self.skip_brute_on_wildcard = skip_brute_on_wildcard
        self.resolver = DNSResolver(timeout=self.timeout)
        if wordlist:
            self.wordlist_path = wordlist
        else:
            self.wordlist_path = DEFAULT_WORDLIST_REL
        self.discovered_by: Dict[str, Set[str]] = {}

    def _add_source(self, host: str, source: str):
        s = self.discovered_by.get(host)
        if s is None:
            self.discovered_by[host] = {source}
        else:
            s.add(source)

    def detect_wildcard(self, samples: int = 3) -> Tuple[bool, List[Set[str]]]:
        baselines: List[Set[str]] = []
        for _ in range(samples):
            rand_label = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
            host = f"{rand_label}.{self.domain}"
            ips = self.resolver.resolve_ips(host)
            if ips:
                baselines.append(ips)
            time.sleep(0.05)
        wildcard = len(baselines) > 0
        if wildcard:
            logging.info("Wildcard DNS detected for %s (baseline sample count: %d)", self.domain, len(baselines))
        else:
            logging.info("No wildcard DNS detected for %s", self.domain)
        return wildcard, baselines

    def bruteforce_dns(self) -> Set[str]:
        words = read_wordlist(self.wordlist_path)
        if not words:
            logging.warning("Wordlist is empty or not found: %s", self.wordlist_path)
            return set()
        candidates = [f"{w.strip().lower()}.{self.domain}" for w in words if w.strip()]
        results: Set[str] = set()
        lock = concurrent.futures.thread.Lock()

        def check(host: str):
            try:
                ips = self.resolver.resolve_ips(host)
                if ips:
                    with lock:
                        results.add(host)
                        self._add_source(host, "dns")
            except Exception as e:
                logging.debug("Error during DNS check for %s: %s", host, e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(check, candidates, chunksize=10))
        logging.info("DNS brute force discovered %d candidates", len(results))
        return results

    def fetch_crtsh(self) -> Set[str]:
        # Cert transparency via crt.sh JSON
        base = "https://crt.sh/?q=%25.{domain}&output=json"
        url = base.format(domain=self.domain)
        content = http_get(url, timeout=max(self.timeout, 5.0), retries=3, backoff=1.5)
        results: Set[str] = set()
        if not content:
            return results
        try:
            # Some instances return multiple JSON objects concatenated; try to make it a list
            txt = content.decode("utf-8", errors="ignore")
            # A valid JSON array?
            data = None
            try:
                data = json.loads(txt)
            except json.JSONDecodeError:
                # Attempt to make it a JSON array if it's lines of objects
                fixed = "[" + ",".join(x for x in txt.splitlines() if x.strip().startswith("{")) + "]"
                data = json.loads(fixed)
            for entry in data:
                name_val = entry.get("name_value")
                if not name_val:
                    continue
                for host in str(name_val).splitlines():
                    host = host.strip().lower().strip(".")
                    if host.startswith("*."):
                        host = host[2:]
                    if is_subdomain(host, self.domain) and is_valid_domain_name(host):
                        results.add(host)
                        self._add_source(host, "ct")
        except Exception as e:
            logging.warning("Failed to parse CRT.sh response: %s", e)
        logging.info("CRT.sh produced %d candidates", len(results))
        return results

    def search_engines(self, max_results: int = 50) -> Set[str]:
        results: Set[str] = set()

        queries = [
            f"site:*.{self.domain} -site:www.{self.domain} -site:{self.domain}",
            f"site:{self.domain} -site:www.{self.domain}",
            f'"{self.domain}" -www.{self.domain}',
        ]
        engines = [
            ("duckduckgo", "https://duckduckgo.com/html/?q={q}&ia=web"),
            ("bing", "https://www.bing.com/search?q={q}&count=50"),
        ]
        for q in queries:
            encoded_q = quote_plus(q)
            for name, tpl in engines:
                url = tpl.format(q=encoded_q)
                content = http_get(url, timeout=max(self.timeout, 5.0), retries=2, backoff=1.0)
                if not content:
                    continue
                text = content.decode("utf-8", errors="ignore")
                hosts = unique_subdomains_from_text(text, self.domain)
                for h in hosts:
                    results.add(h)
                    self._add_source(h, f"search:{name}")
                # Be polite-ish
                time.sleep(0.25)
                if len(results) >= max_results:
                    break
            if len(results) >= max_results:
                break
        logging.info("Search engines produced %d candidates", len(results))
        return results

    def filter_wildcard(self, hosts: Iterable[str], baselines: List[Set[str]]) -> Set[str]:
        if not baselines:
            return set(hosts)
        filtered: Set[str] = set()
        # normalize baseline sets (strings)
        baseline_norm = [",".join(sorted(b)) for b in baselines]
        for h in hosts:
            ips = self.resolver.resolve_ips(h)
            if not ips:
                continue
            norm = ",".join(sorted(ips))
            if norm in baseline_norm:
                # keep if discovered by non-bruteforce sources (ct/search)
                sources = self.discovered_by.get(h, set())
                if any(s for s in sources if s != "dns"):
                    logging.debug("Keeping %s despite wildcard match due to trusted source(s): %s", h, sources)
                    filtered.add(h)
                else:
                    logging.debug("Dropping %s due to wildcard baseline match", h)
            else:
                filtered.add(h)
        return filtered

    def run(self) -> Tuple[Set[str], bool]:
        # Detection
        wildcard, baselines = self.detect_wildcard()
        all_hosts: Set[str] = set()
        # Sources
        if self.use_ct:
            try:
                all_hosts |= self.fetch_crtsh()
            except Exception as e:
                logging.warning("CT fetch error: %s", e)
        if self.use_search:
            try:
                all_hosts |= self.search_engines()
            except Exception as e:
                logging.warning("Search engine error: %s", e)
        if self.use_bruteforce and not (wildcard and self.skip_brute_on_wildcard):
            try:
                all_hosts |= self.bruteforce_dns()
            except Exception as e:
                logging.warning("DNS brute force error: %s", e)

        # Clean and deduplicate
        cleaned: Set[str] = set()
        for h in all_hosts:
            h2 = h.strip().strip(".").lower()
            if is_subdomain(h2, self.domain) and is_valid_domain_name(h2):
                cleaned.add(h2)
        # Wildcard filter
        final: Set[str] = cleaned
        if wildcard:
            final = self.filter_wildcard(cleaned, baselines)
        # Verify uniqueness and validity once more
        verified: Set[str] = set()
        for h in final:
            if is_subdomain(h, self.domain):
                verified.add(h)

        return verified, wildcard


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Subdomain Hunter",
        description="Intelligent subdomain enumeration using DNS brute force, certificate transparency, and search engines.",
    )
    parser.add_argument("domain", help="Target domain (authorized testing only)")
    parser.add_argument(
        "-w",
        "--wordlist",
        help=f"Wordlist for DNS brute forcing (default: {DEFAULT_WORDLIST_REL})",
        default=None,
    )
    parser.add_argument("-t", "--threads", help="Concurrent threads for DNS brute forcing", type=int, default=20)
    parser.add_argument("--timeout", help="Network timeout in seconds", type=float, default=3.0)
    parser.add_argument("--no-ct", help="Disable Certificate Transparency source", action="store_true")
    parser.add_argument("--no-search", help="Disable search engine dorking source", action="store_true")
    parser.add_argument("--no-brute", help="Disable DNS brute force source", action="store_true")
    parser.add_argument(
        "--skip-brute-on-wildcard",
        help="If wildcard is detected, skip brute force to avoid false positives",
        action="store_true",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    parser.add_argument("-o", "--output", help="Write results to file (one per line)")
    parser.add_argument("--resolve", action="store_true", help="Resolve and print IPs for discovered subdomains")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    eprint(ETHICAL_WARNING)

    domain = normalize_domain(args.domain)
    if not is_valid_domain_name(domain):
        eprint(f"Invalid domain: {domain}")
        return 2

    hunter = SubdomainHunter(
        domain=domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        use_ct=not args.no_ct,
        use_search=not args.no_search,
        use_bruteforce=not args.no_brute,
        skip_brute_on_wildcard=args.skip_brute_on_wildcard,
    )
    try:
        subs, wildcard = hunter.run()
    except KeyboardInterrupt:
        eprint("Interrupted by user.")
        return 130
    except Exception as e:
        logging.error("Fatal error: %s", e)
        return 1

    lines: List[str] = sorted(subs)
    if args.resolve:
        resolver = hunter.resolver
        out_lines: List[str] = []
        for h in lines:
            ips = resolver.resolve_ips(h)
            if ips:
                out_lines.append(f"{h} {', '.join(sorted(ips))}")
            else:
                out_lines.append(h)
        lines = out_lines

    # Output
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                for line in lines:
                    f.write(f"{line}\n")
            print(f"[+] Found {len(subs)} unique subdomains for {domain} (wildcard: {'yes' if wildcard else 'no'})")
            print(f"[+] Results written to {args.output}")
        except Exception as e:
            eprint(f"Failed to write output file: {e}")
            for line in lines:
                print(line)
    else:
        print(f"# Subdomain Hunter results for {domain}")
        print(f"# Wildcard DNS detected: {'yes' if wildcard else 'no'}")
        print(f"# Count: {len(subs)}")
        for line in lines:
            print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main())