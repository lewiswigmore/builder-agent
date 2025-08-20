import pytest
import re
import socket
import time
import types
import importlib

# Import the tool module once for all tests
hunter_module = importlib.import_module("tools.recon.subdomain_hunter")


def get_runner():
    # Try class-based API
    if hasattr(hunter_module, "SubdomainHunter"):
        hunter = hunter_module.SubdomainHunter()
        if hasattr(hunter, "run") and callable(getattr(hunter, "run")):
            return lambda domain, **kw: getattr(hunter, "run")(domain, **kw)
        if hasattr(hunter, "hunt") and callable(getattr(hunter, "hunt")):
            return lambda domain, **kw: getattr(hunter, "hunt")(domain, **kw)
        if callable(hunter):
            return lambda domain, **kw: hunter(domain, **kw)
    # Try function-based APIs
    for name in ("find_subdomains", "hunt_subdomains", "run", "hunt", "search"):
        func = getattr(hunter_module, name, None)
        if callable(func):
            return lambda domain, **kw: func(domain, **kw)
    raise AssertionError("No suitable runner found in tools.recon.subdomain_hunter")


def extract_subdomains(result):
    # Normalize results to a set of strings
    if result is None:
        return set()
    if isinstance(result, (list, set, tuple)):
        # If tuple-like and first element is a list, assume (subs, meta)
        if isinstance(result, tuple) and result and isinstance(result[0], (list, set, tuple)):
            return set(map(str, result[0]))
        return set(map(str, result))
    if isinstance(result, dict):
        for key in ("subdomains", "results", "hosts", "domains"):
            if key in result and isinstance(result[key], (list, set, tuple)):
                return set(map(str, result[key]))
    # Fallback: single string?
    if isinstance(result, str):
        return set([result])
    return set()


def is_valid_subdomain(name, domain):
    if not isinstance(name, str):
        return False
    n = name.lower().strip(".")
    dom = domain.lower().strip(".")
    if not n.endswith("." + dom):
        return False
    # There must be at least one label before the domain
    if n.count(".") < dom.count(".") + 1:
        return False
    # Validate each label
    labels = n.split(".")
    label_re = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)
    return all(label_re.match(lbl or "") for lbl in labels)


class FakeResponse:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self._text = text
        self._json = json_data

    @property
    def text(self):
        return self._text

    def json(self):
        return self._json


def patch_requests(monkeypatch, routes):
    """
    Patch requests.get globally and in module to return FakeResponse based on URL matching.
    routes: list of tuples (predicate, responder)
        - predicate: callable(url) -> bool
        - responder: callable(url, **kwargs) -> FakeResponse or raises
    """
    import requests

    def fake_get(url, *args, **kwargs):
        for pred, responder in routes:
            try:
                if pred(url):
                    return responder(url, *args, **kwargs)
            except Exception as e:
                # Propagate intended exceptions like Timeout
                raise
        # Default empty response
        return FakeResponse(status_code=200, text="", json_data=[])

    # Patch globally and within module if imported
    monkeypatch.setattr(requests, "get", fake_get, raising=False)
    if hasattr(hunter_module, "requests"):
        monkeypatch.setattr(hunter_module.requests, "get", fake_get, raising=False)


def patch_dns(monkeypatch, records=None, wildcard_suffix=None, timeout_hosts=None):
    """
    Patch socket DNS methods and, if present, dnspython resolver, to simulate DNS answers.
    - records: dict hostname -> list of IPs
    - wildcard_suffix: any host ending with .<suffix> resolves to 127.0.0.1 if not in records
    - timeout_hosts: set of hostnames to raise timeout
    """
    records = records or {}
    timeout_hosts = timeout_hosts or set()

    def resolve_host(host):
        h = host.lower().strip(".")
        if h in timeout_hosts:
            raise socket.timeout("DNS timeout")
        if h in records:
            return records[h]
        if wildcard_suffix and h.endswith("." + wildcard_suffix.strip(".")):
            return ["127.0.0.1"]
        raise socket.gaierror(f"Name or service not known: {host}")

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        addrs = resolve_host(host)
        # Return tuples like real getaddrinfo would
        return [
            (socket.AF_INET, socket.SOCK_STREAM, proto, "", (addr, port or 0))
            for addr in addrs
        ]

    def fake_gethostbyname(host):
        addrs = resolve_host(host)
        return addrs[0]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo, raising=False)
    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname, raising=False)

    # Patch dnspython resolver if available
    try:
        import dns.resolver as dnsp_resolver  # type: ignore

        def fake_resolve(qname, rdtype="A", *args, **kwargs):
            addrs = resolve_host(str(qname))
            class RR:
                def __init__(self, a):
                    self.address = a

                def to_text(self):
                    return self.address

                def __str__(self):
                    return self.address

            return [RR(a) for a in addrs]

        monkeypatch.setattr(dnsp_resolver, "resolve", fake_resolve, raising=False)
    except Exception:
        # Also attempt to patch in module's namespace if it has dns.resolver
        dns_mod = getattr(hunter_module, "dns", None)
        if dns_mod is not None and hasattr(dns_mod, "resolver"):
            try:
                monkeypatch.setattr(dns_mod.resolver, "resolve", lambda *a, **k: resolve_host(a[0]), raising=False)
            except Exception:
                pass


@pytest.mark.timeout(5)
def test_find_at_least_5_subdomains(monkeypatch):
    domain = "example.com"

    # Patch DNS to resolve known good subdomains to 127.0.0.1
    known_subs = {
        f"www.{domain}": ["127.0.0.1"],
        f"api.{domain}": ["127.0.0.1"],
        f"mail.{domain}": ["127.0.0.1"],
        f"shop.{domain}": ["127.0.0.1"],
        f"docs.{domain}": ["127.0.0.1"],
        f"blog.{domain}": ["127.0.0.1"],
        f"dev.{domain}": ["127.0.0.1"],
    }
    patch_dns(monkeypatch, records=known_subs)

    # Patch requests to simulate CT logs and search engine dorking
    def is_crt(url): return "crt.sh" in url or "certspotter" in url
    def is_search(url): return any(s in url for s in ("google.", "bing.", "duckduckgo", "search"))

    def respond_crt(url, *args, **kwargs):
        if "certspotter" in url:
            data = [
                {"dns_names": [f"dev.{domain}", f"www.{domain}"]},
                {"dns_names": [f"api.{domain}", f"mail.{domain}"]},
            ]
            return FakeResponse(status_code=200, json_data=data)
        # crt.sh-like JSON
        data = [
            {"name_value": f"www.{domain}"},
            {"name_value": f"api.{domain}\nmail.{domain}"},
            {"name_value": f"shop.{domain}"},
        ]
        return FakeResponse(status_code=200, json_data=data)

    def respond_search(url, *args, **kwargs):
        text = f"Results: {domain} blog.{domain} docs.{domain} www.{domain} irrelevant other"
        return FakeResponse(status_code=200, text=text)

    patch_requests(monkeypatch, [
        (is_crt, respond_crt),
        (is_search, respond_search),
    ])

    runner = get_runner()
    result = runner(domain)
    subs = {s.lower().strip() for s in extract_subdomains(result)}

    # Validate at least 5 subdomains and their format
    assert len(subs) >= 5
    assert all(is_valid_subdomain(s, domain) for s in subs)
    # Uniqueness
    assert len(subs) == len(set(subs))


@pytest.mark.timeout(5)
def test_detect_wildcard_dns_configurations(monkeypatch):
    domain = "wildtest.localhost"

    # Wildcard DNS: resolve any subdomain under domain to 127.0.0.1
    patch_dns(monkeypatch, records={}, wildcard_suffix=domain)

    # Return no CT log or search results to avoid "real" entries
    patch_requests(monkeypatch, [
        (lambda url: True, lambda url, *a, **k: FakeResponse(status_code=200, json_data=[])),
    ])

    runner = get_runner()
    result = runner(domain)
    subs = extract_subdomains(result)

    # With wildcard in place and no explicit known good hosts, tool should filter brute-force false positives
    assert isinstance(subs, set)
    assert len(subs) == 0


@pytest.mark.timeout(5)
def test_output_unique_valid_subdomains_only(monkeypatch):
    domain = "example.com"

    # Prepare DNS to resolve only valid hosts
    records = {
        f"good.{domain}": ["127.0.0.1"],
        f"dup.{domain}": ["127.0.0.1"],
    }
    patch_dns(monkeypatch, records=records)

    # Provide duplicates and invalid entries via CT and search
    invalids = [
        f"http://bad.{domain}",
        f"bad..{domain}",
        f"-bad.{domain}",
        f"bad-.{domain}",
        "notadomain",
        f"also.bad.{domain}/path",
    ]
    ct_json = [
        {"name_value": f"dup.{domain}"},
        {"name_value": f"dup.{domain}\n{invalids[0]}"},
        {"name_value": f"good.{domain}"},
    ]
    search_text = f"dup.{domain} some text {invalids[1]} also {invalids[2]} good.{domain} end"

    def is_ct(url): return "crt.sh" in url or "certspotter" in url
    def is_search(url): return any(s in url for s in ("google.", "bing.", "duckduckgo", "search"))

    def respond_ct(url, *a, **k):
        # Mix crt.sh and certspotter styles
        if "certspotter" in url:
            return FakeResponse(status_code=200, json_data=[{"dns_names": [f"dup.{domain}", f"good.{domain}", invalids[3]]}])
        return FakeResponse(status_code=200, json_data=ct_json)

    def respond_search(url, *a, **k):
        return FakeResponse(status_code=200, text=search_text)

    patch_requests(monkeypatch, [
        (is_ct, respond_ct),
        (is_search, respond_search),
    ])

    runner = get_runner()
    result = runner(domain)
    subs = {s.lower().strip() for s in extract_subdomains(result)}

    # Only valid and unique subdomains should remain
    assert f"good.{domain}" in subs
    assert f"dup.{domain}" in subs
    # Invalids shouldn't appear
    for inv in invalids:
        assert inv.lower() not in subs
    # Validate all are subdomains of domain and unique
    assert all(is_valid_subdomain(s, domain) for s in subs)
    assert len(subs) == len(set(subs))


@pytest.mark.timeout(5)
def test_handle_timeouts_gracefully(monkeypatch):
    domain = "example.com"

    # DNS will resolve some, time out others
    records = {
        f"fast.{domain}": ["127.0.0.1"],
        f"ok.{domain}": ["127.0.0.1"],
    }
    timeouts = {f"slow.{domain}", f"timeout.{domain}"}
    patch_dns(monkeypatch, records=records, timeout_hosts=timeouts)

    # Requests will timeout for CT and search
    def always(url): return True

    def raise_timeout(url, *a, **k):
        import requests
        raise requests.exceptions.Timeout("simulated timeout")

    patch_requests(monkeypatch, [(always, raise_timeout)])

    runner = get_runner()
    start = time.time()
    try:
        result = runner(domain)
    except Exception as e:
        pytest.fail(f"Tool should handle timeouts gracefully, but raised: {e!r}")
    elapsed = time.time() - start

    subs = extract_subdomains(result)
    # It may return empty set or partial results; ensure it's a collection and not exploding
    assert isinstance(subs, set)
    for s in subs:
        assert is_valid_subdomain(s, domain)
    # Should not take excessively long when timeouts happen; arbitrary threshold
    assert elapsed < 4.5


@pytest.mark.timeout(5)
def test_invalid_domain_input_edge_case(monkeypatch):
    # Patch all network to avoid real calls
    patch_dns(monkeypatch, records={})
    patch_requests(monkeypatch, [(lambda url: True, lambda url, *a, **k: FakeResponse(status_code=200, json_data=[]))])

    runner = get_runner()
    invalid_domains = ["", " ", "not a domain", "http://example.com", ".example.com", "example..com"]

    for inv in invalid_domains:
        try:
            result = runner(inv)
            subs = extract_subdomains(result)
            assert subs == set() or all(is_valid_subdomain(s, "example.com") for s in subs)
        except (ValueError, RuntimeError):
            # Accept raising a clear error for invalid input
            pass