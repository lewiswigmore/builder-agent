import re
import sys
import types
import json
import time
import socket
import inspect
import threading
from urllib.parse import urlparse, parse_qs
import pytest


# ------------------------------
# Test utilities and fixtures
# ------------------------------

VALID_LABELS = {"www", "api", "mail", "dev", "test", "staging", "blog"}
VALID_IPS = {
    "www": "127.0.0.11",
    "api": "127.0.0.12",
    "mail": "127.0.0.13",
    "dev": "127.0.0.14",
    "test": "127.0.0.15",
    "staging": "127.0.0.16",
    "blog": "127.0.0.17",
}


def make_valid_fqdns(domain):
    return {f"{label}.{domain}" for label in VALID_LABELS}


def is_valid_hostname(hostname, domain=None):
    try:
        hn = hostname.lower()
        if len(hn) > 253 or len(hn) == 0:
            return False
        if hn.endswith("."):
            hn = hn[:-1]
        labels = hn.split(".")
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label[0] == "-" or label[-1] == "-":
                return False
            if "_" in label:
                return False
            if not re.fullmatch(r"[a-z0-9-]+", label):
                return False
        if domain is not None and not hn.endswith("." + domain):
            return False
        return True
    except Exception:
        return False


class FakeHTTPResponse:
    def __init__(self, url, status=200, text="", json_data=None, delay=0.0):
        self.url = url
        self.status_code = status
        self._text = text
        self._json_data = json_data
        self._delay = delay
        self.headers = {"Content-Type": "application/json" if json_data is not None else "text/html"}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    @property
    def text(self):
        if self._delay:
            time.sleep(self._delay)
        if self._json_data is not None:
            return json.dumps(self._json_data)
        return self._text

    @property
    def content(self):
        return self.text.encode("utf-8")

    def json(self):
        if self._delay:
            time.sleep(self._delay)
        if self._json_data is not None:
            return self._json_data
        try:
            return json.loads(self._text)
        except Exception as e:
            raise ValueError("Invalid JSON") from e


def build_mock_http_for_domain(domain, timeout_sources=False):
    """
    Return a function that mocks requests.get and urllib.request.urlopen
    for CT logs and search engine dorking for the given domain.
    If timeout_sources=True, the CT and search sources will raise a timeout.
    """
    valid = make_valid_fqdns(domain)
    invalid = {
        f"-bad.{domain}",
        f"foo..{domain}",
        f"in valid.{domain}",
    }
    # some duplicates
    ct_names = [
        {"name_value": f"www.{domain}\napi.{domain}\ninvalid one.{domain}\n{list(valid)[0]}"},
        {"name_value": f"mail.{domain}"},
        {"name_value": f"dev.{domain}"},
        {"name_value": f"test.{domain}"},
        {"name_value": f"staging.{domain}"},
        {"name_value": f"blog.{domain}"},
        {"name_value": f"www.{domain}"},  # duplicate
        {"name_value": f"-bad.{domain}"},  # invalid
    ]
    search_hits = "\n".join(
        [
            f"<a href='http://{s}/'>link</a>"
            for s in list(valid) + [f"www.{domain}", f"api.{domain}"] + list(invalid)  # include duplicates + invalid
        ]
    )
    ct_json_map = {}

    def parse_domain_from_url(url, params):
        # Try to extract domain from URL or params for ct logs
        if params and "q" in params:
            q = params.get("q")
            if isinstance(q, (list, tuple)):
                q = q[0]
            q = str(q)
            q = q.replace("%25", "").replace("%.", "").replace("*.", "").replace("%", "")
            q = q.strip()
            return q
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        if "q" in q:
            v = q["q"][0]
            v = v.replace("%25", "").replace("%.", "").replace("*.", "").replace("%", "")
            return v
        # fallback: use netloc or path
        return domain

    def fake_requests_get(url, params=None, timeout=None, headers=None, **kwargs):
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        # simulate timeouts for CT logs and search engines if toggled
        if any(k in host for k in ["crt.sh", "certspotter", "facebook.com/cert", "transparencyreport"]):
            q_domain = parse_domain_from_url(url, params)
            if timeout_sources:
                # simulate timeout
                raise _make_requests_timeout()
            return FakeHTTPResponse(url, status=200, json_data=ct_names)
        if any(k in host for k in ["google.", "bing.", "duckduckgo", "yahoo.", "baidu", "search"]):
            if timeout_sources:
                raise _make_requests_timeout()
            html = f"<html><body>{search_hits}</body></html>"
            return FakeHTTPResponse(url, status=200, text=html)
        # default generic
        return FakeHTTPResponse(url, status=404, text="")

    class FakeURLLibResponse:
        def __init__(self, resp: FakeHTTPResponse):
            self._resp = resp

        def read(self):
            return self._resp.content

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urllib_urlopen(url, timeout=None):
        # reuse same logic as requests.get
        resp = fake_requests_get(url, timeout=timeout)
        return FakeURLLibResponse(resp)

    return fake_requests_get, fake_urllib_urlopen


def _make_requests_timeout():
    try:
        import requests

        return requests.Timeout("Timeout")
    except Exception:
        # fallback Exception type
        class _Timeout(Exception):
            pass

        return _Timeout("Timeout")


def build_mock_dns(domain_normal="example.com", wildcard_domain="wild.example.com"):
    """
    Build fake DNS resolver behavior for socket.* APIs.
    """
    valid_full = make_valid_fqdns(domain_normal)

    def _resolve_to_ip(host):
        # Normalize hostname
        h = host.strip(".").lower()
        # Known valid under normal domain
        if h in valid_full:
            label = h.split(".")[0]
            return VALID_IPS.get(label, "127.0.0.42")
        # Wildcard domain: any subdomain returns same IP
        if h.endswith("." + wildcard_domain) and h != wildcard_domain:
            return "127.0.0.66"
        # Non-existent
        raise socket.gaierror(f"Name or service not known: {host}")

    def fake_gethostbyname(host):
        return _resolve_to_ip(host)

    def fake_gethostbyname_ex(host):
        ip = _resolve_to_ip(host)
        return (host, [], [ip])

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        ip = _resolve_to_ip(host)
        # Return a tuple similar to real getaddrinfo
        return [
            (family or socket.AF_INET, type or socket.SOCK_STREAM, proto or 6, "", (ip, port or 80)),
        ]

    # Optional dnspython resolver mock
    class _DNSAnswer:
        def __init__(self, host):
            self.host = host
            self._ip = _resolve_to_ip(host)

        def __iter__(self):
            return iter([self])

        @property
        def address(self):
            return self._ip

        def to_text(self):
            return self._ip

    class _FakeDNSResolver:
        def resolve(self, host, rdtype="A", lifetime=None):
            _resolve_to_ip(host)
            return [_DNSAnswer(host)]

        def query(self, host, rdtype="A", lifetime=None):
            return self.resolve(host, rdtype, lifetime)

    return fake_gethostbyname, fake_gethostbyname_ex, fake_getaddrinfo, _FakeDNSResolver()


@pytest.fixture
def mock_network(monkeypatch):
    """
    Apply DNS and HTTP mocks for default domain example.com and wildcard domain wild.example.com.
    """
    # DNS mocks
    fake_gethostbyname, fake_gethostbyname_ex, fake_getaddrinfo, fake_dns_resolver = build_mock_dns()
    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    # dnspython if present
    try:
        import dns.resolver as _resolver  # type: ignore

        monkeypatch.setattr(_resolver.Resolver, "resolve", lambda self, host, rdtype="A", lifetime=None: fake_dns_resolver.resolve(host, rdtype, lifetime))
        monkeypatch.setattr(_resolver.Resolver, "query", lambda self, host, rdtype="A", lifetime=None: fake_dns_resolver.query(host, rdtype, lifetime))
        monkeypatch.setattr(_resolver, "resolve", lambda host, rdtype="A", lifetime=None: fake_dns_resolver.resolve(host, rdtype, lifetime))
        monkeypatch.setattr(_resolver, "query", lambda host, rdtype="A", lifetime=None: fake_dns_resolver.query(host, rdtype, lifetime))
    except Exception:
        pass

    # HTTP mocks (normal)
    fake_requests_get, fake_urllib_urlopen = build_mock_http_for_domain("example.com", timeout_sources=False)
    # For wildcard domain, return empty/noisy data; DNS wildcard resolution should cause filtering
    fake_requests_get_wild, fake_urllib_urlopen_wild = build_mock_http_for_domain("wild.example.com", timeout_sources=False)

    # Patch requests
    try:
        import requests  # noqa: F401

        # We will dispatch based on URL to the appropriate mock
        def dispatcher(url, *args, **kwargs):
            if "wild.example.com" in url:
                return fake_requests_get_wild(url, *args, **kwargs)
            return fake_requests_get(url, *args, **kwargs)

        monkeypatch.setattr(sys.modules["requests"], "get", dispatcher, raising=True)
    except Exception:
        # Create a minimal fake requests module if not installed
        fake_requests = types.SimpleNamespace()
        fake_requests.Timeout = type("Timeout", (Exception,), {})
        fake_requests.get = lambda url, *args, **kwargs: (fake_requests_get_wild if "wild.example.com" in url else fake_requests_get)(url, *args, **kwargs)
        sys.modules["requests"] = fake_requests

    # Patch urllib
    import urllib.request as urllib_request  # type: ignore

    def urllib_dispatcher(url, *args, **kwargs):
        target = url if isinstance(url, str) else getattr(url, "full_url", str(url))
        if "wild.example.com" in target:
            return fake_urllib_urlopen_wild(target, *args, **kwargs)
        return fake_urllib_urlopen(target, *args, **kwargs)

    monkeypatch.setattr(urllib_request, "urlopen", urllib_dispatcher, raising=True)


@pytest.fixture
def mock_http_timeouts(monkeypatch):
    """
    Patch HTTP clients to raise timeouts for CT logs and search engines.
    """
    fake_requests_get, fake_urllib_urlopen = build_mock_http_for_domain("example.com", timeout_sources=True)
    fake_requests_get_wild, fake_urllib_urlopen_wild = build_mock_http_for_domain("wild.example.com", timeout_sources=True)

    # Patch requests
    try:
        import requests  # noqa: F401

        def dispatcher(url, *args, **kwargs):
            if "wild.example.com" in url:
                return fake_requests_get_wild(url, *args, **kwargs)
            return fake_requests_get(url, *args, **kwargs)

        monkeypatch.setattr(sys.modules["requests"], "get", dispatcher, raising=True)
    except Exception:
        fake_requests = types.SimpleNamespace()
        fake_requests.Timeout = type("Timeout", (Exception,), {})
        fake_requests.get = lambda url, *args, **kwargs: (fake_requests_get_wild if "wild.example.com" in url else fake_requests_get)(url, *args, **kwargs)
        sys.modules["requests"] = fake_requests

    # Patch urllib
    import urllib.request as urllib_request  # type: ignore

    def urllib_dispatcher(url, *args, **kwargs):
        target = url if isinstance(url, str) else getattr(url, "full_url", str(url))
        if "wild.example.com" in target:
            return fake_urllib_urlopen_wild(target, *args, **kwargs)
        return fake_urllib_urlopen(target, *args, **kwargs)

    monkeypatch.setattr(urllib_request, "urlopen", urllib_dispatcher, raising=True)


def import_tool_module():
    # Import the module under test
    import importlib

    return importlib.import_module("tools.recon.subdomain_hunter")


def choose_runner(module):
    """
    Return a callable runner(domain, **kw) -> (result, instance_or_None)
    Tries multiple known entry points.
    """
    candidate_class_names = ["SubdomainHunter", "SubdomainEnumerator", "Hunter"]
    candidate_method_names = [
        "enumerate",
        "enumerate_subdomains",
        "find_subdomains",
        "run",
        "scan",
        "search",
        "hunt",
    ]
    candidate_function_names = [
        "enumerate_subdomains",
        "find_subdomains",
        "run",
        "scan",
        "search_subdomains",
        "hunt",
    ]

    instance = None
    runner_func = None

    # Try class-based
    for cname in candidate_class_names:
        cls = getattr(module, cname, None)
        if cls is None:
            continue
        try:
            # Try to instantiate with minimal args
            try:
                instance = cls()
            except Exception:
                # Try common kwargs
                try:
                    instance = cls(concurrency=8)
                except Exception:
                    instance = cls(wordlist=None)
            # Find method
            for m in candidate_method_names:
                if hasattr(instance, m):
                    meth = getattr(instance, m)
                    if callable(meth):
                        runner_func = meth
                        break
            if runner_func:
                break
        except Exception:
            instance = None
            runner_func = None

    # Try function-based
    if runner_func is None:
        for fname in candidate_function_names:
            func = getattr(module, fname, None)
            if func and callable(func):
                runner_func = func
                break

    if runner_func is None:
        # Fallback: module-level main
        if hasattr(module, "main") and callable(getattr(module, "main")):
            runner_func = getattr(module, "main")

    if runner_func is None:
        raise RuntimeError("No suitable runner found in tools.recon.subdomain_hunter")

    def _caller(domain, timeout=None, enable_wildcard_filter=True):
        nonlocal instance, runner_func
        func = runner_func
        sig = inspect.signature(func)
        # Default kwargs attempting to match parameter names
        kw = {}
        params = sig.parameters
        # Map of possible kw aliases
        aliases = {
            "domain": domain,
            "target": domain,
            "base_domain": domain,
            "root_domain": domain,
            "timeout": timeout if timeout is not None else 2.0,
            "request_timeout": timeout if timeout is not None else 2.0,
            "http_timeout": timeout if timeout is not None else 2.0,
            "dns_timeout": timeout if timeout is not None else 2.0,
            "max_workers": 8,
            "concurrency": 8,
            "workers": 8,
            "filter_wildcards": enable_wildcard_filter,
            "wildcard_filter": enable_wildcard_filter,
            "validate_dns": True,
            "verify": True,
            "use_ct_logs": True,
            "use_search": True,
            "wordlist": ["www", "api", "mail", "dev", "test", "staging", "blog"],
        }
        # Positional domain argument if needed
        args = []
        if params:
            # If first parameter likely is domain, try positional
            first = next(iter(params.values()))
            if first.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
                # Provide the domain if no explicit name match
                if first.name in ("domain", "target", "base_domain", "root_domain", "host"):
                    args.append(domain)
        # Fill kwargs by intersection
        for name in params:
            if name in aliases:
                kw[name] = aliases[name]
            elif name in ("host", "hostname"):
                kw[name] = domain
        # Invoke
        if instance is not None and func.__self__ is instance:
            res = func(*args, **kw)
            return res, instance
        else:
            res = func(*args, **kw)
            return res, None

    return _caller


def extract_subdomains(result, instance=None):
    subs = set()
    original = result
    # If tuple (subs, meta)
    if isinstance(result, tuple) and result:
        result = result[0]
    # If dict-like
    if isinstance(result, dict):
        for key in ("subdomains", "results", "hosts", "data"):
            if key in result and isinstance(result[key], (list, set, tuple)):
                subs = set(map(str, result[key]))
                break
    # If list or set
    if not subs and isinstance(result, (list, set, tuple)):
        subs = set(map(str, result))
    # If object with attribute
    candidate_attrs = ["subdomains", "results", "hosts"]
    if not subs:
        for attr in candidate_attrs:
            if hasattr(result, attr):
                val = getattr(result, attr)
                if isinstance(val, (list, set, tuple)):
                    subs = set(map(str, val))
                    break
    # If instance provided, and nothing yet
    if not subs and instance is not None:
        for attr in candidate_attrs:
            if hasattr(instance, attr):
                val = getattr(instance, attr)
                if isinstance(val, (list, set, tuple)):
                    subs = set(map(str, val))
                    break
            # Possibly a method to get results
            if hasattr(instance, f"get_{attr}") and callable(getattr(instance, f"get_{attr}")):
                try:
                    val = getattr(instance, f"get_{attr}")()
                    if isinstance(val, (list, set, tuple)):
                        subs = set(map(str, val))
                        break
                except Exception:
                    pass
    # Normalize to lowercase FQDNs without trailing dot
    normalized = set()
    for s in subs:
        s2 = s.strip().rstrip(".").lower()
        normalized.add(s2)
    return normalized


def get_wildcard_flag(instance):
    if instance is None:
        return None
    for attr in ("wildcard_detected", "wildcard", "has_wildcard"):
        if hasattr(instance, attr):
            try:
                return bool(getattr(instance, attr))
            except Exception:
                continue
    # method
    for meth in ("is_wildcard", "detect_wildcard"):
        if hasattr(instance, meth) and callable(getattr(instance, meth)):
            try:
                return bool(getattr(instance, meth)())
            except Exception:
                continue
    return None


# ------------------------------
# Tests
# ------------------------------

def test_find_at_least_five_subdomains(mock_network):
    # Import after mocks applied
    mod = import_tool_module()
    runner = choose_runner(mod)
    result, instance = runner("example.com")
    subs = extract_subdomains(result, instance)
    # Only valid, canonical under example.com
    valid = {s for s in subs if is_valid_hostname(s, "example.com")}
    assert len(valid) >= 5, f"Expected at least 5 subdomains, got {len(valid)}: {sorted(valid)}"
    # Ensure they all end with domain and are FQDNs
    assert all(s.endswith(".example.com") and s.count(".") >= 2 for s in valid)


def test_unique_and_valid_subdomains_only(mock_network):
    mod = import_tool_module()
    runner = choose_runner(mod)
    result, instance = runner("example.com")
    # If the tool returns a list, ensure uniqueness
    if isinstance(result, list):
        assert len(result) == len(set(map(str.lower, map(str, result)))), "Results should be unique"
    subs = extract_subdomains(result, instance)
    # Validate names and ensure no invalid items present
    assert all(is_valid_hostname(s, "example.com") for s in subs), "All subdomains must be valid"
    # Check known invalid candidates are not present
    invalids = {
        "in valid.example.com",
        "-bad.example.com",
        "foo..example.com",
        "bad_sub.example.com",
    }
    assert subs.isdisjoint(invalids), f"Invalid subdomains leaked into results: {subs.intersection(invalids)}"


def test_detect_wildcard_dns_and_filtering(mock_network):
    mod = import_tool_module()
    runner = choose_runner(mod)
    result, instance = runner("wild.example.com")
    subs = extract_subdomains(result, instance)
    # With wildcard DNS and no genuine known hosts, results should be empty after filtering
    assert len(subs) == 0, f"Wildcard DNS should be filtered; expected no subdomains, got {sorted(subs)}"
    # If implementation exposes a flag, ensure it's True
    flag = get_wildcard_flag(instance)
    if flag is not None:
        assert flag is True


def test_handle_timeouts_gracefully(mock_network, mock_http_timeouts):
    mod = import_tool_module()
    runner = choose_runner(mod)
    # Execution should not raise despite HTTP timeouts
    try:
        result, instance = runner("example.com", timeout=0.5)
    except Exception as e:
        pytest.fail(f"Tool did not handle timeouts gracefully: {e}")
    subs = extract_subdomains(result, instance)
    # Should still return results from DNS brute force (we mocked DNS to resolve common ones)
    # At minimum, ensure it didn't crash and any outputs are valid
    assert all(is_valid_hostname(s, "example.com") for s in subs)
    # Also ensure it returns unique outputs
    assert len(subs) == len(set(subs))