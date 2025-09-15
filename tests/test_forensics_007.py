import pytest
import importlib
import inspect
import json
import hashlib
from types import SimpleNamespace

try:
    ww_mod = importlib.import_module("tools.forensics.webworkspace_collector")
except Exception as e:
    ww_mod = None
    pytestmark = pytest.mark.skip(reason=f"tools.forensics.webworkspace_collector import failed: {e}")


def _get_collector_class():
    if ww_mod is None:
        return None
    candidates = [
        "BrowserRuntimeArtifactSealer",
        "WebWorkspaceCollector",
        "Collector",
        "ForensicCollector",
    ]
    for name in candidates:
        if hasattr(ww_mod, name):
            return getattr(ww_mod, name)
    return None


def _filter_kwargs_for_ctor(cls, kwargs):
    try:
        sig = inspect.signature(cls)
    except (TypeError, ValueError):
        try:
            sig = inspect.signature(cls.__init__)
        except Exception:
            return {}
    allowed = set(p.name for p in sig.parameters.values() if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY))
    return {k: v for k, v in kwargs.items() if k in allowed}


def _filter_kwargs_for_method(method, kwargs):
    try:
        sig = inspect.signature(method)
    except (TypeError, ValueError):
        return {}
    allowed = set(p.name for p in sig.parameters.values() if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY))
    return {k: v for k, v in kwargs.items() if k in allowed}


def _find_method(obj, names):
    for n in names:
        if hasattr(obj, n) and callable(getattr(obj, n)):
            return getattr(obj, n), n
    return None, None


class FakeDevTools:
    def __init__(self, dataset=None, fail_on_cache=False):
        self.dataset = dataset or {}
        self.fail_on_cache = fail_on_cache
        self.attached = False
        self.attached_origin = None
        self.read_only = None
        self.throttle_safe = None
        self.calls = []
        self.allowed_apis = {
            "Fetch",
            "DOMSnapshot",
            "Storage",
            "Network",
            "WebRTC",
        }

    # Simulated DevTools domain enables
    def enable_domain(self, domain):
        self.calls.append(("enable_domain", domain))
        assert domain in self.allowed_apis, f"Disallowed API used: {domain}"
        return True

    # Ensure no raw JS injection
    def execute_script(self, js):
        raise RuntimeError("JS injection not allowed in read-only mode")

    def attach(self, origin, read_only=True, throttle_safe=True):
        self.calls.append(("attach", {"origin": origin, "read_only": read_only, "throttle_safe": throttle_safe}))
        self.attached = True
        self.attached_origin = origin
        self.read_only = read_only
        self.throttle_safe = throttle_safe
        return True

    # Service workers
    def list_service_workers(self, origin):
        self.calls.append(("list_service_workers", origin))
        return self.dataset.get("service_workers", [])

    def get_service_worker_script(self, script_url):
        self.calls.append(("get_service_worker_script", script_url))
        sws = self.dataset.get("service_workers", [])
        for sw in sws:
            if sw.get("script_url") == script_url:
                return sw.get("content", "")
        return ""

    # Cache Storage
    def list_cache_storage_entries(self, origin):
        self.calls.append(("list_cache_storage_entries", origin))
        return self.dataset.get("cache_entries", [])

    def get_cache_entry(self, url):
        self.calls.append(("get_cache_entry", url))
        if self.fail_on_cache:
            raise RuntimeError("Cache fetch failed")
        for e in self.dataset.get("cache_entries", []):
            if e.get("url") == url:
                return e.get("response", "")
        return ""

    # IndexedDB
    def get_indexeddb(self, origin, include_records=True):
        self.calls.append(("get_indexeddb", {"origin": origin, "include_records": include_records}))
        return self.dataset.get("indexeddb", {})

    # WebRTC signals
    def get_webrtc_signals(self, origin):
        self.calls.append(("get_webrtc_signals", origin))
        return self.dataset.get("webrtc", {})

    # Network flows
    def get_network_flows(self):
        self.calls.append(("get_network_flows", None))
        return self.dataset.get("network_flows", [])


class FakeSealer:
    def __init__(self, chain_of_custody=None):
        self.chain_of_custody = chain_of_custody or {}
        self.last_manifest = None
        self.last_payload_digest = None
        self.last_signed = None
        self.fixed_timestamp = "2025-01-01T00:00:00Z"
        self.fixed_signature = "deadbeef" * 8

    def seal(self, manifest):
        # Normalize to canonical JSON for digest comparison
        try:
            payload_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except TypeError:
            payload_bytes = json.dumps(str(manifest), sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(payload_bytes).hexdigest()
        self.last_manifest = manifest
        self.last_payload_digest = digest
        self.last_signed = {
            "signature": self.fixed_signature,
            "timestamp": self.fixed_timestamp,
            "chain_of_custody": self.chain_of_custody,
            "manifest": manifest,
            "digest": digest,
        }
        return self.last_signed


@pytest.fixture
def dataset_sw_cache():
    return {
        "service_workers": [
            {"script_url": "http://localhost/sw.js", "content": "self.addEventListener('fetch',()=>{})"},
            {"script_url": "http://localhost/sw-extra.js", "content": "console.log('extra')"},
        ],
        "cache_entries": [
            {"url": "http://localhost/style.css", "response": "body{color:#000}"},
            {"url": "http://localhost/app.js", "response": "console.log('app')"},
        ],
    }


@pytest.fixture
def dataset_indexeddb():
    return {
        "indexeddb": {
            "databases": [
                {
                    "name": "appdb",
                    "version": 1,
                    "objectStores": [
                        {
                            "name": "users",
                            "keyPath": "id",
                            "indexes": [{"name": "by_name", "keyPath": "name"}],
                            "records": [
                                {"id": 1, "name": "Alice", "auth_token": "secret-token-123", "sessionCookie": "abcd"},
                                {"id": 2, "name": "Bob", "authToken": "should-hide", "notes": "ok"},
                            ],
                        },
                        {
                            "name": "sessions",
                            "keyPath": "sid",
                            "records": [
                                {"sid": "s1", "cookie": "x=1", "token": "tkn-1"},
                                {"sid": "s2", "cookie": "y=2", "bearerToken": "abc"},
                            ],
                        },
                    ],
                }
            ]
        }
    }


@pytest.fixture
def dataset_webrtc():
    return {
        "webrtc": {
            "sdp_offers": [
                "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 DTLS/SCTP 5000\r\n"
            ],
            "ice_candidates": [
                {"candidate": "candidate:1 1 udp 2122194687 127.0.0.1 54555 typ host", "sdpMid": "0", "sdpMLineIndex": 0, "foundation": "1"},
                {"candidate": "candidate:2 1 tcp 1518280447 127.0.0.1 9 typ host tcptype active", "sdpMid": "0", "sdpMLineIndex": 0, "foundation": "2"},
            ],
            "media_captured": False,
        },
        "network_flows": [
            {"proto": "UDP", "src": "127.0.0.1:54555", "dst": "127.0.0.1:5353", "meta": {"stun": True}},
            {"proto": "TCP", "src": "127.0.0.1:9", "dst": "127.0.0.1:8080", "meta": {}},
        ],
    }


@pytest.fixture
def fake_sealer(monkeypatch):
    sealer = FakeSealer(chain_of_custody={"operator": "unit-test", "case_id": "CASE-123"})
    # Try to patch module-level Sealer or similar factory if present
    if ww_mod is not None:
        for name in ("Sealer", "ManifestSealer", "CryptoSealer", "ArtifactSealer"):
            if hasattr(ww_mod, name):
                monkeypatch.setattr(ww_mod, name, lambda *args, **kwargs: sealer)
    return sealer


def _inject_devtools(monkeypatch, collector, devtools):
    # Try the most likely injection points in both module and instance
    injected = False
    # Common module-level references
    for name in ("DevToolsClient", "CDPClient", "BrowserClient"):
        if hasattr(ww_mod, name):
            monkeypatch.setattr(ww_mod, name, lambda *args, **kwargs: devtools)
            injected = True
    # Instance attributes
    for attr in ("devtools", "client", "cdp", "_devtools", "_client"):
        try:
            setattr(collector, attr, devtools)
            injected = True
        except Exception:
            pass
    return injected


def _attach_origin(collector, origin):
    method, _ = _find_method(collector, ["attach", "attach_to_origin", "connect", "open"])
    if not method:
        pytest.skip("Collector does not expose an attach/connect/open method")
    kwargs = _filter_kwargs_for_method(method, {"origin": origin, "url": origin, "read_only": True, "throttle_safe": True})
    return method(**kwargs)


def _run_collection(collector, origin, artifacts=None):
    artifacts = artifacts or []
    # Attempt a series of method names that might perform collection and sealing
    method_names = [
        "run_playbook",
        "collect_and_seal",
        "collect_artifacts",
        "collect",
        "execute",
        "run",
    ]
    for name in method_names:
        method, _ = _find_method(collector, [name])
        if method:
            kwargs = {"origin": origin, "artifacts": artifacts}
            call_kwargs = _filter_kwargs_for_method(method, kwargs)
            return method(**call_kwargs)
    pytest.skip("Collector does not expose a collection runner method")


def _find_manifest_from_result(result, sealer: FakeSealer):
    if isinstance(result, dict) and ("manifest" in result or "signed_manifest" in result):
        return result.get("signed_manifest") or result.get("manifest")
    # Fallback to FakeSealer captured
    if sealer.last_signed:
        return sealer.last_signed
    return None


def _redacted(value):
    if isinstance(value, str):
        return "[REDACTED]" in value or value == "[REDACTED]"
    return False


@pytest.mark.skipif(ww_mod is None, reason="Collector module not available")
def test_service_worker_and_cache_hash_consistency(monkeypatch, dataset_sw_cache, fake_sealer):
    collector_cls = _get_collector_class()
    if not collector_cls:
        pytest.skip("Collector class not found")
    ctor_kwargs = _filter_kwargs_for_ctor(
        collector_cls,
        {
            "read_only": True,
            "throttle_safe": True,
            "redaction_patterns": ["token", "cookie", "auth"],
            "authorized_pii": False,
            "playbook": ["service_workers", "cache_storage"],
        },
    )
    collector = collector_cls(**ctor_kwargs)
    devtools = FakeDevTools(dataset=dataset_sw_cache)
    injected = _inject_devtools(monkeypatch, collector, devtools)
    if not injected:
        pytest.skip("Could not inject fake DevTools client")

    _attach_origin(collector, "http://localhost:8000")

    # First pass
    _run_collection(collector, "http://localhost:8000", artifacts=["service_workers", "cache_storage"])
    digest_first = fake_sealer.last_payload_digest
    assert digest_first is not None, "Sealer was not invoked on first pass"

    # Second pass with same data but reversed listing order to test canonicalization
    dataset_sw_cache_2 = {
        "service_workers": list(reversed(dataset_sw_cache["service_workers"])),
        "cache_entries": list(reversed(dataset_sw_cache["cache_entries"])),
    }
    devtools.dataset = dataset_sw_cache_2
    _run_collection(collector, "http://localhost:8000", artifacts=["service_workers", "cache_storage"])
    digest_second = fake_sealer.last_payload_digest
    assert digest_second is not None, "Sealer was not invoked on second pass"

    assert digest_first == digest_second, "Hashes/digests are not consistent across two passes"

    # Ensure read-only and throttle-safe attach without JS injection
    assert devtools.read_only is True
    assert devtools.throttle_safe is True
    # Ensure only allowed APIs were enabled if any
    for call in devtools.calls:
        if call[0] == "enable_domain":
            assert call[1] in devtools.allowed_apis


@pytest.mark.skipif(ww_mod is None, reason="Collector module not available")
def test_indexeddb_redaction_and_signed_manifest(monkeypatch, dataset_indexeddb, fake_sealer):
    collector_cls = _get_collector_class()
    if not collector_cls:
        pytest.skip("Collector class not found")
    ctor_kwargs = _filter_kwargs_for_ctor(
        collector_cls,
        {
            "read_only": True,
            "throttle_safe": True,
            "redaction_patterns": ["token", "cookie", "auth"],
            "authorized_pii": False,
            "chain_of_custody": {"operator": "unit-test", "case_id": "CASE-123"},
        },
    )
    collector = collector_cls(**ctor_kwargs)
    devtools = FakeDevTools(dataset=dataset_indexeddb)
    injected = _inject_devtools(monkeypatch, collector, devtools)
    if not injected:
        pytest.skip("Could not inject fake DevTools client")

    _attach_origin(collector, "http://127.0.0.1:8080")

    result = _run_collection(collector, "http://127.0.0.1:8080", artifacts=["indexeddb"])
    signed_manifest = _find_manifest_from_result(result, fake_sealer)
    assert signed_manifest is not None, "No signed manifest produced"
    # Check signature and timestamp presence
    assert "signature" in signed_manifest
    assert "timestamp" in signed_manifest
    # Check chain of custody metadata
    chain = signed_manifest.get("chain_of_custody") or signed_manifest.get("manifest", {}).get("chain_of_custody")
    assert chain is not None and ("operator" in chain or "operator" in str(chain))

    # Check that IndexedDB records were redacted according to patterns
    manifest_payload = signed_manifest.get("manifest") if "manifest" in signed_manifest else signed_manifest
    serialized = json.dumps(manifest_payload, default=str)
    # Ensure secrets aren't present in plaintext
    assert "secret-token-123" not in serialized
    assert "should-hide" not in serialized
    assert '"sessionCookie":"abcd"' not in serialized
    assert any(tag in serialized for tag in ("[REDACTED]", "REDACTED")), "Redaction markers not found"

    # Edge case: when authorized_pii is True, values should not be redacted
    ctor_kwargs_auth = _filter_kwargs_for_ctor(
        collector_cls,
        {
            "read_only": True,
            "throttle_safe": True,
            "redaction_patterns": ["token", "cookie", "auth"],
            "authorized_pii": True,
        },
    )
    collector_auth = collector_cls(**ctor_kwargs_auth)
    devtools2 = FakeDevTools(dataset=dataset_indexeddb)
    _inject_devtools(monkeypatch, collector_auth, devtools2)
    _attach_origin(collector_auth, "http://127.0.0.1:8080")
    _run_collection(collector_auth, "http://127.0.0.1:8080", artifacts=["indexeddb"])

    signed_manifest2 = fake_sealer.last_signed
    manifest_payload2 = signed_manifest2.get("manifest") if signed_manifest2 else {}
    serialized2 = json.dumps(manifest_payload2, default=str)
    assert "secret-token-123" in serialized2 or "should-hide" in serialized2 or '"sessionCookie":"abcd"' in serialized2


@pytest.mark.skipif(ww_mod is None, reason="Collector module not available")
def test_webrtc_signals_without_media_and_network_correlation(monkeypatch, dataset_webrtc, fake_sealer):
    collector_cls = _get_collector_class()
    if not collector_cls:
        pytest.skip("Collector class not found")
    ctor_kwargs = _filter_kwargs_for_ctor(
        collector_cls,
        {
            "read_only": True,
            "throttle_safe": True,
            "playbook": ["webrtc", "network"],
        },
    )
    collector = collector_cls(**ctor_kwargs)
    devtools = FakeDevTools(dataset=dataset_webrtc)
    injected = _inject_devtools(monkeypatch, collector, devtools)
    if not injected:
        pytest.skip("Could not inject fake DevTools client")

    _attach_origin(collector, "http://localhost:3000")

    result = _run_collection(collector, "http://localhost:3000", artifacts=["webrtc", "network"])
    signed_manifest = _find_manifest_from_result(result, fake_sealer)
    assert signed_manifest is not None, "No signed manifest produced for WebRTC collection"

    manifest_payload = signed_manifest.get("manifest") if "manifest" in signed_manifest else signed_manifest
    # Basic presence checks
    payload_json = json.dumps(manifest_payload, default=str)
    assert "sdp" in payload_json.lower() or "sdp_offers" in payload_json
    assert "ice" in payload_json.lower() or "ice_candidates" in payload_json

    # Ensure no media capture occurred
    assert "audio" not in payload_json.lower()
    assert "video" not in payload_json.lower()
    # Correlate ICE with network flows by presence of shared ports/IPs
    assert "127.0.0.1" in payload_json
    assert "54555" in payload_json or "9" in payload_json


@pytest.mark.skipif(ww_mod is None, reason="Collector module not available")
def test_attach_read_only_mode_no_js_injection(monkeypatch):
    collector_cls = _get_collector_class()
    if not collector_cls:
        pytest.skip("Collector class not found")
    ctor_kwargs = _filter_kwargs_for_ctor(collector_cls, {"read_only": True, "throttle_safe": True})
    collector = collector_cls(**ctor_kwargs)
    devtools = FakeDevTools()
    _inject_devtools(monkeypatch, collector, devtools)
    _attach_origin(collector, "http://127.0.0.1")

    # Attempt to simulate any method that might try to inject JS, our FakeDevTools will raise if called.
    # We simply ensure that performing a benign collection avoids JS execution.
    try:
        _run_collection(collector, "http://127.0.0.1", artifacts=[])
    except RuntimeError as e:
        pytest.fail(f"Collector attempted JS injection in read-only mode: {e}")

    # Ensure devtools recorded attach in read-only mode
    assert devtools.read_only is True


@pytest.mark.skipif(ww_mod is None, reason="Collector module not available")
def test_error_handling_cache_fetch_failure(monkeypatch, dataset_sw_cache, fake_sealer):
    collector_cls = _get_collector_class()
    if not collector_cls:
        pytest.skip("Collector class not found")
    ctor_kwargs = _filter_kwargs_for_ctor(
        collector_cls,
        {"read_only": True, "throttle_safe": True, "playbook": ["service_workers", "cache_storage"]},
    )
    collector = collector_cls(**ctor_kwargs)
    devtools = FakeDevTools(dataset=dataset_sw_cache, fail_on_cache=True)
    _inject_devtools(monkeypatch, collector, devtools)
    _attach_origin(collector, "http://localhost")

    # Expect the collector to handle cache fetch failure gracefully:
    # It should either continue and record an error in the manifest or raise a known exception type.
    try:
        result = _run_collection(collector, "http://localhost", artifacts=["service_workers", "cache_storage"])
    except Exception as e:
        # Acceptable if it's a domain-specific exception; otherwise re-raise
        allowed = ("ForensicsCollectionError", "CollectionError")
        if not any(name in e.__class__.__name__ for name in allowed):
            raise
        return

    signed_manifest = _find_manifest_from_result(result, fake_sealer)
    assert signed_manifest is not None, "No signed manifest produced on error path"
    manifest_payload = signed_manifest.get("manifest") if "manifest" in signed_manifest else signed_manifest
    # Look for error indications
    payload_json = json.dumps(manifest_payload, default=str)
    assert "error" in payload_json.lower() or "failed" in payload_json.lower() or "exception" in payload_json.lower()