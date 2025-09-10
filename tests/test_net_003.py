import importlib
import json
import types
import hashlib
import pytest
from copy import deepcopy


@pytest.fixture(scope="module")
def hunter_mod():
    return importlib.import_module("tools.network.dnscovert_hunter")


def _get_detector_class_or_factory(mod):
    # Try common names for class or factory
    candidates = [
        "DNSCovertHunter",
        "DnsCovertHunter",
        "Detector",
        "get_detector",
        "create_detector",
        "new_detector",
    ]
    for name in candidates:
        obj = getattr(mod, name, None)
        if obj is None:
            continue
        if isinstance(obj, type):
            return obj
        if callable(obj):
            try:
                inst = obj()
                return inst.__class__
            except Exception:
                continue
    pytest.skip("No detector class or factory found in tools.network.dnscovert_hunter")


@pytest.fixture
def detector(hunter_mod):
    cls = _get_detector_class_or_factory(hunter_mod)
    try:
        det = cls()
    except TypeError:
        # Try no-arg factory as fallback
        factory = getattr(hunter_mod, "get_detector", None) or getattr(hunter_mod, "create_detector", None)
        if factory:
            det = factory()
        else:
            det = cls()
    # Try to set allowlist strictly
    allowlist = {
        "hosts": {"approved.doh.local"},
        "ips": {"127.0.0.1"},
        "fingerprints": set(),
    }
    _set_allowlist(det, allowlist)
    # Try to reduce noise/reset state
    _clear_state(det)
    return det


def _find_method(obj, names):
    for n in names:
        m = getattr(obj, n, None)
        if callable(m):
            return m
    return None


def _set_allowlist(detector, allowlist):
    setter = _find_method(detector, ["set_allowlist", "configure_allowlist", "set_resolver_allowlist", "configure"])
    if setter:
        try:
            setter(allowlist)
            return
        except TypeError:
            try:
                setter(hosts=allowlist.get("hosts"), ips=allowlist.get("ips"))
                return
            except Exception:
                pass
    # Try attributes
    for key in ("allowlist", "resolver_allowlist", "approved_resolvers"):
        if hasattr(detector, key):
            setattr(detector, key, allowlist)
            return


def _clear_state(detector):
    clearer = _find_method(detector, ["reset", "clear", "clear_state"])
    if clearer:
        try:
            clearer()
        except Exception:
            pass
    # clear alerts if possible
    clearer_alerts = _find_method(detector, ["clear_alerts", "reset_alerts"])
    if clearer_alerts:
        try:
            clearer_alerts()
        except Exception:
            pass


def _ingest(detector, flow):
    ingest = _find_method(detector, ["ingest_flow", "ingest", "process_flow", "process", "submit_flow"])
    if not ingest:
        raise AssertionError("Detector has no flow ingestion method")
    return ingest(flow)


def _alerts(detector):
    getter = _find_method(detector, ["get_alerts", "alerts", "pop_alerts"])
    if getter:
        try:
            res = getter()
            # Some implementations return an object with .to_list()
            if hasattr(res, "to_list"):
                return res.to_list()
            return list(res) if res is not None else []
        except TypeError:
            # alerts as property
            pass
    for name in ("alerts", "alert_buffer", "alert_queue"):
        if hasattr(detector, name):
            val = getattr(detector, name)
            try:
                return list(val)
            except Exception:
                try:
                    return list(val())
                except Exception:
                    pass
    return []


def _flow_store(detector):
    getter = _find_method(detector, ["get_flow_store", "get_store", "get_flows", "get_summaries"])
    if getter:
        try:
            return list(getter())
        except Exception:
            pass
    for name in ("flow_store", "store", "flows", "summaries"):
        if hasattr(detector, name):
            try:
                return list(getattr(detector, name))
            except Exception:
                pass
    return []


def _build_baseline(detector, hours=24):
    builder = _find_method(detector, ["build_baseline", "train_baseline", "baseline", "enable_baseline"])
    if builder:
        try:
            builder(hours=hours)
            return
        except TypeError:
            try:
                builder(hours)
                return
            except Exception:
                try:
                    builder()
                    return
                except Exception:
                    pass
    # If no method, assume online learning; nothing to do.


def _export_report(detector, include_signature=True):
    getter = _find_method(detector, ["export_report", "generate_report", "get_report", "detection_report"])
    report = None
    if getter:
        try:
            report = getter(include_signature=include_signature)
        except TypeError:
            try:
                report = getter(sign=include_signature)
            except Exception:
                try:
                    report = getter()
                except Exception:
                    pass
    if report is None:
        # Try module level
        return None
    return report


def _verify_report(hunter_mod, detector, report):
    verifier = _find_method(detector, ["verify_report", "verify"])
    if verifier:
        try:
            return bool(verifier(report))
        except Exception:
            pass
    # Try module-level verify
    for name in ("verify_report", "verify"):
        f = getattr(hunter_mod, name, None)
        if callable(f):
            try:
                return bool(f(report))
            except Exception:
                pass
    return None


def make_flow(ts, src_port, sni, authority, resolver_identity, approved=False, entropy=7.2, sublens=None, ja3="ja3-A", ja4="ja4-A"):
    if sublens is None:
        sublens = [8, 10, 12, 6, 9]
    return {
        "timestamp": float(ts),
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": int(src_port),
        "dst_port": 443,
        "protocol": "TLS",
        "alpn": "h2",
        "tls": {"sni": sni, "ja3": ja3, "ja4": ja4},
        "http2": {"method": "POST", "path": "/dns-query", "authority": authority},
        "doh": True,
        "entropy": float(entropy),
        "subdomain_len_dist": list(sublens),
        "bytes_out": 1400,
        "bytes_in": 2800,
        "packet_sizes": [120, 1450, 110, 1500, 98],
        "resolver_identity": resolver_identity,
        "approved_resolver": bool(approved),
        "flow_id": hashlib.sha256(f"{ts}-{src_port}-{sni}-{authority}".encode()).hexdigest()[:16],
    }


def _has_plausible_covert_alert(alerts):
    for a in alerts:
        t = (a.get("type") or a.get("alert_type") or "").lower()
        name = (a.get("name") or "").lower()
        if "covert" in t or "covert" in name or "dnscovert" in t or "covert_channel" in t:
            return True
        # Also allow label-based
        labels = a.get("labels") or []
        if any("covert" in str(lbl).lower() for lbl in labels):
            return True
    return False


def _get_attributions(alert):
    for key in ("attributions", "explanations", "feature_attributions", "explain"):
        if key in alert:
            return alert[key]
    return None


def _get_confidence(alert):
    for key in ("confidence", "score", "severity"):
        if key in alert:
            try:
                return float(alert[key])
            except Exception:
                pass
    return None


def test_identify_sustained_high_entropy_nonapproved_resolver_triggers_alert_and_preserves_privacy(detector):
    # Set strict allowlist to only approved.doh.local
    _set_allowlist(detector, {"hosts": {"approved.doh.local"}, "ips": {"127.0.0.1"}, "fingerprints": set()})
    _clear_state(detector)

    # Simulate sustained suspicious flows to non-allowlisted resolver
    base_ts = 1_700_000_000.0
    for i in range(50):
        flow = make_flow(
            ts=base_ts + i * 2.0,
            src_port=40000 + i,
            sni="nonapproved.cdn.local",
            authority="nonapproved.doh.local",
            resolver_identity="nonapproved.doh.local",
            approved=False,
            entropy=7.95,  # high
            sublens=[48, 52, 60, 55, 58],  # long subdomain lengths
            ja3="ja3-X",
            ja4="ja4-X",
        )
        _ingest(detector, flow)

    alerts = _alerts(detector)
    assert alerts, "Expected at least one alert for sustained high-entropy DoH POST to non-allowlisted resolver"
    assert _has_plausible_covert_alert(alerts), "Expected a covert-channel alert to be raised"

    # Check explainable attributions include entropy and subdomain length contributions
    matched = False
    for a in alerts:
        attrs = _get_attributions(a) or {}
        keys = set(k.lower() for k in (attrs.keys() if isinstance(attrs, dict) else attrs))
        text = json.dumps(attrs).lower()
        if "entropy" in keys or "entropy" in text:
            if any("subdomain" in k for k in keys) or "subdomain" in text:
                matched = True
                break
    assert matched, "Alert should provide explainable feature attributions including entropy and subdomain length indicators"

    # Verify privacy: stored flow summaries exist and do not contain raw hostnames or payloads; include anonymized metadata
    store = _flow_store(detector)
    assert store, "Expected flow summaries to be stored"
    # No raw payloads or full URIs
    forbidden_keys = {"payload", "raw_payload", "full_uri", "uri", "query", "dns_query", "domain", "hostname", "host"}
    for summary in store:
        for fk in forbidden_keys:
            assert fk not in summary, f"Privacy violation: found raw field {fk} in stored summary"
        # host info should be anonymized (presence of a hash/anonymized key)
        assert any(k in summary for k in ("host_hash", "resolver_hash", "anonymized_host", "host_anonymized")), \
            "Expected anonymized host metadata in flow summaries"


def test_baseline_allowlisted_resolver_no_alerts_for_24h(detector):
    _clear_state(detector)
    # Build/enable baseline if supported
    _build_baseline(detector, hours=24)
    # Approved resolver traffic across 24 hours
    base_ts = 1_700_100_000.0
    for i in range(24 * 6):  # every 10 minutes for 24h
        flow = make_flow(
            ts=base_ts + i * (10 * 60.0),
            src_port=50000 + i,
            sni="approved.cdn.local",
            authority="approved.doh.local",
            resolver_identity="approved.doh.local",
            approved=True,
            entropy=5.1,
            sublens=[7, 5, 8, 6, 9],  # normal
            ja3="ja3-OS",
            ja4="ja4-Browser",
        )
        _ingest(detector, flow)
    alerts = _alerts(detector)
    assert len(alerts) == 0, f"Expected no alerts for baseline traffic to approved resolver, got {len(alerts)}"


def test_detect_domain_fronted_doh_with_sni_mismatch_and_ja_fingerprint_shift(detector):
    _clear_state(detector)

    base_ts = 1_700_200_000.0
    # First half of session: SNI points to CDN, resolver identity points elsewhere; approved False
    for i in range(5):
        flow = make_flow(
            ts=base_ts + i * 1.0,
            src_port=52000,
            sni="cdn.front.local",
            authority="cdn.front.local",
            resolver_identity="evil-resolver.local",
            approved=False,
            entropy=7.0,
            sublens=[12, 14, 11, 13],
            ja3="ja3-F1",
            ja4="ja4-F1",
        )
        _ingest(detector, flow)
    # Mid-session fingerprint shift
    for i in range(5, 10):
        flow = make_flow(
            ts=base_ts + i * 1.0,
            src_port=52000,
            sni="cdn.front.local",
            authority="cdn.front.local",
            resolver_identity="evil-resolver.local",
            approved=False,
            entropy=7.2,
            sublens=[12, 14, 11, 13],
            ja3="ja3-F2",
            ja4="ja4-F2",
        )
        _ingest(detector, flow)

    alerts = _alerts(detector)
    assert alerts, "Expected an alert for domain-fronted DoH with SNI/CDN mismatch and JA3/JA4 shift"
    # Check attributions and high confidence
    got_mismatch = False
    got_shift = False
    high_conf = False
    for a in alerts:
        attrs = (_get_attributions(a) or {})
        text = json.dumps(attrs).lower()
        if "sni" in text and ("mismatch" in text or "cdn" in text):
            got_mismatch = True
        if "ja3" in text or "ja4" in text or "fingerprint" in text:
            if "shift" in text or "change" in text or "mismatch" in text:
                got_shift = True
        conf = _get_confidence(a)
        if conf is not None and conf >= 0.8:
            high_conf = True
    assert got_mismatch, "Expected attribution indicating SNI/CDN host mismatch with resolver identity"
    assert got_shift, "Expected attribution indicating JA3/JA4 fingerprint shift mid-session"
    assert high_conf, "Expected a high-confidence alert for domain-fronted DoH detection"


def test_alert_rate_limiting(detector):
    _clear_state(detector)
    # If detector exposes rate limit config, set it low
    for name in ("set_rate_limit", "configure_rate_limit", "set_alert_rate_limit"):
        setter = _find_method(detector, [name])
        if setter:
            try:
                setter(per_minute=5)
            except TypeError:
                try:
                    setter(5)
                except Exception:
                    pass
            break

    base_ts = 1_700_300_000.0
    # Generate many suspicious flows within one minute
    for i in range(60):
        flow = make_flow(
            ts=base_ts + i,  # within a minute
            src_port=53000 + i,
            sni="sneaky.nonapproved.local",
            authority="sneaky.nonapproved.local",
            resolver_identity="sneaky.nonapproved.local",
            approved=False,
            entropy=7.9,
            sublens=[50, 55, 49, 60],
            ja3="ja3-RL",
            ja4="ja4-RL",
        )
        _ingest(detector, flow)
    alerts = _alerts(detector)
    # Determine limit if exposed
    limit = None
    for name in ("rate_limit_per_minute", "alerts_per_minute", "alert_rate_limit"):
        if hasattr(detector, name):
            try:
                limit = int(getattr(detector, name))
                break
            except Exception:
                pass
    if limit is None:
        limit = 10  # assume a reasonable default upper bound
    assert len(alerts) <= limit, f"Expected alerts to be rate-limited to <= {limit} per minute, got {len(alerts)}"


def test_report_signing_and_integrity_verification(hunter_mod, detector):
    _clear_state(detector)

    # Create a few alerts to include in report
    base_ts = 1_700_400_000.0
    for i in range(8):
        flow = make_flow(
            ts=base_ts + i * 3,
            src_port=54000 + i,
            sni="nonapproved.c2.local",
            authority="nonapproved.c2.local",
            resolver_identity="nonapproved.c2.local",
            approved=False,
            entropy=7.8,
            sublens=[48, 52, 57],
            ja3="ja3-SIGN",
            ja4="ja4-SIGN",
        )
        _ingest(detector, flow)
    alerts = _alerts(detector)
    assert alerts, "Expected alerts to exist for report signing test"

    report = _export_report(detector, include_signature=True)
    assert report is not None, "Detector should export a detection report"
    # Ensure model/version metadata present
    model = report.get("model") or report.get("detector", {})
    model_ver = report.get("model_version") or (model.get("version") if isinstance(model, dict) else None)
    assert model_ver, "Report should include model/version metadata"

    # Integrity verification should pass
    ok = _verify_report(hunter_mod, detector, report)
    assert ok is True, "Report integrity verification should pass on unmodified report"

    # Tamper with report and expect verification failure
    tampered = deepcopy(report)
    # Flip an alert id or hash
    if tampered.get("alerts"):
        tampered["alerts"][0]["tamper"] = "x"
    else:
        tampered["flow_summaries"] = (tampered.get("flow_summaries") or []) + [{"tamper": True}]
    broken = _verify_report(hunter_mod, detector, tampered)
    assert broken is False, "Report integrity verification should fail after tampering"


def test_error_handling_for_malformed_flow(detector):
    _clear_state(detector)
    # Missing essential fields
    malformed = {
        "timestamp": 1_700_500_000.0,
        "src_ip": "127.0.0.1",
        # "dst_ip" missing
        "doh": True,
        "entropy": 7.0,
    }
    ingest = _find_method(detector, ["ingest_flow", "ingest", "process_flow", "process", "submit_flow"])
    if ingest is None:
        pytest.skip("No ingestion method to test error handling")
    threw = False
    try:
        ingest(malformed)
    except (ValueError, KeyError):
        threw = True
    except Exception:
        # Other exceptions are still errors, but do not fail the test; tool may handle internally
        threw = True
    # Either it should gracefully throw a ValueError/KeyError or skip without alerting
    alerts = _alerts(detector)
    assert threw or len(alerts) == 0, "Malformed flow should not cause undefined behavior or spurious alerts"