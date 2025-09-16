import importlib
import types
import pytest


@pytest.fixture(scope="module")
def hunter_module():
    mod = importlib.import_module("tools.network.webrtc_covert_hunter")
    return mod


def _find_hunter_class(mod):
    candidates = [
        "WebRTCCovertHunter",
        "CovertChannelHunter",
        "WebRTCIDS",
        "Hunter",
        "IDS",
    ]
    for name in candidates:
        obj = getattr(mod, name, None)
        if isinstance(obj, type):
            return obj
    return None


def _build_hunter(mod):
    # Try builder functions
    for fn in ("build_hunter", "new_hunter", "create_hunter", "init_hunter"):
        f = getattr(mod, fn, None)
        if callable(f):
            try:
                return f()
            except TypeError:
                # try without args anyway
                return f
    # Try default instance
    for attr in ("HUNTER", "hunter", "IDS", "ids"):
        inst = getattr(mod, attr, None)
        if inst is not None:
            return inst
    # Try class
    cls = _find_hunter_class(mod)
    if cls:
        try:
            return cls()
        except TypeError:
            # Try with no args
            return cls
    return None


@pytest.fixture
def hunter(hunter_module):
    inst = _build_hunter(hunter_module)
    if inst is None:
        pytest.skip("No hunter class/instance/builder exposed by module")
    # If builder returned a class not instance, instantiate now
    if isinstance(inst, type):
        try:
            inst = inst()
        except Exception:
            pytest.skip("Cannot instantiate hunter")
    # Reset state if possible
    for reset_name in ("reset", "reset_state", "reset_baseline", "clear"):
        reset_fn = getattr(inst, reset_name, None)
        if callable(reset_fn):
            try:
                reset_fn()
            except Exception:
                pass
            break
    return inst


def _call_method(obj, names, *args, **kwargs):
    for name in names:
        fn = getattr(obj, name, None)
        if callable(fn):
            return fn(*args, **kwargs)
    # Try as module-level
    if isinstance(obj, types.ModuleType):
        for name in names:
            fn = getattr(obj, name, None)
            if callable(fn):
                return fn(*args, **kwargs)
    raise AttributeError(f"None of methods {names} exist")


def _analyze(hunter, metadata):
    method_names = ("analyze", "analyze_flow", "process", "process_flow", "handle_metadata", "ingest")
    for name in method_names:
        fn = getattr(hunter, name, None)
        if callable(fn):
            return fn(metadata)
    # Try module-level
    mod = importlib.import_module("tools.network.webrtc_covert_hunter")
    for name in method_names:
        fn = getattr(mod, name, None)
        if callable(fn):
            return fn(metadata)
    raise AttributeError("No analyze/process method found on hunter")


def _get_alerts(hunter):
    # Preferred method
    for name in ("get_alerts", "alerts", "flush_alerts", "pop_alerts"):
        attr = getattr(hunter, name, None)
        if callable(attr):
            try:
                result = attr()
                if isinstance(result, list):
                    return result
                # If returns generator or tuple
                try:
                    return list(result)
                except Exception:
                    pass
            except TypeError:
                pass
        elif isinstance(attr, list):
            return list(attr)
    # Try module-level
    mod = importlib.import_module("tools.network.webrtc_covert_hunter")
    for name in ("get_alerts", "alerts", "flush_alerts", "pop_alerts"):
        attr = getattr(mod, name, None)
        if callable(attr):
            res = attr()
            try:
                return list(res)
            except Exception:
                return res
        elif isinstance(attr, list):
            return list(attr)
    return []


def _add_allowlist(h, domains=None, ips=None):
    domains = domains or []
    ips = ips or []
    added = False
    for name in ("add_allowlist", "set_allowlist", "update_allowlist", "allowlist_add", "train_allowlist"):
        fn = getattr(h, name, None)
        if callable(fn):
            try:
                fn(domains=domains, ips=ips)
                added = True
                break
            except TypeError:
                try:
                    fn(domains, ips)
                    added = True
                    break
                except Exception:
                    pass
            except Exception:
                pass
    if not added:
        # Try attributes
        for attr in ("allowlist_domains", "allowed_domains", "sanctioned_domains"):
            if hasattr(h, attr):
                try:
                    current = set(getattr(h, attr) or [])
                except Exception:
                    current = set()
                current.update(domains)
                try:
                    setattr(h, attr, list(current))
                    added = True
                except Exception:
                    pass
        for attr in ("allowlist_ips", "allowed_ips", "sanctioned_ips"):
            if hasattr(h, attr):
                try:
                    current = set(getattr(h, attr) or [])
                except Exception:
                    current = set()
                current.update(ips)
                try:
                    setattr(h, attr, list(current))
                    added = True
                except Exception:
                    pass
    return added


def _verify_signature(h, alert):
    # Prefer built-in verification
    for name in ("verify_alert_signature", "verify_signature", "validate_signature"):
        fn = getattr(h, name, None)
        if callable(fn):
            try:
                return bool(fn(alert))
            except Exception:
                return False
    # Module-level?
    mod = importlib.import_module("tools.network.webrtc_covert_hunter")
    for name in ("verify_alert_signature", "verify_signature", "validate_signature"):
        fn = getattr(mod, name, None)
        if callable(fn):
            try:
                return bool(fn(alert))
            except Exception:
                return False
    # Fallback: check presence of non-empty signature-like fields
    sig = alert.get("signature") or alert.get("sig")
    return isinstance(sig, (str, bytes)) and len(sig) >= 16


def _has_privacy(alert):
    # Ensure raw identifiers not leaked; prefer hashed values
    # Accept if anonymized flag present or hashes present
    anonymized = alert.get("anonymized") or alert.get("privacy_preserving") or False
    id_fields = ("dst_ip", "src_ip", "dst_domain", "src_domain", "user_id", "sdp", "payload")
    raw_present = any(f in alert for f in id_fields)
    hashed_present = any(k.endswith("_hash") for k in alert.keys()) or "identifiers" in alert
    if "identifiers" in alert and isinstance(alert["identifiers"], dict):
        # Ensure identifiers are hashed/anonymized
        id_dict = alert["identifiers"]
        hashed_present = hashed_present or any(k.endswith("_hash") or str(v).startswith("sha") for k, v in id_dict.items())
        # Ensure no raw sensitive keys
        raw_present = raw_present or any(k in id_fields for k in id_dict.keys())
    return (anonymized or hashed_present) and not ("sdp" in alert or "payload" in alert)


def _find_alert(alerts, predicate):
    for a in alerts:
        try:
            if predicate(a):
                return a
        except Exception:
            continue
    return None


def _baseline_learn(h, flows):
    learned = False
    # Try explicit learning mode
    for name in ("enable_learning", "start_learning", "learning", "set_learning"):
        fn = getattr(h, name, None)
        if callable(fn):
            try:
                fn(True)
                learned = True
                break
            except Exception:
                pass
    # Feed flows with learning hint
    for f in flows:
        f = dict(f)
        f.setdefault("src_ip", "127.0.0.1")
        f.setdefault("dst_ip", "127.0.0.1")
        f["mode"] = f.get("mode", "learning")
        f["learning"] = True
        try:
            _analyze(h, f)
        except Exception:
            # Ensure learning doesn't crash
            pass
    # Try to stop learning mode
    for name in ("disable_learning", "stop_learning", "learning", "set_learning"):
        fn = getattr(h, name, None)
        if callable(fn):
            try:
                if name in ("learning", "set_learning"):
                    fn(False)
                else:
                    fn()
            except Exception:
                pass
    return learned


def _common_webrtc_fields():
    return {
        "protocol": "DTLS-SRTP",
        "turn_relayed": True,
        "ice": True,
        "ice_retries": 0,
        "candidate_churn": 0.1,
        "transport": "UDP",
        "port": 3478,
        "duration_s": 60,
        "bytes_out": 1000000,
        "bytes_in": 900000,
        "datachannel": False,
        "frame_sizes": [1200, 400, 1300, 200],
        "frame_entropy": [6.2, 6.4, 6.1, 6.5],
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "dst_domain": "turn.corp.local",
        "sni": "turn.corp.local",
    }


def test_exfil_turn_dtls_srtp_uniform_high_entropy_to_unsanctioned_generates_signed_incident(hunter):
    # Ensure allowlist does not include the bad domain
    _add_allowlist(hunter, domains=["turn.corp.local", "stun.corp.local"], ips=["127.0.0.1"])

    flow = _common_webrtc_fields()
    flow.update({
        "dst_domain": "bad.unsanctioned.test",
        "sni": "bad.unsanctioned.test",
        "transport": "UDP",
        "port": 3478,
        "datachannel": True,
        "duration_s": 1800,
        "bytes_out": 7_000_000,
        "bytes_in": 150_000,
        "frame_sizes": [512] * 100,
        "frame_entropy": [7.98] * 100,
        "uniformity": 0.98,
        "flow_id": "exfil-1",
    })
    _analyze(hunter, flow)
    alerts = _get_alerts(hunter)
    assert isinstance(alerts, list)

    def is_exfil(a):
        t = (a.get("type") or a.get("alert_type") or "").lower()
        sev = (a.get("severity") or "").lower()
        rationale = (a.get("rationale") or a.get("reason") or "")
        return ("covert" in t or "exfil" in t) and ("high" in sev or "critical" in sev) and (
            ("entropy" in rationale.lower() and "uniform" in rationale.lower()) or
            ("datachannel" in rationale.lower())
        )

    alert = _find_alert(alerts, is_exfil)
    assert alert is not None, f"No exfil alert found in alerts: {alerts}"

    # Signed, forensically sound alert with fingerprints and flow statistics
    assert _verify_signature(hunter, alert), "Alert is not signed or signature verification failed"
    fps = alert.get("fingerprints") or {}
    ja4 = alert.get("ja4") or fps.get("ja4")
    ja4s = alert.get("ja4s") or fps.get("ja4s")
    assert isinstance(ja4, str) and len(ja4) >= 4
    assert isinstance(ja4s, str) and len(ja4s) >= 4
    flow_stats = alert.get("flow_stats") or {}
    assert isinstance(flow_stats, dict) and ("bytes_out" in flow_stats or "duration_s" in flow_stats)

    # Metadata-only analysis with anonymization
    assert _has_privacy(alert), "Alert does not appear to anonymize/hide sensitive identifiers"


def test_corporate_call_on_approved_stun_turn_baselined_no_alert_after_learning(hunter):
    # Add allowlist entries
    ok_domains = ["turn.corp.local", "stun.corp.local", "meet.corp.local"]
    _add_allowlist(hunter, domains=ok_domains, ips=["127.0.0.1"])

    # Learning phase with normal calls
    normal_flows = []
    for i in range(5):
        f = _common_webrtc_fields()
        f.update({
            "dst_domain": "turn.corp.local" if i % 2 == 0 else "stun.corp.local",
            "sni": "turn.corp.local" if i % 2 == 0 else "stun.corp.local",
            "datachannel": False,
            "frame_sizes": [1100, 220, 900, 300, 1300, 140],
            "frame_entropy": [6.2, 6.3, 6.1, 6.4, 6.0, 6.5],
            "duration_s": 120 + i * 5,
            "ice_retries": 1,
            "candidate_churn": 0.15,
            "flow_id": f"learn-{i}",
        })
        normal_flows.append(f)
    _baseline_learn(hunter, normal_flows)

    # Clear any learning alerts
    _ = _get_alerts(hunter)

    # Post-learning flow should not trigger an alert
    test_flow = _common_webrtc_fields()
    test_flow.update({
        "dst_domain": "turn.corp.local",
        "sni": "turn.corp.local",
        "datachannel": False,
        "frame_sizes": [1100, 220, 900, 300, 1300, 140],
        "frame_entropy": [6.2, 6.3, 6.1, 6.4, 6.0, 6.5],
        "duration_s": 180,
        "flow_id": "post-learn-1",
    })
    _analyze(hunter, test_flow)
    alerts = _get_alerts(hunter)
    # Accept zero alerts or only low-severity "learned/baselined" notices
    relevant = [
        a for a in alerts
        if "turn.corp.local" not in (a.get("rationale") or a.get("reason") or "")
        and not str(a.get("type") or "").lower().startswith("baseline")
    ]
    # Filter only non-notify severity
    non_fp = [a for a in relevant if (a.get("severity") or "").lower() not in ("info", "informational", "low")]
    assert len(non_fp) == 0, f"Expected no significant alerts for baselined corporate call, got: {alerts}"


def test_domain_fronted_turn_tls443_with_ice_anomalies_triggers_escalation(hunter):
    # Ensure destination not allowlisted
    _add_allowlist(hunter, domains=["turn.corp.local", "stun.corp.local"], ips=[])

    flow = {
        "protocol": "DTLS-SRTP",
        "turn_relayed": True,
        "transport": "TLS",
        "port": 443,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "dst_domain": "edge.nonapproved.local",
        "sni": "allowed.front.domain",
        "domain_fronting": True,
        "ice": True,
        "ice_retries": 12,
        "candidate_churn": 0.85,
        "duration_s": 420,
        "bytes_out": 2_000_000,
        "bytes_in": 1_800_000,
        "datachannel": True,
        "frame_sizes": [700, 700, 700, 700, 700],
        "frame_entropy": [7.7, 7.8, 7.7, 7.8, 7.75],
        "flow_id": "fronted-1",
    }
    _analyze(hunter, flow)
    alerts = _get_alerts(hunter)
    assert isinstance(alerts, list) and alerts, "No alerts generated for domain-fronted TURN anomaly"

    def is_fronted(a):
        rationale = (a.get("rationale") or a.get("reason") or "").lower()
        t = (a.get("type") or "").lower()
        sev = (a.get("severity") or "").lower()
        return ("front" in rationale or "front" in t) and ("ice" in rationale and "retry" in rationale) and ("churn" in rationale) and (sev in ("high", "critical"))

    alert = _find_alert(alerts, is_fronted)
    assert alert is not None, f"No domain-fronting escalation found in {alerts}"
    # Check remediation guidance present
    remediation = alert.get("remediation") or alert.get("guidance") or ""
    assert isinstance(remediation, str) and any(word in remediation.lower() for word in ["block", "investigate", "range", "credential", "remediation"])


def test_error_handling_missing_fields_and_invalid_types(hunter):
    # Missing critical fields should not raise exceptions
    incomplete_flow = {"src_ip": "127.0.0.1"}
    try:
        _analyze(hunter, incomplete_flow)
    except Exception as e:
        pytest.fail(f"Analyzer raised on incomplete metadata: {e}")

    # Invalid types should be handled gracefully
    invalid_flow = {
        "protocol": None,
        "turn_relayed": "yes",
        "duration_s": "long",
        "frame_sizes": "not-a-list",
        "frame_entropy": 7.9,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
    }
    try:
        _analyze(hunter, invalid_flow)
    except Exception as e:
        pytest.fail(f"Analyzer raised on invalid metadata types: {e}")

    # Ensure any alerts from erroneous input still maintain privacy guarantees
    alerts = _get_alerts(hunter)
    for a in alerts:
        assert _has_privacy(a)


def test_alert_contains_reproducible_rationale_and_fingerprints(hunter):
    # Generate two similar suspicious flows; rationale should be reproducible
    flow_base = _common_webrtc_fields()
    flow_base.update({
        "dst_domain": "bad.unsanctioned.test",
        "sni": "bad.unsanctioned.test",
        "datachannel": True,
        "frame_sizes": [600] * 20,
        "frame_entropy": [7.9] * 20,
        "duration_s": 900,
        "bytes_out": 4_000_000,
        "bytes_in": 100_000,
        "flow_id": "rep-1",
    })
    _analyze(hunter, flow_base)
    alerts1 = _get_alerts(hunter)
    alert1 = alerts1[-1] if alerts1 else None
    assert alert1 is not None

    flow2 = dict(flow_base)
    flow2["flow_id"] = "rep-2"
    _analyze(hunter, flow2)
    alerts2 = _get_alerts(hunter)
    alert2 = alerts2[-1] if alerts2 else None
    assert alert2 is not None

    rationale1 = (alert1.get("rationale") or alert1.get("reason") or "").strip()
    rationale2 = (alert2.get("rationale") or alert2.get("reason") or "").strip()
    assert rationale1 and rationale2 and rationale1 == rationale2, "Rationale should be reproducible across similar flows"

    # Fingerprints must be present and stable across similar flows
    fp1 = alert1.get("fingerprints") or {}
    fp2 = alert2.get("fingerprints") or {}
    ja4_1 = alert1.get("ja4") or fp1.get("ja4")
    ja4_2 = alert2.get("ja4") or fp2.get("ja4")
    ja4s_1 = alert1.get("ja4s") or fp1.get("ja4s")
    ja4s_2 = alert2.get("ja4s") or fp2.get("ja4s")
    assert isinstance(ja4_1, str) and isinstance(ja4_2, str) and ja4_1 == ja4_2
    assert isinstance(ja4s_1, str) and isinstance(ja4s_2, str) and ja4s_1 == ja4s_2


def test_privacy_metadata_only_no_media_content_leakage(hunter):
    # Simulate flow that might include content fields; ensure they are not used or emitted
    flow = _common_webrtc_fields()
    flow.update({
        "dst_domain": "bad.unsanctioned.test",
        "sni": "bad.unsanctioned.test",
        "datachannel": True,
        "frame_sizes": [512] * 10,
        "frame_entropy": [7.95] * 10,
        "sdp": "v=0\no=- 46117392 2 IN IP4 127.0.0.1\ns=-\n...",  # should be ignored for analysis
        "media_content": b"\x00\x01\x02",  # should not be processed
        "flow_id": "privacy-1",
    })
    _analyze(hunter, flow)
    alerts = _get_alerts(hunter)
    assert alerts, "Expected an alert for suspicious flow"
    alert = alerts[-1]
    # Ensure media content not included in alert
    assert "sdp" not in alert and "media_content" not in alert and "payload" not in alert
    assert _has_privacy(alert)