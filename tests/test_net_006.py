import json
import types
import pytest

abuse_module = pytest.importorskip("tools.network.http2_abuse_hunter")


def _get_hunter_class():
    cls = getattr(abuse_module, "HTTP2AbuseHunter", None)
    if cls is None:
        pytest.skip("HTTP2AbuseHunter class not found in tools.network.http2_abuse_hunter")
    return cls


@pytest.fixture
def fixed_now():
    return 1700000000.123456


@pytest.fixture
def hunter(monkeypatch, fixed_now):
    # Ensure deterministic time for signing/time-synchronization
    if hasattr(abuse_module, "time"):
        monkeypatch.setattr(abuse_module.time, "time", lambda: fixed_now, raising=False)

    # Provide deterministic signer if the module expects one
    class FakeSigner:
        def sign(self, data: bytes) -> str:
            # Simple deterministic "signature"
            return "sig-" + str(len(data))

        def verify(self, data: bytes, signature: str) -> bool:
            return signature == self.sign(data)

    Hunter = _get_hunter_class()
    try:
        obj = Hunter(signer=FakeSigner())
    except TypeError:
        obj = Hunter()
        # Try to set signer via attribute or method
        if hasattr(obj, "set_signer") and callable(getattr(obj, "set_signer")):
            obj.set_signer(FakeSigner())
        elif hasattr(obj, "signer"):
            setattr(obj, "signer", FakeSigner())

    # If there is a configure to enforce passive-only metadata and default thresholds
    if hasattr(obj, "configure") and callable(getattr(obj, "configure")):
        try:
            obj.configure(
                thresholds=None,
                passive_only=True,
                retention_seconds=3600,
                pii_salt="testsalt",
            )
        except TypeError:
            # Fallback if signature differs
            try:
                obj.configure(passive_only=True)
            except Exception:
                pass

    return obj


def _feed_events(hunter_obj, events):
    # Accepts a list of dict events; find an ingestion API
    candidates_single = [
        "ingest_packet",
        "process_packet",
        "process_event",
        "ingest_event",
        "add_event",
        "observe",
        "feed",
        "ingest",
        "handle_packet",
    ]
    candidates_multi = [
        "ingest_events",
        "process_events",
        "replay_trace",
        "ingest_trace",
        "feed_events",
    ]

    for name in candidates_multi:
        m = getattr(hunter_obj, name, None)
        if callable(m):
            return m(events)

    # Otherwise feed one-by-one
    method = None
    for name in candidates_single:
        m = getattr(hunter_obj, name, None)
        if callable(m):
            method = m
            break

    if method is None:
        pytest.skip("No suitable ingestion method found on hunter object")

    for ev in events:
        method(ev)


def _get_alerts(hunter_obj):
    # Attempt to fetch alerts
    candidates = [
        "get_alerts",
        "drain_alerts",
        "collect_alerts",
        "export_alerts",
        "flush_alerts",
    ]
    for name in candidates:
        m = getattr(hunter_obj, name, None)
        if callable(m):
            alerts = m()
            if alerts is None:
                return []
            return alerts

    # Try attribute exposure
    attr_candidates = ["alerts", "pending_alerts", "recent_alerts"]
    for name in attr_candidates:
        a = getattr(hunter_obj, name, None)
        if isinstance(a, (list, tuple)):
            return list(a)
        if callable(a):
            res = a()
            if res is None:
                return []
            return res

    # Fallback to empty
    return []


def _correlate_waf(hunter_obj, waf_logs):
    candidates = [
        "correlate_waf_logs",
        "correlate_with_waf",
        "integrate_waf",
        "correlate",
    ]
    for name in candidates:
        m = getattr(hunter_obj, name, None)
        if callable(m):
            return m(waf_logs)
    pytest.skip("No WAF correlation method available")


def _to_json_str(obj):
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _make_rst_burst_events(count=50, start_ts=1700000000.0, interval=0.001):
    events = []
    for i in range(count):
        ts = start_ts + i * interval
        ev = {
            "timestamp": ts,
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "h2",
            "frame_type": "RST_STREAM",
            "stream_id": i + 1,
            "headers": {
                "authority": "example.local",
                "user-agent": "h2tester/1.0",
            },
            "ja3": "771,4865-4867-4866,0-23-65281,29-23-24,0",
            "ja4": "h2:d15babe::s:ae:ch",
            "payload_len": 0,
        }
        events.append(ev)
        # Interleave occasional WINDOW_UPDATE or PING frames to simulate real trace
        if i % 10 == 0:
            events.append(
                {
                    "timestamp": ts + 0.0002,
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                    "src_port": 54321,
                    "dst_port": 443,
                    "protocol": "h2",
                    "frame_type": "PING",
                    "opaque_data_len": 8,
                }
            )
    return events


def _make_benign_multiplex_events(streams=100, concurrency=50, start_ts=1700001000.0, spacing=0.0005):
    events = []
    active = set()
    stream_id = 1
    ts = start_ts
    while stream_id <= streams:
        # Start up to concurrency new streams with HEADERS
        while len(active) < concurrency and stream_id <= streams:
            events.append(
                {
                    "timestamp": ts,
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                    "src_port": 40000 + (stream_id % 100),
                    "dst_port": 443,
                    "protocol": "h2",
                    "frame_type": "HEADERS",
                    "stream_id": stream_id,
                    "headers": {
                        ":method": "GET",
                        ":path": f"/api/v1/resource/{stream_id}",
                        "authority": "api.local",
                        "user-agent": "benign-client/2.1",
                    },
                    "ja3": "771,4865-4867-4866,0-23-65281,29-23-24,0",
                    "ja4": "h2:abc123::s:ae:ok",
                }
            )
            active.add(stream_id)
            stream_id += 1
        # For each active stream, send small DATA and then an END_STREAM
        to_close = set()
        for sid in list(active):
            ts += spacing
            events.append(
                {
                    "timestamp": ts,
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                    "src_port": 40000 + (sid % 100),
                    "dst_port": 443,
                    "protocol": "h2",
                    "frame_type": "DATA",
                    "stream_id": sid,
                    "payload_len": 64,
                    "end_stream": True,
                }
            )
            to_close.add(sid)
        active -= to_close
        ts += spacing
        # occasional WINDOW_UPDATE
        events.append(
            {
                "timestamp": ts,
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "h2",
                "frame_type": "WINDOW_UPDATE",
                "increment": 65535,
            }
        )
    return events


@pytest.mark.acceptance
def test_replayed_rapid_reset_triggers_high_confidence_with_evidence_and_signing(hunter, fixed_now):
    events = _make_rst_burst_events(count=80, start_ts=fixed_now - 1.0, interval=0.002)
    _feed_events(hunter, events)
    alerts = _get_alerts(hunter)

    assert isinstance(alerts, list)

    # Find a high-confidence rapid reset alert
    rapid_alerts = []
    for a in alerts:
        data = _to_json_str(a).lower()
        if "rapid" in data or "rst_stream" in data or "reset" in data:
            rapid_alerts.append(a)

    assert rapid_alerts, "Expected at least one rapid reset alert"

    # choose the highest severity/confidence alert
    def sev_key(alert):
        sev = str(alert.get("severity", "")).lower()
        mapping = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": -1, "informational": -1}
        return mapping.get(sev, 0)

    top = sorted(rapid_alerts, key=sev_key, reverse=True)[0]

    # Evidence checks
    evidence = top.get("evidence", top)
    assert isinstance(evidence, dict)
    assert "burst_rate" in evidence or "burst_per_second" in evidence
    # stream IDs list present and substantial
    sid_key = "stream_ids" if "stream_ids" in evidence else "streams"
    assert sid_key in evidence
    assert isinstance(evidence[sid_key], (list, tuple))
    assert len(evidence[sid_key]) >= 40

    # JA3/JA4 fingerprints present
    ev_json = _to_json_str(top).lower()
    assert "ja3" in ev_json
    assert "ja4" in ev_json

    # Signed and time-synchronized
    # look for signature fields and timestamp matching fixed_now (or close)
    sig = top.get("signature") or top.get("signed", {}).get("signature")
    signed_at = top.get("signed_at") or top.get("signed", {}).get("at") or top.get("timestamp")
    assert sig is not None and len(str(sig)) > 0
    assert signed_at is not None
    # allow slight float vs str differences
    assert abs(float(str(signed_at)) - float(fixed_now)) < 1.0

    # Minimal PCAP snippet and headers summary present
    snippet = top.get("pcap_snippet") or evidence.get("pcap_snippet")
    headers_summary = top.get("headers_summary") or evidence.get("headers_summary")
    assert snippet is not None
    # snippet should be small (metadata only)
    if isinstance(snippet, (bytes, bytearray, str)):
        assert len(snippet) < 4096
    else:
        # if represented as dict, ensure minimal fields
        assert isinstance(snippet, dict)
        assert len(snippet) <= 10
    assert headers_summary is not None

    # PII hashing: raw IP/domain should not appear; expect hash fields instead
    alert_str = _to_json_str(top)
    assert "127.0.0.1" not in alert_str
    assert "example.local" not in alert_str
    # look for indicative hashed fields
    pii_present = any(k for k in ["ip_hash", "src_ip_hash", "dst_ip_hash", "domain_hash", "authority_hash"] if k in top or k in evidence)
    assert pii_present, "Expected hashed PII fields to be present"


@pytest.mark.acceptance
def test_benign_high_concurrency_multiplexed_traffic_no_high_severity_alerts(hunter):
    events = _make_benign_multiplex_events(streams=120, concurrency=60)
    _feed_events(hunter, events)
    alerts = _get_alerts(hunter)

    # It is acceptable to have informational/low alerts, but not high/critical under defaults
    highish = []
    for a in alerts:
        sev = str(a.get("severity", "")).lower()
        if sev in ("high", "critical"):
            highish.append(a)
        # also ensure no misclassified rapid reset
        data = _to_json_str(a).lower()
        if ("rapid" in data or "rst_stream" in data or "reset" in data) and sev in ("high", "critical"):
            highish.append(a)

    assert not highish, f"Unexpected high-severity alerts for benign traffic: {highish}"


@pytest.mark.acceptance
def test_integration_with_waf_logs_correlation_and_mitigation(hunter):
    # First create an alert to correlate against (rapid reset trace)
    events = _make_rst_burst_events(count=30)
    _feed_events(hunter, events)
    initial_alerts = _get_alerts(hunter)
    assert isinstance(initial_alerts, list)

    # Prepare WAF logs; include matching JA3/JA4 and IP/ASN with actionable fields
    waf_logs = [
        {
            "timestamp": events[0]["timestamp"] + 0.5,
            "source_ip": "127.0.0.1",
            "ja3": "771,4865-4867-4866,0-23-65281,29-23-24,0",
            "ja4": "h2:d15babe::s:ae:ch",
            "asn": "AS65535",
            "waf_action": "block",
            "rule_signature": "rapid-reset-detector-v1",
        }
    ]

    # Perform correlation
    try:
        report = _correlate_waf(hunter, waf_logs)
    except pytest.skip.Exception:
        pytest.skip("No WAF correlation available in hunter")
        return

    # The correlation may either return a report or enrich alerts; handle both
    if report is None:
        correlated_alerts = _get_alerts(hunter)
    elif isinstance(report, list):
        correlated_alerts = report
    elif isinstance(report, dict):
        correlated_alerts = [report]
    else:
        correlated_alerts = _get_alerts(hunter)

    assert correlated_alerts, "Expected correlated output or enriched alerts"

    # Find correlated alert with mitigation recommendation
    actionable = None
    for a in correlated_alerts:
        s = _to_json_str(a).lower()
        if "asn" in s or "mitigation" in s or "waf" in s:
            # candidate
            actionable = a
            break

    assert actionable is not None, "Expected an alert/report correlated with WAF data"

    # Verify attacker IP/ASN correlation and mitigation recommendation
    s = _to_json_str(actionable).lower()
    assert "as65535" in s, "ASN not present in correlated report"
    # mitigation should include rate limit or rule signature
    assert ("rate" in s and "limit" in s) or ("rule" in s) or ("block" in s), "No actionable mitigation in report"


def test_error_handling_for_malformed_events_and_invalid_thresholds(hunter):
    # Malformed event missing stream_id on RST_STREAM should not crash
    bad_event = {
        "timestamp": 1700002000.0,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "protocol": "h2",
        "frame_type": "RST_STREAM",
        # "stream_id" missing
        "headers": {"authority": "oops.local"},
        "ja3": "bad",
        "ja4": "bad",
    }
    _feed_events(hunter, [bad_event])
    alerts = _get_alerts(hunter)
    assert isinstance(alerts, list)

    # Attempt to set invalid thresholds if supported
    set_methods = []
    if hasattr(hunter, "set_thresholds") and callable(getattr(hunter, "set_thresholds")):
        set_methods.append(hunter.set_thresholds)
    if hasattr(hunter, "configure") and callable(getattr(hunter, "configure")):
        set_methods.append(lambda t: hunter.configure(thresholds=t))

    if set_methods:
        for setter in set_methods:
            with pytest.raises((ValueError, AssertionError, TypeError)):
                setter({"rst_burst_per_second": -10, "max_concurrency": -1})
    else:
        pytest.skip("No threshold configuration method available to test invalid inputs")