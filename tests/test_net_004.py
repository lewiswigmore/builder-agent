import pytest
from unittest.mock import MagicMock, patch

try:
    # Import module and class under test
    from tools.network import masque_exfil_hunter as meh
    from tools.network.masque_exfil_hunter import MasqueExfilHunter
except Exception as e:
    pytest.skip(f"masque_exfil_hunter module not importable: {e}", allow_module_level=True)


class DummyHSM:
    def __init__(self, salt="salt1"):
        self.salt = salt
        self.calls = 0

    def get_rotating_salt(self):
        return self.salt

    def hash_identifier(self, value):
        self.calls += 1
        return f"hash({value}|{self.salt})"


class DummySigstore:
    def __init__(self, version="2025.09.1", verified=True):
        self.version = version
        self.verified = verified
        self.verify_calls = 0

    def verify_rules(self):
        self.verify_calls += 1
        return {"version": self.version, "verified": self.verified}

    def verify_fingerprints(self, fingerprints):
        # fingerprints can be any iterable of strings
        return {"verified": True, "details": []}


class DummyTimeAttestor:
    def __init__(self, roughtime_ok=True, rfc3161_ok=True, ts=1_700_000_000):
        self.roughtime_ok = roughtime_ok
        self.rfc3161_ok = rfc3161_ok
        self.ts = ts
        self.called = {"roughtime": 0, "rfc3161": 0}

    def get_roughtime(self):
        self.called["roughtime"] += 1
        if not self.roughtime_ok:
            raise RuntimeError("Roughtime unavailable")
        return {"source": "roughtime", "timestamp": self.ts, "valid": True}

    def get_rfc3161(self):
        self.called["rfc3161"] += 1
        if not self.rfc3161_ok:
            raise RuntimeError("RFC3161 TSS unavailable")
        return {"source": "rfc3161", "timestamp": self.ts, "valid": True}


class DummySealer:
    def __init__(self):
        self.calls = 0

    def seal_bundle(self, meta, minimal=False):
        self.calls += 1
        # Minimal pcap headers placeholder and flow stats
        flow_stats = {
            "packets": meta.get("packets", 0),
            "bytes": meta.get("bytes", 0),
            "duration_ms": meta.get("duration_ms", 0),
        }
        return {
            "sealed": True,
            "minimal": minimal,
            "pcap_headers": b"PCAP\x00",
            "ja4": meta.get("ja4"),
            "ja4s": meta.get("ja4s"),
            "flow_stats": flow_stats,
            "attestations": [],
        }


@pytest.fixture
def hunter(monkeypatch):
    # Instantiate hunter with default allowlist empty
    h = MasqueExfilHunter(allowlist=[], fp_threshold=0.0) if hasattr(MasqueExfilHunter, "__call__") or True else MasqueExfilHunter()

    # Inject dependencies if hunter supports attributes; else monkeypatch module-level fallbacks
    # HSM
    h.hsm = DummyHSM()
    if hasattr(meh, "HSMClient"):
        monkeypatch.setattr(meh, "HSMClient", lambda *args, **kwargs: h.hsm, raising=False)
    if hasattr(meh, "hash_identifier"):
        monkeypatch.setattr(meh, "hash_identifier", h.hsm.hash_identifier, raising=False)

    # Sigstore
    h.sigstore = DummySigstore()
    if hasattr(meh, "SigstoreVerifier"):
        monkeypatch.setattr(meh, "SigstoreVerifier", lambda *a, **k: h.sigstore, raising=False)
    if hasattr(meh, "verify_sigstore_artifacts"):
        monkeypatch.setattr(meh, "verify_sigstore_artifacts", lambda: {"version": h.sigstore.version, "verified": h.sigstore.verified}, raising=False)

    # Time attestor
    h.time_attestor = DummyTimeAttestor()
    if hasattr(meh, "TimeAttestor"):
        monkeypatch.setattr(meh, "TimeAttestor", lambda *a, **k: h.time_attestor, raising=False)
    if hasattr(meh, "get_time_attestation"):
        def _get_time_attestation():
            try:
                return h.time_attestor.get_roughtime()
            except Exception:
                try:
                    return h.time_attestor.get_rfc3161()
                except Exception:
                    return {"source": "local", "timestamp": None, "valid": False}
        monkeypatch.setattr(meh, "get_time_attestation", _get_time_attestation, raising=False)

    # Evidence sealer
    h.evidence_sealer = DummySealer()
    if hasattr(meh, "EvidenceSealer"):
        monkeypatch.setattr(meh, "EvidenceSealer", lambda *a, **k: h.evidence_sealer, raising=False)
    if hasattr(meh, "seal_evidence_bundle"):
        monkeypatch.setattr(meh, "seal_evidence_bundle", h.evidence_sealer.seal_bundle, raising=False)

    # Optionally mock JA4 helpers if present
    if hasattr(meh, "compute_ja4"):
        monkeypatch.setattr(meh, "compute_ja4", lambda meta: meta.get("ja4"), raising=False)
    if hasattr(meh, "compute_ja4s"):
        monkeypatch.setattr(meh, "compute_ja4s", lambda meta: meta.get("ja4s"), raising=False)

    # Ensure rules are verified before use
    if hasattr(h, "verify_rules"):
        res = h.verify_rules()  # Should consult h.sigstore
        assert isinstance(res, dict) and res.get("verified", False) is True

    return h


def build_masque_connect_udp_flow():
    # All localhost as required for network tests
    return {
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "alpn": "h3",
        "packets": 42,
        "bytes": 8192,
        "duration_ms": 2500,
        "quic": {
            "version": "1",
            "spin_bit": True,
            "initial_sni": "localhost",
            "dcid": "00112233aabbccdd",
            "token_length": 16,
            "alt_svc": "h3=\":443\"",
        },
        "http3": {
            ":method": "CONNECT",
            ":protocol": "connect-udp",
            "authority": "target.local:443",
            "capsule": True,
            "datagrams": True,
        },
        "masque": {
            "capable_origin": True,
            "connect_udp": True,
            "h3_datagram": True,
        },
        "sni": "localhost",
        "ja4": "h3_1_0_1_127.0.0.1:443_...",
        "ja4s": "quic_sh_1_rtt...",
    }


def build_legit_quic_flow(idx=0):
    return {
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 40000 + idx,
        "dst_port": 443,
        "alpn": "h3",
        "packets": 10 + idx,
        "bytes": 1500 + idx,
        "duration_ms": 100 + idx,
        "quic": {
            "version": "1",
            "spin_bit": False,
            "initial_sni": "localhost",
            "dcid": f"dcid{idx}",
        },
        "http3": {
            ":method": "GET",
            ":path": "/",
            ":authority": "localhost:443",
        },
        "sni": "localhost",
        "ja4": f"h3_legit_{idx}",
        "ja4s": f"quic_legit_{idx}",
    }


def extract_alerts_from_results(results):
    if isinstance(results, dict):
        if "alerts" in results and isinstance(results["alerts"], list):
            return results["alerts"]
        # Fallback if results is a list of events
        if "events" in results and isinstance(results["events"], list):
            return [e.get("alert") for e in results["events"] if e.get("alert")]
    if isinstance(results, list):
        return [e.get("alert") for e in results if e.get("alert")]
    return []


def test_detect_masque_connect_udp_emits_high_confidence_alert_and_evidence(hunter):
    flow = build_masque_connect_udp_flow()
    # Process single flow
    if hasattr(hunter, "process_flow"):
        event = hunter.process_flow(flow)
    elif hasattr(hunter, "analyze_flows"):
        res = hunter.analyze_flows([flow])
        events = res.get("events") if isinstance(res, dict) else res
        event = events[0]
    else:
        pytest.skip("Hunter does not expose process_flow or analyze_flows")

    assert event, "No event returned"
    assert event.get("classification") in ("tunnel", "masque_tunnel", "masque_connect_udp")
    conf = event.get("confidence")
    assert (isinstance(conf, str) and conf.lower() in ("high", "very_high")) or (isinstance(conf, (int, float)) and conf >= 0.9)

    alert = event.get("alert")
    assert alert, "Alert not emitted for MASQUE CONNECT-UDP"
    inds = set(alert.get("indicators", []))
    assert any(tok in inds for tok in {"HTTP3_CONNECT_UDP", "MASQUE_CAPABLE_ORIGIN", "H3_DATAGRAM", "CONNECT-UDP"}), f"Missing indicators: {inds}"

    # Privacy: ensure hashed identifiers present and raw not exposed
    ids = event.get("identifiers", {})
    assert "src_hash" in ids and "dst_hash" in ids and "sni_hash" in ids
    assert ids["src_hash"] != flow["src_ip"]
    assert ids["dst_hash"] != flow["dst_ip"]
    assert ids["sni_hash"] != flow["sni"]
    # Ensure raw values not present outside sealed evidence
    repr_event = repr({k: v for k, v in event.items() if k != "evidence"})
    assert flow["src_ip"] not in repr_event
    assert flow["dst_ip"] not in repr_event
    assert flow["sni"] not in repr_event

    # Signed rules/models and fingerprints verified
    assert event.get("rules_version"), "No rules version recorded"
    assert event.get("rules_verified") is True

    # Time attestations
    ta = event.get("time_attestation")
    assert ta and "timestamp" in ta and ta.get("valid") is True
    assert ta.get("source") in ("roughtime", "rfc3161")

    # Evidence bundle
    ev = event.get("evidence")
    assert ev and ev.get("sealed") is True
    assert "pcap_headers" in ev and isinstance(ev["pcap_headers"], (bytes, bytearray))
    assert ev.get("ja4") == flow["ja4"]
    assert ev.get("ja4s") == flow["ja4s"]
    assert isinstance(ev.get("flow_stats"), dict)
    # Ensure no payload present
    assert "payload" not in ev


def test_legit_quic_traffic_not_flagged_FP_below_threshold(hunter):
    flows = [build_legit_quic_flow(i) for i in range(20)]

    if hasattr(hunter, "analyze_flows"):
        res = hunter.analyze_flows(flows)
        alerts = extract_alerts_from_results(res)
        stats = res.get("stats", {}) if isinstance(res, dict) else {}
    else:
        alerts = []
        for f in flows:
            ev = hunter.process_flow(f)
            if ev.get("alert"):
                alerts.append(ev["alert"])
        stats = {}

    assert len(alerts) == 0, f"Expected no alerts on clean baseline, got {len(alerts)}"
    # If false positive rates are provided, check threshold (zero for clean capture)
    if stats:
        fpr = stats.get("false_positive_rate")
        if fpr is not None:
            assert fpr <= 0.01


def test_allowlisted_masque_egress_suppresses_alert_but_records_event_and_seals_minimal(monkeypatch):
    # Allowlist localhost as enterprise MASQUE egress
    h = MasqueExfilHunter(allowlist=["127.0.0.1", "localhost"], fp_threshold=0.0)
    # Inject dependencies
    h.hsm = DummyHSM()
    h.sigstore = DummySigstore()
    h.time_attestor = DummyTimeAttestor()
    h.evidence_sealer = DummySealer()
    if hasattr(h, "verify_rules"):
        res = h.verify_rules()
        assert res.get("verified") is True

    flow = build_masque_connect_udp_flow()
    # Ensure sni matches allowlist
    flow["sni"] = "localhost"
    flow["quic"]["initial_sni"] = "localhost"

    event = h.process_flow(flow) if hasattr(h, "process_flow") else h.analyze_flows([flow])[0]

    assert event.get("classification") in ("tunnel", "masque_tunnel", "masque_connect_udp")
    # Alert suppressed
    assert not event.get("alert") or event.get("alert", {}).get("suppressed") is True
    # Recorded for audit
    assert event.get("recorded") is True
    ev = event.get("evidence")
    assert ev and ev.get("sealed") is True and ev.get("minimal") is True
    # Time attestation still present
    ta = event.get("time_attestation")
    assert ta and ta.get("valid") is True


def test_hashing_privacy_rotating_salt_and_no_pii_leak(hunter):
    flow = build_masque_connect_udp_flow()

    # First processing with salt1
    hunter.hsm.salt = "salt1"
    e1 = hunter.process_flow(flow) if hasattr(hunter, "process_flow") else hunter.analyze_flows([flow])[0]
    # Rotate salt
    hunter.hsm.salt = "salt2"
    e2 = hunter.process_flow(flow) if hasattr(hunter, "process_flow") else hunter.analyze_flows([flow])[0]

    ids1 = e1.get("identifiers", {})
    ids2 = e2.get("identifiers", {})
    for k in ("src_hash", "dst_hash", "sni_hash"):
        assert ids1.get(k) and ids2.get(k)
        assert ids1[k] != ids2[k], f"Identifier {k} did not change across salt rotation"

    # Ensure HSM hashing was actually used
    assert hunter.hsm.calls >= 3

    # Ensure no raw PII leaks in event structures
    for ev in (e1, e2):
        top_repr = repr({k: v for k, v in ev.items() if k != "evidence"})
        assert flow["src_ip"] not in top_repr
        assert flow["dst_ip"] not in top_repr
        assert flow["sni"] not in top_repr


def test_signed_rules_verified_before_analysis_and_failure_suppresses_alerts(monkeypatch):
    h = MasqueExfilHunter(allowlist=[], fp_threshold=0.0)
    h.hsm = DummyHSM()
    h.sigstore = DummySigstore(verified=False)  # Simulate signature verification failure
    h.time_attestor = DummyTimeAttestor()
    h.evidence_sealer = DummySealer()

    # If verify_rules exists, it should indicate failure
    rules_ok = True
    if hasattr(h, "verify_rules"):
        res = h.verify_rules()
        rules_ok = res.get("verified", False)
    assert rules_ok is False

    flow = build_masque_connect_udp_flow()
    event = h.process_flow(flow) if hasattr(h, "process_flow") else h.analyze_flows([flow])[0]

    # Should not emit actionable alert if rules are not verified
    assert event.get("rules_verified") is False
    assert not event.get("alert") or event.get("alert", {}).get("suppressed") is True
    # Still can classify and record minimally for audit
    assert event.get("classification") in ("tunnel", "masque_tunnel", "masque_connect_udp")
    assert event.get("recorded") is True
    ev = event.get("evidence")
    assert ev and ev.get("sealed") is True


def test_error_handling_missing_fields_and_external_failures(hunter, monkeypatch):
    # Missing http3 section: should not crash or misclassify as tunnel
    flow_missing = {
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 12345,
        "dst_port": 443,
        "alpn": "h3",
        "quic": {"version": "1", "initial_sni": "localhost"},
        "sni": "localhost",
        "packets": 3,
        "bytes": 300,
        "duration_ms": 50,
        "ja4": "h3_missing",
        "ja4s": "quic_missing",
    }
    ev = hunter.process_flow(flow_missing) if hasattr(hunter, "process_flow") else hunter.analyze_flows([flow_missing])[0]
    assert ev.get("classification") not in ("tunnel", "masque_tunnel", "masque_connect_udp")
    assert ev.get("error") in (None, False)

    # Attestation failure: Roughtime fails, RFC3161 succeeds
    hunter.time_attestor.roughtime_ok = False
    flow = build_legit_quic_flow(99)
    ev2 = hunter.process_flow(flow) if hasattr(hunter, "process_flow") else hunter.analyze_flows([flow])[0]
    ta2 = ev2.get("time_attestation")
    assert ta2 and ta2.get("source") == "rfc3161" and ta2.get("valid") is True

    # Both attestations fail: should still produce event with invalid attestation flag
    hunter.time_attestor.rfc3161_ok = False
    ev3 = hunter.process_flow(flow) if hasattr(hunter, "process_flow") else hunter.analyze_flows([flow])[0]
    ta3 = ev3.get("time_attestation")
    assert ta3 and ta3.get("valid") is False

    # HSM hashing error: simulate by monkeypatching hsm.hash_identifier to raise
    def boom(_):
        raise RuntimeError("HSM unavailable")
    hunter.hsm.hash_identifier = boom
    ev4 = hunter.process_flow(build_legit_quic_flow(100)) if hasattr(hunter, "process_flow") else hunter.analyze_flows([build_legit_quic_flow(100)])[0]
    # Should not include raw PII; identifiers may be redacted
    ids = ev4.get("identifiers", {})
    assert "src_hash" in ids and "dst_hash" in ids and "sni_hash" in ids
    assert ids["src_hash"] in ("redacted", None) or isinstance(ids["src_hash"], str)
    repr_ev4 = repr({k: v for k, v in ev4.items() if k != "evidence"})
    assert "127.0.0.1" not in repr_ev4


def test_analyze_flows_empty_input_returns_zero(hunter):
    if hasattr(hunter, "analyze_flows"):
        res = hunter.analyze_flows([])
        if isinstance(res, dict):
            assert res.get("events") == [] or res.get("events") is None
            assert res.get("alerts") == [] or res.get("alerts") is None
            stats = res.get("stats", {})
            if stats:
                assert stats.get("flows_processed", 0) == 0
        elif isinstance(res, list):
            assert res == []
    else:
        # Fallback: simply ensure no exception when nothing to do
        assert True


def test_time_attestations_include_roughtime_or_rfc3161(hunter):
    flow = build_legit_quic_flow(7)
    ev = hunter.process_flow(flow) if hasattr(hunter, "process_flow") else hunter.analyze_flows([flow])[0]
    ta = ev.get("time_attestation")
    assert ta and ta.get("source") in ("roughtime", "rfc3161")
    assert isinstance(ta.get("timestamp"), (int, float)) or ta.get("timestamp") is None