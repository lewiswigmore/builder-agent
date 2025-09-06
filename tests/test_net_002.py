import json
import platform
import time
from unittest.mock import Mock

import pytest

ids_mod = pytest.importorskip("tools.network.quic_behavior_ids")


class FakeSIEMExporter:
    def __init__(self, capacity=5, fail_ratio=0.0):
        self.capacity = capacity
        self.fail_ratio = fail_ratio
        self._queue = []
        self._sent = []
        self._calls = 0

    def send(self, event):
        # Backpressure: if queue is "full", simulate pressure
        self._calls += 1
        if len(self._queue) >= self.capacity or (
            self.fail_ratio > 0.0 and (self._calls % int(1 / self.fail_ratio) == 0)
        ):
            return False
        # Ensure event is JSON-serializable dict
        if isinstance(event, str):
            # Accept string if it's JSON; try to parse
            json.loads(event)
        else:
            json.dumps(event)
        self._queue.append(event)
        return True

    def drain(self):
        while self._queue:
            self._sent.append(self._queue.pop(0))
        return list(self._sent)

    @property
    def sent(self):
        return list(self._sent)

    @property
    def queued(self):
        return list(self._queue)

    @property
    def calls(self):
        return self._calls


@pytest.fixture
def siem_exporter():
    return FakeSIEMExporter(capacity=3, fail_ratio=0.0)


@pytest.fixture
def ids_instance(monkeypatch, siem_exporter):
    if not hasattr(ids_mod, "QUICBehaviorIDS"):
        pytest.skip("QUICBehaviorIDS not implemented in module")

    # Monkeypatch kernel checks to always pass if present
    if hasattr(ids_mod, "check_kernel_ebpf"):
        monkeypatch.setattr(ids_mod, "check_kernel_ebpf", lambda min_version="5.10": True)
    if hasattr(ids_mod, "kernel_supports_ebpf"):
        monkeypatch.setattr(ids_mod, "kernel_supports_ebpf", lambda: True)

    # Create IDS with strict retention and small drop budget
    try:
        ids = ids_mod.QUICBehaviorIDS(
            retention_seconds=2,
            packet_drop_budget=0.05,
            exporter=siem_exporter,
            hash_salt="test-salt",
        )
    except TypeError:
        # Fallback to minimal init
        ids = ids_mod.QUICBehaviorIDS()
        # Try configuring after init
        if hasattr(ids, "set_exporter"):
            ids.set_exporter(siem_exporter)
        if hasattr(ids, "set_packet_drop_budget"):
            ids.set_packet_drop_budget(0.05)
        if hasattr(ids, "set_retention"):
            ids.set_retention(2)

    # Ensure any eBPF verify/sandbox functions succeed
    if hasattr(ids, "get_ebpf_status"):
        status = ids.get_ebpf_status()
        assert isinstance(status, dict)
    if hasattr(ids, "start"):
        ids.start()
    return ids


def mk_quic_meta(
    src_ip="127.0.0.1",
    dst_ip="127.0.0.1",
    src_port=4433,
    dst_port=4433,
    sni="localhost",
    ja4="JA4:CDN:STABLE",
    spin_entropy=0.35,
    pkt_count=8,
    byte_count=1200,
    user_agent="test-agent/1.0",
):
    return {
        "protocol": "quic",
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "sni": sni,
        "ja4": ja4,
        "spin_bit_entropy": spin_entropy,
        "packet_count": pkt_count,
        "byte_count": byte_count,
        "user_agent": user_agent,
        "payload": None,  # Ensure metadata-only
    }


def _ingest(ids, meta):
    if hasattr(ids, "ingest"):
        return ids.ingest(meta)
    if hasattr(ids, "process_metadata"):
        return ids.process_metadata(meta)
    if hasattr(ids, "process_packet_metadata"):
        return ids.process_packet_metadata(meta)
    raise AssertionError("IDS does not expose an ingest/process_metadata method")


def _get_alerts(ids):
    if hasattr(ids, "get_alerts"):
        return ids.get_alerts()
    # Alternative: retrieve last event(s)
    if hasattr(ids, "get_events"):
        evs = ids.get_events()
        return [e for e in evs if isinstance(e, dict) and e.get("type") == "alert"]
    return []


def _warm_up(ids, data):
    if hasattr(ids, "warm_up"):
        return ids.warm_up(data)
    if hasattr(ids, "train"):
        return ids.train(data)
    if hasattr(ids, "baseline"):
        return ids.baseline(data)
    # Fallback: just ingest
    for d in data:
        _ingest(ids, d)


def _flush(ids):
    for method in ("flush", "export_pending", "drain", "flush_events"):
        if hasattr(ids, method):
            getattr(ids, method)()
            return True
    return False


def test_generate_c2_quic_uncommon_ja4_and_spinbit_alert(ids_instance):
    ids = ids_instance

    # Warm-up with benign CDN-like traffic
    baseline = [
        mk_quic_meta(
            sni="video.localhost",
            ja4="JA4:CDN:STABLE",
            spin_entropy=0.2,
            pkt_count=40,
            byte_count=120000,
            user_agent="cdn-player/3.2",
        )
        for _ in range(20)
    ]
    _warm_up(ids, baseline)

    # Simulated QUIC-based C2: uncommon JA4 and abnormal spin-bit entropy
    c2_meta = mk_quic_meta(
        sni="c2.localhost",
        ja4="JA4:UNCOMMON:X9Z1",
        spin_entropy=0.92,
        pkt_count=7,
        byte_count=900,
        user_agent="custom-client/0.1",
    )

    result = _ingest(ids, c2_meta)

    alerts = _get_alerts(ids)
    assert alerts, "Expected at least one alert for C2-like behavior"
    alert = alerts[-1]

    # Verify explainability: features and fingerprints present
    features = alert.get("features") if isinstance(alert, dict) else None
    fingerprints = alert.get("fingerprints") if isinstance(alert, dict) else None

    assert isinstance(features, dict), "Alert must include explainable features"
    assert "spin_bit_entropy" in features, "Feature vector must include spin_bit_entropy"
    assert isinstance(fingerprints, dict), "Alert must include fingerprints"
    assert "ja4" in fingerprints, "Fingerprints must include ja4"

    # High-confidence alert expected
    confidence = alert.get("confidence") if isinstance(alert, dict) else None
    assert confidence is not None and confidence >= 0.8

    # Metadata-only: ensure no raw payload present
    assert "payload" not in alert or alert["payload"] in (None, "", {})

    # PII hashed/anonymized: no raw IPs in alert; hashed fields present
    pii_fields = set(alert.keys())
    assert not any(k in pii_fields for k in ("src_ip", "dst_ip"))
    assert any(k in pii_fields for k in ("src_ip_hash", "dst_ip_hash", "src_ip_anonymized", "dst_ip_anonymized"))


def test_baseline_cdn_reduced_false_positives_after_warmup(ids_instance):
    ids = ids_instance

    cdn_stream = [
        mk_quic_meta(
            sni="video.localhost",
            ja4="JA4:CDN:STABLE",
            spin_entropy=0.25,
            pkt_count=60,
            byte_count=300000,
            user_agent="cdn-player/4.1",
        )
        for _ in range(50)
    ]

    # Measure alerts without warm-up
    for meta in cdn_stream[:10]:
        _ingest(ids, meta)
    alerts_pre = len(_get_alerts(ids))

    # Warm-up phase with unsupervised learning
    _warm_up(ids, cdn_stream)

    # Ingest again post warm-up
    for meta in cdn_stream[10:]:
        _ingest(ids, meta)
    alerts_post = len(_get_alerts(ids)) - alerts_pre

    # Expect false positives reduced after warm-up
    assert alerts_post <= max(1, alerts_pre // 2)


def test_metadata_only_anonymization_and_retention(ids_instance, monkeypatch):
    ids = ids_instance

    # Ensure retention is short
    if hasattr(ids, "set_retention"):
        ids.set_retention(1)

    # Ingest two events with the same PII to test deterministic hashing
    meta1 = mk_quic_meta(src_ip="127.0.0.1", dst_ip="127.0.0.1", sni="pii.localhost")
    meta2 = mk_quic_meta(src_ip="127.0.0.1", dst_ip="127.0.0.1", sni="pii.localhost")

    _ingest(ids, meta1)
    _ingest(ids, meta2)

    events = []
    if hasattr(ids, "get_events"):
        events = [e for e in ids.get_events() if isinstance(e, dict)]
    else:
        # Try to flush to exporter and retrieve
        _flush(ids)
        if hasattr(ids, "exporter"):
            exporter = getattr(ids, "exporter")
            if hasattr(exporter, "drain"):
                events = exporter.drain()

    assert events, "Expected exported events"

    # Check that PII is hashed/anonymized deterministically across events
    ips_h = []
    for e in events:
        if isinstance(e, str):
            e = json.loads(e)
        for key in ("src_ip_hash", "dst_ip_hash", "src_ip_anonymized", "dst_ip_anonymized"):
            if key in e:
                ips_h.append((key, e[key]))
    # At least one hashed/anonymized field present and consistent
    assert ips_h, "No hashed/anonymized PII fields found"
    keys = [k for k, _ in ips_h]
    values = [v for _, v in ips_h]
    # Values appear multiple times and consistent
    assert any(values.count(v) > 1 for v in set(values))

    # Simulate time passing to enforce retention
    base_time = time.time()
    monkeypatch.setattr(time, "time", lambda: base_time + 5)

    # Trigger retention enforcement
    _ingest(ids, mk_quic_meta(sni="retention.trigger"))

    # If retention stats are exposed, verify they are small/cleared
    for attr in ("get_pii_cache_size", "get_state", "get_retained_count"):
        if hasattr(ids, attr):
            val = getattr(ids, attr)()
            if isinstance(val, dict) and "pii_cache" in val:
                assert val["pii_cache"] == 0
            elif isinstance(val, int):
                assert val == 0


def test_ebpf_verification_sandbox_and_rate_limit_drop_budget(ids_instance, monkeypatch):
    ids = ids_instance

    # Check eBPF program status
    if hasattr(ids, "get_ebpf_status"):
        status = ids.get_ebpf_status()
        assert isinstance(status, dict)
        assert status.get("verified", True) is True
        assert status.get("sandboxed", True) is True
        assert status.get("rate_limited", True) in (True, False)

    # Configure packet drop budget
    if hasattr(ids, "set_packet_drop_budget"):
        ids.set_packet_drop_budget(0.05)

    # Simulate a burst that could cause drops
    burst = [
        mk_quic_meta(
            sni="burst.localhost",
            ja4="JA4:CDN:STABLE",
            spin_entropy=0.3,
            pkt_count=3,
            byte_count=300,
            user_agent="load/1.0",
        )
        for _ in range(100)
    ]

    for m in burst:
        _ingest(ids, m)

    # Validate drop rate within budget if exposed
    for attr in ("get_drop_rate", "get_drop_stats"):
        if hasattr(ids, attr):
            val = getattr(ids, attr)()
            if isinstance(val, dict):
                drop_rate = val.get("drop_rate")
            else:
                drop_rate = val
            if drop_rate is not None:
                assert drop_rate <= 0.05 + 0.01  # small tolerance


def test_models_rules_versioned_and_signed_and_explainable_alert(ids_instance):
    ids = ids_instance

    # If model info is exposed, it must be versioned and signature-verified
    if hasattr(ids, "get_model_info"):
        info = ids.get_model_info()
        assert isinstance(info, dict)
        assert "version" in info and isinstance(info["version"], str) and info["version"]
        assert info.get("signature_valid", True) is True

    # Trigger an alert and verify explainability fields present
    alert_meta = mk_quic_meta(
        sni="c2.localhost",
        ja4="JA4:UNCOMMON:Q9A7",
        spin_entropy=0.88,
        pkt_count=5,
        byte_count=800,
        user_agent="weird-client/0.0",
    )
    _ingest(ids, alert_meta)
    alerts = _get_alerts(ids)
    assert alerts, "Expected alert generated"

    latest = alerts[-1]
    if isinstance(latest, str):
        latest = json.loads(latest)
    assert isinstance(latest.get("features"), dict)
    assert isinstance(latest.get("confidence"), (int, float))
    assert latest.get("confidence") >= 0.5
    # Must include fingerprints
    assert isinstance(latest.get("fingerprints"), dict)
    assert "ja4" in latest["fingerprints"]


def test_operate_on_linux_ebpf_and_export_json_with_backpressure(ids_instance, monkeypatch):
    ids = ids_instance

    # Kernel >= 5.10 check if implemented
    if hasattr(ids_mod, "check_kernel_ebpf"):
        assert ids_mod.check_kernel_ebpf("5.10") is True
    else:
        # If not available, simulate by checking current platform string parse at least doesn't crash
        rel = platform.release()
        assert isinstance(rel, str)

    # Replace exporter with one that applies backpressure
    exporter = FakeSIEMExporter(capacity=2, fail_ratio=0.5)
    if hasattr(ids, "set_exporter"):
        ids.set_exporter(exporter)
    elif hasattr(ids, "exporter"):
        setattr(ids, "exporter", exporter)

    # Produce events
    for _ in range(10):
        _ingest(ids, mk_quic_meta(sni="siem.localhost", ja4="JA4:CDN:STABLE"))

    # Attempt to flush repeatedly to observe backpressure handling
    for _ in range(10):
        _flush(ids)
        exporter.drain()

    # Ensure exporter was called and events are structured JSON
    assert exporter.calls > 0
    # Since we drained after flush, sent events must be JSON-serializable
    for e in exporter.sent:
        if isinstance(e, str):
            parsed = json.loads(e)
        else:
            parsed = e
        assert isinstance(parsed, dict)
        assert "type" in parsed
        assert "timestamp" in parsed or "time" in parsed


def test_error_handling_invalid_metadata(ids_instance):
    ids = ids_instance

    # Missing required fields should not crash
    bad_meta = {"protocol": "quic", "timestamp": time.time()}
    try:
        _ingest(ids, bad_meta)
    except Exception as e:
        pytest.fail(f"Ingest raised exception on invalid metadata: {e}")

    # Extremely malformed values
    bad_meta2 = mk_quic_meta()
    bad_meta2["ja4"] = None
    bad_meta2["spin_bit_entropy"] = -1.0
    bad_meta2["packet_count"] = -5
    bad_meta2["byte_count"] = -100

    _ingest(ids, bad_meta2)
    # Should not produce high-confidence alerts
    alerts = _get_alerts(ids)
    if alerts:
        latest = alerts[-1]
        if isinstance(latest, str):
            latest = json.loads(latest)
        conf = latest.get("confidence")
        if conf is not None:
            assert conf < 0.9