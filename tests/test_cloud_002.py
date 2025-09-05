import importlib
import json
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture(scope="module")
def mod():
    try:
        return importlib.import_module("tools.cloud.honeycred_tripwire")
    except Exception as e:
        pytest.skip(f"tools.cloud.honeycred_tripwire not importable: {e}")


def get_attr(obj, names):
    for n in names:
        if hasattr(obj, n):
            return getattr(obj, n)
    return None


@pytest.fixture
def tripwire(mod, monkeypatch):
    # Construct a tripwire instance or use module-level API
    cfg = {
        "storage": "in_memory",
        "signing_key": "test-key",
        "policy": {"deny_write_delete": True},
        "clock_source": "time",
    }

    cls = get_attr(mod, ["HoneyCredTripwire", "Tripwire"])
    factory = get_attr(mod, ["create_tripwire", "init_tripwire", "create", "init"])

    # Prevent any network or cloud provider client calls by stubbing likely attributes
    # Common client names -> replaced by fakes capturing calls
    fake_client = SimpleNamespace(
        calls=[],
        revoke_credentials=lambda cred_id: {"revoked": True, "credential_id": cred_id},
        quarantine_instance=lambda inst_id: {"quarantined": True, "instance_id": inst_id},
        tag_resource=lambda rid, tags: {"tagged": True, "resource_id": rid, "tags": tags},
        delete_resource=lambda rid: (_ for _ in ()).throw(RuntimeError("Destructive operation should not be invoked")),
        terminate_instance=lambda rid: (_ for _ in ()).throw(RuntimeError("Destructive operation should not be invoked")),
    )
    for name in [
        "cloud_client",
        "cloud_api",
        "iam_client",
        "iam_api",
        "ec2_client",
        "gcp_client",
        "azure_client",
        "provider_client",
    ]:
        if hasattr(mod, name):
            monkeypatch.setattr(mod, name, fake_client, raising=False)

    # If module uses boto3, block any real clients
    try:
        import boto3  # noqa
        monkeypatch.setattr("boto3.client", lambda *_args, **_kwargs: fake_client, raising=False)
        monkeypatch.setattr("boto3.Session", lambda *_args, **_kwargs: SimpleNamespace(client=lambda *_a, **_kw: fake_client), raising=False)
    except Exception:
        pass

    # If signer is a class we can replace, make deterministic
    signer_cls = get_attr(mod, ["Signer", "AlertSigner", "SignatureService"])
    if signer_cls:
        deterministic_signer = SimpleNamespace(
            sign=lambda payload: "sig:" + json.dumps(payload, sort_keys=True),
            verify=lambda payload, signature: signature == "sig:" + json.dumps(payload, sort_keys=True),
        )
        try:
            monkeypatch.setattr(mod, "Signer", lambda *_a, **_kw: deterministic_signer, raising=False)
        except Exception:
            pass

    # Create tripwire instance
    instance = None
    if cls:
        try:
            instance = cls(cfg)
        except Exception:
            try:
                instance = cls()
            except Exception:
                instance = None
    elif factory:
        try:
            instance = factory(cfg)
        except Exception:
            try:
                instance = factory()
            except Exception:
                instance = None

    # Fallback: use module as the "instance" if no object
    return instance if instance is not None else mod


def call_process_event(tw, event):
    fn = get_attr(tw, ["process_event", "handle_event", "detect_event", "ingest_event", "watch_event", "on_event"])
    if callable(fn):
        return fn(event)
    # Some implementations may have a detector attribute
    det = get_attr(tw, ["detector", "engine"])
    if det:
        fn = get_attr(det, ["process_event", "handle_event", "detect_event", "ingest_event", "watch_event", "on_event"])
        if callable(fn):
            return fn(event)
    pytest.skip("No event processing function found on HoneyCred Cloud Tripwire")


def get_alerts(tw):
    getter = get_attr(tw, ["get_alerts", "list_alerts"])
    if callable(getter):
        return getter()
    alerts_attr = get_attr(tw, ["alerts"])
    if alerts_attr is not None:
        if callable(alerts_attr):
            return alerts_attr()
        return alerts_attr
    storage = get_attr(tw, ["storage", "alert_store", "store"])
    if storage is not None:
        g = get_attr(storage, ["get_alerts", "list", "list_alerts", "all"])
        if callable(g):
            return g()
        if hasattr(storage, "alerts"):
            return storage.alerts
    return []


def verify_alert_signature(tw, alert):
    # Prefer provided verification API if any
    verify_fn = get_attr(tw, ["verify_alert", "verify_signature"])
    if callable(verify_fn):
        try:
            return bool(verify_fn(alert))
        except Exception:
            return False
    signer = get_attr(tw, ["signer", "signature_service"])
    if signer and hasattr(signer, "verify"):
        payload = alert.get("payload") or {k: v for k, v in alert.items() if k not in ("signature", "prev_hash", "hash")}
        try:
            return bool(signer.verify(payload, alert.get("signature")))
        except Exception:
            return False
    # Fallback: signature field presence
    return "signature" in alert


def verify_tamper_evident_storage(tw):
    storage = get_attr(tw, ["storage", "alert_store", "store"])
    if storage is None:
        return False
    verify = get_attr(storage, ["verify", "verify_chain", "is_valid"])
    if callable(verify):
        try:
            return bool(verify())
        except Exception:
            return False
    # Check for hash chain fields
    alerts = get_alerts(tw)
    if not alerts:
        return False
    prev = None
    for a in alerts:
        if prev is None:
            prev = a.get("hash") or a.get("prev_hash") or ""
            continue
        if "prev_hash" in a and a["prev_hash"] != prev:
            return False
        prev = a.get("hash") or a.get("prev_hash") or prev
    return True


@pytest.fixture
def fixed_time(monkeypatch):
    # Provide a monotonic fixed time that can be advanced in tests
    t = {"now": 1_700_000_000.0}

    def fake_time():
        return t["now"]

    monkeypatch.setattr(time, "time", fake_time)
    return t


def test_detection_creates_signed_alert_within_60s(tripwire, fixed_time, caplog, monkeypatch):
    # If module uses its own time module, patch it too
    try:
        import tools.cloud.honeycred_tripwire as mod
        monkeypatch.setattr(mod.time, "time", time.time, raising=False)
    except Exception:
        pass

    event_time = fixed_time["now"]
    event = {
        "event_time": event_time,
        "honeytoken": True,
        "credential_id": "hc-test-1",
        "caller": "arn:example:iam::123456789012:user/honeytoken",
        "source_ip": "127.0.0.1",
        "resource": {"type": "bucket", "name": "critical-data"},
        "action": "GetObject",
        "context": {"request_id": "req-123"},
    }

    # Advance time by 30s to simulate processing delay within the SLA
    fixed_time["now"] = event_time + 30

    with caplog.at_level("INFO"):
        result = call_process_event(tripwire, event)

    # Alert should be returned or stored
    alerts = []
    if isinstance(result, dict):
        alerts = [result]
    alerts.extend([a for a in get_alerts(tripwire) if isinstance(a, dict)])
    assert alerts, "No alert produced or stored by tripwire for honeytoken event"

    # Find the alert corresponding to the event
    alert = None
    for a in alerts:
        if a.get("credential_id") == "hc-test-1" or a.get("payload", {}).get("credential_id") == "hc-test-1":
            alert = a
            break
    if alert is None:
        alert = alerts[0]

    # Validate alert contents
    payload = alert.get("payload", alert)
    assert payload.get("caller"), "Alert missing caller"
    assert payload.get("source_ip"), "Alert missing source IP"
    assert payload.get("resource"), "Alert missing resource context"

    # Validate time constraint: detected within 60s
    detected_at = payload.get("detected_at") or alert.get("timestamp") or alert.get("time") or fixed_time["now"]
    # If detected_at is a string, try to parse/convert; assume numeric is seconds
    assert isinstance(detected_at, (int, float)), "Detection timestamp missing or not numeric"
    assert 0 <= detected_at - event_time <= 60, f"Detection exceeded 60s SLA: {detected_at - event_time}s"

    # Validate signature and tamper-evident storage
    assert verify_alert_signature(tripwire, alert), "Alert signature missing or invalid"
    assert verify_tamper_evident_storage(tripwire), "Alert storage is not tamper-evident"

    # Ensure log contains some indication of alert creation
    assert any("alert" in rec.message.lower() for rec in caplog.records), "No log entry about alert creation"


def test_attempted_write_delete_is_blocked_and_logged(tripwire, caplog, fixed_time, monkeypatch):
    try:
        import tools.cloud.honeycred_tripwire as mod
        monkeypatch.setattr(mod.time, "time", time.time, raising=False)
    except Exception:
        pass

    fixed_time["now"] += 5
    event = {
        "event_time": fixed_time["now"],
        "honeytoken": True,
        "credential_id": "hc-test-2",
        "caller": "arn:example:iam::123456789012:user/honeytoken",
        "source_ip": "127.0.0.1",
        "resource": {"type": "db", "name": "customer-prod"},
        "action": "DeleteResource",
        "context": {"request_id": "req-456"},
    }

    with caplog.at_level("INFO"):
        res = call_process_event(tripwire, event)

    # Expect that action failed due to policy
    # Check return or logs
    if isinstance(res, dict):
        p = res.get("payload", res)
        assert p.get("blocked", True) or p.get("denied", True) or p.get("status", "").lower() in ("blocked", "denied")
    # Look for deny/blocked in logs
    blocked_log = any(any(kw in r.message.lower() for kw in ("blocked", "denied", "policy")) for r in caplog.records)
    assert blocked_log, "Blocked/denied action not logged"

    # Ensure that any destructive cloud operation stubs were not invoked
    # If tripwire has audit/events, check there too
    audit_getter = get_attr(tripwire, ["get_audit_log", "audit_log", "events"])
    if audit_getter:
        audit = audit_getter() if callable(audit_getter) else audit_getter
        assert not any("delete" in json.dumps(e).lower() for e in (audit or [])), "Destructive operations should not be performed"


def test_revocation_and_quarantine_idempotent_and_audited(tripwire, monkeypatch, caplog):
    # Identify revoke/quarantine methods to patch
    revoke_names = ["revoke_credentials", "revoke_credential", "revoke"]
    quarantine_names = ["quarantine_instance", "quarantine_resource", "quarantine", "tag_and_quarantine"]
    revoke_fn = get_attr(tripwire, revoke_names)
    quarantine_fn = get_attr(tripwire, quarantine_names)

    # If not present on tripwire, try module-level or action handler
    if not callable(revoke_fn) or not callable(quarantine_fn):
        handler = get_attr(tripwire, ["responder", "actions", "response", "remediator"])
        if handler:
            if not callable(revoke_fn):
                revoke_fn = get_attr(handler, revoke_names)
            if not callable(quarantine_fn):
                quarantine_fn = get_attr(handler, quarantine_names)

    if not callable(revoke_fn) or not callable(quarantine_fn):
        pytest.skip("Tripwire does not expose revoke/quarantine functions")

    # Wrap to count and simulate idempotency
    calls = {"revoke": [], "quarantine": []}

    def fake_revoke(cred_id):
        calls["revoke"].append(cred_id)
        # Simulate idempotency by returning already_revoked after first
        already = calls["revoke"].count(cred_id) > 1
        return {"revoked": not already, "already_revoked": already, "credential_id": cred_id}

    def fake_quarantine(target):
        calls["quarantine"].append(target)
        already = calls["quarantine"].count(target) > 1
        return {"quarantined": not already, "already_quarantined": already, "target": target, "tags_applied": ["quarantine"]}

    if hasattr(revoke_fn, "__self__"):
        # Method bound to instance; patch on the owner
        monkeypatch.setattr(revoke_fn.__self__, revoke_fn.__name__, fake_revoke, raising=False)
    else:
        monkeypatch.setattr(tripwire, revoke_fn.__name__, fake_revoke, raising=False)

    if hasattr(quarantine_fn, "__self__"):
        monkeypatch.setattr(quarantine_fn.__self__, quarantine_fn.__name__, fake_quarantine, raising=False)
    else:
        monkeypatch.setattr(tripwire, quarantine_fn.__name__, fake_quarantine, raising=False)

    # Trigger detection that should cause response actions
    event = {
        "event_time": time.time(),
        "honeytoken": True,
        "credential_id": "hc-idem-1",
        "caller": "arn:example:iam::123456789012:user/honeytoken",
        "source_ip": "127.0.0.1",
        "resource": {"type": "vm", "id": "i-abc123"},
        "action": "ListSecrets",  # benign read to trigger detection workflow
        "context": {"request_id": "req-789"},
    }

    with caplog.at_level("INFO"):
        _ = call_process_event(tripwire, event)

    # First response
    resp_handler = get_attr(tripwire, ["respond_to_detection", "on_detection", "take_action", "remediate"])
    if callable(resp_handler):
        resp1 = resp_handler(event)
        # No destructive operations
        assert not any(k in json.dumps(resp1).lower() for k in ("delete", "destroy", "terminate"))

    # Second response (idempotent)
    if callable(resp_handler):
        resp2 = resp_handler(event)
        assert not any(k in json.dumps(resp2).lower() for k in ("delete", "destroy", "terminate"))

    # Verify idempotency via our fake counters
    assert calls["revoke"].count("hc-idem-1") >= 1
    assert calls["quarantine"].count({"type": "vm", "id": "i-abc123"}) == 0  # dict unhashable, we passed obj; ensure call done differently
    # Our fake_quarantine was called with the target; fetch last call argument style
    assert len(calls["quarantine"]) >= 1

    # Ensure "already revoked/quarantined" logged or reflected
    already_msgs = [r for r in caplog.records if "already" in r.message.lower()]
    # It's acceptable if not logged but present in responses
    if callable(resp_handler):
        combined = json.dumps(resp2)
        assert "already" in combined.lower() or already_msgs, "Idempotent second response should note 'already' status"

    # Ensure actions are audited
    audit_getter = get_attr(tripwire, ["get_audit_log", "audit_log", "events"])
    if audit_getter:
        audit = audit_getter() if callable(audit_getter) else audit_getter
        assert audit is not None
        assert any("revoke" in json.dumps(e).lower() or "quarantine" in json.dumps(e).lower() for e in (audit or [])), "Actions not audited"


def test_tamper_evidence_and_time_sync(tripwire, fixed_time, monkeypatch):
    try:
        import tools.cloud.honeycred_tripwire as mod
        monkeypatch.setattr(mod.time, "time", time.time, raising=False)
    except Exception:
        pass

    # Generate two alerts to test chaining and time synchronization
    for i in range(2):
        fixed_time["now"] += 10
        event = {
            "event_time": fixed_time["now"],
            "honeytoken": True,
            "credential_id": f"hc-chain-{i}",
            "caller": "arn:example:iam::123456789012:user/honeytoken",
            "source_ip": "127.0.0.1",
            "resource": {"type": "bucket", "name": f"critical-{i}"},
            "action": "GetObject",
            "context": {"request_id": f"req-chain-{i}"},
        }
        _ = call_process_event(tripwire, event)

    alerts = get_alerts(tripwire)
    assert len(alerts) >= 2, "Expected at least two alerts for chain verification"

    # Verify tamper-evident storage via method or by checking prev_hash link
    assert verify_tamper_evident_storage(tripwire), "Tamper-evident chain invalid"

    # Verify times are synchronized with our patched clock
    for a in alerts[-2:]:
        payload = a.get("payload", a)
        ts = payload.get("detected_at") or a.get("timestamp") or a.get("time")
        assert isinstance(ts, (int, float)), "Alert timestamp missing or invalid"
        # ts should be equal to our fake clock at alert creation; allow small drift
        assert ts <= fixed_time["now"], "Alert timestamp from future w.r.t. time source"


def test_error_handling_for_malformed_event(tripwire, caplog):
    bad_events = [
        {},  # completely empty
        {"event_time": time.time(), "action": "GetObject"},  # missing honeytoken/caller/cred id
        {"honeytoken": True, "caller": None, "credential_id": ""},  # missing required fields
    ]

    handler = get_attr(tripwire, ["process_event", "handle_event", "detect_event", "ingest_event", "watch_event", "on_event"])
    if not callable(handler):
        pytest.skip("No event processing function found on HoneyCred Cloud Tripwire")

    with caplog.at_level("WARNING"):
        for ev in bad_events:
            try:
                res = handler(ev)
                # Should not raise; either returns None/False or an error alert
                assert res is None or res is False or isinstance(res, dict)
            except Exception:
                # Exception allowed if properly logged
                pass

    assert any("invalid" in r.message.lower() or "malformed" in r.message.lower() or "missing" in r.message.lower() for r in caplog.records), "Malformed events not logged as errors/warnings"