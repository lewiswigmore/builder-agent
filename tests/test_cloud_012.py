import hmac
import hashlib
import os
import time
import uuid
import json
import inspect
import types
import pytest


@pytest.fixture(scope="module")
def ws_module():
    return pytest.importorskip("tools.cloud.webhookshield", reason="WebhookShield module not available")


@pytest.fixture
def shield(ws_module, monkeypatch):
    # Try to build a WebhookShield instance if class exists, else use module namespace as handler container
    shield_cls = getattr(ws_module, "WebhookShield", None)
    instance = None
    if isinstance(shield_cls, type):
        try:
            instance = shield_cls()  # default constructor if allowed
        except Exception:
            # Try with a permissive config if supported
            try:
                instance = shield_cls(clock_skew_seconds=60)
            except Exception:
                # Fall back to module-level handlers
                instance = None

    # Mock external timestamping/anchoring if present
    for attr_name in ("anchor_timestamp", "external_anchor", "ExternalAnchorClient", "TimeStamper", "TimestampAuthority"):
        if hasattr(ws_module, attr_name):
            attr = getattr(ws_module, attr_name)
            if isinstance(attr, types.FunctionType):
                monkeypatch.setattr(ws_module, attr_name, lambda *args, **kwargs: {"anchor_id": "fake-anchor", "ts": int(time.time())})
            else:
                # If it's a class or object with anchor method
                try:
                    monkeypatch.setattr(attr, "anchor", lambda *args, **kwargs: {"anchor_id": "fake-anchor", "ts": int(time.time())})
                except Exception:
                    pass

    # Make sure environment secrets are deterministic for tests if the implementation uses env
    monkeypatch.setenv("WEBHOOK_SECRET", "testsecret")
    monkeypatch.setenv("WEBHOOKSHIELD_SECRET", "testsecret")

    return instance if instance is not None else ws_module


def _find_handler(shield_obj):
    # Determine a callable handler on the object or module
    candidates = [
        "handle_webhook",
        "process_webhook",
        "handle_request",
        "process_request",
        "verify_and_process",
        "handle",
        "process",
    ]
    for name in candidates:
        if hasattr(shield_obj, name) and callable(getattr(shield_obj, name)):
            return getattr(shield_obj, name)
    # If the object is a module and has a class with similar methods
    ws_cls = getattr(shield_obj, "WebhookShield", None)
    if isinstance(ws_cls, type):
        for name in candidates:
            if hasattr(ws_cls, name) and callable(getattr(ws_cls, name)):
                # Return a bound method using a new instance if possible
                try:
                    inst = ws_cls()
                    return getattr(inst, name)
                except Exception:
                    continue
    return None


def _call_handler(handler, headers, body, remote_addr="127.0.0.1", path="/webhook", tls_peer=None):
    # Build a generic request payload and dispatch based on handler signature
    req = {
        "headers": headers,
        "body": body,
        "remote_addr": remote_addr,
        "path": path,
    }
    if tls_peer is not None:
        req["tls_peer"] = tls_peer

    sig = inspect.signature(handler)
    params = list(sig.parameters.keys())

    # Try common calling conventions
    try_orders = [
        ("headers", "body", "remote_addr", "path"),
        ("headers", "body", "remote_addr"),
        ("request",),
        ("context",),
        ("req",),
        ("headers", "body"),
        (),
    ]

    for order in try_orders:
        # Map our known fields to the function's parameters by name order
        try:
            if len(order) == 0:
                return handler()
            elif len(order) == 1:
                if order[0] in ("request", "context", "req"):
                    return handler(req)
                else:
                    kwargs = {order[0]: headers}
                    return handler(**kwargs)
            else:
                kwargs = {}
                for name in order:
                    if name == "headers":
                        kwargs[name] = headers
                    elif name == "body":
                        kwargs[name] = body
                    elif name == "remote_addr":
                        kwargs[name] = remote_addr
                    elif name == "path":
                        kwargs[name] = path
                    else:
                        kwargs[name] = req
                return handler(**kwargs)
        except TypeError:
            continue
    # If nothing matched, try passing everything as kwargs if params are visible
    try:
        common = {k: v for k, v in req.items() if k in params}
        if "headers" in params and "body" in params and "remote_addr" in params:
            common.update({"headers": headers, "body": body, "remote_addr": remote_addr})
        return handler(**common)
    except Exception:
        # As a last resort, just call with one arg as the request object
        return handler(req)


def _result_to_status(result):
    # Normalize result into (accepted: bool, code: str)
    accepted = None
    code = ""
    status = None
    if isinstance(result, dict):
        accepted = result.get("accepted")
        code = result.get("code") or result.get("reason") or result.get("error") or ""
        status = result.get("status") or result.get("status_code")
    elif hasattr(result, "accepted") or hasattr(result, "ok") or hasattr(result, "status"):
        accepted = getattr(result, "accepted", None)
        ok = getattr(result, "ok", None)
        status = getattr(result, "status", None) or getattr(result, "status_code", None)
        code = getattr(result, "code", "") or getattr(result, "reason", "") or ""
        if accepted is None and ok is not None:
            accepted = bool(ok)
    elif isinstance(result, tuple) and len(result) >= 2:
        status = result[0]
        code = result[1]
        try:
            accepted = 200 <= int(status) < 300
        except Exception:
            accepted = None
    elif isinstance(result, int):
        status = result
        accepted = 200 <= int(status) < 300
    else:
        # Unknown type, fallback
        accepted = False
    return accepted, code, status


def _compute_sig(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _get_audit_entries(ws_module_or_obj):
    # Try to read audit log entries from common attributes or methods
    candidates = [
        "audit_log",
        "audit",
        "AUDIT_LOG",
        "AuditLog",
        "get_audit_log",
        "get_audit_chain",
        "export_audit_log",
    ]
    for name in candidates:
        if hasattr(ws_module_or_obj, name):
            attr = getattr(ws_module_or_obj, name)
            if callable(attr):
                try:
                    entries = attr()
                    if entries is not None:
                        return entries
                except Exception:
                    continue
            else:
                # Object or list
                if isinstance(attr, list):
                    return attr
                # Try attr.entries or attr.dump
                for subname in ("entries", "dump", "tail"):
                    if hasattr(attr, subname):
                        subattr = getattr(attr, subname)
                        try:
                            return subattr() if callable(subattr) else subattr
                        except Exception:
                            continue
    return None


def _monkeypatch_optional(monkeypatch, target, name, sentinel):
    if hasattr(target, name):
        calls = {"count": 0, "args": []}

        def wrapper(*args, **kwargs):
            calls["count"] += 1
            calls["args"].append((args, kwargs))
            return sentinel

        monkeypatch.setattr(target, name, wrapper)
        return calls
    return None


@pytest.mark.parametrize("skew_seconds", [30, 60])
def test_replay_outside_allowed_window_rejected_and_logged(ws_module, shield, skew_seconds, caplog, monkeypatch):
    handler = _find_handler(shield)
    if handler is None:
        pytest.skip("No webhook handler available")

    # Ideally configure stricter skew if supported
    for attr in ("clock_skew_seconds", "allowed_skew", "max_clock_skew"):
        if hasattr(shield, attr):
            try:
                setattr(shield, attr, skew_seconds)
            except Exception:
                pass

    # Prepare a captured request with old timestamp
    body = json.dumps({"event": "push", "id": "evt-" + uuid.uuid4().hex}).encode()
    headers = {
        "X-Timestamp": str(int(time.time()) - (skew_seconds + 300)),
        "X-Nonce": uuid.uuid4().hex,
        "X-Signature": _compute_sig("testsecret", body),
        "Content-Type": "application/json",
    }

    caplog.clear()
    with caplog.at_level("INFO"):
        result = _call_handler(handler, headers, body, remote_addr="127.0.0.1", path="/webhook")

    accepted, code, status = _result_to_status(result)
    # Expect rejection
    assert accepted is False or (status is not None and int(status) >= 400)

    # Ensure REPLAY_DETECTED is logged with source IP and signature details
    messages = "\n".join([f"{r.levelname}:{r.message}" for r in caplog.records])
    assert "REPLAY_DETECTED" in messages
    assert "127.0.0.1" in messages
    assert "Signature" in messages or "signature" in messages or headers["X-Signature"] in messages

    # Ensure audit log appended
    entries = _get_audit_entries(shield) or _get_audit_entries(ws_module)
    if entries is not None:
        # Find an entry referencing replay with hash linkage if present
        replay_entries = [e for e in entries if "REPLAY_DETECTED" in json.dumps(e)]
        assert len(replay_entries) >= 1


def test_invalid_signature_fails_closed_and_sealed_forensics(ws_module, shield, caplog, monkeypatch):
    handler = _find_handler(shield)
    if handler is None:
        pytest.skip("No webhook handler available")

    body = json.dumps({"event": "push", "id": "evt-" + uuid.uuid4().hex}).encode()
    headers = {
        "X-Timestamp": str(int(time.time())),
        "X-Nonce": uuid.uuid4().hex,
        "X-Signature": "sha256=deadbeef",  # invalid signature
        "Content-Type": "application/json",
    }

    # Spy on forensic artifact emitter/store if present
    forensic_calls = None
    for target in (shield, ws_module):
        for name in ("store_forensic_bundle", "emit_forensic_bundle", "save_forensic_bundle", "seal_forensics"):
            forensic_calls = forensic_calls or _monkeypatch_optional(monkeypatch, target, name, {"sealed": True})

    caplog.clear()
    with caplog.at_level("INFO"):
        result = _call_handler(handler, headers, body, remote_addr="127.0.0.1", path="/webhook")

    accepted, code, status = _result_to_status(result)
    # Must fail closed
    assert accepted is False or (status is not None and int(status) >= 400)

    # Signature invalid should be logged
    messages = "\n".join([f"{r.levelname}:{r.message}" for r in caplog.records])
    assert "SIGNATURE_INVALID" in messages

    # Sealed forensic bundle must be stored/emitted
    forensic_logged = any("forensic" in r.message.lower() and ("sealed" in r.message.lower() or "bundle" in r.message.lower()) for r in caplog.records)
    assert forensic_logged or (forensic_calls is not None and forensic_calls["count"] >= 1)


def test_honey_webhook_rotates_secret_blocks_source_and_opens_incident(ws_module, shield, caplog, monkeypatch):
    handler = _find_handler(shield)
    if handler is None:
        pytest.skip("No webhook handler available")

    # Spy on rotation, blocking and incident emission if present
    rotate_calls = None
    block_calls = None
    incident_calls = None
    for target in (shield, ws_module):
        rotate_calls = rotate_calls or _monkeypatch_optional(monkeypatch, target, "rotate_secret", {"rotated": True})
        block_calls = block_calls or _monkeypatch_optional(monkeypatch, target, "block_source", {"blocked": True})
        for name in ("emit_incident", "open_incident", "create_incident", "report_incident"):
            incident_calls = incident_calls or _monkeypatch_optional(monkeypatch, target, name, {"incident_id": "inc-" + uuid.uuid4().hex})

    body = json.dumps({"trap": True, "id": "evt-" + uuid.uuid4().hex}).encode()
    headers = {
        "X-Timestamp": str(int(time.time())),
        "X-Nonce": uuid.uuid4().hex,
        "X-Signature": "sha256=honey",  # irrelevant for honey
        "Content-Type": "application/json",
        "X-Honey": "1",
    }

    caplog.clear()
    with caplog.at_level("INFO"):
        result = _call_handler(handler, headers, body, remote_addr="127.0.0.1", path="/honey")

    # Ensure honey handling did not crash normal flows
    # The honey endpoint should be quarantined; not necessarily accepted
    # Focus on side effects: rotation, block, incident
    messages = "\n".join([f"{r.levelname}:{r.message}" for r in caplog.records])
    assert ("honey" in messages.lower() or "/honey" in messages.lower() or "quarantine" in messages.lower())

    rotated = ("rotate" in messages.lower() and "secret" in messages.lower()) or (rotate_calls is not None and rotate_calls["count"] >= 1)
    blocked = ("block" in messages.lower() and ("source" in messages.lower() or "ip" in messages.lower())) or (block_calls is not None and block_calls["count"] >= 1)
    incident = ("incident" in messages.lower() and ("opened" in messages.lower() or "created" in messages.lower() or "emitted" in messages.lower())) or (incident_calls is not None and incident_calls["count"] >= 1)
    assert rotated and blocked and incident


def test_nonce_reuse_detected_as_replay(ws_module, shield, caplog):
    handler = _find_handler(shield)
    if handler is None:
        pytest.skip("No webhook handler available")

    body = json.dumps({"ping": True, "id": "evt-" + uuid.uuid4().hex}).encode()
    nonce = uuid.uuid4().hex
    headers1 = {
        "X-Timestamp": str(int(time.time())),
        "X-Nonce": nonce,
        "X-Signature": _compute_sig("testsecret", body),
        "Content-Type": "application/json",
    }
    headers2 = dict(headers1)  # same nonce to simulate replay

    caplog.clear()
    _call_handler(handler, headers1, body, remote_addr="127.0.0.1", path="/webhook")
    # Second call with same nonce should be detected as replay
    with caplog.at_level("INFO"):
        _call_handler(handler, headers2, body, remote_addr="127.0.0.1", path="/webhook")

    messages = "\n".join([f"{r.levelname}:{r.message}" for r in caplog.records])
    assert "REPLAY" in messages.upper() or "NONCE" in messages.upper()


def test_audit_log_hash_chain_integrity(ws_module, shield, monkeypatch):
    # If audit log is exposed, ensure hash chaining prev -> current is consistent across two events.
    entries_before = _get_audit_entries(shield) or _get_audit_entries(ws_module)
    if entries_before is None:
        pytest.skip("Audit log interface not available")
    # Append two synthetic audit entries via available logging/hook mechanism if any, else skip
    appenders = []
    for target in (shield, ws_module):
        for name in ("append_audit", "log_audit", "audit_append", "record_audit"):
            if hasattr(target, name) and callable(getattr(target, name)):
                appenders.append(getattr(target, name))
    if not appenders:
        pytest.skip("No audit appender available")
    # Append first entry
    e1 = {"ts": int(time.time()), "event": "TEST_EVENT_1", "code": "TEST1"}
    appenders[0](e1)
    # Append second entry
    e2 = {"ts": int(time.time()), "event": "TEST_EVENT_2", "code": "TEST2"}
    appenders[0](e2)

    entries = _get_audit_entries(shield) or _get_audit_entries(ws_module)
    assert isinstance(entries, (list, tuple)) and len(entries) >= 2
    # Find our last two entries
    tail = entries[-2:]
    # If hash chaining fields are present, validate linkage
    prev_hash_field_names = ("prev_hash", "previous_hash", "parent", "prev")
    curr_hash_field_names = ("hash", "entry_hash", "digest")
    prev_hash = None
    curr_hash = None
    for name in prev_hash_field_names:
        if name in tail[1]:
            prev_hash = tail[1][name]
            break
    for name in curr_hash_field_names:
        if name in tail[0]:
            curr_hash = tail[0][name]
            break
    if prev_hash is not None and curr_hash is not None:
        assert prev_hash == curr_hash, "Audit hash chain broken between last two entries"