import json
import inspect
import socket
import subprocess
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    # Block non-localhost network connections
    real_create_connection = socket.create_connection

    def guarded_create_connection(address, *args, **kwargs):
        host, port = address
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(f"External network blocked in tests: {host}:{port}")
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)


@pytest.fixture(autouse=True)
def fake_sigstore_and_transparency(monkeypatch):
    """
    Simulate external cosign, in-toto/SLSA, and transparency log (rekor) CLI commands.
    """
    def fake_run(cmd, *args, **kwargs):
        # Normalize command to string
        if isinstance(cmd, (list, tuple)):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = str(cmd)

        class Result:
            def __init__(self, returncode=0, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        # Simulate cosign verification
        if "cosign" in cmd_str:
            # If the command hints at a valid signature token, succeed, else fail
            if "VALID_SIGNATURE" in cmd_str or "--key" in cmd_str or "--certificate" in cmd_str:
                return Result(0, stdout="cosign: Verified OK")
            return Result(1, stdout="", stderr="cosign: verification failed")

        # Simulate in-toto/SLSA verification
        if "in-toto" in cmd_str or "slsa" in cmd_str:
            if "HAVE_PROVENANCE" in cmd_str or "--provenance" in cmd_str:
                return Result(0, stdout="in-toto: provenance OK")
            return Result(1, stdout="", stderr="in-toto: provenance missing")

        # Simulate rekor / transparency log anchoring
        if "rekor" in cmd_str or "transparency" in cmd_str or "ctlog" in cmd_str:
            return Result(0, stdout="rekor: entry created and anchored")

        # Default benign command
        return Result(0, stdout="")

    monkeypatch.setattr(subprocess, "run", fake_run)


@pytest.fixture
def ww_tool(monkeypatch):
    import importlib
    mod = importlib.import_module("tools.ai_security.weightwatch")

    # Attempt to construct a tool instance from the module
    def construct_tool():
        # Prefer a class named WeightWatch
        if hasattr(mod, "WeightWatch") and callable(getattr(mod, "WeightWatch")):
            cls = getattr(mod, "WeightWatch")
            # Filter kwargs to init signature
            init_sig = inspect.signature(cls)
            kwargs = {
                "read_only": True,
                "quarantine_namespace": "quarantine-test",
                "enable_sigstore": True,
                "enable_transparency_log": True,
                "scoped_tokens_only": True,
                "immutable_audit": True,
            }
            filtered = {}
            for p in init_sig.parameters.values():
                if p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD):
                    if p.name in kwargs:
                        filtered[p.name] = kwargs[p.name]
            try:
                return cls(**filtered)
            except Exception:
                try:
                    return cls()
                except Exception:
                    pass

        # Factory-style functions
        for name in ("get_tool", "create", "initialize", "init", "make"):
            if hasattr(mod, name) and callable(getattr(mod, name)):
                fn = getattr(mod, name)
                sig = inspect.signature(fn)
                kwargs = {
                    "read_only": True,
                    "quarantine_namespace": "quarantine-test",
                    "enable_sigstore": True,
                    "enable_transparency_log": True,
                    "scoped_tokens_only": True,
                    "immutable_audit": True,
                }
                filtered = {}
                for p in sig.parameters.values():
                    if p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD):
                        if p.name in kwargs:
                            filtered[p.name] = kwargs[p.name]
                try:
                    return fn(**filtered)
                except Exception:
                    try:
                        return fn()
                    except Exception:
                        continue

        # If no constructor, use module itself as handler
        return mod

    return construct_tool()


def _call_handler(obj, candidate_names, payload):
    """
    Try to call one of the candidate handler names on obj (or obj as module),
    falling back to generic 'process_event' style if present.
    """
    # Handler search on object
    for name in candidate_names:
        if hasattr(obj, name) and callable(getattr(obj, name)):
            fn = getattr(obj, name)
            return _invoke_with_filtered_kwargs(fn, payload)

    # If object is a module, try module-level functions
    if inspect.ismodule(obj):
        for name in candidate_names:
            if hasattr(obj, name) and callable(getattr(obj, name)):
                fn = getattr(obj, name)
                return _invoke_with_filtered_kwargs(fn, payload)

    # Fallback to process_event-like unified entrypoints
    for name in ("process_event", "scan_event", "handle_event", "run", "dispatch"):
        if hasattr(obj, name) and callable(getattr(obj, name)):
            fn = getattr(obj, name)
            # Provide event type in payload if missing
            if "event_type" not in payload and "type" not in payload:
                # Attempt to infer from candidate_names
                if "pull" in candidate_names[0]:
                    payload = {"event_type": "pull", **payload}
                elif "canary" in candidate_names[0]:
                    payload = {"event_type": "canary_access", **payload}
                elif "promotion" in candidate_names[0]:
                    payload = {"event_type": "promotion", **payload}
            return _invoke_with_filtered_kwargs(fn, payload)

    # If obj is callable, attempt calling it
    if callable(obj):
        return _invoke_with_filtered_kwargs(obj, payload)

    raise AttributeError(f"No suitable handler found for names: {candidate_names}")


def _invoke_with_filtered_kwargs(fn, payload):
    """
    Invoke function with only accepted kwargs, or pass a single dict if signature expects 'event' or 'request'.
    """
    sig = inspect.signature(fn)
    params = sig.parameters
    # If function takes a single positional argument commonly named event/request/context
    if len(params) == 1:
        (pname, p) = next(iter(params.items()))
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
            return fn(payload)

    # Otherwise filter kwargs
    allowed = {}
    for pname, p in params.items():
        if pname in payload:
            allowed[pname] = payload[pname]
        # Provide common aliases
        elif pname == "event" or pname == "request":
            allowed[pname] = payload
        elif pname == "ip" and "source_ip" in payload:
            allowed[pname] = payload["source_ip"]
        elif pname == "source_ip" and "ip" in payload:
            allowed[pname] = payload["ip"]
        elif pname == "tag" and "model_tag" in payload:
            allowed[pname] = payload["model_tag"]
    return fn(**allowed)


def _get_field(d, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and k in d:
            return d[k]
    return default


def _truthy_any(result, keys=None, substr=None):
    # Check truthy presence across multiple candidate keys or in stringified result
    if keys:
        for k in keys:
            v = _get_field(result, k, default=None)
            if isinstance(v, bool) and v:
                return True
            if isinstance(v, str) and v:
                return True
    if substr:
        txt = json.dumps(result, sort_keys=True)
        if substr.lower() in txt.lower():
            return True
    return False


def _assert_signed_bundle(result):
    # Accept various shapes for a signed incident bundle
    incident = _get_field(result, "incident", "incident_bundle", "signed_incident", default={})
    assert incident is not None
    if isinstance(incident, dict):
        assert _truthy_any(incident, keys=("signed", "signature", "sig"), substr="sigstore") or _truthy_any(
            result, substr="signed incident"
        )
        assert _truthy_any(incident, keys=("timestamp", "ts", "time")) or _truthy_any(result, substr="timestamp")
    else:
        # fallback to overall result content containing indicators
        assert _truthy_any(result, substr="signed")
        assert _truthy_any(result, substr="timestamp")


def _assert_quarantined(result):
    # Validate that quarantine action was taken in a safe namespace
    assert _truthy_any(result, keys=("quarantined", "is_quarantined"), substr="quarantin")
    qns = _get_field(result, "quarantine_namespace", "namespace", default="").lower()
    if qns:
        assert "quarantine" in qns or "ww" in qns or "tmp" in qns


def _assert_signature_failure(result):
    # Confirm signature verification failed and was considered
    txt = json.dumps(result, sort_keys=True).lower()
    assert ("cosign" in txt or "sigstore" in txt) and ("in-toto" in txt or "slsa" in txt)
    assert ("invalid" in txt or "missing" in txt or "fail" in txt)


def _assert_transparency_anchor(result):
    txt = json.dumps(result, sort_keys=True).lower()
    assert ("rekor" in txt or "transparency" in txt or "ctlog" in txt) and ("anchor" in txt or "entry" in txt)


def _assert_token_revoked(result, token_id):
    # Accept token revocation in different result shapes
    revoked = _get_field(result, "revoked", "token_revoked", "revoked_token", default=None)
    if revoked is None:
        # fallback: search in text
        assert token_id in json.dumps(result, sort_keys=True)
    else:
        if isinstance(revoked, (list, tuple, set)):
            assert token_id in revoked
        else:
            assert str(revoked) == str(token_id)


def _assert_policy_blocked(result):
    # Validate promotion was blocked due to verification and provenance failure
    txt = json.dumps(result, sort_keys=True).lower()
    assert ("block" in txt or "denied" in txt or "rejected" in txt)
    assert ("cosign" in txt or "sigstore" in txt)
    assert ("in-toto" in txt or "slsa" in txt or "provenance" in txt)
    # Remediation hint/diff presence
    assert ("remediation" in txt or "diff" in txt or "how to fix" in txt)


def _assert_minimal_data_collection(result):
    # Ensure no raw weights content is stored in result; only hashes/metadata allowed
    txt = json.dumps(result, sort_keys=True).lower()
    assert "weights" not in txt and "blob" not in txt and "content_bytes" not in txt and "raw_content" not in txt
    # Accept presence of hashes/metadata/audit trails
    assert ("hash" in txt or "digest" in txt or "metadata" in txt or "audit" in txt or "attestation" in txt)


def _anomalous_pull_event():
    return {
        "event_type": "pull",
        "model": "acme/vision",
        "model_tag": "protected-v1",
        "tag": "protected-v1",
        "ip": "203.0.113.50",
        "identity": "unknown",
        "geo": "ZZ",
        "pulls_in_window": 5000,
        "baseline_rate": 50,
        "timestamp": "2024-01-01T12:00:00Z",
        # Provide hints to fake subprocess for signature checks to fail
        "cosign_args": ["--verify"],  # no VALID_SIGNATURE token -> will fail
        "provenance_args": ["--check"],  # no HAVE_PROVENANCE -> will fail
    }


def _canary_access_event():
    return {
        "event_type": "canary_access",
        "bucket": "private-bucket",
        "object": "canary-shard-abc123",
        "token_id": "scoped-xyz",
        "ip": "198.51.100.77",
        "cidr_allowed": ["10.0.0.0/8"],
        "timestamp": "2024-01-01T12:05:00Z",
        # Provide hints to fake subprocess for watermark checks to pass
        "cosign_args": ["--verify", "VALID_SIGNATURE"],
        "provenance_args": ["--provenance", "HAVE_PROVENANCE"],
    }


def _promotion_request_unsigned():
    return {
        "event_type": "promotion",
        "model": "acme/vision",
        "revision": "sha256:deadbeef",
        "source_tag": "candidate",
        "target_tag": "stable",
        "signatures": None,
        "provenance": None,
        "timestamp": "2024-01-01T12:10:00Z",
        # Missing VALID_SIGNATURE/HAVE_PROVENANCE -> verifications will fail
        "cosign_args": ["--verify"],
        "provenance_args": ["--check"],
    }


def test_anomalous_pull_surge_detection_quarantine_and_signed_incident(ww_tool):
    event = _anomalous_pull_event()
    # Call handler
    result = _call_handler(
        ww_tool,
        candidate_names=[
            "handle_pull_event",
            "observe_pull",
            "on_pull",
            "process_pull",
            "detect_pull_anomaly",
        ],
        payload=event,
    )
    assert result is not None

    # Detect anomaly via rate/geo/profile deviation
    txt = json.dumps(result, sort_keys=True).lower()
    assert ("anomaly" in txt or "deviation" in txt or "suspicious" in txt)

    # Confirm missing/invalid signatures were part of the decision
    _assert_signature_failure(result)

    # Emits a signed incident bundle and immutable timestamping
    _assert_signed_bundle(result)

    # Temporarily quarantines the tag
    _assert_quarantined(result)

    # Ensure minimal data collection (no weight content storage)
    _assert_minimal_data_collection(result)


def test_canary_access_from_disallowed_cidr_revokes_token_and_anchors_alert(ww_tool):
    event = _canary_access_event()
    result = _call_handler(
        ww_tool,
        candidate_names=[
            "handle_canary_access",
            "observe_canary",
            "on_canary_access",
            "process_canary_access",
            "detect_canary_leak",
        ],
        payload=event,
    )
    assert result is not None

    txt = json.dumps(result, sort_keys=True).lower()
    # Tool detects access and validates canary watermark
    assert ("canary" in txt and ("valid" in txt or "verified" in txt))
    # Revokes the scoped token
    _assert_token_revoked(result, token_id=event["token_id"])
    # Anchors the alert to transparency logs (rekor/ctlog)
    _assert_transparency_anchor(result)

    # Ensure minimal data collection is upheld
    _assert_minimal_data_collection(result)


def test_promotion_of_unsigned_revision_is_blocked_with_remediation_diff(ww_tool):
    request = _promotion_request_unsigned()
    result = _call_handler(
        ww_tool,
        candidate_names=[
            "policy_gate_promotion",
            "gate_promotion",
            "attempt_promotion",
            "promote",
            "handle_promotion",
        ],
        payload=request,
    )
    assert result is not None

    # Promotion must be blocked due to cosign and in-toto provenance verification failures
    _assert_policy_blocked(result)

    # Ensure minimal data collection is upheld
    _assert_minimal_data_collection(result)


def test_error_handling_missing_fields_and_read_only_guards(ww_tool):
    # Missing critical fields should not crash; should yield structured error or rejection
    bad_event = {
        "event_type": "pull",
        # missing model/tag/ip
        "pulls_in_window": None,
        "baseline_rate": None,
        "timestamp": "2024-01-01T12:00:00Z",
    }
    try:
        result = _call_handler(
            ww_tool,
            candidate_names=[
                "handle_pull_event",
                "observe_pull",
                "on_pull",
                "process_pull",
                "detect_pull_anomaly",
            ],
            payload=bad_event,
        )
    except Exception as e:
        # If tool raises a validation exception, that is acceptable; ensure it's a controlled error
        assert isinstance(e, (ValueError, AssertionError, TypeError, RuntimeError))
        return

    # If tool returns a result, ensure it indicates error/rejection and does not attempt stateful writes
    txt = json.dumps(result, sort_keys=True).lower()
    assert ("error" in txt or "invalid" in txt or "rejected" in txt)
    # Ensure read-only mode is respected: no destructive actions outside quarantine namespace
    assert "delete" not in txt and "overwrite" not in txt
    if "namespace" in txt:
        assert "quarantine" in txt or "tmp" in txt or "ww" in txt

    _assert_minimal_data_collection(result)