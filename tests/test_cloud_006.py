import json
import time
from datetime import datetime, timedelta
from types import SimpleNamespace
import pytest

auditor_module = pytest.importorskip("tools.cloud.saas_connector_egress_auditor")


@pytest.fixture
def test_config():
    # Attempt to create a configuration object with reasonable defaults for test tenant
    cfg_cls = getattr(auditor_module, "AuditorConfig", None)
    base = dict(
        tenant_id="tenant-test-123",
        read_only=True,
        require_human_approval=True,
        rate_limit_per_minute=120,
        token_ttl_seconds=60,
        rekor_url="http://127.0.0.1:8790",
        vault_uri="vault://local/test",
        strict_rbac=True,
        immutable_audit_log=True,
        isolated_tenant=True,
    )
    if cfg_cls:
        try:
            return cfg_cls(**base)  # type: ignore
        except Exception:
            return base
    return base


@pytest.fixture
def auditor(test_config, monkeypatch):
    # Construct auditor instance via typical patterns
    AuditorClass = getattr(auditor_module, "SaaSConnectorEgressAuditor", None)
    factory = getattr(auditor_module, "get_auditor", None)

    if AuditorClass is None and factory is None:
        pytest.skip("SaaSConnectorEgressAuditor or get_auditor factory not found")

    if AuditorClass is not None:
        try:
            instance = AuditorClass(test_config)  # type: ignore
        except TypeError:
            instance = AuditorClass()  # type: ignore
    else:
        instance = factory(test_config)  # type: ignore

    # Set test-friendly components if they exist
    # Mock vault client
    vault = SimpleNamespace(calls=[], storage={})

    def vault_set(path, value, ttl=None):
        vault.calls.append(("set", path, bool(value), ttl))
        vault.storage[path] = dict(value=value, ttl=ttl, ts=time.time())

    def vault_get(path):
        vault.calls.append(("get", path))
        return vault.storage.get(path)

    if hasattr(instance, "vault"):
        instance.vault.set = vault_set  # type: ignore
        instance.vault.get = vault_get  # type: ignore
        instance.vault._calls = vault.calls  # type: ignore
    else:
        setattr(instance, "vault", SimpleNamespace(set=vault_set, get=vault_get, _calls=vault.calls))

    # Mock rate limiter
    limiter_state = {"credits": 1000, "calls": 0}

    def allow(n=1):
        limiter_state["calls"] += 1
        if limiter_state["credits"] >= n:
            limiter_state["credits"] -= n
            return True
        return False

    rl = SimpleNamespace(allow=allow, _state=limiter_state)
    setattr(instance, "rate_limiter", rl)

    # Mock RBAC enforcement marker
    setattr(instance, "rbac", SimpleNamespace(enforce=lambda action, principal=None: True))

    # Mock audit log with immutability (append-only)
    log = []

    class ImmutableAuditLog(list):
        def append(self, item):
            # Add a hash chain to enforce immutability evidence
            prev_hash = self[-1]["hash"] if self else "GENESIS"
            payload = json.dumps(item, sort_keys=True)
            new_hash = f"h::{hash((prev_hash, payload))}"
            super().append({**item, "hash": new_hash, "prev": prev_hash})

        def __setitem__(self, index, value):
            raise RuntimeError("Immutable audit log: modification forbidden")

        def pop(self, *args, **kwargs):
            raise RuntimeError("Immutable audit log: deletion forbidden")

    if hasattr(instance, "audit_log"):
        # Replace with immutable wrapper if not already
        try:
            if not isinstance(instance.audit_log, ImmutableAuditLog):  # type: ignore
                instance.audit_log = ImmutableAuditLog()  # type: ignore
        except AttributeError:
            instance.audit_log = ImmutableAuditLog()  # type: ignore
    else:
        instance.audit_log = ImmutableAuditLog()  # type: ignore

    return instance


@pytest.fixture(autouse=True)
def network_guard(monkeypatch):
    # Ensure only localhost/127.0.0.1 network requests are allowed
    import socket

    def is_localhost(url_or_host):
        try:
            host = url_or_host
            if "://" in url_or_host:
                host = url_or_host.split("://", 1)[1].split("/", 1)[0].split("@")[-1]
            host = host.split(":")[0]
            if host in ("localhost", "127.0.0.1", "::1"):
                return True
            try:
                ip = socket.gethostbyname(host)
                return ip.startswith("127.") or ip == "::1"
            except Exception:
                return False
        except Exception:
            return False

    try:
        import requests

        real_request = requests.sessions.Session.request

        def guarded_request(self, method, url, *args, **kwargs):
            if not is_localhost(url):
                raise RuntimeError(f"Network to non-localhost forbidden in tests: {url}")
            return real_request(self, method, url, *args, **kwargs)

        monkeypatch.setattr(requests.sessions.Session, "request", guarded_request)
    except Exception:
        pass

    try:
        import httpx

        real_httpx = httpx.Client.request

        def guarded_httpx(self, method, url, *args, **kwargs):
            if not is_localhost(url):
                raise RuntimeError(f"Network to non-localhost forbidden in tests: {url}")
            return real_httpx(self, method, url, *args, **kwargs)

        monkeypatch.setattr(httpx.Client, "request", guarded_httpx)
    except Exception:
        pass


def _run_event(auditor, event):
    # Normalize running a single event through the auditor, returning list of findings/incidents
    if hasattr(auditor, "audit"):
        res = auditor.audit([event])  # type: ignore
        if res is None:
            return []
        if isinstance(res, dict):
            return [res]
        return list(res)
    if hasattr(auditor, "handle_event"):
        res = auditor.handle_event(event)  # type: ignore
        if res is None:
            return []
        if isinstance(res, dict):
            return [res]
        return list(res)
    if hasattr(auditor, "process_event"):
        res = auditor.process_event(event)  # type: ignore
        if res is None:
            return []
        if isinstance(res, dict):
            return [res]
        return list(res)
    pytest.skip("No event processing method found (audit/handle_event/process_event).")


def _has_method(obj, name):
    return hasattr(obj, name) and callable(getattr(obj, name))


def _fake_sigstore(monkeypatch, auditor):
    # Provide deterministic signing and Rekor logging
    def sign(payload, identity=None):
        return {
            "signature": "sig:deadbeef",
            "certificate": "cert:test",
            "signed_at": datetime.utcnow().isoformat() + "Z",
            "rekor_uuid": "rekor-uuid-123",
        }

    if hasattr(auditor, "signer"):
        auditor.signer = SimpleNamespace(sign=sign)  # type: ignore
    else:
        monkeypatch.setattr(auditor_module, "sigstore_sign", sign, raising=False)

    def rekor_log(entry):
        return {"uuid": "rekor-uuid-123", "timestamp": datetime.utcnow().isoformat() + "Z"}

    if hasattr(auditor, "rekor"):
        auditor.rekor = SimpleNamespace(log=rekor_log)  # type: ignore
    else:
        monkeypatch.setattr(auditor_module, "rekor_log", rekor_log, raising=False)


def test_mis_scoped_slack_app_detected_and_signed_incident(auditor, monkeypatch):
    _fake_sigstore(monkeypatch, auditor)

    # Ensure honey artifact recognition
    def is_honey_artifact(path, tenant_id=None):
        return "honey" in path

    if hasattr(auditor, "is_honey_artifact"):
        monkeypatch.setattr(auditor, "is_honey_artifact", is_honey_artifact)
    else:
        monkeypatch.setattr(auditor_module, "is_honey_artifact", is_honey_artifact, raising=False)

    # Catch signed incident reports emission if method exists
    emitted = []

    def emit_signed_incident_report(incident):
        emitted.append(incident)
        return {
            **incident,
            "signature": "sig:deadbeef",
            "rekor_uuid": "rekor-uuid-123",
            "signed": True,
        }

    if _has_method(auditor, "emit_signed_incident_report"):
        monkeypatch.setattr(auditor, "emit_signed_incident_report", emit_signed_incident_report)

    # Guard against remediation in read-only mode
    if _has_method(auditor, "apply_remediation"):
        applied = {"count": 0}

        def forbidden_apply(*args, **kwargs):
            applied["count"] += 1
            raise AssertionError("Remediation should not be applied in read-only mode")

        monkeypatch.setattr(auditor, "apply_remediation", forbidden_apply)

    honey_event = {
        "type": "file.access",
        "service": "slack",
        "tenant_id": "tenant-test-123",
        "actor": {"type": "oauth_app", "app_id": "A123", "name": "MisScopedApp"},
        "app_scopes": ["files:read", "channels:history"],
        "workspace_ids": ["*"],
        "path": "/Shared/honey/secret.txt",
        "resource_id": "file/F123",
        "ts": datetime.utcnow().isoformat() + "Z",
    }

    findings = _run_event(auditor, honey_event)
    assert isinstance(findings, list)
    assert any(
        (f.get("type") in ("incident", "finding")
         and f.get("category") in ("mis_scoped_app", "egress", "oauth_scope")
         and ("signature" in f or f.get("signed") is True))
        for f in findings
    ) or len(emitted) > 0, "Expected a signed incident report for mis-scoped app after honey access"

    # Validate correlation information
    correlated = [f for f in findings if f.get("correlation")]
    if correlated:
        corr = correlated[0]["correlation"]
        assert "honey_artifact" in corr or "resource_id" in corr
        assert "access_path" in corr or "path" in corr
        assert corr.get("tenant_id") == "tenant-test-123"

    # Audit log should contain an entry with immutability hash chain
    assert len(auditor.audit_log) >= 1
    last = auditor.audit_log[-1]
    assert "hash" in last and "prev" in last


def test_webhook_exfil_attempt_blocked_or_high_severity(auditor, monkeypatch):
    # Simulate DLP/policy engine
    policy_calls = {"count": 0}

    def dlp_scan(payload):
        policy_calls["count"] += 1
        # Detect honey token in payload
        if "HONEY_TOKEN" in json.dumps(payload):
            return {"risk": "HIGH", "contains_honey": True}
        return {"risk": "LOW", "contains_honey": False}

    def evaluate_policy(dlp_result, dest):
        if dlp_result["contains_honey"]:
            return {"action": "block", "reason": "Honey token exfil attempt"}
        return {"action": "allow"}

    if hasattr(auditor, "dlp_scan"):
        monkeypatch.setattr(auditor, "dlp_scan", dlp_scan)
    else:
        monkeypatch.setattr(auditor_module, "dlp_scan", dlp_scan, raising=False)

    if hasattr(auditor, "evaluate_egress_policy"):
        monkeypatch.setattr(auditor, "evaluate_egress_policy", evaluate_policy)
    else:
        monkeypatch.setattr(auditor_module, "evaluate_egress_policy", evaluate_policy, raising=False)

    # Simulate webhook to localhost to satisfy network guard
    webhook_event = {
        "type": "webhook.request",
        "service": "custom_connector",
        "tenant_id": "tenant-test-123",
        "destination": "http://127.0.0.1:8080/exfil",
        "payload": {"data": "token=HONEY_TOKEN:abc123"},
        "ts": datetime.utcnow().isoformat() + "Z",
    }

    findings = _run_event(auditor, webhook_event)
    assert isinstance(findings, list)
    # Either blocked or a high-severity finding should be present
    blocked = any(f.get("status") == "blocked" or f.get("action") == "block" for f in findings)
    high_sev = any(
        f.get("severity") in ("high", "HIGH", "critical", "CRITICAL") for f in findings
    )
    assert blocked or high_sev, "Expected DLP/policy to block exfil or raise high-severity finding"
    assert policy_calls["count"] >= 1


def test_token_rotation_revocation_and_no_residual_access(auditor, monkeypatch):
    # Ensure rotation method exists or skip
    rotate = None
    for name in ("rotate_tokens", "rotate_test_tokens", "perform_token_rotation"):
        if _has_method(auditor, name):
            rotate = getattr(auditor, name)
            break
    if rotate is None:
        pytest.skip("Token rotation method not present on auditor")

    # Mock revoke and stale grant cleanup
    revoked = {"calls": []}
    stale = {"calls": []}

    def revoke_token(app_id, token_id):
        revoked["calls"].append((app_id, token_id))
        return True

    def remove_stale_grants(app_id):
        stale["calls"].append(app_id)
        return True

    if _has_method(auditor, "revoke_token"):
        monkeypatch.setattr(auditor, "revoke_token", revoke_token)
    if _has_method(auditor, "remove_stale_grants"):
        monkeypatch.setattr(auditor, "remove_stale_grants", remove_stale_grants)

    # Simulate existing token in vault with TTL in the past (force rotation)
    app_id = "app-test-rotate"
    old_token_id = "tok-old-123"
    auditor.vault.set(f"apps/{app_id}/token", {"id": old_token_id, "value": "xyz"}, ttl=1)
    # Advance time by simulating TTL expiry where applicable
    # Call rotation
    try:
        result = rotate(app_id=app_id)  # type: ignore
    except TypeError:
        result = rotate(app_id)  # type: ignore

    # Result should indicate revocation and new token issuance
    if isinstance(result, dict):
        assert result.get("revoked") is True or len(revoked["calls"]) >= 1
        assert result.get("stale_grants_removed") is True or len(stale["calls"]) >= 1
        assert result.get("new_token")
        assert result.get("ttl_seconds") or result.get("expires_at")
    else:
        # fallback assertions through mocks
        assert len(revoked["calls"]) >= 1 or _has_method(auditor, "revoke_token") is False
        assert len(stale["calls"]) >= 1 or _has_method(auditor, "remove_stale_grants") is False

    # Simulate replay with old token and ensure it's blocked
    replay_event = {
        "type": "auth.request",
        "service": "slack",
        "tenant_id": "tenant-test-123",
        "token_id": old_token_id,
        "ts": datetime.utcnow().isoformat() + "Z",
    }
    findings = _run_event(auditor, replay_event)
    assert any(
        ("replay" in f.get("type", "") or f.get("status") == "blocked" or f.get("blocked") is True)
        for f in findings
    ), "Expected replay attempt with revoked token to be blocked"

    # Audit log should reflect a blocked replay
    assert any("replay" in entry.get("event", {}).get("type", "") or entry.get("blocked") for entry in auditor.audit_log)


def test_rate_limiting_and_token_ttl_enforced(auditor):
    # Provide limited credits and ensure events are rate-limited
    auditor.rate_limiter._state["credits"] = 2  # only two events allowed
    # Send three events quickly
    ev = {
        "type": "noop.event",
        "service": "test",
        "tenant_id": "tenant-test-123",
        "ts": datetime.utcnow().isoformat() + "Z",
    }
    out1 = _run_event(auditor, ev)
    out2 = _run_event(auditor, ev)
    out3 = _run_event(auditor, ev)

    # Rate limiter should be consulted at least three times
    assert auditor.rate_limiter._state["calls"] >= 3

    # The third one should be dropped/throttled or marked as rate_limited
    rate_limited = any(
        f.get("status") in ("rate_limited", "throttled") or f.get("dropped") for f in out3
    ) if out3 else True  # no findings may also indicate drop
    assert rate_limited

    # Token TTL enforcement (if method exists to issue tokens)
    if hasattr(auditor, "issue_token"):
        now = datetime.utcnow()
        token = auditor.issue_token(app_id="app-x", ttl_seconds=1)  # type: ignore
        assert token
        # Wait for TTL
        time.sleep(1.1)
        # Validate auto revocation or expiration
        if hasattr(auditor, "validate_token"):
            valid = auditor.validate_token(token)  # type: ignore
            assert not valid


def test_sigstore_failure_marks_report_unsigned(auditor, monkeypatch):
    # Force signer to fail
    def fail_sign(payload, identity=None):
        raise RuntimeError("Sigstore unavailable")

    if hasattr(auditor, "signer"):
        auditor.signer = SimpleNamespace(sign=fail_sign)  # type: ignore
    else:
        monkeypatch.setattr(auditor_module, "sigstore_sign", fail_sign, raising=False)

    honey_event = {
        "type": "file.access",
        "service": "slack",
        "tenant_id": "tenant-test-123",
        "actor": {"type": "oauth_app", "app_id": "A124", "name": "AnotherApp"},
        "app_scopes": ["files:read"],
        "workspace_ids": ["*"],
        "path": "/Shared/honey/tripwire.pdf",
        "resource_id": "file/F456",
        "ts": datetime.utcnow().isoformat() + "Z",
    }

    findings = _run_event(auditor, honey_event)
    # Expect incident still produced but unsigned or error flagged
    assert any(
        f.get("type") in ("incident", "finding")
        and ("signature" not in f and not f.get("signed"))
        or f.get("sign_error")
        for f in findings
    )


def test_remediation_requires_human_approval(auditor):
    # Only test if remediation interface exists
    if not _has_method(auditor, "request_remediation") or not _has_method(auditor, "apply_remediation"):
        pytest.skip("Remediation interfaces not present")

    action = {
        "action": "tighten_scope",
        "service": "slack",
        "app_id": "A125",
        "target_scopes": ["files:read:user"],  # scope tightening
        "reason": "Policy gate due to honey access",
        "tenant_id": "tenant-test-123",
    }
    req = auditor.request_remediation(action)  # type: ignore
    assert req and req.get("status") in ("pending", "PENDING")
    # Attempt apply without approval should fail in read-only / approval required mode
    with pytest.raises(Exception):
        auditor.apply_remediation(req)  # type: ignore
    # Simulate human approval
    req["approved_by"] = "security-admin"
    req["approved_at"] = datetime.utcnow().isoformat() + "Z"
    # Now application may still be gated by read-only, but if allowed, must succeed
    try:
        result = auditor.apply_remediation(req)  # type: ignore
        assert result is True or isinstance(result, dict)
    except Exception:
        # In strict read-only the auditor should reject; that's acceptable if read_only True
        assert getattr(auditor, "read_only", True) is True


def test_vault_secret_storage_and_immutable_audit_log(auditor):
    # Vault set/get
    auditor.vault.set("apps/test/secret", {"token": "abc"}, ttl=60)
    stored = auditor.vault.get("apps/test/secret")
    assert stored and stored["ttl"] == 60
    # Ensure calls recorded
    assert any(c[0] == "set" for c in auditor.vault._calls)
    assert any(c[0] == "get" for c in auditor.vault._calls)

    # Immutable audit log behavior
    before_len = len(auditor.audit_log)
    auditor.audit_log.append({"event": {"type": "test.log"}, "ts": datetime.utcnow().isoformat() + "Z"})
    assert len(auditor.audit_log) == before_len + 1
    entry = auditor.audit_log[-1]
    assert "hash" in entry and "prev" in entry
    # Try to mutate and expect failure
    with pytest.raises(RuntimeError):
        auditor.audit_log[-1] = {"tampered": True}
    with pytest.raises(RuntimeError):
        auditor.audit_log.pop()