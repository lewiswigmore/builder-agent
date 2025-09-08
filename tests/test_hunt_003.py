import re
import datetime as dt
from typing import List, Dict, Any, Optional
import pytest

from tools.threat_hunting.idp_attack_pattern_hunter import IdpAttackPatternHunter  # type: ignore


def is_semver(s: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+(-[\w\.\+]+)?$", s))


def iso(dt_obj: dt.datetime) -> str:
    return dt_obj.replace(microsecond=0).isoformat() + "Z"


@pytest.fixture
def default_policy():
    return {
        "read_only_ingestion": True,
        "response_actions_enabled": False,
        "require_human_approval": True,
        "retention_days": 30,
        "pii_minimization": True,
        "field_level_encryption": True,
        "tamper_evident_logging": True,
        "rulepack_version": "1.0.0",
    }


@pytest.fixture
def hunter(default_policy):
    return IdpAttackPatternHunter(policy=default_policy)


@pytest.fixture
def mfa_fatigue_events() -> List[Dict[str, Any]]:
    base = dt.datetime.utcnow()
    events = []
    for i in range(21):
        events.append(
            {
                "type": "mfa_challenge",
                "user_id": "user-123",
                "user_email": "alice@example.com",
                "ip_address": "127.0.0.1",
                "asn": "AS99999" if i < 20 else "AS88888",
                "is_new_asn": True,
                "is_new_ip": True,
                "method": "push",
                "result": "denied" if i < 20 else "approved",
                "timestamp": iso(base + dt.timedelta(seconds=i * 25)),
                "device_fingerprint": "dev-zzz",
            }
        )
    return events


@pytest.fixture
def aitm_events() -> List[Dict[str, Any]]:
    now = dt.datetime.utcnow()
    return [
        {
            "type": "signin",
            "user_id": "user-777",
            "user_email": "bob@example.com",
            "ip_address": "127.0.0.1",
            "device_fingerprint": "dev-x",
            "expected_device_fingerprint": "dev-y",
            "token_issuer": "evil-proxy.local",
            "token_jti": "jti-1",
            "token_reuse": True,
            "timestamp": iso(now),
        },
        {
            "type": "siem_suspicious",
            "source": "edr",
            "indicator": "token_replay",
            "token_jti": "jti-1",
            "timestamp": iso(now + dt.timedelta(seconds=5)),
        },
    ]


@pytest.fixture
def consent_abuse_events() -> List[Dict[str, Any]]:
    now = dt.datetime.utcnow()
    return [
        {
            "type": "oauth_app_created",
            "app_id": "app-abc",
            "app_name": "Shady Mail Miner",
            "created_by": "service@tenant",
            "timestamp": iso(now),
        },
        {
            "type": "oauth_consent_granted",
            "app_id": "app-abc",
            "user_id": "user-999",
            "user_email": "eve@example.com",
            "scopes": ["Mail.ReadWrite", "offline_access", "Directory.ReadWrite.All"],
            "timestamp": iso(now + dt.timedelta(seconds=30)),
        },
        {
            "type": "api_activity",
            "app_id": "app-abc",
            "api_calls": [
                {"route": "/me/messages", "count": 2500},
                {"route": "/users", "count": 100},
            ],
            "anomalous": True,
            "timestamp": iso(now + dt.timedelta(minutes=2)),
        },
    ]


def _ingest(h, idp_events=None, siem_events=None):
    if idp_events is None:
        idp_events = []
    if siem_events is None:
        siem_events = []
    # The hunter may expose generic ingest; support common variants.
    if hasattr(h, "ingest_idp_events"):
        h.ingest_idp_events(idp_events)
    elif hasattr(h, "ingest_events"):
        h.ingest_events("idp", idp_events)
    else:
        h.ingest(idp_events)

    if hasattr(h, "ingest_siem_events"):
        h.ingest_siem_events(siem_events)
    elif hasattr(h, "ingest_events"):
        h.ingest_events("siem", siem_events)
    else:
        # optional
        pass


def _detect(h) -> List[Dict[str, Any]]:
    if hasattr(h, "detect"):
        return h.detect()
    elif hasattr(h, "run"):
        return h.run()
    return []


def _find_alert(alerts, type_key: str) -> Optional[Dict[str, Any]]:
    for a in alerts:
        t = a.get("type") or a.get("alert_type") or ""
        if t.lower() == type_key.lower():
            return a
    return None


def _has_localhost_only(calls: List[str]) -> bool:
    for url in calls:
        if not (url.startswith("http://127.0.0.1") or url.startswith("http://localhost") or url.startswith("https://127.0.0.1") or url.startswith("https://localhost")):
            return False
    return True


def _confidence_high(alert: Dict[str, Any]) -> bool:
    c = alert.get("confidence")
    if isinstance(c, str):
        return c.lower() in ("high", "very_high")
    if isinstance(c, (int, float)):
        return float(c) >= 0.8
    c2 = alert.get("confidence_score")
    if isinstance(c2, (int, float)):
        return float(c2) >= 0.8
    return False


def _ensure_signature_valid(h, item: Dict[str, Any]) -> bool:
    sig = item.get("signature") or item.get("signed_signature")
    if not isinstance(sig, str) or len(sig) < 40:
        return False
    if hasattr(h, "verify_signature"):
        try:
            return bool(h.verify_signature(item))
        except Exception:
            return False
    return True


def _get_audit_trail(h) -> List[Dict[str, Any]]:
    if hasattr(h, "get_audit_trail"):
        return h.get_audit_trail()
    if hasattr(h, "audit_trail"):
        return getattr(h, "audit_trail")
    return []


def _proposed_actions(alert: Dict[str, Any]) -> List[str]:
    actions = []
    pb = alert.get("proposed_playbook") or alert.get("proposed_playbooks") or alert.get("recommendations") or {}
    if isinstance(pb, dict):
        for k, v in pb.items():
            if isinstance(v, dict) and v.get("action"):
                actions.append(v["action"])
            else:
                actions.append(k)
    elif isinstance(pb, list):
        for v in pb:
            if isinstance(v, dict) and v.get("action"):
                actions.append(v["action"])
            elif isinstance(v, str):
                actions.append(v)
    elif isinstance(pb, str):
        actions.append(pb)
    return actions


def _has_field_encrypted(alert: Dict[str, Any], field: str, plaintext: Optional[str] = None) -> bool:
    # Accept either a separate encrypted_fields list or the field value being redacted/encrypted
    encrypted_fields = alert.get("encrypted_fields") or alert.get("encrypted") or []
    if isinstance(encrypted_fields, dict):
        encrypted_fields = list(encrypted_fields.keys())
    if field in encrypted_fields:
        return True
    if field in alert:
        val = alert.get(field)
        if isinstance(val, str):
            if "REDACTED" in val or val.startswith("ENC(") or "***" in val:
                return True
            if plaintext is not None and val != plaintext and len(val) > 8:
                # heuristically consider it encrypted if not equal
                return True
    # Might be nested
    fields = alert.get("fields") or {}
    if isinstance(fields, dict):
        if f"{field}_encrypted" in fields or field in (fields.get("encrypted_fields") or []):
            return True
    return False


def _alert_methods(alert: Dict[str, Any]) -> Dict[str, bool]:
    m = alert.get("methods") or {}
    out = {
        "deterministic": bool(m.get("deterministic", False) or alert.get("deterministic", False)),
        "ml_assist": bool(m.get("ml_assist", False) or alert.get("ml_assist_used", False)),
    }
    return out


def _get_rulepack_version(alert: Dict[str, Any]) -> Optional[str]:
    return alert.get("rulepack_version") or (alert.get("metadata") or {}).get("rulepack_version")


def _has_evidence_signatures(alert: Dict[str, Any]) -> bool:
    ev = alert.get("evidence") or {}
    if isinstance(ev, dict):
        if "signature" in ev or "evidence_signature" in ev:
            sig = ev.get("signature") or ev.get("evidence_signature")
            return isinstance(sig, str) and len(sig) >= 40
    if isinstance(ev, list):
        # if list, ensure each has signature
        for e in ev:
            sig = (e or {}).get("signature") or (e or {}).get("evidence_signature")
            if not isinstance(sig, str) or len(sig) < 40:
                return False
        return True
    return False


def _chain_ok(audit: List[Dict[str, Any]]) -> bool:
    if not audit:
        return True
    prev = None
    for entry in audit:
        if "prev_hash" in entry and prev is not None:
            if entry.get("prev_hash") != prev:
                return False
        if "hash" not in entry:
            return False
        prev = entry.get("hash")
    return True


def _prepare_events(h, *event_sets: List[Dict[str, Any]]):
    idp = []
    siem = []
    for evset in event_sets:
        for e in evset:
            if e.get("type", "").startswith("siem") or e.get("source") in ("edr", "siem") or e.get("type") == "api_activity":
                siem.append(e)
            else:
                idp.append(e)
    _ingest(h, idp, siem)


def test_mfa_fatigue_detection_and_playbook(hunter, mfa_fatigue_events):
    _prepare_events(hunter, mfa_fatigue_events)
    alerts = _detect(hunter)
    assert isinstance(alerts, list)
    alert = _find_alert(alerts, "MFA_FATIGUE") or _find_alert(alerts, "MFA Fatigue") or _find_alert(alerts, "mfa_fatigue")
    assert alert is not None, "Expected MFA fatigue alert"
    assert _confidence_high(alert), "Expected high-confidence MFA fatigue detection"
    # Proposed playbooks include step-up auth and session reset
    actions = _proposed_actions(alert)
    joined = " ".join(actions).lower()
    assert "step_up" in joined or "step-up" in joined or "step up" in joined, "Expected step-up auth in proposed actions"
    assert "session_reset" in joined or "session reset" in joined or "reset_session" in joined, "Expected session reset in proposed actions"
    # Rulepack version and signatures
    rp = _get_rulepack_version(alert)
    assert isinstance(rp, str) and is_semver(rp)
    assert _ensure_signature_valid(hunter, alert)
    # Ensure deterministic and possibly ML assist flags present
    methods = _alert_methods(alert)
    assert methods["deterministic"] is True
    # ML assist may be used optionally; if present ensure boolean
    assert isinstance(methods["ml_assist"], bool)


def test_aitm_detection_and_signed_containment_bundle(hunter, aitm_events):
    _prepare_events(hunter, aitm_events)
    alerts = _detect(hunter)
    alert = _find_alert(alerts, "AITM") or _find_alert(alerts, "AiTM") or _find_alert(alerts, "Adversary-in-the-Middle")
    assert alert is not None, "Expected AiTM alert"
    details = alert.get("details") or alert
    token_replay = details.get("token_replay") or details.get("suspected_token_replay")
    assert token_replay is True
    containment = alert.get("containment_bundle") or details.get("containment_bundle")
    assert isinstance(containment, dict), "Expected containment bundle for session revocation"
    action = containment.get("action") or containment.get("type")
    assert isinstance(action, str) and ("revocation" in action.lower() or "revoke" in action.lower())
    # Signed containment bundle
    signed = containment.get("signed") or False
    assert signed is True
    assert _ensure_signature_valid(hunter, containment)
    # Overall alert should be signed and versioned too
    assert _ensure_signature_valid(hunter, alert)
    rp = _get_rulepack_version(alert)
    assert isinstance(rp, str) and is_semver(rp)


def test_consent_abuse_detection_and_recommendations(hunter, consent_abuse_events):
    _prepare_events(hunter, consent_abuse_events)
    alerts = _detect(hunter)
    alert = _find_alert(alerts, "CONSENT_ABUSE") or _find_alert(alerts, "Consent Abuse")
    assert alert is not None, "Expected consent abuse alert"
    details = alert.get("details") or alert
    scopes = details.get("scopes") or details.get("risk_scopes") or []
    joined_scopes = " ".join(scopes).lower()
    assert "mail.readwrite" in joined_scopes
    assert "directory.readwrite.all" in joined_scopes
    consent_users = details.get("consent_user_count") or 1
    assert int(consent_users) == 1
    recs = alert.get("recommendations") or alert.get("proposed_playbooks") or {}
    # Admin review recommendation
    rec_text = str(recs).lower()
    assert "admin" in rec_text and "review" in rec_text
    # One-click quarantine recommended but requires approval if enabled
    assert ("quarantine" in rec_text) or any("quarantine" in str(x).lower() for x in _proposed_actions(alert))
    # Attempt to execute a quarantine action without enablement/approval should fail
    with pytest.raises(PermissionError):
        if hasattr(hunter, "response_action"):
            hunter.response_action(alert, action="quarantine_app", approve=False, approver=None)
        else:
            pytest.skip("Hunter lacks response_action method")
    # Enable response actions in policy; still require approval
    if hasattr(hunter, "set_policy"):
        hunter.set_policy({"response_actions_enabled": True, "require_human_approval": True})
    else:
        hunter.policy.update({"response_actions_enabled": True, "require_human_approval": True})
    with pytest.raises(PermissionError):
        if hasattr(hunter, "response_action"):
            hunter.response_action(alert, action="quarantine_app", approve=False, approver=None)
    # Now approve with a human
    if hasattr(hunter, "response_action"):
        res = hunter.response_action(alert, action="quarantine_app", approve=True, approver="analyst@example.com")
        assert isinstance(res, dict) and res.get("status") in ("ok", "success", "approved")
        audit = _get_audit_trail(hunter)
        assert any((e.get("action") == "quarantine_app" and e.get("approved_by") == "analyst@example.com") for e in audit)
        assert _chain_ok(audit)


def test_pii_minimization_and_field_level_encryption(hunter, mfa_fatigue_events):
    _prepare_events(hunter, mfa_fatigue_events)
    alerts = _detect(hunter)
    alert = _find_alert(alerts, "MFA_FATIGUE")
    assert alert is not None
    # Sensitive attributes should be minimized/encrypted
    # user_email should be redacted or encrypted
    # Since we know plaintext, ensure it's not present as-is
    if "user_email" in alert:
        val = alert.get("user_email")
        assert isinstance(val, str)
        assert val != "alice@example.com"
        assert ("***" in val) or ("REDACTED" in val) or val.startswith("ENC(")
    assert _has_field_encrypted(alert, "user_email", "alice@example.com")
    # ip_address field-level encryption/redaction
    assert _has_field_encrypted(alert, "ip_address", "127.0.0.1")
    # device_fingerprint encryption
    assert _has_field_encrypted(alert, "device_fingerprint", "dev-zzz")
    # Retention/access controls: direct access to raw PII should be denied
    if hasattr(hunter, "access_raw_pii"):
        with pytest.raises(PermissionError):
            hunter.access_raw_pii("user_email", subject="user-123")


def test_versioned_rulepacks_and_signed_evidence(hunter, aitm_events, consent_abuse_events):
    _prepare_events(hunter, aitm_events, consent_abuse_events)
    alerts = _detect(hunter)
    assert alerts, "Expected some alerts"
    for alert in alerts:
        # Rulepack version is semver
        rp = _get_rulepack_version(alert)
        assert isinstance(rp, str) and is_semver(rp)
        # Methods
        methods = _alert_methods(alert)
        assert methods["deterministic"] is True
        assert isinstance(methods["ml_assist"], bool)
        # Signed detections and evidence
        assert _ensure_signature_valid(hunter, alert)
        assert _has_evidence_signatures(alert)


def test_empty_and_malformed_events_error_handling(hunter):
    # Empty events should result in no alerts
    _ingest(hunter, [], [])
    alerts = _detect(hunter)
    assert isinstance(alerts, list)
    assert len(alerts) == 0
    # Malformed events should be skipped, not crash
    malformed = [
        {"type": "mfa_challenge", "timestamp": "not-a-time"},  # bad timestamp
        {"type": "signin"},  # missing fields
        {"no_type": True},  # missing type
        None,  # completely invalid
    ]
    _ingest(hunter, malformed, [])
    alerts2 = _detect(hunter)
    assert isinstance(alerts2, list)  # may or may not have alerts, but should not crash
    audit = _get_audit_trail(hunter)
    # Expect at least one error logged about malformed events
    assert any("error" in (e.get("level") or "").lower() or "malformed" in str(e).lower() for e in audit)


def test_no_external_network_calls_during_detection(monkeypatch, hunter, mfa_fatigue_events, aitm_events, consent_abuse_events):
    # Intercept any requests made by the module to ensure localhost-only and no real network calls
    calls = []

    class DummyResp:
        def __init__(self):
            self.status_code = 200

        def json(self):
            return {"ok": True}

        @property
        def text(self):
            return "ok"

    def fake_request(self, method, url, *args, **kwargs):
        calls.append(url)
        # Allow only localhost
        assert url.startswith("http://127.0.0.1") or url.startswith("https://127.0.0.1") or url.startswith("http://localhost") or url.startswith("https://localhost")
        return DummyResp()

    # Try to patch requests in the module if present
    try:
        import tools.threat_hunting.idp_attack_pattern_hunter as mod  # type: ignore
        import requests  # type: ignore

        if hasattr(mod, "requests"):
            monkeypatch.setattr(mod.requests.Session, "request", fake_request, raising=True)
        else:
            # Patch global requests as fallback
            monkeypatch.setattr(requests.Session, "request", fake_request, raising=True)
    except Exception:
        # If requests isn't used by the module, continue without patching
        pass

    _prepare_events(hunter, mfa_fatigue_events, aitm_events, consent_abuse_events)
    alerts = _detect(hunter)
    assert isinstance(alerts, list)
    # If any network calls were made, ensure only localhost
    if calls:
        assert _has_localhost_only(calls)


def test_tamper_evident_logging(hunter, mfa_fatigue_events):
    _prepare_events(hunter, mfa_fatigue_events)
    _ = _detect(hunter)
    audit = _get_audit_trail(hunter)
    # Tamper-evident fields present and chain consistent
    assert isinstance(audit, list)
    assert _chain_ok(audit)
    # If module exposes a verifier, use it
    if hasattr(hunter, "verify_audit_log_chain"):
        assert hunter.verify_audit_log_chain(audit) is True
    # Ensure entries contain timestamps and actions or events
    assert all(e.get("timestamp") for e in audit)
    assert any(e.get("action") or e.get("event") for e in audit)