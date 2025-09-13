import pytest
from unittest.mock import MagicMock, call
from datetime import datetime, timedelta
import hashlib

from tools.mobile.baseband_esim_auditor import BasebandESimAuditor, RateLimitError


class FakeDevice:
    def __init__(self, device_id="dev-1", imsi="310150123456789", platform="android"):
        self.id = device_id
        self.imsi = imsi
        self.platform = platform


class FakeTelemetryLogger:
    def __init__(self):
        self.events = []

    def log_event(self, event_type, metadata):
        # Must not contain payload data in production
        if metadata.get("mode") == "production":
            assert "payload" not in metadata
        # Mark it as forensically sound and signed
        metadata["forensically_sound"] = True
        metadata["signed"] = True
        metadata["logged_at"] = datetime.utcnow().isoformat() + "Z"
        event_id = f"evt-{len(self.events)+1}"
        self.events.append({"id": event_id, "type": event_type, "metadata": metadata})
        return event_id


@pytest.fixture
def fake_signer():
    def _sign(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
    return _sign


@pytest.fixture
def telemetry_logger():
    return FakeTelemetryLogger()


@pytest.fixture
def auditor_lab(telemetry_logger, fake_signer):
    # Lab mode auditor
    return BasebandESimAuditor(
        mode="lab",
        telemetry_logger=telemetry_logger,
        signer=fake_signer,
        rate_limit_per_minute=2,
        lab_only_endpoint="http://127.0.0.1"
    )


@pytest.fixture
def auditor_prod(telemetry_logger, fake_signer):
    # Production mode auditor
    return BasebandESimAuditor(
        mode="production",
        telemetry_logger=telemetry_logger,
        signer=fake_signer,
        rate_limit_per_minute=2,
        lab_only_endpoint="http://127.0.0.1"
    )


def test_wap_push_acceptance_detection_and_sealed_evidence(auditor_lab, monkeypatch):
    device = FakeDevice()
    dest_urls = []

    # Ensure emulation uses localhost and isolated test IMSI, and simulate acceptance without consent
    def fake_send_wap_push(*args, **kwargs):
        url = kwargs.get("url") or (args[1] if len(args) > 1 else "http://127.0.0.1/wap")
        imsi = kwargs.get("test_imsi") or kwargs.get("imsi") or (args[2] if len(args) > 2 else None)
        consent = kwargs.get("consent", False)
        dest_urls.append(url)
        assert url.startswith("http://127.0.0.1")
        # Must never use the real device IMSI in lab simulation
        assert imsi is not None and imsi != device.imsi
        assert imsi.startswith("999") or imsi.startswith("001")  # isolated/lab test ranges
        # Simulate device accepts without user consent
        return {"accepted": True, "user_prompted": False, "used_imsi": imsi, "url": url, "consent": consent}

    monkeypatch.setattr(auditor_lab, "_send_wap_push", fake_send_wap_push, raising=False)

    result = auditor_lab.audit_wap_push_handling(device)

    # Device accepting WAP Push without user consent is detected
    assert result.get("accepted_without_user_consent") is True

    # Recommend MDM/carrier configuration remediation
    recommendation = result.get("recommendation", "")
    assert isinstance(recommendation, str) and recommendation
    assert "MDM" in recommendation or "Mobile Device Management" in recommendation
    assert "carrier" in recommendation.lower()
    assert "remediation" in recommendation.lower() or "harden" in recommendation.lower()

    # Sealed evidence record with cryptographic seal and timestamp
    evidence = result.get("evidence", {})
    assert evidence.get("sealed") is True
    assert "timestamp" in evidence and isinstance(evidence["timestamp"], str)
    assert "signature" in evidence and evidence["signature"]
    assert "hash" in evidence and evidence["hash"]
    assert auditor_lab.verify_seal(evidence) is True

    # Ensure only lab endpoint was used
    assert all(u.startswith("http://127.0.0.1") for u in dest_urls)


def test_mdm_profile_silent_flash_sms_flagged_with_baseline_and_validation_script(auditor_prod, monkeypatch):
    # MDM profile permitting silent/flash SMS should be flagged and provide hardening with validation script
    mdm_profile = {
        "id": "profile-1",
        "allow_flash_sms": True,
        "allow_silent_sms": True,
        "name": "Test Profile"
    }

    # Ensure the auditor will not attempt to apply changes in production
    applied = {"called": False}

    def forbid_apply(*args, **kwargs):  # should never be called
        applied["called"] = True
        raise AssertionError("Should not apply MDM changes in production")

    monkeypatch.setattr(auditor_prod, "apply_mdm_hardening", forbid_apply, raising=False)

    finding = auditor_prod.audit_mdm_profile(mdm_profile)

    # Verify issue is flagged
    issue = finding.get("issue", "")
    assert isinstance(issue, str) and issue
    assert "silent" in issue.lower() or "class 0" in issue.lower() or "flash" in issue.lower()

    # Hardening baseline and validation script present
    baseline = finding.get("hardening_baseline")
    script = finding.get("validation_script")
    assert baseline and isinstance(baseline, (dict, str))
    assert script and isinstance(script, str)
    assert "enforce" in script.lower() or "validate" in script.lower()

    # Evidence is sealed
    evidence = finding.get("evidence", {})
    assert evidence.get("sealed") is True
    assert "signature" in evidence and auditor_prod.verify_seal(evidence) is True

    # No application of settings in production
    assert applied["called"] is False


def test_canary_class0_sms_blocked_and_logged_with_signed_telemetry(auditor_prod, telemetry_logger, monkeypatch):
    device = FakeDevice()
    send_called = {"called": False}

    def forbid_send_sms(*args, **kwargs):
        send_called["called"] = True
        raise AssertionError("Should not send canary Class 0 SMS in production")

    monkeypatch.setattr(auditor_prod, "_send_sms", forbid_send_sms, raising=False)

    res = auditor_prod.send_canary_class0_sms(device=device, payload="CANARY", consent=False)

    # Blocked in production, with no user-visible disruption
    assert res.get("blocked") is True
    assert res.get("no_user_visible_disruption") is True

    # Telemetry logged with signed, forensically sound metadata only (no payload)
    event_id = res.get("logged_event_id")
    assert event_id is not None
    assert len(telemetry_logger.events) >= 1
    evt = next(e for e in telemetry_logger.events if e["id"] == event_id)
    meta = evt["metadata"]
    assert meta.get("forensically_sound") is True
    assert meta.get("signed") is True
    assert "payload" not in meta
    assert meta.get("mode") == "production"

    # Ensure no SMS was actually attempted to be sent
    assert send_called["called"] is False


def test_rate_limiting_enforced_on_radio_interactions(auditor_lab, monkeypatch):
    device = FakeDevice()

    # Stub out actual radio interaction
    monkeypatch.setattr(auditor_lab, "_send_wap_push", lambda *a, **k: {"accepted": False, "user_prompted": True}, raising=False)

    # First two calls okay (rate_limit_per_minute=2 in fixture)
    auditor_lab.audit_wap_push_handling(device)
    auditor_lab.audit_wap_push_handling(device)

    # Third call within the same window should raise RateLimitError
    with pytest.raises(RateLimitError):
        auditor_lab.audit_wap_push_handling(device)


def test_lab_mode_requires_explicit_consent_for_payload_collection(auditor_lab, monkeypatch):
    device = FakeDevice()

    # Fake handler returns both metadata and payload if allowed
    def fake_send_wap_push(*args, **kwargs):
        consent = kwargs.get("consent", False)
        # payload present only with explicit consent in lab
        return {
            "accepted": True,
            "user_prompted": False,
            "metadata": {"wap_type": "si", "url": kwargs.get("url", "http://127.0.0.1/wap")},
            "payload": b"FAKE_WAP_PUSH" if consent else None
        }

    monkeypatch.setattr(auditor_lab, "_send_wap_push", fake_send_wap_push, raising=False)

    # Without consent: payload must not be captured
    res_no_consent = auditor_lab.emulate_wap_push(device=device, url="http://127.0.0.1/wappush", consent=False)
    assert res_no_consent.get("captured_payload") in (None, b"", "")
    assert res_no_consent.get("metadata_only") is True

    # With consent: payload may be captured in lab
    res_with_consent = auditor_lab.emulate_wap_push(device=device, url="http://127.0.0.1/wappush", consent=True)
    assert res_with_consent.get("captured_payload") in (b"FAKE_WAP_PUSH", "FAKE_WAP_PUSH")
    assert res_with_consent.get("metadata_only") is False


def test_emulation_uses_isolated_test_imsi_and_localhost(auditor_lab, monkeypatch):
    device = FakeDevice(imsi="310260123456789")
    capture = {"used_imsi": None, "url": None}

    def fake_send_wap_push(*args, **kwargs):
        url = kwargs.get("url", "http://127.0.0.1/wappush")
        imsi = kwargs.get("test_imsi") or "999010000000000"
        capture["url"] = url
        capture["used_imsi"] = imsi
        return {"accepted": False, "user_prompted": True}

    monkeypatch.setattr(auditor_lab, "_send_wap_push", fake_send_wap_push, raising=False)

    auditor_lab.emulate_wap_push(device=device, url="http://127.0.0.1/wappush", consent=False)

    assert capture["url"].startswith("http://127.0.0.1")
    assert capture["used_imsi"] != device.imsi
    assert capture["used_imsi"].startswith(("999", "001"))


def test_production_mode_disallows_lab_only_simulation(auditor_prod):
    device = FakeDevice()
    # Lab-only emulation should not be allowed in production mode
    with pytest.raises(PermissionError):
        auditor_prod.emulate_wap_push(device=device, url="http://127.0.0.1/wappush", consent=False)


def test_mdm_api_failure_is_handled_with_sealed_error_record(auditor_prod, monkeypatch):
    # Simulate an MDM API error during profile audit
    def broken_audit(*args, **kwargs):
        raise RuntimeError("MDM API unreachable")

    monkeypatch.setattr(auditor_prod, "_evaluate_mdm_profile", broken_audit, raising=False)

    finding = auditor_prod.audit_mdm_profile({"id": "bad"})

    assert finding.get("status") in ("error", "failed")
    assert "MDM API unreachable" in finding.get("error", "")
    evidence = finding.get("evidence", {})
    assert evidence.get("sealed") is True
    assert "signature" in evidence and auditor_prod.verify_seal(evidence) is True


def test_never_alter_carrier_settings_in_production(auditor_prod, monkeypatch):
    # Ensure any carrier settings changes are not executed in production
    called = {"carrier_change": False}

    def forbid_carrier_change(*args, **kwargs):
        called["carrier_change"] = True
        raise AssertionError("Must not alter carrier settings in production")

    # Patch any potential mutating methods
    monkeypatch.setattr(auditor_prod, "apply_carrier_settings", forbid_carrier_change, raising=False)
    monkeypatch.setattr(auditor_prod, "push_carrier_config", forbid_carrier_change, raising=False)

    device = FakeDevice()
    # Run a generic audit routine that might propose changes; ensure none executed
    res = auditor_prod.audit_device_configuration(device)

    assert res is not None
    assert called["carrier_change"] is False


def test_production_captures_only_metadata_for_wap_push_assessment(auditor_prod, monkeypatch):
    device = FakeDevice()

    # Although production should not emulate, internal assessment routines must capture only metadata
    # Stub assessment to return payload but tool should strip it in production
    def fake_assess(*args, **kwargs):
        return {
            "accepted": True,
            "user_prompted": False,
            "metadata": {"wap": "si"},
            "payload": b"SENSITIVE"
        }

    monkeypatch.setattr(auditor_prod, "_assess_wap_push_noninvasive", fake_assess, raising=False)

    res = auditor_prod.audit_wap_push_handling(device)

    assert res.get("accepted_without_user_consent") in (True, False)
    # No payload in production
    assert res.get("captured_payload") in (None, "", b"")
    # Evidence must be sealed with timestamp
    evidence = res.get("evidence", {})
    assert evidence.get("sealed") is True and "timestamp" in evidence
    assert auditor_prod.verify_seal(evidence) is True


def test_edge_case_invalid_mdm_profile_input(auditor_lab):
    # Invalid MDM profile schema should raise ValueError
    with pytest.raises(ValueError):
        auditor_lab.audit_mdm_profile(["not", "a", "dict"])