import pytest

from tools.iot.lpwan_guard import LPWANGuard, SafetyError


class MockTSA:
    def __init__(self):
        self.requests = []

    def timestamp(self, digest: bytes):
        # Simulate a trusted timestamp response
        self.requests.append(digest)
        return {
            "tsa": "mock-tsa",
            "ts": "2025-01-01T00:00:00Z",
            "digest": digest.hex(),
            "trusted": True,
        }


class MockTransmitter:
    def __init__(self):
        self.sent = []
        self.calls = 0

    def send(self, *, freq_hz: int, power_dbm: int, duty_cycle: float, payload: bytes, target: str = "127.0.0.1"):
        # Enforce localhost only
        assert target in ("127.0.0.1", "localhost")
        self.calls += 1
        self.sent.append(
            {
                "freq_hz": freq_hz,
                "power_dbm": power_dbm,
                "duty_cycle": duty_cycle,
                "payload": payload,
                "target": target,
            }
        )
        return {"status": "queued"}


@pytest.fixture
def guard_with_mocks():
    tsa = MockTSA()
    tx = MockTransmitter()
    guard = LPWANGuard(tsa=tsa, transmitter=tx)
    return guard, tsa, tx


def serialize_report(report):
    # Helper to allow both dict-like and object-like report
    try:
        return str(report)
    except Exception:
        return repr(report)


def extract_findings(report):
    # Support dict or object with attribute
    if isinstance(report, dict):
        return report.get("findings", [])
    if hasattr(report, "findings"):
        return getattr(report, "findings")
    return []


def extract_evidence(report):
    # Support dict or object with attribute
    if isinstance(report, dict):
        return report.get("evidence_bundle") or report.get("evidence") or report.get("bundle")
    if hasattr(report, "evidence_bundle"):
        return getattr(report, "evidence_bundle")
    if hasattr(report, "evidence"):
        return getattr(report, "evidence")
    if hasattr(report, "bundle"):
        return getattr(report, "bundle")
    return None


def get_safety_log(guard):
    if hasattr(guard, "get_safety_log"):
        return guard.get_safety_log()
    if hasattr(guard, "safety_log"):
        return getattr(guard, "safety_log")
    return []


def is_sealed(evidence):
    if evidence is None:
        return False
    if hasattr(evidence, "sealed"):
        return bool(getattr(evidence, "sealed"))
    # fall back to presence of typical fields
    has_chain = hasattr(evidence, "hash_chain") or (isinstance(evidence, dict) and "hash_chain" in evidence)
    has_ts = hasattr(evidence, "trusted_timestamp") or (isinstance(evidence, dict) and "trusted_timestamp" in evidence)
    return has_chain and has_ts


def evidence_verify(evidence):
    if evidence is None:
        return False
    if hasattr(evidence, "verify"):
        return bool(evidence.verify())
    # If no verify method, ensure it carries a trusted timestamp marker
    if isinstance(evidence, dict):
        ts = evidence.get("trusted_timestamp")
        return bool(ts and (ts.get("trusted") or ts.get("tsa")))
    if hasattr(evidence, "trusted_timestamp"):
        ts = getattr(evidence, "trusted_timestamp")
        return hasattr(ts, "trusted") or hasattr(ts, "tsa")
    return False


def redact_default(text, secret):
    return secret not in text


def test_replay_risk_flagged_and_evidence_sealed(guard_with_mocks):
    guard, tsa, _ = guard_with_mocks

    # Two OTAA join requests with the same DevNonce for the same DevEUI
    frames = [
        {
            "type": "join_request",
            "DevEUI": "A1B2C3D4E5F60708",
            "AppEUI": "0102030405060708",
            "DevNonce": "0001",
            "frame_id": "f1",
            "timestamp": 1000.0,
        },
        {
            "type": "join_request",
            "DevEUI": "A1B2C3D4E5F60708",
            "AppEUI": "0102030405060708",
            "DevNonce": "0001",  # repeated
            "frame_id": "f2",
            "timestamp": 1010.0,
        },
        # Include another device to ensure per-device analysis
        {
            "type": "join_request",
            "DevEUI": "DEADBEEF00112233",
            "AppEUI": "AABBCCDDEEFF0011",
            "DevNonce": "0001",
            "frame_id": "f3",
            "timestamp": 1020.0,
        },
    ]

    report = guard.audit(frames, mode="passive")  # must default to passive RF monitoring

    # Ensure TSA was used to seal evidence
    assert len(tsa.requests) >= 1

    findings = extract_findings(report)
    assert any(f.get("code") == "REPLAY_RISK" for f in findings), "Expected REPLAY_RISK finding"

    # Check that the finding references supporting frames
    rr = [f for f in findings if f.get("code") == "REPLAY_RISK"][0]
    refs = rr.get("evidence_refs") or rr.get("supporting_frames") or []
    assert "f1" in refs and "f2" in refs

    # Evidence bundle is sealed with hash chain and trusted timestamp
    bundle = extract_evidence(report)
    assert is_sealed(bundle), "Evidence bundle should be sealed"
    assert evidence_verify(bundle) is True

    # Redaction: DevEUI/AppEUI must be redacted by default in outputs
    s = serialize_report(report)
    assert redact_default(s, "A1B2C3D4E5F60708"), "DevEUI should be redacted by default"
    assert redact_default(s, "0102030405060708"), "AppEUI should be redacted by default"


def test_abp_default_keys_recommendations_include_otaa_rotation(guard_with_mocks):
    guard, _, _ = guard_with_mocks

    # Provide an inventory that marks one ABP device as using default/known keys
    inventory = {
        "abp_devices": [
            {
                "DevAddr": "26011BDA",
                "DevEUI": "1122334455667788",
                "NwkSKey": "00000000000000000000000000000000",
                "AppSKey": "00000000000000000000000000000000",
                "default": True,
            }
        ],
        "otaa_devices": [],
    }
    guard.load_inventory(inventory)

    frames = [
        {"type": "data_uplink", "DevAddr": "26011BDA", "FCnt": 1, "frame_id": "u1", "timestamp": 2000.0},
    ]

    report = guard.audit(frames, mode="passive")

    findings = extract_findings(report)
    # Identify ABP with default known keys
    assert any(
        f.get("code") in ("ABP_DEFAULT_KEYS", "DEFAULT_KEYS") and f.get("DevAddr") == "26011BDA" for f in findings
    )

    # The tool should recommend OTAA migration and key rotation with concrete steps
    recommendations = " ".join(f.get("recommendation", "") for f in findings)
    details = " ".join(f.get("details", "") for f in findings)
    text = (recommendations + " " + details).lower()
    assert "otaa" in text, "Recommendation should mention OTAA migration"
    assert "key rotation" in text or "rotate key" in text, "Recommendation should mention key rotation"
    # Check that some actionable phrasing exists
    assert any(k in text for k in ("step", "configure", "migrate", "rotate", "disable abp"))

    # Ensure redaction by default (DevEUI should not be present in plain text)
    s = serialize_report(report)
    assert "1122334455667788" not in s


def test_attempt_active_transmission_without_lab_mode_refused_and_logged(guard_with_mocks):
    guard, _, tx = guard_with_mocks

    # No lab mode configured yet
    with pytest.raises(SafetyError) as ei:
        guard.active_transmit(payload=b"\x01\x02", freq_hz=868100000, power_dbm=14, target="127.0.0.1")

    # Tool refuses to transmit
    assert tx.calls == 0 and len(tx.sent) == 0

    # Safety error includes LAB_MODE_REQUIRED
    assert "LAB_MODE_REQUIRED" in str(ei.value)

    # And it is recorded in the safety log
    log = get_safety_log(guard)
    assert any(entry.get("code") == "LAB_MODE_REQUIRED" for entry in log)


def test_lab_mode_enables_active_transmission_with_limits(guard_with_mocks):
    guard, _, tx = guard_with_mocks

    # Configure lab mode with required parameters
    guard.enable_lab_mode(duty_cycle=0.01, frequency_plan="EU868", power_limit_dbm=14)

    # Now active transmission should be allowed
    resp = guard.active_transmit(payload=b"\xAA\xBB", freq_hz=868100000, power_dbm=14, target="127.0.0.1")
    assert isinstance(resp, dict)

    # Ensure transmitter was called exactly once
    assert tx.calls == 1 and len(tx.sent) == 1

    sent = tx.sent[0]
    assert sent["freq_hz"] == 868100000
    assert sent["power_dbm"] <= 14  # power limit enforced
    assert sent["duty_cycle"] <= 0.01
    assert sent["target"] in ("127.0.0.1", "localhost")


def test_identifiers_redacted_by_default_and_can_be_disabled(guard_with_mocks):
    guard, _, _ = guard_with_mocks

    frames = [
        {
            "type": "join_request",
            "DevEUI": "CAFEBABECAFEBABE",
            "AppEUI": "F00DF00DF00DF00D",
            "DevNonce": "0002",
            "frame_id": "j1",
            "timestamp": 3000.0,
        },
    ]

    # Default should redact identifiers
    report = guard.audit(frames, mode="passive")
    s = serialize_report(report)
    assert "CAFEBABECAFEBABE" not in s
    assert "F00DF00DF00DF00D" not in s

    # Disable redaction and check identifiers appear
    guard.set_redaction(False)
    report2 = guard.audit(frames, mode="passive")
    s2 = serialize_report(report2)
    assert "CAFEBABECAFEBABE" in s2
    assert "F00DF00DF00DF00D" in s2


def test_evidence_bundle_includes_hash_chain_and_trusted_timestamp(guard_with_mocks):
    guard, tsa, _ = guard_with_mocks

    frames = [
        {
            "type": "join_request",
            "DevEUI": "0101010101010101",
            "AppEUI": "0202020202020202",
            "DevNonce": "0003",
            "frame_id": "jj1",
            "timestamp": 4000.0,
        },
        {
            "type": "join_accept",
            "DevEUI": "0101010101010101",
            "frame_id": "ja1",
            "timestamp": 4001.0,
        },
    ]

    report = guard.audit(frames, mode="passive")
    bundle = extract_evidence(report)

    # Evidence shows sealing artifacts
    # Hash chain presence
    has_chain = False
    if hasattr(bundle, "hash_chain"):
        chain = getattr(bundle, "hash_chain")
        has_chain = bool(chain)
    elif isinstance(bundle, dict) and "hash_chain" in bundle:
        has_chain = bool(bundle["hash_chain"])
    assert has_chain, "Evidence bundle must include a hash chain"

    # Trusted timestamp with TSA
    ts_obj = None
    if hasattr(bundle, "trusted_timestamp"):
        ts_obj = getattr(bundle, "trusted_timestamp")
    elif isinstance(bundle, dict):
        ts_obj = bundle.get("trusted_timestamp")

    assert ts_obj, "Evidence bundle must have a trusted timestamp"
    if isinstance(ts_obj, dict):
        assert ts_obj.get("tsa") == "mock-tsa"
        assert ts_obj.get("trusted") is True or "ts" in ts_obj

    # Verify integrity via provided API
    assert evidence_verify(bundle) is True

    # Tamper with bundle content if accessible and ensure verification fails
    tamper_possible = False
    if isinstance(bundle, dict) and "items" in bundle:
        bundle["items"].append({"frame_id": "tamper"})
        tamper_possible = True
    elif hasattr(bundle, "items"):
        try:
            items = getattr(bundle, "items")
            if isinstance(items, list):
                items.append({"frame_id": "tamper"})
                tamper_possible = True
        except Exception:
            tamper_possible = False

    if tamper_possible and hasattr(bundle, "verify"):
        assert bundle.verify() is False, "Tampering should break evidence verification"