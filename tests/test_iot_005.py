import io
import json
import os
import re
import socket
import time
from typing import List, Dict, Any

import pytest

from tools.iot.edgevision_guard import EdgeVisionGuard, ConsentRequiredError, EvidenceIntegrityError, FirmwareParseError


class FakeCVEFeed:
    def __init__(self, mapping: Dict[tuple, List[Dict[str, Any]]]):
        self.mapping = mapping

    def lookup(self, name: str, version: str) -> List[Dict[str, Any]]:
        return self.mapping.get((name.lower(), version), [])


class DummyBackdooredModel:
    # Returns 'person' with high confidence if TRIGGER token present, else 'car'
    def predict(self, inp: Any) -> Dict[str, Any]:
        data = inp if isinstance(inp, str) else str(inp)
        if "TRIGGER" in data:
            return {"label": "person", "confidence": 0.99}
        return {"label": "car", "confidence": 0.90}


class DummyBenignModel:
    def predict(self, inp: Any) -> Dict[str, Any]:
        return {"label": "car", "confidence": 0.90}


@pytest.fixture
def fake_firmware_file(tmp_path):
    fw = tmp_path / "firmware.bin"
    # Embed some parsable strings for SBOM and credentials
    content = b"""
    BusyBox v1.31.0 (multi-call binary)
    OpenSSL libssl.so.1.0.2
    username=admin
    password=admin123
    RTSP://127.0.0.2/stream
    """
    fw.write_bytes(content)
    return fw


@pytest.fixture
def fake_cve_feed():
    mapping = {
        ("busybox", "1.31.0"): [
            {"id": "CVE-2020-0001", "severity": "MEDIUM", "summary": "BusyBox issue"}
        ],
        ("openssl", "1.0.2"): [
            {
                "id": "CVE-2016-0800",
                "severity": "HIGH",
                "summary": "DROWN vulnerability",
                "recommendation": "Upgrade to >=1.1.1",
            }
        ],
    }
    return FakeCVEFeed(mapping)


@pytest.fixture
def dummy_artifacts(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")  # pcap magic
    model_stats = tmp_path / "model_stats.json"
    model_stats.write_text(json.dumps({"accuracy": 0.95, "notes": "contains email john.doe@example.com"}))
    screenshot = tmp_path / "screenshot.png"
    screenshot.write_bytes(b"\x89PNG\r\n\x1a\nMASKME")  # fake png
    return [str(pcap), str(model_stats), str(screenshot)]


def test_extract_sbom_cves_and_credentials_with_mitigations(tmp_path, fake_firmware_file, fake_cve_feed, monkeypatch):
    # Ensure no external network calls occur
    orig_socket = socket.socket

    def forbid_socket(*args, **kwargs):
        raise AssertionError("External socket operations must be mocked")

    monkeypatch.setattr(socket, "socket", forbid_socket)

    guard = EdgeVisionGuard()
    sandbox_profile = {"segments": ["lan", "mgmt", "wan"], "rate_limit_per_sec": 5}

    result = guard.analyze_firmware(
        firmware_image=str(fake_firmware_file),
        cve_feed=fake_cve_feed,
        sandbox_profile=sandbox_profile,
    )
    assert isinstance(result, dict)
    # SBOM should include BusyBox 1.31.0 and OpenSSL 1.0.2
    names = {(c.get("name", "").lower(), c.get("version")) for c in result.get("sbom", [])}
    assert ("busybox", "1.31.0") in names
    assert ("openssl", "1.0.2") in names

    # Correlate to CVEs via provided feed
    cves = result.get("cves", {})
    assert any(cve["id"] == "CVE-2016-0800" for cve in cves.get("openssl@1.0.2", []))

    # Flag hardcoded credentials
    creds = result.get("credentials", [])
    assert any(c.get("username") == "admin" for c in creds)
    assert any("hardcoded credentials" in m.lower() for m in result.get("mitigations", []))
    # Recommended mitigation for OpenSSL
    assert any("upgrade" in m.lower() and "1.1.1" in m for m in result.get("mitigations", []))

    # Sandbox microsegmentation and rate limit enforcement
    sandbox_info = result.get("sandbox", {})
    assert set(sandbox_info.get("segments", [])) == set(sandbox_profile["segments"])
    assert sandbox_info.get("rate_limit_per_sec") == sandbox_profile["rate_limit_per_sec"]
    assert sandbox_info.get("rate_enforced") is True

    # Provide fuzz metrics if available
    metrics = result.get("sandbox_metrics", {})
    if "fuzz_events_per_sec" in metrics:
        assert metrics["fuzz_events_per_sec"] <= sandbox_profile["rate_limit_per_sec"]


def test_analyze_firmware_invalid_image_raises(tmp_path):
    guard = EdgeVisionGuard()
    bad_fw = tmp_path / "bad_firmware.img"
    bad_fw.write_bytes(b"\x00\x01\x02")  # nonsensical content

    with pytest.raises(FirmwareParseError):
        guard.analyze_firmware(str(bad_fw), cve_feed=None, sandbox_profile={"segments": [], "rate_limit_per_sec": 1})


def test_evidence_bundle_creation_verification_and_reproducibility(tmp_path, dummy_artifacts):
    guard = EdgeVisionGuard()

    metadata = {
        "chain_of_custody": {
            "operator": "alice",
            "timestamp": "2025-01-01T00:00:00Z",
            "purpose": "unit test",
        },
        "notes": "PII should be masked in artifacts",
    }
    bundle1 = guard.create_evidence_bundle(artifacts=dummy_artifacts, metadata=metadata)
    assert isinstance(bundle1, dict)
    assert os.path.exists(bundle1["path"])
    assert isinstance(bundle1.get("hash"), str) and len(bundle1["hash"]) >= 32
    assert isinstance(bundle1.get("signature"), str) and len(bundle1["signature"]) >= 32
    assert "chain_of_custody" in bundle1.get("metadata", {})
    # Verify signature/hash
    assert guard.verify_evidence_bundle(bundle1["path"]) is True

    # Reproducible hash with same inputs
    bundle2 = guard.create_evidence_bundle(artifacts=dummy_artifacts, metadata=metadata)
    assert bundle1["hash"] == bundle2["hash"]

    # Tamper with an artifact and expect verification to fail
    with open(dummy_artifacts[0], "ab") as f:
        f.write(b"\x00TAMPER")
    with pytest.raises(EvidenceIntegrityError):
        assert guard.verify_evidence_bundle(bundle1["path"]) is False


def test_privacy_masking_in_logs():
    guard = EdgeVisionGuard()
    log = "User john.doe@example.com accessed from 192.168.1.50, SSN 123-45-6789, Phone +1-202-555-0168"
    masked = guard.mask_pii(log)
    assert isinstance(masked, str)
    # Emails masked
    assert "john.doe@example.com" not in masked
    # IP masked
    assert "192.168.1.50" not in masked
    # SSN masked
    assert "123-45-6789" not in masked
    # Phone masked
    assert "202-555-0168" not in masked
    # Ensure some redaction marker present
    assert re.search(r"\[REDACTED|\*{3,}|MASKED\]", masked) or "REDACTED" in masked.upper()


def test_model_backdoor_detection_with_saliency_and_confidence_shift(tmp_path):
    guard = EdgeVisionGuard()
    model = DummyBackdooredModel()
    dataset = [
        {"input": "car", "label": "car"},
        {"input": "TRIGGER car", "label": "car"},
        {"input": "car", "label": "car"},
        {"input": "TRIGGER bicycle", "label": "bicycle"},
    ]
    sandbox_profile = {"segments": ["ml", "storage"], "rate_limit_per_sec": 8}
    result = guard.analyze_model(
        model=model,
        dataset=dataset,
        sandbox_profile=sandbox_profile,
        consent=True,
        live_device=False,
    )
    assert isinstance(result, dict)
    assert result.get("backdoor_detected") is True
    saliency = result.get("trigger_saliency")
    assert saliency is not None
    # Saliency should reference the trigger; representation can vary (list, heatmap, etc.)
    # We assert it has non-zero size or includes 'trigger' keyword
    if isinstance(saliency, (list, tuple)):
        assert len(saliency) > 0
    elif isinstance(saliency, dict):
        assert saliency
    elif isinstance(saliency, str):
        assert "trigger" in saliency.lower()
    # Confidence shift report should indicate a significant shift
    conf = result.get("confidence_shift", {})
    assert conf
    mean_shift = conf.get("mean_shift") or conf.get("avg_shift") or conf.get("delta")
    assert mean_shift is not None and mean_shift > 0.05
    # Sandbox rate limit applied
    sbx = result.get("sandbox", {})
    assert sbx.get("rate_limit_per_sec") == 8
    assert sbx.get("rate_enforced") is True


def test_model_analysis_without_consent_when_live_device_raises():
    guard = EdgeVisionGuard()
    model = DummyBenignModel()
    dataset = [{"input": "car", "label": "car"}]
    with pytest.raises(ConsentRequiredError):
        guard.analyze_model(
            model=model,
            dataset=dataset,
            sandbox_profile={"segments": [], "rate_limit_per_sec": 1},
            consent=False,
            live_device=True,
        )


def test_model_analysis_no_backdoor_detected_for_benign_model():
    guard = EdgeVisionGuard()
    model = DummyBenignModel()
    dataset = [
        {"input": "car", "label": "car"},
        {"input": "TRIGGER car", "label": "car"},
        {"input": "bicycle", "label": "bicycle"},
    ]
    res = guard.analyze_model(
        model=model,
        dataset=dataset,
        sandbox_profile={"segments": ["ml"], "rate_limit_per_sec": 3},
        consent=True,
        live_device=False,
    )
    assert res.get("backdoor_detected") is False


def test_emulated_runtime_detects_blocks_unauthorized_egress_and_signs_incident_report(tmp_path, monkeypatch):
    guard = EdgeVisionGuard()

    # Ensure network calls are not actually made
    def fake_connect(*args, **kwargs):
        raise AssertionError("Network connections must be mocked within sandbox")

    monkeypatch.setattr(socket.socket, "connect", fake_connect, raising=True)

    firmware = str(tmp_path / "fw.img")
    # just create an empty firmware placeholder
    open(firmware, "wb").close()
    model = DummyBenignModel()

    network_topology = {
        "allowlist": ["127.0.0.1"],
        "segments": ["camera", "wan"],
        "rate_limit_per_sec": 10,
    }
    # Simulate egress attempts to loopback addresses not in allowlist set above
    simulate_egress = ["rtsp://127.0.0.2/stream", "https://127.0.0.3/api"]

    result = guard.run_emulation(
        firmware=firmware,
        model=model,
        network_topology=network_topology,
        consent=True,
        simulate_egress=simulate_egress,
    )
    assert isinstance(result, dict)
    blocked = result.get("blocked_connections", [])
    assert any("127.0.0.2" in b for b in blocked)
    assert any("127.0.0.3" in b for b in blocked)
    # Ensure PCAP captured in sandbox and referenced
    pcap_path = result.get("pcap")
    assert pcap_path and os.path.exists(pcap_path)

    # Incident report must be cryptographically signed and verifiable
    reports = result.get("incident_reports", [])
    assert reports and isinstance(reports[0], dict)
    report = reports[0]
    assert "signature" in report and isinstance(report["signature"], str)
    assert guard.verify_signed_report(report) is True

    # Tampering invalidates signature
    tampered = dict(report)
    tampered["details"] = dict(report.get("details", {}))
    tampered["details"]["tampered"] = True
    with pytest.raises(EvidenceIntegrityError):
        assert guard.verify_signed_report(tampered) is False

    # Sandbox indicators
    sbx = result.get("sandbox", {})
    assert set(sbx.get("segments", [])) == set(network_topology["segments"])
    assert sbx.get("rate_limit_per_sec") == 10
    assert sbx.get("rate_enforced") is True


def test_emulated_runtime_requires_consent(tmp_path):
    guard = EdgeVisionGuard()
    firmware = str(tmp_path / "fw.img")
    open(firmware, "wb").close()
    with pytest.raises(ConsentRequiredError):
        guard.run_emulation(
            firmware=firmware,
            model=DummyBenignModel(),
            network_topology={"allowlist": ["127.0.0.1"], "segments": [], "rate_limit_per_sec": 1},
            consent=False,
            simulate_egress=[],
        )


def test_evidence_bundle_creation_missing_artifact_raises(tmp_path):
    guard = EdgeVisionGuard()
    missing = str(tmp_path / "does_not_exist.pcap")
    with pytest.raises(FileNotFoundError):
        guard.create_evidence_bundle(artifacts=[missing], metadata={"chain_of_custody": {"operator": "alice"}})