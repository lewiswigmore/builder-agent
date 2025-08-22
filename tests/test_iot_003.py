import io
import json
import os
import tarfile
import time
import hashlib
import pytest

import tools.iot_security.fuzzfox as fuzzfox_mod
from tools.iot_security.fuzzfox import FuzzFox


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


@pytest.fixture
def sample_firmware_archive(tmp_path):
    # Build a simple tar archive simulating a vendor firmware package
    fw_dir = tmp_path / "fw"
    fw_dir.mkdir()
    # Files with secrets and PII to detect and redact
    (fw_dir / "etc").mkdir()
    (fw_dir / "home").mkdir()
    secret_content = b"api_key=ABC123\npassword=hunter2\n"
    pii_content = b"contact_email=user@example.com\n"
    (fw_dir / "etc" / "config.txt").write_bytes(secret_content)
    (fw_dir / "home" / "readme.txt").write_bytes(pii_content)

    archive_path = tmp_path / "vendor_firmware.tar"
    with tarfile.open(archive_path, "w") as tar:
        tar.add(fw_dir, arcname=".")

    return {
        "archive": str(archive_path),
        "secret_path": str(fw_dir / "etc" / "config.txt"),
        "pii_path": str(fw_dir / "home" / "readme.txt"),
        "secret_sha256": _sha256_bytes(secret_content),
        "pii_bytes": pii_content,
    }


@pytest.fixture
def signed_yara_pack(tmp_path):
    pack_path = tmp_path / "rules.yar.pack"
    pack_path.write_bytes(b"fake-yara-rules")
    sig_path = tmp_path / "rules.yar.pack.sig"
    sig_path.write_bytes(b"fake-signature")
    return str(pack_path)


def test_fuzzfox_passive_fingerprint_and_protocol_aware_fuzzers_rate_limit_and_isolation(monkeypatch, caplog):
    ff = FuzzFox(iface="lo", namespace="ff-test-ns")

    discovered = [
        {
            "id": "mqtt-cam-1",
            "ip": "127.0.0.1",
            "port": 1883,
            "protocol": "mqtt",
            "fingerprint_sources": {"mdns", "ssdp", "heuristics"},
        },
        {
            "id": "coap-sensor-1",
            "ip": "127.0.0.1",
            "port": 5683,
            "protocol": "coap",
            "fingerprint_sources": {"mdns", "ssdp", "heuristics"},
        },
    ]

    # Mock passive fingerprinting to return our localhost devices
    monkeypatch.setattr(ff, "passive_fingerprint", lambda: discovered)

    # Ensure no real eBPF or network calls are made; simulate counters and traffic accounting
    class FakeNamespace:
        def __init__(self, name):
            self.name = name
            self.egress_packets = 0
            self.leak_packets = 0

        def account(self, packets):
            self.egress_packets += packets

        def counters(self):
            return {
                "namespace": self.name,
                "egress_packets": self.egress_packets,
                "egress_bytes": self.egress_packets * 64,
                "leak_packets": self.leak_packets,
                "leak_bytes": 0,
                "interfaces": {"lo": self.egress_packets, "external": 0},
            }

    fake_ns = FakeNamespace("ff-test-ns")

    # If implementation uses get_namespace_counters, return fake counters
    def fake_get_namespace_counters():
        return fake_ns.counters()

    monkeypatch.setattr(ff, "get_namespace_counters", fake_get_namespace_counters, raising=False)

    # If implementation applies ebpf policy, stub it
    monkeypatch.setattr(ff, "apply_ebpf_policies", lambda: True, raising=False)

    # If implementation enforces microsegmentation/namespace setup, stub it
    monkeypatch.setattr(ff, "setup_isolation", lambda: True, raising=False)

    # Monkeypatch time.sleep so tests run fast if used for rate limiting
    monkeypatch.setattr(time, "sleep", lambda s: None)

    # Optionally, if implementation uses a send function internally, stub to account against fake namespace
    if hasattr(ff, "send_fuzz_packet"):
        original_send = ff.send_fuzz_packet

        def wrapped_send(device, payload):
            fake_ns.account(1)
            return original_send(device, payload)

        monkeypatch.setattr(ff, "send_fuzz_packet", wrapped_send)

    # Run discovery and fuzzing
    targets = ff.passive_fingerprint()
    assert {t["protocol"] for t in targets} == {"mqtt", "coap"}
    for t in targets:
        assert {"mdns", "ssdp"}.issubset(t["fingerprint_sources"])

    result = ff.run_protocol_fuzzers(targets, rate_limit=100, duration=0.2, health_checks=True)

    # Acceptance assertions
    assert isinstance(result, dict)
    assert result.get("crashes", []) == []
    assert any(issue.get("type") == "input_validation" for issue in result.get("issues", []))

    per_target_pps = result.get("per_target_pps", {})
    assert set(per_target_pps.keys()) == {t["id"] for t in targets}
    for pps in per_target_pps.values():
        assert pps <= 100

    ns_counters = result.get("namespace_counters") or ff.get_namespace_counters()
    assert ns_counters["namespace"] == "ff-test-ns"
    assert ns_counters.get("leak_packets", 0) == 0
    assert ns_counters.get("interfaces", {}).get("external", 0) == 0


def test_kill_switch_quarantine_on_anomaly(monkeypatch):
    ff = FuzzFox(iface="lo", namespace="ff-ns-anom")

    # Single CoAP target on localhost
    targets = [
        {
            "id": "coap-sensor-2",
            "ip": "127.0.0.1",
            "port": 5683,
            "protocol": "coap",
            "fingerprint_sources": {"heuristics"},
        }
    ]

    # Stub health check to report anomaly after first iteration
    anomaly_flag = {"raised": False}

    def fake_health_check(device):
        if not anomaly_flag["raised"]:
            anomaly_flag["raised"] = True
            return {"ok": False, "reason": "heartbeat_timeout"}
        return {"ok": True}

    monkeypatch.setattr(ff, "health_check", fake_health_check, raising=False)

    # Stub kill_switch to mark quarantine
    quarantined = []

    def fake_kill_switch(reason, device_id=None):
        if device_id:
            quarantined.append(device_id)
        ff._kill = True  # if implementation uses internal flag

    monkeypatch.setattr(ff, "kill_switch", fake_kill_switch, raising=False)

    result = ff.run_protocol_fuzzers(targets, rate_limit=100, duration=0.1, health_checks=True)
    assert result.get("quarantined") or quarantined
    q = result.get("quarantined") or quarantined
    assert "coap-sensor-2" in q
    # Ensure no crashes and isolation still intact
    assert result.get("crashes", []) == []
    ns_counters = result.get("namespace_counters") or ff.get_namespace_counters()
    assert ns_counters.get("leak_packets", 0) == 0


def test_rate_limit_edge_cases(monkeypatch):
    ff = FuzzFox(iface="lo", namespace="ff-ns-limit")
    targets = [{"id": "mqtt-cam-2", "ip": "127.0.0.1", "port": 1883, "protocol": "mqtt", "fingerprint_sources": {"mdns"}}]

    with pytest.raises(ValueError):
        ff.run_protocol_fuzzers(targets, rate_limit=-1, duration=0.1, health_checks=False)

    # Zero targets handled gracefully
    empty_result = ff.run_protocol_fuzzers([], rate_limit=100, duration=0.1, health_checks=False)
    assert empty_result.get("issues", []) == []
    assert empty_result.get("crashes", []) == []
    assert empty_result.get("per_target_pps", {}) == {}


def test_firmware_analysis_detects_secrets_redacts_and_preserves_hashes_and_enforces_read_only(
    sample_firmware_archive, signed_yara_pack, monkeypatch, caplog
):
    archive = sample_firmware_archive["archive"]
    secret_sha256 = sample_firmware_archive["secret_sha256"]
    pii_bytes = sample_firmware_archive["pii_bytes"]

    # Mock YARA signature verification to pass
    monkeypatch.setattr(fuzzfox_mod, "verify_yara_pack_signature", lambda pack: True, raising=False)

    # Mock YARA scanning to find our secrets
    def fake_scan(path, pack):
        # Return list of findings with path and raw secret values
        return [
            {"path": "etc/config.txt", "secret": "ABC123"},
            {"path": "home/readme.txt", "secret": "user@example.com"},
        ]

    monkeypatch.setattr(fuzzfox_mod, "scan_with_yara", fake_scan, raising=False)

    # Prevent any mount attempts
    def fake_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args")
        if isinstance(cmd, (list, tuple)) and any("mount" in str(x) for x in cmd):
            raise AssertionError("Mount should not be called during firmware extraction")
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(fuzzfox_mod, "subprocess_run", fake_run, raising=False)

    # Enforce read-only by denying writes specifically to firmware archive path
    # If implementation tries to write to the archive path, raise PermissionError and expect logging
    original_open = getattr(fuzzfox_mod, "open", None)

    def guard_open(file, mode="r", *args, **kwargs):
        if os.fspath(file) == archive and any(ch in mode for ch in ("w", "a", "+")):
            raise PermissionError("Read-only enforcement: denied write to firmware path")
        if original_open:
            return original_open(file, mode, *args, **kwargs)
        import builtins

        return builtins.open(file, mode, *args, **kwargs)

    monkeypatch.setattr(fuzzfox_mod, "open", guard_open, raising=False)

    caplog.set_level("INFO")
    result = fuzzfox_mod.analyze_firmware(archive, signed_yara_pack, read_only=True)

    # Verify signature
    assert result.get("signature_verified") is True

    # Verify report redaction: secrets and PII should not appear as plaintext
    report = result.get("report_redacted", "")
    assert "ABC123" not in report
    assert "user@example.com" not in report
    assert any(token in report for token in ("REDACTED", "****", "[REDACTED]"))

    # Verify sealed manifest and SHA-256 evidence
    manifest = result.get("manifest") or {}
    assert manifest.get("sealed") is True
    artefacts = manifest.get("artefacts") or manifest.get("artifacts") or []
    # At least one artefact recorded
    assert isinstance(artefacts, list) and artefacts
    # Must include an entry for etc/config.txt or the secret hash record
    secrets_found = result.get("secrets_found") or []
    assert any(s.get("sha256") == hashlib.sha256(b"ABC123").hexdigest() for s in secrets_found)
    # Optionally verify file-level hash present anywhere
    any_hashes = json.dumps(manifest).encode()
    assert hashlib.sha256(b"ABC123").hexdigest().encode() in any_hashes or secret_sha256.encode() in any_hashes

    # Verify read-only enforcement observed in logs or result flags
    ro_flag = result.get("readonly_enforced") or result.get("read_only_enforced")
    if ro_flag is not None:
        assert ro_flag is True
    # Also accept presence of a log line indicating enforcement
    assert any(
        "read-only" in rec.message.lower() or "denied write" in rec.message.lower() for rec in caplog.records
    )

    # Verify runtime security posture flags if provided
    runtime = result.get("runtime") or {}
    if runtime:
        assert runtime.get("non_root") is True
        caps = set(runtime.get("caps_dropped") or [])
        assert ("CAP_SYS_ADMIN" in caps) or ("ALL" in caps)


def test_firmware_analysis_invalid_yara_pack_signature(monkeypatch, sample_firmware_archive, signed_yara_pack):
    archive = sample_firmware_archive["archive"]

    # Signature invalid
    monkeypatch.setattr(fuzzfox_mod, "verify_yara_pack_signature", lambda pack: False, raising=False)

    # Depending on implementation, either raises or returns result with signature_verified False
    try:
        result = fuzzfox_mod.analyze_firmware(archive, signed_yara_pack, read_only=True)
    except Exception as e:
        assert isinstance(e, (ValueError, PermissionError, RuntimeError))
    else:
        assert result.get("signature_verified") is False
        assert not result.get("secrets_found")


def test_firmware_analysis_handles_corrupted_archive(monkeypatch, tmp_path, signed_yara_pack):
    bad_archive = tmp_path / "bad.tar"
    bad_archive.write_bytes(b"not a real tar")

    # Provide passing signature verification to get to extraction
    monkeypatch.setattr(fuzzfox_mod, "verify_yara_pack_signature", lambda pack: True, raising=False)

    with pytest.raises(Exception):
        fuzzfox_mod.analyze_firmware(str(bad_archive), signed_yara_pack, read_only=True)