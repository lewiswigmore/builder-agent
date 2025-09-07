import json
import os
import hashlib
import time
import pytest

from tools.iot.canary_lab import CANaryLab, verify_evidence_bundle


class MockBus:
    def __init__(self):
        self.sent = []
        self.running = True

    def send(self, frame):
        ts = time.monotonic()
        self.sent.append((ts, frame))

    def close(self):
        self.running = False


class MockUDS:
    def __init__(self, seed=b"\xAA\xBB", expected_key=b"\x11\x22", level=1):
        self.seed = seed
        self.expected_key = expected_key
        self.level = level
        self.granted = False
        self.requests = []

    def request_seed(self, level):
        self.requests.append(("seed", level))
        if level != self.level:
            raise ValueError("Unsupported level")
        return self.seed

    def send_key(self, level, key):
        self.requests.append(("key", level, key))
        if level != self.level:
            return False
        ok = key == self.expected_key
        self.granted = self.granted or ok
        return ok


class MockSigner:
    def __init__(self, secret=b"test-secret"):
        self.secret = secret

    def sign(self, data: bytes) -> bytes:
        return hashlib.sha256(self.secret + data).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        return signature == self.sign(data)

    @property
    def public_material(self):
        # Represent a public key or verifier identity
        return hashlib.sha256(self.secret).hexdigest()


class MockClock:
    def __init__(self, start=1700000000.0, step=0.123):
        self._t = start
        self._step = step

    def now(self) -> float:
        # wall time seconds
        self._t += self._step
        return self._t

    def monotonic(self) -> float:
        return self.now()


@pytest.fixture
def mock_components(tmp_path, monkeypatch):
    signer = MockSigner()
    clock = MockClock()
    bus = MockBus()
    uds = MockUDS()
    append_log_path = tmp_path / "append_only_log.jsonl"

    # Ensure time.monotonic used by any internals is deterministic
    m = clock
    monkeypatch.setattr(time, "monotonic", m.monotonic)

    return {
        "signer": signer,
        "clock": clock,
        "bus": bus,
        "uds": uds,
        "append_log_path": append_log_path,
        "tmpdir": tmp_path,
    }


def test_detects_unsecured_diagnostic_session_and_logs_finding(mock_components, tmp_path):
    signer = mock_components["signer"]
    clock = mock_components["clock"]
    bus = mock_components["bus"]
    uds = mock_components["uds"]
    append_log_path = mock_components["append_log_path"]

    # Weak/default algorithm returns the exact expected key regardless of seed
    def weak_default_algorithm(seed: bytes) -> bytes:
        return uds.expected_key

    lab = CANaryLab(
        bus=bus,
        uds=uds,
        signer=signer,
        clock=clock,
        append_log_path=str(append_log_path),
        security_algorithms={"weak_default": weak_default_algorithm},
    )

    safety_cfg = {
        "speed_threshold_kph": 5,
        "rpm_threshold": 1500,
        "vin_allowlist": ["TESTVIN0000000001"],
        "ecu_allowlist": ["0x7E0"],
        "safe_services": {0x10, 0x22, 0x19},
        "require_confirmation_services": {0x11, 0x27},
    }
    lab.configure_safety(safety_cfg)

    # Operator confirms risky services; simulate explicit confirmation granted
    lab.start_active_fuzzing(
        targets=["0x7E0"],
        services=[0x27],  # securityAccess
        operator_confirm=lambda svc: True,
    )

    # Attempt security access with known weak algorithm
    result = lab.attempt_security_access(level=uds.level)

    assert result is True, "Security access should be granted using weak default algorithm"

    # Verify the lab logged a finding about weak security access
    events = list(lab.events)
    matching = [
        e
        for e in events
        if e.get("type") in ("security_access_granted", "security_access_weak_granted")
        and e.get("weak", True) is True
        and e.get("algorithm") == "weak_default"
        and e.get("level") == uds.level
    ]
    assert matching, f"Expected weak security access finding; got events: {events}"

    lab.stop()


def test_speed_threshold_switches_to_passive_sniffing_and_emits_safety_event(mock_components):
    signer = mock_components["signer"]
    clock = mock_components["clock"]
    bus = mock_components["bus"]
    uds = mock_components["uds"]
    append_log_path = mock_components["append_log_path"]

    lab = CANaryLab(
        bus=bus,
        uds=uds,
        signer=signer,
        clock=clock,
        append_log_path=str(append_log_path),
        security_algorithms={},
    )

    lab.configure_safety(
        {
            "speed_threshold_kph": 5,
            "rpm_threshold": 2000,
            "vin_allowlist": ["TESTVIN0000000002"],
            "ecu_allowlist": ["0x7E1"],
            "safe_services": {0x10, 0x22, 0x19},
            "require_confirmation_services": {0x11, 0x27, 0x31},
        }
    )

    lab.configure_rate_control(
        {
            "inter_frame_gap_ms": 10,
            "busload_limit_percent": 30,
            "stateful_sessions": True,
        }
    )

    lab.start_active_fuzzing(
        targets=["0x7E1"],
        services=[0x10, 0x22],  # safe services
        operator_confirm=lambda svc: True,
    )
    assert getattr(lab, "mode", "unknown") in ("active", "active_fuzzing")

    # Simulate vehicle speed exceeding threshold
    lab.update_vehicle_state(speed_kph=12.3, rpm=900, vin="TESTVIN0000000002")

    # Expect automatic switch to passive sniffing and safety event
    assert getattr(lab, "mode", "") in ("passive", "sniffing", "passive_sniffing")

    safety_events = [e for e in lab.events if e.get("type") in ("safety_speed_threshold_exceeded", "safety_event")]
    assert safety_events, "Expected a safety event when speed exceeds threshold"
    assert any("speed" in e.get("details", {}) or "speed_kph" in e.get("details", {}) for e in safety_events)

    lab.stop()


def test_export_signed_evidence_bundle_containing_artifacts_and_verify_hash_chain(mock_components):
    signer = mock_components["signer"]
    clock = mock_components["clock"]
    bus = mock_components["bus"]
    uds = mock_components["uds"]
    append_log_path = mock_components["append_log_path"]
    tmpdir = mock_components["tmpdir"]

    lab = CANaryLab(
        bus=bus,
        uds=uds,
        signer=signer,
        clock=clock,
        append_log_path=str(append_log_path),
        security_algorithms={},
    )

    # Simulate some capture/transcript content via lab-record APIs if available
    # We don't assume a specific API; at least ensure exporting works on empty state.
    bundle_dir_1 = lab.export_evidence_bundle(destination=str(tmpdir / "bundle1"))
    assert os.path.isdir(bundle_dir_1), "Bundle export should create a directory"

    ok1, errs1 = verify_evidence_bundle(bundle_dir_1)
    assert ok1, f"Bundle signatures or hashes failed verification: {errs1}"

    # Export a second time to extend the append-only log
    bundle_dir_2 = lab.export_evidence_bundle(destination=str(tmpdir / "bundle2"))
    ok2, errs2 = verify_evidence_bundle(bundle_dir_2)
    assert ok2, f"Second bundle verification failed: {errs2}"

    # Validate append-only log exists and has valid hash chain
    assert os.path.exists(append_log_path), "Append-only log should exist"
    with open(append_log_path, "rb") as f:
        lines = f.read().splitlines()

    assert len(lines) >= 2, "Expected at least two entries in append-only log after two exports"

    # Verify simple hash chain: each entry includes prev_hash that equals SHA256 of previous entry canonical bytes
    prev_digest = None
    for i, line in enumerate(lines):
        entry = json.loads(line.decode("utf-8"))
        data_for_hash = json.dumps({k: v for k, v in entry.items() if k not in ("prev_hash", "signature")}, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(data_for_hash).hexdigest()

        if i == 0:
            assert entry.get("prev_hash") in (None, "", "GENESIS"), "First log entry should have empty/GENESIS prev_hash"
        else:
            assert entry.get("prev_hash") == prev_digest, "Hash chain broken in append-only log"

        prev_digest = digest

    # Check that the evidence bundle contains required artifacts
    for bundle_dir in (bundle_dir_1, bundle_dir_2):
        manifest_path = os.path.join(bundle_dir, "manifest.json")
        sig_path = os.path.join(bundle_dir, "manifest.sig")
        assert os.path.exists(manifest_path), "Manifest should be present"
        assert os.path.exists(sig_path), "Manifest signature should be present"

        with open(manifest_path, "rb") as mf, open(sig_path, "rb") as sf:
            manifest_bytes = mf.read()
            sig_bytes = sf.read()
            assert signer.verify(manifest_bytes, sig_bytes), "Manifest signature should verify"

        # Check that CAN PCAP and UDS transcript are referenced by manifest
        manifest = json.load(open(manifest_path, "r", encoding="utf-8"))
        files = manifest.get("files", [])
        names = {f.get("name") for f in files}
        assert any(n and n.endswith(".pcap") for n in names), "CAN PCAP should be included in bundle"
        assert any("transcript" in (n or "") for n in names), "UDS transcript should be included in bundle"


def test_fail_safe_on_critical_dtc_halts_active_fuzzing(mock_components):
    signer = mock_components["signer"]
    clock = mock_components["clock"]
    bus = mock_components["bus"]
    uds = mock_components["uds"]
    append_log_path = mock_components["append_log_path"]

    lab = CANaryLab(
        bus=bus,
        uds=uds,
        signer=signer,
        clock=clock,
        append_log_path=str(append_log_path),
        security_algorithms={},
    )

    lab.configure_safety(
        {
            "speed_threshold_kph": 30,
            "rpm_threshold": 4000,
            "vin_allowlist": ["TESTVIN0000000003"],
            "ecu_allowlist": ["0x7E2"],
            "safe_services": {0x10, 0x22},
            "require_confirmation_services": {0x11, 0x27, 0x31},
        }
    )

    lab.start_active_fuzzing(
        targets=["0x7E2"],
        services=[0x10, 0x22],
        operator_confirm=lambda svc: True,
    )

    assert getattr(lab, "mode", "") in ("active", "active_fuzzing")

    # Report a critical DTC for airbags; expect immediate fail-safe and halt
    lab.report_fault_code(system="airbags", code="B0001")

    assert getattr(lab, "mode", "") in ("fail_safe", "halted", "passive_sniffing")
    events = [e for e in lab.events if e.get("type") in ("fail_safe_critical_dtc", "critical_dtc_detected")]
    assert events, "Expected a critical DTC event"
    details = events[-1].get("details", {})
    assert details.get("system") == "airbags"

    # Ensure fuzzing stopped
    lab.stop()