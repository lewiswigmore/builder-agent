import hashlib
import re
import struct
import time
from typing import Any, Dict, List, Optional

import pytest

# Import tool under test
import tools.forensics.gpu_vram_artifact_hunter as hunter_mod


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeVendorGPU:
    def __init__(self, snapshot: Optional[bytes], supported: bool = True):
        self._snapshot = snapshot
        self.supported = supported
        self.calls = []

    def snapshot_vram(self, read_only: bool = True, signed_kernel_module: bool = True) -> bytes:
        # enforce read-only and signed module flags
        self.calls.append(
            {
                "method": "snapshot_vram",
                "read_only": read_only,
                "signed_kernel_module": signed_kernel_module,
            }
        )
        if not self.supported:
            raise RuntimeError("NO_SUPPORTED_GPU")
        if not read_only or not signed_kernel_module:
            raise PermissionError("Acquisition must be read-only and use signed kernel module")
        if self._snapshot is None:
            return b""
        return self._snapshot


class FakeSigstore:
    def __init__(self):
        self.signed_payloads: List[Dict[str, Any]] = []

    def sign(self, payload: bytes) -> Dict[str, Any]:
        sig = hashlib.sha256(b"sig:" + payload).hexdigest()
        entry = {
            "signature": sig,
            "certificate": "FAKE-CERT",
            "log_index": 1,
        }
        self.signed_payloads.append(
            {
                "payload_sha256": _sha256(payload),
                "entry": entry,
            }
        )
        return entry


class FakeInToto:
    def __init__(self):
        self.statements: List[Dict[str, Any]] = []

    def attest(self, step_name: str, materials: Dict[str, str], products: Dict[str, str], timestamp: int) -> Dict[str, Any]:
        statement = {
            "type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "stepName": step_name,
            "materials": materials,
            "products": products,
            "timestamp": timestamp,
        }
        self.statements.append(statement)
        return statement


class FakeKMS:
    def __init__(self, key_id: str = "kms://fake-key"):
        self.key_id = key_id
        self.audit_log: List[Dict[str, Any]] = []

    def _audit(self, action: str, meta: Optional[Dict[str, Any]] = None):
        self.audit_log.append(
            {
                "action": action,
                "key_id": self.key_id,
                "meta": meta or {},
                "ts": int(time.time()),
            }
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        self._audit("encrypt", {"len": len(plaintext)})
        # toy reversible encoding to simulate encryption (XOR not used to avoid crypto claims)
        return b"ENCRYPTED:" + hashlib.sha256(plaintext).digest() + plaintext[::-1]

    def decrypt(self, ciphertext: bytes) -> bytes:
        self._audit("decrypt", {"len": len(ciphertext)})
        if not ciphertext.startswith(b"ENCRYPTED:"):
            raise ValueError("Malformed ciphertext")
        # not actually decrypting; only used to verify presence, not called in tests

    def sign(self, payload: bytes) -> Dict[str, Any]:
        self._audit("sign", {"payload_sha256": _sha256(payload)})
        return {"kms_key_id": self.key_id, "sig": hashlib.sha256(b"kms:" + payload).hexdigest()}


class FakeSandbox:
    def __init__(self, memory_safe: bool = True, no_exec: bool = True, fuzzed_parsers: bool = True):
        self.memory_safe = memory_safe
        self.no_exec = no_exec
        self.fuzzed_parsers = fuzzed_parsers
        self.runs: List[Dict[str, Any]] = []

    def run_analyzer(self, snapshot: bytes) -> Dict[str, Any]:
        # Enforce sandbox configuration
        if not (self.memory_safe and self.no_exec and self.fuzzed_parsers):
            raise RuntimeError("Analyzer must be sandboxed with memory-safe parsers and no code execution")
        findings: List[Dict[str, Any]] = []
        secrets: List[Dict[str, Any]] = []

        # Detect marked float32 blocks
        marker = b"F32BLOCK"
        idx = snapshot.find(marker)
        if idx != -1:
            offset = idx + len(marker)
            # basic confidence heuristic: check contiguous length divisible by 4
            block_len = min(len(snapshot) - offset, 400)
            block_len -= block_len % 4
            if block_len > 0:
                findings.append(
                    {
                        "type": "float32_tensor",
                        "offset": offset,
                        "length": block_len,
                        "confidence": 0.91,
                    }
                )

        # Detect API keys (general pattern and AWS style)
        for m in re.finditer(rb"(sk-[A-Za-z0-9]{10,})", snapshot):
            secrets.append({"type": "api_key", "value": m.group(1).decode("utf-8", errors="ignore"), "offset": m.start()})
        for m in re.finditer(rb"(AKIA[0-9A-Z]{16})", snapshot):
            secrets.append({"type": "aws_access_key", "value": m.group(1).decode("utf-8", errors="ignore"), "offset": m.start()})

        self.runs.append({"len": len(snapshot), "findings": findings, "secrets": secrets})
        return {"findings": findings, "secrets": secrets, "sandbox": {"memory_safe": self.memory_safe, "no_exec": self.no_exec, "fuzzed_parsers": self.fuzzed_parsers}}


@pytest.fixture
def fixed_time(monkeypatch):
    monkeypatch.setattr(hunter_mod.time, "time", lambda: 1700000000.0)
    try:
        import time as pytime

        monkeypatch.setattr(pytime, "time", lambda: 1700000000.0)
    except Exception:
        pass
    return 1700000000


@pytest.fixture
def sample_snapshot_and_offsets():
    # Construct a snapshot: padding, marker + float32 block, padding, API keys
    pad1 = b"\x00" * 1024
    floats = [0.001 * i for i in range(100)]
    float_block = struct.pack("<" + "f" * len(floats), *floats)
    marker = b"F32BLOCK"
    tensor_region = marker + float_block
    pad2 = b"\x11" * 128
    api_keys_region = b"some noise sk-TESTSECRETKEY123456 some more AKIAABCDEFGHIJKLMNOP and tail"
    snapshot = pad1 + tensor_region + pad2 + api_keys_region
    tensor_offset = len(pad1) + len(marker)
    return snapshot, tensor_offset, api_keys_region


def _ensure_function(module, name: str):
    fn = getattr(module, name, None)
    if callable(fn):
        return fn
    pytest.skip(f"Required function {name} not found in module")


def test_capture_vram_identify_float32_and_seal_report(monkeypatch, fixed_time, sample_snapshot_and_offsets):
    hunt_fn = _ensure_function(hunter_mod, "hunt_gpu_vram_artifacts")

    snapshot, tensor_offset, _ = sample_snapshot_and_offsets
    vendor = FakeVendorGPU(snapshot=snapshot, supported=True)
    sigstore = FakeSigstore()
    intoto = FakeInToto()
    kms = FakeKMS()
    sandbox = FakeSandbox(memory_safe=True, no_exec=True, fuzzed_parsers=True)

    # Ensure no network calls by stubbing any network-related fields if present
    if hasattr(hunter_mod, "DEFAULT_SIGSTORE_FULCIO_URL"):
        monkeypatch.setattr(hunter_mod, "DEFAULT_SIGSTORE_FULCIO_URL", "http://127.0.0.1:8080")
    if hasattr(hunter_mod, "DEFAULT_SIGSTORE_REKOR_URL"):
        monkeypatch.setattr(hunter_mod, "DEFAULT_SIGSTORE_REKOR_URL", "http://127.0.0.1:8080")

    result = hunt_fn(
        config={"read_only": True, "signed_kernel_module": True},
        vendor=vendor,
        sigstore=sigstore,
        in_toto=intoto,
        kms=kms,
        sandbox=sandbox,
    )

    # Acquisition assertions
    assert vendor.calls, "Vendor API should be invoked"
    assert vendor.calls[0]["read_only"] is True
    assert vendor.calls[0]["signed_kernel_module"] is True

    # Artifacts hashed and present
    artifacts = result.get("artifacts", [])
    assert isinstance(artifacts, list) and artifacts, "Artifacts list should be non-empty"
    snapshot_art = next((a for a in artifacts if a.get("type") == "vram_snapshot"), None)
    assert snapshot_art is not None, "VRAM snapshot artifact must be present"
    assert snapshot_art.get("sha256") == _sha256(snapshot)

    # Analysis findings: float32 tensor block with offsets and confidence
    report = result.get("report", {})
    findings = report.get("findings", [])
    assert findings, "Findings should not be empty"
    tensor_findings = [f for f in findings if f.get("type") == "float32_tensor"]
    assert tensor_findings, "Should identify float32 tensor blocks"
    assert any(abs(f["offset"] - tensor_offset) < 8 for f in tensor_findings), "Offset should match marker location"
    assert all(0.0 <= f.get("confidence", 0) <= 1.0 for f in tensor_findings), "Confidence scores should be in [0,1]"

    # Sealed report and attestations
    sealed_report = result.get("sealed_report", {})
    assert sealed_report.get("attestation", {}).get("timestamp") == fixed_time
    assert "sigstore" in sealed_report.get("attestation", {})
    assert "in_toto" in sealed_report.get("attestation", {})
    assert sigstore.signed_payloads, "Sigstore should have signed payloads"
    assert intoto.statements, "in-toto statements should be recorded"

    # Chain-of-custody and KMS audit
    assert any(entry["action"] == "sign" for entry in kms.audit_log), "KMS sign action should be audited"


def test_detect_and_redact_api_keys_preserve_encrypted_artifact(monkeypatch, fixed_time, sample_snapshot_and_offsets):
    hunt_fn = _ensure_function(hunter_mod, "hunt_gpu_vram_artifacts")

    snapshot, _, api_keys_region = sample_snapshot_and_offsets
    vendor = FakeVendorGPU(snapshot=snapshot, supported=True)
    sigstore = FakeSigstore()
    intoto = FakeInToto()
    kms = FakeKMS()
    sandbox = FakeSandbox(memory_safe=True, no_exec=True, fuzzed_parsers=True)

    result = hunt_fn(
        config={"read_only": True, "signed_kernel_module": True},
        vendor=vendor,
        sigstore=sigstore,
        in_toto=intoto,
        kms=kms,
        sandbox=sandbox,
    )

    # Redacted human-readable output should not leak API keys
    redacted_text = result.get("redacted_report_text") or ""
    assert isinstance(redacted_text, str)
    assert "sk-TESTSECRETKEY123456" not in redacted_text
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted_text
    # It should note redactions where appropriate
    assert ("[REDACTED]" in redacted_text) or ("redacted" in redacted_text.lower())

    # Encrypted, sealed original artifact must be preserved
    enc_art = result.get("encrypted_original_artifact")
    assert enc_art is not None and isinstance(enc_art, (bytes, bytearray))
    # Verify KMS encrypt was used and audited
    assert any(entry["action"] == "encrypt" for entry in kms.audit_log)
    # Artifact hash present and matches the original report or snapshot hash references
    artifacts = result.get("artifacts", [])
    enc_meta = next((a for a in artifacts if a.get("type") == "encrypted_original"), None)
    assert enc_meta is not None, "Encrypted original artifact metadata should be recorded"
    assert "sha256" in enc_meta and isinstance(enc_meta["sha256"], str)
    # Ensure the encrypted bytes refer back to an original artifact (chain-of-custody)
    assert "source_artifact_sha256" in enc_meta


def test_system_without_supported_gpu_emits_signed_nil_attestation(monkeypatch, fixed_time):
    hunt_fn = _ensure_function(hunter_mod, "hunt_gpu_vram_artifacts")

    # No supported GPU
    vendor = FakeVendorGPU(snapshot=None, supported=False)
    sigstore = FakeSigstore()
    intoto = FakeInToto()
    kms = FakeKMS()
    sandbox = FakeSandbox(memory_safe=True, no_exec=True, fuzzed_parsers=True)

    result = hunt_fn(
        config={"read_only": True, "signed_kernel_module": True},
        vendor=vendor,
        sigstore=sigstore,
        in_toto=intoto,
        kms=kms,
        sandbox=sandbox,
    )

    # Nil attestation with reason codes and zero artifacts
    nil = result.get("nil_attestation", {})
    assert nil.get("signed") is True
    assert nil.get("timestamp") == fixed_time
    reasons = nil.get("reasons", [])
    assert any("NO_SUPPORTED_GPU" in r for r in reasons)
    artifacts = result.get("artifacts", [])
    assert isinstance(artifacts, list) and len(artifacts) == 0

    # Ensure sigstore was still used to sign the nil attestation
    assert sigstore.signed_payloads, "Nil attestation should be signed"


def test_analyzer_must_run_sandboxed_and_memory_safe(monkeypatch, fixed_time, sample_snapshot_and_offsets):
    hunt_fn = _ensure_function(hunter_mod, "hunt_gpu_vram_artifacts")

    snapshot, _, _ = sample_snapshot_and_offsets
    vendor = FakeVendorGPU(snapshot=snapshot, supported=True)
    sigstore = FakeSigstore()
    intoto = FakeInToto()
    kms = FakeKMS()
    # Provide a sandbox that violates requirements
    bad_sandbox = FakeSandbox(memory_safe=False, no_exec=False, fuzzed_parsers=False)

    with pytest.raises(RuntimeError):
        hunt_fn(
            config={"read_only": True, "signed_kernel_module": True},
            vendor=vendor,
            sigstore=sigstore,
            in_toto=intoto,
            kms=kms,
            sandbox=bad_sandbox,
        )


def test_error_handling_corrupt_snapshot(monkeypatch, fixed_time):
    hunt_fn = _ensure_function(hunter_mod, "hunt_gpu_vram_artifacts")

    # Corrupt snapshot (not bytes or empty) should be handled gracefully
    vendor = FakeVendorGPU(snapshot=b"", supported=True)
    sigstore = FakeSigstore()
    intoto = FakeInToto()
    kms = FakeKMS()
    sandbox = FakeSandbox(memory_safe=True, no_exec=True, fuzzed_parsers=True)

    result = hunt_fn(
        config={"read_only": True, "signed_kernel_module": True},
        vendor=vendor,
        sigstore=sigstore,
        in_toto=intoto,
        kms=kms,
        sandbox=sandbox,
    )

    # Expect no findings but still a sealed report indicating empty acquisition
    report = result.get("report", {})
    assert report.get("findings", []) == []
    sealed_report = result.get("sealed_report", {})
    assert sealed_report.get("attestation", {}).get("timestamp") == fixed_time
    # Artifacts should include an entry for the empty snapshot with correct hash
    artifacts = result.get("artifacts", [])
    snap_meta = next((a for a in artifacts if a.get("type") == "vram_snapshot"), None)
    assert snap_meta is not None
    assert snap_meta["sha256"] == _sha256(b"")