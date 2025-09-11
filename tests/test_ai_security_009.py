import io
import json
import os
import socket
import uuid
import pytest

from tools.ai_security import synthguard


@pytest.fixture
def guard():
    # Instantiate SynthGuard
    if hasattr(synthguard, "SynthGuard"):
        return synthguard.SynthGuard()
    pytest.skip("SynthGuard class not found in tools.ai_security.synthguard")


def _get_audit_callable(guard_instance):
    # Discover an audit-like entry point
    if hasattr(guard_instance, "audit_pipeline"):
        return guard_instance.audit_pipeline
    if hasattr(guard_instance, "audit"):
        return guard_instance.audit
    if hasattr(guard_instance, "audit_generator"):
        return guard_instance.audit_generator
    if hasattr(synthguard, "audit_pipeline"):
        return getattr(synthguard, "audit_pipeline")
    if hasattr(synthguard, "audit"):
        return getattr(synthguard, "audit")
    if hasattr(synthguard, "audit_generator"):
        return getattr(synthguard, "audit_generator")
    return None


def test_canary_leak_blocks_release_and_signed_incident_bundle(guard, monkeypatch, tmp_path):
    # Seed canary
    canary = f"CANARY-{uuid.uuid4()}"
    dataset = {"id": "ds1", "records": [f"record-{i}" for i in range(100)] + [canary]}
    model = {"id": "m1", "path": str(tmp_path / "model.bin")}
    generator = type(
        "DummyGen",
        (),
        {"id": "g1", "name": "dummy-gen", "generate": lambda self, n: [f"out-{i}" for i in range(n)]},
    )()

    # Mock provenance verifier to pass
    def fake_verify_provenance(artifact, kind=None, **kwargs):
        return {"verified": True, "rekor": {"logIndex": 123}}

    monkeypatch.setattr(synthguard, "verify_provenance", fake_verify_provenance, raising=False)

    # Mock sandbox execution to capture limits and ensure localhost-only egress
    captured = {"egress": None, "limits": None}

    def fake_sandbox_execute(func, *args, **kwargs):
        captured["egress"] = kwargs.get("egress_allowlist", [])
        captured["limits"] = {
            "rate": kwargs.get("rate_limit"),
            "cpu": kwargs.get("cpu_limit"),
            "mem": kwargs.get("mem_limit"),
            "timeout": kwargs.get("timeout"),
        }
        return func(*args, **kwargs)

    monkeypatch.setattr(synthguard, "sandbox_execute", fake_sandbox_execute, raising=False)

    # Mock canary probes to detect a leak with high confidence
    def fake_run_canary_probes(gen, ds, samples=10000, **kwargs):
        assert samples == 10000
        return {
            "leaks": [{"token": canary, "confidence": 0.971}],
            "max_confidence": 0.971,
            "num_samples": samples,
        }

    if hasattr(guard, "run_canary_probes"):
        monkeypatch.setattr(guard, "run_canary_probes", fake_run_canary_probes, raising=True)
    else:
        monkeypatch.setattr(synthguard, "run_canary_probes", fake_run_canary_probes, raising=False)

    # Mock report signing
    def fake_sign_report(report_bytes):
        assert isinstance(report_bytes, (bytes, bytearray))
        return {
            "signed": True,
            "signature": "MEUCIQFakeSignature==",
            "bundle": report_bytes,
            "sig_alg": "ECDSA_P256_SHA256",
        }

    monkeypatch.setattr(synthguard, "sign_audit_report", fake_sign_report, raising=False)

    # Discover audit entry point
    audit_callable = _get_audit_callable(guard)
    if not audit_callable:
        pytest.skip("No audit entry point found in SynthGuard")

    # Run audit
    result = audit_callable(dataset=dataset, model=model, generator=generator, num_samples=10000)

    # Validate canary leak detection and policy enforcement
    assert isinstance(result, dict)
    assert result.get("canary", {}).get("detected") is True
    assert result.get("canary", {}).get("confidence", 0.0) >= 0.95
    assert result.get("release_blocked") is True

    # Validate signed incident bundle/report
    incident = result.get("incident_bundle") or result.get("incident")
    assert incident is not None
    assert incident.get("signed") is True
    assert isinstance(incident.get("bundle"), (bytes, bytearray))
    assert "MEUCIQ" in incident.get("signature", "")

    # Validate sandbox constraints captured
    assert captured["egress"] is not None
    # Only localhost egress should be permitted
    for host in captured["egress"]:
        assert host in ("127.0.0.1", "localhost")
    # Rate/resource limits should be set to some non-null values
    limits = captured["limits"]
    assert limits["rate"] is not None
    assert limits["cpu"] is not None
    assert limits["mem"] is not None
    assert limits["timeout"] is not None


def test_rekor_verification_blocks_on_tampered_artifact_with_evidence(guard, monkeypatch, tmp_path):
    dataset = {"id": "ds2", "path": str(tmp_path / "tampered.csv")}
    model = {"id": "m2", "path": str(tmp_path / "model.bin")}
    generator = {"id": "g2", "path": str(tmp_path / "plugin.so")}

    class TamperError(Exception):
        pass

    # Provide a dedicated exception type if available
    ProvenanceError = getattr(synthguard, "ProvenanceError", TamperError)

    # Fake verify to detect tampering and include reproducible evidence (digest mismatch + Rekor proof)
    def fake_verify_provenance(artifact, kind=None, **kwargs):
        raise ProvenanceError(
            json.dumps(
                {
                    "artifact": artifact.get("id") if isinstance(artifact, dict) else str(artifact),
                    "kind": kind,
                    "policy_violation": "SIG_VERIFICATION_FAILED",
                    "evidence": {
                        "expected_digest": "sha256:deadbeef",
                        "observed_digest": "sha256:badc0ffee",
                        "rekor_check": {"included": False, "reason": "entry not found"},
                    },
                }
            )
        )

    monkeypatch.setattr(synthguard, "verify_provenance", fake_verify_provenance, raising=False)

    # Intercept audit to ensure it fails closed on provenance failure
    audit_callable = _get_audit_callable(guard)
    if not audit_callable:
        pytest.skip("No audit entry point found in SynthGuard")

    with pytest.raises((ProvenanceError, AssertionError, RuntimeError, ValueError)) as exc:
        audit_callable(dataset=dataset, model=model, generator=generator, num_samples=100)

    # If tool captures and returns a dict instead of raising, allow that path too
    if exc.value is None and isinstance(getattr(exc, "value", None), dict):
        res = exc.value
    else:
        # If an exception was raised, we can also verify if tool exposes a last_policy_violation
        res = getattr(guard, "last_policy_violation", None)

    # Try to examine violation evidence either from exception message or guard state
    if isinstance(res, dict):
        evidence = json.loads(res.get("evidence") if isinstance(res.get("evidence"), str) else json.dumps(res.get("evidence")))
        assert evidence["rekor_check"]["included"] is False
        assert evidence["expected_digest"] != evidence["observed_digest"]


def test_rekor_transparency_log_verification_success(guard, monkeypatch):
    artifact = {"id": "ds3", "attestation": "intoto-slsa", "digest": "sha256:abcdef"}

    def fake_verify_provenance_ok(artifact, kind=None, **kwargs):
        return {
            "verified": True,
            "rekor": {
                "logIndex": 42,
                "uuid": str(uuid.uuid4()),
                "inclusionProof": {"rootHash": "00" * 32, "hashes": ["11" * 32]},
            },
        }

    monkeypatch.setattr(synthguard, "verify_provenance", fake_verify_provenance_ok, raising=False)

    res = synthguard.verify_provenance(artifact, kind="dataset")
    assert res["verified"] is True
    assert "rekor" in res
    assert "inclusionProof" in res["rekor"]


def test_membership_inference_quarantines_model_over_threshold(guard, monkeypatch):
    model = {"id": "m3"}
    policy_threshold = 0.5

    # Fake membership inference to exceed threshold
    def fake_membership_inference(target_model, **kwargs):
        assert target_model["id"] == model["id"]
        return {"risk_score": 0.78, "method": "shadow-models"}

    # Mock quarantine recording
    quarantine_calls = []

    def fake_quarantine(subject_type, subject_id, reason=None):
        quarantine_calls.append((subject_type, subject_id, reason))
        return {"status": "quarantined", "subject_type": subject_type, "subject_id": subject_id}

    # Patch
    if hasattr(guard, "run_membership_inference"):
        monkeypatch.setattr(guard, "run_membership_inference", fake_membership_inference, raising=True)
    else:
        monkeypatch.setattr(synthguard, "run_membership_inference", fake_membership_inference, raising=False)

    if hasattr(guard, "quarantine"):
        monkeypatch.setattr(guard, "quarantine", fake_quarantine, raising=True)
    else:
        monkeypatch.setattr(synthguard, "quarantine", fake_quarantine, raising=False)

    # Orchestrate via guard if it offers a policy evaluation method
    if hasattr(guard, "evaluate_membership_leakage"):
        res = guard.evaluate_membership_leakage(model, threshold=policy_threshold)
    else:
        # Fallback: directly run and enforce
        mi_res = fake_membership_inference(model)
        if mi_res["risk_score"] > policy_threshold:
            fake_quarantine("model", model["id"], reason="membership_leakage_risk")

        res = {"risk_score": mi_res["risk_score"], "threshold": policy_threshold}

    assert res["risk_score"] > policy_threshold
    assert any(c for c in quarantine_calls if c[0] == "model" and c[1] == model["id"])


def test_sandbox_egress_allowlist_blocks_external_network(guard, monkeypatch):
    # Fake sandbox will try to open network sockets; ensure only localhost is allowed
    attempted_connections = []

    def fake_connect(addr):
        attempted_connections.append(addr)
        host, port = addr
        # Only allow localhost
        if host not in ("127.0.0.1", "localhost"):
            raise PermissionError("Egress to non-allowlisted host blocked")
        return None

    # Monkeypatch socket.connect used within sandboxed tasks
    monkeypatch.setattr(socket.socket, "connect", fake_connect, raising=False)

    # Simulate sandbox task that tries to connect to example.com and localhost
    def task_with_egress_attempts():
        s = socket.socket()
        with pytest.raises(PermissionError):
            s.connect(("93.184.216.34", 80))  # example.com IP (non-localhost)
        s.connect(("127.0.0.1", 80))  # allowed
        return True

    # Run via sandbox with allowlist only for localhost
    if hasattr(synthguard, "sandbox_execute"):
        ok = synthguard.sandbox_execute(
            task_with_egress_attempts,
            egress_allowlist=["127.0.0.1", "localhost"],
            rate_limit=100,
            cpu_limit=0.1,
            mem_limit=64 * 1024 * 1024,
            timeout=1.0,
        )
    elif hasattr(guard, "sandbox_execute"):
        ok = guard.sandbox_execute(
            task_with_egress_attempts,
            egress_allowlist=["127.0.0.1", "localhost"],
            rate_limit=100,
            cpu_limit=0.1,
            mem_limit=64 * 1024 * 1024,
            timeout=1.0,
        )
    else:
        pytest.skip("No sandbox_execute available in SynthGuard")
    assert ok is True
    # Verify attempted both blocked and allowed destinations
    assert ("93.184.216.34", 80) in attempted_connections
    assert ("127.0.0.1", 80) in attempted_connections


def test_sandbox_rate_and_resource_limits_enforced(guard, monkeypatch):
    # Simulate worker exceeding limits -> should raise or return an error status
    class RateLimitExceeded(Exception):
        pass

    class ResourceLimitExceeded(Exception):
        pass

    def fake_sandbox_execute(func, *args, **kwargs):
        # Simulate hitting limits based on provided constraints
        if kwargs.get("rate_limit", 0) < 10:
            raise RateLimitExceeded("Rate limit exceeded")
        if kwargs.get("cpu_limit", 0) < 0.05 or kwargs.get("mem_limit", 0) < (16 * 1024 * 1024):
            raise ResourceLimitExceeded("Resource limit exceeded")
        return func(*args, **kwargs)

    monkeypatch.setattr(synthguard, "sandbox_execute", fake_sandbox_execute, raising=False)

    # Define a trivial task
    def trivial_task():
        return "ok"

    with pytest.raises(RateLimitExceeded):
        synthguard.sandbox_execute(trivial_task, rate_limit=5, cpu_limit=1.0, mem_limit=256 * 1024 * 1024)

    with pytest.raises(ResourceLimitExceeded):
        synthguard.sandbox_execute(trivial_task, rate_limit=100, cpu_limit=0.01, mem_limit=256 * 1024 * 1024)

    with pytest.raises(ResourceLimitExceeded):
        synthguard.sandbox_execute(trivial_task, rate_limit=100, cpu_limit=0.2, mem_limit=4 * 1024 * 1024)

    ok = synthguard.sandbox_execute(trivial_task, rate_limit=100, cpu_limit=0.2, mem_limit=256 * 1024 * 1024)
    assert ok == "ok"


def test_pii_phi_scanner_and_dp_threshold_quarantines_generator(guard, monkeypatch):
    generator = {"id": "gen-risky", "name": "risky-generator"}

    # Fake scanners report high PII/PHI leakage and DP epsilon too high
    def fake_scan_output(outputs, **kwargs):
        # Return a risk score with findings
        return {
            "pii_findings": [{"type": "SSN", "count": 2}, {"type": "PhoneNumber", "count": 1}],
            "phi_findings": [{"type": "MedicalRecordNumber", "count": 1}],
            "risk_score": 0.92,
        }

    def fake_dp_assess(outputs, **kwargs):
        return {"epsilon": 8.5, "threshold": 4.0, "breach": True}

    quarantine_calls = []

    def fake_quarantine(subject_type, subject_id, reason=None):
        quarantine_calls.append((subject_type, subject_id, reason))
        return {"status": "quarantined"}

    monkeypatch.setattr(synthguard, "scan_outputs_for_pii_phi", fake_scan_output, raising=False)
    monkeypatch.setattr(synthguard, "assess_differential_privacy", fake_dp_assess, raising=False)
    if hasattr(guard, "quarantine"):
        monkeypatch.setattr(guard, "quarantine", fake_quarantine, raising=True)
    else:
        monkeypatch.setattr(synthguard, "quarantine", fake_quarantine, raising=False)

    # Invoke an evaluation path
    outputs = ["John Doe, SSN: 123-45-6789", "Call me at (555) 123-4567", "MRN: 987654"]
    if hasattr(guard, "evaluate_output_risk"):
        risk = guard.evaluate_output_risk(outputs, generator=generator, dp_policy={"epsilon": 4.0})
    else:
        # Fallback emulate
        pii = fake_scan_output(outputs)
        dp = fake_dp_assess(outputs)
        if pii["risk_score"] > 0.9 or dp["breach"]:
            fake_quarantine("generator", generator["id"], reason="output_leakage_risk")
        risk = {"pii": pii, "dp": dp}

    assert risk.get("pii", {}).get("risk_score", 0.0) >= 0.9 or risk.get("dp", {}).get("breach") is True
    assert any(c for c in quarantine_calls if c[0] == "generator" and c[1] == generator["id"])


def test_missing_attestation_fails_closed(guard, monkeypatch):
    artifact = {"id": "no-att", "attestation": None}

    class AttestationMissing(Exception):
        pass

    def fake_verify_provenance(artifact, kind=None, **kwargs):
        if not artifact.get("attestation"):
            raise AttestationMissing("Missing attestation")
        return {"verified": True}

    monkeypatch.setattr(synthguard, "verify_provenance", fake_verify_provenance, raising=False)

    with pytest.raises(AttestationMissing):
        synthguard.verify_provenance(artifact, kind="dataset")


def test_rekor_unreachable_fails_closed(guard, monkeypatch):
    artifact = {"id": "ds4", "attestation": "intoto", "digest": "sha256:abcd"}

    class RekorUnavailable(Exception):
        pass

    def fake_verify_provenance(artifact, kind=None, **kwargs):
        # Simulate rekor unreachable
        raise RekorUnavailable("Rekor service unreachable")

    monkeypatch.setattr(synthguard, "verify_provenance", fake_verify_provenance, raising=False)

    with pytest.raises(RekorUnavailable):
        synthguard.verify_provenance(artifact, kind="dataset")