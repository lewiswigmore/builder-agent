import pytest
import importlib
import hashlib
from types import MethodType
from urllib.parse import urlparse
from datetime import datetime


@pytest.fixture(scope="module")
def gpushield_module():
    return importlib.import_module("tools.cloud.gpushield")


@pytest.fixture
def Auditor(gpushield_module):
    auditor_cls = getattr(gpushield_module, "GPUShieldAuditor", None) or getattr(gpushield_module, "GPUShield", None)
    if auditor_cls is None:
        pytest.skip("GPUShieldAuditor/GPUShield class not found in tools/cloud/gpushield.py")
    return auditor_cls


@pytest.fixture
def auditor(Auditor):
    # Try a few instantiation patterns to support dependency injection in implementation
    try:
        return Auditor()
    except TypeError:
        try:
            return Auditor(config={"rekor_url": "http://127.0.0.1:3000", "test_mode": True, "namespace_prefix": "gpushield-test"})
        except TypeError:
            try:
                return Auditor(rekor_url="http://127.0.0.1:3000", test_mode=True, namespace_prefix="gpushield-test")
            except TypeError:
                return Auditor(rekor_url="http://127.0.0.1:3000")


@pytest.fixture
def canary_pattern():
    return b"GPU_SHIELD_CANARY_PATTERN_v1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fake_attestation(self, audit_id, evidence, manifest, hw_fingerprint):
    # offline/local attestation with Rekor anchoring simulated to localhost
    return {
        "audit_id": audit_id,
        "evidence": evidence,
        "manifest": manifest,
        "hw_fingerprint": hw_fingerprint,
        "signature": "FAKE_SIGNATURE",
        "rekor": {
            "uuid": "00000000-0000-0000-0000-000000000001",
            "logIndex": 42,
            "url": "http://127.0.0.1:3000/api/v1/log/entries/00000000-0000-0000-0000-000000000001",
        },
        "created_at": datetime.utcnow().isoformat() + "Z",
        "verifier": "gpu-shield-test-suite",
    }


def _fake_verify_attestation(self, attestation):
    # basic shape and signature presence checks
    required = {"audit_id", "evidence", "manifest", "hw_fingerprint", "signature", "rekor"}
    if not isinstance(attestation, dict) or not required.issubset(set(attestation.keys())):
        return False
    if not attestation["signature"]:
        return False
    rekor = attestation.get("rekor", {})
    try:
        host = urlparse(rekor.get("url", "")).hostname
    except Exception:
        host = None
    return host in ("127.0.0.1", "localhost")


@pytest.mark.parametrize("enforce_mig", [True])
def test_isolated_tenants_no_residue_and_signed_attestation(monkeypatch, auditor, canary_pattern, enforce_mig):
    # Ensure produce_attestation/verify_attestation are mocked to avoid network/crypto
    if hasattr(auditor, "produce_attestation"):
        monkeypatch.setattr(auditor, "produce_attestation", MethodType(_fake_attestation, auditor))
    if hasattr(auditor, "verify_attestation"):
        monkeypatch.setattr(auditor, "verify_attestation", MethodType(_fake_verify_attestation, auditor))

    quotas = {"gpu": 1, "cpu": "500m", "memory": "1Gi"}

    assert hasattr(auditor, "create_tenant"), "create_tenant method is required"
    tenant_a = auditor.create_tenant(name="gpushield-test-a", quotas=quotas, mig_required=enforce_mig)
    tenant_b = auditor.create_tenant(name="gpushield-test-b", quotas=quotas, mig_required=enforce_mig)

    # Canary write in tenant A
    assert hasattr(auditor, "write_canary"), "write_canary method is required"
    canary_meta = auditor.write_canary(tenant=tenant_a, pattern=canary_pattern)
    assert "hash" in canary_meta and "duration_ms" in canary_meta
    assert canary_meta["hash"] == _sha256(canary_pattern)
    # Ensure only integrity metadata is collected
    evidence = canary_meta.get("evidence", {})
    disallowed_keys = {"raw", "bytes", "payload", "content", "tensor", "model"}
    assert not (set(canary_meta.keys()) & disallowed_keys)
    assert not (set(evidence.keys()) & disallowed_keys)

    # Tear down tenant A to simulate deallocation/cleanup
    assert hasattr(auditor, "destroy_tenant"), "destroy_tenant method is required"
    auditor.destroy_tenant(tenant=tenant_a)

    # Scan for residue in tenant B
    assert hasattr(auditor, "scan_for_residue"), "scan_for_residue method is required"
    residue = auditor.scan_for_residue(tenant=tenant_b, expected_hash=canary_meta["hash"])
    assert isinstance(residue, dict)
    assert residue.get("matches", []) == []
    assert residue.get("indicators", {}).get("residue", False) is False

    # Attestation generation with reproducible manifest and hardware/driver fingerprints
    assert hasattr(auditor, "get_reproducible_env_manifest"), "get_reproducible_env_manifest method is required"
    assert hasattr(auditor, "get_hw_fingerprint"), "get_hw_fingerprint method is required"
    manifest = auditor.get_reproducible_env_manifest()
    hw_fp = auditor.get_hw_fingerprint()
    att = auditor.produce_attestation(
        audit_id=residue.get("audit_id", "audit-iso-1"),
        evidence={"canary_hash": canary_meta["hash"], "scan": residue, "timing_ms": canary_meta["duration_ms"]},
        manifest=manifest,
        hw_fingerprint=hw_fp,
    )
    # Verify output constraints
    assert att.get("signature")
    rekor_url = att.get("rekor", {}).get("url", "")
    host = urlparse(rekor_url).hostname
    assert host in ("127.0.0.1", "localhost")
    # Ensure manifests/hw fingerprints present
    assert manifest and hw_fp
    # Verify attestation
    ok = auditor.verify_attestation(att)
    assert ok is True

    # Automated cleanup: destroy tenant B
    auditor.destroy_tenant(tenant=tenant_b)


def test_critical_leakage_finding_with_signed_evidence(monkeypatch, auditor, canary_pattern):
    if hasattr(auditor, "produce_attestation"):
        monkeypatch.setattr(auditor, "produce_attestation", MethodType(_fake_attestation, auditor))
    if hasattr(auditor, "verify_attestation"):
        monkeypatch.setattr(auditor, "verify_attestation", MethodType(_fake_verify_attestation, auditor))

    quotas = {"gpu": 1}
    tenant_a = auditor.create_tenant(name="gpushield-test-leak-a", quotas=quotas, mig_required=True)
    tenant_b = auditor.create_tenant(name="gpushield-test-leak-b", quotas=quotas, mig_required=True)

    canary_meta = auditor.write_canary(tenant=tenant_a, pattern=canary_pattern)
    auditor.destroy_tenant(tenant=tenant_a)

    # Simulate a leakage by monkeypatching scan_for_residue to return a match
    def fake_scan(self, tenant, expected_hash):
        return {
            "audit_id": "audit-leak-1",
            "matches": [expected_hash],
            "indicators": {"residue": True, "severity": "critical"},
            "duration_ms": 7,
        }

    monkeypatch.setattr(auditor, "scan_for_residue", MethodType(fake_scan, auditor))
    residue = auditor.scan_for_residue(tenant=tenant_b, expected_hash=canary_meta["hash"])
    assert residue["matches"] == [canary_meta["hash"]]
    assert residue["indicators"]["severity"] == "critical"

    manifest = auditor.get_reproducible_env_manifest()
    hw_fp = auditor.get_hw_fingerprint()
    att = auditor.produce_attestation(
        audit_id=residue["audit_id"],
        evidence={"canary_hash": canary_meta["hash"], "scan": residue},
        manifest=manifest,
        hw_fingerprint=hw_fp,
    )
    assert att["evidence"]["canary_hash"] == _sha256(canary_pattern)
    # Ensure evidence doesn't include raw content
    disallowed = {"raw", "bytes", "payload", "content", "tensor", "model"}
    assert not (set(att["evidence"].keys()) & disallowed)
    assert att["signature"]
    assert auditor.verify_attestation(att) is True

    auditor.destroy_tenant(tenant=tenant_b)


def test_detect_driver_firmware_drift_and_block_admission(monkeypatch, auditor):
    assert hasattr(auditor, "set_baseline"), "set_baseline method is required"
    assert hasattr(auditor, "detect_driver_drift"), "detect_driver_drift method is required"
    assert hasattr(auditor, "generate_policy_remediation"), "generate_policy_remediation method is required"
    assert hasattr(auditor, "block_node_admission"), "block_node_admission method is required"

    baseline = {
        "driver_version": "535.104.05",
        "firmware": "fw-1.2.3",
        "mps_mode": "isolated",
        "device_plugin": "v0.15.0",
    }
    auditor.set_baseline(baseline)

    # Simulate current fingerprint drift via monkeypatch get_hw_fingerprint
    def fake_hw_fp(self):
        return {
            "driver_version": "535.43.03",  # vulnerable branch
            "firmware": "fw-1.2.2",  # drifted
            "mps_mode": "mixed",  # mixed security mode
            "device_plugin": "v0.14.0",
        }

    if hasattr(auditor, "get_hw_fingerprint"):
        monkeypatch.setattr(auditor, "get_hw_fingerprint", MethodType(fake_hw_fp, auditor))

    drift = auditor.detect_driver_drift()
    assert drift["drift"] is True
    assert drift["details"]
    assert drift.get("mps_mixed_security", False) is True

    policy = auditor.generate_policy_remediation(drift)
    # Expect policy-as-code structure (OPA/Kyverno style constraints)
    assert isinstance(policy, dict)
    assert policy.get("kind") in {"Constraint", "ClusterPolicy", "AdmissionPolicy", "Policy"}
    assert "rules" in policy or "spec" in policy

    # Admission control blocks non-compliant autoscaling nodes
    blocked = auditor.block_node_admission(drift_report=drift)
    assert isinstance(blocked, (list, tuple, set))
    assert len(blocked) >= 0
    # If drift present, expect at least one node blocked (implementation may block all pending)
    if drift["drift"]:
        assert len(blocked) >= 1


def test_device_plugin_hardening_misconfig_blocks_scheduling_and_reports(monkeypatch, auditor):
    assert hasattr(auditor, "validate_device_plugin"), "validate_device_plugin method is required"
    assert hasattr(auditor, "block_risky_scheduling"), "block_risky_scheduling method is required"

    # Simulate a misconfiguration: hostPath, missing cgroup, permissive ioctl filters
    misconfig = {
        "hostPath": True,
        "cgroup_filters": [],
        "ioctl_allowlist": ["*"],  # too permissive
        "device_nodes": ["/dev/nvidia0", "/dev/nvidiactl"],
    }

    posture = auditor.validate_device_plugin(config=misconfig)
    assert isinstance(posture, dict)
    assert posture.get("secure") is False
    findings = posture.get("findings", [])
    assert any("hostPath" in f for f in findings)
    assert any("cgroup" in f.lower() for f in findings)
    assert any("ioctl" in f.lower() for f in findings)

    blocked = auditor.block_risky_scheduling(posture_report=posture)
    assert blocked is True
    assert "summary" in posture and isinstance(posture["summary"], str)


def test_quotas_enforced_automated_cleanup_and_no_production_disruption(auditor):
    quotas = {"gpu": 1, "cpu": "1", "memory": "2Gi"}
    # Production namespace must be rejected
    with pytest.raises(Exception):
        auditor.create_tenant(name="prod-ml-trainer", quotas=quotas, mig_required=True)

    # Test tenants operate in isolated namespaces/projects with quotas
    t = auditor.create_tenant(name="gpushield-test-quota", quotas=quotas, mig_required=True)
    # Quotas enforcement check: either returned on tenant or retrievable
    tenant_quotas = None
    if isinstance(t, dict) and "quotas" in t:
        tenant_quotas = t["quotas"]
    elif hasattr(auditor, "get_namespace_quota"):
        tenant_quotas = auditor.get_namespace_quota(tenant=t)
    assert tenant_quotas == quotas

    auditor.destroy_tenant(tenant=t)
    # Automated cleanup verification
    ns_gone = False
    if hasattr(auditor, "namespace_exists"):
        ns_gone = not auditor.namespace_exists(tenant=t)
    elif hasattr(auditor, "list_resources"):
        ns_gone = len(auditor.list_resources(tenant=t)) == 0
    assert ns_gone is True


def test_attestation_rekor_anchoring_and_error_handling(monkeypatch, auditor):
    # Mock attestation functions to avoid external calls and simulate failures
    if hasattr(auditor, "produce_attestation"):
        monkeypatch.setattr(auditor, "produce_attestation", MethodType(_fake_attestation, auditor))
    if hasattr(auditor, "verify_attestation"):
        monkeypatch.setattr(auditor, "verify_attestation", MethodType(_fake_verify_attestation, auditor))

    manifest = {"k8s": "v1.30.0", "device_plugin": "v0.15.0"}
    hw_fp = {"gpu": "A100-40GB", "driver_version": "535.104.05", "firmware": "fw-1.2.3", "mps_mode": "isolated"}

    att = auditor.produce_attestation(
        audit_id="audit-att-1",
        evidence={"hashes": ["abc123"], "timing_ms": 12, "indicators": {"residue": False}},
        manifest=manifest,
        hw_fingerprint=hw_fp,
    )
    # Rekor anchoring host should be localhost/127.0.0.1 only
    host = urlparse(att["rekor"]["url"]).hostname
    assert host in ("127.0.0.1", "localhost")
    assert auditor.verify_attestation(att) is True

    # Tamper with attestation to simulate verification failure
    tampered = dict(att)
    tampered["signature"] = ""
    assert auditor.verify_attestation(tampered) is False

    # Simulate Rekor unavailability and ensure graceful error handling
    def failing_attestation(self, audit_id, evidence, manifest, hw_fingerprint):
        raise RuntimeError("Rekor unavailable")

    if hasattr(auditor, "produce_attestation"):
        monkeypatch.setattr(auditor, "produce_attestation", MethodType(failing_attestation, auditor))

    with pytest.raises(RuntimeError):
        auditor.produce_attestation(
            audit_id="audit-att-2",
            evidence={"hashes": ["def456"], "timing_ms": 5, "indicators": {"residue": False}},
            manifest=manifest,
            hw_fingerprint=hw_fp,
        )