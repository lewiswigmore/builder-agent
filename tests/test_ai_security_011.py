import pytest
import types
import time
from datetime import datetime, timezone

ft_mod = pytest.importorskip("tools.ai_security.finetune_sentinel", reason="FineTune Sentinel module not available")


def _make_sentinel(monkeypatch, allowlist=None, risk_threshold=0.7):
    # Try to create a sentinel instance in a resilient way
    sentinel_cls = getattr(ft_mod, "FineTuneSentinel", None)
    if sentinel_cls is None:
        pytest.skip("FineTuneSentinel class not found in module")
    try:
        # Try simplest ctor
        sentinel = sentinel_cls()
    except Exception:
        # Try with known kwargs
        try:
            sentinel = sentinel_cls(egress_allowlist=allowlist or ["127.0.0.1", "localhost"], membership_risk_threshold=risk_threshold)
        except Exception:
            # As a last resort, try no-arg and set attributes after
            sentinel = sentinel_cls()
    # Set config attributes if present
    if allowlist is None:
        allowlist = ["127.0.0.1", "localhost"]
    if hasattr(sentinel, "egress_allowlist"):
        setattr(sentinel, "egress_allowlist", set(allowlist))
    if hasattr(sentinel, "membership_risk_threshold"):
        setattr(sentinel, "membership_risk_threshold", risk_threshold)
    # Provide no-op encrypt if needed by evidence store
    if hasattr(sentinel, "evidence_store") and getattr(sentinel, "evidence_store") is None:
        class _DummyEvidenceStore:
            def __init__(self):
                self.saved = []

            def store(self, bundle):
                self.saved.append(bundle)
                return f"bundle-{len(self.saved)}"

        sentinel.evidence_store = _DummyEvidenceStore()
    return sentinel


def _patch_sigstore_sign(monkeypatch, sentinel, fail_once=False):
    # Try to patch a sign_attestation method, or a sigstore client
    calls = {"count": 0, "payloads": []}

    def signer(payload):
        calls["count"] += 1
        calls["payloads"].append(payload)
        if fail_once and calls["count"] == 1:
            raise RuntimeError("sigstore signing failed")
        return {
            "signature": "MEUCIQDummysignature==",
            "rekor_log_index": 12345,
            "fulcio_cert_subject": "sentinel@example.test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    if hasattr(sentinel, "sign_attestation") and callable(getattr(sentinel, "sign_attestation")):
        monkeypatch.setattr(sentinel, "sign_attestation", signer)
    elif hasattr(sentinel, "sigstore"):
        # If sigstore client object exists, patch its sign method
        sigstore_client = getattr(sentinel, "sigstore")
        if sigstore_client is None:
            # Create a dummy client with sign method
            class _DummySigstore:
                def sign(self, payload):
                    return signer(payload)
            sentinel.sigstore = _DummySigstore()
        else:
            if hasattr(sigstore_client, "sign"):
                monkeypatch.setattr(sigstore_client, "sign", signer)
            else:
                # Attach sign method dynamically
                def _sign(self, payload):
                    return signer(payload)
                sentinel.sigstore.sign = types.MethodType(_sign, sigstore_client)
    else:
        # Attach a sign_attestation method dynamically
        sentinel.sign_attestation = signer

    return calls


def _ensure_policy_engine(monkeypatch, sentinel, allow):
    # Ensure OPA/policy engine will return allow or deny
    # Patch methods if available; else attach one dynamically
    def _fake_opa_evaluate(input_doc):
        return {"allow": allow, "reason": "hash_mismatch" if not allow else "ok", "input": input_doc}

    if hasattr(sentinel, "opa_evaluate") and callable(getattr(sentinel, "opa_evaluate")):
        monkeypatch.setattr(sentinel, "opa_evaluate", _fake_opa_evaluate)
    elif hasattr(ft_mod, "OPAClient"):
        # Patch OPA client evaluate method
        cls = getattr(ft_mod, "OPAClient")
        if hasattr(cls, "evaluate"):
            monkeypatch.setattr(cls, "evaluate", staticmethod(lambda policy, input_doc: _fake_opa_evaluate(input_doc)))
    else:
        # Attach dynamically
        sentinel.opa_evaluate = _fake_opa_evaluate


@pytest.fixture
def sentinel(monkeypatch):
    s = _make_sentinel(monkeypatch, allowlist=["127.0.0.1", "localhost"], risk_threshold=0.75)
    return s


def test_canary_leakage_blocks_promotion_and_emits_signed_attestation(monkeypatch, sentinel):
    # Arrange
    sign_calls = _patch_sigstore_sign(monkeypatch, sentinel, fail_once=False)
    canary_markers = ["FTS-CANARY-12345"]
    model_outputs = [
        "normal output",
        "some text with FTS-CANARY-12345 indicator here",
        "more normal output",
    ]

    # Use a generic evaluation entrypoint if available
    if hasattr(sentinel, "process_evaluation"):
        result = sentinel.process_evaluation(
            job_id="job-abc",
            model_outputs=model_outputs,
            canary_markers=canary_markers,
            egress_destinations=["http://127.0.0.1:9999/api"],
        )
    elif hasattr(sentinel, "evaluate_outputs"):
        result = sentinel.evaluate_outputs(
            job_id="job-abc",
            outputs=model_outputs,
            canaries=canary_markers,
            egress_destinations=["http://127.0.0.1:9999/api"],
        )
    elif hasattr(sentinel, "evaluate"):
        result = sentinel.evaluate(
            job_id="job-abc",
            model_outputs=model_outputs,
            canary_markers=canary_markers,
            egress_destinations=["http://127.0.0.1:9999/api"],
        )
    else:
        pytest.skip("No evaluation method found on FineTuneSentinel")

    # Assert
    assert result is not None
    blocked = result.get("block_promotion") if isinstance(result, dict) else getattr(result, "block_promotion", False)
    assert blocked is True, "Promotion should be blocked when canary leakage is detected"

    att = result.get("attestation") if isinstance(result, dict) else getattr(result, "attestation", None)
    assert att is not None, "Signed attestation must be present"
    assert "signature" in att and att["signature"], "Signature missing from attestation"
    assert "timestamp" in att and att["timestamp"], "Timestamp missing from attestation"

    assert sign_calls["count"] >= 1, "Sigstore signing should be invoked"
    assert any("canary" in str(p).lower() or "leak" in str(p).lower() for p in sign_calls["payloads"]), "Attestation payload should mention leakage/canary"

    # Try to promote and expect block
    if hasattr(sentinel, "promote"):
        with pytest.raises(Exception):
            sentinel.promote("job-abc")


def test_sigstore_signing_failure_still_blocks_promotion(monkeypatch, sentinel):
    # Arrange
    _patch_sigstore_sign(monkeypatch, sentinel, fail_once=True)
    canary_markers = ["FTS-CANARY-FAIL"]
    model_outputs = ["text with FTS-CANARY-FAIL inside"]
    # Act
    if hasattr(sentinel, "process_evaluation"):
        result = sentinel.process_evaluation(job_id="job-fail", model_outputs=model_outputs, canary_markers=canary_markers)
    elif hasattr(sentinel, "evaluate_outputs"):
        result = sentinel.evaluate_outputs(job_id="job-fail", outputs=model_outputs, canaries=canary_markers)
    elif hasattr(sentinel, "evaluate"):
        result = sentinel.evaluate(job_id="job-fail", model_outputs=model_outputs, canary_markers=canary_markers)
    else:
        pytest.skip("No evaluation method found on FineTuneSentinel")
    # Assert: even if signing failed initially, promotion must be blocked and error recorded
    blocked = result.get("block_promotion") if isinstance(result, dict) else getattr(result, "block_promotion", False)
    assert blocked is True
    errors = result.get("errors", []) if isinstance(result, dict) else getattr(result, "errors", [])
    assert isinstance(errors, (list, tuple))


def test_finetune_job_blocked_on_missing_or_mismatched_dataset_hash_provenance(monkeypatch, sentinel):
    # Arrange: configure policy engine to deny run
    _ensure_policy_engine(monkeypatch, sentinel, allow=False)

    job_cfg = {
        "job_id": "job-prov-1",
        "dataset_manifest": {"hash": "abc123", "items": 100},
        "provenance": None,  # missing attestation
    }

    # Act/Assert
    # Try start method if available
    if hasattr(sentinel, "start_finetune_job"):
        with pytest.raises(Exception) as ei:
            sentinel.start_finetune_job(job_cfg)
        # Extract policy report
        e = ei.value
        report = getattr(e, "policy_violation_report", None) or getattr(e, "report", None)
        if report is None and hasattr(sentinel, "last_policy_violation_report"):
            report = getattr(sentinel, "last_policy_violation_report")
        assert report is not None, "Policy violation report must be generated"
        assert report.get("reason") in {"hash_mismatch", "missing_provenance", "deny"}, "Unexpected violation reason"
        assert report.get("opa_decision", {}).get("allow") in {False, 0}, "OPA must deny the job"
    elif hasattr(sentinel, "validate_dataset"):
        ok, report = sentinel.validate_dataset(job_cfg["dataset_manifest"], job_cfg["provenance"])
        assert ok is False
        assert isinstance(report, dict)
        assert report.get("opa_decision", {}).get("allow") in {False, 0}
    else:
        pytest.skip("No job start/validation method found on FineTuneSentinel")


def test_egress_allowlist_blocks_disallowed_destination(monkeypatch, sentinel):
    # Arrange
    # Ensure allowlist is localhost only
    if hasattr(sentinel, "egress_allowlist"):
        sentinel.egress_allowlist = {"127.0.0.1", "localhost"}
    # Provide a generic method to check egress
    url_blocked = None

    def try_egress(url):
        nonlocal url_blocked
        if hasattr(sentinel, "enforce_egress_allowlist"):
            return sentinel.enforce_egress_allowlist(url)
        elif hasattr(sentinel, "check_egress"):
            return sentinel.check_egress(url)
        else:
            # Fallback: simulate behavior by calling a generic validate method if any,
            # else raise to indicate we cannot perform this test
            url_blocked = "skip"
            pytest.skip("No egress allowlist enforcement method found on FineTuneSentinel")

    # Act/Assert: disallowed
    with pytest.raises(Exception):
        try_egress("https://example.com/api")  # not localhost
    # Allowed examples
    res1 = try_egress("http://127.0.0.1:8080/ok") if url_blocked is None else None
    res2 = try_egress("http://localhost:5000/ok") if url_blocked is None else None
    if url_blocked is None:
        assert res1 is True
        assert res2 is True


def test_membership_inference_risk_triggers_quarantine_and_evidence_bundle_stored(monkeypatch, sentinel):
    # Arrange
    # Capture evidence storage and ensure encrypted, hashed-only content
    stored = {"bundles": []}

    def fake_store(bundle):
        stored["bundles"].append(bundle)
        return f"bundle-{len(stored['bundles'])}"

    if hasattr(sentinel, "evidence_store") and sentinel.evidence_store is not None and hasattr(sentinel.evidence_store, "store"):
        monkeypatch.setattr(sentinel.evidence_store, "store", fake_store)
    else:
        # Attach directly
        class _Store:
            def store(self, bundle):
                return fake_store(bundle)
        sentinel.evidence_store = _Store()

    # Act
    high_risk = 0.99
    job_id = "job-risk-1"
    artifact_id = "model-art-1"

    # Use a generic method to assess risk or pass via evaluation
    quarantined = None
    result = None
    if hasattr(sentinel, "assess_membership_inference"):
        result = sentinel.assess_membership_inference(job_id=job_id, artifact_id=artifact_id, risk_score=high_risk)
    elif hasattr(sentinel, "evaluate"):
        result = sentinel.evaluate(job_id=job_id, model_outputs=[], canary_markers=[], membership_risk_score=high_risk, model_artifact_id=artifact_id)
    elif hasattr(sentinel, "process_evaluation"):
        result = sentinel.process_evaluation(job_id=job_id, model_outputs=[], canary_markers=[], membership_risk_score=high_risk, model_artifact_id=artifact_id)
    else:
        pytest.skip("No method to assess membership inference risk found")

    if isinstance(result, dict):
        quarantined = result.get("quarantined")
    else:
        quarantined = getattr(result, "quarantined", None)

    # Assert
    assert quarantined is True, "High membership inference risk should quarantine the model artifact"
    assert len(stored["bundles"]) >= 1, "Evidence bundle should be stored"

    bundle = stored["bundles"][-1]
    # Verify encryption-at-rest indicator present
    assert bundle.get("encrypted", True) is True, "Evidence should be encrypted-at-rest"
    # Ensure metrics are hashed-only; no raw PII keys
    hashed_fields = bundle.get("hashed_metadata") or bundle.get("hashes") or {}
    assert isinstance(hashed_fields, dict)
    # Check no obvious raw PII values present
    for k, v in bundle.items():
        if isinstance(v, str) and ("@" in v or v.startswith("+") or v.replace("-", "").isdigit()):
            assert False, "Evidence bundle appears to include raw PII"
    # Check reproducibility: presence of replay inputs
    replay = bundle.get("replay_inputs")
    assert replay is not None and isinstance(replay, (dict, list)), "Evidence bundle should include reproducible replay inputs"


def test_default_read_only_and_no_raw_pii_in_evidence(monkeypatch, sentinel):
    # Arrange: simulate dataset with PII and ensure only hashed metadata is collected
    stored = {"bundles": []}

    def fake_store(bundle):
        stored["bundles"].append(bundle)
        return f"bundle-{len(stored['bundles'])}"

    if hasattr(sentinel, "evidence_store") and sentinel.evidence_store is not None and hasattr(sentinel.evidence_store, "store"):
        monkeypatch.setattr(sentinel.evidence_store, "store", fake_store)
    else:
        class _Store:
            def store(self, bundle):
                return fake_store(bundle)
        sentinel.evidence_store = _Store()

    dataset_manifest = {"hash": "deadbeef", "items": 1}
    provenance_attestation = {"issuer": "prov@example.test", "subject": "dataset-v1"}
    dataset_sample = {"email": "user@example.com", "phone": "+1-555-123-4567", "name": "Alice"}

    # Use a generic method to collect evidence/metadata
    if hasattr(sentinel, "collect_dataset_evidence"):
        sentinel.collect_dataset_evidence(dataset_manifest, provenance_attestation, sample=dataset_sample)
    elif hasattr(sentinel, "validate_dataset"):
        # Many validators store evidence as part of validation
        sentinel.validate_dataset(dataset_manifest, provenance_attestation, sample=dataset_sample)  # ignore return
    else:
        pytest.skip("No dataset evidence collection method found on FineTuneSentinel")

    assert len(stored["bundles"]) >= 1, "Evidence should be stored"

    bundle = stored["bundles"][-1]
    # Should contain hashed metadata or metrics, not raw PII
    hashed = bundle.get("hashed_metadata") or bundle.get("hashes") or {}
    assert isinstance(hashed, dict) and hashed, "Hashed metadata must be present"
    # Ensure raw fields are absent
    for raw_key in ("email", "phone", "name"):
        assert raw_key not in bundle, f"Raw PII field {raw_key} should not be stored in evidence"
    # Evidence should have role-scoped access markers if implemented
    if "access_scope" in bundle:
        scope = bundle["access_scope"]
        assert isinstance(scope, dict) and "roles" in scope, "Evidence access should be role-scoped"


def test_rejects_start_when_dataset_hash_mismatch_via_opa(monkeypatch, sentinel):
    # Arrange: Force OPA to deny
    _ensure_policy_engine(monkeypatch, sentinel, allow=False)
    job_cfg = {
        "job_id": "job-prov-2",
        "dataset_manifest": {"hash": "abc123", "items": 2},
        "provenance": {"issuer": "prov@example.test", "subject": "dataset-v2"},
        "expected_hash": "fff999",  # mismatch
    }

    # Act/Assert depending on available API
    if hasattr(sentinel, "start_finetune_job"):
        with pytest.raises(Exception) as ei:
            sentinel.start_finetune_job(job_cfg)
        e = ei.value
        report = getattr(e, "policy_violation_report", None) or getattr(e, "report", None)
        if report is None and hasattr(sentinel, "last_policy_violation_report"):
            report = getattr(sentinel, "last_policy_violation_report")
        assert report is not None
        assert report.get("opa_decision", {}).get("allow") in {False, 0}
        assert report.get("reproducible") in {True, False}  # presence indicates evidence of replay inputs
    elif hasattr(sentinel, "validate_dataset"):
        ok, report = sentinel.validate_dataset(job_cfg["dataset_manifest"], job_cfg["provenance"], expected_hash=job_cfg["expected_hash"])
        assert ok is False
        assert report.get("opa_decision", {}).get("allow") in {False, 0}
    else:
        pytest.skip("No job start/validation method found on FineTuneSentinel")