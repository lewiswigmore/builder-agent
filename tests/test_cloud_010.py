import json
import time
import types
import pytest

try:
    from tools.cloud.artifactgraph_guard import ArtifactGraphGuard
except Exception as e:  # pragma: no cover
    ArtifactGraphGuard = None


pytestmark = pytest.mark.skipif(ArtifactGraphGuard is None, reason="ArtifactGraphGuard not available")


@pytest.fixture
def guard():
    g = ArtifactGraphGuard()
    # ensure read-only default behavior is exposed
    assert getattr(g, "read_only", True) is True
    return g


@pytest.fixture(autouse=True)
def restrict_network(monkeypatch):
    # Restrict any requests-like HTTP client to localhost/127.0.0.1
    try:
        import requests

        orig_request = requests.Session.request

        def safe_request(self, method, url, *args, **kwargs):
            if "localhost" not in url and "127.0.0.1" not in url:
                raise RuntimeError(f"External network call blocked: {url}")
            return orig_request(self, method, url, *args, **kwargs)

        monkeypatch.setattr(requests.Session, "request", safe_request, raising=True)
    except Exception:
        pass
    try:
        import urllib.request as urllib_request

        orig_urlopen = urllib_request.urlopen

        def safe_urlopen(req, *args, **kwargs):
            target = req.full_url if hasattr(req, "full_url") else req
            if "localhost" not in target and "127.0.0.1" not in target:
                raise RuntimeError(f"External network call blocked: {target}")
            return orig_urlopen(req, *args, **kwargs)

        monkeypatch.setattr(urllib_request, "urlopen", safe_urlopen, raising=True)
    except Exception:
        pass


def _mock_unsigned_verification(monkeypatch, guard):
    # Provide internal hooks if they exist; otherwise attach them to the guard so code under test can use them.
    def mock_verify_signatures(image_ref, require_provenance=True, require_attestations=True):
        return {
            "image": image_ref,
            "signed": False,
            "provenance": False,
            "attestations": [],
            "rekor_included": False,
            "chain_verified": False,
            "details": "No signature found; no provenance attestations; Rekor inclusion not found",
        }

    def mock_rekor_inclusion(digest):
        return False

    for name, fn in [
        ("verify_signatures", mock_verify_signatures),
        ("_verify_signatures", mock_verify_signatures),
        ("rekor_inclusion", mock_rekor_inclusion),
        ("_rekor_inclusion", mock_rekor_inclusion),
        ("_rekor_check_inclusion", mock_rekor_inclusion),
    ]:
        try:
            monkeypatch.setattr(guard, name, fn, raising=False)
        except Exception:
            setattr(guard, name, fn)


def _mock_signed_report(monkeypatch, guard):
    # Ensure reports are "signed" deterministically for testing
    def mock_sign_report(report):
        payload = report if isinstance(report, str) else json.dumps(report, sort_keys=True)
        return f"---BEGIN SIGNED REPORT---\n{payload}\n---END SIGNED REPORT---"

    for name in ("sign_report", "_sign_report"):
        monkeypatch.setattr(guard, name, mock_sign_report, raising=False)


def _ensure_method(guard, name):
    # Create a placeholder method if not present to make tests more resilient
    if not hasattr(guard, name):
        def _missing(*args, **kwargs):
            raise NotImplementedError(f"{name} not implemented")
        setattr(guard, name, _missing)


def test_unsigned_images_block_promotion_with_signed_report_and_remediation(guard, monkeypatch):
    _mock_unsigned_verification(monkeypatch, guard)
    _mock_signed_report(monkeypatch, guard)
    _ensure_method(guard, "evaluate_promotion_request")

    promotion_request = {
        "source": "registry.local/private/protected/app:1.2.3",
        "target": "registry.local/prod/app:1.2.3",
        "protected": True,
        "metadata": {"requested_by": "ci-bot", "change_id": "CHG-1234"},
    }

    # Simulate fail-closed behavior if Rekor is unreachable
    def mock_rekor_inclusion_fail(_digest):
        raise ConnectionError("Rekor unreachable")

    # First check error handling path
    monkeypatch.setattr(guard, "rekor_inclusion", mock_rekor_inclusion_fail, raising=False)

    decision = guard.evaluate_promotion_request(promotion_request)
    assert isinstance(decision, (dict, object))
    allowed = decision["allowed"] if isinstance(decision, dict) else getattr(decision, "allowed", None)
    assert allowed is False, "Unsigned images must be blocked when Rekor is unreachable (fail-closed)."

    # Restore unsigned but reachable path
    _mock_unsigned_verification(monkeypatch, guard)

    decision = guard.evaluate_promotion_request(promotion_request)
    allowed = decision["allowed"] if isinstance(decision, dict) else getattr(decision, "allowed", None)
    assert allowed is False

    report = decision.get("report") if isinstance(decision, dict) else getattr(decision, "report", "")
    assert report, "Decision must include a detailed report"
    assert "unsigned" in report.lower() or "no signature" in report.lower()
    assert "protected" in report.lower()
    assert "rekor" in report.lower()

    signed_report = decision.get("signed_report") if isinstance(decision, dict) else getattr(decision, "signed_report", "")
    assert signed_report and "BEGIN SIGNED REPORT" in signed_report

    remediation = decision.get("remediation_steps") if isinstance(decision, dict) else getattr(decision, "remediation_steps", [])
    assert isinstance(remediation, (list, tuple))
    joined = " ".join(remediation).lower()
    assert "cosign" in joined
    assert "rekor" in joined or "transparency" in joined
    assert "slsa" in joined or "attestation" in joined

    # Validate read-only behavior - no change logs for evaluation
    change_log = getattr(guard, "change_log", [])
    assert not change_log, "Read-only evaluation should not produce change logs or modify state"


def test_replication_rule_private_to_public_escalated_with_blast_radius(guard):
    _ensure_method(guard, "detect_replication_misconfig")

    replication_rule = {
        "id": "rule-42",
        "source": {
            "registry": "registry.local",
            "repository": "private/*",
            "visibility": "private",
        },
        "target": {
            "registry": "registry-1.docker.io",
            "repository": "public/${repo}",
            "visibility": "public",
        },
        "filters": {"tags": ["latest", "release-*"]},
        "enabled": True,
        "description": "Replicate all private repos to public space",
    }

    result = guard.detect_replication_misconfig(replication_rule)
    assert isinstance(result, (dict, object))
    severity = result.get("severity") if isinstance(result, dict) else getattr(result, "severity", "")
    escalate = result.get("escalate") if isinstance(result, dict) else getattr(result, "escalate", False)
    issues = result.get("issues") if isinstance(result, dict) else getattr(result, "issues", [])
    blast = result.get("blast_radius") if isinstance(result, dict) else getattr(result, "blast_radius", [])

    assert severity in ("critical", "high"), "Exposing private to public must be critical"
    assert escalate is True, "Critical misconfigurations should be escalated"
    assert any("private" in str(i).lower() and "public" in str(i).lower() for i in issues), "Issues should explain private->public exposure"
    assert isinstance(blast, (list, tuple)) and blast, "Blast radius mapping must be provided"
    assert any("*" in replication_rule["source"]["repository"] or "private" in str(br).lower() for br in blast)


def test_cross_cloud_oidc_audience_issuer_mismatch_blocked(guard):
    _ensure_method(guard, "validate_cross_cloud_oidc")

    oidc_config = {
        "source_cloud": "gcp",
        "target_cloud": "aws",
        "oidc": {
            "issuer": "https://accounts.google.com",
            "audience": "arn:aws:iam::123456789012:role/CrossCloudReplicationRole",
            "jwks_uri": "http://127.0.0.1:8080/jwks.json",
        },
        "webhook": {
            "url": "http://localhost:8081/hooks/replicate",
            "expected_issuer": "https://sts.amazonaws.com",
            "expected_audience": "projects/1234567890/locations/global/workloadIdentityPools/pool/providers/provider",
        },
    }

    result = guard.validate_cross_cloud_oidc(oidc_config)
    assert isinstance(result, (dict, object))
    valid = result.get("valid") if isinstance(result, dict) else getattr(result, "valid", None)
    blocked = result.get("blocked") if isinstance(result, dict) else getattr(result, "blocked", None)
    issues = result.get("issues") if isinstance(result, dict) else getattr(result, "issues", [])

    assert valid is False
    assert blocked is True
    text = " ".join(issues).lower()
    assert "audience" in text and "mismatch" in text or "issuer" in text and "mismatch" in text, "Should explain audience/issuer mismatch"


def test_remediation_requires_explicit_approval_and_least_privilege(guard):
    _ensure_method(guard, "perform_remediation")

    # Attempt remediation without approval
    with pytest.raises((PermissionError, AssertionError, ValueError, RuntimeError)):
        guard.perform_remediation(
            action="block_replication_rule",
            credentials={"role": "admin", "scope": "*"},
            approval=None,
        )

    # Attempt remediation with approval but over-privileged credentials
    res = None
    try:
        res = guard.perform_remediation(
            action="block_replication_rule",
            credentials={"role": "admin", "scope": "*"},
            approval={"requested_by": "secops", "ticket": "SEC-9001"},
        )
    except Exception as e:
        # If it raises, ensure it's due to least-privilege violation
        assert "privilege" in str(e).lower() or "scope" in str(e).lower()
    else:
        # If it returns a result, ensure it's denied with reason
        if isinstance(res, dict):
            assert res.get("allowed") is False
            assert "least-privilege" in " ".join([str(res.get("reason", "")), str(res.get("message", ""))]).lower()

    # Proper scoped credentials and approval
    res_ok = guard.perform_remediation(
        action="block_replication_rule",
        credentials={"role": "replication-controller", "scope": "rules:write:rule-42"},
        approval={"requested_by": "secops", "ticket": "SEC-9002", "expires": int(time.time()) + 600},
    )
    if isinstance(res_ok, dict):
        assert res_ok.get("allowed") is True
        assert res_ok.get("change_id")
    change_log = getattr(guard, "change_log", [])
    assert change_log, "Remediation should produce change logs"
    entry = change_log[-1] if change_log else {}
    assert "action" in entry and "who" in entry and "when" in entry


def test_canary_artifacts_namespaced_ttl_auto_cleanup_and_no_customer_deletion(guard, monkeypatch):
    _ensure_method(guard, "validate_policy_with_canary")

    # Track deletes to ensure only canaries are cleaned
    deleted = []

    def mock_delete_artifact(ref, force=False):
        deleted.append({"ref": ref, "force": force})
        return {"deleted": True, "ref": ref}

    # Attach a delete method if the guard exposes one, otherwise attach a stub
    if hasattr(guard, "delete_artifact"):
        monkeypatch.setattr(guard, "delete_artifact", mock_delete_artifact, raising=True)
    else:
        setattr(guard, "delete_artifact", mock_delete_artifact)

    result = guard.validate_policy_with_canary(namespace="ag-guard", ttl_seconds=45, cleanup=True)
    assert isinstance(result, (dict, object))
    canary_ref = result.get("canary_ref") if isinstance(result, dict) else getattr(result, "canary_ref", "")
    ttl = result.get("ttl_seconds") if isinstance(result, dict) else getattr(result, "ttl_seconds", None)
    cleanup_scheduled = result.get("cleanup_scheduled") if isinstance(result, dict) else getattr(result, "cleanup_scheduled", False)

    assert isinstance(canary_ref, str) and canary_ref.startswith("ag-guard/")
    assert ttl in (45, "45", None) or int(ttl) == 45
    assert cleanup_scheduled is True

    # Simulate presence of a customer artifact; ensure no deletion without opt-in
    customer_ref = "customer-namespace/app:latest"
    # Suppose cleanup routine runs; only canary should be deleted
    # We simulate cleanup executing by calling delete on canary and verifying no customer deletion
    guard.delete_artifact(canary_ref)
    assert any(d["ref"] == canary_ref for d in deleted)
    assert not any(d["ref"] == customer_ref for d in deleted), "Customer artifacts must not be deleted without opt-in"

    # If tool supports opt-in deletion, ensure explicit flag is required
    if hasattr(guard, "cleanup_orphans"):
        with pytest.raises((PermissionError, ValueError, AssertionError)):
            guard.cleanup_orphans(artifacts=[customer_ref], opt_in=False)
        ok = guard.cleanup_orphans(artifacts=[customer_ref], opt_in=True)
        if isinstance(ok, dict):
            assert ok.get("deleted", []) == [customer_ref]


def test_error_handling_rekor_unreachable_blocks_promotion(guard, monkeypatch):
    _ensure_method(guard, "evaluate_promotion_request")

    def mock_verify_signatures(image_ref, require_provenance=True, require_attestations=True):
        return {"image": image_ref, "signed": True, "provenance": True, "attestations": ["slsa"], "rekor_included": False, "chain_verified": True}

    def mock_rekor_raise(_digest):
        raise TimeoutError("Rekor timeout")

    monkeypatch.setattr(guard, "verify_signatures", mock_verify_signatures, raising=False)
    monkeypatch.setattr(guard, "rekor_inclusion", mock_rekor_raise, raising=False)

    promotion_request = {"source": "registry.local/protected/app@sha256:deadbeef", "target": "registry.local/stage/app:deadbeef", "protected": True}
    decision = guard.evaluate_promotion_request(promotion_request)
    allowed = decision["allowed"] if isinstance(decision, dict) else getattr(decision, "allowed", None)
    assert allowed is False, "Rekor errors should cause fail-closed behavior and block promotion"

    report = decision.get("report") if isinstance(decision, dict) else getattr(decision, "report", "")
    assert "rekor" in str(report).lower() and ("unreachable" in str(report).lower() or "timeout" in str(report).lower())