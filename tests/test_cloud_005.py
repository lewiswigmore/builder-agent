import pytest
from unittest.mock import MagicMock, patch
import time

probe_mod = pytest.importorskip("tools.cloud.dataperimeter_probe")
DataPerimeterProbe = getattr(probe_mod, "DataPerimeterProbe", None)
if DataPerimeterProbe is None:
    pytest.skip("DataPerimeterProbe not found in tools.cloud.dataperimeter_probe", allow_module_level=True)


@pytest.fixture
def fixed_time(monkeypatch):
    fixed = 1_700_000_000
    monkeypatch.setattr(time, "time", lambda: fixed)
    return fixed


@pytest.fixture
def probe(monkeypatch, fixed_time):
    # Construct probe with minimal config satisfying allowlists and rate limits
    # Assumes DataPerimeterProbe accepts a config dict; adjust if needed in implementation.
    cfg = {
        "allowlist": {
            "accounts": ["acct-test"],
            "projects": ["proj-test"],
            "regions": ["us-east-1", "us-west-2"]
        },
        "rate_limit": {"max_per_minute": 5},
        "labels": {"dp_canary": "true"},
        "ttl_seconds": 3600,
        "immutable_logging": True,
        "log_correlation_prefix": "corr-",
    }
    p = DataPerimeterProbe(config=cfg)

    # Force deterministic correlation IDs
    if hasattr(p, "_generate_correlation_id"):
        monkeypatch.setattr(p, "_generate_correlation_id", lambda: "corr-fixed-001")
    elif hasattr(p, "generate_correlation_id"):
        monkeypatch.setattr(p, "generate_correlation_id", lambda: "corr-fixed-001")

    # Provide a fake immutable log store if accessible
    class FakeImmutableStore:
        def __init__(self):
            self._store = {}
            self._sealed = set()

        def append(self, correlation_id, record):
            if correlation_id in self._sealed:
                raise RuntimeError("Immutable store: cannot append to sealed correlation_id")
            self._store.setdefault(correlation_id, []).append(record)

        def seal(self, correlation_id):
            self._sealed.add(correlation_id)

        def get(self, correlation_id):
            # Return a copy to avoid mutation
            return list(self._store.get(correlation_id, []))

    fake_store = FakeImmutableStore()

    # Monkeypatch logging sinks if available
    if hasattr(p, "immutable_log_store"):
        p.immutable_log_store = fake_store
    elif hasattr(p, "_immutable_log_store"):
        setattr(p, "_immutable_log_store", fake_store)

    # Replace any real network HTTP clients with a local stub to respect network rules
    if hasattr(probe_mod, "requests"):
        monkeypatch.setattr(probe_mod, "requests", MagicMock())
    return p


def _set_logging_hooks(probe, monkeypatch, records):
    def log_action(action, correlation_id=None, **kwargs):
        rec = {"action": action, "correlation_id": correlation_id}
        rec.update(kwargs)
        records.append(rec)
        # Also try to persist to immutable store if available
        store = getattr(probe, "immutable_log_store", getattr(probe, "_immutable_log_store", None))
        if store:
            store.append(correlation_id or "unknown", rec)

    if hasattr(probe, "_log_action"):
        monkeypatch.setattr(probe, "_log_action", log_action)
    elif hasattr(probe, "log_action"):
        monkeypatch.setattr(probe, "log_action", log_action)
    return records


def test_detects_untrusted_egress_on_unconstrained_bucket(monkeypatch, probe):
    # Acceptance: simulate egress read from untrusted network on bucket missing constraints
    logs = _set_logging_hooks(probe, monkeypatch, [])

    # Simulate missing VPC/Private Endpoint constraints
    if hasattr(probe, "_get_bucket_constraints"):
        monkeypatch.setattr(probe, "_get_bucket_constraints", lambda bucket_id: {})
    elif hasattr(probe, "get_bucket_constraints"):
        monkeypatch.setattr(probe, "get_bucket_constraints", lambda bucket_id: {})

    # Network trust evaluation
    if hasattr(probe, "_network_is_trusted"):
        monkeypatch.setattr(probe, "_network_is_trusted", lambda ctx: False)
    elif hasattr(probe, "network_is_trusted"):
        monkeypatch.setattr(probe, "network_is_trusted", lambda ctx: False)

    # Prevent any production modifications
    for attr in ("apply_bucket_policy", "put_bucket_policy", "update_bucket_policy"):
        if hasattr(probe, attr):
            monkeypatch.setattr(probe, attr, lambda *a, **k: (_ for _ in ()).throw(AssertionError("No destructive policy changes allowed")))

    # Simulate read succeeds (indicating leak)
    perf_called = {"called": 0}

    def fake_perform_read(bucket_id, network_context):
        perf_called["called"] += 1
        return {"status": "success", "bytes": 123, "source_ip": network_context.get("source_ip")}

    if hasattr(probe, "_perform_egress_read"):
        monkeypatch.setattr(probe, "_perform_egress_read", fake_perform_read)
    elif hasattr(probe, "perform_egress_read"):
        monkeypatch.setattr(probe, "perform_egress_read", fake_perform_read)

    # Run probe
    if hasattr(probe, "run_egress_probe"):
        result = probe.run_egress_probe(bucket_id="bucket-no-vpc", network_context={"source_ip": "127.0.0.1", "trusted": False})
    else:
        # Fallback: simulate via generic run or method pattern
        run_method = getattr(probe, "run", None) or getattr(probe, "probe_egress", None)
        assert callable(run_method), "Probe does not expose a run method for egress tests"
        result = run_method(target="bucket-no-vpc", network_context={"source_ip": "127.0.0.1", "trusted": False}, mode="egress")

    assert result.get("detected") is True, "Leak should be detected from untrusted network"
    assert "bucket-no-vpc" in result.get("leak_path", ""), "Leak path should include bucket id"
    remediation = result.get("remediation", "").lower()
    assert "vpc" in remediation or "private endpoint" in remediation, "Remediation should suggest VPC/Private Endpoint constraints"
    assert result.get("correlation_id") == "corr-fixed-001", "Correlation ID should be propagated"
    assert perf_called["called"] == 1, "Egress read should be attempted exactly once"

    # Verify logging with correlation ID and immutable persistence
    store = getattr(probe, "immutable_log_store", getattr(probe, "_immutable_log_store", None))
    assert any(rec.get("action") in ("egress_read", "egress_probe") for rec in logs)
    if store:
        persisted = store.get("corr-fixed-001")
        assert persisted, "Actions should be stored immutably with correlation id"
        assert any(r.get("action") in ("egress_read", "egress_probe") for r in persisted)


def test_presigned_url_cross_region_detection_and_correlation(monkeypatch, probe, fixed_time):
    # Acceptance: Create presigned URL, attempt cross-region access, verify detection and log correlation
    logs = _set_logging_hooks(probe, monkeypatch, [])

    # Mock signer to produce deterministic token and enforce expiry
    def fake_sign(payload):
        return "sig-fixed-abc123"

    def fake_validate(token, now=None):
        # Ensure time-bounded tokens are validated against fixed time
        now = now if now is not None else time.time()
        parts = dict(p.split("=", 1) for p in token.split("&"))
        exp = int(parts.get("exp", "0"))
        return now <= exp and parts.get("sig") == "sig-fixed-abc123"

    for sign_attr in ("_sign_token", "sign_token"):
        if hasattr(probe, sign_attr):
            monkeypatch.setattr(probe, sign_attr, fake_sign)
    for val_attr in ("_validate_token", "validate_token"):
        if hasattr(probe, val_attr):
            monkeypatch.setattr(probe, val_attr, fake_validate)

    # Create presigned URL builder
    def fake_create_presigned_url(resource_id, region, expires_in=300):
        exp = int(time.time() + expires_in)
        token = f"sig=sig-fixed-abc123&exp={exp}&rid={resource_id}"
        # Use localhost to satisfy network test rule
        return f"http://127.0.0.1/{resource_id}?{token}", {"token": token, "expires": exp, "correlation_id": "corr-fixed-001"}

    create_name = None
    for attr in ("create_presigned_url", "_create_presigned_url"):
        if hasattr(probe, attr):
            create_name = attr
            monkeypatch.setattr(probe, attr, fake_create_presigned_url)
            break
    assert create_name is not None, "Probe must expose presigned URL creation method"

    # Simulate cross-region access detection and cloud log correlation
    def fake_attempt_presigned_access(url, from_region):
        # Simulate that the URL region is us-east-1 and access from us-west-2 triggers detection
        detected = from_region != "us-east-1"
        return {
            "detected": detected,
            "event": "cross_region_access",
            "correlation_id": "corr-fixed-001",
            "logs": {
                "cloudtrail": {"matched": True, "eventName": "GetObject", "region": "us-east-1"},
                "azure_activity": None,
                "gcp_audit": None,
            },
        }

    attempt_name = None
    for attr in ("attempt_presigned_access", "_attempt_presigned_access"):
        if hasattr(probe, attr):
            attempt_name = attr
            monkeypatch.setattr(probe, attr, fake_attempt_presigned_access)
            break
    assert attempt_name is not None, "Probe must expose presigned URL access attempt method"

    # Run flow
    url, meta = getattr(probe, create_name)("canary-object-1", region="us-east-1", expires_in=300)
    result = getattr(probe, attempt_name)(url, from_region="us-west-2")

    assert result["detected"] is True, "Cross-region access should be detected"
    assert result["correlation_id"] == "corr-fixed-001", "Correlation ID should match"
    # Verify logs include CloudTrail/Azure Activity/GCP Audit structure
    logs_struct = result.get("logs") or {}
    assert "cloudtrail" in logs_struct, "CloudTrail correlation missing"
    assert logs_struct["cloudtrail"].get("matched") is True
    # Ensure action logs were written with the correlation id
    assert any(rec.get("correlation_id") == "corr-fixed-001" for rec in logs)


def test_auto_cleanup_removes_only_labeled_canaries(monkeypatch, probe, fixed_time):
    # Acceptance: Auto-cleanup removes only labeled canary resources and no production modifications
    # Prepare candidate resources: two canaries (one expired, one not) and one production
    canary_expired = {
        "id": "bucket/canary-expired",
        "labels": {"dp_canary": "true", "ttl": str(fixed_time - 10)},
        "type": "object",
    }
    canary_active = {
        "id": "bucket/canary-active",
        "labels": {"dp_canary": "true", "ttl": str(fixed_time + 9999)},
        "type": "object",
    }
    production_obj = {
        "id": "bucket/prod-object",
        "labels": {"env": "prod"},
        "type": "object",
    }
    production_bucket = {
        "id": "bucket/prod-bucket",
        "labels": {"env": "prod"},
        "type": "bucket",
    }
    resources = [canary_expired, canary_active, production_obj, production_bucket]

    # Mock lister
    if hasattr(probe, "_list_candidate_resources"):
        monkeypatch.setattr(probe, "_list_candidate_resources", lambda: list(resources))
    elif hasattr(probe, "list_candidate_resources"):
        monkeypatch.setattr(probe, "list_candidate_resources", lambda: list(resources))

    # Track deletions and policy changes
    deleted = []
    policy_changes = {"count": 0}

    def fake_delete(res_id):
        deleted.append(res_id)
        return True

    for attr in ("_delete_resource", "delete_resource"):
        if hasattr(probe, attr):
            monkeypatch.setattr(probe, attr, fake_delete)

    def forbid_policy_change(*args, **kwargs):
        policy_changes["count"] += 1
        raise AssertionError("No production bucket policy modifications allowed during cleanup")

    for attr in ("apply_bucket_policy", "put_bucket_policy", "update_bucket_policy"):
        if hasattr(probe, attr):
            monkeypatch.setattr(probe, attr, forbid_policy_change)

    # Run cleanup
    cleanup_method = getattr(probe, "cleanup_canary_resources", getattr(probe, "_cleanup_canary_resources", None))
    assert callable(cleanup_method), "Probe must support cleanup_canary_resources"
    result = cleanup_method()

    # Validate only expired canary deleted
    assert "bucket/canary-expired" in deleted
    assert "bucket/canary-active" not in deleted
    assert "bucket/prod-object" not in deleted
    assert "bucket/prod-bucket" not in deleted
    # Ensure return structure consistent
    removed = result.get("removed") or result.get("deleted") or []
    skipped = result.get("skipped") or []
    assert any("canary-expired" in r for r in removed)
    assert any("prod-object" in s or "canary-active" in s or "prod-bucket" in s for s in skipped)
    assert policy_changes["count"] == 0


def test_rate_limited_probes_and_auto_pause(monkeypatch, probe):
    # Requirements: Rate-limited probes with allowlists; auto pause on anomaly spikes/guardrail violations.
    # Simulate a strict rate limiter allowing 1 op, then block subsequent attempts and trigger pause.
    state = {"count": 0}

    def fake_rate_limit_check():
        state["count"] += 1
        return state["count"] <= 1

    for attr in ("_rate_limit_ok", "rate_limit_ok"):
        if hasattr(probe, attr):
            monkeypatch.setattr(probe, attr, fake_rate_limit_check)

    def fake_pause(reason):
        setattr(probe, "paused", True)
        setattr(probe, "pause_reason", reason)

    for attr in ("_pause_on_violation", "pause_on_violation"):
        if hasattr(probe, attr):
            monkeypatch.setattr(probe, attr, fake_pause)

    # First probe should pass, second should cause pause
    if hasattr(probe, "run_egress_probe"):
        probe.run_egress_probe(bucket_id="bucket-rl-1", network_context={"source_ip": "127.0.0.1", "trusted": True})
        probe.run_egress_probe(bucket_id="bucket-rl-2", network_context={"source_ip": "127.0.0.1", "trusted": True})
    else:
        run_method = getattr(probe, "run", None) or getattr(probe, "probe_egress", None)
        run_method(target="bucket-rl-1", network_context={"source_ip": "127.0.0.1", "trusted": True}, mode="egress")
        run_method(target="bucket-rl-2", network_context={"source_ip": "127.0.0.1", "trusted": True}, mode="egress")

    assert getattr(probe, "paused", False) is True
    assert hasattr(probe, "pause_reason")


def test_canary_tokens_are_unique_signed_and_time_bounded(monkeypatch, probe, fixed_time):
    # Requirements: Canary objects and tokens are uniquely identified, signed, and time-bounded
    # Sign and validate two tokens; ensure uniqueness and expiry enforcement.
    sign = getattr(probe, "_sign_token", getattr(probe, "sign_token", None))
    validate = getattr(probe, "_validate_token", getattr(probe, "validate_token", None))
    assert callable(sign) and callable(validate), "Probe must expose token sign/validate"

    token1_sig = sign({"rid": "r1", "ts": fixed_time})
    token2_sig = sign({"rid": "r2", "ts": fixed_time})
    assert token1_sig != token2_sig or "sig-fixed" in token1_sig, "Signatures should be unique per payload"

    # Compose tokens with expiry
    t1 = f"sig={token1_sig}&exp={fixed_time + 10}&rid=r1"
    t2 = f"sig={token2_sig}&exp={fixed_time - 1}&rid=r2"  # already expired

    assert validate(t1, now=fixed_time) is True, "Valid, unexpired token should pass"
    assert validate(t2, now=fixed_time) is False, "Expired token should fail validation"


def test_allowlists_enforced(monkeypatch, probe):
    # Requirements: Explicit allowlists enforced for account/project/region
    # Simulate context outside allowlist and expect rejection/skip
    disallowed_ctx = {"account": "acct-other", "project": "proj-other", "region": "eu-central-1"}
    was_checked = {"called": False}

    def fake_check_allowlist(ctx):
        was_checked["called"] = True
        return False

    for attr in ("_is_allowed_context", "is_allowed_context"):
        if hasattr(probe, attr):
            monkeypatch.setattr(probe, attr, fake_check_allowlist)

    with pytest.raises(Exception):
        if hasattr(probe, "run_egress_probe"):
            probe.run_egress_probe(bucket_id="bucket-disallowed", network_context={"source_ip": "127.0.0.1", "trusted": True}, context=disallowed_ctx)
        else:
            run_method = getattr(probe, "run", None) or getattr(probe, "probe_egress", None)
            run_method(target="bucket-disallowed", network_context={"source_ip": "127.0.0.1", "trusted": True}, mode="egress", context=disallowed_ctx)
    assert was_checked["called"] is True


def test_error_handling_and_no_destructive_ops(monkeypatch, probe):
    # Requirements: Test error handling; ensure no destructive operations on production assets
    # Force an error during network read and ensure it is logged and handled gracefully.
    errors = []

    def failing_read(*args, **kwargs):
        raise RuntimeError("Simulated network read failure")

    if hasattr(probe, "_perform_egress_read"):
        monkeypatch.setattr(probe, "_perform_egress_read", failing_read)
    elif hasattr(probe, "perform_egress_read"):
        monkeypatch.setattr(probe, "perform_egress_read", failing_read)

    def collect_log(action, correlation_id=None, **kwargs):
        errors.append((action, kwargs.get("error")))

    if hasattr(probe, "_log_action"):
        monkeypatch.setattr(probe, "_log_action", collect_log)
    elif hasattr(probe, "log_action"):
        monkeypatch.setattr(probe, "log_action", collect_log)

    # Forbid any destructive op
    for attr in ("apply_bucket_policy", "put_bucket_policy", "update_bucket_policy", "delete_resource"):
        if hasattr(probe, attr):
            monkeypatch.setattr(probe, attr, lambda *a, **k: (_ for _ in ()).throw(AssertionError("No destructive operations allowed")))

    # Run and assert graceful error reporting
    if hasattr(probe, "run_egress_probe"):
        result = probe.run_egress_probe(bucket_id="bucket-error", network_context={"source_ip": "127.0.0.1", "trusted": True})
    else:
        run_method = getattr(probe, "run", None) or getattr(probe, "probe_egress", None)
        result = run_method(target="bucket-error", network_context={"source_ip": "127.0.0.1", "trusted": True}, mode="egress")

    assert result.get("detected") in (False, None)
    assert "error" in result
    assert any(act == "error" or err is not None for act, err in errors)