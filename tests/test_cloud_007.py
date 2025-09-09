import pytest
import types
import inspect
from datetime import datetime, timezone

# Import the tool under test
import tools.cloud.metasurf_watch as mw


class FakeRateLimiter:
    def __init__(self):
        self.acquires = 0

    def acquire(self):
        self.acquires += 1
        return True


class FakeHTTPClient:
    def __init__(self, allow_hosts=("localhost", "127.0.0.1", "simulated-metadata")):
        self.allow_hosts = set(allow_hosts)
        self.requests = []
        self.raise_timeout = False

    def _check_url(self, url: str):
        self.requests.append(url)
        # Disallow real metadata endpoints explicitly
        forbidden_hosts = ("169.254.169.254", "metadata.google.internal", "metadata", "metadata.google")
        for fh in forbidden_hosts:
            if fh in url:
                raise AssertionError(f"Unsafe metadata access attempted: {url}")
        # Only allow localhost/simulated
        if not any(allowed in url for allowed in self.allow_hosts):
            raise AssertionError(f"External network access attempted: {url}")
        if self.raise_timeout:
            raise TimeoutError("Simulated timeout")

    def get(self, url, *args, **kwargs):
        self._check_url(url)
        return types.SimpleNamespace(status_code=200, text="ok", json=lambda: {"status": "ok"})

    def head(self, url, *args, **kwargs):
        self._check_url(url)
        return types.SimpleNamespace(status_code=200, headers={}, text="")


class FakeSigner:
    def __init__(self, now_fn):
        self.sign_calls = []
        self.now_fn = now_fn

    def sign(self, payload: dict):
        ts = self.now_fn()
        self.sign_calls.append(payload)
        return {
            "signature": "signed:deadbeef",
            "timestamp": ts.isoformat(),
            "public_key_id": "kid-123",
            "workload_identity_proof": {"type": "sa-jwt", "sub": "workload:metasurf-watch"},
        }


class FakeEvidenceStore:
    def __init__(self):
        self.write_calls = []
        self.raise_on_write = False

    def write_once(self, path: str, data: bytes, retention_days: int = 365):
        if self.raise_on_write:
            raise RuntimeError("WORM write failure")
        self.write_calls.append({"path": path, "data": data, "retention_days": retention_days})
        return {"path": path, "retention_days": retention_days}

    # Some implementations might call put or put_object; ensure it's not used by tests
    def put(self, *args, **kwargs):
        raise AssertionError("Non-WORM write attempted")

    def put_object(self, *args, **kwargs):
        raise AssertionError("Non-WORM write attempted")


class FakeTicketClient:
    def __init__(self):
        self.tickets = []
        self.raise_on_create = False

    def create_incident(self, title: str, severity: str, details: dict):
        if self.raise_on_create:
            raise RuntimeError("Ticketing failure")
        self.tickets.append({"title": title, "severity": severity, "details": details})
        return {"id": "INC-12345"}


class FakeCloudClient:
    def __init__(self):
        self.isolation_calls = []
        self.tags = []

    def apply_network_isolation(self, resource_id: str):
        self.isolation_calls.append(resource_id)
        return {"resource_id": resource_id, "status": "isolated"}

    def tag_resource(self, resource_id: str, tags: dict):
        self.tags.append((resource_id, tags))
        return {"resource_id": resource_id, "tags": tags}


class FakeCanaryManager:
    def __init__(self, call_log=None):
        self.revocations = []
        self.call_log = call_log

    def rotate_and_revoke(self, token_id: str):
        self.revocations.append(token_id)
        if self.call_log is not None:
            self.call_log.append(("rotate_and_revoke", token_id))
        return {"token_id": token_id, "status": "revoked"}


@pytest.fixture
def now_fn():
    # Fixed timestamp for deterministic tests
    return lambda: datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


@pytest.fixture
def deps(now_fn):
    rl = FakeRateLimiter()
    http = FakeHTTPClient()
    signer = FakeSigner(now_fn)
    store = FakeEvidenceStore()
    tickets = FakeTicketClient()
    cloud = FakeCloudClient()
    call_log = []
    canary = FakeCanaryManager(call_log=call_log)
    return {
        "rate_limiter": rl,
        "http_client": http,
        "signer": signer,
        "evidence_store": store,
        "ticket_client": tickets,
        "cloud_client": cloud,
        "canary_manager": canary,
        "now": now_fn,
        "call_log": call_log,
    }


def _make_watch_or_functions(deps):
    # Try to construct a class if present; otherwise, return function references
    interface = {}
    if hasattr(mw, "MetasurfWatch"):
        cls = mw.MetasurfWatch
        # Try flexible constructor kwargs
        ctor_kwargs = {}
        for k in ("rate_limiter", "signer", "evidence_store", "ticket_client", "cloud_client", "canary_manager", "now"):
            if k in deps:
                ctor_kwargs[k] = deps[k]
        try:
            watch = cls(**ctor_kwargs)
        except TypeError:
            # Try empty constructor if mismatch
            watch = cls()
            # Attempt to set attributes directly
            for k, v in ctor_kwargs.items():
                setattr(watch, k, v)
        interface["scan_imds_exposure"] = getattr(watch, "scan_imds_exposure", None)
        interface["inspect_outbound_request"] = getattr(watch, "inspect_outbound_request", None)
        interface["handle_canary_observation"] = getattr(watch, "handle_canary_observation", None)
        interface["_instance"] = watch
    else:
        # Map top-level functions if available
        interface["scan_imds_exposure"] = getattr(mw, "scan_imds_exposure", None)
        interface["inspect_outbound_request"] = getattr(mw, "inspect_outbound_request", None)
        interface["handle_canary_observation"] = getattr(mw, "handle_canary_observation", None)
        interface["_instance"] = None
    return interface


def _call_with_supported(func, kwargs):
    sig = inspect.signature(func)
    supported = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return func(**supported)


def _scan_imds(interface, deps, env):
    func = interface["scan_imds_exposure"]
    assert callable(func), "scan_imds_exposure not implemented"
    # Build kwargs with common aliases
    kwargs = {
        "env": env,
        "instance": env,
        "instance_info": env,
        "http_client": deps["http_client"],
        "client": deps["http_client"],
        "rate_limiter": deps["rate_limiter"],
        "limiter": deps["rate_limiter"],
        "signer": deps["signer"],
        "evidence_store": deps["evidence_store"],
        "now": deps["now"],
    }
    return _call_with_supported(func, kwargs)


def _inspect_outbound(interface, deps, request, pod_context):
    func = interface["inspect_outbound_request"]
    assert callable(func), "inspect_outbound_request not implemented"
    kwargs = {
        "request": request,
        "pod_context": pod_context,
        "ticket_client": deps["ticket_client"],
        "rate_limiter": deps["rate_limiter"],
        "signer": deps["signer"],
        "now": deps["now"],
    }
    return _call_with_supported(func, kwargs)


def _handle_canary(interface, deps, event):
    func = interface["handle_canary_observation"]
    assert callable(func), "handle_canary_observation not implemented"
    kwargs = {
        "event": event,
        "quarantine_client": deps["cloud_client"],
        "cloud_client": deps["cloud_client"],
        "signer": deps["signer"],
        "evidence_store": deps["evidence_store"],
        "canary_manager": deps["canary_manager"],
        "now": deps["now"],
    }
    return _call_with_supported(func, kwargs)


def test_detect_imdsv1_hop_limit_gt1_high_severity_with_remediation_and_safe_probe(deps):
    interface = _make_watch_or_functions(deps)
    env = {
        "cloud": "aws",
        "instance_id": "i-0123456789abcdef0",
        "account_id": "111122223333",
        "region": "us-east-1",
        "imds": {"version": "v1", "hop_limit": 2},
    }
    finding = _scan_imds(interface, deps, env)
    assert finding, "No finding produced"
    assert str(finding.get("severity", "")).upper() == "HIGH"
    # Must include remediation with Terraform and CLI steps
    remediation = finding.get("remediation", "") or ""
    assert "Terraform" in remediation or "terraform" in remediation
    assert "aws ec2 modify-instance-metadata-options" in remediation or "http_tokens" in remediation
    # Ensure safe, rate-limited probe
    assert deps["rate_limiter"].acquires >= 1
    # Ensure only safe endpoints were touched by http_client
    for url in deps["http_client"].requests:
        assert "169.254.169.254" not in url
        assert "metadata.google.internal" not in url
    # Findings must be cryptographically signed with timestamp and identity proof
    sig = finding.get("signature") or finding.get("signed") or {}
    assert isinstance(sig, dict) and sig.get("signature")
    assert sig.get("timestamp")
    assert sig.get("workload_identity_proof")

def test_probe_handles_timeout_and_returns_safe_default(deps):
    interface = _make_watch_or_functions(deps)
    deps["http_client"].raise_timeout = True
    env = {
        "cloud": "aws",
        "instance_id": "i-0123456789abcdef0",
        "account_id": "111122223333",
        "region": "us-east-1",
        "imds": {"version": "v1", "hop_limit": 2},
    }
    finding = _scan_imds(interface, deps, env)
    # Even if timeouts happen, scanner should produce a determination from config/env and not crash
    assert finding
    assert finding.get("severity")
    assert deps["rate_limiter"].acquires >= 1

def test_ssrf_sensor_blocks_metadata_and_opens_ticket_with_pod_context(deps):
    interface = _make_watch_or_functions(deps)
    # Attempt to access AWS IMDS
    request = {"method": "GET", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "headers": {}}
    pod = {"namespace": "default", "name": "api-123", "service_account": "sa-api", "node": "node-a"}
    decision = _inspect_outbound(interface, deps, request, pod)
    assert decision and decision.get("action") in ("block", "deny")
    assert "metadata" in decision.get("reason", "").lower() or "imds" in decision.get("reason", "").lower()
    ctx = decision.get("pod") or decision.get("context") or {}
    # Verify pod binding
    assert ctx.get("namespace") == "default"
    assert ctx.get("name") == "api-123"
    # Ticket should be opened with blast-radius analysis
    assert len(deps["ticket_client"].tickets) >= 1
    ticket = deps["ticket_client"].tickets[-1]
    assert "blast" in (str(ticket["details"]) or "").lower()
    assert ticket["severity"].lower() in ("high", "critical")
    # Also signed detection event
    # We accept either the decision carries a signature or ticket details include a signature
    signed = decision.get("signature") or ticket["details"].get("signature") if isinstance(ticket["details"], dict) else None
    assert not (signed is None), "Expected a cryptographic signature in decision or ticket details"

def test_ssrf_sensor_handles_ticketing_errors_but_still_blocks(deps):
    interface = _make_watch_or_functions(deps)
    deps["ticket_client"].raise_on_create = True
    request = {"method": "GET", "url": "http://metadata.google.internal/computeMetadata/v1/", "headers": {}}
    pod = {"namespace": "prod", "name": "jobs-789", "service_account": "sa-jobs", "node": "node-x"}
    decision = _inspect_outbound(interface, deps, request, pod)
    assert decision and decision.get("action") in ("block", "deny")
    # Even with ticketing failure, it must not raise and must block

def test_canary_usage_triggers_quarantine_and_signed_evidence_bundle(deps, now_fn):
    interface = _make_watch_or_functions(deps)
    event = {
        "platform": "aws",
        "token_id": "tok-abc123",
        "resource_id": "i-0abc",
        "source_ip": "203.0.113.5",
        "user_agent": "curl/7.64.1",
        "cloudtrail_event_id": "ev-123",
    }
    evidence = _handle_canary(interface, deps, event)
    # Quarantine workflow should be triggered (tagging or isolate)
    assert deps["cloud_client"].isolation_calls or deps["cloud_client"].tags
    if deps["cloud_client"].tags:
        rid, tags = deps["cloud_client"].tags[-1]
        assert rid == "i-0abc"
        assert any(k for k in tags.keys() if "isolate" in k or "quarantine" in k)
    # Canary credentials rotated and revoked immediately
    assert "tok-abc123" in deps["canary_manager"].revocations
    # Evidence bundle must be cryptographically signed and include context
    assert evidence
    sig = evidence.get("signature") or {}
    assert sig.get("signature") and sig.get("timestamp")
    assert evidence.get("source_ip") == "203.0.113.5"
    assert evidence.get("user_agent") == "curl/7.64.1"
    # Evidence stored in write-once bucket with retention policy
    assert deps["evidence_store"].write_calls
    wr = deps["evidence_store"].write_calls[-1]
    assert isinstance(wr.get("retention_days"), int) and wr["retention_days"] >= 30

def test_canary_revocation_precedes_or accompanies_storage_and_quarantine(deps):
    interface = _make_watch_or_functions(deps)
    event = {
        "platform": "gcp",
        "token_id": "tok-xyz789",
        "resource_id": "vm-123",
        "source_ip": "198.51.100.44",
        "user_agent": "Wget/1.20",
        "activity_log_id": "ev-456",
    }
    deps["call_log"].clear()
    evidence = _handle_canary(interface, deps, event)
    # Ensure rotate_and_revoke is called (recorded in call_log)
    assert ("rotate_and_revoke", "tok-xyz789") in deps["call_log"]
    # At minimum, should not exceed least privilege; we can't verify IAM here, but we can ensure evidence bundle doesn't contain secrets
    forbidden_keys = {"access_key", "secret", "token", "password"}
    assert not any(k in forbidden_keys for k in evidence.keys())

def test_findings_are_signed_and_include_workload_identity_proof_for_imds_and_canary(deps):
    interface = _make_watch_or_functions(deps)
    env = {
        "cloud": "aws",
        "instance_id": "i-9",
        "account_id": "000000000000",
        "region": "us-west-2",
        "imds": {"version": "v1", "hop_limit": 3},
    }
    finding = _scan_imds(interface, deps, env)
    assert finding.get("signature", {}).get("workload_identity_proof")
    event = {"platform": "aws", "token_id": "tok-1", "resource_id": "i-1", "source_ip": "192.0.2.1", "user_agent": "ua"}
    evidence = _handle_canary(interface, deps, event)
    assert evidence.get("signature", {}).get("workload_identity_proof")