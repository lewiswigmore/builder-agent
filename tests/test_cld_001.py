import json
import time
import types
import socket
import pytest

# Import the tool under test
import tools.cloud_security.lambdashield as lambdashield


class ToolAdapter:
    """
    A helper adapter to interact with LambdaShield with flexible method name resolution.
    """

    def __init__(self, tool):
        self.tool = tool

    def _resolve_attr(self, names):
        for name in names:
            if hasattr(self.tool, name):
                return getattr(self.tool, name)
        # Also try module-level functions if tool is a module-like object
        # This allows adapter to wrap modules as well as class instances
        if hasattr(lambdashield, "__dict__"):
            for name in names:
                if hasattr(lambdashield, name):
                    return getattr(lambdashield, name)
        raise AttributeError(f"None of the expected methods found: {', '.join(names)}")

    def configure_allowlist(self, allowlist):
        fn = self._resolve_attr(
            [
                "configure_allowlist",
                "set_egress_allowlist",
                "set_allowlist",
                "configure_egress_allowlist",
            ]
        )
        return fn(allowlist)

    def runtime_event(self, event):
        fn = self._resolve_attr(
            [
                "monitor_runtime",
                "process_runtime_event",
                "enforce_runtime_policies",
                "handle_runtime_event",
                "handle_outbound_call",
                "check_egress",
            ]
        )
        return fn(event)

    def detect_trust_misconfig(self, graph):
        fn = self._resolve_attr(
            [
                "detect_trust_misconfiguration",
                "detect_trust_misconfig",
                "detect_risky_trust",
                "detect_cross_account_paths",
                "analyze_trust_graph",
            ]
        )
        return fn(graph)

    def propose_least_privilege(self, graph_or_issue):
        fn = self._resolve_attr(
            [
                "propose_least_privilege_fix",
                "recommend_least_privilege",
                "recommend_iam_constraints",
                "recommend_iam",
            ]
        )
        return fn(graph_or_issue)

    def simulate_remediation(self, issue_or_change):
        fn = self._resolve_attr(
            [
                "simulate_remediation",
                "apply_remediation_dry_run",
                "dry_run_remediation",
                "simulate_one_click_remediation",
            ]
        )
        return fn(issue_or_change)

    def rollback(self, remediation_id_or_change):
        fn = self._resolve_attr(["rollback", "rollback_remediation", "undo_change"])
        return fn(remediation_id_or_change)

    def scan_image(self, image_ref=None, sbom=None):
        fn = self._resolve_attr(["scan_image", "scan_sbom", "sbom_scan"])
        # Prefer passing sbom if provided
        if sbom is not None:
            return fn(sbom=sbom, image=image_ref) if "sbom" in fn.__code__.co_varnames else fn(sbom)
        if image_ref is not None:
            return fn(image=image_ref) if "image" in fn.__code__.co_varnames else fn(image_ref)
        return fn()

    def enforce_ci_gate(self, scan_result, policies=None):
        fn = self._resolve_attr(
            [
                "enforce_ci_gate",
                "enforce_ci_policies",
                "evaluate_ci_gate",
                "enforce_signed_policy",
            ]
        )
        kwargs = {}
        if "policies" in getattr(fn, "__code__", types.SimpleNamespace(co_varnames=())).co_varnames:
            kwargs["policies"] = policies or []
        return fn(scan_result, **kwargs)

    def verify_policy_signature(self, policy):
        fn = self._resolve_attr(
            [
                "verify_policy_signature",
                "validate_policy_signature",
                "verify_signed_policy",
                "verify_policy",
            ]
        )
        return fn(policy)

    def submit_policy(self, policy):
        fn = self._resolve_attr(
            [
                "submit_policy",
                "enforce_policy",
                "apply_policy",
                "evaluate_policy",
                "policy_as_code_submit",
            ]
        )
        return fn(policy)

    def get_audit_log(self):
        fn = self._resolve_attr(["get_audit_log", "list_audit_log", "audit_trail"])
        return fn()

    def discover_inventory(self, clouds=None):
        fn = self._resolve_attr(
            [
                "discover_and_inventory",
                "discover_inventory",
                "inventory",
                "discover",
            ]
        )
        if clouds is not None:
            if "clouds" in getattr(fn, "__code__", types.SimpleNamespace(co_varnames=())).co_varnames:
                return fn(clouds=clouds)
            return fn(clouds)
        return fn()

    def detect_drift(self, baseline, current):
        fn = self._resolve_attr(
            [
                "detect_drift",
                "detect_configuration_drift",
                "drift_detection",
            ]
        )
        return fn(baseline, current)


@pytest.fixture(scope="module")
def tool_instance():
    # Attempt to construct a LambdaShield instance.
    if hasattr(lambdashield, "LambdaShield"):
        try:
            return lambdashield.LambdaShield()
        except Exception:
            # Fall back to module-level API
            return lambdashield
    # Try a factory function
    for name in ("get_tool", "get_instance", "init", "initialize"):
        if hasattr(lambdashield, name):
            return getattr(lambdashield, name)()
    # Fall back to module itself
    return lambdashield


@pytest.fixture(autouse=True)
def restrict_network(monkeypatch):
    # Prevent any outbound network calls except to localhost
    original_connect = socket.socket.connect

    def safe_connect(self, address):
        host, port = address
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            raise RuntimeError("Blocked DNS resolution in tests")
        if ip not in ("127.0.0.1", "::1"):
            raise RuntimeError(f"Blocked outbound connection to non-localhost: {host}")
        return original_connect(self, (ip, port))

    monkeypatch.setattr(socket.socket, "connect", safe_connect)
    # Also block getaddrinfo for external hosts
    original_getaddrinfo = socket.getaddrinfo

    def safe_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host not in (None, "", "localhost", "127.0.0.1", "::1"):
            raise RuntimeError(f"Blocked DNS resolution for host: {host}")
        return original_getaddrinfo(host, port, family, type, proto, flags)

    monkeypatch.setattr(socket, "getaddrinfo", safe_getaddrinfo)
    yield


@pytest.fixture
def ls(tool_instance):
    return ToolAdapter(tool_instance)


def assert_high_severity_finding(result):
    # Accept both 'severity' or 'level', string values high/critical
    severity = (result.get("severity") or result.get("level") or "").lower()
    assert severity in ("high", "critical")
    # Ensure finding metadata present
    assert result.get("finding") or result.get("finding_id") or result.get("id")


def assert_call_graph_present(result):
    call_graph = result.get("call_graph") or result.get("trace") or result.get("graph")
    assert call_graph, "Call graph/trace missing"
    assert isinstance(call_graph, (list, dict))
    # If list, ensure at least one node/edge
    if isinstance(call_graph, list):
        assert len(call_graph) > 0


def make_outbound_event(function_id="aws:lambda:exfil", dest_host="127.0.0.1", dest_port=8080):
    return {
        "type": "outbound_call",
        "function": {
            "id": function_id,
            "platform": "aws_lambda",
            "runtime": "python3.11",
        },
        "network": {"dest_host": dest_host, "dest_port": dest_port, "protocol": "tcp"},
        "syscalls": ["connect", "sendto"],
        "dns": [],
        "timestamp": time.time(),
    }


def make_trust_graph():
    # Minimal representation of a trust graph with an external principal path
    return {
        "accounts": [
            {"id": "111111111111", "cloud": "aws"},
            {"id": "222222222222", "cloud": "aws", "external": True},
        ],
        "roles": [
            {
                "arn": "arn:aws:iam::111111111111:role/app-role",
                "trusts": [
                    "arn:aws:iam::111111111111:root",
                    "arn:aws:iam::222222222222:root",
                ],
                "permissions": ["s3:*", "sts:AssumeRole"],
            }
        ],
        "edges": [
            {
                "from": "arn:aws:iam::222222222222:root",
                "to": "arn:aws:iam::111111111111:role/app-role",
                "type": "assumeRole",
            }
        ],
    }


def make_sbom_with_issues():
    # Simplified SBOM with components, CVEs, and secrets
    return {
        "image": "registry.local/app:bad",
        "layers": ["sha256:deadbeef", "sha256:cafebabe"],
        "components": [
            {"name": "openssl", "version": "1.0.1", "cves": ["CVE-2014-0160"], "severity": "critical"},
            {"name": "libyaml", "version": "0.2.1", "cves": [], "severity": "none"},
        ],
        "secrets": [
            {"type": "generic", "location": "/app/.env", "match": "API_KEY=sk_live_..."}
        ],
        "generated_at": time.time(),
    }


def make_signed_policy(block_on_critical=True, signature="valid-signature", tampered=False):
    policy = {
        "name": "ci-deploy-policy",
        "engine": "opa",
        "rego": 'package ci.policy allow = false { input.critical_vulns > 0 }',
        "enforce": True,
        "block_on_critical": block_on_critical,
        "provenance": {"author": "secops", "commit": "abc123", "pipeline": "ci"},
        "signature": signature,
    }
    if tampered:
        policy["rego"] = 'package ci.policy allow = true'  # Malicious modification
    return policy


@pytest.mark.parametrize("dest_host", ["127.0.0.1", "localhost"])
def test_blocks_unauthorized_egress_and_emits_finding_with_call_graph(ls, dest_host):
    # Configure allowlist to exclude the test destination
    ls.configure_allowlist(allowlist=["allowed.local"])
    event = make_outbound_event(dest_host=dest_host, dest_port=8081)

    t0 = time.time()
    result = ls.runtime_event(event)
    elapsed = time.time() - t0

    assert isinstance(result, dict)
    assert result.get("blocked") is True, "Egress should be blocked"
    assert_high_severity_finding(result)
    assert_call_graph_present(result)
    # Ensure action taken within 30 seconds
    assert elapsed <= 30.0

    # Edge case: Missing destination should be handled gracefully
    bad_event = {k: v for k, v in event.items() if k != "network"}
    bad_result = ls.runtime_event(bad_event)
    assert isinstance(bad_result, dict)
    # Either blocked by default or error provided, but not a crash
    assert bad_result.get("blocked") in (True, False) or "error" in bad_result


def test_trust_misconfig_detect_fix_and_rollback(ls):
    graph = make_trust_graph()
    detection = ls.detect_trust_misconfig(graph)
    assert isinstance(detection, dict)
    risky = detection.get("risky_paths") or detection.get("findings") or []
    assert risky, "Should detect at least one risky cross-account assumeRole path"

    recommendation = ls.propose_least_privilege(detection)
    assert isinstance(recommendation, dict)
    # Ensure least-privilege recommendation is present
    assert recommendation.get("least_privilege") or recommendation.get("proposed_fix")

    # Simulate one-click remediation
    remediation = ls.simulate_remediation(recommendation)
    assert isinstance(remediation, dict)
    assert remediation.get("success") is True

    # Rollback capability
    rollback = ls.rollback(remediation.get("id") or remediation)
    assert isinstance(rollback, dict)
    assert rollback.get("rolled_back") is True

    # Edge case: simulate remediation without sufficient permissions
    # If the API supports a parameter, use it; otherwise, pass a marker to trigger error handling.
    insufficient = {"simulate_error": "access_denied", "change": recommendation}
    try:
        remediation_fail = ls.simulate_remediation(insufficient)
        assert isinstance(remediation_fail, dict)
        assert remediation_fail.get("success") in (False, None)
        assert "error" in remediation_fail
        # Rollback plan should still be available
        assert remediation_fail.get("rollback_plan") is not None
    except AttributeError:
        # If simulate_remediation does not support error simulation, skip this edge case
        pytest.skip("simulate_remediation edge-case not supported by implementation")


def test_sbom_scanner_flags_cve_and_secret_and_blocks_deploy_via_signed_policy(ls):
    sbom = make_sbom_with_issues()
    scan = ls.scan_image(sbom=sbom)
    assert isinstance(scan, dict)
    crit_count = (
        scan.get("critical_vulns")
        or scan.get("critical")
        or (scan.get("vulns", {}).get("critical") if isinstance(scan.get("vulns"), dict) else None)
    )
    secret_count = (
        scan.get("secrets_found")
        or (len(scan.get("secrets")) if isinstance(scan.get("secrets"), list) else None)
        or (scan.get("issues", {}).get("secrets") if isinstance(scan.get("issues"), dict) else None)
    )
    assert (crit_count or 0) > 0, "Critical CVEs should be detected"
    assert (secret_count or 0) > 0, "Embedded secrets should be detected"

    signed_policy = make_signed_policy(block_on_critical=True, signature="valid")
    gate = ls.enforce_ci_gate(scan, policies=[signed_policy])
    assert isinstance(gate, dict)
    gate_status = (gate.get("status") or gate.get("ci_gate") or "").lower()
    assert gate.get("blocked") is True or gate_status in ("fail", "failed")
    # Ensure it's due to signed policy enforcement
    reason = " ".join(str(v) for v in gate.values())
    assert "policy" in reason.lower() or gate.get("policy_enforced") is True

    # Edge case: empty SBOM should return an error or safe default
    empty_scan = ls.scan_image(sbom={})
    assert isinstance(empty_scan, dict)
    assert "error" in empty_scan or empty_scan.get("critical_vulns") in (0, None)


def test_tampered_policy_signature_fails_and_audit_is_immutable(ls):
    tampered = make_signed_policy(signature="invalid", tampered=True)
    # Verify signature
    verified = ls.verify_policy_signature(tampered)
    if isinstance(verified, dict):
        assert verified.get("valid") is False
    else:
        assert verified is False

    # Submission should halt pipeline
    submission = ls.submit_policy(tampered)
    assert isinstance(submission, dict)
    status = (submission.get("pipeline_status") or submission.get("status") or "").lower()
    assert "halt" in status or submission.get("halted") is True or submission.get("blocked") is True

    # Immutable audit record with provenance details
    audit = ls.get_audit_log()
    assert isinstance(audit, (list, tuple))
    assert len(audit) > 0
    last = audit[-1]
    # Check provenance present
    prov = last.get("provenance") if isinstance(last, dict) else None
    assert prov and ("commit" in prov or "author" in prov or "pipeline" in prov)
    # Check immutable flag or hash chain present
    immutable_flag = last.get("immutable") if isinstance(last, dict) else None
    integrity = last.get("hash") if isinstance(last, dict) else None
    assert immutable_flag is True or (integrity is not None and len(str(integrity)) > 0)

    # Attempt mutation should be rejected if API allows modification
    if isinstance(audit, list):
        with pytest.raises(Exception):
            # Try to mutate the last record if it's supposed to be immutable
            if isinstance(last, dict):
                last["tamper"] = True
            else:
                audit[-1] = ("tampered",)


def test_discovery_across_clouds_and_drift_detection(ls):
    clouds = ["aws", "azure", "gcp", "containers"]
    inventory = ls.discover_inventory(clouds=clouds)
    assert isinstance(inventory, dict)
    # Expect keys for each cloud
    for cloud in clouds:
        assert cloud in inventory, f"Missing inventory for {cloud}"
        assert isinstance(inventory[cloud], (list, dict))

    # CSPM baseline and drift detection
    baseline = {
        "aws": [{"id": "lambda:func1", "config": {"memory": 256, "timeout": 10}}],
        "azure": [{"id": "funcapp:func2", "config": {"auth_required": True}}],
        "gcp": [{"id": "gcf:func3", "config": {"ingress": "internal"}}],
        "containers": [{"id": "deploy:svc", "config": {"image": "app:1.0"}}],
    }
    current = {
        "aws": [{"id": "lambda:func1", "config": {"memory": 128, "timeout": 10}}],  # drift
        "azure": [{"id": "funcapp:func2", "config": {"auth_required": True}}],
        "gcp": [{"id": "gcf:func3", "config": {"ingress": "all"}}],  # drift
        "containers": [{"id": "deploy:svc", "config": {"image": "app:1.1"}}],  # drift
    }
    drift = ls.detect_drift(baseline, current)
    assert isinstance(drift, dict)
    # Ensure drifts identified
    assert any(drift.get(k) for k in clouds), "Expected at least one drift to be detected"

    # Edge case: unsupported cloud provider
    with pytest.raises(Exception):
        ls.discover_inventory(clouds=["digitalocean"])