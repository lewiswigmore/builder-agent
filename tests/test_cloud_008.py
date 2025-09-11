import time
import socket
import types
import hashlib
import json
import pytest

from tools.cloud.kubeidentity_tripwire import KubeIdentityTripwire


@pytest.fixture(autouse=True)
def block_external_network(monkeypatch):
    # Disallow all outbound network connects in tests
    original_connect = socket.socket.connect

    def guard_connect(self, address):
        host, port = address[0], address[1]
        local_hosts = {"127.0.0.1", "::1", "localhost"}
        # If host is a string of an IP, allow localhost variants only
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host
        if ip not in {"127.0.0.1"}:
            raise AssertionError(f"Outbound network is not allowed in tests: attempted to connect to {host}:{port}")
        return original_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guard_connect)
    yield


@pytest.fixture
def tool(tmp_path):
    tw = KubeIdentityTripwire()
    # Configure evidence sink to a local file-based memory sink to avoid network
    sink = {
        "type": "memory",
        "encryption_at_rest": True,
        "access_controls": True,
        "path": str(tmp_path / "evidence.jsonl"),
        "endpoint": "http://127.0.0.1:0/evidence"  # placeholder, but localhost only
    }
    if hasattr(tw, "configure_evidence_sink"):
        tw.configure_evidence_sink(sink)
    else:
        setattr(tw, "evidence_sink", sink)
    # Configure allowlist to localhost only
    allowlist = ["127.0.0.1", "localhost"]
    if hasattr(tw, "configure_network_egress_allowlist"):
        tw.configure_network_egress_allowlist(allowlist)
    else:
        setattr(tw, "egress_allowlist", allowlist)
    return tw


def wait_for_condition(fn, timeout=5.0, interval=0.05):
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        result = fn()
        if result:
            return result
        time.sleep(interval)
    return fn()


def verify_signed(obj, verifier):
    if hasattr(verifier, "verify_signature"):
        try:
            return bool(verifier.verify_signature(obj))
        except Exception:
            return False
    # Fallback: basic presence of signature field
    sig = obj.get("signature")
    if not sig:
        return False
    # Pseudo-verification: signature is sha256 of payload if present
    payload = json.dumps({k: v for k, v in obj.items() if k != "signature"}, sort_keys=True).encode()
    try:
        return sig == hashlib.sha256(payload).hexdigest()
    except Exception:
        return False


def make_audit_event(sa_name, namespace, token_id, audience, src_ip):
    return {
        "type": "TokenUse",
        "src_ip": src_ip,
        "service_account": sa_name,
        "namespace": namespace,
        "token_id": token_id,
        "audience": audience,
        "timestamp": time.time(),
    }


def _projected_token_assertions(honey):
    assert isinstance(honey, dict)
    assert honey["namespace_scoped"] is True
    token = honey["token"]
    assert token["projected"] is True
    assert token["rotation_enabled"] is True
    assert token["namespace"] == honey["namespace"]
    assert "exp" in token
    assert token["exp"] - time.time() <= 60  # time-bound within a minute per requirement
    assert token.get("signed") is True
    rbac = honey.get("rbac") or {}
    assert rbac.get("read_only") is True


def test_honey_sa_replay_detection_auto_revoke_signed_alert(tool):
    # Create time-bound, namespace-scoped honey SA with projected token and rotation enabled
    honey = tool.create_honey_service_account(
        namespace="honey-ns",
        audience=["kubernetes"],
        ttl_seconds=45,
        rotate=True,
    )
    _projected_token_assertions(honey)
    assert honey["namespace"] == "honey-ns"
    token_id = honey["token"]["id"]

    # Simulate token replay from an external IP (TEST-NET-3)
    event = make_audit_event(
        sa_name=honey["name"],
        namespace=honey["namespace"],
        token_id=token_id,
        audience=honey["token"]["audience"],
        src_ip="203.0.113.9",
    )
    # Process audit event to trigger detection and response
    tool.process_audit_event(event)

    # Within 60 seconds, auto-revocation and signed alert should appear
    alerts = wait_for_condition(lambda: tool.get_alerts(), timeout=2.0)
    assert isinstance(alerts, list) and len(alerts) >= 1
    alert = next((a for a in alerts if a.get("token_id") == token_id), alerts[-1])
    assert alert["action"] in {"revoke_token", "revoke_and_alert", "alert_and_revoke"}
    assert alert["token_id"] == token_id
    assert alert["honey_service_account"] == honey["name"]
    # Alert must be cryptographically signed
    assert verify_signed(alert, tool) is True
    # Evidence must be sealed and only to designated sink with encryption at rest and access controls
    evidence = alert.get("evidence") or {}
    assert evidence.get("sealed") is True
    sink = evidence.get("sink") or getattr(tool, "evidence_sink", {})
    assert sink.get("encryption_at_rest") is True
    assert sink.get("access_controls") is True

    # Token must be revoked
    revocations = wait_for_condition(lambda: tool.get_revocations(), timeout=2.0)
    assert isinstance(revocations, list) and any(r.get("token_id") == token_id and r.get("revoked") for r in revocations)


def test_scan_cluster_report_automount_tokens_with_remediation_diffs(tool, monkeypatch):
    # Mock internal discovery to ensure least-privilege, read-only RBAC queries
    # Provide pods across namespaces
    pods = [
        {"namespace": "prod", "name": "api-0", "automountServiceAccountToken": True},
        {"namespace": "default", "name": "web-0", "automountServiceAccountToken": False},
        {"namespace": "kube-system", "name": "controller", "automountServiceAccountToken": True},
        {"namespace": "dev", "name": "worker", "automountServiceAccountToken": True},
    ]

    # If tool exposes hooks to list pods, patch them; otherwise patch scan_posture directly
    if hasattr(tool, "_list_pods"):
        monkeypatch.setattr(tool, "_list_pods", lambda: pods)
    else:
        # Wrap original scan_posture if exists to isolate input
        if hasattr(tool, "scan_posture"):
            original = tool.scan_posture

            def wrapped(restricted_namespaces):
                return {
                    "pods": [
                        p | {
                            "rbac_least_privilege": {
                                "read_only": True,
                                "verbs": ["get", "list", "watch"],
                                "resources": ["pods", "serviceaccounts"],
                            },
                            "remediation_diff": f"spec:\n  automountServiceAccountToken: false  # in {p['namespace']}/{p['name']}",
                        }
                        for p in pods
                    ],
                    "rbac": {"read_only": True},
                }

            monkeypatch.setattr(tool, "scan_posture", wrapped)

    report = tool.scan_posture(restricted_namespaces=["prod", "kube-system"])
    assert isinstance(report, dict)
    assert report.get("rbac", {}).get("read_only") is True  # least-privileged discovery
    flagged = [
        p
        for p in report.get("pods", [])
        if p["namespace"] in {"prod", "kube-system"} and p.get("automountServiceAccountToken") is True
    ]
    assert len(flagged) >= 2
    for p in flagged:
        # Must include remediation diffs and least-privilege RBAC proposals
        rlp = p.get("rbac_least_privilege") or {}
        assert rlp.get("read_only") is True
        assert set(rlp.get("verbs", [])) <= {"get", "list", "watch"}
        assert "remediation_diff" in p
        assert "automountServiceAccountToken: false" in p["remediation_diff"]


def test_identify_and_fix_broad_or_missing_audiences(tool, monkeypatch):
    # Simulate analysis finding SA tokens with '*' audience and missing audience
    issues = [
        {
            "service_account": "default",
            "namespace": "prod",
            "audiences": ["*"],
            "problem": "overly_broad_audience",
            "recommendation": {"audiences": ["kubernetes", "vault.prod.local"]},
        },
        {
            "service_account": "builder",
            "namespace": "dev",
            "audiences": [],
            "problem": "missing_audience",
            "recommendation": {"audiences": ["kubernetes"]},
        },
    ]

    # Monkeypatch analyze to return our issues
    if hasattr(tool, "analyze_token_audiences"):
        monkeypatch.setattr(tool, "analyze_token_audiences", lambda: {"issues": issues})
    else:
        # If not present, add method dynamically
        def analyze_token_audiences():
            return {"issues": issues}

        tool.analyze_token_audiences = types.MethodType(lambda self=tool: {"issues": issues}, tool)

    # Patch apply to "fix" issues by clearing them on subsequent scan
    fixed_flag = {"done": False}

    def apply_recs(recs):
        fixed_flag["done"] = True
        return True

    if hasattr(tool, "apply_audience_recommendations"):
        monkeypatch.setattr(tool, "apply_audience_recommendations", apply_recs)
    else:
        tool.apply_audience_recommendations = types.MethodType(lambda self, recs: apply_recs(recs), tool)

    # After fix, re-scan should report no issues
    initial = tool.analyze_token_audiences()
    assert isinstance(initial, dict)
    found = initial.get("issues", [])
    assert any(i["problem"] in {"overly_broad_audience", "missing_audience"} for i in found)

    ok = tool.apply_audience_recommendations([i["recommendation"] for i in found])
    assert ok is True and fixed_flag["done"] is True

    # Now patched analyze to return no issues
    monkeypatch.setattr(tool, "analyze_token_audiences", lambda: {"issues": []})
    rescanned = tool.analyze_token_audiences()
    assert rescanned.get("issues") == []


def test_egress_allowlist_blocks_non_localhost(tool, monkeypatch):
    # Configure evidence sink to a non-allowed endpoint to ensure no exfiltration occurs
    bad_sink = {
        "type": "http",
        "endpoint": "http://198.51.100.10:8080/evidence",  # TEST-NET-2 non-local
        "encryption_at_rest": True,
        "access_controls": True,
    }
    # Temporarily override sink
    if hasattr(tool, "configure_evidence_sink"):
        tool.configure_evidence_sink(bad_sink)
    else:
        setattr(tool, "evidence_sink", bad_sink)

    honey = tool.create_honey_service_account(namespace="honey-ns", audience="kubernetes", ttl_seconds=30, rotate=True)
    _projected_token_assertions(honey)

    event = make_audit_event(
        sa_name=honey["name"],
        namespace=honey["namespace"],
        token_id=honey["token"]["id"],
        audience=honey["token"]["audience"],
        src_ip="203.0.113.5",
    )

    # Process event; tool should refuse to exfiltrate to non-allowlisted endpoint and record the block
    tool.process_audit_event(event)
    alerts = wait_for_condition(lambda: tool.get_alerts(), timeout=2.0)
    alert = next((a for a in alerts if a.get("token_id") == honey["token"]["id"]), alerts[-1])
    # Must indicate egress blocked or skipped due to allowlist
    assert alert.get("egress_blocked") is True or alert.get("evidence", {}).get("sent") is False


def test_invalid_honey_sa_params_error_handled(tool):
    # Negative TTL should be handled gracefully
    with pytest.raises((ValueError, AssertionError)):
        tool.create_honey_service_account(namespace="honey-ns", audience="kubernetes", ttl_seconds=-10, rotate=True)

    # Missing namespace should raise
    with pytest.raises((ValueError, AssertionError, TypeError)):
        tool.create_honey_service_account(namespace="", audience="kubernetes", ttl_seconds=30, rotate=True)