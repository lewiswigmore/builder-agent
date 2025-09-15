import pytest
import hashlib
import json
import datetime as dt

from tools.cloud import meshguard as meshguard_mod

MeshGuard = getattr(meshguard_mod, "MeshGuard")
MeshGuardError = getattr(meshguard_mod, "MeshGuardError", Exception)


def _val(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class FakeClock:
    def __init__(self, start=None):
        self._now = start or dt.datetime(2025, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)

    def now(self):
        return self._now

    def advance(self, seconds=0):
        self._now = self._now + dt.timedelta(seconds=seconds)


class FakeK8s:
    def __init__(self):
        self._authzs = []
        self._workloads = []
        self._applied = []
        self._apply_called = False
        self._raises_on_list_authz = False

    def list_authorization_policies(self, namespaces=None):
        if self._raises_on_list_authz:
            raise RuntimeError("k8s API failure")
        if namespaces is None:
            return self._authzs
        ns_set = set(n for n in namespaces)
        return [a for a in self._authzs if a.get("namespace") in ns_set]

    def list_workloads(self, namespaces=None):
        if namespaces is None:
            return self._workloads
        ns_set = set(n for n in namespaces)
        return [w for w in self._workloads if w.get("namespace") in ns_set]

    def apply(self, resources):
        self._apply_called = True
        self._applied.append(resources)

    def reset_apply(self):
        self._apply_called = False
        self._applied.clear()


class FakeMesh:
    def __init__(self):
        self._call_graph = {"nodes": [], "edges": []}
        self._spiffe_map = {}  # (ns, sa or workload) -> spiffe
        self._egress_flows = []  # dicts with workload, dest_ip, via: node|sidecar
        self._certs = []  # dicts with workload, not_after datetime
        self._trust_bundle = {"root_hash": "h1", "version": 1}

    def get_call_graph(self, namespaces=None):
        return self._call_graph

    def get_spiffe_id(self, namespace, workload):
        return self._spiffe_map.get((namespace, workload))

    def list_egress_flows(self, namespaces=None):
        if namespaces is None:
            return self._egress_flows
        ns_set = set(n for n in namespaces)
        return [f for f in self._egress_flows if f.get("namespace") in ns_set]

    def get_sds_certs(self, namespaces=None):
        if namespaces is None:
            return self._certs
        ns_set = set(n for n in namespaces)
        return [c for c in self._certs if c.get("namespace") in ns_set]

    def get_trust_bundle(self):
        return self._trust_bundle


class FakeSigner:
    def __init__(self):
        self.signed = []

    def sign(self, payload_bytes):
        digest = hashlib.sha256(payload_bytes).hexdigest()
        signature = f"sig:{digest[:16]}"
        self.signed.append({"digest": digest, "signature": signature, "payload": payload_bytes})
        return {"digest": digest, "signature": signature}


class FakeRekor:
    def __init__(self, url="http://127.0.0.1:3000"):
        self.url = url
        self.submissions = []

    def submit(self, digest, signature, metadata=None):
        entry_id = f"rekor-{len(self.submissions)+1}"
        self.submissions.append({"id": entry_id, "digest": digest, "signature": signature, "metadata": metadata})
        return {"entry_id": entry_id, "url": self.url}


@pytest.fixture
def deps():
    k8s = FakeK8s()
    mesh = FakeMesh()
    signer = FakeSigner()
    rekor = FakeRekor()
    clock = FakeClock()
    try:
        mg = MeshGuard(k8s=k8s, mesh=mesh, signer=signer, rekor=rekor, clock=clock)
    except TypeError:
        # Fall back to attribute injection if constructor doesn't accept deps
        mg = MeshGuard()
        setattr(mg, "k8s", k8s)
        setattr(mg, "mesh", mesh)
        setattr(mg, "signer", signer)
        setattr(mg, "rekor", rekor)
        setattr(mg, "clock", clock)
    return mg, k8s, mesh, signer, rekor, clock


def test_detects_misconfigured_authorization_policy_cross_namespace(deps):
    mg, k8s, mesh, signer, rekor, clock = deps

    # Setup: misconfigured policy in 'payments' allows cross-namespace traffic
    k8s._authzs = [
        {
            "name": "payments-allow-all",
            "namespace": "payments",
            "spec": {
                "rules": [
                    {
                        "from": [
                            {"source": {"principals": ["*"]}},  # overly broad
                        ]
                    }
                ]
            },
        }
    ]
    # Workloads and identities
    k8s._workloads = [
        {"name": "payments-svc", "namespace": "payments", "sidecar": True},
        {"name": "orders-svc", "namespace": "orders", "sidecar": True},
    ]
    mesh._spiffe_map = {
        ("payments", "payments-svc"): "spiffe://cluster.local/ns/payments/sa/payments-sa",
        ("orders", "orders-svc"): "spiffe://cluster.local/ns/orders/sa/orders-sa",
    }
    mesh._call_graph = {
        "nodes": [
            {"namespace": "orders", "workload": "orders-svc"},
            {"namespace": "payments", "workload": "payments-svc"},
        ],
        "edges": [
            {
                "from": {"namespace": "orders", "workload": "orders-svc"},
                "to": {"namespace": "payments", "workload": "payments-svc"},
                "protocol": "HTTP",
                "path": "/charge",
            }
        ],
    }

    # Exercise
    findings = mg.analyze_authorization_policies(namespaces=["orders", "payments"])

    # Verify a finding indicates cross-namespace misconfiguration
    assert isinstance(findings, (list, tuple)) and findings, "Expected findings for misconfigured policy"
    f = next((x for x in findings if _val(x, "type") in ("AUTHZ_CROSS_NAMESPACE", "AuthorizationPolicyCrossNamespace")), None)
    assert f is not None, f"Expected AUTHZ_CROSS_NAMESPACE finding in {findings}"

    # Verify call graph and SPIFFE IDs present
    call_graph = _val(f, "call_graph")
    assert call_graph and isinstance(call_graph, dict)
    edges = call_graph.get("edges") or []
    assert any(
        e.get("from", {}).get("namespace") == "orders" and e.get("to", {}).get("namespace") == "payments" for e in edges
    ), "Call graph should reflect cross-namespace call from orders to payments"

    spiffes = _val(f, "spiffe_ids") or []
    assert any("spiffe://cluster.local/ns/orders" in s for s in spiffes)
    assert any("spiffe://cluster.local/ns/payments" in s for s in spiffes)

    # Verify severity and recommended remediation
    severity = _val(f, "severity", "").lower()
    assert severity in ("high", "critical")
    remediation = _val(f, "remediation") or {}
    text = remediation.get("summary", "") + json.dumps(remediation)
    assert "namespace" in text and ("restrict" in text or "least privilege" in text)


def test_identifies_egress_bypass_and_workloads_without_sidecars(deps):
    mg, k8s, mesh, signer, rekor, clock = deps

    # Setup workloads including one without sidecar
    k8s._workloads = [
        {"name": "api", "namespace": "frontend", "sidecar": True},
        {"name": "legacy-batch", "namespace": "data", "sidecar": False},
    ]
    # Egress flows include bypass via node routing to 127.0.0.1 (simulated external)
    mesh._egress_flows = [
        {"namespace": "frontend", "workload": "api", "dest_ip": "127.0.0.1", "via": "sidecar"},
        {"namespace": "data", "workload": "legacy-batch", "dest_ip": "127.0.0.1", "via": "node"},
    ]

    findings = mg.audit_egress(namespaces=["frontend", "data"])

    # Check that egress bypass is detected
    bypass = next((x for x in findings if _val(x, "type") in ("EGRESS_BYPASS", "EgressBypassDetected")), None)
    assert bypass is not None, f"Expected EGRESS_BYPASS finding in {findings}"
    affected = _val(bypass, "affected_workloads") or []
    assert any(w.get("namespace") == "data" and w.get("workload") == "legacy-batch" for w in affected)

    # Check that workloads without sidecars are flagged
    no_sidecar = next((x for x in findings if _val(x, "type") in ("SIDECAR_MISSING", "WorkloadSidecarMissing")), None)
    assert no_sidecar is not None, "Expected SIDECAR_MISSING finding"
    ns_list = [w.get("namespace") for w in (_val(no_sidecar, "affected_workloads") or [])]
    assert "data" in ns_list

    # Recommendations include NetworkPolicy and egress gateway usage
    recommendations = (_val(bypass, "remediation") or {}).get("recommendations") or []
    joined = " ".join(recommendations).lower()
    assert "networkpolicy" in joined or "network policy" in joined
    assert "egress gateway" in joined


def test_validates_sds_cert_rotation_continuity_and_trust_bundle_drift(deps):
    mg, k8s, mesh, signer, rekor, clock = deps

    # Setup certs nearing expiration and trust bundle drift
    soon = clock.now() + dt.timedelta(seconds=1800)  # 30 min
    later = clock.now() + dt.timedelta(days=10)
    mesh._certs = [
        {"namespace": "payments", "workload": "payments-svc", "not_after": soon},
        {"namespace": "orders", "workload": "orders-svc", "not_after": later},
    ]
    mesh._trust_bundle = {"root_hash": "h2", "version": 2, "prev_hash": "h1"}  # drifted from earlier h1

    alerts = mg.validate_sds_rotation(threshold_seconds=3600)

    # Cert expiring within threshold should be alerted
    cert_alert = next((x for x in alerts if _val(x, "type") in ("CERT_ROTATION_RISK", "SDSCertExpirationSoon")), None)
    assert cert_alert is not None, "Expected CERT_ROTATION_RISK alert"
    affected = _val(cert_alert, "affected_workloads") or []
    assert any(a.get("workload") == "payments-svc" for a in affected)

    # Trust bundle drift or expiration should be alerted
    drift_alert = next((x for x in alerts if _val(x, "type") in ("TRUST_BUNDLE_DRIFT", "TrustBundleDriftDetected")), None)
    assert drift_alert is not None, "Expected TRUST_BUNDLE_DRIFT alert"
    drift_meta = _val(drift_alert, "metadata") or {}
    assert drift_meta.get("previous_hash") == "h1"
    assert drift_meta.get("current_hash") == "h2"

    # Edge: exactly at threshold should alert
    exactly_threshold = clock.now() + dt.timedelta(seconds=3600)
    mesh._certs = [{"namespace": "frontend", "workload": "api", "not_after": exactly_threshold}]
    alerts2 = mg.validate_sds_rotation(threshold_seconds=3600)
    assert any(_val(x, "type") in ("CERT_ROTATION_RISK", "SDSCertExpirationSoon") for x in alerts2)


def test_canary_deployment_zero_impact_namespace_scoped_and_time_bounded(deps):
    mg, k8s, mesh, signer, rekor, clock = deps

    # Deploy canary in payments, deny-by-default, ttl 300s, dry-run (zero impact)
    try:
        plan = mg.deploy_canary(namespace="payments", deny_by_default=True, credential_ttl_seconds=300, dry_run=True)
    except TypeError:
        # Fallback for positional arguments
        plan = mg.deploy_canary("payments", True, 300, True)

    # Ensure no changes applied to cluster
    assert not k8s._apply_called, "Canary deploy should be zero-impact in dry-run"
    # Ensure scope is limited to 'payments' namespace
    resources = getattr(plan, "resources", None) or getattr(plan, "plan", None) or []
    resources_json = json.dumps(resources)
    assert "payments" in resources_json and "deny" in resources_json.lower()
    assert "orders" not in resources_json

    # Ensure deny-by-default egress in plan
    lower = resources_json.lower()
    assert ("egress" in lower and "deny" in lower) or ("deny-all-egress" in lower)

    # Ensure time-bounded credentials
    expires_at = getattr(plan, "expires_at", None) or (getattr(plan, "metadata", {}) or {}).get("expires_at")
    assert expires_at is not None, "Expected expires_at on canary plan"
    # Expiry should be within now + 300 seconds (+/- small margin)
    if isinstance(expires_at, str):
        # Accept isoformat strings
        expires_at_dt = dt.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    else:
        expires_at_dt = expires_at
    delta = (expires_at_dt - clock.now()).total_seconds()
    assert 250 <= delta <= 360, f"Expected TTL around 300s, got {delta}"


def test_read_only_and_approval_enforced_for_policy_changes(deps):
    mg, k8s, mesh, signer, rekor, clock = deps

    # Create a dummy remediation plan with a denied egress policy to apply
    dummy_plan = type("Plan", (), {"resources": [{"kind": "NetworkPolicy", "metadata": {"namespace": "data"}}]})

    # Dry-run should not apply
    try:
        mg.apply_remediations(dummy_plan, dry_run=True, require_approval=True)
    except TypeError:
        mg.apply_remediations(dummy_plan, True, True)
    assert not k8s._apply_called, "Dry-run must not apply changes"

    # Without explicit approval, applying should raise
    with pytest.raises(MeshGuardError):
        try:
            mg.apply_remediations(dummy_plan, dry_run=False, require_approval=True)
        except TypeError:
            mg.apply_remediations(dummy_plan, False, True)

    # With approval token, allow apply
    k8s.reset_apply()
    try:
        mg.apply_remediations(dummy_plan, dry_run=False, require_approval=True, approval_token="APPROVED")
    except TypeError:
        # Some implementations may accept approvals in kwargs only
        mg.apply_remediations(dummy_plan, False, True, approval_token="APPROVED")
    assert k8s._apply_called, "Expected apply to be called after explicit approval"


def test_signed_immutable_logs_and_privacy_preserving_metadata(deps):
    mg, k8s, mesh, signer, rekor, clock = deps

    # Produce minimal findings with sensitive identifiers
    findings = [
        {
            "type": "AUTHZ_CROSS_NAMESPACE",
            "spiffe_ids": [
                "spiffe://cluster.local/ns/orders/sa/orders-sa",
                "spiffe://cluster.local/ns/payments/sa/payments-sa",
            ],
            "call_graph": {"nodes": [], "edges": []},
            "severity": "high",
        }
    ]
    # Attempt sign and attest
    try:
        receipt = mg.sign_and_attest(findings, privacy_preserving=True, rekor_url=rekor.url)
    except TypeError:
        # Fallback for different signature
        receipt = mg.sign_and_attest(findings, True, rekor.url)

    # Verify signer was used and rekor entry created
    assert signer.signed, "Expected findings to be signed"
    assert rekor.submissions, "Expected submission to Rekor"

    # Verify that metadata is privacy preserving (hashes, not raw SPIFFE IDs)
    last_meta = rekor.submissions[-1]["metadata"] or {}
    meta_json = json.dumps(last_meta)
    assert "spiffe://" not in meta_json
    # Expect hashes for spiffe_ids present
    hashes = last_meta.get("spiffe_id_hashes") or []
    assert hashes and all(len(h) >= 16 for h in hashes)

    # Logs should be immutable: signing digest must match payload digest
    signed_digest = signer.signed[-1]["digest"]
    assert isinstance(receipt, (dict,)) and receipt.get("digest") == signed_digest


def test_error_handling_on_k8s_api_failure(deps):
    mg, k8s, mesh, signer, rekor, clock = deps

    # Simulate underlying API failure
    k8s._raises_on_list_authz = True

    with pytest.raises(MeshGuardError):
        mg.analyze_authorization_policies(namespaces=["default"])