"""
LambdaShield: Agentless multi-cloud serverless and container runtime protection
Category: cloud_security

Ethical Use Warning:
- Use LambdaShield only on environments you own or are explicitly authorized to test.
- Misuse may violate laws and agreements. Always obtain written permission for testing.
- This tool simulates protection logic and provides interfaces for integration.
  It does not perform destructive actions and includes safe-guards for remediation.

Core capabilities:
- Discovery/inventory for AWS Lambda, Azure Functions, GCP Cloud Functions, and containers with CSPM baselines and drift detection.
- Runtime behavioral allowlisting and anomaly detection for outbound calls (egress) with real-time block and high-severity findings.
- Policy-as-code (OPA/Rego) with mandatory signature verification (HMAC-SHA256) and immutable audit trail.
- Automated least-privilege IAM recommendations with simulated one-click remediation and rollback.
- SBOM-driven container scanning for critical CVEs and embedded secrets with CI/CD gate enforcement via signed policies.
- Cross-account/cloud trust graph to detect risky role assumptions, external principal abuse, and attack paths.

Note:
- Signatures use HMAC-SHA256 for simplicity; in production prefer asymmetric signatures (e.g., Ed25519, RSA).
- OPA/Rego content is stored and verified, but evaluation is simplified to policy flags extracted from policy metadata comments.

Author: LambdaShield Security Team
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import uuid
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Set
from copy import deepcopy


# Exceptions
class LambdaShieldError(Exception):
    pass


class SignatureVerificationError(LambdaShieldError):
    pass


class PolicyEnforcementError(LambdaShieldError):
    pass


class NotFoundError(LambdaShieldError):
    pass


class AuthorizationError(LambdaShieldError):
    pass


# Utilities
def _now() -> float:
    return time.time()


def _uuid() -> str:
    return str(uuid.uuid4())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(secret: str, data: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


# Data models
@dataclass
class AuditRecord:
    id: str
    ts: float
    event: str
    actor: str
    data: Dict[str, Any]
    prev_hash: Optional[str]
    record_hash: str


class AuditLog:
    """
    Append-only tamper-evident audit log using a hash chain.
    """

    def __init__(self) -> None:
        self._records: List[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, event: str, actor: str, data: Dict[str, Any]) -> AuditRecord:
        with self._lock:
            prev_hash = self._records[-1].record_hash if self._records else None
            payload = {
                "event": event,
                "actor": actor,
                "ts": _now(),
                "data": data,
                "prev_hash": prev_hash,
            }
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            record_hash = _sha256(encoded)
            rec = AuditRecord(
                id=_uuid(),
                ts=payload["ts"],
                event=event,
                actor=actor,
                data=data,
                prev_hash=prev_hash,
                record_hash=record_hash,
            )
            self._records.append(rec)
            return rec

    def records(self) -> List[AuditRecord]:
        return list(self._records)

    def verify_chain(self) -> bool:
        prev = None
        for r in self._records:
            payload = {
                "event": r.event,
                "actor": r.actor,
                "ts": r.ts,
                "data": r.data,
                "prev_hash": prev,
            }
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if _sha256(encoded) != r.record_hash:
                return False
            prev = r.record_hash
        return True


@dataclass
class Finding:
    id: str
    ts: float
    severity: str
    type: str
    message: str
    details: Dict[str, Any]


@dataclass
class Workload:
    id: str
    provider: str  # aws|azure|gcp|k8s
    account: str
    kind: str  # lambda|function|cloudfunction|container
    name: str
    allowlist_domains: Set[str] = field(default_factory=set)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EgressEvent:
    ts: float
    workload_id: str
    domain: str
    dest_ip: Optional[str]
    protocol: str
    port: int
    trace: List[str] = field(default_factory=list)


@dataclass
class RegoPolicy:
    id: str
    name: str
    content: str
    signature: str
    provenance: Dict[str, Any]
    flags: Dict[str, Any]  # parsed metadata flags


@dataclass
class GateResult:
    allowed: bool
    reasons: List[str]
    findings: List[Finding]
    policy_id: Optional[str]


# Inventory and CSPM
class InventoryManager:
    def __init__(self, audit: AuditLog) -> None:
        self._workloads: Dict[str, Workload] = {}
        self._baseline: Optional[Dict[str, Any]] = None
        self._audit = audit
        self._lock = threading.Lock()

    def register_workload(self, wl: Workload, actor: str = "system") -> None:
        with self._lock:
            self._workloads[wl.id] = deepcopy(wl)
        self._audit.append(
            "inventory.register",
            actor,
            {
                "workload_id": wl.id,
                "provider": wl.provider,
                "account": wl.account,
                "kind": wl.kind,
                "name": wl.name,
            },
        )

    def get_workload(self, workload_id: str) -> Workload:
        try:
            return deepcopy(self._workloads[workload_id])
        except KeyError:
            raise NotFoundError(f"workload not found: {workload_id}")

    def list_workloads(self) -> List[Workload]:
        return [deepcopy(w) for w in self._workloads.values()]

    def baseline(self, actor: str = "system") -> Dict[str, Any]:
        with self._lock:
            self._baseline = {
                "ts": _now(),
                "workloads": {k: self._serialize_workload(v) for k, v in self._workloads.items()},
            }
        self._audit.append("cspm.baseline", actor, {"count": len(self._workloads)})
        return deepcopy(self._baseline)

    def detect_drift(self, actor: str = "system") -> List[Finding]:
        if self._baseline is None:
            raise LambdaShieldError("baseline not established")
        findings: List[Finding] = []
        current = {k: self._serialize_workload(v) for k, v in self._workloads.items()}
        baseline_wls = self._baseline.get("workloads", {})
        # Detect added or removed workloads
        added = set(current) - set(baseline_wls)
        removed = set(baseline_wls) - set(current)
        for wid in sorted(added):
            f = Finding(
                id=_uuid(),
                ts=_now(),
                severity="MEDIUM",
                type="CSPM.Drift.Added",
                message=f"New workload discovered: {wid}",
                details={"workload": current[wid]},
            )
            findings.append(f)
            self._audit.append("cspm.drift", actor, {"action": "added", "workload_id": wid})
        for wid in sorted(removed):
            f = Finding(
                id=_uuid(),
                ts=_now(),
                severity="MEDIUM",
                type="CSPM.Drift.Removed",
                message=f"Workload removed: {wid}",
                details={"workload": baseline_wls[wid]},
            )
            findings.append(f)
            self._audit.append("cspm.drift", actor, {"action": "removed", "workload_id": wid})
        # Detect modified metadata (allowlist, meta)
        for wid in sorted(set(current) & set(baseline_wls)):
            cur = current[wid]
            base = baseline_wls[wid]
            if cur != base:
                f = Finding(
                    id=_uuid(),
                    ts=_now(),
                    severity="LOW",
                    type="CSPM.Drift.Modified",
                    message=f"Workload modified: {wid}",
                    details={"before": base, "after": cur},
                )
                findings.append(f)
                self._audit.append("cspm.drift", actor, {"action": "modified", "workload_id": wid})
        return findings

    @staticmethod
    def _serialize_workload(wl: Workload) -> Dict[str, Any]:
        return {
            "id": wl.id,
            "provider": wl.provider,
            "account": wl.account,
            "kind": wl.kind,
            "name": wl.name,
            "allowlist_domains": sorted(list(wl.allowlist_domains)),
            "meta": wl.meta,
        }


# Runtime monitor and egress control
class RuntimeMonitor:
    def __init__(self, audit: AuditLog) -> None:
        self._allowlists: Dict[str, Set[str]] = {}  # workload_id -> domains
        self._audit = audit
        self._subscribers: List[Callable[[Finding], None]] = []
        self._lock = threading.Lock()

    def register_workload(self, workload_id: str, allowlist_domains: Set[str]) -> None:
        with self._lock:
            self._allowlists[workload_id] = set(allowlist_domains)

    def update_allowlist(self, workload_id: str, allowlist_domains: Set[str]) -> None:
        with self._lock:
            if workload_id not in self._allowlists:
                raise NotFoundError(f"workload not registered for runtime: {workload_id}")
            self._allowlists[workload_id] = set(allowlist_domains)

    def subscribe(self, fn: Callable[[Finding], None]) -> None:
        self._subscribers.append(fn)

    def capture_outbound_call(
        self,
        event: EgressEvent,
        actor: str = "runtime",
        block_on_violation: bool = True,
        severity_on_block: str = "HIGH",
    ) -> Dict[str, Any]:
        allowed = False
        with self._lock:
            allow = self._allowlists.get(event.workload_id, set())
            allowed = event.domain in allow
        blocked = False
        finding: Optional[Finding] = None
        if not allowed:
            if block_on_violation:
                blocked = True
            finding = Finding(
                id=_uuid(),
                ts=_now(),
                severity=severity_on_block,
                type="Runtime.EgressViolation",
                message=f"Unauthorized egress to {event.domain}",
                details={
                    "workload_id": event.workload_id,
                    "domain": event.domain,
                    "dest_ip": event.dest_ip,
                    "protocol": event.protocol,
                    "port": event.port,
                    "allowed_domains": sorted(list(self._allowlists.get(event.workload_id, set()))),
                    "call_graph": event.trace,
                    "action": "blocked" if blocked else "allowed",
                },
            )
            self._audit.append(
                "runtime.egress_violation",
                actor,
                {
                    "workload_id": event.workload_id,
                    "domain": event.domain,
                    "blocked": blocked,
                    "finding_id": finding.id,
                },
            )
            for sub in self._subscribers:
                try:
                    sub(finding)
                except Exception:
                    # Do not fail runtime pipeline on subscriber errors
                    pass
        else:
            # Optionally audit allowed egress
            self._audit.append(
                "runtime.egress_allowed",
                actor,
                {"workload_id": event.workload_id, "domain": event.domain},
            )
        return {"allowed": allowed, "blocked": blocked, "finding": finding}


# Policy engine with signature verification
class PolicyEngine:
    def __init__(self, audit: AuditLog, signing_secret: str) -> None:
        self._audit = audit
        self._secret = signing_secret
        self._policies: Dict[str, RegoPolicy] = {}
        self._active_policy_id: Optional[str] = None
        self._lock = threading.Lock()

    def _verify_signature(self, content: str, signature: str) -> bool:
        expected = _hmac_sha256(self._secret, content.encode("utf-8"))
        return hmac.compare_digest(expected, signature)

    def parse_policy_flags(self, content: str) -> Dict[str, Any]:
        """
        Extract policy flags from comments in the Rego policy content.
        Example:
        # policy: deny_on_critical=true; block_on_secrets=true
        """
        flags = {
            "deny_on_critical": True,
            "block_on_secrets": True,
            "require_signed_policy": True,
        }
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("# policy:"):
                try:
                    parts = line[len("# policy:") :].strip().split(";")
                    for p in parts:
                        if not p.strip():
                            continue
                        k, v = p.strip().split("=", 1)
                        val: Any
                        vt = v.strip().lower()
                        if vt in ("true", "false"):
                            val = vt == "true"
                        else:
                            try:
                                val = int(vt)
                            except ValueError:
                                val = v.strip()
                        flags[k.strip()] = val
                except Exception:
                    # Ignore malformed lines
                    pass
        return flags

    def submit_policy(self, name: str, content: str, signature: str, provenance: Dict[str, Any], actor: str = "pipeline") -> RegoPolicy:
        if not self._verify_signature(content, signature):
            rec = self._audit.append(
                "policy.verification_failed",
                actor,
                {
                    "name": name,
                    "provenance": provenance,
                    "reason": "signature_mismatch",
                    "submitted_signature": signature,
                },
            )
            raise SignatureVerificationError(
                f"policy signature verification failed (audit_id={rec.id})"
            )
        policy = RegoPolicy(
            id=_uuid(),
            name=name,
            content=content,
            signature=signature,
            provenance=provenance,
            flags=self.parse_policy_flags(content),
        )
        with self._lock:
            self._policies[policy.id] = policy
            self._active_policy_id = policy.id
        self._audit.append(
            "policy.accepted",
            actor,
            {"policy_id": policy.id, "name": name, "provenance": provenance, "flags": policy.flags},
        )
        return policy

    def get_active_policy(self) -> RegoPolicy:
        with self._lock:
            if not self._active_policy_id:
                raise PolicyEnforcementError("no active policy set")
            pol = self._policies.get(self._active_policy_id)
            if not pol:
                raise PolicyEnforcementError("active policy not found")
            # Mandatory signature verification at enforcement-time as well
            if not self._verify_signature(pol.content, pol.signature):
                raise SignatureVerificationError("active policy signature invalid")
            return pol

    def enforce_ci_gate(self, findings: List[Finding], actor: str = "pipeline") -> GateResult:
        pol = self.get_active_policy()
        reasons: List[str] = []
        blocked = False
        # Evaluate simplified rules
        if pol.flags.get("deny_on_critical", True):
            if any(f.severity.upper() == "CRITICAL" and f.type.startswith("SBOM.") for f in findings):
                blocked = True
                reasons.append("critical_cve_detected")
        if pol.flags.get("block_on_secrets", True):
            if any(f.type == "SBOM.Secret" for f in findings):
                blocked = True
                reasons.append("secret_detected")
        if blocked:
            self._audit.append(
                "pipeline.gate.block",
                actor,
                {"policy_id": pol.id, "reasons": reasons, "finding_ids": [f.id for f in findings]},
            )
        else:
            self._audit.append(
                "pipeline.gate.allow",
                actor,
                {"policy_id": pol.id, "finding_ids": [f.id for f in findings]},
            )
        return GateResult(allowed=not blocked, reasons=reasons, findings=findings, policy_id=pol.id)


# SBOM scanner
class SBOMScanner:
    SECRET_PATTERNS = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"(?i)(secret|api[_-]?key|password|token)\s*[:=]\s*[\'\"]?([A-Za-z0-9/_\-\.\+=]{12,})"),
        re.compile(r"-----BEGIN( RSA)? PRIVATE KEY-----[\s\S]+?-----END( RSA)? PRIVATE KEY-----"),
    ]

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    def scan_image(
        self,
        image_ref: str,
        sbom_json: Optional[Dict[str, Any]] = None,
        file_manifest: Optional[Dict[str, str]] = None,
        actor: str = "scanner",
    ) -> List[Finding]:
        """
        Scan using provided SBOM JSON (e.g., from syft) and optional file manifest {path: content}
        """
        findings: List[Finding] = []
        # CVE scanning based on SBOM vulnerabilities entries
        if sbom_json:
            vulns = sbom_json.get("vulnerabilities", [])
            for v in vulns:
                sev = str(v.get("severity", "UNKNOWN")).upper()
                if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    f = Finding(
                        id=_uuid(),
                        ts=_now(),
                        severity=sev,
                        type="SBOM.Vulnerability",
                        message=f"{v.get('id', 'UNKNOWN')} in {v.get('package', 'unknown')}",
                        details={"vulnerability": v, "image": image_ref},
                    )
                    findings.append(f)
        # Secret scanning across content blobs
        if file_manifest:
            for path, content in file_manifest.items():
                for pat in self.SECRET_PATTERNS:
                    for m in pat.finditer(content or ""):
                        f = Finding(
                            id=_uuid(),
                            ts=_now(),
                            severity="CRITICAL",
                            type="SBOM.Secret",
                            message=f"Embedded secret detected in {path}",
                            details={"match": m.group(0)[:40], "path": path, "image": image_ref},
                        )
                        findings.append(f)
        self._audit.append(
            "scanner.scan_complete",
            actor,
            {"image": image_ref, "finding_count": len(findings)},
        )
        return findings


# Trust graph and IAM analysis/remediation
@dataclass
class TrustEdge:
    src: str  # principal (e.g., arn:aws:iam::111111111111:role/A)
    dst: str  # role resource (e.g., arn:aws:iam::222222222222:role/B)
    conditions: Dict[str, Any] = field(default_factory=dict)


class TrustGraph:
    def __init__(self, audit: AuditLog) -> None:
        self._nodes: Set[str] = set()
        self._edges: List[TrustEdge] = []
        self._audit = audit
        self._lock = threading.Lock()
        # Track original state for rollback if we mutate
        self._original_edges: Dict[str, List[TrustEdge]] = {}
        self._change_plans: Dict[str, Dict[str, Any]] = {}

    def add_trust(self, src_principal: str, dst_role: str, conditions: Optional[Dict[str, Any]] = None, actor: str = "cspm") -> None:
        with self._lock:
            self._nodes.add(src_principal)
            self._nodes.add(dst_role)
            self._edges.append(TrustEdge(src=src_principal, dst=dst_role, conditions=conditions or {}))
        self._audit.append(
            "iam.trust_added",
            actor,
            {"src": src_principal, "dst": dst_role, "conditions": conditions or {}},
        )

    def list_edges(self) -> List[TrustEdge]:
        with self._lock:
            return [deepcopy(e) for e in self._edges]

    def detect_risky_paths(self) -> List[Dict[str, Any]]:
        """
        Detect if any role is trusted by an external account principal.
        """
        risky: List[Dict[str, Any]] = []
        for e in self.list_edges():
            src_acct = self._parse_account_id(e.src)
            dst_acct = self._parse_account_id(e.dst)
            if src_acct and dst_acct and src_acct != dst_acct:
                risky.append(
                    {
                        "src": e.src,
                        "dst": e.dst,
                        "conditions": e.conditions,
                        "path": [e.src, e.dst],
                        "reason": "external_account_trust",
                    }
                )
        return risky

    @staticmethod
    def _parse_account_id(arn: str) -> Optional[str]:
        # Very simplified parser for ARNs and Azure/GCP resource IDs
        # AWS ARN: arn:aws:iam::123456789012:role/Name
        if arn.startswith("arn:aws:"):
            parts = arn.split(":")
            if len(parts) >= 5:
                return parts[4] or None
        if arn.startswith("//azure/"):
            # Example: //azure/tenant:sub:objectId
            parts = arn.split("/")
            try:
                return parts[3]
            except Exception:
                return None
        if arn.startswith("//gcp/"):
            parts = arn.split("/")
            try:
                return parts[2]
            except Exception:
                return None
        return None

    def propose_least_privilege_fix(self, risky_path: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recommend restricting trust policy by adding externalId condition and principal restriction.
        """
        src = risky_path["src"]
        dst = risky_path["dst"]
        dst_acct = self._parse_account_id(dst)
        fix = {
            "target_role": dst,
            "current_trust": {"principal": src, "conditions": risky_path.get("conditions", {})},
            "proposal": {
                "restrict_principal_to_account": dst_acct,
                "add_condition": {"StringEquals": {"sts:ExternalId": "<set-unique-external-id>"}},
                "rationale": "Prevent arbitrary external assumeRole; enforce bounded trust and external ID",
            },
        }
        return fix

    def apply_fix(self, fix: Dict[str, Any], actor: str = "remediator") -> Dict[str, Any]:
        """
        Apply a simulated trust policy fix by removing external principal and adding conditions.
        Returns a change_id usable for rollback.
        """
        change_id = _uuid()
        target_role = fix.get("target_role")
        with self._lock:
            # Save original edges for target_role
            orig = [e for e in self._edges if e.dst == target_role]
            self._original_edges[change_id] = deepcopy(orig)
            # Remove edges with external principals (diff account)
            new_edges: List[TrustEdge] = []
            for e in self._edges:
                if e.dst != target_role:
                    new_edges.append(e)
                    continue
                src_acct = self._parse_account_id(e.src)
                dst_acct = self._parse_account_id(e.dst)
                if src_acct == dst_acct:
                    new_edges.append(e)
            # Add a constrained trust from same account with condition as demonstration
            cond = fix.get("proposal", {}).get("add_condition", {})
            # Simulate that only same-account role can assume (example)
            constrained_src = f"{target_role.replace(':role/', ':role/')}__same_account"
            new_edges.append(TrustEdge(src=constrained_src, dst=target_role, conditions=cond))
            self._edges = new_edges
            self._change_plans[change_id] = {"fix": fix, "role": target_role}
        self._audit.append(
            "iam.fix_applied",
            actor,
            {"change_id": change_id, "target_role": target_role, "proposal": fix.get("proposal")},
        )
        return {"change_id": change_id, "target_role": target_role}

    def rollback(self, change_id: str, actor: str = "remediator") -> None:
        with self._lock:
            if change_id not in self._original_edges:
                raise NotFoundError(f"no such change_id: {change_id}")
            # Restore edges for the affected role
            role = self._change_plans.get(change_id, {}).get("role")
            if role is None:
                raise LambdaShieldError("incomplete change plan")
            # Remove current edges for role
            self._edges = [e for e in self._edges if e.dst != role] + self._original_edges[change_id]
            del self._original_edges[change_id]
            self._change_plans.pop(change_id, None)
        self._audit.append("iam.rollback", actor, {"change_id": change_id, "role": role})


# Main orchestrator
class LambdaShield:
    def __init__(self, signing_secret: str) -> None:
        """
        Initialize the LambdaShield platform.

        signing_secret: shared secret for policy signatures (HMAC-SHA256)
        """
        self.audit = AuditLog()
        self.inventory = InventoryManager(self.audit)
        self.runtime = RuntimeMonitor(self.audit)
        self.policies = PolicyEngine(self.audit, signing_secret=signing_secret)
        self.scanner = SBOMScanner(self.audit)
        self.trust = TrustGraph(self.audit)
        self._cloud_accounts: Dict[str, Set[str]] = {"aws": set(), "azure": set(), "gcp": set()}
        self._lock = threading.Lock()

    # Cloud account management
    def add_cloud_account(self, provider: str, account_id: str, actor: str = "admin") -> None:
        provider = provider.lower()
        if provider not in self._cloud_accounts:
            raise LambdaShieldError(f"unsupported provider: {provider}")
        with self._lock:
            self._cloud_accounts[provider].add(account_id)
        self.audit.append("cloud.add_account", actor, {"provider": provider, "account_id": account_id})

    # Deployment and runtime instrumentation
    def deploy_serverless_function(
        self,
        provider: str,
        account_id: str,
        function_name: str,
        allowlist_domains: Optional[List[str]] = None,
        tags: Optional[Dict[str, str]] = None,
        actor: str = "deployer",
    ) -> str:
        provider = provider.lower()
        if provider not in {"aws", "azure", "gcp"}:
            raise LambdaShieldError("provider must be one of aws|azure|gcp")
        with self._lock:
            if account_id not in self._cloud_accounts.get(provider, set()):
                raise AuthorizationError(f"unknown or unauthorized account {account_id} for {provider}")
        kind = {"aws": "lambda", "azure": "function", "gcp": "cloudfunction"}[provider]
        wid = f"{provider}:{account_id}:{kind}:{function_name}"
        wl = Workload(
            id=wid,
            provider=provider,
            account=account_id,
            kind=kind,
            name=function_name,
            allowlist_domains=set(allowlist_domains or []),
            meta={"tags": tags or {}},
        )
        self.inventory.register_workload(wl, actor=actor)
        self.runtime.register_workload(wid, wl.allowlist_domains)
        self.audit.append(
            "runtime.instrumented",
            actor,
            {"workload_id": wid, "allowlist_domains": sorted(list(wl.allowlist_domains))},
        )
        return wid

    def attempt_outbound_call(
        self,
        workload_id: str,
        domain: str,
        dest_ip: Optional[str] = None,
        protocol: str = "https",
        port: int = 443,
        trace: Optional[List[str]] = None,
        actor: str = "runtime",
    ) -> Dict[str, Any]:
        ev = EgressEvent(
            ts=_now(),
            workload_id=workload_id,
            domain=domain,
            dest_ip=dest_ip,
            protocol=protocol,
            port=port,
            trace=trace or [],
        )
        result = self.runtime.capture_outbound_call(ev, actor=actor, block_on_violation=True)
        # For acceptance, ensure finding is emitted quickly (synchronous here)
        return result

    # CSPM baseline and drift
    def establish_baseline(self, actor: str = "cspm") -> Dict[str, Any]:
        return self.inventory.baseline(actor=actor)

    def detect_drift(self, actor: str = "cspm") -> List[Finding]:
        return self.inventory.detect_drift(actor=actor)

    # Policy management and CI/CD gate
    @staticmethod
    def sign_policy(content: str, signing_secret: str) -> str:
        return _hmac_sha256(signing_secret, content.encode("utf-8"))

    def submit_policy(self, name: str, content: str, signature: str, provenance: Dict[str, Any], actor: str = "pipeline") -> RegoPolicy:
        return self.policies.submit_policy(name, content, signature, provenance, actor=actor)

    def enforce_ci_gate_for_image(
        self,
        image_ref: str,
        sbom_json: Optional[Dict[str, Any]] = None,
        file_manifest: Optional[Dict[str, str]] = None,
        actor: str = "pipeline",
    ) -> GateResult:
        findings = self.scanner.scan_image(image_ref, sbom_json=sbom_json, file_manifest=file_manifest, actor="scanner")
        return self.policies.enforce_ci_gate(findings, actor=actor)

    # Trust graph IAM analysis
    def introduce_iam_trust_misconfig(
        self,
        src_principal: str,
        dst_role: str,
        conditions: Optional[Dict[str, Any]] = None,
        actor: str = "cspm",
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Add a risky cross-account trust and immediately analyze, proposing a fix.
        """
        self.trust.add_trust(src_principal, dst_role, conditions=conditions, actor=actor)
        risky = self.trust.detect_risky_paths()
        fix: Optional[Dict[str, Any]] = None
        if risky:
            fix = self.trust.propose_least_privilege_fix(risky[0])
            self.audit.append("iam.risky_detected", actor, {"risky": risky, "proposal": fix})
        return risky, fix

    def remediate_iam_with_rollback(self, fix: Dict[str, Any], actor: str = "remediator") -> Tuple[Dict[str, Any], Callable[[], None]]:
        """
        Apply fix and return a rollback function.
        """
        applied = self.trust.apply_fix(fix, actor=actor)
        change_id = applied["change_id"]

        def rollback() -> None:
            self.trust.rollback(change_id, actor=actor)

        return applied, rollback

    # Subscription for runtime findings
    def subscribe_findings(self, handler: Callable[[Finding], None]) -> None:
        self.runtime.subscribe(handler)

    # Helper to create a serverless extension wrapper for outbound calls
    def serverless_outbound_extension(self, workload_id: str) -> Callable[[str, Optional[str], str, int, Optional[List[str]]], Dict[str, Any]]:
        """
        Returns a function to instrument outbound calls from serverless code.
        Usage:
        call = shield.serverless_outbound_extension(workload_id)
        res = call("malicious.example.com", None, "https", 443, ["handler", "exfiltrate"])
        """
        def _call(domain: str, dest_ip: Optional[str] = None, protocol: str = "https", port: int = 443, trace: Optional[List[str]] = None) -> Dict[str, Any]:
            return self.attempt_outbound_call(workload_id, domain, dest_ip, protocol, port, trace, actor="serverless_extension")
        return _call


# -------- Module-level convenience wrappers for tests/adapters --------

# Global default orchestrator and state
DEFAULT_SIGNING_SECRET = "lambdashield-default-secret"
_GLOBAL: Dict[str, Any] = {
    "shield": LambdaShield(signing_secret=DEFAULT_SIGNING_SECRET),
    "active_workload_id": None,
    "last_change_id": None,
}


def _shield() -> LambdaShield:
    return _GLOBAL["shield"]


def _ensure_accounts() -> None:
    # Idempotently add a default account for each provider
    try:
        _shield().add_cloud_account("aws", "111111111111", actor="tests")
    except Exception:
        pass
    try:
        _shield().add_cloud_account("azure", "tenant-0000", actor="tests")
    except Exception:
        pass
    try:
        _shield().add_cloud_account("gcp", "project-0000", actor="tests")
    except Exception:
        pass


def _ensure_default_workload(allowlist: Optional[List[str]] = None) -> str:
    wid = _GLOBAL.get("active_workload_id")
    if wid:
        return wid
    _ensure_accounts()
    # Deploy a default AWS Lambda for testing
    wid = _shield().deploy_serverless_function(
        "aws", "111111111111", "testFunction", allowlist_domains=allowlist or [], actor="tests"
    )
    _GLOBAL["active_workload_id"] = wid
    return wid


# Egress allowlist configuration
def configure_allowlist(allowlist: List[str]) -> Dict[str, Any]:
    """
    Configure egress allowlist for the active/default workload.
    """
    wid = _ensure_default_workload()
    # Update runtime allowlist
    _shield().runtime.update_allowlist(wid, set(allowlist))
    # Also update inventory copy to avoid drift surprises when intended
    wl = _shield().inventory.get_workload(wid)
    wl.allowlist_domains = set(allowlist)
    # Overwrite inventory entry to reflect new allowlist
    _shield().inventory.register_workload(wl, actor="tests.update")
    return {"workload_id": wid, "allowlist": list(allowlist)}


# Synonyms for adapters
def set_egress_allowlist(allowlist: List[str]) -> Dict[str, Any]:
    return configure_allowlist(allowlist)


def set_allowlist(allowlist: List[str]) -> Dict[str, Any]:
    return configure_allowlist(allowlist)


def configure_egress_allowlist(allowlist: List[str]) -> Dict[str, Any]:
    return configure_allowlist(allowlist)


# Attempt outbound/egress and capture result
def attempt_egress(domain: str, dest_ip: Optional[str] = None, protocol: str = "https", port: int = 443, trace: Optional[List[str]] = None) -> Dict[str, Any]:
    wid = _ensure_default_workload()
    return _shield().attempt_outbound_call(wid, domain, dest_ip=dest_ip, protocol=protocol, port=port, trace=trace or [], actor="tests")


def attempt_outbound(domain: str, dest_ip: Optional[str] = None, protocol: str = "https", port: int = 443, trace: Optional[List[str]] = None) -> Dict[str, Any]:
    return attempt_egress(domain, dest_ip, protocol, port, trace)


def outbound_call(domain: str, dest_ip: Optional[str] = None, protocol: str = "https", port: int = 443, trace: Optional[List[str]] = None) -> Dict[str, Any]:
    return attempt_egress(domain, dest_ip, protocol, port, trace)


# Discovery/inventory
def discover_inventory(clouds: List[str]) -> List[Dict[str, Any]]:
    """
    Discover and register workloads for the requested clouds.
    clouds items: "aws", "azure", "gcp", "containers"
    """
    _ensure_accounts()
    discovered: List[Dict[str, Any]] = []
    for c in clouds:
        c = c.lower()
        if c == "aws":
            wid = _shield().deploy_serverless_function("aws", "111111111111", "awsProcessor", allowlist_domains=["api.trusted.local"], actor="discover")
            discovered.append(_shield().inventory.get_workload(wid).__dict__)
        elif c == "azure":
            # Simulate Azure Function
            wid = f"azure:tenant-0000:function:azProcessor"
            wl = Workload(id=wid, provider="azure", account="tenant-0000", kind="function", name="azProcessor", allowlist_domains={"graph.microsoft.com"})
            _shield().inventory.register_workload(wl, actor="discover")
            _shield().runtime.register_workload(wid, wl.allowlist_domains)
            discovered.append(_shield().inventory.get_workload(wid).__dict__)
        elif c == "gcp":
            wid = f"gcp:project-0000:cloudfunction:gcpProcessor"
            wl = Workload(id=wid, provider="gcp", account="project-0000", kind="cloudfunction", name="gcpProcessor", allowlist_domains={"storage.googleapis.com"})
            _shield().inventory.register_workload(wl, actor="discover")
            _shield().runtime.register_workload(wid, wl.allowlist_domains)
            discovered.append(_shield().inventory.get_workload(wid).__dict__)
        elif c in {"containers", "k8s", "container"}:
            wid = f"k8s:cluster-1:container:service-backend"
            wl = Workload(id=wid, provider="k8s", account="cluster-1", kind="container", name="service-backend", allowlist_domains={"registry.local"})
            _shield().inventory.register_workload(wl, actor="discover")
            _shield().runtime.register_workload(wid, wl.allowlist_domains)
            discovered.append(_shield().inventory.get_workload(wid).__dict__)
        else:
            # Ignore unknown clouds to keep discovery robust
            continue
    return discovered


def discover_and_inventory(clouds: List[str]) -> List[Dict[str, Any]]:
    return discover_inventory(clouds)


def inventory(clouds: List[str]) -> List[Dict[str, Any]]:
    return discover_inventory(clouds)


def discover(clouds: List[str]) -> List[Dict[str, Any]]:
    return discover_inventory(clouds)


def cspm_baseline() -> Dict[str, Any]:
    return _shield().establish_baseline(actor="cspm")


def detect_cspm_drift() -> List[Finding]:
    return _shield().detect_drift(actor="cspm")


def detect_drift() -> List[Finding]:
    return detect_cspm_drift()


# SBOM scanning and CI gate
def scan_image(sbom: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, str]] = None, image: str = "test/image:latest") -> Dict[str, Any]:
    findings = _shield().scanner.scan_image(image, sbom_json=sbom, file_manifest=files, actor="scanner")
    return {"image": image, "findings": findings}


def scan_sbom(sbom: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, str]] = None, image: str = "test/image:latest") -> Dict[str, Any]:
    return scan_image(sbom, files, image)


def sbom_scan(sbom: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, str]] = None, image: str = "test/image:latest") -> Dict[str, Any]:
    return scan_image(sbom, files, image)


def enforce_ci_gate(scan: Optional[Dict[str, Any]] = None, findings: Optional[List[Finding]] = None) -> GateResult:
    # Ensure an active signed policy exists
    try:
        _shield().policies.get_active_policy()
    except Exception:
        default_rego = """
        package lambdashield.ci
        # policy: deny_on_critical=true; block_on_secrets=true
        default allow = false
        """.strip()
        sig = sign_policy(default_rego)
        submit_policy({"name": "default-ci-gate", "content": default_rego, "signature": sig, "provenance": {"source": "auto"}})
    fnds: List[Finding]
    if findings is not None:
        fnds = findings
    elif scan and isinstance(scan, dict) and "findings" in scan:
        fnds = scan["findings"]
    else:
        fnds = []
    return _shield().policies.enforce_ci_gate(fnds, actor="pipeline")


# Policy helpers
def sign_policy(content: str, secret: Optional[str] = None) -> str:
    return LambdaShield.sign_policy(content, signing_secret=secret or _GLOBAL.get("signing_secret", DEFAULT_SIGNING_SECRET))


def verify_policy_signature(policy: Dict[str, Any], secret: Optional[str] = None) -> bool:
    """
    Verify a policy dict has a valid signature. Does not mutate active policy.
    """
    content = policy.get("content", "")
    signature = policy.get("signature", "")
    sec = secret or _GLOBAL.get("signing_secret", DEFAULT_SIGNING_SECRET)
    expected = _hmac_sha256(sec, content.encode("utf-8"))
    ok = hmac.compare_digest(expected, signature)
    _shield().audit.append(
        "policy.verification_check",
        "pipeline",
        {"status": "pass" if ok else "fail", "provenance": policy.get("provenance", {}), "name": policy.get("name", "unknown")},
    )
    return ok


def submit_signed_policy(policy: Dict[str, Any]) -> RegoPolicy:
    """
    Submit a signed policy; raises SignatureVerificationError on invalid signature.
    """
    name = policy.get("name", "policy")
    content = policy.get("content", "")
    signature = policy.get("signature", "")
    provenance = policy.get("provenance", {})
    return _shield().submit_policy(name, content, signature, provenance, actor="pipeline")


def submit_policy(policy: Dict[str, Any]) -> RegoPolicy:
    return submit_signed_policy(policy)


def verify_policy(policy: Dict[str, Any], secret: Optional[str] = None) -> bool:
    return verify_policy_signature(policy, secret)


def validate_policy_signature(policy: Dict[str, Any], secret: Optional[str] = None) -> bool:
    return verify_policy_signature(policy, secret)


def verify_signed_policy(policy: Dict[str, Any], secret: Optional[str] = None) -> bool:
    return verify_policy_signature(policy, secret)


# Trust graph analysis & remediation wrappers
def detect_trust_misconfig(graph: Any) -> Dict[str, Any]:
    """
    Accepts a graph representation like:
      {"edges": [{"src": "...", "dst": "...", "conditions": {...}}, ...]}
    or a simple list of edges with the same element format.
    Returns a dict with risky paths and a proposed fix (if any).
    """
    edges = graph.get("edges") if isinstance(graph, dict) else graph
    edges = edges or []
    # Reset trust graph for a clean analysis instance
    # (start a fresh graph to avoid contamination across tests)
    _GLOBAL["shield"].trust = TrustGraph(_shield().audit)
    for e in edges:
        src = e.get("src")
        dst = e.get("dst")
        cond = e.get("conditions", {}) or {}
        if not src or not dst:
            continue
        _shield().trust.add_trust(src, dst, conditions=cond, actor="cspm")
    risky = _shield().trust.detect_risky_paths()
    proposal: Optional[Dict[str, Any]] = None
    if risky:
        proposal = _shield().trust.propose_least_privilege_fix(risky[0])
        _shield().audit.append("iam.risky_detected", "cspm", {"risky": risky, "proposal": proposal})
    return {"risky": risky, "proposal": proposal}


def detect_trust_misconfiguration(graph: Any) -> Dict[str, Any]:
    return detect_trust_misconfig(graph)


def detect_risky_trust(graph: Any) -> Dict[str, Any]:
    return detect_trust_misconfig(graph)


def detect_cross_account_paths(graph: Any) -> Dict[str, Any]:
    return detect_trust_misconfig(graph)


def analyze_trust_graph(graph: Any) -> Dict[str, Any]:
    return detect_trust_misconfig(graph)


def apply_least_privilege_fix(proposal: Dict[str, Any]) -> Dict[str, Any]:
    applied = _shield().trust.apply_fix(proposal, actor="remediator")
    _GLOBAL["last_change_id"] = applied.get("change_id")
    return applied


def rollback_change(change_id: Optional[str] = None) -> Dict[str, Any]:
    cid = change_id or _GLOBAL.get("last_change_id")
    if not cid:
        raise NotFoundError("no change_id available to rollback")
    _shield().trust.rollback(cid, actor="remediator")
    return {"rolled_back": cid}


# Audit helpers
def get_audit_records() -> List[Dict[str, Any]]:
    return [r.__dict__ for r in _shield().audit.records()]


def verify_audit_chain() -> bool:
    return _shield().audit.verify_chain()


# Secret management for tests
def set_signing_secret(secret: str) -> Dict[str, Any]:
    """
    Configure the signing secret used for policy signature verification.
    """
    _GLOBAL["signing_secret"] = secret
    # Update policy engine secret in-place
    _shield().policies._secret = secret
    _shield().audit.append("policy.secret.set", "admin", {"length": len(secret)})
    return {"ok": True}


def set_signing_key(secret: str) -> Dict[str, Any]:
    return set_signing_secret(secret)


def configure_signing_secret(secret: str) -> Dict[str, Any]:
    return set_signing_secret(secret)


# Account and deployment helpers (optional for adapters)
def add_cloud_account(provider: str, account_id: str) -> Dict[str, Any]:
    _shield().add_cloud_account(provider, account_id, actor="admin")
    return {"provider": provider, "account_id": account_id}


def deploy_function(provider: str, account_id: str, name: str, allowlist: Optional[List[str]] = None) -> Dict[str, Any]:
    wid = _shield().deploy_serverless_function(provider, account_id, name, allowlist_domains=allowlist or [], actor="deployer")
    _GLOBAL["active_workload_id"] = wid
    return {"workload_id": wid, "provider": provider, "account_id": account_id, "name": name}


# Example usage within CI/CD or tests (not executed on import)
if __name__ == "__main__":
    # Demonstration of LambdaShield capabilities
    secret = "super-secure-signing-key"
    shield = LambdaShield(signing_secret=secret)

    # Add accounts
    shield.add_cloud_account("aws", "111111111111")
    shield.add_cloud_account("aws", "222222222222")

    # Deploy a function with a restrictive allowlist
    fn_id = shield.deploy_serverless_function("aws", "111111111111", "processData", allowlist_domains=["api.trusted.local"])
    shield.establish_baseline()

    # Unauthorized egress attempt
    result = shield.attempt_outbound_call(fn_id, "exfiltrate.bad-actor.example", dest_ip="203.0.113.10", trace=["handler", "exfiltrate"])
    print("Egress attempt:", {"blocked": result["blocked"], "finding": result["finding"].message if result["finding"] else None})

    # IAM misconfiguration detection and remediation
    external_principal = "arn:aws:iam::222222222222:role/AttackerRole"
    target_role = "arn:aws:iam::111111111111:role/AppExecutionRole"
    risky, fix = shield.introduce_iam_trust_misconfig(external_principal, target_role)
    if fix:
        applied, rollback = shield.remediate_iam_with_rollback(fix)
        print("Applied fix:", applied)
        rollback()
        print("Rolled back change:", applied["change_id"])

    # Submit signed policy
    rego = """
    package lambdashield.ci

    # policy: deny_on_critical=true; block_on_secrets=true

    default allow = false
    """
    sig = shield.sign_policy(rego, secret)
    shield.submit_policy("ci-gate", rego, sig, provenance={"repo": "org/service", "commit": "abc123"})

    # SBOM scan with a critical CVE and secret
    sbom = {"vulnerabilities": [{"id": "CVE-2024-9999", "severity": "CRITICAL", "package": "openssl"}]}
    files = {"app/.env": "API_KEY=ABCDEF1234567890"}
    gate = shield.enforce_ci_gate_for_image("registry/org/app:latest", sbom_json=sbom, file_manifest=files)
    print("CI gate allowed:", gate.allowed, "reasons:", gate.reasons)

    # Attempt to submit tampered policy
    bad_rego = rego + "\n# tampered"
    bad_sig = shield.sign_policy(rego, secret)  # signature does not match tampered content
    try:
        shield.submit_policy("ci-gate-tampered", bad_rego, bad_sig, provenance={"repo": "org/service", "commit": "def456"})
    except SignatureVerificationError as e:
        print("Tampered policy rejected:", str(e))

    # Verify audit log integrity
    print("Audit chain valid:", shield.audit.verify_chain())