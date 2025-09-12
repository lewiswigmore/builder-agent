import base64
import datetime
import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

# Ethical notice: This tool is designed for authorized testing and audit use only.
# Do not use against systems or datasets without explicit permission.
# It avoids collecting raw PII and stores hashed metadata/metrics with at-rest sealing.
# The included crypto and sigstore components are simulated for testability and must not be used in production.

logger = logging.getLogger("FineTuneSentinel")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# Exceptions
class PolicyViolation(Exception):
    def __init__(self, message: str, report: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.report = report or {}


class PromotionBlocked(Exception):
    pass


class QuarantineTriggered(Exception):
    pass


class EgressViolation(Exception):
    pass


class AttestationError(Exception):
    pass


# Access control
class AccessController:
    def __init__(self, role_policies: Optional[Dict[str, List[str]]] = None):
        # actions: store_evidence, retrieve_evidence, sign_attestation
        self.role_policies = role_policies or {
            "auditor": ["store_evidence", "retrieve_evidence", "sign_attestation"],
            "viewer": ["retrieve_evidence"],
        }

    def check_access(self, role: str, action: str) -> bool:
        return action in self.role_policies.get(role, [])


# Simulated at-rest sealing. Do not use in production.
class SealingProvider:
    def __init__(self, key: Optional[bytes] = None):
        # Use HMAC key for keystream derivation (simulation).
        self._key = key or hashlib.sha256(f"fts:{uuid.uuid4()}".encode()).digest()

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        stream = b""
        counter = 0
        while len(stream) < length:
            block = hmac.new(self._key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            stream += block
            counter += 1
        return stream[:length]

    def seal(self, plaintext: bytes) -> str:
        nonce = uuid.uuid4().bytes
        ks = self._keystream(nonce, len(plaintext))
        ct = bytes([a ^ b for a, b in zip(plaintext, ks)])
        payload = {
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode(),
            "alg": "XOR-HMAC-SHA256-KESTREAM-SIM",
        }
        return base64.b64encode(json.dumps(payload).encode()).decode()

    def unseal(self, sealed: str) -> bytes:
        try:
            payload = json.loads(base64.b64decode(sealed.encode()).decode())
            nonce = base64.b64decode(payload["nonce"].encode())
            ct = base64.b64decode(payload["ct"].encode())
            ks = self._keystream(nonce, len(ct))
            pt = bytes([a ^ b for a, b in zip(ct, ks)])
            return pt
        except Exception as e:
            raise ValueError(f"Unseal failed: {e}") from e


# In-memory encrypted evidence store with role-scoped access
class EvidenceStore:
    def __init__(self, sealer: SealingProvider, acl: AccessController):
        self._sealer = sealer
        self._acl = acl
        self._lock = threading.Lock()
        self._store: Dict[str, str] = {}  # bundle_id -> sealed content

    def store(self, bundle_id: str, bundle: Dict[str, Any], role: str) -> None:
        if not self._acl.check_access(role, "store_evidence"):
            raise PermissionError("Access denied: store_evidence")
        sealed = self._sealer.seal(json.dumps(bundle).encode())
        with self._lock:
            self._store[bundle_id] = sealed

    def retrieve(self, bundle_id: str, role: str) -> Dict[str, Any]:
        if not self._acl.check_access(role, "retrieve_evidence"):
            raise PermissionError("Access denied: retrieve_evidence")
        with self._lock:
            sealed = self._store.get(bundle_id)
        if sealed is None:
            raise KeyError("Evidence bundle not found")
        data = json.loads(self._sealer.unseal(sealed).decode())
        return data

    def exists(self, bundle_id: str) -> bool:
        with self._lock:
            return bundle_id in self._store


# Sigstore-like signer simulator
class SigstoreSigner:
    def __init__(self, identity_email: str, acl: AccessController, role: str = "auditor"):
        self.identity_email = identity_email
        self._acl = acl
        self._role = role
        self._priv = hashlib.sha256(f"sigstore-sim:{identity_email}".encode()).digest()
        self._rekor: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def sign(self, payload: bytes) -> Dict[str, Any]:
        if not self._acl.check_access(self._role, "sign_attestation"):
            raise PermissionError("Access denied: sign_attestation")
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        sig = hmac.new(self._priv, payload, hashlib.sha256).hexdigest()
        payload_hash = hashlib.sha256(payload).hexdigest()
        record = {
            "rekor_uuid": str(uuid.uuid4()),
            "payload_hash": payload_hash,
            "signature": sig,
            "signed_by": self.identity_email,
            "fulcio_issuer": "https://fulcio.sigstore.dev",
            "timestamp": ts,
        }
        with self._lock:
            self._rekor[payload_hash] = record
        return {
            "signature": sig,
            "payload_hash": payload_hash,
            "rekor": record,
        }

    def verify(self, payload: bytes, signature: str) -> bool:
        calc = hmac.new(self._priv, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(calc, signature)

    def get_rekor_record(self, payload_hash: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._rekor.get(payload_hash)


# Egress allowlist enforcement
class EgressAllowlist:
    def __init__(self, allowed_tools: Optional[List[str]] = None):
        self._allowed = set(allowed_tools or ["builtin.canary_tester", "builtin.membership_risk", "builtin.drift_check"])

    def check(self, tools_used: List[str]) -> None:
        not_allowed = [t for t in tools_used if t not in self._allowed]
        if not_allowed:
            raise EgressViolation(f"Egress tools not allowed: {not_allowed}")


@dataclass
class DatasetManifest:
    manifest_id: str
    hashes: Dict[str, str]
    created_at: str
    declared_by: str
    canary_records: List[str] = field(default_factory=list)


@dataclass
class ProvenanceAttestation:
    attestation_id: str
    dataset_manifest_id: str
    source: str
    signed_by: str
    timestamp: str
    signature: str  # Simulated signature of dataset_manifest_id


@dataclass
class Attestation:
    attestation_id: str
    decision_type: str
    job_id: str
    timestamp: str
    payload_hash: str
    signature: str
    rekor_uuid: str
    signed_by: str


@dataclass
class FineTuneJob:
    job_id: str
    provider: str
    dataset_manifest: Optional[DatasetManifest] = None
    provenance_attestation: Optional[ProvenanceAttestation] = None
    state: str = "PENDING"
    blocked_reasons: List[str] = field(default_factory=list)
    quarantined: bool = False
    evidence_ids: List[str] = field(default_factory=list)
    attestations: List[Attestation] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    can_promote: bool = False


class OPAPolicyEngine:
    def __init__(    self,
        require_dataset_manifest: bool = True,
        require_provenance_attestation: bool = True,
        allowed_provenance_sources: Optional[List[str]] = None,
    ):
        self.require_dataset_manifest = require_dataset_manifest
        self.require_provenance_attestation = require_provenance_attestation
        self.allowed_provenance_sources = set(allowed_provenance_sources or ["approved-source"])

    def evaluate_preflight(self, job: FineTuneJob) -> Tuple[bool, Dict[str, Any]]:
        violations = []
        inputs = {
            "job_id": job.job_id,
            "has_manifest": job.dataset_manifest is not None,
            "has_provenance": job.provenance_attestation is not None,
            "provenance_source": getattr(job.provenance_attestation, "source", None),
            "manifest_id": getattr(job.dataset_manifest, "manifest_id", None),
            "provenance_manifest_id": getattr(job.provenance_attestation, "dataset_manifest_id", None),
        }
        if self.require_dataset_manifest and not inputs["has_manifest"]:
            violations.append("missing_dataset_manifest")
        if self.require_provenance_attestation and not inputs["has_provenance"]:
            violations.append("missing_provenance_attestation")
        if inputs["has_manifest"] and inputs["has_provenance"]:
            if inputs["manifest_id"] != inputs["provenance_manifest_id"]:
                violations.append("dataset_manifest_id_mismatch")
            if inputs["provenance_source"] not in self.allowed_provenance_sources:
                violations.append("unapproved_provenance_source")
        decision = len(violations) == 0
        report = {
            "decision_allow": decision,
            "violations": violations,
            "inputs": inputs,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }
        return decision, report


class FineTuneSentinel:
    def __init__(
        self,
        signer: SigstoreSigner,
        evidence_store: EvidenceStore,
        egress_allowlist: EgressAllowlist,
        policy_engine: OPAPolicyEngine,
        membership_risk_threshold: float = 0.5,
    ):
        logger.warning(
            "FineTune Sentinel is for authorized testing and audits only. "
            "Avoid uploading raw PII; only hashed metadata is processed."
        )
        self._signer = signer
        self._evidence_store = evidence_store
        self._egress = egress_allowlist
        self._policy = policy_engine
        self._membership_threshold = membership_risk_threshold
        self._lock = threading.Lock()
        self._jobs: Dict[str, FineTuneJob] = {}

    # Utility hashing
    @staticmethod
    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def register_job(
        self,
        job_id: str,
        provider: str,
        dataset_manifest: Optional[DatasetManifest],
        provenance_attestation: Optional[ProvenanceAttestation],
    ) -> FineTuneJob:
        job = FineTuneJob(job_id=job_id, provider=provider, dataset_manifest=dataset_manifest, provenance_attestation=provenance_attestation)
        with self._lock:
            self._jobs[job_id] = job
        # Preflight OPA policy check
        allow, report = self._policy.evaluate_preflight(job)
        replay_inputs = {
            "job_id": job_id,
            "manifest_id": getattr(dataset_manifest, "manifest_id", None),
            "provenance_attestation_id": getattr(provenance_attestation, "attestation_id", None),
            "policy_report_hash": self._sha256(json.dumps(report, sort_keys=True)),
        }
        if not allow:
            job.state = "BLOCKED"
            job.blocked_reasons.extend(report.get("violations", []))
            # Generate policy violation evidence + attestation
            bundle_id = f"policy-violation-{job_id}-{uuid.uuid4()}"
            evidence = {
                "type": "policy_violation",
                "job_id": job_id,
                "violations": report.get("violations", []),
                "inputs": report.get("inputs"),
                "report_timestamp": report.get("timestamp"),
                "replay_inputs": replay_inputs,
            }
            # Store sealed evidence (no raw PII)
            self._evidence_store.store(bundle_id, evidence, role="auditor")
            job.evidence_ids.append(bundle_id)
            self._emit_signed_attestation(job, decision_type="policy_violation_block", findings={"violations": report.get("violations", [])})
            return job
        # Allow to start
        job.state = "RUNNING"
        job.can_promote = False
        # Evidence of preflight approval
        bundle_id = f"preflight-approval-{job_id}-{uuid.uuid4()}"
        evidence = {
            "type": "preflight_approval",
            "job_id": job_id,
            "report": report,
            "replay_inputs": replay_inputs,
        }
        self._evidence_store.store(bundle_id, evidence, role="auditor")
        job.evidence_ids.append(bundle_id)
        return job

    def run_evaluation(
        self,
        job_id: str,
        model_outputs: List[str],
        tools_used: Optional[List[str]] = None,
        canary_records: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        job = self._jobs.get(job_id)
        if job is None:
            raise KeyError("Unknown job_id")
        self._egress.check(tools_used or ["builtin.canary_tester"])
        job.state = "EVALUATING"
        canaries = canary_records or (job.dataset_manifest.canary_records if job.dataset_manifest else [])
        canary_hits = []
        # Detect canary leakage
        canary_set = set([c for c in canaries if c])
        for out in model_outputs:
            for c in canary_set:
                if c and c in out:
                    canary_hits.append({"canary_hash": self._sha256(c), "output_hash": self._sha256(out)})
        findings = {
            "canary_hits": canary_hits,
            "outputs_count": len(model_outputs),
            "outputs_aggregate_hash": self._sha256("|".join([self._sha256(o) for o in model_outputs])),
        }
        bundle_id = f"evaluation-{job_id}-{uuid.uuid4()}"
        evidence = {
            "type": "evaluation_results",
            "job_id": job_id,
            "findings": findings,
            "replay_inputs": {
                "job_id": job_id,
                "canaries_hash": [self._sha256(c) for c in canaries],
                "tools_used": tools_used or ["builtin.canary_tester"],
            },
        }
        self._evidence_store.store(bundle_id, evidence, role="auditor")
        job.evidence_ids.append(bundle_id)

        if canary_hits:
            job.state = "BLOCKED"
            job.can_promote = False
            job.blocked_reasons.append("canary_leak_detected")
            self._emit_signed_attestation(job, decision_type="canary_leakage_block", findings={"canary_hits": canary_hits})
            raise PromotionBlocked("Promotion blocked due to canary leakage")
        else:
            # No canary leakage found; proceed to further checks
            job.can_promote = True
        return findings

    def assess_membership_inference(
        self,
        job_id: str,
        risk_score: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        job = self._jobs.get(job_id)
        if job is None:
            raise KeyError("Unknown job_id")
        # Compute risk if not provided (placeholder heuristic)
        computed = risk_score if risk_score is not None else 0.0
        decision = "ok"
        if computed > self._membership_threshold:
            decision = "quarantine"
            job.quarantined = True
            job.state = "QUARANTINED"
            job.can_promote = False
            # Store reproducible evidence bundle (hashed/aggregated)
            bundle_id = f"membership-risk-{job_id}-{uuid.uuid4()}"
            evidence = {
                "type": "membership_inference_risk",
                "job_id": job_id,
                "risk_score": computed,
                "threshold": self._membership_threshold,
                "details_hash": self._sha256(json.dumps(details or {}, sort_keys=True)),
                "replay_inputs": {
                    "job_id": job_id,
                    "risk_score": computed,
                    "threshold": self._membership_threshold,
                },
            }
            self._evidence_store.store(bundle_id, evidence, role="auditor")
            job.evidence_ids.append(bundle_id)
            self._emit_signed_attestation(job, decision_type="quarantine", findings={"risk_score": computed})
            raise QuarantineTriggered("Model quarantined due to membership inference risk")
        result = {
            "risk_score": computed,
            "threshold": self._membership_threshold,
            "decision": decision,
        }
        return result

    def _emit_signed_attestation(self, job: FineTuneJob, decision_type: str, findings: Dict[str, Any]) -> Attestation:
        payload = {
            "job_id": job.job_id,
            "decision_type": decision_type,
            "findings_hash": self._sha256(json.dumps(findings, sort_keys=True)),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "provider": job.provider,
            "blocked_reasons": job.blocked_reasons,
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        sig_info = self._signer.sign(payload_bytes)
        att = Attestation(
            attestation_id=str(uuid.uuid4()),
            decision_type=decision_type,
            job_id=job.job_id,
            timestamp=payload["timestamp"],
            payload_hash=sig_info["payload_hash"],
            signature=sig_info["signature"],
            rekor_uuid=sig_info["rekor"]["rekor_uuid"],
            signed_by=sig_info["rekor"]["signed_by"],
        )
        job.attestations.append(att)
        # Store attestation as evidence bundle (sealed)
        bundle_id = f"attestation-{job.job_id}-{att.attestation_id}"
        bundle = {
            "type": "attestation",
            "attestation": {
                "attestation_id": att.attestation_id,
                "decision_type": att.decision_type,
                "job_id": att.job_id,
                "timestamp": att.timestamp,
                "payload_hash": att.payload_hash,
                "signature": att.signature,
                "rekor_uuid": att.rekor_uuid,
                "signed_by": att.signed_by,
            },
        }
        self._evidence_store.store(bundle_id, bundle, role="auditor")
        job.evidence_ids.append(bundle_id)
        return att

    # Public helpers

    def get_job(self, job_id: str) -> FineTuneJob:
        job = self._jobs.get(job_id)
        if job is None:
            raise KeyError("Unknown job_id")
        return job

    def list_attestations(self, job_id: str) -> List[Attestation]:
        job = self.get_job(job_id)
        return list(job.attestations)

    def evidence_exists(self, bundle_id: str) -> bool:
        return self._evidence_store.exists(bundle_id)

    def set_membership_risk_threshold(self, threshold: float) -> None:
        self._membership_threshold = threshold

    # Provider API collection (read-only, hashed)
    def collect_job_metrics(self, job_id: str, provider_metrics: Dict[str, Any]) -> Dict[str, str]:
        job = self.get_job(job_id)
        # Only store hashed metrics keys/values to avoid PII
        hashed = {self._sha256(str(k)): self._sha256(str(v)) for k, v in provider_metrics.items()}
        job.metrics.update({"hashed_metrics": hashed})
        return hashed


# Example factory to instantiate a ready-to-use sentinel
def build_default_sentinel() -> FineTuneSentinel:
    acl = AccessController()
    sealer = SealingProvider()
    store = EvidenceStore(sealer=sealer, acl=acl)
    signer = SigstoreSigner(identity_email="auditor@example.com", acl=acl, role="auditor")
    egress = EgressAllowlist()
    policy = OPAPolicyEngine(
        require_dataset_manifest=True,
        require_provenance_attestation=True,
        allowed_provenance_sources=["approved-source"],
    )
    return FineTuneSentinel(
        signer=signer,
        evidence_store=store,
        egress_allowlist=egress,
        policy_engine=policy,
        membership_risk_threshold=0.5,
    )


# Utility functions to help create manifests/attestations for tests

def create_dataset_manifest(declared_by: str, canaries: Optional[List[str]] = None, hashes: Optional[Dict[str, str]] = None) -> DatasetManifest:
    manifest_id = str(uuid.uuid4())
    m_hashes = hashes or {"train.jsonl": hashlib.sha256(b"train").hexdigest()}
    return DatasetManifest(
        manifest_id=manifest_id,
        hashes=m_hashes,
        created_at=datetime.datetime.utcnow().isoformat() + "Z",
        declared_by=declared_by,
        canary_records=canaries or [],
    )


def create_provenance_attestation(manifest: DatasetManifest, source: str, signed_by: str) -> ProvenanceAttestation:
    att_id = str(uuid.uuid4())
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    sig = hmac.new(hashlib.sha256(f"prov:{signed_by}".encode()).digest(), manifest.manifest_id.encode(), hashlib.sha256).hexdigest()
    return ProvenanceAttestation(
        attestation_id=att_id,
        dataset_manifest_id=manifest.manifest_id,
        source=source,
        signed_by=signed_by,
        timestamp=ts,
        signature=sig,
    )