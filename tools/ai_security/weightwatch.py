import os
import json
import time
import hmac
import uuid
import hashlib
import logging
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

"""
WeightWatch: Model Artifact Exfiltration & Registry Leak Hunter

Ethical use only: This tool is intended solely for authorized security monitoring and testing
within environments you own or have explicit permission to assess. Do not use it to access,
interfere with, or monitor systems without consent. The tool operates in read-only fashion with
scoped honey tokens and never mutates production artifacts; quarantines are logical and restricted
to internal namespaces for triage.

Core guarantees:
- Read-only scopes for production: no writes to production registries or storage.
- Signature and provenance gating: requires valid Sigstore/cosign and in-toto/SLSA attestations.
- Data minimization: no storage of weight contents; only hashes, metadata, and signed audit trails
  with immutable, hash-chained timestamp anchors (transparency logs).

This module provides in-memory primitives and interfaces that can be integrated with your systems
to simulate and enforce the required controls. External integrations (cosign, in-toto) are modeled
via pluggable verifiers and lightweight stubs to support testing without network access.
"""

# Configure logger
logger = logging.getLogger("weightwatch")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)sZ %(levelname)s weightwatch: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(obj: Any) -> bytes:
    """
    Produce a canonical JSON representation of obj for stable hashing/signing.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PolicyViolation(Exception):
    def __init__(self, message: str, remediation: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.remediation = remediation
        self.details = details or {}


@dataclass
class ArtifactRecord:
    repo: str
    tag: str
    digest: str
    signed: bool
    provenance_ok: bool
    created_at: datetime = field(default_factory=_now)
    quarantined: bool = False


@dataclass
class PullEvent:
    repo: str
    tag: str
    digest: str
    ip: str
    identity: str
    user_agent: str
    ts: datetime = field(default_factory=_now)


@dataclass
class CanaryRecord:
    canary_id: str
    bucket: str
    watermark: str
    token: str
    allowed_cidrs: List[str]
    created_at: datetime = field(default_factory=_now)
    revoked: bool = False
    note_hash: str = ""  # hash of note/seed, not the note itself


@dataclass
class IncidentBundle:
    incident_id: str
    incident_type: str
    severity: str
    subject: Dict[str, Any]
    summary: str
    details: Dict[str, Any]
    evidence_hashes: List[str]
    timestamp: datetime
    signature_alg: str = "HMAC-SHA256"
    signature: Optional[str] = None
    transparency_anchor: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "subject": self.subject,
            "summary": self.summary,
            "details": self.details,
            "evidence_hashes": self.evidence_hashes,
            "timestamp": self.timestamp.isoformat(),
            "signature_alg": self.signature_alg,
            "signature": self.signature,
            "transparency_anchor": self.transparency_anchor,
        }


class Signer:
    """
    Lightweight signer using HMAC for signed alerts/bundles.
    In production, replace with Sigstore keyless or KMS-backed signing for alerts.
    """

    def __init__(self, key: Optional[bytes] = None):
        env_key = os.environ.get("WEIGHTWATCH_ALERT_SIGNING_KEY")
        if key:
            self._key = key
        elif env_key:
            self._key = env_key.encode("utf-8")
        else:
            # Deterministic ephemeral fallback for testing only
            seed = (os.environ.get("HOSTNAME", "") + os.environ.get("USER", "")).encode("utf-8")
            self._key = hashlib.sha256(seed or b"weightwatch-default").digest()

    def sign(self, data: bytes) -> str:
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature)


class TransparencyLog:
    """
    Append-only hash-chained log for immutable timestamp anchoring.
    """

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []
        self._last_hash: str = "0" * 64

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        ts = _now().isoformat()
        body = {k: entry[k] for k in sorted(entry.keys())}
        body["timestamp"] = ts
        body_bytes = canonical_json(body)
        entry_hash = sha256_hex(body_bytes)
        chain_input = (self._last_hash + entry_hash).encode("utf-8")
        anchor = sha256_hex(chain_input)
        anchored = {
            "index": len(self._entries),
            "timestamp": ts,
            "entry_hash": entry_hash,
            "prev_hash": self._last_hash,
            "anchor": anchor,
        }
        self._entries.append(anchored)
        self._last_hash = anchor
        return anchored

    def head(self) -> Optional[Dict[str, Any]]:
        return self._entries[-1] if self._entries else None

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self._entries)


class AuditStore:
    """
    Minimal audit store for signed, reproducible alerts and event anchors.
    Stores only hashes and metadata (no weight contents).
    """

    def __init__(self, signer: Signer, tlog: TransparencyLog):
        self.signer = signer
        self.tlog = tlog
        self._events: Dict[str, Dict[str, Any]] = {}

    def emit_incident(self, bundle: IncidentBundle) -> IncidentBundle:
        payload = bundle.to_dict()
        # Create canonical signed representation without mutable fields
        sign_obj = dict(payload)
        sign_obj.pop("signature", None)
        sign_obj.pop("transparency_anchor", None)
        signature = self.signer.sign(canonical_json(sign_obj))
        bundle.signature = signature
        anchor = self.tlog.append({"type": "incident", "incident_id": bundle.incident_id, "signature": signature})
        bundle.transparency_anchor = anchor
        self._events[bundle.incident_id] = bundle.to_dict()
        logger.warning("Incident anchored: id=%s anchor=%s", bundle.incident_id, anchor["anchor"])
        return bundle

    def verify_incident(self, incident: IncidentBundle) -> bool:
        sign_obj = dict(incident.to_dict())
        signature = sign_obj.pop("signature", None)
        sign_obj.pop("transparency_anchor", None)
        if not signature:
            return False
        return self.signer.verify(canonical_json(sign_obj), signature)

    def list_incidents(self) -> List[Dict[str, Any]]:
        return list(self._events.values())


class CosignVerifier:
    """
    Stub verifier for Sigstore/cosign signatures.
    Integrate with cosign CLI or APIs in production.
    """

    def verify(self, repo: str, tag: str, digest: str, record: ArtifactRecord) -> bool:
        return bool(record.signed)


class InTotoVerifier:
    """
    Stub verifier for in-toto/SLSA provenance.
    Integrate with in-toto attestation verification in production.
    """

    def verify(self, repo: str, digest: str, record: ArtifactRecord) -> bool:
        return bool(record.provenance_ok)


class RegistryMonitor:
    """
    Read-only view over artifact registry metadata and tag state.
    Detects tag drift and signature/provenance compliance.
    """

    def __init__(self, cosign: CosignVerifier, intoto: InTotoVerifier):
        self._records: Dict[Tuple[str, str], ArtifactRecord] = {}
        self.cosign = cosign
        self.intoto = intoto

    def register_artifact(self, repo: str, tag: str, digest: str, signed: bool, provenance_ok: bool) -> ArtifactRecord:
        rec = ArtifactRecord(repo=repo, tag=tag, digest=digest, signed=signed, provenance_ok=provenance_ok)
        self._records[(repo, tag)] = rec
        logger.info("Registered artifact: %s:%s digest=%s signed=%s provenance=%s", repo, tag, digest, signed, provenance_ok)
        return rec

    def get_record(self, repo: str, tag: str) -> Optional[ArtifactRecord]:
        return self._records.get((repo, tag))

    def detect_tag_drift(self, repo: str, tag: str, new_digest: str) -> Optional[str]:
        rec = self.get_record(repo, tag)
        if rec and rec.digest != new_digest:
            logger.error("Tag drift detected for %s:%s expected=%s got=%s", repo, tag, rec.digest, new_digest)
            return f"Tag drift detected for {repo}:{tag}, expected {rec.digest} but observed {new_digest}"
        return None

    def verify_artifact(self, repo: str, tag: str) -> bool:
        rec = self.get_record(repo, tag)
        if not rec:
            return False
        sig_ok = self.cosign.verify(repo, tag, rec.digest, rec)
        prov_ok = self.intoto.verify(repo, rec.digest, rec)
        return sig_ok and prov_ok

    def set_quarantined(self, repo: str, tag: str, quarantined: bool = True) -> None:
        rec = self.get_record(repo, tag)
        if rec:
            # Read-only policy: no mutation of production artifacts; internal flag only.
            rec.quarantined = quarantined
            logger.warning("Quarantine status set: %s:%s -> %s", repo, tag, quarantined)

    def list_artifacts(self) -> List[ArtifactRecord]:
        return [v for v in self._records.values()]


class QuarantineManager:
    """
    Logical quarantine registry namespace and controls.
    """

    def __init__(self, registry: RegistryMonitor):
        self.registry = registry
        self._quarantined: set = set()  # (repo, tag)

    def quarantine(self, repo: str, tag: str) -> None:
        self._quarantined.add((repo, tag))
        self.registry.set_quarantined(repo, tag, True)

    def release(self, repo: str, tag: str) -> None:
        self._quarantined.discard((repo, tag))
        self.registry.set_quarantined(repo, tag, False)

    def is_quarantined(self, repo: str, tag: str) -> bool:
        return (repo, tag) in self._quarantined


class ProvenanceCorrelator:
    """
    Correlates egress events with CI/CD provenance windows.
    """

    def __init__(self):
        # identity -> list of (start, end, run_id, commit)
        self._runs: Dict[str, List[Tuple[datetime, datetime, str, str]]] = defaultdict(list)

    def record_run(self, identity: str, run_id: str, commit: str, start: datetime, end: datetime):
        self._runs[identity].append((start, end, run_id, commit))

    def correlate(self, identity: str, ts: datetime) -> Optional[Tuple[str, str]]:
        for start, end, run_id, commit in self._runs.get(identity, []):
            if start <= ts <= end:
                return (run_id, commit)
        return None


class PullMonitor:
    """
    Pull monitoring with anomaly detection and automatic incident generation/quarantine.
    """

    def __init__(
        self,
        registry: RegistryMonitor,
        audit: AuditStore,
        quarantine: QuarantineManager,
        prov_corr: ProvenanceCorrelator,
    ):
        self.registry = registry
        self.audit = audit
        self.quarantine = quarantine
        self.prov_corr = prov_corr
        # Tag baseline configs
        self._baselines: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # Pull history per (repo, tag)
        self._pulls: Dict[Tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=1000))

    def set_baseline(
        self,
        repo: str,
        tag: str,
        allowed_cidrs: List[str],
        allowed_identities: List[str],
        max_rate_per_min: int,
        ua_patterns: Optional[List[str]] = None,
    ):
        self._baselines[(repo, tag)] = {
            "allowed_cidrs": allowed_cidrs,
            "allowed_identities": set(allowed_identities),
            "max_rate_per_min": max_rate_per_min,
            "ua_patterns": ua_patterns or [],
        }

    @staticmethod
    def _ip_in_any_cidr(ip: str, cidrs: List[str]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
            except ValueError:
                continue
        return False

    def record_pull(self, event: PullEvent) -> Optional[IncidentBundle]:
        key = (event.repo, event.tag)
        baseline = self._baselines.get(key)
        rec = self.registry.get_record(event.repo, event.tag)
        if not rec:
            logger.error("Pull for unknown artifact: %s:%s", event.repo, event.tag)
            return None

        pulls = self._pulls[key]
        pulls.append(event)

        anomalies = []
        if baseline:
            if not self._ip_in_any_cidr(event.ip, baseline["allowed_cidrs"]):
                anomalies.append("ip_outside_allowed_cidrs")
            if event.identity not in baseline["allowed_identities"]:
                anomalies.append("unknown_identity")
            if baseline["ua_patterns"]:
                if not any(pat in event.user_agent for pat in baseline["ua_patterns"]):
                    anomalies.append("unexpected_user_agent")
            # Rate check in last minute
            one_min_ago = _now() - timedelta(minutes=1)
            recent_count = sum(1 for e in pulls if e.ts >= one_min_ago)
            if recent_count > baseline["max_rate_per_min"]:
                anomalies.append("rate_surge")
        else:
            anomalies.append("no_baseline_configured")

        # Correlate with CI/CD provenance windows
        prov_match = self.prov_corr.correlate(event.identity, event.ts)
        if not prov_match:
            anomalies.append("no_ci_provenance_correlation")

        if anomalies:
            # Check signatures and provenance to confirm risk
            signatures_ok = self.registry.verify_artifact(event.repo, event.tag)
            severity = "high" if not signatures_ok else "medium"
            subject = {
                "repo": event.repo,
                "tag": event.tag,
                "digest": rec.digest,
            }
            summary = "Anomalous pull pattern detected"
            details = {
                "anomalies": anomalies,
                "ip": event.ip,
                "identity": event.identity,
                "user_agent": event.user_agent,
                "signatures_ok": signatures_ok,
                "provenance_ok": rec.provenance_ok,
                "quarantine_action": False,
            }
            # Quarantine if signatures/provenance not ok
            if not signatures_ok:
                self.quarantine.quarantine(event.repo, event.tag)
                details["quarantine_action"] = True

            ev_hash = sha256_hex(
                canonical_json(
                    {
                        "repo": event.repo,
                        "tag": event.tag,
                        "digest": rec.digest,
                        "ip": event.ip,
                        "identity": event.identity,
                        "ts": event.ts.isoformat(),
                    }
                )
            )
            bundle = IncidentBundle(
                incident_id=str(uuid.uuid4()),
                incident_type="anomalous_pull",
                severity=severity,
                subject=subject,
                summary=summary,
                details=details,
                evidence_hashes=[ev_hash],
                timestamp=_now(),
            )
            return self.audit.emit_incident(bundle)
        return None


class CanaryManager:
    """
    Canary shard seeding and detection with scoped honey tokens.
    Read-only by design; canary creation is within designated sandbox/private buckets.
    """

    def __init__(self, audit: AuditStore):
        self.audit = audit
        self._canaries: Dict[str, CanaryRecord] = {}
        # Token -> canary_id
        self._token_index: Dict[str, str] = {}

    def seed_canary(self, bucket: str, note: str, allowed_cidrs: List[str]) -> CanaryRecord:
        canary_id = str(uuid.uuid4())
        token = sha256_hex((canary_id + ":token").encode("utf-8"))[:32]
        note_hash = sha256_hex(note.encode("utf-8"))
        watermark = sha256_hex((canary_id + ":" + note_hash).encode("utf-8"))
        rec = CanaryRecord(
            canary_id=canary_id,
            bucket=bucket,
            watermark=watermark,
            token=token,
            allowed_cidrs=allowed_cidrs,
            note_hash=note_hash,
        )
        self._canaries[canary_id] = rec
        self._token_index[token] = canary_id
        logger.info("Seeded canary shard: id=%s bucket=%s", canary_id, bucket)
        return rec

    def get_canary(self, canary_id: str) -> Optional[CanaryRecord]:
        return self._canaries.get(canary_id)

    def verify_watermark(self, canary_id: str, presented_watermark: str) -> bool:
        rec = self._canaries.get(canary_id)
        if not rec:
            return False
        return hmac.compare_digest(rec.watermark, presented_watermark)

    def revoke_token(self, token: str) -> None:
        canary_id = self._token_index.get(token)
        if canary_id:
            rec = self._canaries.get(canary_id)
            if rec:
                rec.revoked = True
                logger.warning("Revoked honey token for canary id=%s", canary_id)
            self._token_index.pop(token, None)

    @staticmethod
    def _ip_in_any_cidr(ip: str, cidrs: List[str]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
            except ValueError:
                continue
        return False

    def record_access(
        self,
        canary_id: str,
        token: str,
        ip: str,
        presented_watermark: Optional[str] = None,
    ) -> Optional[IncidentBundle]:
        rec = self._canaries.get(canary_id)
        if not rec:
            logger.error("Access for unknown canary id=%s", canary_id)
            return None
        if rec.revoked:
            logger.info("Access attempt for revoked canary id=%s", canary_id)
        # Disallow if token mismatch
        token_ok = token == rec.token and not rec.revoked
        ip_allowed = self._ip_in_any_cidr(ip, rec.allowed_cidrs)
        wm_ok = self.verify_watermark(canary_id, presented_watermark or "")

        if (not ip_allowed) or (not token_ok) or (presented_watermark and not wm_ok):
            summary = "Canary access policy violation"
            details = {
                "ip": ip,
                "token_ok": token_ok,
                "ip_allowed": ip_allowed,
                "watermark_valid": wm_ok if presented_watermark else None,
                "action_token_revoked": False,
            }
            # Revoke token on policy breach
            if token_ok and not ip_allowed:
                self.revoke_token(token)
                details["action_token_revoked"] = True

            evidence = {
                "canary_id": canary_id,
                "bucket": rec.bucket,
                "ip": ip,
                "token_present": bool(token),
                "presented_watermark": presented_watermark,
                "ts": _now().isoformat(),
            }
            ev_hash = sha256_hex(canonical_json(evidence))
            bundle = IncidentBundle(
                incident_id=str(uuid.uuid4()),
                incident_type="canary_access_violation",
                severity="high",
                subject={"canary_id": canary_id, "bucket": rec.bucket},
                summary=summary,
                details=details,
                evidence_hashes=[ev_hash],
                timestamp=_now(),
            )
            return self.audit.emit_incident(bundle)
        return None


class PolicyGate:
    """
    Enforces signature and provenance gating for promotions.
    """

    def __init__(self, registry: RegistryMonitor):
        self.registry = registry

    def gate_promotion(
        self,
        repo: str,
        revision_digest: str,
        target_tag: str,
        signed: bool,
        provenance_ok: bool,
    ) -> str:
        """
        Validate promotion preconditions. Returns message if allowed, raises PolicyViolation if blocked.
        """
        # Read-only: we only validate; do not perform the promotion.
        if not signed or not provenance_ok:
            remediation_cmds = []
            if not signed:
                remediation_cmds.append(
                    f"# sign the artifact digest\ncosign sign --key $COSIGN_KEY {repo}@{revision_digest}"
                )
                remediation_cmds.append(
                    f"# verify the signature\ncosign verify {repo}@{revision_digest}"
                )
            if not provenance_ok:
                remediation_cmds.append(
                    "# attach in-toto/SLSA provenance attestation\nin-toto-attest --predicate slsa.json --subject-digest "
                    + revision_digest
                )
                remediation_cmds.append(
                    "# verify attestation\nin-toto-verify --layout root.layout --layout-keys root.pub --products " + revision_digest
                )
            remediation = "\n".join(remediation_cmds)
            diff = {
                "required": {"signed": True, "provenance_ok": True},
                "provided": {"signed": signed, "provenance_ok": provenance_ok},
            }
            raise PolicyViolation(
                message=f"Promotion blocked: {repo}@{revision_digest} -> {target_tag} fails policy checks",
                remediation=remediation,
                details=diff,
            )
        # Optionally detect tag drift preemptively
        drift = self.registry.detect_tag_drift(repo, target_tag, revision_digest)
        if drift:
            raise PolicyViolation(
                message=f"Promotion blocked due to tag drift risk: {drift}",
                remediation="Ensure tag is updated via approved promotion pipeline with signed provenance.",
            )
        return f"Promotion allowed: {repo}@{revision_digest} -> {target_tag}"


class WeightWatch:
    """
    Facade for WeightWatch capabilities:
    - Registry monitoring and signature/provenance verification
    - Pull anomaly detection and quarantining of risky tags (logical only)
    - Canary seeding and exfiltration detection with token revocation
    - Promotion policy gate enforcing cosign + in-toto
    - Signed, reproducible incident bundles anchored to transparency logs
    """

    def __init__(self):
        self.signer = Signer()
        self.tlog = TransparencyLog()
        self.audit = AuditStore(self.signer, self.tlog)
        self.cosign = CosignVerifier()
        self.intoto = InTotoVerifier()
        self.registry = RegistryMonitor(self.cosign, self.intoto)
        self.quarantine = QuarantineManager(self.registry)
        self.prov_corr = ProvenanceCorrelator()
        self.pull_monitor = PullMonitor(self.registry, self.audit, self.quarantine, self.prov_corr)
        self.canaries = CanaryManager(self.audit)
        self.policy_gate = PolicyGate(self.registry)

    # ---------- Simulation helpers for acceptance tests ----------

    def simulate_anomalous_pull_surge(
        self,
        repo: str,
        tag: str,
        digest: str,
        signed: bool,
        provenance_ok: bool,
        baseline_allowed_cidrs: List[str],
        baseline_identities: List[str],
        max_rate_per_min: int,
        pulls: List[Tuple[str, str, str]],  # list of (ip, identity, user_agent)
    ) -> Optional[IncidentBundle]:
        """
        Simulate a surge of pulls for a protected tag from unknown IP/identity.
        Returns the resulting incident bundle if triggered.
        """
        self.registry.register_artifact(repo, tag, digest, signed, provenance_ok)
        self.pull_monitor.set_baseline(
            repo=repo,
            tag=tag,
            allowed_cidrs=baseline_allowed_cidrs,
            allowed_identities=baseline_identities,
            max_rate_per_min=max_rate_per_min,
            ua_patterns=["ci/", "pipelines/"],
        )
        # Correlate known CI identity
        start = _now() - timedelta(minutes=5)
        end = _now() + timedelta(minutes=5)
        if baseline_identities:
            self.prov_corr.record_run(identity=baseline_identities[0], run_id="ci-123", commit="deadbeef", start=start, end=end)

        incident: Optional[IncidentBundle] = None
        for ip, identity, ua in pulls:
            evt = PullEvent(repo=repo, tag=tag, digest=digest, ip=ip, identity=identity, user_agent=ua, ts=_now())
            incident = self.pull_monitor.record_pull(evt) or incident
            # Simulate surge: no sleep
        return incident

    def simulate_canary_access(
        self,
        bucket: str,
        note: str,
        allowed_cidrs: List[str],
        access_ip: str,
        present_watermark: bool = True,
    ) -> Tuple[CanaryRecord, Optional[IncidentBundle]]:
        """
        Seed a signed canary shard and attempt retrieval from given IP.
        Revokes the scoped token and anchors alert on violation.
        """
        can = self.canaries.seed_canary(bucket=bucket, note=note, allowed_cidrs=allowed_cidrs)
        wm = can.watermark if present_watermark else "invalid"
        incident = self.canaries.record_access(canary_id=can.canary_id, token=can.token, ip=access_ip, presented_watermark=wm)
        return can, incident

    def simulate_unsigned_promotion(
        self,
        repo: str,
        revision_digest: str,
        target_tag: str,
        signed: bool,
        provenance_ok: bool,
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[Dict[str, Any]]]:
        """
        Attempt to promote an unsigned model revision to 'stable'.
        Returns tuple: (allowed, message, remediation, details)
        """
        try:
            msg = self.policy_gate.gate_promotion(
                repo=repo,
                revision_digest=revision_digest,
                target_tag=target_tag,
                signed=signed,
                provenance_ok=provenance_ok,
            )
            return True, msg, None, None
        except PolicyViolation as e:
            return False, str(e), e.remediation, e.details


# --------- Example safeguards (disabled by default) ---------
# The following demonstrates how the tool could be used programmatically.
# Ensure you only run these in authorized test environments.
if __name__ == "__main__":
    ww = WeightWatch()

    # Example 1: anomalous pull surge detection and quarantine
    incident1 = ww.simulate_anomalous_pull_surge(
        repo="org/protected-model",
        tag="v1.2.3",
        digest="sha256:" + "a" * 64,
        signed=False,
        provenance_ok=False,
        baseline_allowed_cidrs=["10.0.0.0/8", "192.168.0.0/16"],
        baseline_identities=["ci-bot"],
        max_rate_per_min=10,
        pulls=[
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
            ("203.0.113.10", "unknown-user", "python-requests/2.31"),
        ],
    )
    if incident1:
        logger.info("Incident1: %s", json.dumps(incident1.to_dict(), indent=2))

    # Example 2: canary access from disallowed CIDR triggers revocation and alert anchoring
    can, incident2 = ww.simulate_canary_access(
        bucket="private-bucket",
        note="secret-canary",
        allowed_cidrs=["10.0.0.0/8"],
        access_ip="198.51.100.99",
        present_watermark=True,
    )
    if incident2:
        logger.info("Incident2: %s", json.dumps(incident2.to_dict(), indent=2))

    # Example 3: promotion gate blocks unsigned/no provenance
    allowed, msg, remediation, details = ww.simulate_unsigned_promotion(
        repo="org/protected-model",
        revision_digest="sha256:" + "b" * 64,
        target_tag="stable",
        signed=False,
        provenance_ok=False,
    )
    if not allowed:
        logger.info("Promotion blocked: %s\nRemediation:\n%s\nDetails:%s", msg, remediation, json.dumps(details, indent=2))
    else:
        logger.info("Promotion allowed: %s", msg)