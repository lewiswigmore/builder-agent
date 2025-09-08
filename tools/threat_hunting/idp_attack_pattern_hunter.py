"""
IdP Attack Pattern Hunter: MFA Fatigue, AiTM & Consent Abuse

Ethical and legal warning:
- Use this tool only on systems and data you are explicitly authorized to monitor and test.
- Ensure compliance with organizational policies, privacy regulations, and applicable laws.
- PII minimization and encryption are provided, but you must configure keys and access controls responsibly.

This tool:
- Ingests IdP and EDR/SIEM events (read-only by default).
- Correlates signals to detect MFA fatigue/push-bombing, adversary-in-the-middle token replay, device-code phishing indicators, and OAuth consent-grant abuse.
- Uses deterministic rulepacks plus ML-assisted heuristics.
- Produces signed detections and incident bundles.
- Provides human-in-the-loop playbooks; response actions are optional and require explicit policy and human approval with full audit trails.
- Maintains tamper-evident audit logging and retention controls.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ----------------------- Simple crypto and signing (warning: illustrative) -----------------------


class SimpleCrypto:
    """
    Simple symmetric crypto and signing utilities.
    WARNING: This is a lightweight reversible keystream/XOR mechanism for field-level encryption
    in demonstration contexts. For production, use a vetted crypto library and KMS/HSM.
    """

    def __init__(self, secret_key: bytes):
        if not secret_key or len(secret_key) < 16:
            raise ValueError("Secret key must be provided and at least 16 bytes.")
        self._key = secret_key

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        stream = b""
        counter = 0
        while len(stream) < length:
            block = hashlib.sha256(self._key + nonce + counter.to_bytes(8, "big")).digest()
            stream += block
            counter += 1
        return stream[:length]

    def encrypt(self, plaintext: str) -> str:
        if plaintext is None:
            return ""
        b = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(16)
        ks = self._keystream(nonce, len(b))
        ct = bytes([a ^ c for a, c in zip(b, ks)])
        token = base64.urlsafe_b64encode(nonce + ct).decode("ascii")
        return token

    def decrypt(self, token: str) -> str:
        if not token:
            return ""
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        nonce, ct = raw[:16], raw[16:]
        ks = self._keystream(nonce, len(ct))
        pt = bytes([a ^ c for a, c in zip(ct, ks)])
        return pt.decode("utf-8")

    def sign(self, data: bytes) -> str:
        mac = hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return mac

    def verify(self, data: bytes, signature: str) -> bool:
        try:
            mac = hmac.new(self._key, data, hashlib.sha256).hexdigest()
            return hmac.compare_digest(mac, signature)
        except Exception:
            return False

    def hmac_hash(self, value: str) -> str:
        """Deterministic HMAC-based pseudonymous hash for PII minimization."""
        if value is None:
            return ""
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()


# ----------------------- Tamper-evident audit logging -----------------------


@dataclass
class AuditEntry:
    ts: str
    actor: str
    action: str
    details: Dict[str, Any]
    prev_hash: str
    entry_hash: str


class AuditLogger:
    def __init__(self, crypto: SimpleCrypto):
        self._crypto = crypto
        self._entries: List[AuditEntry] = []
        self._last_hash = "GENESIS"
        self._lock = threading.Lock()

    def append(self, actor: str, action: str, details: Dict[str, Any]) -> None:
        with self._lock:
            ts = dt.datetime.now(dt.timezone.utc).isoformat()
            digest_input = json.dumps(
                {"ts": ts, "actor": actor, "action": action, "details": details, "prev": self._last_hash},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            entry_hash = self._crypto.sign(digest_input)
            entry = AuditEntry(ts=ts, actor=actor, action=action, details=details, prev_hash=self._last_hash, entry_hash=entry_hash)
            self._entries.append(entry)
            self._last_hash = entry_hash

    def export(self) -> List[Dict[str, Any]]:
        return [entry.__dict__ for entry in self._entries]


# ----------------------- Event storage with PII minimization and retention -----------------------


def mask_ip(ip: Optional[str]) -> str:
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = ip.split(".")
            return ".".join(parts[:3] + ["0"])
        else:
            # Mask to /64
            return str(ipaddress.IPv6Address(int(addr) >> 64 << 64))
    except Exception:
        return ""


@dataclass
class Event:
    id: str
    ts: dt.datetime
    source: str  # "okta", "azuread", "google", "edr", "siem", "network"
    type: str  # e.g., "mfa_challenge", "mfa_approved", "login_success", "token_used", "oauth_app_created", "oauth_consent_granted"
    actor_hash: str
    # Sensitive attributes stored encrypted
    actor_enc: Optional[str] = None
    ip_masked: Optional[str] = None
    ip_enc: Optional[str] = None
    asn: Optional[str] = None
    device_fp_hash: Optional[str] = None
    device_fp_enc: Optional[str] = None
    token_issuer: Optional[str] = None
    issuer_anomalous: Optional[bool] = None
    app_id: Optional[str] = None
    app_name_enc: Optional[str] = None
    scopes: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)


class EventStore:
    def __init__(self, crypto: SimpleCrypto, retention_days: int = 30):
        self._crypto = crypto
        self._retention_days = retention_days
        self._events: List[Event] = []
        self._lock = threading.Lock()
        # Baselines
        self._baseline_asn_by_user: Dict[str, set] = {}
        self._baseline_ip_by_user: Dict[str, set] = {}

    def set_retention_days(self, days: int) -> None:
        if days < 1 or days > 3650:
            raise ValueError("Retention days must be between 1 and 3650.")
        self._retention_days = days

    def purge_old(self, now: Optional[dt.datetime] = None) -> int:
        if now is None:
            now = dt.datetime.now(dt.timezone.utc)
        cutoff = now - dt.timedelta(days=self._retention_days)
        with self._lock:
            before = len(self._events)
            self._events = [e for e in self._events if e.ts >= cutoff]
            return before - len(self._events)

    def _hash(self, value: Optional[str]) -> str:
        return self._crypto.hmac_hash(value or "")

    def _enc(self, value: Optional[str]) -> str:
        return self._crypto.encrypt(value or "")

    def ingest(self, source: str, type_: str, ts: Optional[dt.datetime], attrs: Dict[str, Any]) -> str:
        """
        Read-only ingestion of external logs. PII minimized; sensitive fields encrypted.
        attrs keys may include: user, email, ip, asn, device_fp, token_issuer, issuer_anomalous, app_id, app_name, scopes, extra
        """
        if ts is None:
            ts = dt.datetime.now(dt.timezone.utc)
        user = attrs.get("user") or attrs.get("email") or attrs.get("principal")
        actor_hash = self._hash(str(user)) if user else ""
        device_fp = attrs.get("device_fp") or ""
        ip = attrs.get("ip") or ""
        asn = attrs.get("asn") or ""
        app_name = attrs.get("app_name") or ""
        event = Event(
            id=secrets.token_hex(8),
            ts=ts,
            source=source,
            type=type_,
            actor_hash=actor_hash,
            actor_enc=self._enc(str(user)) if user else None,
            ip_masked=mask_ip(ip),
            ip_enc=self._enc(ip) if ip else None,
            asn=str(asn) if asn else None,
            device_fp_hash=self._hash(device_fp) if device_fp else None,
            device_fp_enc=self._enc(device_fp) if device_fp else None,
            token_issuer=attrs.get("token_issuer"),
            issuer_anomalous=attrs.get("issuer_anomalous"),
            app_id=attrs.get("app_id"),
            app_name_enc=self._enc(app_name) if app_name else None,
            scopes=list(attrs.get("scopes") or []),
            extra=dict(attrs.get("extra") or {}),
        )
        with self._lock:
            self._events.append(event)
            # Update baselines cautiously: only after successful login or stable events
            if type_ in ("login_success", "token_used"):
                if actor_hash:
                    self._baseline_asn_by_user.setdefault(actor_hash, set())
                    self._baseline_ip_by_user.setdefault(actor_hash, set())
                    if asn:
                        self._baseline_asn_by_user[actor_hash].add(str(asn))
                    if ip:
                        self._baseline_ip_by_user[actor_hash].add(mask_ip(ip))
        return event.id

    def list_events(self, since: Optional[dt.datetime] = None) -> List[Event]:
        with self._lock:
            if not since:
                return list(self._events)
            return [e for e in self._events if e.ts >= since]

    def get_user_baseline(self, actor_hash: str) -> Tuple[set, set]:
        return self._baseline_asn_by_user.get(actor_hash, set()), self._baseline_ip_by_user.get(actor_hash, set())


# ----------------------- Rulepacks and detections -----------------------


@dataclass
class Detection:
    id: str
    type: str
    severity: str
    confidence: float
    ts: str
    subject_hash: str
    description: str
    details: Dict[str, Any]
    rule_version: str
    ml_score: Optional[float] = None
    evidence_signature: Optional[str] = None


class RulePack:
    def __init__(self, version: str):
        self.version = version
        self.allowed_token_issuers = {"login.microsoftonline.com", "accounts.google.com", "okta.com"}
        self.high_risk_scopes = {
            "offline_access",
            "Files.ReadWrite.All",
            "Mail.ReadWrite",
            "Directory.AccessAsUser.All",
            "User.ReadWrite.All",
            "cloud-platform",
        }

    def describe(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "policies": [
                "MFA fatigue detection: >20 push prompts in 10 minutes, mostly from new ASN/IPs, followed by approval.",
                "AiTM/token replay: mismatched device fingerprint post-login, anomalous token issuer or replay indicators.",
                "Consent abuse: new OAuth app with high-risk scopes gains single-user consent and shows unusual API calls.",
            ],
        }


# ----------------------- Playbooks, approvals, and response policy -----------------------


@dataclass
class Action:
    type: str
    target: Dict[str, Any]
    description: str


@dataclass
class ApprovalRequest:
    id: str
    action: Action
    requested_by: str
    status: str  # "pending", "approved", "rejected"
    ts: str
    approved_by: Optional[str] = None
    resolution_ts: Optional[str] = None


class PlaybookEngine:
    def __init__(self, audit: AuditLogger, policy: Dict[str, Any]):
        self._audit = audit
        self._policy = policy
        self._approvals: Dict[str, ApprovalRequest] = {}

    def propose(self, detection: Detection) -> List[Action]:
        actions: List[Action] = []
        if detection.type == "mfa_fatigue":
            actions.append(
                Action(
                    type="step_up_auth",
                    target={"subject_hash": detection.subject_hash},
                    description="Trigger step-up authentication for user and notify.",
                )
            )
            actions.append(
                Action(
                    type="reset_sessions",
                    target={"subject_hash": detection.subject_hash},
                    description="Reset active sessions and invalidate push factors.",
                )
            )
        elif detection.type == "aitm_token_replay":
            actions.append(
                Action(
                    type="revoke_tokens",
                    target={"subject_hash": detection.subject_hash},
                    description="Revoke refresh/access tokens and force re-authentication.",
                )
            )
            actions.append(
                Action(
                    type="reset_sessions",
                    target={"subject_hash": detection.subject_hash},
                    description="Reset active sessions.",
                )
            )
        elif detection.type == "oauth_consent_abuse":
            app_id = detection.details.get("app_id", "")
            actions.append(
                Action(
                    type="quarantine_oauth_app",
                    target={"app_id": app_id},
                    description="Disable or quarantine OAuth app pending admin review.",
                )
            )
            actions.append(
                Action(
                    type="notify_admins",
                    target={"app_id": app_id},
                    description="Notify administrators and trigger app risk review.",
                )
            )
        self._audit.append(actor="system", action="proposed_actions", details={"detection_id": detection.id, "count": len(actions)})
        return actions

    def request_approval(self, action: Action, requested_by: str) -> ApprovalRequest:
        req = ApprovalRequest(
            id=secrets.token_hex(8),
            action=action,
            requested_by=requested_by,
            status="pending",
            ts=dt.datetime.now(dt.timezone.utc).isoformat(),
        )
        self._approvals[req.id] = req
        self._audit.append(actor=requested_by, action="approval_requested", details={"request_id": req.id, "action": action.type})
        return req

    def approve(self, request_id: str, approver: str, approve: bool) -> ApprovalRequest:
        req = self._approvals.get(request_id)
        if not req:
            raise KeyError("Approval request not found")
        if req.status != "pending":
            raise ValueError("Approval request already resolved")
        req.status = "approved" if approve else "rejected"
        req.approved_by = approver
        req.resolution_ts = dt.datetime.now(dt.timezone.utc).isoformat()
        self._audit.append(actor=approver, action="approval_resolved", details={"request_id": request_id, "status": req.status})
        return req

    def execute(self, req: ApprovalRequest) -> Dict[str, Any]:
        # Enforce policy gating
        enabled = bool(self._policy.get("enable_response", False))
        allowed = set(self._policy.get("allowed_actions", []))
        require_approval = bool(self._policy.get("require_approval", True))
        if not enabled:
            self._audit.append(actor="system", action="response_blocked", details={"reason": "response_disabled", "action": req.action.type})
            return {"status": "skipped", "reason": "Response disabled by policy"}
        if req.action.type not in allowed:
            self._audit.append(actor="system", action="response_blocked", details={"reason": "action_not_allowed", "action": req.action.type})
            return {"status": "skipped", "reason": "Action not allowed by policy"}
        if require_approval and req.status != "approved":
            self._audit.append(actor="system", action="response_blocked", details={"reason": "not_approved", "action": req.action.type})
            return {"status": "skipped", "reason": "Not approved"}
        # Simulate execution (read-only by default; real integrations must be added with caution)
        self._audit.append(actor="system", action="response_executed", details={"action": req.action.type, "target": req.action.target})
        return {"status": "executed", "action": req.action.type, "target": req.action.target}


# ----------------------- Hunter: analytics and detections -----------------------


class IdPAttackPatternHunter:
    def __init__(
        self,
        secret_key: str,
        retention_days: int = 30,
        response_policy: Optional[Dict[str, Any]] = None,
        rulepack_version: str = "2025.09.01",
    ):
        self.crypto = SimpleCrypto(secret_key.encode("utf-8"))
        self.audit = AuditLogger(self.crypto)
        self.events = EventStore(self.crypto, retention_days=retention_days)
        self.rulepack = RulePack(rulepack_version)
        self.playbooks = PlaybookEngine(self.audit, response_policy or {})
        self._lock = threading.Lock()

    # Access control placeholders
    def _require_role(self, actor_roles: List[str], required: str) -> None:
        if required not in actor_roles:
            raise PermissionError(f"Operation requires role: {required}")

    def ingest_event(self, source: str, type_: str, attrs: Dict[str, Any], ts: Optional[dt.datetime] = None) -> str:
        eid = self.events.ingest(source=source, type_=type_, ts=ts, attrs=attrs)
        self.audit.append(actor="ingest", action="event_ingested", details={"source": source, "type": type_, "event_id": eid})
        return eid

    def _window_events_by_user(self, since: dt.datetime) -> Dict[str, List[Event]]:
        user_events: Dict[str, List[Event]] = {}
        for e in self.events.list_events(since=since):
            if not e.actor_hash:
                continue
            user_events.setdefault(e.actor_hash, []).append(e)
        for evs in user_events.values():
            evs.sort(key=lambda x: x.ts)
        return user_events

    def _detect_mfa_fatigue(self, now: dt.datetime, user_events: Dict[str, List[Event]]) -> List[Detection]:
        detections: List[Detection] = []
        window = dt.timedelta(minutes=10)
        for user, evs in user_events.items():
            # Collect MFA challenges and approvals in window slices
            idx = 0
            while idx < len(evs):
                e = evs[idx]
                if e.type not in ("mfa_challenge", "mfa_approved"):
                    idx += 1
                    continue
                start = e.ts
                end = start + window
                challenges: List[Event] = []
                approvals: List[Event] = []
                new_asn_count = 0
                baseline_asns, baseline_ips = self.events.get_user_baseline(user)
                j = idx
                while j < len(evs) and evs[j].ts <= end:
                    if evs[j].type == "mfa_challenge":
                        challenges.append(evs[j])
                        # new ASN/IP?
                        if evs[j].asn and evs[j].asn not in baseline_asns:
                            new_asn_count += 1
                        elif evs[j].ip_masked and evs[j].ip_masked not in baseline_ips:
                            new_asn_count += 1
                    elif evs[j].type == "mfa_approved":
                        approvals.append(evs[j])
                    j += 1
                # Policy: >20 challenges, mostly from new ASN/IP, and followed by an approval
                if len(challenges) >= 21 and approvals:
                    novelty_ratio = new_asn_count / max(1, len(challenges))
                    # ML-assisted simple score: combination of rate and novelty
                    rate = len(challenges) / max(1, (end - start).total_seconds() / 60.0)
                    ml_score = min(1.0, 0.5 * (len(challenges) / 25.0) + 0.5 * novelty_ratio)
                    if novelty_ratio >= 0.5:
                        det = Detection(
                            id=secrets.token_hex(8),
                            type="mfa_fatigue",
                            severity="high",
                            confidence=0.95,
                            ts=now.isoformat(),
                            subject_hash=user,
                            description="MFA fatigue suspected: high volume of push prompts from new networks followed by approval.",
                            details={
                                "challenge_count": len(challenges),
                                "approval_count": len(approvals),
                                "novelty_ratio": round(novelty_ratio, 3),
                                "window_minutes": 10,
                                "first_challenge_ts": challenges[0].ts.isoformat() if challenges else "",
                                "last_event_ts": evs[min(j - 1, len(evs) - 1)].ts.isoformat(),
                            },
                            rule_version=self.rulepack.version,
                            ml_score=round(ml_score, 3),
                        )
                        det.evidence_signature = self.crypto.sign(json.dumps(det.details, sort_keys=True).encode("utf-8"))
                        detections.append(det)
                idx = j
        return detections

    def _detect_aitm_token_replay(self, now: dt.datetime, user_events: Dict[str, List[Event]]) -> List[Detection]:
        detections: List[Detection] = []
        for user, evs in user_events.items():
            # correlate token_used events with preceding login_success
            for i, e in enumerate(evs):
                if e.type != "token_used":
                    continue
                # find nearest preceding login_success
                prev_login = None
                for k in range(i - 1, -1, -1):
                    if evs[k].type == "login_success":
                        prev_login = evs[k]
                        break
                if not prev_login:
                    continue
                # Within 30 minutes window
                if (e.ts - prev_login.ts) > dt.timedelta(minutes=30):
                    continue
                # device fingerprint mismatch
                mismatch_fp = prev_login.device_fp_hash and e.device_fp_hash and prev_login.device_fp_hash != e.device_fp_hash
                issuer_anom = (e.token_issuer and e.token_issuer not in self.rulepack.allowed_token_issuers) or bool(e.issuer_anomalous)
                if mismatch_fp and issuer_anom:
                    det = Detection(
                        id=secrets.token_hex(8),
                        type="aitm_token_replay",
                        severity="critical",
                        confidence=0.9,
                        ts=now.isoformat(),
                        subject_hash=user,
                        description="Possible AiTM/token replay: device fingerprint mismatch and anomalous token issuer.",
                        details={
                            "login_ts": prev_login.ts.isoformat(),
                            "token_use_ts": e.ts.isoformat(),
                            "token_issuer": e.token_issuer or "",
                            "issuer_anomalous": bool(e.issuer_anomalous or (e.token_issuer not in self.rulepack.allowed_token_issuers if e.token_issuer else False)),
                        },
                        rule_version=self.rulepack.version,
                        ml_score=0.85,
                    )
                    det.evidence_signature = self.crypto.sign(json.dumps(det.details, sort_keys=True).encode("utf-8"))
                    detections.append(det)
        return detections

    def _detect_oauth_consent_abuse(self, now: dt.datetime) -> List[Detection]:
        detections: List[Detection] = []
        events = self.events.list_events()
        # Map app_id to metadata
        apps: Dict[str, Dict[str, Any]] = {}
        consents: Dict[str, set] = {}
        api_calls: Dict[str, int] = {}
        for e in events:
            if e.type == "oauth_app_created" and e.app_id:
                apps[e.app_id] = {"scopes": set(e.scopes or []), "created_ts": e.ts}
            elif e.type == "oauth_consent_granted" and e.app_id:
                consents.setdefault(e.app_id, set()).add(e.actor_hash)
            elif e.type in ("api_call", "token_used") and e.app_id:
                api_calls[e.app_id] = api_calls.get(e.app_id, 0) + 1
        for app_id, meta in apps.items():
            scopes = set(meta.get("scopes", set()))
            high_risk = bool(scopes & self.rulepack.high_risk_scopes)
            single_user = len(consents.get(app_id, set())) == 1
            unusual_activity = api_calls.get(app_id, 0) > 10  # heuristic
            if high_risk and single_user:
                det = Detection(
                    id=secrets.token_hex(8),
                    type="oauth_consent_abuse",
                    severity="high",
                    confidence=0.9 if unusual_activity else 0.75,
                    ts=now.isoformat(),
                    subject_hash=list(consents.get(app_id) or [""])[0],
                    description="New OAuth app with high-risk scopes gained consent from a single user.",
                    details={
                        "app_id": app_id,
                        "high_risk_scopes": sorted(list(scopes & self.rulepack.high_risk_scopes)),
                        "consent_user_count": len(consents.get(app_id, set())),
                        "api_call_count": api_calls.get(app_id, 0),
                        "created_ts": meta["created_ts"].isoformat() if meta.get("created_ts") else "",
                    },
                    rule_version=self.rulepack.version,
                    ml_score=0.6 + (0.3 if unusual_activity else 0.0),
                )
                det.evidence_signature = self.crypto.sign(json.dumps(det.details, sort_keys=True).encode("utf-8"))
                detections.append(det)
        return detections

    def run_analytics(self, actor_roles: Optional[List[str]] = None) -> List[Detection]:
        """
        Execute detection analytics. Returns detections with signed evidence.
        """
        self._require_role(actor_roles or ["analyst"], "analyst")
        now = dt.datetime.now(dt.timezone.utc)
        since = now - dt.timedelta(hours=24)
        user_events = self._window_events_by_user(since)
        d1 = self._detect_mfa_fatigue(now, user_events)
        d2 = self._detect_aitm_token_replay(now, user_events)
        d3 = self._detect_oauth_consent_abuse(now)
        detections = d1 + d2 + d3
        self.audit.append(actor="system", action="analytics_executed", details={"detections": len(detections)})
        return detections

    def prepare_signed_incident_bundle(self, detection: Detection) -> Dict[str, Any]:
        bundle = {
            "bundle_id": secrets.token_hex(8),
            "created_ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "detection": {
                "id": detection.id,
                "type": detection.type,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "ts": detection.ts,
                "subject_hash": detection.subject_hash,
                "details": detection.details,
                "rule_version": detection.rule_version,
                "evidence_signature": detection.evidence_signature,
            },
            "playbook_recommendations": [a.__dict__ for a in self.playbooks.propose(detection)],
            "rulepack_meta": self.rulepack.describe(),
        }
        bundle["bundle_signature"] = self.crypto.sign(json.dumps(bundle["detection"], sort_keys=True).encode("utf-8"))
        self.audit.append(actor="system", action="incident_bundle_prepared", details={"bundle_id": bundle["bundle_id"], "detection_id": detection.id})
        return bundle

    # ----------------------- Operator-facing helpers -----------------------

    def propose_actions(self, detection: Detection) -> List[Action]:
        return self.playbooks.propose(detection)

    def request_action_approval(self, action: Action, requested_by: str, actor_roles: Optional[List[str]] = None) -> ApprovalRequest:
        self._require_role(actor_roles or ["analyst"], "analyst")
        return self.playbooks.request_approval(action, requested_by)

    def resolve_approval(self, request_id: str, approver: str, approve: bool, actor_roles: Optional[List[str]] = None) -> ApprovalRequest:
        self._require_role(actor_roles or ["approver"], "approver")
        return self.playbooks.approve(request_id, approver, approve)

    def execute_action(self, approval_request: ApprovalRequest, actor_roles: Optional[List[str]] = None) -> Dict[str, Any]:
        self._require_role(actor_roles or ["approver"], "approver")
        return self.playbooks.execute(approval_request)

    def export_audit_log(self) -> List[Dict[str, Any]]:
        return self.audit.export()

    def purge_old_events(self, actor_roles: Optional[List[str]] = None) -> int:
        self._require_role(actor_roles or ["analyst"], "analyst")
        deleted = self.events.purge_old()
        self.audit.append(actor="system", action="events_purged", details={"deleted": deleted})
        return deleted


# ----------------------- Example usage (commented for safety) -----------------------
# The following is provided to illustrate how the tool might be used.
# Actual integrations with IdP/EDR APIs must be implemented carefully with read-only defaults.
#
# if __name__ == "__main__":
#     hunter = IdPAttackPatternHunter(secret_key="change-this-32byte-secret-change-this")
#     # Authorized testing only:
#     now = dt.datetime.now(dt.timezone.utc)
#     # Simulate MFA fatigue
#     user = "user@example.com"
#     for i in range(22):
#         hunter.ingest_event("okta", "mfa_challenge", {"user": user, "ip": f"1.2.3.{i%5}", "asn": f"AS{i}", "device_fp": "devA"}, ts=now - dt.timedelta(minutes=9, seconds=600 - i*25))
#     hunter.ingest_event("okta", "mfa_approved", {"user": user, "ip": "1.2.3.9", "asn": "AS999", "device_fp": "devA"}, ts=now - dt.timedelta(minutes=1))
#     # Simulate AiTM/token replay
#     hunter.ingest_event("azuread", "login_success", {"user": user, "ip": "5.6.7.8", "asn": "AS100", "device_fp": "devA"}, ts=now - dt.timedelta(minutes=20))
#     hunter.ingest_event("azuread", "token_used", {"user": user, "ip": "9.9.9.9", "asn": "AS200", "device_fp": "devB", "token_issuer": "evilginx.example", "issuer_anomalous": True}, ts=now - dt.timedelta(minutes=10))
#     # OAuth consent abuse
#     hunter.ingest_event("azuread", "oauth_app_created", {"app_id": "app1", "app_name": "Helper", "scopes": ["offline_access", "Files.ReadWrite.All"]}, ts=now - dt.timedelta(hours=2))
#     hunter.ingest_event("azuread", "oauth_consent_granted", {"user": user, "app_id": "app1"}, ts=now - dt.timedelta(hours=1, minutes=30))
#     for _ in range(12):
#         hunter.ingest_event("siem", "api_call", {"app_id": "app1"}, ts=now - dt.timedelta(minutes=20))
#     detections = hunter.run_analytics(actor_roles=["analyst"])
#     for d in detections:
#         bundle = hunter.prepare_signed_incident_bundle(d)
#         print(d.type, d.description, bundle["bundle_signature"])
#     print("Audit entries:", len(hunter.export_audit_log()))