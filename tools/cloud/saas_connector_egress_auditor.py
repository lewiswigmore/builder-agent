import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Callable

"""
SaaS Connector Egress Auditor
Category: cloud

Ethical warning:
- This tool is for authorized testing in isolated test tenants only.
- Never target production tenants or real user data.
- Use least-privilege OAuth apps, short-lived tokens, and explicit approvals for any remediation.

This module simulates core functionality required to satisfy acceptance criteria without contacting real SaaS APIs.
It offers safe, non-destructive, read-only operations by default and policy-gated remediation requiring human approvals.
"""


# ---------- Logging ----------
logger = logging.getLogger("saas_connector_egress_auditor")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ---------- Utilities ----------
def utc_now() -> float:
    return time.time()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def masked(s: str, show: int = 4) -> str:
    if not s:
        return ""
    return f"{s[:show]}...{s[-show:]}" if len(s) > 2 * show else "*" * len(s)


# ---------- Rate Limiting ----------
class RateLimiter:
    def __init__(self, rate_per_sec: float, capacity: int):
        self.rate = rate_per_sec
        self.capacity = capacity
        self.tokens = capacity
        self.last = utc_now()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            now = utc_now()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait(self, tokens: int = 1, timeout: float = 5.0) -> bool:
        end = utc_now() + timeout
        while utc_now() < end:
            if self.consume(tokens):
                return True
            time.sleep(0.05)
        return False


# ---------- Vault (in-memory, with TTL and revocation) ----------
@dataclass
class SecretRecord:
    value: str
    created_at: float
    expires_at: float
    revoked: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class Vault:
    """
    Minimal in-memory vault for demo. Do not use in production.
    Stores secrets with expiration and revocation flags.
    """

    def __init__(self):
        self._secrets: Dict[str, SecretRecord] = {}
        self._lock = threading.Lock()

    def put(self, key: str, value: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self._secrets[key] = SecretRecord(
                value=value, created_at=utc_now(), expires_at=utc_now() + ttl_seconds, metadata=metadata or {}
            )
            logger.debug("Vault: stored secret %s ttl=%ss", key, ttl_seconds)

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            rec = self._secrets.get(key)
            if not rec:
                return None
            if rec.revoked or rec.expires_at <= utc_now():
                return None
            return rec.value

    def revoke(self, key: str) -> bool:
        with self._lock:
            rec = self._secrets.get(key)
            if not rec:
                return False
            rec.revoked = True
            logger.info("Vault: revoked secret %s", key)
            return True

    def info(self, key: str) -> Optional[SecretRecord]:
        with self._lock:
            return self._secrets.get(key)

    def delete(self, key: str) -> None:
        with self._lock:
            if key in self._secrets:
                del self._secrets[key]


# ---------- RBAC ----------
class RBAC:
    """
    Simple RBAC for gated remediation.
    Roles: viewer (read-only), auditor (read, simulate), approver (remediate if approved), admin (all).
    """

    def __init__(self, user_roles: Dict[str, List[str]]):
        self.user_roles = user_roles

    def check(self, user: str, action: str, require_approval: bool = False, approved_by: Optional[str] = None) -> bool:
        roles = self.user_roles.get(user, [])
        if "admin" in roles:
            return True
        if action.startswith("read") or action.startswith("simulate"):
            return "viewer" in roles or "auditor" in roles or "approver" in roles
        if action.startswith("remediate"):
            if "approver" in roles:
                return not require_approval or bool(approved_by and ("approver" in self.user_roles.get(approved_by, []) or "admin" in self.user_roles.get(approved_by, [])))
        return False


# ---------- Immutable Audit Log with hash chaining ----------
class ImmutableAuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("")

    def _last_hash(self) -> str:
        try:
            with open(self.path, "rb") as f:
                last = b""
                for line in f:
                    last = line.strip()
                if not last:
                    return "GENESIS"
                try:
                    obj = json.loads(last.decode("utf-8"))
                    return obj.get("entry_hash", "GENESIS")
                except Exception:
                    return "GENESIS"
        except Exception:
            return "GENESIS"

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            prev_hash = self._last_hash()
            data = {**entry, "prev_hash": prev_hash, "ts": utc_now()}
            entry_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
            entry_hash = sha256_hex(entry_bytes)
            record = {**data, "entry_hash": entry_hash}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            return record


# ---------- Evidence Bundler (emulated sigstore/rekor) ----------
class EvidenceBundler:
    """
    Emulates Sigstore/Rekor sealing using HMAC-SHA256 with a key stored in Vault.
    Produces a bundle containing content hash, signature, and an emulated Rekor index.
    """

    def __init__(self, vault: Vault, audit_log: ImmutableAuditLog, hmac_key_id: str = "sigstore_hmac_key"):
        self.vault = vault
        self.audit_log = audit_log
        self.hmac_key_id = hmac_key_id
        if not self.vault.get(self.hmac_key_id):
            self.vault.put(self.hmac_key_id, value=self._random_key(), ttl_seconds=10 * 365 * 24 * 3600)

    def _random_key(self) -> str:
        return sha256_hex(os.urandom(32))

    def sign(self, content: Dict[str, Any]) -> Dict[str, Any]:
        key = self.vault.get(self.hmac_key_id)
        if not key:
            raise RuntimeError("EvidenceBundler: missing HMAC key in vault")
        serialized = json.dumps(content, sort_keys=True).encode("utf-8")
        sig = hmac.new(key.encode("utf-8"), serialized, hashlib.sha256).hexdigest()
        bundle = {
            "content": content,
            "content_sha256": sha256_hex(serialized),
            "signature_hmac_sha256": sig,
            "sigstore_emulated": True,
        }
        # emulate Rekor by logging bundle and returning index
        record = self.audit_log.append({"type": "evidence_bundle", "bundle": bundle})
        bundle["rekor_log_index"] = record.get("entry_hash")
        return bundle


# ---------- Honey Artifacts ----------
@dataclass
class HoneyArtifact:
    id: str
    type: str  # "document" or "token"
    tenant: str
    created_at: float
    expires_at: float
    sealed_bundle: Dict[str, Any]


class HoneyArtifactManager:
    def __init__(self, bundler: EvidenceBundler):
        self.bundler = bundler
        self._artifacts: Dict[str, HoneyArtifact] = {}
        self._lock = threading.Lock()

    def create_honey_document(self, tenant: str, ttl_seconds: int = 7 * 24 * 3600) -> HoneyArtifact:
        with self._lock:
            doc_id = f"doc_{sha256_hex(os.urandom(16))[:12]}"
            content = {
                "artifact_id": doc_id,
                "artifact_type": "document",
                "tenant": tenant,
                "ethical": "Authorized testing only; do not use in production.",
            }
            sealed = self.bundler.sign({"honey_document": content})
            art = HoneyArtifact(
                id=doc_id,
                type="document",
                tenant=tenant,
                created_at=utc_now(),
                expires_at=utc_now() + ttl_seconds,
                sealed_bundle=sealed,
            )
            self._artifacts[doc_id] = art
            return art

    def create_canary_token(self, tenant: str, ttl_seconds: int = 24 * 3600) -> HoneyArtifact:
        with self._lock:
            tok_id = f"tok_{sha256_hex(os.urandom(16))[:12]}"
            content = {
                "artifact_id": tok_id,
                "artifact_type": "token",
                "tenant": tenant,
                "ethical": "Authorized testing only; do not use in production.",
            }
            sealed = self.bundler.sign({"canary_token": content})
            art = HoneyArtifact(
                id=tok_id,
                type="token",
                tenant=tenant,
                created_at=utc_now(),
                expires_at=utc_now() + ttl_seconds,
                sealed_bundle=sealed,
            )
            self._artifacts[tok_id] = art
            return art

    def is_honey(self, artifact_id: str) -> bool:
        with self._lock:
            return artifact_id in self._artifacts

    def get(self, artifact_id: str) -> Optional[HoneyArtifact]:
        with self._lock:
            return self._artifacts.get(artifact_id)


# ---------- Simulated Slack API Wrapper ----------
@dataclass
class SlackApp:
    app_id: str
    workspace: str
    scopes: List[str]
    token_key: str  # vault key for token
    redirect_urls: List[str]


class SlackClientStub:
    """
    A minimal stub simulating Slack interactions for testing.
    """

    def __init__(self, vault: Vault, rate_limiter: RateLimiter):
        self.vault = vault
        self.rate = rate_limiter
        self.apps: Dict[str, SlackApp] = {}
        self.revoked_tokens: set[str] = set()

    def register_app(self, app_id: str, workspace: str, token: str, scopes: List[str], redirect_urls: List[str], ttl_seconds: int = 3600) -> SlackApp:
        if not self.rate.wait():
            raise RuntimeError("Rate limit exceeded")
        token_key = f"slack_token_{app_id}"
        self.vault.put(token_key, token, ttl_seconds=ttl_seconds, metadata={"workspace": workspace, "app_id": app_id})
        app = SlackApp(app_id=app_id, workspace=workspace, scopes=scopes, token_key=token_key, redirect_urls=redirect_urls)
        self.apps[app_id] = app
        return app

    def get_oauth_scopes(self, app_id: str) -> List[str]:
        if not self.rate.wait():
            raise RuntimeError("Rate limit exceeded")
        app = self.apps.get(app_id)
        if not app:
            raise ValueError("Unknown Slack app")
        return list(app.scopes)

    def get_redirect_urls(self, app_id: str) -> List[str]:
        if not self.rate.wait():
            raise RuntimeError("Rate limit exceeded")
        app = self.apps.get(app_id)
        if not app:
            raise ValueError("Unknown Slack app")
        return list(app.redirect_urls)

    def revoke_token(self, app_id: str) -> bool:
        if not self.rate.wait():
            raise RuntimeError("Rate limit exceeded")
        app = self.apps.get(app_id)
        if not app:
            return False
        self.vault.revoke(app.token_key)
        # track token to block replay
        rec = self.vault.info(app.token_key)
        if rec:
            self.revoked_tokens.add(rec.value)
        return True

    def rotate_token(self, app_id: str, new_token: str, ttl_seconds: int = 3600) -> Tuple[Optional[str], str]:
        if not self.rate.wait():
            raise RuntimeError("Rate limit exceeded")
        app = self.apps.get(app_id)
        if not app:
            raise ValueError("Unknown Slack app")
        old_rec = self.vault.info(app.token_key)
        old = old_rec.value if old_rec else None
        if old:
            self.revoked_tokens.add(old)
        self.vault.put(app.token_key, new_token, ttl_seconds=ttl_seconds, metadata={"workspace": app.workspace, "app_id": app_id})
        return old, new_token

    def try_use_token(self, token: str) -> bool:
        """
        Simulate API call using token; returns True if accepted, False if blocked.
        """
        if not self.rate.wait():
            raise RuntimeError("Rate limit exceeded")
        if token in self.revoked_tokens:
            return False
        # also reject expired or unknown tokens
        # search vault for token match
        for k in list(self.apps.values()):
            rec = self.vault.info(k.token_key)
            if rec and rec.value == token and not rec.revoked and rec.expires_at > utc_now():
                return True
        return False


# ---------- Slack Auditor ----------
@dataclass
class Incident:
    id: str
    severity: str
    type: str
    summary: str
    details: Dict[str, Any]
    signed_evidence: Dict[str, Any]


class SlackAuditor:
    def __init__(self, slack: SlackClientStub, honey: HoneyArtifactManager, bundler: EvidenceBundler, audit_log: ImmutableAuditLog):
        self.slack = slack
        self.honey = honey
        self.bundler = bundler
        self.audit_log = audit_log

    def validate_oauth_scopes(self, app_id: str, allowed_scopes: List[str]) -> Dict[str, Any]:
        scopes = self.slack.get_oauth_scopes(app_id)
        mis_scoped = [s for s in scopes if s not in allowed_scopes]
        info = {"app_id": app_id, "scopes": scopes, "mis_scoped": mis_scoped}
        self.audit_log.append({"type": "slack_scope_validation", "info": info})
        return info

    def validate_redirects(self, app_id: str, allowed_redirect_prefixes: List[str]) -> Dict[str, Any]:
        redirects = self.slack.get_redirect_urls(app_id)
        bad = [r for r in redirects if not any(r.startswith(p) for p in allowed_redirect_prefixes)]
        info = {"app_id": app_id, "redirects": redirects, "invalid_redirects": bad}
        self.audit_log.append({"type": "slack_redirect_validation", "info": info})
        return info

    def process_access_event(self, event: Dict[str, Any]) -> Optional[Incident]:
        """
        event: {
          "type": "file_access",
          "app_id": "...",
          "workspace": "...",
          "file_id": "...",
          "access_path": "channels/C123/file/F456",
          "ts": 123.456
        }
        """
        try:
            if event.get("type") != "file_access":
                return None
            file_id = event.get("file_id")
            if not file_id or not self.honey.is_honey(file_id):
                return None
            honey_art = self.honey.get(file_id)
            app_id = event.get("app_id")
            scopes = self.slack.get_oauth_scopes(app_id)
            # Detect mis-scope: e.g., files:read across all workspaces
            mis_scope = "files:read" in scopes
            severity = "high" if mis_scope else "medium"
            summary = f"Honey document {file_id} accessed by app {app_id} in workspace {event.get('workspace')}"
            details = {
                "access_path": event.get("access_path"),
                "app_scopes": scopes,
                "workspace": event.get("workspace"),
                "honey_tenant": honey_art.tenant if honey_art else None,
                "ethical": "Authorized testing only; no production artifacts modified.",
            }
            signed = self.bundler.sign({"incident": {"summary": summary, "details": details, "ts": utc_now(), "type": "slack_honey_access"}})
            incident = Incident(
                id=f"inc_{sha256_hex(os.urandom(8))[:10]}",
                severity="high" if mis_scope else "medium",
                type="slack_honey_access",
                summary=summary,
                details=details,
                signed_evidence=signed,
            )
            self.audit_log.append({"type": "incident", "incident": {"id": incident.id, "severity": incident.severity, "summary": summary}})
            return incident
        except Exception as e:
            logger.error("Error processing access event: %s", e)
            return None


# ---------- Egress/DLP Auditor ----------
@dataclass
class DlpPolicy:
    allowed_webhook_domains: List[str]
    block_external_by_default: bool = True


class WebhookEgressAuditor:
    def __init__(self, honey: HoneyArtifactManager, bundler: EvidenceBundler, audit_log: ImmutableAuditLog, policy: DlpPolicy):
        self.honey = honey
        self.bundler = bundler
        self.audit_log = audit_log
        self.policy = policy
        self.quarantined_urls: set[str] = set()

    def _domain(self, url: str) -> str:
        try:
            return urllib.parse.urlparse(url).netloc.lower()
        except Exception:
            return ""

    def simulate_exfiltration_attempt(self, connector_name: str, webhook_url: str, token_id: str) -> Tuple[bool, Optional[Incident]]:
        """
        Returns (blocked, incident_if_any)
        """
        try:
            is_honey = self.honey.is_honey(token_id)
            domain = self._domain(webhook_url)
            allowed = any(domain.endswith(d) for d in self.policy.allowed_webhook_domains)
            blocked = self.policy.block_external_by_default and (not allowed)
            if webhook_url in self.quarantined_urls:
                blocked = True
            details = {
                "connector": connector_name,
                "webhook_url": webhook_url,
                "domain": domain,
                "is_honey_token": is_honey,
                "policy_allowed": allowed,
                "blocked": blocked,
                "ethical": "Authorized simulation only; no network calls performed.",
            }
            self.audit_log.append({"type": "egress_simulation", "details": details})
            if not blocked and is_honey:
                summary = f"Unsanctioned egress detected for honey token {token_id} to {domain}"
                signed = self.bundler.sign({"incident": {"summary": summary, "details": details, "type": "webhook_egress"}})
                incident = Incident(
                    id=f"inc_{sha256_hex(os.urandom(8))[:10]}",
                    severity="high",
                    type="webhook_egress",
                    summary=summary,
                    details=details,
                    signed_evidence=signed,
                )
                self.audit_log.append({"type": "incident", "incident": {"id": incident.id, "severity": incident.severity, "summary": summary}})
                return (False, incident)
            return (True, None)
        except Exception as e:
            logger.error("Egress simulation error: %s", e)
            return (True, None)

    def quarantine_webhook(self, url: str, rbac: RBAC, user: str, require_approval: bool, approved_by: Optional[str] = None) -> bool:
        if not rbac.check(user, action="remediate.quarantine_webhook", require_approval=require_approval, approved_by=approved_by):
            logger.warning("RBAC denied quarantine request by %s", user)
            return False
        self.quarantined_urls.add(url)
        self.audit_log.append({"type": "remediation", "action": "quarantine_webhook", "url": url, "by": user, "approved_by": approved_by})
        return True


# ---------- Token Rotation and Validation ----------
class TokenRotator:
    def __init__(self, slack: SlackClientStub, audit_log: ImmutableAuditLog, bundler: EvidenceBundler):
        self.slack = slack
        self.audit_log = audit_log
        self.bundler = bundler

    def rotate_and_revoke(self, app_id: str, new_token: str, ttl_seconds: int = 900) -> Dict[str, Any]:
        old, new = self.slack.rotate_token(app_id, new_token=new_token, ttl_seconds=ttl_seconds)
        if old:
            self.slack.revoke_token(app_id)
        record = {"app_id": app_id, "old_masked": masked(old or ""), "new_masked": masked(new or ""), "ttl": ttl_seconds}
        self.audit_log.append({"type": "token_rotation", "record": record})
        return record

    def validate_revocation(self, old_token: str) -> Dict[str, Any]:
        accepted = self.slack.try_use_token(old_token)
        result = {"old_token_masked": masked(old_token), "replay_blocked": not accepted}
        signed = self.bundler.sign({"revocation_validation": result})
        self.audit_log.append({"type": "revocation_validation", "result": result})
        return {"result": result, "signed_evidence": signed}


# ---------- Orchestrator ----------
class SaaSConnectorEgressAuditor:
    """
    Main tool orchestrating honey artifacts, validation, egress simulation, and token rotation.
    All operations are non-destructive by default. Remediation is gated by RBAC.
    """

    def __init__(self, audit_log_path: str = "./audit/immutable_audit.log"):
        self.vault = Vault()
        self.audit_log = ImmutableAuditLog(audit_log_path)
        self.bundler = EvidenceBundler(self.vault, self.audit_log)
        self.honey = HoneyArtifactManager(self.bundler)
        self.rate = RateLimiter(rate_per_sec=5, capacity=10)
        self.slack = SlackClientStub(self.vault, self.rate)
        self.slack_auditor = SlackAuditor(self.slack, self.honey, self.bundler, self.audit_log)
        self.egress_auditor = WebhookEgressAuditor(self.honey, self.bundler, self.audit_log, DlpPolicy(allowed_webhook_domains=["internal.example.com"]))
        self.token_rotator = TokenRotator(self.slack, self.audit_log, self.bundler)
        self.rbac = RBAC(user_roles={})

    # ---------- Setup roles ----------
    def set_user_roles(self, user_roles: Dict[str, List[str]]) -> None:
        self.rbac = RBAC(user_roles=user_roles)

    # ---------- Honey deployment ----------
    def deploy_honey_artifacts(self, tenant: str) -> Dict[str, HoneyArtifact]:
        doc = self.honey.create_honey_document(tenant=tenant)
        tok = self.honey.create_canary_token(tenant=tenant)
        self.audit_log.append({"type": "honey_deploy", "tenant": tenant, "doc_id": doc.id, "token_id": tok.id})
        return {"document": doc, "token": tok}

    # ---------- Slack registration for test tenant ----------
    def register_test_slack_app(self, app_id: str, workspace: str, token: str, scopes: List[str], redirect_urls: List[str], ttl_seconds: int = 900) -> SlackApp:
        app = self.slack.register_app(app_id=app_id, workspace=workspace, token=token, scopes=scopes, redirect_urls=redirect_urls, ttl_seconds=ttl_seconds)
        self.audit_log.append({"type": "slack_register_app", "app_id": app_id, "workspace": workspace, "ttl": ttl_seconds})
        return app

    # ---------- Validations ----------
    def validate_oauth_scopes_and_redirects(self, app_id: str, allowed_scopes: List[str], allowed_redirect_prefixes: List[str]) -> Dict[str, Any]:
        scopes_info = self.slack_auditor.validate_oauth_scopes(app_id, allowed_scopes=allowed_scopes)
        redirects_info = self.slack_auditor.validate_redirects(app_id, allowed_redirect_prefixes=allowed_redirect_prefixes)
        bundle = self.bundler.sign({"oauth_validation": {"scopes": scopes_info, "redirects": redirects_info}})
        return {"scopes": scopes_info, "redirects": redirects_info, "signed_evidence": bundle}

    # ---------- Event processing ----------
    def ingest_slack_access_event(self, event: Dict[str, Any]) -> Optional[Incident]:
        return self.slack_auditor.process_access_event(event)

    # ---------- Egress simulation ----------
    def attempt_webhook_exfiltration(self, connector_name: str, webhook_url: str, token_id: str) -> Tuple[bool, Optional[Incident]]:
        return self.egress_auditor.simulate_exfiltration_attempt(connector_name, webhook_url, token_id)

    def quarantine_webhook(self, url: str, user: str, require_approval: bool = True, approved_by: Optional[str] = None) -> bool:
        return self.egress_auditor.quarantine_webhook(url, rbac=self.rbac, user=user, require_approval=require_approval, approved_by=approved_by)

    # ---------- Token rotation ----------
    def rotate_and_validate_tokens(self, app_id: str, new_token: str, ttl_seconds: int = 600) -> Dict[str, Any]:
        rotation = self.token_rotator.rotate_and_revoke(app_id, new_token=new_token, ttl_seconds=ttl_seconds)
        old_rec = self.vault.info(f"slack_token_{app_id}")
        old_token = None
        if old_rec:
            # We already rotated; need to retrieve previous token from rotation record masked; not available.
            # For validation, simulate replay using the revoked set: pick a token from revoked set for this app if available.
            # For deterministic behavior, we require caller to provide old token; as a fallback, replay against masked won't work.
            pass
        # In our simple flow, we can reconstruct old token from the SlackClientStub revoked_tokens set only if provided.
        # Expose a helper to validate a specific token:
        return rotation

    def validate_old_token_blocked(self, old_token: str) -> Dict[str, Any]:
        return self.token_rotator.validate_revocation(old_token)

    # ---------- Remediation (policy-gated) ----------
    def tighten_scopes(self, app_id: str, new_scopes: List[str], user: str, require_approval: bool = True, approved_by: Optional[str] = None) -> bool:
        if not self.rbac.check(user, action="remediate.tighten_scopes", require_approval=require_approval, approved_by=approved_by):
            logger.warning("RBAC denied scope tightening by %s", user)
            return False
        try:
            app = self.slack.apps.get(app_id)
            if not app:
                return False
            app.scopes = new_scopes[:]  # scoped change for test app
            self.audit_log.append({"type": "remediation", "action": "tighten_scopes", "app_id": app_id, "by": user, "approved_by": approved_by})
            return True
        except Exception as e:
            logger.error("Error tightening scopes: %s", e)
            return False


# ---------- Convenience acceptance-scenario helpers ----------
def acceptance_scenario_mis_scoped_slack_access() -> Tuple[Incident, Dict[str, Any]]:
    """
    - Create honey doc
    - Register mis-scoped Slack app (files:read)
    - Simulate access event to honey doc
    - Expect high-severity incident with signed bundle
    """
    auditor = SaaSConnectorEgressAuditor()
    auditor.set_user_roles({"alice": ["viewer"], "bob": ["approver"]})
    artifacts = auditor.deploy_honey_artifacts(tenant="test-tenant-1")
    doc = artifacts["document"]
    app = auditor.register_test_slack_app(
        app_id="A123",
        workspace="W_TEST",
        token="xoxb-test-123",
        scopes=["files:read", "channels:read"],
        redirect_urls=["https://internal.example.com/oauth/callback"],
        ttl_seconds=600,
    )
    _ = auditor.validate_oauth_scopes_and_redirects(app_id=app.app_id, allowed_scopes=["channels:read"], allowed_redirect_prefixes=["https://internal.example.com"])
    event = {
        "type": "file_access",
        "app_id": app.app_id,
        "workspace": app.workspace,
        "file_id": doc.id,
        "access_path": "channels/C123/file/" + doc.id,
        "ts": utc_now(),
    }
    incident = auditor.ingest_slack_access_event(event)
    if not incident:
        raise RuntimeError("Expected incident not generated")
    return incident, artifacts["document"].sealed_bundle


def acceptance_scenario_webhook_exfiltration(block_by_policy: bool) -> Tuple[bool, Optional[Incident]]:
    """
    - Create honey token
    - Simulate connector attempting to exfiltrate to external webhook
    - If policy blocks, expect blocked=True; else expect high-severity incident
    """
    auditor = SaaSConnectorEgressAuditor()
    auditor.egress_auditor.policy.block_external_by_default = block_by_policy
    artifacts = auditor.deploy_honey_artifacts(tenant="test-tenant-2")
    token = artifacts["token"]
    blocked, incident = auditor.attempt_webhook_exfiltration(
        connector_name="sim-connector",
        webhook_url="https://malicious.example.net/hook",
        token_id=token.id,
    )
    return blocked, incident


def acceptance_scenario_token_rotation_and_validation() -> Dict[str, Any]:
    """
    - Register test app with short TTL token
    - Rotate token and revoke old
    - Validate old token is blocked via replay
    """
    auditor = SaaSConnectorEgressAuditor()
    app = auditor.register_test_slack_app(
        app_id="A_ROT",
        workspace="W_ROT",
        token="xoxb-rot-000",
        scopes=["channels:read"],
        redirect_urls=["https://internal.example.com/oauth/callback"],
        ttl_seconds=60,
    )
    # Save old token for replay attempt
    old_token = "xoxb-rot-000"
    rotation = auditor.rotate_and_validate_tokens(app_id=app.app_id, new_token="xoxb-rot-111", ttl_seconds=60)
    # Revoke explicitly to emulate cleanup of stale grants
    auditor.slack.revoke_token(app_id=app.app_id)
    validation = auditor.validate_old_token_blocked(old_token)
    return {"rotation": rotation, "validation": validation}