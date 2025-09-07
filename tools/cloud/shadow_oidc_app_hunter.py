import json
import os
import sys
import time
import uuid
import hmac
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# Ethical and legal warning displayed upon execution
ETHICAL_WARNING = (
    "AUTHORIZED TESTING ONLY: This tool is intended solely for lawful security assessment "
    "of environments you own or are explicitly authorized to test. Misuse may violate law "
    "and policy. The tool operates in read-only mode by default with explicit approval gates "
    "for any remediation. Proceed responsibly."
)


def utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


class RateLimiter:
    def __init__(self, rate_per_sec: float, burst: int = 5):
        self.rate = rate_per_sec
        self.burst = burst
        self.tokens = burst
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            if self.tokens < 1:
                # Backoff proportional to deficit
                sleep_time = (1 - self.tokens) / self.rate
                time.sleep(max(0.01, sleep_time))
                self.tokens = 0
            else:
                self.tokens -= 1


class AuditLogger:
    """
    Audit logger producing JSONL log entries. Each entry includes a detached HMAC signature
    using an ephemeral per-run key. For production, integrate with KMS/HSM signing.
    """

    def __init__(self, log_path: str = "shadow_oidc_audit.log"):
        self.log_path = log_path
        # Ephemeral key for this run; rotate per run
        seed = uuid.uuid4().hex + utc_now_iso()
        self._key = hashlib.sha256(seed.encode()).digest()
        self._session_id = str(uuid.uuid4())

    @property
    def session_id(self) -> str:
        return self._session_id

    def sign(self, payload: Dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True).encode()
        return hmac_sha256_hex(self._key, body)

    def log(self, action: str, details: Dict[str, Any]):
        entry = {
            "ts": utc_now_iso(),
            "session": self._session_id,
            "action": action,
            "details": details,
        }
        sig = self.sign(entry)
        wrapped = {"entry": entry, "signature": sig, "sig_alg": "HMAC-SHA256-ephemeral"}
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(wrapped) + "\n")


class EphemeralTokenStore:
    """
    Simulates least-privilege, ephemeral credentials stored via KMS/HSM.
    In this reference implementation, tokens are read from environment variables
    and never persisted. Rotation and revocation are simulated in-memory.

    ENV:
      - OKTA_TOKEN
      - AZUREAD_TOKEN
      - GOOGLE_TOKEN
    """

    def __init__(self, auditor: AuditLogger):
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.auditor = auditor
        self._load_env_tokens()

    def _load_env_tokens(self):
        for provider, env in [("okta", "OKTA_TOKEN"), ("azuread", "AZUREAD_TOKEN"), ("google", "GOOGLE_TOKEN")]:
            token = os.getenv(env)
            if token:
                self.tokens[provider] = {
                    "token": token,
                    "created": utc_now_iso(),
                    "revoked": False,
                    "scopes": "least-privilege",
                }
                self.auditor.log("credential_load", {"provider": provider, "source": "env", "scopes": "least-privilege"})

    def get(self, provider: str) -> Optional[str]:
        meta = self.tokens.get(provider)
        if not meta or meta.get("revoked"):
            return None
        return meta["token"]

    def rotate(self, provider: str):
        # Simulated rotation: generate non-functional ephemeral token
        new_tok = sha256_hex(uuid.uuid4().bytes + os.urandom(16))
        self.tokens[provider] = {
            "token": new_tok,
            "created": utc_now_iso(),
            "revoked": False,
            "scopes": "least-privilege",
        }
        self.auditor.log("credential_rotate", {"provider": provider, "mode": "ephemeral"})

    def revoke(self, provider: str):
        if provider in self.tokens:
            self.tokens[provider]["revoked"] = True
            self.auditor.log("credential_revoke", {"provider": provider})


class SafeRedirectVerifier:
    """
    Verifies redirect URIs safely without enabling open redirect behavior.
    - Parses and validates scheme/host/path patterns.
    - Flags wildcard usage.
    - Optionally performs a HEAD request to the exact redirect endpoint WITHOUT following redirects
      and without including any sensitive parameters. Network checks are disabled by default.
    """

    def __init__(self, network_enabled: bool = False, allowlist_domains: Optional[List[str]] = None):
        self.network_enabled = network_enabled and bool(os.getenv("SHADOW_OIDC_ENABLE_NETWORK"))
        self.allowlist = set(allowlist_domains or [])

    @staticmethod
    def analyze_uri(uri: str) -> Dict[str, Any]:
        p = urlparse(uri)
        issues = []
        if p.scheme not in ("https", "http"):
            issues.append("non_http_scheme")
        if p.scheme != "https":
            issues.append("insecure_scheme_http")
        host = p.hostname or ""
        if "*" in uri or (host and host.startswith("*")):
            issues.append("wildcard_redirect")
        if host.endswith(".local") or host in ("localhost", "127.0.0.1"):
            issues.append("localhost_redirect")
        if p.path == "" or p.path == "/":
            issues.append("root_path_redirect")
        return {
            "uri": uri,
            "scheme": p.scheme,
            "host": host,
            "path": p.path,
            "issues": issues,
        }

    def head_check(self, uri: str) -> Dict[str, Any]:
        # Network checks are disabled by default for safety and to adhere to rate limits.
        if not self.network_enabled:
            return {"uri": uri, "network_checked": False, "status": "skipped"}
        host = urlparse(uri).hostname or ""
        if self.allowlist and host not in self.allowlist:
            return {"uri": uri, "network_checked": False, "status": "not_allowlisted"}
        # Minimalist safe check: open socket-less; urllib without redirects
        try:
            import urllib.request

            class HeadRequest(urllib.request.Request):
                def get_method(self):
                    return "HEAD"

            req = HeadRequest(uri, headers={"User-Agent": "shadow-oidc-safety/1.0"})
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
            # Prevent automatic redirect following by using a custom handler
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(NoRedirect)
            resp = opener.open(req, timeout=5)
            code = getattr(resp, "code", 0)
            return {"uri": uri, "network_checked": True, "status_code": code}
        except Exception as e:
            return {"uri": uri, "network_checked": True, "error": str(e)}


class OIDCApp:
    def __init__(self, provider: str, name: str, client_id: str, redirect_uris: List[str],
                 pkce_required: bool, consent_mode: str, managed: bool, metadata: Optional[Dict[str, Any]] = None):
        self.provider = provider
        self.name = name
        self.client_id = client_id
        self.redirect_uris = redirect_uris
        self.pkce_required = pkce_required
        self.consent_mode = consent_mode  # e.g., "explicit", "auto", "preconsent"
        self.managed = managed
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "name": self.name,
            "client_id": self.client_id,
            "redirect_uris": self.redirect_uris,
            "pkce_required": self.pkce_required,
            "consent_mode": self.consent_mode,
            "managed": self.managed,
            "metadata": self.metadata,
        }


class IdPClientBase:
    def __init__(self, provider: str, token_store: EphemeralTokenStore, rate_limiter: RateLimiter, auditor: AuditLogger):
        self.provider = provider
        self.tokens = token_store
        self.rate = rate_limiter
        self.auditor = auditor

    def discover_apps(self, source_file: Optional[str] = None) -> List[OIDCApp]:
        # Read-only discovery, prefer offline file for safety
        self.rate.acquire()
        apps: List[OIDCApp] = []
        if source_file and os.path.exists(source_file):
            with open(source_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data.get(self.provider, []):
                apps.append(
                    OIDCApp(
                        provider=self.provider,
                        name=item.get("name", f"{self.provider}-app"),
                        client_id=item.get("client_id", sha256_hex(uuid.uuid4().bytes)[:16]),
                        redirect_uris=item.get("redirect_uris", []),
                        pkce_required=item.get("pkce_required", False),
                        consent_mode=item.get("consent_mode", "auto"),
                        managed=item.get("managed", False),
                        metadata=item.get("metadata", {}),
                    )
                )
            self.auditor.log("discover_apps_file", {"provider": self.provider, "count": len(apps), "source": source_file})
            return apps

        # If no file, return empty in reference implementation to avoid network calls
        self.auditor.log("discover_apps_empty", {"provider": self.provider, "reason": "no_source_file"})
        return apps


class ShadowOIDCAppHunter:
    def __init__(self, auditor: Optional[AuditLogger] = None):
        self.auditor = auditor or AuditLogger()
        self.tokens = EphemeralTokenStore(self.auditor)
        # Conservative rate limits to respect provider limits
        self.okta = IdPClientBase("okta", self.tokens, RateLimiter(rate_per_sec=2, burst=4), self.auditor)
        self.azure = IdPClientBase("azuread", self.tokens, RateLimiter(rate_per_sec=2, burst=4), self.auditor)
        self.google = IdPClientBase("google", self.tokens, RateLimiter(rate_per_sec=2, burst=4), self.auditor)
        self.redirect_verifier = SafeRedirectVerifier()
        self._attestation_key = hashlib.sha256(("attest-" + self.auditor.session_id).encode()).digest()

    def discover(self, source_file: Optional[str] = None) -> List[OIDCApp]:
        apps = []
        apps.extend(self.okta.discover_apps(source_file))
        apps.extend(self.azure.discover_apps(source_file))
        apps.extend(self.google.discover_apps(source_file))
        self.auditor.log("discovery_complete", {"total_apps": len(apps)})
        return apps

    def validate_security_posture(self, apps: List[OIDCApp]) -> List[Dict[str, Any]]:
        results = []
        for app in apps:
            findings = []
            risk = 0
            # PKCE requirement
            if not app.pkce_required:
                findings.append({"type": "pkce_missing", "severity": "high", "message": "PKCE is not required"})
                risk += 40
            # Redirect URIs analysis
            redirect_checks = []
            for uri in app.redirect_uris:
                analysis = self.redirect_verifier.analyze_uri(uri)
                redirect_checks.append(analysis)
                if "wildcard_redirect" in analysis["issues"]:
                    findings.append({"type": "wildcard_redirect", "severity": "high", "uri": uri})
                    risk += 40
                if "insecure_scheme_http" in analysis["issues"]:
                    findings.append({"type": "insecure_redirect_scheme", "severity": "medium", "uri": uri})
                    risk += 15
                if "root_path_redirect" in analysis["issues"]:
                    findings.append({"type": "root_path_redirect", "severity": "low", "uri": uri})
                    risk += 5
            # Consent prompts
            if app.consent_mode in ("auto", "preconsent"):
                findings.append({"type": "weak_consent", "severity": "medium", "message": f"Consent mode '{app.consent_mode}'"})
                risk += 10
            # Managed flag
            if not app.managed:
                findings.append({"type": "unmanaged_app", "severity": "medium", "message": "App not managed in IdP"})
                risk += 10

            risk = min(100, risk)
            results.append(
                {
                    "app": app.to_dict(),
                    "risk_score": risk,
                    "findings": findings,
                    "redirect_checks": redirect_checks,
                    "remediation": self._remediation_plan_for_app(app, findings),
                }
            )
        self.auditor.log("validation_complete", {"count": len(results)})
        return results

    def _remediation_plan_for_app(self, app: OIDCApp, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        plan = []
        priority = 1
        types = {f["type"] for f in findings}
        if "pkce_missing" in types:
            plan.append({"priority": priority, "action": "enforce_pkce", "details": {"client_id": app.client_id}})
            priority += 1
        if "wildcard_redirect" in types:
            safe_uris = [a["uri"] for a in self.redirect_verifier_analyze(app.redirect_uris) if "wildcard_redirect" not in a["issues"]]
            plan.append({"priority": priority, "action": "remove_wildcard_redirects", "details": {"client_id": app.client_id, "recommended_redirects": safe_uris}})
            priority += 1
        if "insecure_redirect_scheme" in types:
            plan.append({"priority": priority, "action": "enforce_https_redirects", "details": {"client_id": app.client_id}})
            priority += 1
        if "weak_consent" in types:
            plan.append({"priority": priority, "action": "require_explicit_consent", "details": {"client_id": app.client_id}})
            priority += 1
        if "unmanaged_app" in types:
            plan.append({"priority": priority, "action": "onboard_to_mgmt", "details": {"client_id": app.client_id, "provider": app.provider}})
        return plan

    def redirect_verifier_analyze(self, uris: List[str]) -> List[Dict[str, Any]]:
        return [self.redirect_verifier.analyze_uri(u) for u in uris]

    def simulate_benign_auth_flow(self, app: OIDCApp) -> Dict[str, Any]:
        """
        Simulates building an authorization request with safe parameters and validating redirect.
        No network is performed. This validates the posture and highlights misconfigurations.
        """
        state = sha256_hex(uuid.uuid4().bytes)[:16]
        code_verifier = sha256_hex(uuid.uuid4().bytes)[:43]  # simulated
        uses_pkce = app.pkce_required
        redirect_ok = True
        redirect_issues = []
        for u in app.redirect_uris:
            a = self.redirect_verifier.analyze_uri(u)
            redirect_issues.extend(a["issues"])
            if a["issues"]:
                redirect_ok = False
        result = {
            "client_id": app.client_id,
            "uses_pkce": uses_pkce,
            "state": state,
            "code_verifier": "set" if uses_pkce else "not_used",
            "redirects_valid": redirect_ok,
            "redirect_issues": list(sorted(set(redirect_issues))),
            "note": "Simulation only; no tokens or real auth performed.",
        }
        self.auditor.log("simulate_auth_flow", {"client_id": app.client_id, "redirects_valid": redirect_ok, "uses_pkce": uses_pkce})
        return result

    def correlate_cloud_logs_for_replay(self, cloud_logs: List[Dict[str, Any]], window_minutes: int = 60) -> Dict[str, Any]:
        """
        Detects id_token replay using simple heuristics:
        - Same token_hash observed from multiple IPs or User-Agents within window.
        Input logs should include fields: ts, event_type, token_hash, ip, ua, resource, subject
        """
        by_token: Dict[str, List[Dict[str, Any]]] = {}
        for e in cloud_logs:
            if "token_hash" not in e:
                # derive if id_token present
                tok = e.get("id_token") or ""
                if tok:
                    e["token_hash"] = sha256_hex(tok.encode())
            th = e.get("token_hash")
            if not th:
                continue
            by_token.setdefault(th, []).append(e)

        findings = []
        blast_radius: Dict[str, Any] = {}
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        for token_hash, events in by_token.items():
            ips = set()
            uas = set()
            recent_events = []
            for ev in events:
                try:
                    ts = datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.utcnow()
                if ts >= cutoff:
                    recent_events.append(ev)
                    ips.add(ev.get("ip", ""))
                    uas.add(ev.get("ua", ""))
            if len(ips) > 1 or len(uas) > 1:
                resources = list({ev.get("resource", "") for ev in recent_events if ev.get("resource")})
                subjects = list({ev.get("subject", "") for ev in recent_events if ev.get("subject")})
                findings.append(
                    {
                        "token_hash": token_hash,
                        "anomalous_ips": list(ips),
                        "anomalous_uas": list(uas),
                        "events": recent_events,
                        "resources": resources,
                        "subjects": subjects,
                    }
                )
                for r in resources:
                    blast_radius.setdefault(r, set()).update(subjects)

        # Convert sets to lists
        blast_radius = {k: sorted(list(v)) for k, v in blast_radius.items()}

        recommendations = []
        for f in findings:
            recommendations.append(
                {
                    "token_hash": f["token_hash"],
                    "actions": [
                        "revoke_token_or_session",
                        "invalidate_refresh_tokens_for_subjects",
                        "enforce_token_binding_or_dpop",
                        "enable_ip_risk_signals_and_mfa_stepup",
                    ],
                }
            )
        report = {"findings": findings, "blast_radius": blast_radius, "recommendations": recommendations}
        self.auditor.log("log_correlation_complete", {"replay_findings": len(findings)})
        return report

    def remediation_apply(self, plan: List[Dict[str, Any]], approve: bool = False) -> Dict[str, Any]:
        """
        Applies remediation actions only if explicitly approved. Reference implementation
        performs no destructive change; it records what would be done.
        """
        actions = []
        for item in sorted(plan, key=lambda x: x.get("priority", 999)):
            actions.append({"action": item["action"], "details": item.get("details", {}), "applied": False})
        self.auditor.log("remediation_plan_review", {"count": len(actions), "approved": approve})
        if approve:
            # Still non-destructive; in production, call provider APIs with least-privilege scopes.
            for a in actions:
                a["applied"] = True
            self.auditor.log("remediation_apply", {"count": len(actions), "mode": "dry-run"})
        return {"actions": actions, "approved": approve, "note": "Dry-run; no changes performed."}

    def generate_attestation(self, validation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Produces a DSSE-like signed attestation enumerating discovered apps, risk scores,
        and policy compliance. Uses an HMAC signature as a placeholder for Sigstore in this
        reference implementation. For production, integrate Sigstore keyless signing.
        """
        predicate = {
            "timestamp": utc_now_iso(),
            "policy": {
                "pkce_required": True,
                "no_wildcard_redirects": True,
                "https_redirects_only": True,
                "explicit_consent": True,
            },
            "apps": [
                {
                    "provider": r["app"]["provider"],
                    "name": r["app"]["name"],
                    "client_id": r["app"]["client_id"],
                    "risk_score": r["risk_score"],
                    "findings": r["findings"],
                }
                for r in validation_results
            ],
            "compliance_summary": {
                "total": len(validation_results),
                "passing": sum(1 for r in validation_results if r["risk_score"] <= 10),
                "failing": sum(1 for r in validation_results if r["risk_score"] > 10),
            },
            "ethics": "Authorized testing only. See tool disclaimer.",
        }
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "shadow-oidc-apps", "digest": {"sha256": sha256_hex(json.dumps(predicate, sort_keys=True).encode())}}],
            "predicateType": "custom:shadow-oidc/policy",
            "predicate": predicate,
        }
        payload = json.dumps(statement, sort_keys=True).encode()
        sig = hmac_sha256_hex(self._attestation_key, payload)
        envelope = {
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": payload.decode(),
                "signatures": [
                    {
                        "keyid": sha256_hex(self._attestation_key)[:16],
                        "sig": sig,
                        "sig_alg": "HMAC-SHA256-ephemeral",
                        "sigstore": {
                            "mode": "placeholder",
                            "note": "Integrate Sigstore keyless for production (Fulcio/Rekor).",
                        },
                    }
                ],
            }
        }
        self.auditor.log("attestation_generated", {"apps": len(predicate["apps"])})
        return envelope

    # Convenience utilities for acceptance scenarios

    def scenario_identify_misconfig(self, source_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Acceptance: Identify an OAuth app lacking PKCE and using wildcard redirect URIs;
        simulate a benign auth flow and flag misconfiguration with prioritized remediation steps.
        """
        apps = self.discover(source_file)
        validation = self.validate_security_posture(apps)
        simulations = {}
        for r in validation:
            sim = self.simulate_benign_auth_flow(OIDCApp(**r["app"]))
            simulations[r["app"]["client_id"]] = sim
        return {"validation": validation, "simulations": simulations}

    def scenario_detect_token_replay(self, cloud_logs_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Acceptance: Correlate cloud access logs to detect an id_token replay from an anomalous IP/UA;
        produce a blast-radius report and revocation recommendations.
        """
        logs: List[Dict[str, Any]] = []
        if cloud_logs_file and os.path.exists(cloud_logs_file):
            with open(cloud_logs_file, "r", encoding="utf-8") as f:
                logs = json.load(f)
        return self.correlate_cloud_logs_for_replay(logs)

    def scenario_signed_attestation(self, source_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Acceptance: Produce a Sigstore-signed attestation enumerating discovered apps, risk scores,
        and policy compliance results suitable for CI/CD gating.
        """
        apps = self.discover(source_file)
        validation = self.validate_security_posture(apps)
        return self.generate_attestation(validation)


def main():
    print(ETHICAL_WARNING, file=sys.stderr)
    auditor = AuditLogger()
    hunter = ShadowOIDCAppHunter(auditor)

    # CLI-lite behavior for demonstration
    # Arguments:
    #   discover <source.json>
    #   correlate <logs.json>
    #   attest <source.json> > attestation.json
    args = sys.argv[1:]
    if not args:
        print("Usage:", file=sys.stderr)
        print("  python tools/cloud/shadow_oidc_app_hunter.py discover <source.json>", file=sys.stderr)
        print("  python tools/cloud/shadow_oidc_app_hunter.py correlate <logs.json>", file=sys.stderr)
        print("  python tools/cloud/shadow_oidc_app_hunter.py attest <source.json>", file=sys.stderr)
        sys.exit(2)

    cmd = args[0]
    if cmd == "discover":
        src = args[1] if len(args) > 1 else None
        out = hunter.scenario_identify_misconfig(src)
        print(json.dumps(out, indent=2))
    elif cmd == "correlate":
        logs = args[1] if len(args) > 1 else None
        out = hunter.scenario_detect_token_replay(logs)
        print(json.dumps(out, indent=2))
    elif cmd == "attest":
        src = args[1] if len(args) > 1 else None
        out = hunter.scenario_signed_attestation(src)
        print(json.dumps(out, indent=2))
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()