import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


@dataclass
class Alert:
    id: str
    severity: str  # HIGH, MEDIUM, LOW, INFO
    message: str
    remediation: str
    provider: Optional[str] = None
    timestamp: float = field(default_factory=lambda: time.time())
    policy_check_failed: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyFailure:
    rule_id: str
    severity: str
    message: str
    remediation: str
    provider: str


@dataclass
class ProviderConfig:
    name: str
    cloud: str  # aws|gcp|azure
    expected_issuer: str
    audiences: List[str]
    subject_patterns: List[str]
    metadata_url: Optional[str] = None
    allow_wildcard_subject: bool = False

    # Runtime state
    last_discovery: Optional[Dict[str, Any]] = None
    last_jwks: Optional[Dict[str, Any]] = None
    last_jwks_kids: Set[str] = field(default_factory=set)
    issuer_drift_detected: bool = False
    drift_reason: Optional[str] = None
    last_error: Optional[str] = None


@dataclass
class TrustBinding:
    id: str
    provider_name: str
    expected_issuer: str
    allowed_audiences: List[str]
    subject_pattern: str
    enforce_exp: bool = True
    require_nonce: bool = True
    cloud: str = "generic"  # for sim behavior
    additional_constraints: Dict[str, Any] = field(default_factory=dict)


class PolicyEngine:
    def __init__(self) -> None:
        self.rules = [
            self._rule_block_wildcard_audience,
            self._rule_block_overbroad_subject,
            self._rule_validate_https_issuer,
        ]

    def evaluate_provider(self, provider: ProviderConfig) -> List[PolicyFailure]:
        failures: List[PolicyFailure] = []
        for rule in self.rules:
            res = rule(provider)
            if isinstance(res, list):
                failures.extend(res)
            elif res:
                failures.append(res)
        return failures

    def _rule_block_wildcard_audience(self, provider: ProviderConfig) -> Optional[PolicyFailure]:
        for aud in provider.audiences:
            if aud.strip() == "*" or "*" in aud:
                return PolicyFailure(
                    rule_id="FG-PA-001",
                    severity="HIGH",
                    message=f"Provider '{provider.name}' has wildcard audience '{aud}'. This enables token replay/misbinding.",
                    remediation=(
                        "Restrict the audience to exact values used by your workloads (e.g., "
                        "for GitHub Actions use 'https://token.actions.githubusercontent.com' and scope via conditions). "
                        "Remove any '*' or wildcard patterns and validate audience per provider binding."
                    ),
                    provider=provider.name,
                )
        return None

    def _rule_block_overbroad_subject(self, provider: ProviderConfig) -> Optional[PolicyFailure]:
        if provider.allow_wildcard_subject:
            return None
        for pat in provider.subject_patterns:
            if pat.strip() == "*" or pat.strip() in ("repo:*", "sub:*") or "*" in pat:
                return PolicyFailure(
                    rule_id="FG-PA-002",
                    severity="HIGH",
                    message=f"Provider '{provider.name}' allows overbroad subject pattern '{pat}'.",
                    remediation=(
                        "Constrain subject claims to exact repositories/branches/tags. "
                        "Avoid '*' wildcards. For example, use 'repo:org/repo:ref:refs/heads/main'."
                    ),
                    provider=provider.name,
                )
        return None

    def _rule_validate_https_issuer(self, provider: ProviderConfig) -> Optional[PolicyFailure]:
        if not provider.expected_issuer.startswith("https://"):
            return PolicyFailure(
                rule_id="FG-PA-003",
                severity="MEDIUM",
                message=f"Provider '{provider.name}' issuer '{provider.expected_issuer}' is not HTTPS.",
                remediation="Use a secure HTTPS OIDC issuer URL.",
                provider=provider.name,
            )
        return None


class FederationGuard:
    def __init__(self, authorized_testing: bool = False, logger: Optional[logging.Logger] = None) -> None:
        self.providers: Dict[str, ProviderConfig] = {}
        self.policy_engine = PolicyEngine()
        self.event_log: List[Dict[str, Any]] = []
        self.alerts: List[Alert] = []
        self._stop_event = threading.Event()
        self.authorized_testing = authorized_testing
        self.replay_cache: Dict[str, Set[str]] = {}  # binding_id -> seen jti/nonce
        self.logger = logger or self._default_logger()

    def _default_logger(self) -> logging.Logger:
        logger = logging.getLogger("FederationGuard")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def register_provider(self, provider: ProviderConfig) -> None:
        if provider.name in self.providers:
            raise ValueError(f"Provider '{provider.name}' is already registered")
        self.providers[provider.name] = provider
        self.logger.info(f"Registered provider: {provider.name}")

    def monitor_providers(self, run_once: bool = True, interval: int = 300, http_timeout: int = 5) -> None:
        """
        Fetch discovery and JWKS, validate issuer drift and weak policies.
        If run_once=False, runs continuously until stop_monitoring() is called.
        """
        ethical_notice = (
            "Ethical use notice: FederationGuard performs only metadata fetches and simulations. "
            "Do not target third-party endpoints without authorization."
        )
        self.logger.warning(ethical_notice)
        try:
            while True:
                for provider in self.providers.values():
                    try:
                        self._check_provider(provider, http_timeout=http_timeout)
                    except Exception as e:
                        provider.last_error = str(e)
                        self.logger.error(f"Error checking provider {provider.name}: {e}")
                        self._record_event(
                            "provider_check_error",
                            {"provider": provider.name, "error": str(e)},
                        )
                self._run_policy_checks()
                if run_once:
                    break
                if self._stop_event.wait(interval):
                    break
        except KeyboardInterrupt:
            self.logger.info("Monitoring interrupted by user.")

    def stop_monitoring(self) -> None:
        self._stop_event.set()

    def _check_provider(self, provider: ProviderConfig, http_timeout: int = 5) -> None:
        # Proactive issuer lookalike detection if metadata_url indicates drift
        if provider.metadata_url and not provider.issuer_drift_detected:
            try:
                exp = urlparse(provider.expected_issuer)
                meta = urlparse(provider.metadata_url)
                ehost = (exp.netloc or exp.path).lower()
                mhost = (meta.netloc or meta.path).lower()
                if ehost and mhost and ehost != mhost:
                    lookalike, reason = self._is_lookalike_url(provider.expected_issuer, provider.metadata_url)
                    provider.issuer_drift_detected = True
                    provider.drift_reason = reason or "Issuer mismatch"
                    severity = "HIGH" if lookalike else "MEDIUM"
                    self._raise_alert(
                        Alert(
                            id="FG-DRIFT-ISSUER",
                            severity=severity,
                            message=f"Issuer drift suspected for provider '{provider.name}': expected host '{ehost}', metadata points to '{mhost}'.",
                            remediation=(
                                "Verify the issuer and metadata URL. If this change was unintended, revert immediately and block token exchanges. "
                                "Ensure trust bindings reference the exact issuer domain."
                            ),
                            provider=provider.name,
                            policy_check_failed=True,
                            details={"expected_host": ehost, "metadata_host": mhost, "reason": reason, "lookalike": lookalike, "metadata_url": provider.metadata_url},
                        )
                    )
            except Exception as e:
                provider.last_error = f"metadata_url_check_error: {e}"
                self._record_event("metadata_url_check_error", {"provider": provider.name, "error": str(e)})

        discovery = self._fetch_discovery(provider, http_timeout=http_timeout)
        if discovery:
            provider.last_discovery = discovery
            issuer = discovery.get("issuer")
            if issuer and issuer != provider.expected_issuer:
                lookalike, reason = self._is_lookalike_url(provider.expected_issuer, issuer)
                provider.issuer_drift_detected = True
                provider.drift_reason = reason or "Issuer mismatch"
                severity = "HIGH" if lookalike else "MEDIUM"
                self._raise_alert(
                    Alert(
                        id="FG-DRIFT-ISSUER",
                        severity=severity,
                        message=f"Issuer drift detected for provider '{provider.name}': expected '{provider.expected_issuer}', got '{issuer}'.",
                        remediation=(
                            "Investigate configuration changes and ensure trust is bound to the exact issuer. "
                            "Revert to the expected issuer or update bindings securely. Block access until validated."
                        ),
                        provider=provider.name,
                        policy_check_failed=True,
                        details={"expected": provider.expected_issuer, "actual": issuer, "lookalike": lookalike, "reason": reason},
                    )
                )
            jwks_uri = discovery.get("jwks_uri")
            if jwks_uri:
                jwks = self._fetch_jwks(jwks_uri, http_timeout=http_timeout)
                if jwks:
                    new_kids = {k.get("kid", "") for k in jwks.get("keys", []) if isinstance(k, dict)}
                    if provider.last_jwks_kids and new_kids and new_kids != provider.last_jwks_kids:
                        self._record_event(
                            "jwks_rotation",
                            {"provider": provider.name, "old_kids": list(provider.last_jwks_kids), "new_kids": list(new_kids)},
                        )
                        self.logger.info(f"JWKS rotation detected for provider {provider.name}")
                    provider.last_jwks = jwks
                    provider.last_jwks_kids = new_kids

    def _fetch_discovery(self, provider: ProviderConfig, http_timeout: int = 5) -> Optional[Dict[str, Any]]:
        url = provider.metadata_url or (provider.expected_issuer.rstrip("/") + "/.well-known/openid-configuration")
        try:
            req = Request(url, headers={"User-Agent": "FederationGuard/1.0"})
            with urlopen(req, timeout=http_timeout) as resp:
                data = resp.read()
                discovery = json.loads(data.decode("utf-8"))
                self._record_event("fetched_discovery", {"provider": provider.name, "url": url})
                return discovery
        except (HTTPError, URLError) as e:
            self.logger.warning(f"Failed to fetch discovery for {provider.name} from {url}: {e}")
            self._record_event("discovery_fetch_failed", {"provider": provider.name, "url": url, "error": str(e)})
            return None
        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid discovery JSON for {provider.name} from {url}: {e}")
            self._record_event("discovery_invalid_json", {"provider": provider.name, "url": url, "error": str(e)})
            return None

    def _fetch_jwks(self, jwks_uri: str, http_timeout: int = 5) -> Optional[Dict[str, Any]]:
        try:
            req = Request(jwks_uri, headers={"User-Agent": "FederationGuard/1.0"})
            with urlopen(req, timeout=http_timeout) as resp:
                data = resp.read()
                jwks = json.loads(data.decode("utf-8"))
                if "keys" not in jwks or not isinstance(jwks["keys"], list):
                    raise ValueError("JWKS missing 'keys'")
                self._record_event("fetched_jwks", {"jwks_uri": jwks_uri, "key_count": len(jwks.get("keys", []))})
                return jwks
        except (HTTPError, URLError, ValueError) as e:
            self.logger.warning(f"Failed to fetch JWKS from {jwks_uri}: {e}")
            self._record_event("jwks_fetch_failed", {"jwks_uri": jwks_uri, "error": str(e)})
            return None
        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid JWKS JSON from {jwks_uri}: {e}")
            self._record_event("jwks_invalid_json", {"jwks_uri": jwks_uri, "error": str(e)})
            return None

    def _run_policy_checks(self) -> None:
        for provider in self.providers.values():
            failures = self.policy_engine.evaluate_provider(provider)
            for f in failures:
                self._raise_alert(
                    Alert(
                        id=f.rule_id,
                        severity=f.severity,
                        message=f.message,
                        remediation=f.remediation,
                        provider=f.provider,
                        policy_check_failed=True,
                    )
                )

    def simulate_token_attempt(self, token: Dict[str, Any], binding: TrustBinding) -> Dict[str, Any]:
        """
        Simulates using an OIDC token to exchange for cloud credentials on a target binding.
        Returns a dict with 'accepted' bool and 'reason'.
        Requires authorized_testing=True to run.
        """
        if not self.authorized_testing:
            raise PermissionError(
                "Unauthorized operation: Simulation requires explicit consent. "
                "Set authorized_testing=True to FederationGuard to proceed. "
                "Ethical use only against systems you own or are authorized to test."
            )
        now = int(time.time())
        iss = str(token.get("iss", ""))
        aud = token.get("aud")
        sub = str(token.get("sub", ""))
        exp = token.get("exp")
        jti = str(token.get("jti") or token.get("nonce") or "")

        # Validate issuer
        if iss != binding.expected_issuer:
            reason = "issuer_mismatch"
            self._record_event("token_rejected", {"binding": binding.id, "reason": reason, "iss": iss})
            return {"accepted": False, "reason": reason}

        # Validate audience membership
        aud_ok = False
        if isinstance(aud, list):
            aud_ok = any(a in binding.allowed_audiences for a in aud)
        else:
            aud_ok = aud in binding.allowed_audiences
        if not aud_ok:
            reason = "audience_mismatch"
            self._record_event("token_rejected", {"binding": binding.id, "reason": reason, "aud": aud})
            return {"accepted": False, "reason": reason}

        # Validate subject pattern
        if not self._subject_matches(sub, binding.subject_pattern):
            reason = "subject_mismatch"
            self._record_event("token_rejected", {"binding": binding.id, "reason": reason, "sub": sub})
            return {"accepted": False, "reason": reason}

        # Validate expiry
        if binding.enforce_exp:
            try:
                exp_int = int(exp)
            except Exception:
                reason = "invalid_exp"
                self._record_event("token_rejected", {"binding": binding.id, "reason": reason})
                return {"accepted": False, "reason": reason}
            if exp_int <= now:
                reason = "expired"
                self._record_event("token_rejected", {"binding": binding.id, "reason": reason, "exp": exp_int, "now": now})
                return {"accepted": False, "reason": reason}

        # Replay protection
        if binding.require_nonce:
            if not jti:
                reason = "missing_nonce"
                self._record_event("token_rejected", {"binding": binding.id, "reason": reason})
                return {"accepted": False, "reason": reason}
            seen = self.replay_cache.setdefault(binding.id, set())
            if jti in seen:
                reason = "replay_detected"
                self._record_event("token_rejected", {"binding": binding.id, "reason": reason, "jti": jti})
                return {"accepted": False, "reason": reason}
            seen.add(jti)

        # Accepted
        self._record_event("token_accepted", {"binding": binding.id, "iss": iss, "aud": aud, "sub": sub})
        return {"accepted": True, "reason": "ok"}

    def simulate_token_replay(self, token: Dict[str, Any], binding: TrustBinding) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Attempts a token exchange twice to validate replay protection.
        Returns (first_attempt_result, second_attempt_result)
        """
        first = self.simulate_token_attempt(token, binding)
        second = self.simulate_token_attempt(token, binding)
        return first, second

    def _subject_matches(self, subject: str, pattern: str) -> bool:
        # Convert simple wildcard pattern to regex
        # Escape regex meta, then replace '*' with '.*'
        regex = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
        return re.match(regex, subject) is not None

    def _is_lookalike_url(self, expected: str, actual: str) -> Tuple[bool, Optional[str]]:
        try:
            ep = urlparse(expected)
            ap = urlparse(actual)
            ehost = (ep.netloc or ep.path).lower()
            ahost = (ap.netloc or ap.path).lower()
            if ehost == ahost:
                return False, None
            # Normalize confusables
            def norm(s: str) -> str:
                table = str.maketrans(
                    {
                        "0": "o",
                        "1": "l",
                        "l": "l",
                        "i": "l",
                        "5": "s",
                        "2": "z",
                        "8": "b",
                    }
                )
                return s.translate(table)

            ne = norm(ehost)
            na = norm(ahost)
            # Compare base domains (last two labels)
            def base(dom: str) -> str:
                parts = dom.split(".")
                return ".".join(parts[-2:]) if len(parts) >= 2 else dom

            # Heuristic: if normalized hosts are within small edit distance or share base domain, flag lookalike
            similar = self._levenshtein_leq(ne, na, 2)
            same_base = base(ehost) == base(ahost)
            reason = None
            if similar or same_base:
                reason = f"Lookalike detection: expected host '{ehost}', actual '{ahost}', normalized '{ne}' vs '{na}', same_base={same_base}"
                return True, reason
            return False, "Issuer mismatch"
        except Exception:
            return False, "Issuer mismatch"

    def _levenshtein_leq(self, a: str, b: str, threshold: int) -> bool:
        # Early exit if length diff exceeds threshold
        if abs(len(a) - len(b)) > threshold:
            return False
        # Limited Levenshtein to check <= threshold
        # Use dynamic programming with pruning
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            curr = [i] + [0] * len(b)
            min_row = curr[0]
            for j, cb in enumerate(b, start=1):
                cost = 0 if ca == cb else 1
                curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
                if curr[j] < min_row:
                    min_row = curr[j]
            if min_row > threshold:
                return False
            prev = curr
        return prev[-1] <= threshold

    def _raise_alert(self, alert: Alert) -> None:
        # Avoid duplicates by id+provider+message in a short window
        key = (alert.id, alert.provider, alert.message)
        exists = any((a.id, a.provider, a.message) == key for a in self.alerts[-50:])
        if not exists:
            self.alerts.append(alert)
            self._record_event(
                "alert",
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "provider": alert.provider,
                    "message": alert.message,
                    "remediation": alert.remediation,
                },
            )
            if alert.severity in ("HIGH", "CRITICAL"):
                self.logger.error(f"ALERT[{alert.severity}] {alert.message}")
            else:
                self.logger.warning(f"ALERT[{alert.severity}] {alert.message}")

    def _record_event(self, event_type: str, data: Dict[str, Any]) -> None:
        entry = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "data": data,
        }
        self.event_log.append(entry)

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)

    def get_event_log(self) -> List[Dict[str, Any]]:
        return list(self.event_log)


# Convenience scenario builders for acceptance testing
def build_wildcard_audience_provider(name: str = "gcp-wif") -> ProviderConfig:
    return ProviderConfig(
        name=name,
        cloud="gcp",
        expected_issuer="https://accounts.google.com",
        audiences=["*"],  # insecure
        subject_patterns=["repo:org/*"],
    )


def build_binding_for_ci(provider_name: str, issuer: str, project: str = "proj-1") -> TrustBinding:
    return TrustBinding(
        id=f"{provider_name}:{project}",
        provider_name=provider_name,
        expected_issuer=issuer,
        allowed_audiences=["https://token.actions.githubusercontent.com"],
        subject_pattern="repo:org/repo:ref:refs/heads/main",
        enforce_exp=True,
        require_nonce=True,
        cloud="gcp",
    )


def example_usage():
    # Ethical notice: this is a self-contained simulation. Do not direct at third-party systems.
    fg = FederationGuard(authorized_testing=True)

    # 1) Detect wildcard audience in a provider
    p = build_wildcard_audience_provider()
    fg.register_provider(p)
    # simulate policy checks (no network needed)
    fg.monitor_providers(run_once=True)
    alerts = fg.get_alerts()
    high_risk = [a for a in alerts if a.id == "FG-PA-001"]
    assert high_risk, "Should detect wildcard audience"
    # 2) Replay token simulation
    binding = build_binding_for_ci(p.name, issuer="https://token.actions.githubusercontent.com")
    now = int(time.time())
    token = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "https://token.actions.githubusercontent.com",
        "sub": "repo:org/repo:ref:refs/heads/main",
        "exp": now + 300,
        "jti": "nonce-123",
    }
    first, second = fg.simulate_token_replay(token, binding)
    assert first["accepted"] is True
    assert second["accepted"] is False and second["reason"] == "replay_detected"
    # 3) Issuer drift to lookalike
    p2 = ProviderConfig(
        name="azure-wif",
        cloud="azure",
        expected_issuer="https://login.microsoftonline.com/tenantid/v2.0",
        audiences=["api://AzureADTokenExchange"],
        subject_patterns=["repo:org/repo:ref:refs/heads/main"],
    )
    fg.register_provider(p2)
    # monkeypatch discovery (simulating drift)
    p2.metadata_url = "https://login.microsof1online.com/tenantid/v2.0/.well-known/openid-configuration"  # lookalike host
    fg.monitor_providers(run_once=True)  # will try to fetch; likely fail if offline but will run policy checks
    # Directly simulate detection using internal heuristic without network:
    lookalike, reason = fg._is_lookalike_url(
        p2.expected_issuer, "https://login.microsof1online.com/tenantid/v2.0"
    )
    if lookalike:
        fg._raise_alert(
            Alert(
                id="FG-DRIFT-ISSUER",
                severity="HIGH",
                message=f"Issuer drift detected for provider '{p2.name}': expected '{p2.expected_issuer}', got 'https://login.microsof1online.com/tenantid/v2.0'.",
                remediation="Revert issuer and block access until validated.",
                provider=p2.name,
                policy_check_failed=True,
                details={"reason": reason},
            )
        )
    # Simulate blocked access due to issuer mismatch
    binding2 = TrustBinding(
        id="azure-wif:sub1",
        provider_name="azure-wif",
        expected_issuer=p2.expected_issuer,
        allowed_audiences=["api://AzureADTokenExchange"],
        subject_pattern="repo:org/repo:ref:refs/heads/main",
        cloud="azure",
    )
    token2 = {
        "iss": "https://login.microsof1online.com/tenantid/v2.0",
        "aud": "api://AzureADTokenExchange",
        "sub": "repo:org/repo:ref:refs/heads/main",
        "exp": int(time.time()) + 600,
        "jti": "nonce-xyz",
    }
    res = fg.simulate_token_attempt(token2, binding2)
    assert res["accepted"] is False and res["reason"] == "issuer_mismatch"
    return fg


if __name__ == "__main__":
    # Demonstration only; not a test runner
    fg = example_usage()
    print("Alerts:")
    for a in fg.get_alerts():
        print(f"- [{a.severity}] {a.id} on {a.provider}: {a.message}")
        print(f"  Remediation: {a.remediation}")
    print("\nRecent events (last 10):")
    for e in fg.get_event_log()[-10:]:
        print(e)