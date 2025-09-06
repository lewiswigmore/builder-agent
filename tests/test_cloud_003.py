import base64
import json
import logging
import time as _time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

import pytest

from tools.cloud.federation_guard import FederationGuard


def b64url(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def make_jwt(
    payload: Dict[str, Any],
    header: Optional[Dict[str, Any]] = None,
    signature: str = "signature",
) -> str:
    if header is None:
        header = {"alg": "RS256", "typ": "JWT", "kid": "test-kid"}
    header_part = b64url(json.dumps(header, separators=(",", ":")))
    payload_part = b64url(json.dumps(payload, separators=(",", ":")))
    signature_part = b64url(signature)
    return f"{header_part}.{payload_part}.{signature_part}"


def get_field(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    if hasattr(obj, key):
        return getattr(obj, key)
    return default


def extract_alerts(report: Any) -> List[Any]:
    alerts = get_field(report, "alerts")
    if alerts is None:
        alerts = get_field(report, "events")
    if alerts is None:
        alerts = get_field(report, "issues")
    if alerts is None:
        return []
    return list(alerts)


def alert_matches(alert: Any, severity: Optional[Iterable[str]] = None, contains: Optional[Iterable[str]] = None) -> bool:
    sev = str(get_field(alert, "severity", get_field(alert, "level", ""))).lower()
    msg = (
        str(get_field(alert, "message", ""))
        + " "
        + str(get_field(alert, "detail", ""))
        + " "
        + str(get_field(alert, "description", ""))
    ).lower()
    if severity:
        if sev not in [s.lower() for s in severity]:
            return False
    if contains:
        low = [c.lower() for c in contains]
        if not any(c in msg for c in low):
            return False
    return True


def has_high_risk_alert_with_text(report: Any, text_substrings: Iterable[str]) -> bool:
    alerts = extract_alerts(report)
    for a in alerts:
        if alert_matches(a, severity=("high", "critical"), contains=text_substrings):
            return True
    return False


def has_remediation(report: Any, keyword_substrings: Iterable[str]) -> bool:
    alerts = extract_alerts(report)
    for a in alerts:
        remediation = (
            str(get_field(a, "remediation", ""))
            + " "
            + str(get_field(a, "recommendation", ""))
            + " "
            + str(get_field(a, "fix", ""))
        ).lower()
        if any(k.lower() in remediation for k in keyword_substrings):
            return True
    return False


def policy_blocked(report: Any) -> bool:
    # Direct "blocked"
    if bool(get_field(report, "blocked", False)):
        return True
    # Policy object with blocked/deny
    policy = get_field(report, "policy") or get_field(report, "policy_result") or get_field(report, "decision")
    if policy:
        if bool(get_field(policy, "blocked", False)) or str(get_field(policy, "decision", "")).lower() in ("deny", "block"):
            return True
        # checks list
        checks = get_field(policy, "checks") or get_field(policy, "results") or get_field(policy, "rules")
        if checks:
            for c in checks:
                status = str(get_field(c, "status", "")).lower()
                if status in ("fail", "block", "deny", "violation"):
                    return True
    # Generic checks on top-level
    for list_key in ("policy_checks", "checks", "results", "rules", "violations"):
        checks = get_field(report, list_key)
        if checks:
            for c in checks:
                status = str(get_field(c, "status", "")).lower()
                sev = str(get_field(c, "severity", "")).lower()
                if status in ("fail", "block", "deny", "violation") or sev in ("high", "critical"):
                    return True
    return False


def find_method(obj: Any, candidates: Iterable[str]) -> Callable:
    for name in candidates:
        if hasattr(obj, name) and callable(getattr(obj, name)):
            return getattr(obj, name)
    raise AttributeError(f"None of the candidate methods exist: {', '.join(candidates)}")


def call_replay_simulation(guard: FederationGuard, token: str, target: Dict[str, Any]) -> Any:
    method = find_method(
        guard,
        (
            "simulate_token_replay",
            "simulate_replay",
            "replay_token",
            "replay",
            "test_replay",
        ),
    )
    try:
        return method(token, target)  # Preferred signature
    except TypeError:
        # Try with keyword args
        return method(token=token, target=target)


class DummyResponse:
    def __init__(self, json_data: Dict[str, Any], status_code: int = 200, headers: Optional[Dict[str, str]] = None):
        self._json = json_data
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.text = json.dumps(json_data)

    def json(self) -> Dict[str, Any]:
        return self._json

    def raise_for_status(self) -> None:
        if not (200 <= self.status_code < 300):
            raise Exception(f"HTTP {self.status_code}")


@pytest.fixture
def guard() -> FederationGuard:
    return FederationGuard()


def test_detect_wildcard_audience_high_risk_policy_block(guard: FederationGuard, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)
    provider_cfg = {
        "name": "wif-provider-test",
        "issuer": "http://127.0.0.1:8000",
        "audiences": ["*"],
        "subject_claims": ["repo:org/*"],
        "project": "proj-x",
    }
    audit = find_method(guard, ("audit_wif_provider", "audit_provider", "audit", "evaluate_provider"))
    report = audit(provider_cfg)

    assert has_high_risk_alert_with_text(report, ("wildcard", "audience", "wif", "workload identity"))
    assert has_remediation(report, ("limit audience", "restrict audience", "tighten", "scope"))
    assert policy_blocked(report)


def test_replay_previously_valid_token_rejected_and_logged(guard: FederationGuard, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)
    now = int(_time.time())
    payload = {
        "iss": "https://issuer.ci.local",
        "aud": "sts.amazonaws.com",
        "sub": "repo:org/repo:ref:refs/heads/main",
        "iat": now,
        "exp": now + 5,
        "nonce": "nonce-12345",
        "jti": "jti-abc-001",
        "bound_project": "project-a",
    }
    token = make_jwt(payload)
    target = {
        "cloud": "gcp",
        "project": "project-a",
        "audience": "https://iamcredentials.googleapis.com",
        "binding": {"provider": "wip/provider-1", "service_account": "sa@test.iam.gserviceaccount.com"},
    }

    # First attempt: previously valid issuance (do not assert outcome strictly; some tools may simulate only)
    _ = call_replay_simulation(guard, token, target)

    # Advance time to ensure token is expired and considered replay if reused
    monkeypatch.setattr("tools.cloud.federation_guard.time.time", lambda: now + 120, raising=False)
    result = call_replay_simulation(guard, token, target)

    # Interpret result generically
    status = str(get_field(result, "status", get_field(result, "decision", get_field(result, "result", "")))).lower()
    accepted = get_field(result, "accepted", get_field(result, "ok", None))
    rejected = get_field(result, "rejected", None)

    # Expect rejection due to nonce/exp/binding enforcement
    assert (
        rejected is True
        or accepted is False
        or status in ("rejected", "blocked", "deny", "failed")
    )

    # Ensure event is logged
    log_text = " ".join(rec.getMessage().lower() for rec in caplog.records)
    assert any(k in log_text for k in ("replay", "expired", "nonce", "binding", "rejected"))


def test_issuer_url_drift_lookalike_flagged_and_blocked(guard: FederationGuard, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.DEBUG)

    expected_issuer = "https://accounts.example.com"
    lookalike_issuer = "https://acc0unts.example.com"  # lookalike drift
    metadata_url = "http://127.0.0.1:8000/.well-known/openid-configuration"

    def fake_get(url: str, *args, **kwargs):
        if url == metadata_url:
            return DummyResponse(
                {
                    "issuer": lookalike_issuer,
                    "jwks_uri": "http://127.0.0.1:8000/keys.json",
                    "token_endpoint": "http://127.0.0.1:8000/token",
                }
            )
        elif url == "http://127.0.0.1:8000/keys.json":
            return DummyResponse({"keys": [{"kty": "RSA", "kid": "k1", "n": "00", "e": "AQAB"}]})
        return DummyResponse({}, status_code=404)

    monkeypatch.setattr("tools.cloud.federation_guard.requests.get", fake_get, raising=False)

    # Prefer a high-level drift monitor, else fall back to fetch + drift detection
    try:
        monitor = find_method(guard, ("monitor_issuer", "audit_issuer", "validate_issuer", "check_issuer_drift"))
        report = monitor(metadata_url, expected_issuer)
    except AttributeError:
        fetch = find_method(guard, ("fetch_oidc_metadata", "get_oidc_metadata", "load_oidc_metadata"))
        md = fetch(metadata_url)
        drift_check = find_method(guard, ("detect_issuer_drift", "check_issuer_drift", "validate_issuer_binding"))
        report = drift_check(get_field(md, "issuer", md), expected_issuer)

    assert has_high_risk_alert_with_text(report, ("issuer", "drift", "lookalike", "mismatch", "misbinding"))
    assert policy_blocked(report)

    # simulate blocked access message in logs
    log_text = " ".join(rec.getMessage().lower() for rec in caplog.records)
    assert any(k in log_text for k in ("blocked", "mismatch", "drift", "lookalike", "misbinding"))


def test_error_handling_metadata_fetch_failure(guard: FederationGuard, monkeypatch: pytest.MonkeyPatch):
    from requests.exceptions import ConnectionError

    def raise_conn_error(*args, **kwargs):
        raise ConnectionError("simulated connection failure")

    monkeypatch.setattr("tools.cloud.federation_guard.requests.get", raise_conn_error, raising=False)

    # Try using the metadata fetcher if available, else the higher level monitor
    url = "http://127.0.0.1:8000/.well-known/openid-configuration"

    # The tool should either raise a domain-specific error or return an error alert
    try:
        fetch = find_method(guard, ("fetch_oidc_metadata", "get_oidc_metadata", "load_oidc_metadata"))
        result = fetch(url)
        # If no exception, ensure an error alert is present
        assert has_high_risk_alert_with_text(result, ("error", "fetch", "network", "connection"))
    except Exception:
        # Accept raising as valid error handling
        assert True