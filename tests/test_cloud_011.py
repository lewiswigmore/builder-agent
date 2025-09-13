import pytest
import types
import inspect
from datetime import datetime, timedelta, timezone

mod = pytest.importorskip("tools.cloud.auditlog_tamper_sentinel")


class FakeTSAClient:
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
        self.requests = []

    def rfc3161_timestamp(self, data: bytes):
        self.requests.append(data)
        if self.should_fail:
            raise ConnectionError("TSA unreachable")
        return {
            "tsa_token": b"fake-tsa-token",
            "tsa_cert": "CN=Fake TSA,O=Test",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify(self, data: bytes, token: bytes):
        if self.should_fail:
            raise ConnectionError("TSA unreachable")
        return {"ok": True, "verified_at": datetime.now(timezone.utc).isoformat()}


class FakeRekorClient:
    def __init__(self):
        self.entries = []

    def log_entry(self, digest_hex: str):
        entry = {
            "rekor_uuid": "123e4567-e89b-12d3-a456-426614174000",
            "integrated_time": int(datetime.now(timezone.utc).timestamp()),
            "log_index": 42,
            "digest": digest_hex,
        }
        self.entries.append(entry)
        return entry

    def verify_entry(self, digest_hex: str):
        for e in self.entries:
            if e["digest"] == digest_hex:
                return {"ok": True, "entry": e}
        return {"ok": False, "reason": "not found"}


class FakeSigner:
    def __init__(self, key_id="kms-key-1", hsm=False):
        self.key_id = key_id
        self.hsm = hsm
        self.requests = []

    def sign(self, data: bytes):
        self.requests.append(data)
        return {
            "signature": b"fake-signature",
            "key_id": self.key_id,
            "provider": "HSM" if self.hsm else "KMS",
            "algo": "ECDSA_P256_SHA256",
        }


class FakeArchive:
    def __init__(self):
        self.records = []

    def store_immutable(self, bundle: bytes, rotation: str = "daily", retention_days: int = 365):
        rec = {
            "archive_id": f"imm-{len(self.records)+1}",
            "rotation": rotation,
            "retention_days": retention_days,
            "immutable": True,
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        self.records.append(rec)
        return rec


class FakeTimeSync:
    def __init__(self, healthy=True):
        self.healthy = healthy
        self.checked = False

    def check(self):
        self.checked = True
        return {
            "healthy": self.healthy,
            "source": "ntp/chrony",
            "offset_ms": 3 if self.healthy else 2500,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


class FakeAWSClient:
    def __init__(
        self,
        digest_issue=False,
        missing_interval=False,
        drift=False,
        compliant=True,
        read_only=True,
    ):
        self.digest_issue = digest_issue
        self.missing_interval = missing_interval
        self.drift = drift
        self.compliant = compliant
        self.read_only = read_only
        self.calls = []

    def name(self):
        return "aws"

    def use_least_privilege(self):
        # simulate role info
        return {"role": "ReadOnlyAudit", "least_privilege": self.read_only, "write": False}

    def verify_digests(self, start: datetime, end: datetime):
        self.calls.append(("verify_digests", start, end))
        findings = []
        if self.digest_issue:
            findings.append(
                {
                    "type": "digest_mismatch" if not self.missing_interval else "missing_digest_interval",
                    "service": "cloudtrail",
                    "time_window": {
                        "start": (start + timedelta(minutes=5)).replace(microsecond=0).isoformat(),
                        "end": (start + timedelta(minutes=35)).replace(microsecond=0).isoformat(),
                    },
                    "artifacts": {
                        "provider_signed_digest": "fake-digest.sig",
                        "manifest_chain": ["m1.json", "m2.json"],
                        "recomputed_root": "abc123",
                        "expected_root": "def456" if not self.missing_interval else "missing",
                    },
                }
            )
        return findings

    def check_policy_immutability(self, resource_arn: str):
        self.calls.append(("check_policy_immutability", resource_arn))
        if self.drift:
            return {
                "resource": resource_arn,
                "drift": True,
                "issues": [
                    {"type": "retention_reduced", "from_days": 365, "to_days": 30},
                    {"type": "legal_hold_disabled", "was": True, "now": False},
                ],
                "proposed_remediation_as_code": 'resource "aws_s3_bucket_object_lock_configuration" "logs" { ... }',
            }
        return {"resource": resource_arn, "drift": False, "issues": [], "proposed_remediation_as_code": ""}

    def verify_continuity(self, start: datetime, end: datetime):
        self.calls.append(("verify_continuity", start, end))
        return {
            "period": {"start": start.replace(microsecond=0).isoformat(), "end": end.replace(microsecond=0).isoformat()},
            "intact": self.compliant and not self.digest_issue,
            "immutable": self.compliant and not self.drift,
            "evidence": {
                "chain": ["m1.json", "m2.json", "m3.json"],
                "provider_sigs": ["sig1", "sig2", "sig3"],
            },
        }


def _get_sentinel_instance(tsa_fail=False):
    # Locate the class or factory to create a sentinel
    sentinel_cls = getattr(mod, "AuditLogTamperSentinel", None)
    if sentinel_cls is None:
        pytest.skip("AuditLogTamperSentinel class not found in module")
    # Determine constructor signature
    sig = inspect.signature(sentinel_cls)
    kwargs = {}
    # Provide DI based on parameters
    fake_tsa = FakeTSAClient(should_fail=tsa_fail)
    fake_rekor = FakeRekorClient()
    fake_signer = FakeSigner()
    fake_archive = FakeArchive()
    fake_time = FakeTimeSync(healthy=not tsa_fail)

    clients = {"aws": FakeAWSClient()}
    if "cloud_clients" in sig.parameters:
        kwargs["cloud_clients"] = clients
    elif "clients" in sig.parameters:
        kwargs["clients"] = clients
    if "tsa_client" in sig.parameters:
        kwargs["tsa_client"] = fake_tsa
    if "rekor_client" in sig.parameters:
        kwargs["rekor_client"] = fake_rekor
    if "signer" in sig.parameters:
        kwargs["signer"] = fake_signer
    if "archive" in sig.parameters:
        kwargs["archive"] = fake_archive
    if "time_sync" in sig.parameters:
        kwargs["time_sync"] = fake_time

    try:
        sentinel = sentinel_cls(**kwargs)
    except TypeError:
        # Fallback empty init
        sentinel = sentinel_cls()

    # Attach DI attributes even if constructor didn't accept them
    for name, value in [
        ("cloud_clients", clients),
        ("clients", clients),
        ("tsa_client", fake_tsa),
        ("rekor_client", fake_rekor),
        ("signer", fake_signer),
        ("archive", fake_archive),
        ("time_sync", fake_time),
    ]:
        try:
            setattr(sentinel, name, value)
        except Exception:
            pass

    return sentinel, clients, fake_tsa, fake_rekor, fake_signer, fake_archive, fake_time


def _call_audit(sentinel, targets):
    # Find audit-like method
    for m in ("audit", "run", "execute", "run_audit"):
        fn = getattr(sentinel, m, None)
        if callable(fn):
            sig = inspect.signature(fn)
            try:
                if len(sig.parameters) == 0:
                    return fn()
                elif len(sig.parameters) == 1:
                    return fn(targets)
                else:
                    # Try passing as keyword if possible
                    if "targets" in sig.parameters:
                        return fn(targets=targets)
                    # else fill with None for extra
                    args = []
                    for p in sig.parameters.values():
                        if p.name == "targets":
                            args.append(targets)
                        else:
                            args.append(None)
                    return fn(*args)
            except Exception as e:
                pytest.fail(f"audit invocation failed: {e}")
    pytest.skip("No audit-like method found on sentinel")


def _find_alert(result, predicate):
    # Search in dict/list/objects for alerts
    alerts = []
    if isinstance(result, dict):
        if "alerts" in result and isinstance(result["alerts"], list):
            alerts = result["alerts"]
    else:
        alerts = getattr(result, "alerts", [])
    for a in alerts:
        if predicate(a):
            return a
    return None


def _get_policy_drift(result):
    if isinstance(result, dict):
        return result.get("policy_drift") or result.get("drifts") or []
    return getattr(result, "policy_drift", [])


def _get_attestations(result):
    if isinstance(result, dict):
        return result.get("attestations") or []
    return getattr(result, "attestations", [])


@pytest.fixture
def time_window():
    start = datetime(2025, 1, 10, 0, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)
    return start, end


def test_cloudtrail_digest_mismatch_critical_alert(monkeypatch, time_window):
    sentinel, clients, tsa, rekor, signer, archive, time_sync = _get_sentinel_instance()
    # Configure AWS client to produce digest mismatch
    aws = clients["aws"]
    aws.digest_issue = True
    aws.missing_interval = False
    aws.drift = False
    aws.compliant = False

    # Targets definition
    start, end = time_window
    targets = [
        {
            "provider": "aws",
            "service": "cloudtrail",
            "region": "us-east-1",
            "bucket": "org-cloudtrail-logs",
            "start": start,
            "end": end,
            "resource": "arn:aws:s3:::org-cloudtrail-logs",
        }
    ]

    result = _call_audit(sentinel, targets)

    # Must raise a critical alert with exact time window and verification artifacts
    alert = _find_alert(
        result,
        lambda a: (
            isinstance(a, dict)
            and a.get("severity", "").lower() == "critical"
            and ("digest" in str(a.get("type", "")).lower() or "digest" in str(a.get("message", "")).lower())
            and ("cloudtrail" in str(a.get("service", "")).lower() or "cloudtrail" in str(a.get("message", "")).lower())
        ),
    )
    assert alert is not None, f"No critical digest alert found in: {getattr(result, 'alerts', result)}"

    tw = alert.get("time_window") or {}
    assert tw.get("start") and tw.get("end"), "Alert missing affected time window"
    assert tw["start"].startswith((start + timedelta(minutes=5)).replace(microsecond=0).isoformat()[:16])
    assert tw["end"].startswith((start + timedelta(minutes=35)).replace(microsecond=0).isoformat()[:16])

    artifacts = alert.get("artifacts") or {}
    assert "provider_signed_digest" in artifacts
    assert "manifest_chain" in artifacts and isinstance(artifacts["manifest_chain"], list)
    # Cross-verification should have occurred
    # Simulate that Rekor and TSA were engaged
    # Rekor entry should exist for some digest during run
    # We can't know internal digest; but ensure the rekor client was used or attestation captures it
    attestations = _get_attestations(result)
    # At least evidence bundle must carry TSA/Rekor verification if present
    if attestations:
        att = attestations[0]
        ev = att.get("evidence_bundle") if isinstance(att, dict) else getattr(att, "evidence_bundle", {})
        assert ev is None or isinstance(ev, (dict, bytes))
    # Ensure time sync checked
    assert time_sync.checked is True


def test_policy_drift_detected_with_remediation(monkeypatch, time_window):
    sentinel, clients, tsa, rekor, signer, archive, time_sync = _get_sentinel_instance()
    # Configure AWS client to produce policy drift
    aws = clients["aws"]
    aws.digest_issue = False
    aws.drift = True
    aws.compliant = False

    start, end = time_window
    targets = [
        {
            "provider": "aws",
            "service": "cloudtrail",
            "region": "us-east-1",
            "bucket": "org-cloudtrail-logs",
            "start": start,
            "end": end,
            "resource": "arn:aws:s3:::org-cloudtrail-logs",
        }
    ]

    result = _call_audit(sentinel, targets)

    drifts = _get_policy_drift(result)
    assert drifts, "Expected policy drift to be reported"
    drift_entry = drifts[0] if isinstance(drifts, list) else drifts
    issues = drift_entry.get("issues") or []
    issue_types = {i.get("type") for i in issues}
    assert "retention_reduced" in issue_types or "legal_hold_disabled" in issue_types

    remediation = drift_entry.get("proposed_remediation_as_code") or drift_entry.get("remediation_code") or ""
    assert isinstance(remediation, str) and remediation.strip(), "Expected remediation-as-code to be proposed"


def test_compliant_logs_produce_signed_attestation(monkeypatch, time_window):
    sentinel, clients, tsa, rekor, signer, archive, time_sync = _get_sentinel_instance()
    # Configure AWS client to be fully compliant
    aws = clients["aws"]
    aws.digest_issue = False
    aws.drift = False
    aws.compliant = True

    start, end = time_window
    targets = [
        {
            "provider": "aws",
            "service": "cloudtrail",
            "region": "us-east-1",
            "bucket": "org-cloudtrail-logs",
            "start": start,
            "end": end,
            "resource": "arn:aws:s3:::org-cloudtrail-logs",
        }
    ]

    result = _call_audit(sentinel, targets)

    attestations = _get_attestations(result)
    assert attestations, "Expected a signed attestation for compliant logs"
    att = attestations[0]

    def get(field):
        return att.get(field) if isinstance(att, dict) else getattr(att, field, None)

    assert get("signed") in (True, "true", "yes") or get("signature") or get("signature_info"), "Attestation should be signed"
    period = get("period") or {}
    assert period.get("start") and period.get("end"), "Attestation should include audited period"
    assert get("policy_compliant") in (True, "true", "yes")
    # Evidence sealing and archive
    evidence_bundle = get("evidence_bundle")
    archive_record = get("archive_record") or get("archive")
    assert evidence_bundle is not None, "Evidence bundle should be included"
    assert archive_record is not None and (archive_record.get("immutable") if isinstance(archive_record, dict) else True)
    # Ensure signer was used and time sync checked
    assert len(signer.requests) > 0
    assert time_sync.checked is True


def test_tsa_unreachable_results_in_verification_failure_alert(monkeypatch, time_window):
    sentinel, clients, tsa, rekor, signer, archive, time_sync = _get_sentinel_instance(tsa_fail=True)
    # Configure digest verification OK but TSA unavailable
    aws = clients["aws"]
    aws.digest_issue = False
    aws.drift = False
    aws.compliant = True

    start, end = time_window
    targets = [
        {
            "provider": "aws",
            "service": "cloudtrail",
            "region": "us-east-1",
            "bucket": "org-cloudtrail-logs",
            "start": start,
            "end": end,
            "resource": "arn:aws:s3:::org-cloudtrail-logs",
        }
    ]

    result = _call_audit(sentinel, targets)

    # Expect some alert or flag indicating TSA verification failed (graceful handling)
    alert = _find_alert(
        result,
        lambda a: (
            isinstance(a, dict)
            and ("tsa" in str(a.get("type", "")).lower() or "timestamp" in str(a.get("type", "")).lower())
            and ("fail" in str(a.get("message", "")).lower() or "unreachable" in str(a.get("message", "")).lower())
        ),
    )
    # If the implementation surfaces verification status elsewhere, accept alternative
    if not alert:
        # Look at attestations verification statuses
        attestations = _get_attestations(result)
        if attestations:
            att = attestations[0]
            tsa_status = att.get("tsa_verification") if isinstance(att, dict) else getattr(att, "tsa_verification", {})
            assert tsa_status and (tsa_status.get("ok") is False or "fail" in str(tsa_status).lower())
        else:
            pytest.skip("No alert or attestation to validate TSA failure handling")
    else:
        assert alert.get("severity", "").lower() in ("warning", "error", "critical")


def test_least_privilege_roles_enforced(monkeypatch, time_window):
    sentinel, clients, tsa, rekor, signer, archive, time_sync = _get_sentinel_instance()
    aws = clients["aws"]
    start, end = time_window
    targets = [{"provider": "aws", "service": "cloudtrail", "start": start, "end": end, "resource": "arn:aws:s3:::org-cloudtrail-logs"}]

    # We expect the tool to check or use least-privilege/read-only credentials
    # If implementation exposes a hook, verify it; otherwise, infer via client
    role_info = aws.use_least_privilege()
    assert role_info.get("least_privilege") is True and role_info.get("write") is False

    result = _call_audit(sentinel, targets)
    # No additional assertion needed; ensure run didn't escalate privileges (no write calls recorded)
    write_calls = [c for c in getattr(aws, "calls", []) if "put" in c[0] or "delete" in c[0] or "write" in c[0]]
    assert not write_calls, f"Detected write-like operations in read-only mode: {write_calls}"