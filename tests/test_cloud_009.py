import json
import hashlib
import time
import pytest

from tools.cloud.keytrace_guardian import KeyTraceGuardian


class FakeSigner:
    def sign(self, payload: dict) -> dict:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = hashlib.sha256(data).hexdigest()
        return {
            "algorithm": "SHA256",
            "signature": f"sig:{sig}",
            "signed_at": int(time.time()),
        }


class FakeEvidenceWriter:
    def __init__(self, cmk_arn="arn:aws:kms:us-east-1:111111111111:key/abc", destination="evidence://guardian/alerts"):
        self.records = []
        self.cmk_arn = cmk_arn
        self.destination = destination

    def write(self, record: dict) -> None:
        # Enforce dedicated evidence store destination and encryption with CMK and immutability flags
        assert isinstance(record, dict)
        assert record.get("destination", "").startswith("evidence://")
        assert record.get("immutable") is True
        enc = record.get("encryption") or {}
        assert enc.get("cmk_arn") == self.cmk_arn
        self.records.append(record)


@pytest.fixture
def signer():
    return FakeSigner()


@pytest.fixture
def evidence_writer():
    return FakeEvidenceWriter()


@pytest.fixture
def guardian(signer, evidence_writer):
    # Allow dependency injection; if implementation requires different signature,
    # adapt by providing kwargs expected by KeyTraceGuardian.
    try:
        return KeyTraceGuardian(evidence_writer=evidence_writer, signer=signer)
    except TypeError:
        # Fallback to no-arg constructor then set attributes if available
        g = KeyTraceGuardian()
        if hasattr(g, "evidence_writer"):
            g.evidence_writer = evidence_writer
        if hasattr(g, "signer"):
            g.signer = signer
        return g


def make_aws_decrypt_canary_event(
    principal="arn:aws:iam::111111111111:user/test",
    ip="127.0.0.1",
    account_id="111111111111",
    region="us-east-1",
    key_arn="arn:aws:kms:us-east-1:111111111111:key/abc",
    canary_id="canary-123",
):
    return {
        "provider": "aws",
        "eventSource": "kms.amazonaws.com",
        "eventName": "Decrypt",
        "awsRegion": region,
        "recipientAccountId": account_id,
        "userIdentity": {"arn": principal, "accountId": account_id, "type": "IAMUser"},
        "sourceIPAddress": ip,
        "requestParameters": {
            "encryptionContext": {
                "KeyTraceGuardianCanary": "true",
                "CanaryId": canary_id,
                "KeyArn": key_arn,
            }
        },
        "responseElements": {},
        "resources": [key_arn],
    }


def make_azure_decrypt_canary_event(
    principal="aad:principal-123",
    ip="127.0.0.1",
    subscription_id="sub-1111",
    region="eastus",
    key_id="/subscriptions/sub-1111/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v/keys/k/vers",
    canary_id="canary-az-123",
):
    return {
        "provider": "azure",
        "operationName": "MICROSOFT.KEYVAULT/KEYS/DECRYPT/action",
        "resourceId": key_id,
        "resourceGroupName": "rg",
        "subscriptionId": subscription_id,
        "category": "AuditEvent",
        "caller": principal,
        "identity": {"claims": {"ipaddr": ip}},
        "location": region,
        "properties": {
            "additionalProperties": {
                "KeyTraceGuardianCanary": "true",
                "CanaryId": canary_id,
                "KeyId": key_id,
            }
        },
    }


def make_gcp_decrypt_canary_event(
    principal="user@project.iam.gserviceaccount.com",
    ip="127.0.0.1",
    project_id="proj-1111",
    location="us-central1",
    key_name="projects/proj-1111/locations/us-central1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    canary_id="canary-gcp-123",
):
    return {
        "provider": "gcp",
        "logName": f"projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "kms_key", "labels": {"location": location, "project_id": project_id}},
        "protoPayload": {
            "serviceName": "cloudkms.googleapis.com",
            "methodName": "Decrypt",
            "resourceName": key_name,
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": ip},
            "request": {
                "name": key_name,
                "additionalAuthenticatedData": {
                    "KeyTraceGuardianCanary": "true",
                    "CanaryId": canary_id,
                },
            },
        },
    }


def test_wildcard_principal_policy_flagged_high_severity_with_remediation(guardian):
    account_id = "111111111111"
    region = "us-west-2"
    key_arn = "arn:aws:kms:us-west-2:111111111111:key/xyz"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAllWild",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }
    findings = guardian.check_key_policy(policy_doc, account_id, region, key_arn)
    assert isinstance(findings, list)
    assert any(f.get("severity") in ("HIGH", "CRITICAL") for f in findings)
    high = next(f for f in findings if f.get("severity") in ("HIGH", "CRITICAL"))
    assert "wildcard" in json.dumps(high).lower()
    # proposed least-privilege remediation plan present
    remediation = high.get("remediation") or {}
    rem_text = json.dumps(remediation).lower()
    assert "least" in rem_text and "privilege" in rem_text
    assert any(
        kw in rem_text
        for kw in [
            "remove wildcard",
            "restrict principal",
            "narrow principal",
            "use grants",
            "specific arn",
        ]
    )


@pytest.mark.parametrize(
    "event_maker",
    [make_aws_decrypt_canary_event, make_azure_decrypt_canary_event, make_gcp_decrypt_canary_event],
)
def test_canary_decrypt_event_generates_signed_alert_with_principal_and_ip_and_evidence(guardian, evidence_writer, signer, event_maker):
    event = event_maker()
    alert = guardian.handle_audit_event(event)
    # Immediate signed alert with calling principal and source IP
    assert isinstance(alert, dict)
    assert alert.get("type") in ("DECRYPT_CANARY_USED", "CANARY_DECRYPT")
    assert alert.get("principal") or alert.get("caller") or alert.get("principal_email")
    assert alert.get("source_ip") in ("127.0.0.1", "::1", "localhost")
    sig = alert.get("signature")
    assert isinstance(sig, dict) and "signature" in sig and sig["signature"].startswith("sig:")
    # Evidence written to immutable CMK-encrypted store
    assert len(evidence_writer.records) >= 1
    last = evidence_writer.records[-1]
    assert last["destination"].startswith("evidence://")
    assert last["immutable"] is True
    assert last["encryption"]["cmk_arn"] == evidence_writer.cmk_arn


def test_non_rotating_key_with_mismatched_alias_detected_with_drift_and_remediation(guardian):
    keys_by_region = {
        "us-east-1": {
            "key_id": "abc",
            "arn": "arn:aws:kms:us-east-1:111111111111:key/abc",
            "rotation_enabled": False,
            "last_rotated_days": 730,
            "alias": "alias/production",
        },
        "us-west-2": {
            "key_id": "def",
            "arn": "arn:aws:kms:us-west-2:111111111111:key/def",
            "rotation_enabled": True,
            "last_rotated_days": 45,
            "alias": "alias/prod",
        },
    }
    drifts = guardian.assess_rotation_and_alias_drift(keys_by_region)
    assert isinstance(drifts, list)
    assert drifts, "Expected at least one drift finding"
    text = json.dumps(drifts).lower()
    assert "rotation" in text and ("disabled" in text or "non-rotating" in text or "not enabled" in text)
    assert "alias" in text and ("mismatch" in text or "inconsistent" in text or "hygiene" in text)
    remediation = json.dumps(drifts[0].get("remediation") or {}).lower()
    assert any(kw in remediation for kw in ["enable rotation", "turn on rotation", "rotate annually", "90 days"])
    assert any(kw in remediation for kw in ["align aliases", "standardize alias", "consistent alias"])


def test_policy_malformed_is_handled_gracefully(guardian):
    # Missing Statement array and other fields
    bad_policy = {"Version": "2012-10-17", "Statement": "not-a-list"}
    findings = guardian.check_key_policy(bad_policy, "111111111111", "us-east-1", "arn:aws:kms:us-east-1:111111111111:key/abc")
    assert isinstance(findings, list)
    # Should not raise, may generate an informative finding or none
    assert all(isinstance(f, dict) for f in findings)


def test_non_canary_decrypt_event_produces_no_alert(guardian, evidence_writer):
    # An AWS decrypt event without canary markers should not alert
    event = {
        "provider": "aws",
        "eventSource": "kms.amazonaws.com",
        "eventName": "Decrypt",
        "awsRegion": "us-east-1",
        "recipientAccountId": "111111111111",
        "userIdentity": {"arn": "arn:aws:iam::111111111111:user/test"},
        "sourceIPAddress": "127.0.0.1",
        "requestParameters": {"encryptionContext": {"App": "prod"}},
        "resources": ["arn:aws:kms:us-east-1:111111111111:key/abc"],
    }
    alert = guardian.handle_audit_event(event)
    assert alert is None
    # And should not write any evidence for non-canary usage
    assert all("KeyTraceGuardianCanary" not in json.dumps(r) for r in evidence_writer.records)


def test_handle_event_missing_source_ip_is_tolerated(guardian):
    event = make_aws_decrypt_canary_event(ip=None)
    alert = guardian.handle_audit_event(event)
    assert isinstance(alert, dict)
    assert "source_ip" in alert
    # Accept None/unknown
    assert alert["source_ip"] in (None, "unknown", "")


def test_detects_unintended_cross_account_access_in_policy(guardian):
    account_id = "111111111111"
    region = "us-east-1"
    key_arn = "arn:aws:kms:us-east-1:111111111111:key/abc"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CrossAccount",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": ["kms:Decrypt", "kms:Encrypt"],
                "Resource": "*",
            }
        ],
    }
    findings = guardian.check_key_policy(policy_doc, account_id, region, key_arn)
    assert any("cross-account" in json.dumps(f).lower() for f in findings)
    # Severity at least medium
    assert any(f.get("severity") in ("HIGH", "CRITICAL", "MEDIUM") for f in findings)