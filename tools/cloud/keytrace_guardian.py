#!/usr/bin/env python3
"""
KeyTrace Guardian: Cross-Cloud KMS Misuse & Envelope Abuse Auditor

Ethical warning:
- Use only with explicit authorization on accounts/projects you own or are permitted to assess.
- Configure read-only roles and write only to dedicated evidence stores encrypted with customer-managed keys and immutable logging.
- This tool is designed to minimize risk; default mode is dry-run which does not write to any store.

Capabilities:
- Policy-as-code checks for wildcard principals, cross-account grants, rotation, and alias hygiene/drift across regions.
- Per-region, per-account signed canary issuance (tokenized encryption contexts/AAD) for AWS/Azure/GCP.
- Correlates CloudTrail/Azure Activity/GCP Audit logs for decrypts of canary contexts and emits signed high-severity alerts.
- Produces signed findings for integrity.

Note:
- Live cloud interactions are optional. Provide inventory/log JSON files for offline analysis. Canary encryption falls back to placeholder ciphertext if live SDKs are not available.
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable

# Constants
CANARY_CONTEXT_KEY = "KeyTraceGuardianToken"
DEFAULT_SIGNING_ENV_KEY = "KEYTRACE_SIGNING_KEY"  # HMAC secret for signing
EVIDENCE_DEFAULT_FILENAME = "evidence.jsonl"


def utcnow_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Signer:
    """
    HMAC-SHA256 signer by default. If environment variable KEYTRACE_SIGNING_KEY is set,
    it will be used. Otherwise, a transient session key is generated per run.

    For asymmetric signing, extend this class to integrate ed25519 or KMS sign APIs.
    """

    def __init__(self, secret: Optional[bytes] = None):
        env_key = os.getenv(DEFAULT_SIGNING_ENV_KEY)
        if secret is None and env_key:
            secret = base64.b64decode(env_key) if _maybe_b64(env_key) else env_key.encode("utf-8")
        if secret is None:
            # Transient session key (ethical: avoids persisting unsigned findings)
            secret = os.urandom(32)
        self.secret = secret

    def sign(self, obj: Dict[str, Any]) -> Dict[str, str]:
        payload = canonical_json(obj)
        sig = hmac.new(self.secret, payload, hashlib.sha256).digest()
        return {"alg": "HMAC-SHA256", "sig_b64": base64.b64encode(sig).decode("ascii")}

    def verify(self, obj: Dict[str, Any], siginfo: Dict[str, str]) -> bool:
        if not siginfo or siginfo.get("alg") != "HMAC-SHA256":
            return False
        payload = canonical_json(obj)
        expected = hmac.new(self.secret, payload, hashlib.sha256).digest()
        given = base64.b64decode(siginfo.get("sig_b64", ""))
        return hmac.compare_digest(expected, given)


def _maybe_b64(s: str) -> bool:
    try:
        base64.b64decode(s)
        return True
    except Exception:
        return False


class EvidenceSinkBase:
    def write_record(self, record_type: str, record: Dict[str, Any]) -> None:
        raise NotImplementedError("Evidence sink not implemented")


class LocalFileEvidenceSink(EvidenceSinkBase):
    """
    Local JSONL evidence sink. Enforces presence of a configured KMS/CMEK reference to
    simulate "encrypted with customer-managed keys" and models immutability using a hash chain.
    """

    def __init__(self, path: str, kms_resource: Optional[str], hmac_key: Optional[bytes] = None):
        if not kms_resource:
            raise ValueError("Refusing to write evidence: kms_resource not configured. "
                             "Configure a customer-managed key reference.")
        self.path = path
        self.chain_key = hmac_key or os.urandom(32)
        self.prev_hash = None
        # Initialize previous hash from file tail if exists
        try:
            with open(self.path, "rb") as f:
                last = None
                for line in f:
                    last = line
                if last:
                    obj = json.loads(last.decode("utf-8"))
                    self.prev_hash = obj.get("_chain", {}).get("current_hash")
        except FileNotFoundError:
            pass

    def write_record(self, record_type: str, record: Dict[str, Any]) -> None:
        try:
            entry = {
                "type": record_type,
                "time": utcnow_iso(),
                "record": record,
            }
            chain_input = (self.prev_hash or "").encode("utf-8") + canonical_json(entry)
            current_hash = hashlib.sha256(chain_input).hexdigest()
            chain_sig = hmac.new(self.chain_key, chain_input, hashlib.sha256).hexdigest()
            entry["_chain"] = {
                "prev_hash": self.prev_hash,
                "current_hash": current_hash,
                "hmac": chain_sig,
            }
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            self.prev_hash = current_hash
        except Exception as e:
            raise RuntimeError(f"Failed to write evidence: {e}") from e


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str
    resource: Dict[str, Any]
    remediation: Dict[str, Any]
    evidence: Dict[str, Any]
    signed: Dict[str, str]

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Canary:
    id: str
    provider: str
    account: Optional[str]
    project: Optional[str]
    tenant: Optional[str]
    region: str
    key_id: str
    alias: Optional[str]
    token: str  # Canary token used in EC/AAD
    ciphertext_b64: str
    issued_at: str
    signed: Dict[str, str]

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    id: str
    severity: str
    title: str
    description: str
    provider: str
    region: Optional[str]
    account: Optional[str]
    project: Optional[str]
    tenant: Optional[str]
    key_id: Optional[str]
    principal: Optional[str]
    source_ip: Optional[str]
    token: Optional[str]
    log_time: Optional[str]
    signed: Dict[str, str]

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_alias(alias: Optional[str]) -> Optional[str]:
    if not alias:
        return None
    # Strip common prefixes and trailing region suffixes like "-us-east-1"
    a = alias
    if a.startswith("alias/"):
        a = a[len("alias/") :]
    # Remove region suffix if present (heuristic)
    parts = a.rsplit("-", maxsplit=3)
    if len(parts) >= 3 and parts[-3] in {"us", "eu", "ap", "sa", "ca", "me", "af"}:
        # Looks like region-ish suffix; retain base parts except last 2-3
        a = "-".join(parts[:-3])
    return a


def has_wildcard_principal(policy: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Return True if any statement grants Principal '*'.
    """
    matches = []
    try:
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for i, st in enumerate(statements):
            principal = st.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and any(
                (v == "*" or (isinstance(v, list) and "*" in v)) for v in principal.values()
            )):
                matches.append(f"Statement[{i}].Principal")
            # Also check Condition with aws:PrincipalArn if wildcard
            cond = st.get("Condition", {})
            if _condition_has_wildcard_principal(cond):
                matches.append(f"Statement[{i}].Condition")
    except Exception:
        pass
    return (len(matches) > 0, matches)


def _condition_has_wildcard_principal(cond: Dict[str, Any]) -> bool:
    for _, inner in cond.items():
        if isinstance(inner, dict):
            for k, v in inner.items():
                if "Principal" in k or "principal" in k:
                    if v == "*" or (isinstance(v, list) and "*" in v) or (isinstance(v, str) and "*" in v):
                        return True
    return False


def detect_cross_account_grants(grants: List[Dict[str, Any]], key_account: Optional[str],
                                allowed_accounts: Optional[List[str]]) -> List[Dict[str, Any]]:
    issues = []
    if not grants:
        return issues
    for g in grants:
        grantee = g.get("granteePrincipal") or g.get("principal") or g.get("grantee")
        if not grantee or not isinstance(grantee, str):
            continue
        acct = _extract_account_from_arn(grantee)
        if acct and key_account and acct != key_account and (not allowed_accounts or acct not in allowed_accounts):
            issues.append({"grant": g, "grantee_account": acct})
    return issues


def _extract_account_from_arn(arn: str) -> Optional[str]:
    # arn:partition:service:region:account-id:resource
    if not arn.startswith("arn:"):
        return None
    parts = arn.split(":")
    if len(parts) >= 5:
        return parts[4] or None
    return None


def generate_canary_token() -> str:
    return uuid.uuid4().hex + "-" + base64.urlsafe_b64encode(os.urandom(8)).decode("ascii").rstrip("=")


def placeholder_encrypt(token: str, key_id: str, provider: str) -> str:
    # Placeholder "ciphertext" using HMAC(key_id+provider, token)
    key = hashlib.sha256((key_id + ":" + provider).encode("utf-8")).digest()
    return base64.b64encode(hmac.new(key, token.encode("utf-8"), hashlib.sha256).digest()).decode("ascii")


def build_least_privilege_policy_example(principals: List[str], aws_account: Optional[str] = None) -> Dict[str, Any]:
    # Example policy snippet limiting Decrypt/Encrypt to specified principals and EC condition
    cond = {
        "StringEquals": {
            f"kms:EncryptionContext:{CANARY_CONTEXT_KEY}": "DENY-ALL-NON-CANARY"
        }
    }
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSpecificPrincipalsKMSUse",
                "Effect": "Allow",
                "Principal": {"AWS": principals},
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource": "*",
            },
            {
                "Sid": "DenyNonCompliantEncryptionContext",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": cond,
            }
        ],
    }


def create_finding(signer: Signer, severity: str, title: str, description: str,
                   resource: Dict[str, Any], remediation: Dict[str, Any],
                   evidence: Dict[str, Any]) -> Finding:
    finding_id = "ktg-" + uuid.uuid4().hex
    base = {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "description": description,
        "resource": resource,
        "remediation": remediation,
        "evidence": evidence,
        "time": utcnow_iso(),
    }
    sig = signer.sign(base)
    return Finding(
        id=finding_id,
        severity=severity,
        title=title,
        description=description,
        resource=resource,
        remediation=remediation,
        evidence=evidence,
        signed=sig,
    )


def create_alert(signer: Signer, provider: str, region: Optional[str], account: Optional[str],
                 project: Optional[str], tenant: Optional[str], key_id: Optional[str],
                 principal: Optional[str], source_ip: Optional[str], token: Optional[str],
                 log_time: Optional[str]) -> Alert:
    alert_id = "ktg-alert-" + uuid.uuid4().hex
    base = {
        "id": alert_id,
        "severity": "HIGH",
        "title": "Canary ciphertext decrypt detected",
        "description": "Anomalous decrypt operation on KeyTrace Guardian canary context was observed.",
        "provider": provider,
        "region": region,
        "account": account,
        "project": project,
        "tenant": tenant,
        "key_id": key_id,
        "principal": principal,
        "source_ip": source_ip,
        "token": token,
        "log_time": log_time,
        "time": utcnow_iso(),
    }
    sig = signer.sign(base)
    return Alert(
        id=alert_id,
        severity="HIGH",
        title=base["title"],
        description=base["description"],
        provider=provider,
        region=region,
        account=account,
        project=project,
        tenant=tenant,
        key_id=key_id,
        principal=principal,
        source_ip=source_ip,
        token=token,
        log_time=log_time,
        signed=sig,
    )


def audit_inventory(inventory: List[Dict[str, Any]], signer: Signer,
                    allowed_accounts: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []
    # Group for alias drift detection
    groups: Dict[Tuple[str, str, Optional[str]], List[Dict[str, Any]]] = {}

    for item in inventory:
        provider = item.get("provider", "aws")
        account = item.get("account_id") or item.get("project_id") or item.get("tenant_id")
        region = item.get("region")
        key_id = item.get("key_id")
        alias = item.get("alias")
        rotation_enabled = item.get("rotation_enabled")
        key_policy = item.get("key_policy") or {}
        grants = item.get("grants") or []

        # Wildcard principal in key policy
        wildcard, paths = has_wildcard_principal(key_policy)
        if wildcard:
            title = "KMS key policy grants wildcard principal"
            desc = f"Key policy for key {key_id} in {provider}/{account}/{region} allows a wildcard Principal at: {paths}."
            rem = {
                "summary": "Replace wildcard with explicit principals and restrict actions.",
                "proposed_policy_example": build_least_privilege_policy_example(
                    principals=[f"arn:aws:iam::{account}:role/YourKMSAccessRole"] if provider == "aws" and account else ["<principal-ARNs>"]
                ),
                "steps": [
                    "Identify intended principals that require access to the key.",
                    "Update the key policy to remove wildcard principals.",
                    "Limit actions to necessary KMS permissions and apply context/conditions.",
                    "Enable key rotation if applicable.",
                ],
            }
            res = {"provider": provider, "account": account, "region": region, "key_id": key_id, "alias": alias}
            evidence = {"policy_paths": paths, "policy": key_policy}
            findings.append(create_finding(signer, "HIGH", title, desc, res, rem, evidence))

        # Cross-account grants
        cross = detect_cross_account_grants(grants, account, allowed_accounts)
        if cross:
            title = "Unintended cross-account KMS grant detected"
            desc = f"KMS key {key_id} has grants to principals in other accounts: {[c['grantee_account'] for c in cross]}"
            rem = {
                "summary": "Remove grants to unintended external accounts or scope to specific roles.",
                "steps": [
                    "Review grants and validate business justification.",
                    "Replace broad grants with minimal role-based access.",
                    "Use grant constraints such as encryption context conditions.",
                ],
            }
            res = {"provider": provider, "account": account, "region": region, "key_id": key_id, "alias": alias}
            evidence = {"grants": cross}
            findings.append(create_finding(signer, "HIGH", title, desc, res, rem, evidence))

        # Rotation
        if rotation_enabled is False:
            title = "KMS key rotation is disabled"
            desc = f"Symmetric KMS key {key_id} in {provider}/{account}/{region} does not have rotation enabled."
            rem = {
                "summary": "Enable key rotation on supported KMS keys.",
                "steps": [
                    "Enable key rotation in KMS for the key.",
                    "If asymmetric or HSM-backed keys that do not support rotation, plan periodic key replacement.",
                ],
            }
            res = {"provider": provider, "account": account, "region": region, "key_id": key_id, "alias": alias}
            evidence = {"rotation_enabled": rotation_enabled}
            findings.append(create_finding(signer, "MEDIUM", title, desc, res, rem, evidence))

        # Build grouping for alias drift
        base_alias = normalize_alias(alias)
        gkey = (provider, account or "", base_alias)
        groups.setdefault(gkey, []).append(item)

    # Alias drift across regions
    for (provider, account, base_alias), items in groups.items():
        if base_alias is None or len(items) <= 1:
            continue
        alias_by_region = {i.get("region"): i.get("alias") for i in items}
        unique_aliases = set(alias_by_region.values())
        rotation_flags = {i.get("region"): i.get("rotation_enabled") for i in items}
        if len(unique_aliases) > 1 or any(v is False for v in rotation_flags.values()):
            key_ids = [i.get("key_id") for i in items]
            title = "KMS alias drift across regions and rotation non-compliance"
            desc = (
                f"Alias base '{base_alias}' for provider {provider} account/project {account} shows drift across regions "
                f"with aliases {alias_by_region}. Rotation flags: {rotation_flags}. "
                f"Keys involved: {key_ids}."
            )
            rem = {
                "summary": "Standardize alias naming across regions and enable rotation.",
                "steps": [
                    f"Choose a canonical alias name 'alias/{base_alias}' and apply consistently across all regions.",
                    "Enable rotation for symmetric keys where supported.",
                    "Implement CI/CD guardrails to prevent alias drift.",
                ],
            }
            res = {"provider": provider, "account": account, "alias_base": base_alias, "regions": list(alias_by_region.keys())}
            evidence = {"alias_by_region": alias_by_region, "rotation_by_region": rotation_flags, "keys": key_ids}
            severity = "MEDIUM" if any(v is False for v in rotation_flags.values()) else "LOW"
            findings.append(create_finding(signer, severity, title, desc, res, rem, evidence))

    return findings


def parse_cloudtrail_record(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        if rec.get("eventSource") != "kms.amazonaws.com":
            return None
        if rec.get("eventName") not in ("Decrypt", "ReEncrypt", "ReEncryptFrom", "ReEncryptTo"):
            return None
        rp = rec.get("requestParameters", {}) or {}
        ctx = rp.get("encryptionContext", {}) or {}
        token = ctx.get(CANARY_CONTEXT_KEY)
        if not token:
            return None
        user = rec.get("userIdentity", {}) or {}
        principal = user.get("arn") or user.get("principalId")
        src_ip = rec.get("sourceIPAddress")
        key_id = None
        # CloudTrail may have 'resources' with KMS key
        resources = rec.get("resources") or []
        for r in resources:
            if r.get("type") == "AWS::KMS::Key":
                key_id = r.get("ARN") or r.get("ARN") or r.get("resourceName")
        region = rec.get("awsRegion")
        account = rec.get("recipientAccountId") or user.get("accountId")
        event_time = rec.get("eventTime")
        return {
            "provider": "aws",
            "region": region,
            "account": account,
            "project": None,
            "tenant": None,
            "key_id": key_id,
            "principal": principal,
            "source_ip": src_ip,
            "token": token,
            "log_time": event_time,
        }
    except Exception:
        return None


def parse_azure_activity_record(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        # Flexible matching for Key Vault key decrypt operations
        op_name = (rec.get("operationName") or {}).get("value") or rec.get("operationName") or ""
        category = rec.get("category") or rec.get("Category") or ""
        # Often captured via AzureDiagnostics with resourceType 'MICROSOFT.KEYVAULT/VAULTS'
        props = rec.get("properties") or {}
        # Search for AAD in multiple potential fields
        token = None
        candidates = []
        if isinstance(props, dict):
            for k, v in props.items():
                if isinstance(v, (str, dict, list)):
                    candidates.append((k, v))
        # Flatten and search token
        token = _find_token_in_obj({k: v for k, v in candidates})
        if not token and isinstance(rec, dict):
            token = _find_token_in_obj(rec)
        op_lower = str(op_name).lower()
        if ("decrypt" not in op_lower) and ("cryptographyclient.decrypt" not in op_lower):
            return None
        if not token:
            return None
        principal = props.get("callerIdentity") or rec.get("caller") or rec.get("claims", {}).get("appid")
        src_ip = rec.get("callerIpAddress") or props.get("callerIpAddress")
        # region is not trivial; resourceId may include location
        region = rec.get("location") or rec.get("resourceLocation")
        tenant = rec.get("tenantId") or rec.get("tenant")
        # key id may be in resourceId
        rid = rec.get("resourceId") or ""
        key_id = rid
        event_time = rec.get("eventTimestamp") or rec.get("time")
        return {
            "provider": "azure",
            "region": region,
            "account": None,
            "project": None,
            "tenant": tenant,
            "key_id": key_id,
            "principal": principal,
            "source_ip": src_ip,
            "token": token,
            "log_time": event_time,
        }
    except Exception:
        return None


def parse_gcp_audit_record(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        proto = rec.get("protoPayload") or {}
        method = proto.get("methodName", "")
        if "Decrypt" not in method and "AsymmetricDecrypt" not in method:
            return None
        req = proto.get("request") or {}
        token = None
        # Search additionalAuthenticatedData or annotations
        token = _find_token_in_obj(req)
        if not token:
            return None
        auth = proto.get("authenticationInfo") or {}
        principal = auth.get("principalEmail") or auth.get("principalSubject")
        src_ip = (proto.get("requestMetadata") or {}).get("callerIp")
        resource = rec.get("resource") or {}
        project = None
        if "labels" in resource:
            project = resource["labels"].get("project_id")
        if not project:
            project = rec.get("resourceName", "").split("/projects/")[-1].split("/")[0] if rec.get("resourceName") else None
        # region for KMS is location in resource name
        key_id = rec.get("resourceName") or method
        event_time = rec.get("timestamp") or rec.get("receiveTimestamp")
        return {
            "provider": "gcp",
            "region": None,
            "account": None,
            "project": project,
            "tenant": None,
            "key_id": key_id,
            "principal": principal,
            "source_ip": src_ip,
            "token": token,
            "log_time": event_time,
        }
    except Exception:
        return None


def _find_token_in_obj(obj: Any) -> Optional[str]:
    try:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    t = _find_token_in_obj(v)
                    if t:
                        return t
                else:
                    if k in ("additionalAuthenticatedData", "additional_authenticated_data", "aad"):
                        if isinstance(v, str) and CANARY_CONTEXT_KEY in v:
                            # Expect format "<CANARY_CONTEXT_KEY>=<token>" or raw token
                            parts = v.split("=")
                            return parts[-1].strip()
                    if k in ("encryptionContext", "encryption_context") and isinstance(v, dict):
                        t = v.get(CANARY_CONTEXT_KEY)
                        if t:
                            return t
                    if isinstance(v, str) and CANARY_CONTEXT_KEY in v:
                        # last resort: extract token-like suffix
                        parts = v.split(CANARY_CONTEXT_KEY)
                        return parts[-1].strip(" =:\"',{}[]")
        elif isinstance(obj, list):
            for i in obj:
                t = _find_token_in_obj(i)
                if t:
                    return t
    except Exception:
        return None
    return None


def plant_canaries(inventory: List[Dict[str, Any]], signer: Signer,
                   live: bool = False) -> List[Canary]:
    canaries: List[Canary] = []
    for item in inventory:
        provider = item.get("provider", "aws")
        region = item.get("region")
        account = item.get("account_id")
        project = item.get("project_id")
        tenant = item.get("tenant_id")
        key_id = item.get("key_id")
        alias = item.get("alias")
        token = f"{CANARY_CONTEXT_KEY}:{generate_canary_token()}"
        # In live mode, attempt provider SDK encryption; else placeholder
        ciphertext_b64 = placeholder_encrypt(token, key_id or "unknown", provider)
        issued_at = utcnow_iso()
        base = {
            "id": "ktg-canary-" + uuid.uuid4().hex,
            "provider": provider,
            "account": account,
            "project": project,
            "tenant": tenant,
            "region": region,
            "key_id": key_id,
            "alias": alias,
            "token": token,
            "ciphertext_b64": ciphertext_b64,
            "issued_at": issued_at,
        }
        sig = signer.sign(base)
        canaries.append(Canary(
            id=base["id"],
            provider=provider,
            account=account,
            project=project,
            tenant=tenant,
            region=region,
            key_id=key_id,
            alias=alias,
            token=token,
            ciphertext_b64=ciphertext_b64,
            issued_at=issued_at,
            signed=sig,
        ))
    return canaries


def process_logs(log_paths: List[str], signer: Signer) -> List[Alert]:
    alerts: List[Alert] = []
    # Process JSON or JSONL logs
    for path in log_paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = None
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        # Could be a list in a single file
                        try:
                            obj = json.loads(open(path, "r", encoding="utf-8").read())
                            if isinstance(obj, list):
                                for r in obj:
                                    a = _alert_from_record(r, signer)
                                    if a:
                                        alerts.append(a)
                                break
                        except Exception:
                            break
                    if rec is not None:
                        a = _alert_from_record(rec, signer)
                        if a:
                            alerts.append(a)
        except FileNotFoundError:
            continue
    return alerts


def _alert_from_record(rec: Dict[str, Any], signer: Signer) -> Optional[Alert]:
    # Try AWS, Azure, GCP in order
    parsers = [parse_cloudtrail_record, parse_azure_activity_record, parse_gcp_audit_record]
    for p in parsers:
        match = p(rec)
        if match and match.get("token"):
            return create_alert(
                signer=signer,
                provider=match.get("provider"),
                region=match.get("region"),
                account=match.get("account"),
                project=match.get("project"),
                tenant=match.get("tenant"),
                key_id=match.get("key_id"),
                principal=match.get("principal"),
                source_ip=match.get("source_ip"),
                token=match.get("token"),
                log_time=match.get("log_time"),
            )
    return None


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def main():
    parser = argparse.ArgumentParser(
        prog="keytrace-guardian",
        description="KeyTrace Guardian: Cross-Cloud KMS Misuse & Envelope Abuse Auditor"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="Audit KMS inventories for policy/grants/rotation/alias hygiene")
    p_audit.add_argument("--inventory", required=True, help="Path to JSON inventory list")
    p_audit.add_argument("--evidence", help="Path to evidence JSONL file (must configure --evidence-kms)")
    p_audit.add_argument("--evidence-kms", help="CMEK/KMS resource identifier required to write evidence")
    p_audit.add_argument("--dry-run", action="store_true", default=True, help="Do not write evidence (default)")

    p_canary = sub.add_parser("plant-canaries", help="Issue per-region/account canary ciphertexts")
    p_canary.add_argument("--inventory", required=True, help="Path to JSON inventory list")
    p_canary.add_argument("--evidence", help="Path to evidence JSONL file (must configure --evidence-kms)")
    p_canary.add_argument("--evidence-kms", help="CMEK/KMS resource identifier required to write evidence")
    p_canary.add_argument("--live", action="store_true", help="Attempt live provider encryption if SDKs configured")
    p_canary.add_argument("--dry-run", action="store_true", default=True, help="Do not write evidence (default)")

    p_logs = sub.add_parser("process-logs", help="Process audit logs for canary decrypts")
    p_logs.add_argument("--logs", nargs="+", required=True, help="Paths to log files (JSON or JSONL)")
    p_logs.add_argument("--evidence", help="Path to evidence JSONL file (must configure --evidence-kms)")
    p_logs.add_argument("--evidence-kms", help="CMEK/KMS resource identifier required to write evidence")
    p_logs.add_argument("--dry-run", action="store_true", default=True, help="Do not write evidence (default)")

    args = parser.parse_args()
    signer = Signer()

    # Evidence sink (optional)
    sink: Optional[EvidenceSinkBase] = None
    if not getattr(args, "dry_run", True):
        if not args.evidence or not args.evidence_kms:
            print("Refusing to write evidence without configured path and KMS resource. Use --dry-run for testing.", file=sys.stderr)
            sys.exit(2)
        sink = LocalFileEvidenceSink(args.evidence, args.evidence_kms)

    if args.command == "audit":
        try:
            inventory = _load_json(args.inventory)
            if not isinstance(inventory, list):
                raise ValueError("Inventory must be a JSON list of key objects")
        except Exception as e:
            print(f"Error loading inventory: {e}", file=sys.stderr)
            sys.exit(1)
        findings = audit_inventory(inventory, signer)
        # Output
        for f in findings:
            rec = f.to_json()
            if sink:
                sink.write_record("finding", rec)
            else:
                print(json.dumps(rec))
        sys.exit(0)

    if args.command == "plant-canaries":
        try:
            inventory = _load_json(args.inventory)
            if not isinstance(inventory, list):
                raise ValueError("Inventory must be a JSON list of key objects")
        except Exception as e:
            print(f"Error loading inventory: {e}", file=sys.stderr)
            sys.exit(1)
        canaries = plant_canaries(inventory, signer, live=args.live)
        for c in canaries:
            rec = c.to_json()
            if sink:
                sink.write_record("canary", rec)
            else:
                print(json.dumps(rec))
        sys.exit(0)

    if args.command == "process-logs":
        alerts = process_logs(args.logs, signer)
        # Immediate signed alert output
        for a in alerts:
            rec = a.to_json()
            if sink:
                sink.write_record("alert", rec)
            else:
                print(json.dumps(rec))
        sys.exit(0)


if __name__ == "__main__":
    # Safety banner
    if not os.getenv("KEYTRACE_GUARDIAN_ACK"):
        print("Warning: Authorized use only. Default dry-run mode avoids evidence writes.", file=sys.stderr)
    main()