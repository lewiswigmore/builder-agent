#!/usr/bin/env python3
# HoneyCred Cloud Tripwire
# CATEGORY: cloud
# DESCRIPTION: Deploys and rotates scoped honeytokens across AWS/Azure/GCP, monitors for any usage via cloud logs,
# auto-revokes credentials, quarantines implicated workloads, and emits signed, tamper-evident, forensically sound alerts.
#
# IMPORTANT ETHICAL WARNING:
# This tool is intended solely for authorized testing and defense by owners of the target cloud accounts and resources.
# Do not deploy or operate it against accounts or resources you do not own or have explicit written permission to test.
# Misuse may be illegal and unethical. Always follow organizational policies and legal requirements.

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

# Optional imports for clouds
try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None
    ClientError = Exception

# Globals
DEFAULT_DIR = os.path.expanduser("~/.honeycred_tripwire")
ALERTS_FILE = "alerts.jsonl"
STATE_FILE = "state.json"
SECRET_FILE = "secret.key"

# Critical write actions to explicitly deny in AWS
AWS_DENY_ACTIONS = [
    "*:Create*", "*:Put*", "*:Update*", "*:Delete*", "*:Modify*", "iam:*", "kms:ScheduleKeyDeletion",
    "ec2:TerminateInstances", "ec2:StopInstances", "ec2:RebootInstances", "ec2:DeleteSecurityGroup",
    "s3:PutBucketPolicy", "s3:DeleteBucket", "s3:PutObject", "s3:DeleteObject",
    "rds:DeleteDBInstance", "lambda:DeleteFunction", "cloudtrail:StopLogging",
]

# AWS Managed read-only policy ARN
AWS_READONLY_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"

# Quarantine tag key
QUARANTINE_TAG_KEY = "honeycred-quarantine"
QUARANTINE_TAG_VALUE = "true"

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def try_ntp_time(timeout=2.0) -> Tuple[dt.datetime, str]:
    # Minimal SNTP query to pool.ntp.org (not full validation). Falls back to system time.
    addr = ("pool.ntp.org", 123)
    msg = b"\x1b" + 47 * b"\0"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, addr)
        _msg, _ = s.recvfrom(1024)
        if len(_msg) >= 48:
            # Transmit Timestamp starts at byte 40
            t = _msg[40:48]
            # Convert NTP time (seconds since 1900) to UNIX epoch
            NTP_DELTA = 2208988800
            secs = int.from_bytes(t[0:4], "big") - NTP_DELTA
            frac = int.from_bytes(t[4:8], "big")
            ts = secs + frac / 2**32
            dt_utc = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
            return dt_utc, "ntp"
    except Exception:
        pass
    return utc_now(), "system"


class HmacSigner:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self.key_path = os.path.join(base_dir, SECRET_FILE)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                return f.read()
        key = secrets.token_bytes(32)
        with open(self.key_path, "wb") as f:
            f.write(key)
        os.chmod(self.key_path, 0o600)
        return key

    def sign(self, data: bytes) -> str:
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()[:16]


class TamperEvidentStore:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self.signer = HmacSigner(base_dir)
        self.alerts_path = os.path.join(base_dir, ALERTS_FILE)
        self._lock = threading.Lock()
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not os.path.exists(self.alerts_path):
            return "0" * 64
        last = "0" * 64
        try:
            with open(self.alerts_path, "r", encoding="utf-8") as f:
                for line in f:
                    rec = json.loads(line)
                    last = rec.get("record_hash", last)
        except Exception:
            pass
        return last

    def append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            serialized = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            chain_input = (self._last_hash + hashlib.sha256(serialized).hexdigest()).encode()
            record_hash = hashlib.sha256(chain_input).hexdigest()
            signature = self.signer.sign(record_hash.encode())
            envelope = {
                "time": event.get("time"),
                "event": event,
                "record_hash": record_hash,
                "prev_hash": self._last_hash,
                "signature": signature,
                "sig_scheme": "HMAC-SHA256",
                "key_fingerprint": self.signer.fingerprint(),
            }
            with open(self.alerts_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(envelope, sort_keys=True) + "\n")
            self._last_hash = record_hash
            return envelope

    def verify(self) -> bool:
        last = "0" * 64
        try:
            with open(self.alerts_path, "r", encoding="utf-8") as f:
                for line in f:
                    env = json.loads(line)
                    if env.get("prev_hash") != last:
                        return False
                    event = env["event"]
                    serialized = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
                    chain_input = (last + hashlib.sha256(serialized).hexdigest()).encode()
                    record_hash = hashlib.sha256(chain_input).hexdigest()
                    if record_hash != env.get("record_hash"):
                        return False
                    sig_ok = hmac.compare_digest(
                        env.get("signature", ""), self.signer.sign(record_hash.encode())
                    )
                    if not sig_ok:
                        return False
                    last = record_hash
            return True
        except FileNotFoundError:
            return True
        except Exception:
            return False


class StateStore:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self.path = os.path.join(base_dir, STATE_FILE)
        self._lock = threading.Lock()
        self._state = self._load()

    def _load(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return {"tokens": {}, "quarantined": {}, "audit": []}
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save(self):
        with self._lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)

    def add_token(self, provider: str, token_id: str, meta: Dict[str, Any]):
        with self._lock:
            self._state["tokens"].setdefault(provider, {})[token_id] = meta
            self._state["audit"].append({"time": utc_now().isoformat(), "action": "add_token", "provider": provider, "token_id": token_id})
            self.save()

    def get_tokens(self, provider: str) -> Dict[str, Any]:
        return self._state.get("tokens", {}).get(provider, {})

    def get_token(self, provider: str, token_id: str) -> Optional[Dict[str, Any]]:
        return self.get_tokens(provider).get(token_id)

    def mark_revoked(self, provider: str, token_id: str):
        with self._lock:
            tok = self.get_token(provider, token_id)
            if tok:
                tok["revoked"] = True
                tok["revoked_at"] = utc_now().isoformat()
                self._state["audit"].append({"time": utc_now().isoformat(), "action": "revoke", "provider": provider, "token_id": token_id})
                self.save()

    def mark_quarantined(self, provider: str, resource_id: str):
        with self._lock:
            self._state["quarantined"].setdefault(provider, {})[resource_id] = {"time": utc_now().isoformat()}
            self._state["audit"].append({"time": utc_now().isoformat(), "action": "quarantine", "provider": provider, "resource_id": resource_id})
            self.save()


class ProviderBase:
    def __init__(self, state: StateStore, base_dir: str, dry_run: bool = False):
        self.state = state
        self.base_dir = base_dir
        self.dry_run = dry_run

    def deploy_honeytoken(self, name: str, tags: Dict[str, str]) -> Dict[str, Any]:
        raise NotImplementedError

    def rotate_honeytoken(self, token_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def enforce_least_privilege(self, token_meta: Dict[str, Any]) -> None:
        raise NotImplementedError

    def monitor_events(self, since: dt.datetime) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def revoke_credentials(self, token_id: str, token_meta: Dict[str, Any]) -> None:
        raise NotImplementedError

    def quarantine(self, context: Dict[str, Any]) -> List[str]:
        raise NotImplementedError

    def name(self) -> str:
        raise NotImplementedError


class AWSProvider(ProviderBase):
    def __init__(self, state: StateStore, base_dir: str, dry_run: bool = False, region: Optional[str] = None):
        super().__init__(state, base_dir, dry_run)
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        if boto3:
            self.iam = boto3.client("iam")
            self.cloudtrail = boto3.client("cloudtrail", region_name=self.region)
            self.ec2 = boto3.client("ec2", region_name=self.region)
            self.sts = boto3.client("sts")
        else:
            self.iam = None
            self.cloudtrail = None
            self.ec2 = None
            self.sts = None

    def name(self) -> str:
        return "aws"

    def _mk_user_name(self, name: str) -> str:
        # IAM user name constraints: alphanumeric with plus, =, , . @ - acceptable; limit 64.
        suffix = secrets.token_hex(3)
        base = "".join(c for c in name if c.isalnum() or c in "+=,.@-")[:50]
        return f"{base}-honey-{suffix}"

    def deploy_honeytoken(self, name: str, tags: Dict[str, str]) -> Dict[str, Any]:
        assert self.iam or self.dry_run, "boto3 required for AWS operations"
        user_name = self._mk_user_name(name)
        policy_name = "ExplicitDenyCriticalWrites"
        tags = dict(tags)
        tags.update({"honeytoken": "true", "managed-by": "honeycred-tripwire"})
        try:
            if not self.dry_run:
                self.iam.create_user(UserName=user_name, Tags=[{"Key": k, "Value": v} for k, v in tags.items()])
                self.iam.attach_user_policy(UserName=user_name, PolicyArn=AWS_READONLY_POLICY_ARN)
                deny_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Deny", "Action": AWS_DENY_ACTIONS, "Resource": "*"}
                    ],
                }
                self.iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy))
                key = self.iam.create_access_key(UserName=user_name)["AccessKey"]
                token_id = key["AccessKeyId"]
                meta = {
                    "user_name": user_name,
                    "access_key_id": key["AccessKeyId"],
                    "created": utc_now().isoformat(),
                    "arn": self.iam.get_user(UserName=user_name)["User"]["Arn"],
                    "type": "iam_user_access_key",
                    "tags": tags,
                    "policy_name": policy_name,
                    "region": self.region,
                }
                # Store secret safely in local state for testing only (never store in production)
                meta["secret_access_key_b64"] = base64.b64encode(key["SecretAccessKey"].encode()).decode()
            else:
                token_id = "AKIA" + secrets.token_hex(10).upper()
                meta = {
                    "user_name": user_name,
                    "access_key_id": token_id,
                    "created": utc_now().isoformat(),
                    "arn": f"arn:aws:iam::123456789012:user/{user_name}",
                    "type": "iam_user_access_key",
                    "tags": tags,
                    "policy_name": policy_name,
                    "region": self.region,
                }
            self.state.add_token(self.name(), token_id, meta)
            logging.info("Deployed AWS honeytoken user=%s access_key=%s", user_name, token_id)
            return {"provider": self.name(), "token_id": token_id, "meta": meta}
        except ClientError as e:
            logging.error("AWS deploy failed: %s", e)
            raise

    def rotate_honeytoken(self, token_id: str) -> Dict[str, Any]:
        meta = self.state.get_token(self.name(), token_id)
        assert meta, "Unknown token"
        user = meta["user_name"]
        assert self.iam or self.dry_run, "boto3 required for AWS operations"
        try:
            if not self.dry_run:
                # Create new key
                new_key = self.iam.create_access_key(UserName=user)["AccessKey"]
                # Deactivate old key for safety
                try:
                    self.iam.update_access_key(UserName=user, AccessKeyId=token_id, Status="Inactive")
                except ClientError:
                    pass
                new_id = new_key["AccessKeyId"]
                meta["rotated_from"] = token_id
                meta["access_key_id"] = new_id
                meta["rotated_at"] = utc_now().isoformat()
                meta["secret_access_key_b64"] = base64.b64encode(new_key["SecretAccessKey"].encode()).decode()
                self.state.add_token(self.name(), new_id, meta.copy())
                self.state.mark_revoked(self.name(), token_id)
                logging.info("Rotated AWS honeytoken old=%s new=%s", token_id, new_id)
                return {"old": token_id, "new": new_id, "meta": meta}
            else:
                new_id = "AKIA" + secrets.token_hex(10).upper()
                meta["rotated_from"] = token_id
                meta["access_key_id"] = new_id
                meta["rotated_at"] = utc_now().isoformat()
                self.state.add_token(self.name(), new_id, meta.copy())
                self.state.mark_revoked(self.name(), token_id)
                logging.info("Dry-run rotated AWS honeytoken old=%s new=%s", token_id, new_id)
                return {"old": token_id, "new": new_id, "meta": meta}
        except ClientError as e:
            logging.error("AWS rotate failed: %s", e)
            raise

    def enforce_least_privilege(self, token_meta: Dict[str, Any]) -> None:
        # Ensure RO policy and explicit deny attached
        assert self.iam or self.dry_run, "boto3 required for AWS operations"
        user = token_meta["user_name"]
        try:
            if not self.dry_run:
                attached = self.iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", [])
                if not any(p["PolicyArn"] == AWS_READONLY_POLICY_ARN for p in attached):
                    self.iam.attach_user_policy(UserName=user, PolicyArn=AWS_READONLY_POLICY_ARN)
                # Re-apply deny inline
                deny_policy = {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": AWS_DENY_ACTIONS, "Resource": "*"}],
                }
                self.iam.put_user_policy(UserName=user, PolicyName=token_meta.get("policy_name", "ExplicitDenyCriticalWrites"), PolicyDocument=json.dumps(deny_policy))
            logging.info("Least privilege enforced for %s", user)
        except ClientError as e:
            logging.error("AWS enforce least privilege failed: %s", e)
            raise

    def monitor_events(self, since: dt.datetime) -> List[Dict[str, Any]]:
        assert self.cloudtrail or self.dry_run, "boto3 required for AWS operations"
        events: List[Dict[str, Any]] = []
        tokens = self.state.get_tokens(self.name())
        if not tokens:
            return events
        try:
            if self.dry_run:
                return events
            for token_id, meta in tokens.items():
                if meta.get("revoked"):
                    continue
                lookups = [
                    {"AttributeKey": "AccessKeyId", "AttributeValue": meta["access_key_id"]},
                    {"AttributeKey": "Username", "AttributeValue": meta["user_name"]},
                ]
                for la in lookups:
                    resp = self.cloudtrail.lookup_events(LookupAttributes=[la], StartTime=since)
                    for e in resp.get("Events", []):
                        try:
                            detail = json.loads(e["CloudTrailEvent"])
                        except Exception:
                            detail = {}
                        events.append({
                            "provider": "aws",
                            "token_id": token_id,
                            "access_key_id": meta["access_key_id"],
                            "user_name": meta["user_name"],
                            "event_time": e.get("EventTime", utc_now()).astimezone(dt.timezone.utc).isoformat(),
                            "event_name": e.get("EventName"),
                            "source_ip": detail.get("sourceIPAddress") or e.get("SourceIPAddress"),
                            "caller": detail.get("userIdentity", {}).get("arn") or e.get("Username"),
                            "resources": e.get("Resources", []),
                            "raw": detail,
                        })
        except ClientError as e:
            logging.error("AWS monitor failed: %s", e)
        return events

    def revoke_credentials(self, token_id: str, token_meta: Dict[str, Any]) -> None:
        assert self.iam or self.dry_run, "boto3 required for AWS operations"
        user = token_meta["user_name"]
        akid = token_meta["access_key_id"]
        try:
            if not self.dry_run:
                # Idempotent: set status to Inactive; if already Inactive or not found, ignore.
                try:
                    self.iam.update_access_key(UserName=user, AccessKeyId=akid, Status="Inactive")
                except ClientError as ce:
                    if ce.response.get("Error", {}).get("Code") not in ("NoSuchEntity",):
                        raise
            self.state.mark_revoked(self.name(), token_id)
            logging.info("Revoked (deactivated) access key for %s (%s)", user, akid)
        except ClientError as e:
            logging.error("AWS revoke failed: %s", e)
            raise

    def _tag_ec2_instance(self, instance_id: str):
        assert self.ec2 or self.dry_run, "boto3 required for AWS operations"
        try:
            if not self.dry_run:
                self.ec2.create_tags(Resources=[instance_id], Tags=[{"Key": QUARANTINE_TAG_KEY, "Value": QUARANTINE_TAG_VALUE}])
            self.state.mark_quarantined(self.name(), instance_id)
            logging.info("Tagged EC2 instance %s as quarantined", instance_id)
        except ClientError as e:
            logging.error("AWS quarantine tag failed: %s", e)

    def quarantine(self, context: Dict[str, Any]) -> List[str]:
        # Non-destructive quarantine by tagging instances; optionally could adjust SG in future.
        quarantined: List[str] = []
        res = context.get("resources") or []
        for r in res:
            if isinstance(r, dict):
                if r.get("ResourceType") == "AWS::EC2::Instance":
                    iid = r.get("ResourceName")
                    if iid:
                        self._tag_ec2_instance(iid)
                        quarantined.append(iid)
        return quarantined


class AzureProvider(ProviderBase):
    def name(self) -> str:
        return "azure"

    def deploy_honeytoken(self, name: str, tags: Dict[str, str]) -> Dict[str, Any]:
        # Placeholder implementation: requires azure-* SDKs; ensure only dry-run unless user extends.
        if not self.dry_run:
            raise NotImplementedError("Azure deployment requires azure SDK and proper configuration.")
        token_id = "azure-sp-" + secrets.token_hex(8)
        meta = {"appId": token_id, "displayName": f"{name}-honey", "role": "Reader", "tags": tags, "type": "service_principal"}
        self.state.add_token(self.name(), token_id, meta)
        logging.info("Dry-run: deployed Azure honeytoken %s", token_id)
        return {"provider": self.name(), "token_id": token_id, "meta": meta}

    def rotate_honeytoken(self, token_id: str) -> Dict[str, Any]:
        if not self.dry_run:
            raise NotImplementedError("Azure rotation requires azure SDK.")
        new_id = "azure-sp-" + secrets.token_hex(8)
        meta = {"rotated_from": token_id, "appId": new_id}
        self.state.add_token(self.name(), new_id, meta)
        self.state.mark_revoked(self.name(), token_id)
        logging.info("Dry-run: rotated Azure honeytoken %s -> %s", token_id, new_id)
        return {"old": token_id, "new": new_id, "meta": meta}

    def enforce_least_privilege(self, token_meta: Dict[str, Any]) -> None:
        logging.info("Azure least-privilege: ensure Reader role only (dry-run or requires SDK)")

    def monitor_events(self, since: dt.datetime) -> List[Dict[str, Any]]:
        logging.warning("Azure monitor not implemented without SDK; returning empty")
        return []

    def revoke_credentials(self, token_id: str, token_meta: Dict[str, Any]) -> None:
        if not self.dry_run:
            raise NotImplementedError("Azure revoke requires azure SDK.")
        self.state.mark_revoked(self.name(), token_id)
        logging.info("Dry-run: revoked Azure honeytoken %s", token_id)

    def quarantine(self, context: Dict[str, Any]) -> List[str]:
        logging.info("Azure quarantine not implemented; no-op")
        return []


class GCPProvider(ProviderBase):
    def name(self) -> str:
        return "gcp"

    def deploy_honeytoken(self, name: str, tags: Dict[str, str]) -> Dict[str, Any]:
        if not self.dry_run:
            raise NotImplementedError("GCP deployment requires google-cloud SDK.")
        token_id = "gcp-sa-" + secrets.token_hex(8)
        meta = {"email": f"{name}-honey@project.iam.gserviceaccount.com", "unique_id": token_id, "role": "roles/viewer", "tags": tags, "type": "service_account"}
        self.state.add_token(self.name(), token_id, meta)
        logging.info("Dry-run: deployed GCP honeytoken %s", token_id)
        return {"provider": self.name(), "token_id": token_id, "meta": meta}

    def rotate_honeytoken(self, token_id: str) -> Dict[str, Any]:
        if not self.dry_run:
            raise NotImplementedError("GCP rotation requires google-cloud SDK.")
        new_id = "gcp-sa-" + secrets.token_hex(8)
        meta = {"rotated_from": token_id, "unique_id": new_id}
        self.state.add_token(self.name(), new_id, meta)
        self.state.mark_revoked(self.name(), token_id)
        logging.info("Dry-run: rotated GCP honeytoken %s -> %s", token_id, new_id)
        return {"old": token_id, "new": new_id, "meta": meta}

    def enforce_least_privilege(self, token_meta: Dict[str, Any]) -> None:
        logging.info("GCP least-privilege: ensure roles/viewer only (dry-run or requires SDK)")

    def monitor_events(self, since: dt.datetime) -> List[Dict[str, Any]]:
        logging.warning("GCP monitor not implemented without SDK; returning empty")
        return []

    def revoke_credentials(self, token_id: str, token_meta: Dict[str, Any]) -> None:
        if not self.dry_run:
            raise NotImplementedError("GCP revoke requires google-cloud SDK.")
        self.state.mark_revoked(self.name(), token_id)
        logging.info("Dry-run: revoked GCP honeytoken %s", token_id)

    def quarantine(self, context: Dict[str, Any]) -> List[str]:
        logging.info("GCP quarantine not implemented; no-op")
        return []


class AlertEmitter:
    def __init__(self, store: TamperEvidentStore):
        self.store = store

    def emit(self, provider: str, event: Dict[str, Any], blast_radius: Dict[str, Any]) -> Dict[str, Any]:
        timestamp, time_source = try_ntp_time()
        alert = {
            "time": timestamp.isoformat(),
            "time_source": time_source,
            "provider": provider,
            "caller": event.get("caller"),
            "source_ip": event.get("source_ip"),
            "resource_context": event.get("resources"),
            "event_name": event.get("event_name"),
            "event_time": event.get("event_time"),
            "token_id": event.get("token_id"),
            "access_key_id": event.get("access_key_id"),
            "blast_radius": blast_radius,
            "note": "Signed alert from HoneyCred Tripwire; stored in tamper-evident log",
        }
        envelope = self.store.append(alert)
        logging.info("Signed alert emitted: token=%s event=%s", event.get("token_id"), event.get("event_name"))
        return envelope


def analyze_blast_radius(provider: ProviderBase, token_meta: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal heuristic: RO policy and explicit deny => no write/delete
    if isinstance(provider, AWSProvider):
        allowed_write = []
        return {
            "privilege": "ReadOnly with explicit deny writes",
            "allowed_write_actions": allowed_write,
            "policy": {"managed": "ReadOnlyAccess", "explicit_deny": AWS_DENY_ACTIONS},
        }
    return {"privilege": "Reader/Viewer", "allowed_write_actions": []}


def get_provider(name: str, state: StateStore, base_dir: str, dry_run: bool) -> ProviderBase:
    name = name.lower()
    if name == "aws":
        return AWSProvider(state, base_dir, dry_run)
    if name == "azure":
        return AzureProvider(state, base_dir, dry_run)
    if name == "gcp":
        return GCPProvider(state, base_dir, dry_run)
    raise ValueError(f"Unknown provider {name}")


def enforce_policies_all(provider: ProviderBase, state: StateStore):
    tokens = state.get_tokens(provider.name())
    for token_id, meta in tokens.items():
        try:
            provider.enforce_least_privilege(meta)
        except Exception as e:
            logging.error("Policy enforcement failed for %s:%s - %s", provider.name(), token_id, e)


def monitor_loop(providers: List[ProviderBase], store: TamperEvidentStore, state: StateStore, interval: int = 30):
    emitter = AlertEmitter(store)
    last_checked = utc_now() - dt.timedelta(seconds=60)
    while True:
        for p in providers:
            try:
                events = p.monitor_events(last_checked)
                for ev in events:
                    token_id = ev.get("token_id")
                    meta = state.get_token(p.name(), token_id) if token_id else None
                    if not meta:
                        for tid, m in state.get_tokens(p.name()).items():
                            if m.get("access_key_id") == ev.get("access_key_id"):
                                token_id, meta = tid, m
                                ev["token_id"] = tid
                                break
                    if not meta:
                        continue
                    br = analyze_blast_radius(p, meta)
                    envelope = emitter.emit(p.name(), ev, br)
                    try:
                        p.revoke_credentials(token_id, meta)
                    except Exception as e:
                        logging.error("Auto-revoke failed for %s:%s - %s", p.name(), token_id, e)
                    try:
                        quarantined = p.quarantine({"resources": ev.get("resources", [])})
                        if quarantined:
                            logging.info("Quarantined resources: %s", ", ".join(quarantined))
                    except Exception as e:
                        logging.error("Quarantine failed: %s", e)
                    logging.info("Alert record hash: %s", envelope.get("record_hash"))
            except Exception as e:
                logging.error("Monitor error for %s: %s", p.name(), e)
        last_checked = utc_now() - dt.timedelta(seconds=59)
        time.sleep(interval)


def parse_args():
    p = argparse.ArgumentParser(description="HoneyCred Cloud Tripwire - Authorized defensive testing only.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c_deploy = sub.add_parser("deploy", help="Deploy a honeytoken")
    c_deploy.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    c_deploy.add_argument("--name", required=True, help="Logical name for honeytoken")
    c_deploy.add_argument("--tag", action="append", default=[], help="k=v tag pairs")
    c_deploy.add_argument("--dry-run", action="store_true")

    c_rotate = sub.add_parser("rotate", help="Rotate a honeytoken")
    c_rotate.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    c_rotate.add_argument("--token-id", required=True)
    c_rotate.add_argument("--dry-run", action="store_true")

    c_enforce = sub.add_parser("enforce", help="Enforce least-privilege policies on all honeytokens for a provider")
    c_enforce.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    c_enforce.add_argument("--dry-run", action="store_true")

    c_monitor = sub.add_parser("monitor", help="Monitor for honeytoken usage and auto-respond")
    c_monitor.add_argument("--provider", action="append", choices=["aws", "azure", "gcp"], default=["aws"])
    c_monitor.add_argument("--interval", type=int, default=30, help="Polling interval seconds")
    c_monitor.add_argument("--dry-run", action="store_true")

    c_revoke = sub.add_parser("revoke", help="Manually revoke honeytoken credentials")
    c_revoke.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    c_revoke.add_argument("--token-id", required=True)
    c_revoke.add_argument("--dry-run", action="store_true")

    c_quar = sub.add_parser("quarantine", help="Quarantine implicated resources by tag (non-destructive)")
    c_quar.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    c_quar.add_argument("--resource", action="append", required=True, help="Resource identifiers (e.g., i-0123...)")
    c_quar.add_argument("--dry-run", action="store_true")

    c_verify = sub.add_parser("verify-log", help="Verify tamper-evident alert log")
    c_verify.add_argument("--base-dir", default=DEFAULT_DIR)

    p.add_argument("--base-dir", default=DEFAULT_DIR, help="State and log directory")
    return p.parse_args()


def parse_tags(tag_list: List[str]) -> Dict[str, str]:
    tags = {}
    for kv in tag_list:
        if "=" in kv:
            k, v = kv.split("=", 1)
            tags[k.strip()] = v.strip()
    return tags


def main():
    args = parse_args()
    print("WARNING: Use only with authorization. This tool may create cloud identities and perform monitoring.")
    base_dir = args.base_dir
    state = StateStore(base_dir)
    store = TamperEvidentStore(base_dir)

    if args.cmd == "deploy":
        provider = get_provider(args.provider, state, base_dir, args.dry_run)
        tags = parse_tags(args.tag)
        res = provider.deploy_honeytoken(args.name, tags)
        provider.enforce_least_privilege(res["meta"])
        print(json.dumps(res, indent=2))
        return

    if args.cmd == "rotate":
        provider = get_provider(args.provider, state, base_dir, args.dry_run)
        res = provider.rotate_honeytoken(args.token_id)
        print(json.dumps(res, indent=2))
        return

    if args.cmd == "enforce":
        provider = get_provider(args.provider, state, base_dir, args.dry_run)
        enforce_policies_all(provider, state)
        print(json.dumps({"status": "ok", "provider": provider.name()}))
        return

    if args.cmd == "monitor":
        provs = [get_provider(p, state, base_dir, args.dry_run) for p in args.provider]
        logging.info("Starting monitor for providers: %s", ", ".join([p.name() for p in provs]))
        monitor_loop(provs, store, state, interval=args.interval)
        return

    if args.cmd == "revoke":
        provider = get_provider(args.provider, state, base_dir, args.dry_run)
        meta = state.get_token(provider.name(), args.token_id)
        if not meta:
            raise SystemExit("Unknown token-id")
        provider.revoke_credentials(args.token_id, meta)
        print(json.dumps({"status": "revoked", "provider": provider.name(), "token_id": args.token_id}))
        return

    if args.cmd == "quarantine":
        provider = get_provider(args.provider, state, base_dir, args.dry_run)
        if provider.name() == "aws":
            resources = [{"ResourceType": "AWS::EC2::Instance", "ResourceName": r} for r in args.resource]
        else:
            resources = [{"id": r} for r in args.resource]
        q = provider.quarantine({"resources": resources})
        print(json.dumps({"status": "ok", "quarantined": q}))
        return

    if args.cmd == "verify-log":
        ok = store.verify()
        print(json.dumps({"verified": ok, "alerts_path": os.path.join(args.base_dir, ALERTS_FILE)}))
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.")