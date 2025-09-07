import argparse
import base64
import collections
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import uuid
from typing import Any, Deque, Dict, List, Optional, Tuple

ETHICAL_WARNING = (
    "Ethical and legal notice: This tool performs security validation using controlled canaries. "
    "Only run against accounts/projects/subscriptions and regions you own and have explicit written authorization to test. "
    "It is designed for read-only discovery and write-only operations to labeled, dedicated test resources. "
    "No destructive operations will be performed on production assets. Misuse may violate policies and laws."
)

def now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)

def utc_ts() -> float:
    return now_utc().timestamp()

@dataclasses.dataclass
class Config:
    providers_allowed: List[str]
    accounts_allowed: List[str]
    projects_allowed: List[str]
    subscriptions_allowed: List[str]
    regions_allowed: List[str]
    rate_limit_per_minute: int = 30
    anomaly_threshold: int = 5
    anomaly_window_seconds: int = 300
    log_path: str = "./dataperimeter_probe.log"
    canary_label_key: str = "dataperimeter"
    canary_label_value: str = "canary"
    canary_ttl_seconds: int = 3600
    dry_run: bool = True
    opa_policy_path: Optional[str] = None
    secret_key: Optional[str] = None
    state_path: Optional[str] = None

class AppendOnlyJSONLogger:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        fd = os.open(self.path, os.O_CREAT, 0o600)
        os.close(fd)
    def log(self, record: Dict[str, Any]) -> None:
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n"); f.flush(); os.fsync(f.fileno())

class RateLimiter:
    def __init__(self, max_per_minute: int):
        self.max = max_per_minute
        self.events: Deque[float] = collections.deque()
        self._lock = threading.Lock()
    def allow(self) -> bool:
        with self._lock:
            now = time.time(); window_start = now - 60
            while self.events and self.events[0] < window_start: self.events.popleft()
            if len(self.events) < self.max: self.events.append(now); return True
            return False

class AnomalyGuard:
    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold; self.window_seconds = window_seconds
        self._events: Deque[float] = collections.deque(); self.paused = False; self._lock = threading.Lock()
    def record_anomaly(self) -> None:
        with self._lock:
            now = time.time(); ws = now - self.window_seconds
            while self._events and self._events[0] < ws: self._events.popleft()
            self._events.append(now); 
            if len(self._events) >= self.threshold: self.paused = True
    def should_pause(self) -> bool:
        with self._lock: return self.paused
    def reset(self) -> None:
        with self._lock: self.paused = False; self._events.clear()

@dataclasses.dataclass
class Canary:
    id: str
    created_at: float
    expires_at: float
    scope: Dict[str, str]
    signature: str
    correlation_id: str
    @staticmethod
    def create(secret_key: str, ttl_seconds: int, scope: Dict[str, str], correlation_id: str) -> "Canary":
        cid = str(uuid.uuid4()); created = utc_ts(); expires = created + ttl_seconds
        payload = f"{cid}|{int(created)}|{int(expires)}|{json.dumps(scope, sort_keys=True)}|{correlation_id}".encode("utf-8")
        sig = base64.urlsafe_b64encode(hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).digest()).decode("utf-8")
        return Canary(id=cid, created_at=created, expires_at=expires, scope=scope, signature=sig, correlation_id=correlation_id)
    def validate(self, secret_key: str) -> bool:
        payload = f"{self.id}|{int(self.created_at)}|{int(self.expires_at)}|{json.dumps(self.scope, sort_keys=True)}|{self.correlation_id}".encode("utf-8")
        expected = hmac.new(secret_key.encode("utf-8"), payload, hashlib.sha256).digest()
        try: got = base64.urlsafe_b64decode(self.signature.encode("utf-8"))
        except Exception: return False
        if not hmac.compare_digest(expected, got): return False
        return utc_ts() <= self.expires_at
    def to_metadata(self, label_key: str, label_value: str) -> Dict[str, str]:
        return {label_key: label_value,"canary_id": self.id,"canary_created_at": str(int(self.created_at)),"canary_expires_at": str(int(self.expires_at)),"canary_signature": self.signature,"correlation_id": self.correlation_id}

@dataclasses.dataclass
class Bucket:
    name: str
    region: str
    labels: Dict[str, str]
    account_id: Optional[str] = None
    project_id: Optional[str] = None
    subscription_id: Optional[str] = None
    vpc_endpoint_required: bool = False
    private_endpoint_ids: Optional[List[str]] = None
    vpc_sc_enabled: bool = False
    allow_public_read: bool = False

@dataclasses.dataclass
class ObjectMeta:
    object_id: str
    bucket: str
    created_at: float
    labels: Dict[str, str]
    correlation_id: str
    region: str

class PolicyChecker:
    def __init__(self, config: Config):
        self.config = config; self.opa_path = config.opa_policy_path
    def check(self, action: str, resource: Dict[str, Any]) -> Tuple[bool, str]:
        if self.opa_path:
            try:
                import shutil, subprocess
                opa_bin = shutil.which("opa")
                if opa_bin:
                    input_data = {"action": action, "resource": resource}
                    cmd = [opa_bin,"eval","--format","json","-d",self.opa_path,"-I","--stdin-input","data.dataperimeter.allow"]
                    proc = subprocess.run(cmd, input=json.dumps(input_data).encode("utf-8"), capture_output=True, check=False)
                    if proc.returncode == 0:
                        output = json.loads(proc.stdout.decode("utf-8")); allow = False
                        for r in output.get("result", []):
                            for ex in r.get("expressions", []):
                                if isinstance(ex.get("value"), bool): allow = ex.get("value")
                        if allow: return True, "allowed_by_opa"
                        return False, f"denied_by_opa:{proc.stdout.decode('utf-8')}"
                    else:
                        return False, f"opa_error:{proc.stderr.decode('utf-8')}"
            except Exception as e:
                return False, f"opa_exception:{e}"
        labels = resource.get("labels", {})
        if action in ("write_canary","generate_presigned","cleanup"):
            lk = labels.get(self.config.canary_label_key)
            if lk != self.config.canary_label_value:
                return False, f"guardrail_denied:not_a_canary_resource:{labels}"
        provider = resource.get("provider"); region = resource.get("region")
        if provider and provider.lower() not in [p.lower() for p in self.config.providers_allowed]:
            return False, f"guardrail_denied:provider_not_allowlisted:{provider}"
        if region and self.config.regions_allowed and region not in self.config.regions_allowed:
            return False, f"guardrail_denied:region_not_allowlisted:{region}"
        if resource.get("account_id") and self.config.accounts_allowed and resource["account_id"] not in self.config.accounts_allowed:
            return False, f"guardrail_denied:account_not_allowlisted:{resource['account_id']}"
        if resource.get("project_id") and self.config.projects_allowed and resource["project_id"] not in self.config.projects_allowed:
            return False, f"guardrail_denied:project_not_allowlisted:{resource['project_id']}"
        if resource.get("subscription_id") and self.config.subscriptions_allowed and resource["subscription_id"] not in self.config.subscriptions_allowed:
            return False, f"guardrail_denied:subscription_not_allowlisted:{resource['subscription_id']}"
        return True, "ok"

class CloudProvider:
    def name(self) -> str: raise NotImplementedError
    def list_storage_buckets(self) -> List[Bucket]: raise NotImplementedError
    def can_write_to_bucket(self, bucket: Bucket, config: Config) -> bool: raise NotImplementedError
    def create_canary_object(self, bucket: Bucket, canary: Canary, content: bytes) -> ObjectMeta: raise NotImplementedError
    def generate_presigned_url(self, bucket: Bucket, object_meta: ObjectMeta, expires_in: int) -> str: raise NotImplementedError
    def simulate_read_from_untrusted_network(self, bucket: Bucket, object_meta: ObjectMeta) -> bool: raise NotImplementedError
    def get_audit_logs(self, correlation_id: str) -> List[Dict[str, Any]]: raise NotImplementedError
    def cleanup_expired_canaries(self, label_key: str, label_value: str, ttl: int, now_ts: float) -> int: raise NotImplementedError
    def account_id(self) -> Optional[str]: return None
    def project_id(self) -> Optional[str]: return None
    def subscription_id(self) -> Optional[str]: return None
    def region(self) -> Optional[str]: return None

class SimulatedProvider(CloudProvider):
    def __init__(self, state: Dict[str, Any]):
        self.state = state; self._lock = threading.Lock()
    def name(self) -> str: return self.state.get("provider", "simulated")
    def list_storage_buckets(self) -> List[Bucket]:
        res: List[Bucket] = []; account_id = self.state.get("account_id"); project_id = self.state.get("project_id"); subscription_id = self.state.get("subscription_id")
        for bn, bd in self.state.get("buckets", {}).items():
            res.append(Bucket(name=bn,region=bd.get("region", self.state.get("region")),labels=bd.get("labels", {}),account_id=account_id,project_id=project_id,subscription_id=subscription_id,vpc_endpoint_required=bool(bd.get("vpc_endpoint_required", False)),private_endpoint_ids=list(bd.get("private_endpoint_ids", []) or []),vpc_sc_enabled=bool(bd.get("vpc_sc_enabled", False)),allow_public_read=bool(bd.get("allow_public_read", False))))
        return res
    def _bucket_state(self, bucket: Bucket) -> Dict[str, Any]: return self.state["buckets"][bucket.name]
    def can_write_to_bucket(self, bucket: Bucket, config: Config) -> bool:
        return bucket.labels.get(config.canary_label_key) == config.canary_label_value
    def _resource_dict(self, bucket: Bucket) -> Dict[str, Any]:
        return {"bucket": bucket.name,"region": bucket.region,"labels": bucket.labels,"account_id": bucket.account_id,"project_id": bucket.project_id,"subscription_id": bucket.subscription_id,"provider": self.name()}
    def create_canary_object(self, bucket: Bucket, canary: Canary, content: bytes) -> ObjectMeta:
        with self._lock:
            objid = f"canary-{canary.id}"; bstate = self._bucket_state(bucket); objects = bstate.setdefault("objects", {})
            if objid in objects: objid = f"{objid}-{int(time.time())}"
            meta = {"created_at": canary.created_at,"labels": canary.to_metadata(label_key=self.state.get("canary_label_key","dataperimeter"),label_value=self.state.get("canary_label_value","canary")),"correlation_id": canary.correlation_id,"content_len": len(content)}
            objects[objid] = meta
            return ObjectMeta(object_id=objid,bucket=bucket.name,created_at=canary.created_at,labels=meta["labels"],correlation_id=canary.correlation_id,region=bucket.region)
    def generate_presigned_url(self, bucket: Bucket, object_meta: ObjectMeta, expires_in: int) -> str:
        token = {"bucket": bucket.name,"object_id": object_meta.object_id,"region": bucket.region,"expires_at": int(utc_ts() + expires_in),"cid": object_meta.correlation_id}
        raw = json.dumps(token, sort_keys=True).encode("utf-8")
        return f"https://simulated/{self.name()}/{bucket.name}/{object_meta.object_id}?ps={base64.urlsafe_b64encode(raw).decode('utf-8')}"
    def simulate_read_from_untrusted_network(self, bucket: Bucket, object_meta: ObjectMeta) -> bool:
        leak = bucket.allow_public_read or ((not bucket.vpc_endpoint_required) and (not bucket.private_endpoint_ids) and (not bucket.vpc_sc_enabled))
        with self._lock:
            self.state.setdefault("audit_logs", [])
            self.state["audit_logs"].append({"time": int(utc_ts()),"provider": self.name(),"action": "GetObject","bucket": bucket.name,"region": bucket.region,"object_id": object_meta.object_id,"correlation_id": object_meta.correlation_id,"network": "untrusted","result": "Allowed" if leak else "Denied"})
        return leak
    def access_presigned_url_from_region(self, url: str, access_region: str) -> Dict[str, Any]:
        if "?ps=" not in url: raise ValueError("invalid presigned url")
        b64 = url.split("?ps=")[1]; token = json.loads(base64.urlsafe_b64decode(b64.encode("utf-8")).decode("utf-8"))
        cross_region = token["region"] != access_region
        result = {"bucket": token["bucket"],"object_id": token["object_id"],"issued_region": token["region"],"access_region": access_region,"cross_region": cross_region,"correlation_id": token["cid"],"expires_at": token["expires_at"],"result": "Allowed" if utc_ts() <= token["expires_at"] else "Expired"}
        with self._lock:
            self.state.setdefault("audit_logs", [])
            self.state["audit_logs"].append({"time": int(utc_ts()),"provider": self.name(),"action": "PresignedURLAccess","bucket": token["bucket"],"region": access_region,"issued_region": token["region"],"object_id": token["object_id"],"correlation_id": token["cid"],"cross_region": cross_region,"result": result["result"]})
        return result
    def get_audit_logs(self, correlation_id: str) -> List[Dict[str, Any]]:
        return [e for e in self.state.get("audit_logs", []) if e.get("correlation_id") == correlation_id]
    def cleanup_expired_canaries(self, label_key: str, label_value: str, ttl: int, now_ts: float) -> int:
        count = 0
        with self._lock:
            for _, bd in self.state.get("buckets", {}).items():
                objects = bd.get("objects", {}); remove_keys = []
                for oid, meta in objects.items():
                    labels = meta.get("labels", {})
                    if labels.get(label_key) == label_value:
                        created_at = float(meta.get("created_at", meta.get("canary_created_at", now_ts - ttl - 1)))
                        if now_ts - created_at > ttl: remove_keys.append(oid)
                for oid in remove_keys: objects.pop(oid, None); count += 1
        return count
    def account_id(self) -> Optional[str]: return self.state.get("account_id")
    def project_id(self) -> Optional[str]: return self.state.get("project_id")
    def subscription_id(self) -> Optional[str]: return self.state.get("subscription_id")
    def region(self) -> Optional[str]: return self.state.get("region")

class ProbeEngine:
    def __init__(self, config: Config, provider: CloudProvider, logger: AppendOnlyJSONLogger):
        self.config = config; self.provider = provider; self.logger = logger
        self.policy = PolicyChecker(config); self.ratelimiter = RateLimiter(config.rate_limit_per_minute)
        self.guard = AnomalyGuard(config.anomaly_threshold, config.anomaly_window_seconds)
        self.secret_key = config.secret_key or base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        self._paused_reason: Optional[str] = None
    def _enforce_allowlists(self, bucket: Bucket) -> Tuple[bool, str]:
        if self.provider.name().lower() not in [p.lower() for p in self.config.providers_allowed]:
            return False, f"provider {self.provider.name()} not allowlisted"
        if self.config.regions_allowed and bucket.region not in self.config.regions_allowed:
            return False, f"region {bucket.region} not allowlisted"
        if self.provider.account_id() and self.config.accounts_allowed and self.provider.account_id() not in self.config.accounts_allowed:
            return False, f"account {self.provider.account_id()} not allowlisted"
        if self.provider.project_id() and self.config.projects_allowed and self.provider.project_id() not in self.config.projects_allowed:
            return False, f"project {self.provider.project_id()} not allowlisted"
        if self.provider.subscription_id() and self.config.subscriptions_allowed and self.provider.subscription_id() not in self.config.subscriptions_allowed:
            return False, f"subscription {self.provider.subscription_id()} not allowlisted"
        return True, "ok"
    def _check_rate_and_guard(self) -> None:
        if self.guard.should_pause(): raise RuntimeError(f"Probing paused due to anomaly threshold reached: {self._paused_reason or 'excess anomalies'}")
        if not self.ratelimiter.allow(): raise RuntimeError("Rate limit exceeded; try again later")
    def _log(self, correlation_id: str, event: Dict[str, Any]) -> None:
        ev = dict(event); ev["time"] = int(utc_ts()); ev["correlation_id"] = correlation_id; self.logger.log(ev)
    def probe_egress_read(self, bucket: Bucket) -> Dict[str, Any]:
        self._check_rate_and_guard(); ok, reason = self._enforce_allowlists(bucket)
        if not ok: raise PermissionError(reason)
        resource = {"bucket": bucket.name,"region": bucket.region,"labels": bucket.labels,"account_id": bucket.account_id,"project_id": bucket.project_id,"subscription_id": bucket.subscription_id,"provider": self.provider.name()}
        allow, why = self.policy.check("write_canary", resource)
        if not allow: raise PermissionError(why)
        correlation_id = str(uuid.uuid4())
        canary = Canary.create(secret_key=self.secret_key, ttl_seconds=self.config.canary_ttl_seconds, scope={"bucket": bucket.name}, correlation_id=correlation_id)
        content = f"canary:{canary.id}:{canary.correlation_id}".encode("utf-8")
        objmeta = self.provider.create_canary_object(bucket, canary, content)
        self._log(correlation_id, {"event": "canary_object_created","bucket": bucket.name,"object_id": objmeta.object_id,"provider": self.provider.name(),"region": bucket.region})
        allow_read = self.provider.simulate_read_from_untrusted_network(bucket, objmeta)
        result: Dict[str, Any] = {"correlation_id": correlation_id,"provider": self.provider.name(),"bucket": bucket.name,"region": bucket.region,"object_id": objmeta.object_id,"egress_leak_detected": allow_read,"details": {},"remediation": []}
        if allow_read:
            details = {"path": "untrusted_network_read","vpc_endpoint_required": bucket.vpc_endpoint_required,"private_endpoint_ids": bucket.private_endpoint_ids,"vpc_sc_enabled": bucket.vpc_sc_enabled,"allow_public_read": bucket.allow_public_read}
            remediation = []
            if bucket.allow_public_read: remediation.append("Disable public read access at bucket level and enable block-public-access.")
            if not bucket.vpc_endpoint_required: remediation.append("Enforce VPC/VNet/Private Endpoint access using explicit condition keys or service endpoints.")
            if not bucket.private_endpoint_ids: remediation.append("Scope access to approved PrivateLink/Private Endpoint service IDs.")
            if not bucket.vpc_sc_enabled: remediation.append("Enable VPC Service Controls or equivalent perimeter (GCP VPC-SC/Azure Private Endpoints).")
            result["details"] = details; result["remediation"] = remediation
            self._log(correlation_id, {"event": "egress_leak_detected","details": details,"severity": "high"})
            self.guard.record_anomaly()
            if self.guard.should_pause(): self._paused_reason = "excessive egress leaks detected"
        else:
            self._log(correlation_id, {"event": "egress_block_enforced","severity": "info"})
        return result
    def probe_presigned_cross_region(self, bucket: Bucket) -> Dict[str, Any]:
        self._check_rate_and_guard(); ok, reason = self._enforce_allowlists(bucket)
        if not ok: raise PermissionError(reason)
        resource = {"bucket": bucket.name,"region": bucket.region,"labels": bucket.labels,"account_id": bucket.account_id,"project_id": bucket.project_id,"subscription_id": bucket.subscription_id,"provider": self.provider.name()}
        allow, why = self.policy.check("generate_presigned", resource)
        if not allow: raise PermissionError(why)
        correlation_id = str(uuid.uuid4())
        canary = Canary.create(secret_key=self.secret_key, ttl_seconds=self.config.canary_ttl_seconds, scope={"bucket": bucket.name}, correlation_id=correlation_id)
        objmeta = self.provider.create_canary_object(bucket, canary, content=b"")
        url = self.provider.generate_presigned_url(bucket, objmeta, expires_in=300)
        access_region = "eu-west-1" if bucket.region != "eu-west-1" else "us-east-1"
        if self.config.regions_allowed and access_region not in self.config.regions_allowed: access_region = bucket.region
        res = {}
        if hasattr(self.provider, "access_presigned_url_from_region"):
            res = getattr(self.provider, "access_presigned_url_from_region")(url, access_region)  # type: ignore
        logs = self.provider.get_audit_logs(correlation_id)
        out = {"correlation_id": correlation_id,"provider": self.provider.name(),"bucket": bucket.name,"object_id": objmeta.object_id,"issued_region": bucket.region,"access_region": res.get("access_region", access_region),"cross_region": res.get("cross_region", False),"presigned_url": url if self.config.dry_run else "<redacted>","audit_events": logs}
        self._log(correlation_id, {"event": "presigned_url_probe","issued_region": bucket.region,"access_region": access_region,"cross_region": out["cross_region"]})
        return out
    def cleanup_canaries(self) -> Dict[str, Any]:
        self._check_rate_and_guard()
        cleaned = self.provider.cleanup_expired_canaries(self.config.canary_label_key, self.config.canary_label_value, self.config.canary_ttl_seconds, now_ts=utc_ts())
        cid = str(uuid.uuid4()); self._log(cid, {"event": "cleanup","removed_count": cleaned})
        return {"correlation_id": cid, "removed_count": cleaned}

def load_config(path: Optional[str]) -> Config:
    if not path: raise ValueError("config path is required")
    with open(path, "r", encoding="utf-8") as f: data = json.load(f)
    return Config(providers_allowed=data.get("providers_allowed", ["simulated"]),accounts_allowed=data.get("accounts_allowed", []),projects_allowed=data.get("projects_allowed", []),subscriptions_allowed=data.get("subscriptions_allowed", []),regions_allowed=data.get("regions_allowed", []),rate_limit_per_minute=int(data.get("rate_limit_per_minute", 30)),anomaly_threshold=int(data.get("anomaly_threshold", 5)),anomaly_window_seconds=int(data.get("anomaly_window_seconds", 300)),log_path=data.get("log_path", "./dataperimeter_probe.log"),canary_label_key=data.get("canary_label_key", "dataperimeter"),canary_label_value=data.get("canary_label_value", "canary"),canary_ttl_seconds=int(data.get("canary_ttl_seconds", 3600)),dry_run=bool(data.get("dry_run", True)),opa_policy_path=data.get("opa_policy_path"),secret_key=data.get("secret_key"),state_path=data.get("state_path"))

def load_simulated_state(path: Optional[str]) -> Dict[str, Any]:
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    return {"provider": "aws","account_id": "111122223333","region": "us-east-1","buckets": {"prod-data": {"region": "us-east-1","labels": {"env": "prod"},"vpc_endpoint_required": False,"private_endpoint_ids": [],"vpc_sc_enabled": False,"allow_public_read": False,"objects": {}},"dp-probe-canary-us-east-1": {"region": "us-east-1","labels": {"dataperimeter": "canary","ttl": "3600"},"vpc_endpoint_required": False,"private_endpoint_ids": [],"vpc_sc_enabled": False,"allow_public_read": False,"objects": {}},"dp-probe-strict": {"region": "us-east-1","labels": {"dataperimeter": "canary"},"vpc_endpoint_required": True,"private_endpoint_ids": ["vpce-12345"],"vpc_sc_enabled": True,"allow_public_read": False,"objects": {}}},"audit_logs": [],"canary_label_key": "dataperimeter","canary_label_value": "canary"}

def save_simulated_state(path: Optional[str], state: Dict[str, Any]) -> None:
    if not path: return
    with open(path, "w", encoding="utf-8") as f: json.dump(state, f, indent=2, sort_keys=True)

def find_canary_buckets(provider: CloudProvider, config: Config) -> List[Bucket]:
    return [b for b in provider.list_storage_buckets() if b.labels.get(config.canary_label_key) == config.canary_label_value]

def cli():
    print(ETHICAL_WARNING, file=sys.stderr)
    parser = argparse.ArgumentParser(description="DataPerimeter Probe: Cloud Data Egress Policy Validator (Simulated)")
    parser.add_argument("--config", required=True, help="Path to JSON config")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-state", help="Initialize a simulated provider state file if missing")
    sub.add_parser("status", help="Show current canary buckets")
    p_probe = sub.add_parser("probe-egress", help="Probe egress on canary buckets"); p_probe.add_argument("--bucket", help="Specific bucket to probe")
    p_pre = sub.add_parser("probe-presigned", help="Probe presigned URL cross-region access"); p_pre.add_argument("--bucket", help="Specific bucket to probe")
    sub.add_parser("cleanup", help="Cleanup expired canaries")
    args = parser.parse_args()
    cfg = load_config(args.config); state = load_simulated_state(cfg.state_path); provider = SimulatedProvider(state)
    logger = AppendOnlyJSONLogger(cfg.log_path); engine = ProbeEngine(cfg, provider, logger)
    if args.cmd == "init-state":
        if cfg.state_path and not os.path.exists(cfg.state_path):
            save_simulated_state(cfg.state_path, state); print(f"Initialized simulated state at {cfg.state_path}")
        else:
            print("State path exists or not provided.")
        return
    if args.cmd == "status":
        buckets = provider.list_storage_buckets(); canary_buckets = find_canary_buckets(provider, cfg)
        out = {"provider": provider.name(),"account_id": provider.account_id(),"project_id": provider.project_id(),"subscription_id": provider.subscription_id(),"region": provider.region(),"buckets_total": len(buckets),"canary_buckets": [b.name for b in canary_buckets]}
        print(json.dumps(out, indent=2)); return
    if args.cmd == "probe-egress":
        results = []; targets = find_canary_buckets(provider, cfg)
        if args.bucket: targets = [b for b in targets if b.name == args.bucket]
        for b in targets:
            try: results.append(engine.probe_egress_read(b))
            except Exception as e: results.append({"bucket": b.name, "error": str(e)})
        print(json.dumps(results, indent=2)); save_simulated_state(cfg.state_path, state); return
    if args.cmd == "probe-presigned":
        results = []; targets = find_canary_buckets(provider, cfg)
        if args.bucket: targets = [b for b in targets if b.name == args.bucket]
        for b in targets:
            try: results.append(engine.probe_presigned_cross_region(b))
            except Exception as e: results.append({"bucket": b.name, "error": str(e)})
        print(json.dumps(results, indent=2)); save_simulated_state(cfg.state_path, state); return
    if args.cmd == "cleanup":
        out = engine.cleanup_canaries(); print(json.dumps(out, indent=2)); save_simulated_state(cfg.state_path, state); return

if __name__ == "__main__":
    cli()