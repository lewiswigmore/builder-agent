import argparse
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

ETHICS_NOTICE = (
    "Authorized testing only. Do not scan or deploy canaries in accounts or environments "
    "without explicit written permission. This tool avoids requesting sensitive real metadata, "
    "preferring simulated/canary endpoints and minimal scopes."
)

METADATA_HOSTS = {
    "aws": ["169.254.169.254"],
    "azure": ["169.254.169.254"],
    "gcp": ["169.254.169.254", "metadata.google.internal"],
}
ALL_METADATA_HOSTS = set(sum(METADATA_HOSTS.values(), []))


def utc_now() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def safe_json_dumps(d: Dict[str, Any]) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


class RateLimiter:
    def __init__(self, rate_per_sec: float = 1.0):
        self.rate = max(0.01, rate_per_sec)
        self._lock = threading.Lock()
        self._last = 0.0

    def acquire(self):
        with self._lock:
            now = time.time()
            min_interval = 1.0 / self.rate
            wait = self._last + min_interval - now
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()


class Signer:
    def __init__(self, key: Optional[bytes] = None, key_path: Optional[Path] = None):
        env_key = os.environ.get("METASURF_SIGNING_KEY")
        if env_key:
            key = env_key.encode("utf-8")
        self.key_path = key_path or Path(os.environ.get("METASURF_SIGNING_KEY_FILE", "") or "")
        if key is None and self.key_path and self.key_path.exists():
            key = self.key_path.read_bytes()
        if key is None:
            # Generate a random 32-byte key if none provided (for demo/testing only).
            key = os.urandom(32)
            if self.key_path:
                self.key_path.parent.mkdir(parents=True, exist_ok=True)
                self.key_path.write_bytes(key)
        self.key = key

    def sign(self, message: str) -> str:
        mac = hmac.new(self.key, message.encode("utf-8"), hashlib.sha256)
        return mac.hexdigest()

    def verify(self, message: str, signature: str) -> bool:
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)


class EvidenceStore:
    def __init__(self, base_dir: Optional[Path] = None):
        self.base = base_dir or Path(os.environ.get("METASURF_EVIDENCE_DIR", ".metasurf_evidence"))
        self.base.mkdir(parents=True, exist_ok=True)
        # Retention policy metadata (purely informational here)
        self.retention_days = int(os.environ.get("METASURF_EVIDENCE_RETENTION_DAYS", "365"))

    def write_once(self, prefix: str, payload: Dict[str, Any]) -> Path:
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        uid = uuid.uuid4().hex
        name = f"{prefix}-{ts}-{uid}.json"
        path = self.base / name
        data = safe_json_dumps(payload) + "\n"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(str(path), flags, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(data)
            # Make read-only to simulate WORM
            path.chmod(0o400)
            return path
        except FileExistsError:
            # Extremely unlikely due to UUID; retry with new UUID
            return self.write_once(prefix, payload)

    def open_ticket(self, title: str, details: Dict[str, Any]) -> Path:
        ticket = {
            "type": "ticket",
            "title": title,
            "details": details,
            "created_at": utc_now(),
            "ethics_notice": ETHICS_NOTICE,
        }
        return self.write_once("ticket", ticket)


class CanaryManager:
    def __init__(self, store: EvidenceStore, signer: Signer):
        self.store = store
        self.signer = signer
        self.registry_path = self.store.base / "canaries.json"
        self._load_registry()

    def _load_registry(self):
        if self.registry_path.exists():
            try:
                self.registry = json.loads(self.registry_path.read_text())
            except Exception:
                self.registry = {"canaries": []}
        else:
            self.registry = {"canaries": []}

    def _save_registry(self):
        tmp = {"canaries": self.registry.get("canaries", [])}
        tmp_json = safe_json_dumps(tmp)
        sig = self.signer.sign(tmp_json)
        payload = {"registry": tmp, "signed_at": utc_now(), "signature": sig}
        # Write as a new evidence record and update a pointer file
        p = self.store.write_once("canary-registry", payload)
        # Pointer file (non-WORM) for quick lookups
        self.registry_path.write_text(json.dumps(tmp, indent=2))
        return p

    def deploy_canary(self, provider: str, scope: str = "deny_all") -> Dict[str, Any]:
        # Simulated canary credentials. We DO NOT create real cloud credentials here.
        canary_id = f"CANARY-{uuid.uuid4().hex[:12].upper()}"
        secret = uuid.uuid4().hex + uuid.uuid4().hex
        record = {
            "provider": provider,
            "canary_id": canary_id,
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "created_at": utc_now(),
            "revoked_at": None,
            "policy": self._least_privilege_policy(provider, scope),
            "note": "Simulated canary for detection. Do not grant broad privileges.",
        }
        self.registry.setdefault("canaries", []).append(record)
        self._save_registry()
        evidence = {
            "event": "canary_deployed",
            "provider": provider,
            "canary_id": canary_id,
            "created_at": record["created_at"],
            "policy": record["policy"],
            "ethics_notice": ETHICS_NOTICE,
        }
        sig = self.signer.sign(safe_json_dumps(evidence))
        evidence_path = self.store.write_once("canary-deploy", {"evidence": evidence, "signature": sig})
        return {"canary_id": canary_id, "secret": secret, "policy": record["policy"], "evidence": str(evidence_path)}

    def revoke_canary(self, canary_id: str) -> Dict[str, Any]:
        for c in self.registry.get("canaries", []):
            if c["canary_id"] == canary_id and c["revoked_at"] is None:
                c["revoked_at"] = utc_now()
                self._save_registry()
                ev = {"event": "canary_revoked", "canary_id": canary_id, "revoked_at": c["revoked_at"]}
                sig = self.signer.sign(safe_json_dumps(ev))
                path = self.store.write_once("canary-revoke", {"evidence": ev, "signature": sig})
                return {"status": "revoked", "evidence": str(path)}
        return {"status": "not_found_or_already_revoked"}

    def rotate_canary(self, provider: str, scope: str = "deny_all", old_canary_id: Optional[str] = None) -> Dict[str, Any]:
        if old_canary_id:
            self.revoke_canary(old_canary_id)
        return self.deploy_canary(provider, scope)

    def find_canary(self, canary_id: str) -> Optional[Dict[str, Any]]:
        for c in self.registry.get("canaries", []):
            if c["canary_id"] == canary_id:
                return c
        return None

    def _least_privilege_policy(self, provider: str, scope: str) -> Dict[str, Any]:
        # Scope "deny_all": any usage triggers AccessDenied but still logs in audit trails.
        if provider == "aws":
            if scope == "deny_all":
                return {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
            # Minimal example: allow only sts:GetCallerIdentity (common safe scope).
            if scope == "identity_only":
                return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"}]}
        elif provider == "azure":
            return {"roleDefinition": "DenyAllCustomRole", "permissions": []}
        elif provider == "gcp":
            if scope == "deny_all":
                return {"iamPolicy": {"bindings": []}}
        return {"note": "default_empty_policy"}


def is_metadata_host(host: str) -> bool:
    try:
        # Match literal IPs and resolvable hostnames
        if host in ALL_METADATA_HOSTS:
            return True
        ip = ipaddress.ip_address(host)
        return str(ip) in ALL_METADATA_HOSTS
    except ValueError:
        # Not an IP; compare hostname
        h = host.lower().strip(".")
        return h in ALL_METADATA_HOSTS


class MetasurfWatch:
    def __init__(self, rate: float = 1.0):
        self.ratelimiter = RateLimiter(rate_per_sec=rate)
        self.signer = Signer(key_path=Path(".metasurf_keys/signing.key"))
        self.store = EvidenceStore()
        self.canaries = CanaryManager(self.store, self.signer)
        self.scanner_id = os.environ.get("METASURF_SCANNER_ID", f"metasurf-{socket.gethostname()}")

    def _identity_proof(self, workload_identity: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        proof = {
            "scanner_id": self.scanner_id,
            "timestamp": utc_now(),
            "workload_identity": workload_identity or {},
        }
        msg = safe_json_dumps(proof)
        sig = self.signer.sign(msg)
        proof["signature"] = sig
        return proof

    def _store_signed_evidence(self, prefix: str, evidence: Dict[str, Any]) -> Path:
        msg = safe_json_dumps(evidence)
        sig = self.signer.sign(msg)
        return self.store.write_once(prefix, {"evidence": evidence, "signature": sig})

    def scan_instance(self, provider: str, instance: Dict[str, Any], workload_identity: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        instance: dict with metadata options per provider. For AWS, keys:
          - instance_id
          - metadata_options: { http_tokens: 'required'|'optional', http_put_response_hop_limit: int, endpoint: 'enabled'|'disabled' }
        """
        self.ratelimiter.acquire()
        findings: List[Dict[str, Any]] = []
        severity = "info"
        if provider == "aws":
            mo = instance.get("metadata_options", {})
            http_tokens = str(mo.get("http_tokens", "")).lower() or "optional"
            hop = int(mo.get("http_put_response_hop_limit", 1))
            endpoint = mo.get("endpoint", "enabled")
            if http_tokens != "required" or hop > 1 or endpoint != "enabled":
                sev = "high" if http_tokens != "required" or hop > 1 else "medium"
                severity = max(severity, sev, key=lambda s: ["info", "low", "medium", "high", "critical"].index(s))
                details = {
                    "provider": "aws",
                    "instance_id": instance.get("instance_id"),
                    "http_tokens": http_tokens,
                    "hop_limit": hop,
                    "endpoint": endpoint,
                    "issue": "IMDSv1 enabled or excessive hop limit" if http_tokens != "required" or hop > 1 else "IMDS endpoint misconfiguration",
                }
                remediation = self._remediation_aws_imds(instance.get("instance_id", "i-xxxxxxxxxxxxxxxxx"))
                finding = {
                    "severity": sev,
                    "category": "imds_hardening",
                    "details": details,
                    "remediation": remediation,
                    "ethics_notice": ETHICS_NOTICE,
                    "identity_proof": self._identity_proof(workload_identity),
                    "timestamp": utc_now(),
                }
                findings.append(finding)
        elif provider in ("azure", "gcp"):
            # Provide generic guidance; cannot directly configure IMDS tokens like AWS
            findings.append({
                "severity": "medium",
                "category": "imds_hardening",
                "details": {"provider": provider, "issue": "Validate metadata access is restricted via network policies / sidecars"},
                "remediation": self._remediation_generic(provider),
                "ethics_notice": ETHICS_NOTICE,
                "identity_proof": self._identity_proof(workload_identity),
                "timestamp": utc_now(),
            })
        result = {"provider": provider, "findings": findings}
        path = self._store_signed_evidence("scan-instance", result)
        result["evidence_path"] = str(path)
        return result

    def _remediation_aws_imds(self, instance_id: str) -> Dict[str, Any]:
        tf = (
            'resource "aws_instance" "example" {\n'
            '  # ...\n'
            '  metadata_options {\n'
            '    http_tokens                 = "required"\n'
            '    http_put_response_hop_limit = 1\n'
            '  }\n'
            '}\n'
        )
        cli = (
            f"aws ec2 modify-instance-metadata-options --instance-id {instance_id} "
            f"--http-tokens required --http-put-response-hop-limit 1"
        )
        endpoint_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "ec2:DescribeInstanceAttribute", "Resource": "*", "Condition": {"StringNotEquals": {"ec2:Attribute": "metadataOptions"}}}
            ],
        }
        return {
            "terraform": tf,
            "cli": cli,
            "notes": [
                "Ensure applications use IMDSv2 session tokens.",
                "Set hop limit to 1 to prevent container SSRF pivots.",
                "Consider endpoint policies and VPC traffic controls to constrain access.",
            ],
            "endpoint_policy_example": endpoint_policy,
        }

    def _remediation_generic(self, provider: str) -> Dict[str, Any]:
        notes = [
            "Block metadata IP (169.254.169.254) from untrusted pods via network policies.",
            "Use sidecars or IMDS proxy with token protection where supported.",
        ]
        if provider == "gcp":
            notes.append("Use GKE Workload Identity and disable legacy metadata APIs.")
        if provider == "azure":
            notes.append("Require Metadata:true header and implement egress restrictions in NSGs.")
        return {"notes": notes}

    def simulate_ssrf_attempt(self, origin: Dict[str, Any], request: Dict[str, Any]) -> Dict[str, Any]:
        """
        origin: { cluster, namespace, pod, service_account, pod_uid, node }
        request: { method, host, path, user_agent }
        """
        self.ratelimiter.acquire()
        dest_host = request.get("host", "")
        blocked = False
        reason = None
        if is_metadata_host(dest_host):
            blocked = True
            reason = "Attempt to access cloud metadata endpoint"
        result = {
            "blocked": blocked,
            "reason": reason,
            "origin": origin,
            "request": request,
            "ethics_notice": ETHICS_NOTICE,
            "timestamp": utc_now(),
        }
        blast = self._blast_radius_analysis(origin)
        ticket_details = {
            "type": "ssrf_attempt",
            "result": result,
            "blast_radius": blast,
            "recommended_actions": self._quarantine_plan_from_origin(origin),
        }
        ticket_path = self.store.open_ticket(
            title=f"SSRF attempt to {dest_host} by pod {origin.get('pod')}",
            details=ticket_details,
        )
        result["ticket_path"] = str(ticket_path)
        ev_path = self._store_signed_evidence("ssrf-detection", {"result": result, "blast_radius": blast})
        result["evidence_path"] = str(ev_path)
        return result

    def _blast_radius_analysis(self, origin: Dict[str, Any]) -> Dict[str, Any]:
        # Static analysis based on provided context; for real-world, integrate with cluster RBAC APIs
        roles = origin.get("roles", ["view"])
        ns = origin.get("namespace", "default")
        possible_impacts = []
        if "admin" in roles or "edit" in roles:
            possible_impacts.append("Can list and read secrets in namespace")
        else:
            possible_impacts.append("Limited read-only in namespace")
        return {
            "namespace": ns,
            "service_account": origin.get("service_account"),
            "roles": roles,
            "node": origin.get("node"),
            "estimated_blast_radius": possible_impacts,
        }

    def _quarantine_plan_from_origin(self, origin: Dict[str, Any]) -> Dict[str, Any]:
        # Provide steps without executing: tag node/pod or apply network policy
        return {
            "kubernetes": {
                "network_policy": {
                    "action": "apply",
                    "namespace": origin.get("namespace", "default"),
                    "policy_name": f"deny-metadata-{origin.get('pod','pod')}",
                    "spec_snippet": {
                        "podSelector": {"matchLabels": {"app": origin.get("pod", "unknown")}},
                        "policyTypes": ["Egress"],
                        "egress": [{"to": [{"ipBlock": {"cidr": "169.254.169.254/32"}}], "ports": []}],
                    },
                }
            }
        }

    def handle_log_event(self, provider: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process audit logs (CloudTrail, Azure Activity Logs, GCP Audit Logs).
        Detect canary usage and trigger quarantine workflow.
        Expected minimal fields for canary detection:
          - aws: { userIdentity: { accessKeyId }, sourceIPAddress, userAgent }
          - azure/gcp: provide principalId or accessKeyId-equivalent in 'auth' and source ip/ua.
        """
        self.ratelimiter.acquire()
        canary_id = self._extract_canary_id(provider, event)
        response: Dict[str, Any] = {"provider": provider, "canary_triggered": False, "ethics_notice": ETHICS_NOTICE}
        if canary_id:
            canary = self.canaries.find_canary(canary_id)
            response["canary_triggered"] = True
            response["canary_id"] = canary_id
            src_ip, ua = self._extract_src_ua(provider, event)
            evidence = {
                "event": "canary_usage_detected",
                "provider": provider,
                "canary_id": canary_id,
                "source_ip": src_ip,
                "user_agent": ua,
                "raw_event": event,
                "timestamp": utc_now(),
                "identity_proof": self._identity_proof(),
            }
            ev_path = self._store_signed_evidence("canary-usage", evidence)
            response["evidence_path"] = str(ev_path)
            # Quarantine workflow (non-executing): propose network isolate tag or equivalent
            quarantine = self._quarantine_workflow(provider, event)
            response["quarantine_plan"] = quarantine
            # Auto-rotate and revoke
            if canary:
                self.canaries.revoke_canary(canary_id)
                rotated = self.canaries.rotate_canary(provider, scope="deny_all")
                response["rotation"] = {"new_canary_id": rotated.get("canary_id")}
        return response

    def _extract_canary_id(self, provider: str, event: Dict[str, Any]) -> Optional[str]:
        if provider == "aws":
            akid = (
                (event.get("userIdentity") or {}).get("accessKeyId")
                or event.get("accessKeyId")
                or (event.get("requestParameters") or {}).get("accessKeyId")
            )
            if akid and str(akid).startswith("CANARY-"):
                return akid
        else:
            # Generic pathway, look for "canary_id"
            cid = event.get("canary_id") or (event.get("auth") or {}).get("canary_id")
            if cid and str(cid).startswith("CANARY-"):
                return cid
        return None

    def _extract_src_ua(self, provider: str, event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        if provider == "aws":
            return event.get("sourceIPAddress"), event.get("userAgent")
        # generic:
        http_req = event.get("httpRequest") or {}
        return http_req.get("remoteIp") or event.get("sourceIp"), http_req.get("userAgent") or event.get("userAgent")

    def _quarantine_workflow(self, provider: str, event: Dict[str, Any]) -> Dict[str, Any]:
        # Provide least-privilege remediation-as-code steps without executing.
        if provider == "aws":
            target = (event.get("userIdentity") or {}).get("principalId", "unknown-principal")
            return {
                "tagging": {
                    "action": "create_tag",
                    "resource": f"arn:aws:iam::{target}",
                    "tag_key": "network-isolate",
                    "tag_value": "true",
                    "cli": "aws ec2 create-tags --resources <eni-or-instance-id> --tags Key=network-isolate,Value=true",
                    "iam_min_permissions": ["ec2:CreateTags", "ec2:DescribeInstances"],
                }
            }
        elif provider == "azure":
            return {
                "tagging": {
                    "action": "set_tag",
                    "resource": "/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/virtualMachines/...",
                    "tag_key": "network-isolate",
                    "tag_value": "true",
                    "cli": "az resource tag --ids <resource-id> --tags network-isolate=true",
                    "rbac_min_role": "Tag Contributor on target resource",
                }
            }
        elif provider == "gcp":
            return {
                "tagging": {
                    "action": "set_label",
                    "resource": "projects/.../zones/.../instances/...",
                    "label_key": "network-isolate",
                    "label_value": "true",
                    "cli": "gcloud compute instances add-labels <instance> --labels=network-isolate=true --zone=<zone>",
                    "iam_min_permissions": ["compute.instances.setLabels"],
                }
            }
        return {"note": "no_quarantine_plan"}

    def safe_probe(self, provider: str, allow_network: bool = False, timeout: float = 0.3) -> Dict[str, Any]:
        """
        Perform a safe, rate-limited probe to metadata endpoints without requesting sensitive data.
        By default, no network activity occurs unless allow_network=True. If allowed, sends a HEAD
        request to a non-secret path or canary endpoint simulation.
        """
        self.ratelimiter.acquire()
        probe_result = {"provider": provider, "performed_network": False, "reachable": None, "ethics_notice": ETHICS_NOTICE}
        if not allow_network:
            probe_result["note"] = "Network probing disabled. Use --allow-probes for authorized testing."
            return probe_result
        try:
            # Simulate probe by TCP connect only; do not send HTTP requests.
            host = METADATA_HOSTS.get(provider, ["169.254.169.254"])[0]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, 80))
                probe_result["performed_network"] = True
                probe_result["reachable"] = True
                probe_result["note"] = "TCP connectivity to metadata endpoint detected (no data requested)."
        except Exception as e:
            probe_result["performed_network"] = True
            probe_result["reachable"] = False
            probe_result["error"] = str(e)
        path = self._store_signed_evidence("safe-probe", {"result": probe_result, "timestamp": utc_now()})
        probe_result["evidence_path"] = str(path)
        return probe_result


def parse_args():
    p = argparse.ArgumentParser(description="Metasurf Watch: IMDS/SSRF Exposure Scanner & Canary")
    sub = p.add_subparsers(dest="cmd")

    s_scan = sub.add_parser("scan-instance", help="Scan instance metadata hardening (no external calls)")
    s_scan.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    s_scan.add_argument("--instance-json", required=True, help="Path to JSON file describing instance config")
    s_scan.add_argument("--workload-identity-json", help="Optional workload identity JSON")

    s_ssrf = sub.add_parser("simulate-ssrf", help="Simulate a container SSRF attempt and open a ticket")
    s_ssrf.add_argument("--origin-json", required=True, help="Path to JSON describing pod origin")
    s_ssrf.add_argument("--request-json", required=True, help="Path to JSON describing attempted request")

    s_log = sub.add_parser("handle-log", help="Handle cloud audit log event (detect canary usage)")
    s_log.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    s_log.add_argument("--event-json", required=True, help="Path to JSON event file")

    s_probe = sub.add_parser("safe-probe", help="Perform safe, rate-limited metadata TCP probe (authorized testing only)")
    s_probe.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    s_probe.add_argument("--allow-probes", action="store_true")

    s_deploy = sub.add_parser("deploy-canary", help="Deploy simulated canary credentials (no cloud API calls)")
    s_deploy.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    s_deploy.add_argument("--scope", choices=["deny_all", "identity_only"], default="deny_all")

    s_revoke = sub.add_parser("revoke-canary", help="Revoke a simulated canary credential")
    s_revoke.add_argument("--canary-id", required=True)

    s_list = sub.add_parser("list-canaries", help="List canaries in local registry")

    return p.parse_args()


def main():
    args = parse_args()
    mw = MetasurfWatch(rate=1.0)
    try:
        if args.cmd == "scan-instance":
            instance = json.loads(Path(args.instance_json).read_text())
            workload = json.loads(Path(args.workload_identity_json).read_text()) if args.workload_identity_json else None
            out = mw.scan_instance(args.provider, instance, workload)
            print(json.dumps(out, indent=2))
        elif args.cmd == "simulate-ssrf":
            origin = json.loads(Path(args.origin_json).read_text())
            request = json.loads(Path(args.request_json).read_text())
            out = mw.simulate_ssrf_attempt(origin, request)
            print(json.dumps(out, indent=2))
        elif args.cmd == "handle-log":
            event = json.loads(Path(args.event_json).read_text())
            out = mw.handle_log_event(args.provider, event)
            print(json.dumps(out, indent=2))
        elif args.cmd == "safe-probe":
            out = mw.safe_probe(args.provider, allow_network=args.allow_probes)
            print(json.dumps(out, indent=2))
        elif args.cmd == "deploy-canary":
            out = mw.canaries.deploy_canary(args.provider, scope=args.scope)
            print(json.dumps(out, indent=2))
        elif args.cmd == "revoke-canary":
            out = mw.canaries.revoke_canary(args.canary_id)
            print(json.dumps(out, indent=2))
        elif args.cmd == "list-canaries":
            print(json.dumps(mw.canaries.registry, indent=2))
        else:
            print(json.dumps({"error": "No command provided", "ethics_notice": ETHICS_NOTICE}, indent=2))
            sys.exit(1)
    except Exception as e:
        err = {"error": str(e), "ethics_notice": ETHICS_NOTICE, "timestamp": utc_now()}
        # Store error as evidence for auditability
        try:
            mw._store_signed_evidence("error", err)
        except Exception:
            pass
        print(json.dumps(err, indent=2))
        sys.exit(2)


if __name__ == "__main__":
    main()