#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import errno
import glob
import hmac
import hashlib
import ipaddress
import json
import os
import secrets
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Optional crypto for encryption-at-rest
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    _HAS_AESGCM = True
except Exception:
    _HAS_AESGCM = False

# Optional network for outbound alerts (respecting allowlist)
try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False

# Optional kubernetes client
try:
    from kubernetes import client, config
    from kubernetes.client import ApiException
    _HAS_K8S = True
except Exception:
    client = None
    config = None
    ApiException = Exception
    _HAS_K8S = False

ETHICAL_WARNING = (
    "KubeIdentity Tripwire: SA Token Abuse & Lateral Movement Auditor\n"
    "IMPORTANT: Use only on clusters you are authorized to assess. This tool deploys honey service accounts,"
    " processes audit logs, and may revoke credentials upon suspected abuse. Ensure change windows and approvals,"
    " and validate egress allowlists and evidence sinks prior to use."
)

DEFAULT_RESTRICTED_NAMESPACES = ["kube-system", "kube-public", "kube-node-lease"]
DEFAULT_CLUSTER_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def utc_now_iso() -> str:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()


def mkdir_secure(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except Exception:
        pass


def write_secure_file(path: Path, data: bytes):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        fd = os.open(str(path), flags, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except OSError as e:
        if e.errno == errno.ENOENT:
            mkdir_secure(path.parent)
            fd = os.open(str(path), flags, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        else:
            raise


class EvidenceSigner:
    def __init__(self, evidence_dir: Path, signing_key_b64: Optional[str], encryption_key_b64: Optional[str]):
        self.evidence_dir = evidence_dir
        mkdir_secure(self.evidence_dir)
        # Signing key (HMAC-SHA256)
        if signing_key_b64:
            try:
                self.signing_key = base64.b64decode(signing_key_b64)
            except Exception:
                raise ValueError("Invalid base64 signing key")
        else:
            # Generate ephemeral signing key; write key-id file with strong perms
            self.signing_key = secrets.token_bytes(32)
            write_secure_file(self.evidence_dir / "ephemeral_signing.key", base64.b64encode(self.signing_key))
        self.key_id = hashlib.sha256(self.signing_key).hexdigest()[:16]
        # Optional encryption key (AES-GCM 256)
        self.encrypt_enabled = False
        self.aesgcm = None  # type: ignore
        if encryption_key_b64 and _HAS_AESGCM:
            try:
                key = base64.b64decode(encryption_key_b64)
                if len(key) not in (16, 24, 32):
                    raise ValueError("AES-GCM key must be 16/24/32 bytes")
                self.aesgcm = AESGCM(key)
                self.encrypt_enabled = True
            except Exception:
                raise ValueError("Invalid base64 encryption key or crypto backend unavailable")

    def sign(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self.signing_key, canonical, hashlib.sha256).hexdigest()
        envelope = {
            "signed_at": utc_now_iso(),
            "key_id": self.key_id,
            "payload": payload,
            "signature": sig,
            "alg": "HMAC-SHA256",
        }
        return envelope

    def seal_to_file(self, name_prefix: str, envelope: Dict[str, Any]) -> Path:
        data = json.dumps(envelope, sort_keys=True).encode("utf-8")
        if self.encrypt_enabled and self.aesgcm:
            nonce = secrets.token_bytes(12)
            ct = self.aesgcm.encrypt(nonce, data, None)
            blob = {
                "enc": "AES-GCM",
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ct).decode(),
                "key_id": self.key_id,
            }
            out = json.dumps(blob).encode("utf-8")
            suffix = ".sealed.json"
        else:
            out = data
            suffix = ".signed.json"
        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = self.evidence_dir / f"{name_prefix}-{ts}{suffix}"
        write_secure_file(path, out)
        return path


class EgressPolicy:
    def __init__(self, allowlist: List[str]):
        # allowlist items can be exact hostnames or suffix patterns starting with "."
        self.allowlist = [h.lower().strip() for h in allowlist if h.strip()]

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower()
        if not host:
            return False
        for entry in self.allowlist:
            if entry.startswith("."):
                if host.endswith(entry):
                    return True
            elif host == entry:
                return True
        return False


class KubeClient:
    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        if not _HAS_K8S:
            raise RuntimeError("kubernetes client library not available. Install 'kubernetes' package.")
        self._configure(kubeconfig, context)
        self.core = client.CoreV1Api()
        self.rbac = client.RbacAuthorizationV1Api()
        self.auth = client.AuthenticationV1Api()
        self.version = client.VersionApi()

    def _configure(self, kubeconfig: Optional[str], context: Optional[str]):
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig, context=context)
        else:
            # try incluster, fallback to default kubeconfig
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config(context=context)

    def list_namespaces(self) -> List[str]:
        ns = self.core.list_namespace()
        return [i.metadata.name for i in ns.items]

    def list_pods(self, namespace: Optional[str] = None):
        if namespace:
            return self.core.list_namespaced_pod(namespace)
        return self.core.list_pod_for_all_namespaces()

    def get_rolebindings(self, namespace: Optional[str] = None):
        if namespace:
            return self.rbac.list_namespaced_role_binding(namespace)
        return self.rbac.list_role_binding_for_all_namespaces()

    def get_clusterrolebindings(self):
        return self.rbac.list_cluster_role_binding()

    def get_role(self, namespace: str, name: str):
        return self.rbac.read_namespaced_role(name, namespace)

    def get_clusterrole(self, name: str):
        return self.rbac.read_cluster_role(name)

    def create_honey_sa(self, namespace: str, name: str, labels: Dict[str, str]) -> Dict[str, Any]:
        sa = client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(name=name, namespace=namespace, labels=labels, annotations={"kubeidentity.tripwire/honey": "true"})
        )
        self.core.create_namespaced_service_account(namespace, sa)
        return self.core.read_namespaced_service_account(name, namespace).to_dict()

    def delete_serviceaccount(self, namespace: str, name: str):
        try:
            self.core.delete_namespaced_service_account(name, namespace)
        except ApiException as e:
            if e.status != 404:
                raise

    def create_role_and_binding(self, namespace: str, role_name: str, sa_name: str):
        # Least-privileged read-only: get,list,watch on pods in namespace
        rules = [
            client.V1PolicyRule(api_groups=[""], resources=["pods"], verbs=["get", "list", "watch"]),
        ]
        role = client.V1Role(metadata=client.V1ObjectMeta(name=role_name, namespace=namespace), rules=rules)
        try:
            self.rbac.create_namespaced_role(namespace, role)
        except ApiException as e:
            if e.status != 409:
                raise
        rb = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(name=f"{role_name}-bind", namespace=namespace),
            role_ref=client.V1RoleRef(api_group="rbac.authorization.k8s.io", kind="Role", name=role_name),
            subjects=[client.V1Subject(kind="ServiceAccount", name=sa_name, namespace=namespace)],
        )
        try:
            self.rbac.create_namespaced_role_binding(namespace, rb)
        except ApiException as e:
            if e.status != 409:
                raise

    def delete_rolebinding(self, namespace: str, name: str):
        try:
            self.rbac.delete_namespaced_role_binding(name, namespace)
        except ApiException as e:
            if e.status != 404:
                raise

    def delete_role(self, namespace: str, name: str):
        try:
            self.rbac.delete_namespaced_role(name, namespace)
        except ApiException as e:
            if e.status != 404:
                raise

    def request_token(self, namespace: str, sa_name: str, audience: str, ttl_seconds: int) -> Dict[str, Any]:
        body = client.V1TokenRequest(
            spec=client.V1TokenRequestSpec(
                audiences=[audience],
                expiration_seconds=ttl_seconds
            )
        )
        tr = self.auth.create_namespaced_service_account_token(sa_name, namespace, body)
        return tr.to_dict()


class AuditLogTailer(threading.Thread):
    def __init__(self, file_path: Path, callback, poll_interval: float = 2.0):
        super().__init__(daemon=True)
        self.file_path = file_path
        self.callback = callback
        self.poll_interval = poll_interval
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        # Tail file; support log rotation by reopening if inode changes
        position = 0
        fh = None
        inode = None
        while not self._stop_evt.is_set():
            try:
                st = os.stat(self.file_path)
                if fh is None or inode != st.st_ino:
                    if fh:
                        fh.close()
                    fh = open(self.file_path, "r", encoding="utf-8")
                    inode = st.st_ino
                    position = 0
                fh.seek(position)
                lines = fh.readlines()
                if lines:
                    position = fh.tell()
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            self.callback(rec)
                        except Exception:
                            # ignore bad lines
                            pass
                else:
                    time.sleep(self.poll_interval)
            except FileNotFoundError:
                time.sleep(self.poll_interval)
            except Exception:
                time.sleep(self.poll_interval)


class KubeIdentityTripwire:
    def __init__(
        self,
        kube: KubeClient,
        evidence_signer: EvidenceSigner,
        cluster_cidrs: List[str],
        restricted_namespaces: List[str],
        honey_namespace: str,
        allowed_egress_hosts: List[str],
        alert_webhook: Optional[str],
        honey_audience: str,
        honey_ttl: int = 300,
    ):
        self.kube = kube
        self.signer = evidence_signer
        self.cluster_nets = [ipaddress.ip_network(cidr) for cidr in cluster_cidrs]
        self.restricted_ns = restricted_namespaces
        self.honey_namespace = honey_namespace
        self.egress = EgressPolicy(allowed_egress_hosts)
        self.alert_webhook = alert_webhook
        self.honey_audience = honey_audience
        self.honey_ttl = honey_ttl
        self.honey_cache: Dict[str, Dict[str, Any]] = {}  # honey_id -> {namespace,name,created_at,expires_at}

    # -------------------- Honey SA lifecycle --------------------
    def deploy_honey_service_account(self) -> Dict[str, Any]:
        honey_id = secrets.token_hex(8)
        sa_name = f"honey-sa-{honey_id}"
        labels = {"kubeidentity.tripwire/honey": "true", "kubeidentity.tripwire/id": honey_id}
        sa = self.kube.create_honey_sa(self.honey_namespace, sa_name, labels)
        role_name = f"honey-ro-{honey_id}"
        self.kube.create_role_and_binding(self.honey_namespace, role_name, sa_name)
        token = self.kube.request_token(self.honey_namespace, sa_name, self.honey_audience, self.honey_ttl)
        created_at = utc_now_iso()
        expires_at = (dt.datetime.utcnow() + dt.timedelta(seconds=self.honey_ttl)).replace(tzinfo=dt.timezone.utc).isoformat()
        credential_meta = {
            "honey_id": honey_id,
            "namespace": self.honey_namespace,
            "service_account": sa_name,
            "audience": self.honey_audience,
            "created_at": created_at,
            "expires_at": expires_at,
            "token_sha256": hashlib.sha256(token.get("status", {}).get("token", "").encode()).hexdigest(),
            "note": "Token value is not stored to avoid secret exfiltration.",
        }
        envelope = self.signer.sign({"type": "honey_credential_issued", "credential": credential_meta})
        path = self.signer.seal_to_file(f"honey-cred-{honey_id}", envelope)
        self.honey_cache[honey_id] = {
            "namespace": self.honey_namespace,
            "service_account": sa_name,
            "role": role_name,
            "created_at": created_at,
            "expires_at": expires_at,
            "evidence_path": str(path),
        }
        return {"honey_id": honey_id, "service_account": sa_name, "namespace": self.honey_namespace, "evidence": str(path)}

    def rotate_expired_honey(self):
        now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
        to_rotate = []
        for hid, meta in list(self.honey_cache.items()):
            try:
                exp = dt.datetime.fromisoformat(meta["expires_at"])
            except Exception:
                continue
            if exp <= now:
                to_rotate.append(hid)
        for hid in to_rotate:
            try:
                self.revoke_honey(hid, reason="expired_rotation")
            except Exception:
                pass
            # deploy new honey
            self.deploy_honey_service_account()

    def revoke_honey(self, honey_id: str, reason: str):
        meta = self.honey_cache.get(honey_id)
        if not meta:
            return
        ns = meta["namespace"]
        sa = meta["service_account"]
        role = meta.get("role")
        self.kube.delete_serviceaccount(ns, sa)
        if role:
            self.kube.delete_rolebinding(ns, f"{role}-bind")
            self.kube.delete_role(ns, role)
        event = {
            "type": "honey_revoked",
            "honey_id": honey_id,
            "namespace": ns,
            "service_account": sa,
            "reason": reason,
            "revoked_at": utc_now_iso(),
        }
        env = self.signer.sign(event)
        self.signer.seal_to_file(f"honey-revoke-{honey_id}", env)
        try:
            del self.honey_cache[honey_id]
        except KeyError:
            pass

    # -------------------- Audit correlation --------------------
    def _ip_is_external(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return True
        for net in self.cluster_nets:
            if addr in net:
                return False
        # RFC1918 + RFC4193 + loopback considered internal
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
        return True

    def _send_webhook_if_allowed(self, doc: Dict[str, Any]):
        if not self.alert_webhook:
            return
        if not _HAS_REQUESTS:
            return
        host = urlparse(self.alert_webhook).hostname or ""
        if not self.egress.host_allowed(host):
            return
        headers = {"Content-Type": "application/json"}
        try:
            requests.post(self.alert_webhook, headers=headers, data=json.dumps(doc), timeout=5)
        except Exception:
            pass

    def handle_audit_record(self, record: Dict[str, Any]):
        # Expect k8s audit event structure
        user = record.get("user", {}) or record.get("user", {})
        username = user.get("username", "")
        source_ips = record.get("sourceIPs") or record.get("sourceIPs", [])
        if not username or not source_ips:
            return
        # If matches any honey SA
        for hid, meta in list(self.honey_cache.items()):
            sa_fq = f"system:serviceaccount:{meta['namespace']}:{meta['service_account']}"
            if username == sa_fq:
                # check external source IP
                external_ips = [ip for ip in source_ips if self._ip_is_external(ip)]
                if external_ips:
                    abuse = {
                        "type": "honey_sa_abuse_detected",
                        "honey_id": hid,
                        "service_account_fq": sa_fq,
                        "source_ips": source_ips,
                        "external_ips": external_ips,
                        "requestURI": record.get("requestURI"),
                        "verb": record.get("verb"),
                        "stage": record.get("stage"),
                        "userAgent": record.get("userAgent"),
                        "received_at": utc_now_iso(),
                    }
                    env = self.signer.sign(abuse)
                    path = self.signer.seal_to_file(f"honey-abuse-{hid}", env)
                    # Auto-revoke abused credentials
                    self.revoke_honey(hid, reason="abuse_detected")
                    # Send minimal alert with no secrets
                    alert_doc = {
                        "alert": "KubeIdentityTripwire::HoneySAAbuse",
                        "honey_id": hid,
                        "service_account": sa_fq,
                        "external_ips": external_ips,
                        "evidence": str(path),
                        "time": utc_now_iso(),
                    }
                    self._send_webhook_if_allowed(alert_doc)

    def monitor_audit_file(self, audit_file: Path) -> AuditLogTailer:
        tailer = AuditLogTailer(audit_file, self.handle_audit_record, poll_interval=2.0)
        tailer.start()
        return tailer

    # -------------------- Posture scanning & RBAC analysis --------------------
    def scan_pods_automount(self, namespaces: Optional[List[str]] = None) -> Dict[str, Any]:
        report: Dict[str, Any] = {"scanned_at": utc_now_iso(), "findings": []}
        target_ns = set(namespaces or self.restricted_ns)
        pods = self.kube.list_pods()
        for p in pods.items:
            ns = p.metadata.namespace
            if ns not in target_ns:
                continue
            automount = p.spec.automount_service_account_token
            # If None, SA or namespace default applies - treat as risky
            if automount is True or automount is None:
                finding = {
                    "namespace": ns,
                    "pod": p.metadata.name,
                    "service_account": p.spec.service_account_name or "default",
                    "automountServiceAccountToken": automount if automount is not None else "inherited",
                    "severity": "medium" if automount is None else "high",
                }
                finding["remediation"] = self._build_automount_remediation(p)
                finding["rbac_review"] = self._least_privilege_rbac_suggestion(ns, p.spec.service_account_name or "default")
                report["findings"].append(finding)
        return report

    def _build_automount_remediation(self, pod) -> Dict[str, Any]:
        # Provide patch diffs for Pod and ServiceAccount
        sa_name = pod.spec.service_account_name or "default"
        pod_patch = {
            "op": "add",
            "path": "/spec/automountServiceAccountToken",
            "value": False
        }
        sa_patch = {
            "op": "add",
            "path": "/automountServiceAccountToken",
            "value": False
        }
        return {
            "pod_patch_jsonpatch": [pod_patch],
            "serviceaccount_annotation": {"metadata": {"annotations": {"kubernetes.io/enforce-mountable-secrets": "true"}}},
            "serviceaccount_patch_strategic": sa_patch,
            "notes": "Prefer setting automountServiceAccountToken: false on Pod spec. Alternatively disable on ServiceAccount."
        }

    def _least_privilege_rbac_suggestion(self, namespace: str, sa_name: str) -> Dict[str, Any]:
        # Analyze current bindings and suggest get/list/watch only on pods
        broad_rules: List[Dict[str, Any]] = []
        try:
            # Namespaced RoleBindings
            rbs = self.kube.get_rolebindings()
            for rb in rbs.items:
                for subj in (rb.subjects or []):
                    if subj.kind == "ServiceAccount" and subj.name == sa_name and subj.namespace == namespace:
                        # Resolve role rules
                        try:
                            role = self.kube.get_role(rb.metadata.namespace, rb.role_ref.name)
                            for r in role.rules or []:
                                if ("*" in (r.verbs or [])) or ("*" in (r.resources or [])) or ("*" in (r.api_groups or [])):
                                    broad_rules.append({"binding": rb.metadata.name, "namespace": rb.metadata.namespace, "rule": role.to_dict()})
                        except Exception:
                            pass
            # ClusterRoleBindings
            crbs = self.kube.get_clusterrolebindings()
            for rb in crbs.items:
                for subj in (rb.subjects or []):
                    if subj.kind == "ServiceAccount" and subj.name == sa_name and subj.namespace == namespace:
                        try:
                            cr = self.kube.get_clusterrole(rb.role_ref.name)
                            for r in cr.rules or []:
                                if ("*" in (r.verbs or [])) or ("*" in (r.resources or [])) or ("*" in (r.api_groups or [])):
                                    broad_rules.append({"binding": rb.metadata.name, "cluster": True, "rule": cr.to_dict()})
                        except Exception:
                            pass
        except Exception:
            pass
        suggestion_role = {
            "kind": "Role",
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "metadata": {"name": f"lp-{sa_name}", "namespace": namespace},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}],
        }
        suggestion_rb = {
            "kind": "RoleBinding",
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "metadata": {"name": f"lp-{sa_name}-bind", "namespace": namespace},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": f"lp-{sa_name}"},
            "subjects": [{"kind": "ServiceAccount", "name": sa_name, "namespace": namespace}],
        }
        return {"broad_bindings": broad_rules, "suggested_role": suggestion_role, "suggested_rolebinding": suggestion_rb}

    def scan_token_audiences(self, namespaces: Optional[List[str]] = None) -> Dict[str, Any]:
        target_ns = set(namespaces or self.restricted_ns)
        report: Dict[str, Any] = {"scanned_at": utc_now_iso(), "audience_findings": []}
        pods = self.kube.list_pods()
        for p in pods.items:
            ns = p.metadata.namespace
            if ns not in target_ns:
                continue
            # Inspect projected serviceAccountToken volumes
            projected = [v for v in (p.spec.volumes or []) if v.projected and v.projected.sources]
            for vol in projected:
                for src in vol.projected.sources:
                    sat = getattr(src, "service_account_token", None)
                    if sat is None:
                        continue
                    audience = getattr(sat, "audience", None)
                    missing = audience is None or str(audience).strip() == ""
                    overly_broad = isinstance(audience, str) and audience.strip() in ("*", "any", "all")
                    if missing or overly_broad:
                        rec = {
                            "namespace": ns,
                            "pod": p.metadata.name,
                            "volume": vol.name,
                            "audience": audience if audience is not None else "(default)",
                            "issue": "missing" if missing else "overly_broad",
                            "recommendation": f"Set audience to a constrained value such as '{self.honey_audience}'",
                        }
                        report["audience_findings"].append(rec)
        return report

    # --------------- Command runners ---------------
    def run_scan(self, namespaces: Optional[List[str]] = None):
        posture = self.scan_pods_automount(namespaces=namespaces)
        audiences = self.scan_token_audiences(namespaces=namespaces)
        output = {"posture": posture, "audiences": audiences, "generated_at": utc_now_iso()}
        print(json.dumps(output, indent=2))

    def run_deploy_honey(self):
        res = self.deploy_honey_service_account()
        # Output minimal info; never print tokens
        print(json.dumps({"deployed": res, "generated_at": utc_now_iso()}, indent=2))

    def run_monitor(self, audit_file: Path):
        tailer = self.monitor_audit_file(audit_file)
        try:
            while True:
                # Rotate honey if needed
                self.rotate_expired_honey()
                time.sleep(5)
        except KeyboardInterrupt:
            tailer.stop()

    def run_all(self, audit_file: Path, namespaces: Optional[List[str]] = None):
        # Deploy honey SA if none
        if not self.honey_cache:
            self.deploy_honey_service_account()
        tailer = self.monitor_audit_file(audit_file)
        try:
            while True:
                self.rotate_expired_honey()
                # Periodic scan
                self.run_scan(namespaces=namespaces)
                time.sleep(30)
        except KeyboardInterrupt:
            tailer.stop()


def parse_args():
    p = argparse.ArgumentParser(description="KubeIdentity Tripwire: SA Token Abuse & Lateral Movement Auditor")
    p.add_argument("--kubeconfig", default=os.environ.get("KUBECONFIG"))
    p.add_argument("--context", default=None)
    p.add_argument("--restricted-namespaces", default=os.environ.get("RESTRICTED_NAMESPACES", ",".join(DEFAULT_RESTRICTED_NAMESPACES)))
    p.add_argument("--cluster-cidrs", default=os.environ.get("CLUSTER_CIDRS", ",".join(DEFAULT_CLUSTER_CIDRS)))
    p.add_argument("--honey-namespace", default=os.environ.get("HONEY_NAMESPACE", "default"))
    p.add_argument("--evidence-dir", default=os.environ.get("EVIDENCE_DIR", "/var/run/kubeidentity-tripwire/evidence"))
    p.add_argument("--signing-key-b64", default=os.environ.get("KUBE_TRIPWIRE_SIGNING_KEY"))
    p.add_argument("--encryption-key-b64", default=os.environ.get("KUBE_TRIPWIRE_EVIDENCE_KEY"))
    p.add_argument("--allowed-egress-hosts", default=os.environ.get("ALLOWED_EGRESS_HOSTS", "").strip())
    p.add_argument("--alert-webhook", default=os.environ.get("ALERT_WEBHOOK"))
    p.add_argument("--honey-audience", default=os.environ.get("HONEY_AUDIENCE", "kubeidentity.tripwire.local"))
    p.add_argument("--honey-ttl", type=int, default=int(os.environ.get("HONEY_TTL", "300")))
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="Scan cluster posture and token audiences")

    sub.add_parser("deploy-honey", help="Deploy a honey ServiceAccount and issue a projected token")

    mon = sub.add_parser("monitor", help="Monitor audit logs for honey SA misuse")
    mon.add_argument("--audit-file", required=True, help="Path to Kubernetes audit log JSON file")

    runall = sub.add_parser("run-all", help="Deploy honey and continuously monitor and scan")
    runall.add_argument("--audit-file", required=True, help="Path to Kubernetes audit log JSON file")

    return p.parse_args()


def main():
    print(ETHICAL_WARNING, file=sys.stderr)
    args = parse_args()
    restricted_ns = [n.strip() for n in args.restricted_namespaces.split(",") if n.strip()]
    cluster_cidrs = [c.strip() for c in args.cluster_cidrs.split(",") if c.strip()]
    allowed_egress_hosts = [h.strip() for h in args.allowed_egress_hosts.split(",") if h.strip()]
    evidence_dir = Path(args.evidence_dir)
    signer = EvidenceSigner(evidence_dir, args.signing_key_b64, args.encryption_key_b64)

    kube = KubeClient(args.kubeconfig, args.context)
    tripwire = KubeIdentityTripwire(
        kube=kube,
        evidence_signer=signer,
        cluster_cidrs=cluster_cidrs,
        restricted_namespaces=restricted_ns,
        honey_namespace=args.honey_namespace,
        allowed_egress_hosts=allowed_egress_hosts,
        alert_webhook=args.alert_webhook,
        honey_audience=args.honey_audience,
        honey_ttl=args.honey_ttl,
    )

    if args.cmd == "scan":
        tripwire.run_scan(namespaces=restricted_ns)
    elif args.cmd == "deploy-honey":
        tripwire.run_deploy_honey()
    elif args.cmd == "monitor":
        tripwire.run_monitor(Path(args.audit_file))
    elif args.cmd == "run-all":
        tripwire.run_all(Path(args.audit_file), namespaces=restricted_ns)
    else:
        print("Unknown command", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
            # High-level error handling with ethical logging
            msg = {
                "error": str(e),
                "time": utc_now_iso(),
                "note": "Ensure you have authorization and correct permissions. No secrets have been exfiltrated.",
            }
            print(json.dumps(msg, indent=2), file=sys.stderr)
            sys.exit(1)