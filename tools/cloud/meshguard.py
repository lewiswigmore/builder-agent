import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

ETHICAL_WARNING = (
    "MeshGuard ethical notice: audit only clusters and namespaces you are authorized to assess. "
    "Do not use findings to attempt unauthorized access. This tool is read-only by default; "
    "no changes will be applied unless explicitly approved. Privacy-preserving logging is enabled."
)

# Optional dependencies
try:
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
    from kubernetes.client import ApiException
except Exception:  # pragma: no cover - handled at runtime
    k8s_client = None
    k8s_config = None
    ApiException = Exception  # type: ignore

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except Exception:  # pragma: no cover
    x509 = None
    default_backend = None
    Ed25519PrivateKey = None  # type: ignore
    Encoding = None  # type: ignore
    PublicFormat = None  # type: ignore


def eprint(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def load_kube() -> Tuple[Optional[Any], Optional[Any], Optional[Any], Optional[Any]]:
    if k8s_client is None:
        return None, None, None, None
    try:
        # Prefer in-cluster, then kubeconfig
        try:
            k8s_config.load_incluster_config()
        except Exception:
            k8s_config.load_kube_config()
        core = k8s_client.CoreV1Api()
        apps = k8s_client.AppsV1Api()
        custom = k8s_client.CustomObjectsApi()
        version = k8s_client.VersionApi()
        return core, apps, custom, version
    except Exception as ex:  # pragma: no cover
        eprint(f"[MeshGuard] Kubernetes client initialization failed: {ex}")
        return None, None, None, None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def hash_identifier(identifier: str, salt: Optional[str] = None) -> str:
    s = salt if salt else ""
    return sha256_hex((s + "|" + identifier).encode("utf-8"))[:16]


def parse_spiffe_ns_sa(spiffe_id: str) -> Tuple[Optional[str], Optional[str]]:
    # spiffe://<trust>/ns/<namespace>/sa/<serviceaccount>
    try:
        m = re.match(r"spiffe://[^/]+/ns/([^/]+)/sa/([^/]+)$", spiffe_id)
        if m:
            return m.group(1), m.group(2)
    except Exception:
        pass
    return None, None


class MeshGuard:
    def __init__(
        self,
        namespaces: Optional[List[str]] = None,
        threshold_days: int = 30,
        dry_run: bool = True,
        trust_domain: str = "cluster.local",
        privacy_salt: Optional[str] = None,
    ):
        self.core, self.apps, self.custom, self.version = load_kube()
        self.namespaces = namespaces
        self.threshold_days = threshold_days
        self.dry_run = dry_run
        self.trust_domain = trust_domain
        self.privacy_salt = privacy_salt or sha256_hex(os.urandom(16).hex().encode("utf-8"))
        self._ethical_notice_shown = False

    def ethical_notice(self) -> None:
        if not self._ethical_notice_shown:
            eprint(ETHICAL_WARNING)
            self._ethical_notice_shown = True

    def _list_namespaces(self) -> List[str]:
        if not self.core:
            return []
        try:
            if self.namespaces:
                return self.namespaces
            ns_list = self.core.list_namespace().items
            return [n.metadata.name for n in ns_list]
        except Exception as ex:
            eprint(f"[MeshGuard] Failed to list namespaces: {ex}")
            return self.namespaces or []

    def list_pods(self, namespace: Optional[str] = None) -> List[Any]:
        if not self.core:
            return []
        try:
            if namespace:
                return self.core.list_namespaced_pod(namespace=namespace).items
            return self.core.list_pod_for_all_namespaces().items
        except Exception as ex:
            eprint(f"[MeshGuard] Failed to list pods: {ex}")
            return []

    def list_istio_authorization_policies(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.custom:
            return []
        group = "security.istio.io"
        version = "v1beta1"
        plural = "authorizationpolicies"
        try:
            if namespace:
                resp = self.custom.list_namespaced_custom_object(group, version, namespace, plural)
            else:
                resp = self.custom.list_cluster_custom_object(group, version, plural)
            items = resp.get("items", [])
            return items
        except ApiException as ex:
            if getattr(ex, "status", None) == 404:
                return []
            eprint(f"[MeshGuard] Failed to list Istio AuthorizationPolicies: {ex}")
            return []
        except Exception as ex:
            eprint(f"[MeshGuard] Error listing AuthorizationPolicies: {ex}")
            return []

    def get_namespace_labels(self) -> Dict[str, Dict[str, str]]:
        labels: Dict[str, Dict[str, str]] = {}
        if not self.core:
            return labels
        try:
            for ns in self.core.list_namespace().items:
                labels[ns.metadata.name] = ns.metadata.labels or {}
        except Exception as ex:
            eprint(f"[MeshGuard] Failed to get namespace labels: {ex}")
        return labels

    def _pod_has_sidecar(self, pod: Any) -> bool:
        try:
            containers = [c.name for c in pod.spec.containers or []]
            init_containers = [c.name for c in (pod.spec.init_containers or [])]
            names = set(containers + init_containers)
            # Common sidecar names
            for name in names:
                if name in ("istio-proxy", "linkerd-proxy") or "envoy" in name:
                    return True
            # Linkerd also sets annotation
            ann = pod.metadata.annotations or {}
            if ann.get("linkerd.io/proxy-version"):
                return True
            return False
        except Exception:
            return False

    def _pod_bypasses_mesh(self, pod: Any) -> bool:
        # Heuristics: no sidecar, or hostNetwork True, or injection disabled
        try:
            if pod.spec.host_network:
                return True
        except Exception:
            pass
        ann = (pod.metadata.annotations or {})
        if ann.get("sidecar.istio.io/inject") in ("false", "disabled", "0"):
            return True
        if not self._pod_has_sidecar(pod):
            return True
        return False

    def _build_target_workloads(self, policy: Dict[str, Any]) -> List[Dict[str, str]]:
        # Returns list of target pods metadata: ns, name, serviceaccount, spiffe
        targets: List[Dict[str, str]] = []
        ns = policy.get("metadata", {}).get("namespace", "")
        selector = (policy.get("spec", {}) or {}).get("selector", {})
        match_labels = selector.get("matchLabels", {}) if isinstance(selector, dict) else {}
        for pod in self.list_pods(ns):
            pod_labels = pod.metadata.labels or {}
            if all(pod_labels.get(k) == v for k, v in match_labels.items()):
                sa = pod.spec.service_account_name or "default"
                spiffe = f"spiffe://{self.trust_domain}/ns/{ns}/sa/{sa}"
                targets.append(
                    {
                        "namespace": ns,
                        "pod": pod.metadata.name,
                        "serviceaccount": sa,
                        "spiffe": spiffe,
                    }
                )
        # If selector empty, policy applies to all in ns; limit to distinct SA identities
        if not match_labels:
            seen_sa: set = set()
            for pod in self.list_pods(ns):
                sa = pod.spec.service_account_name or "default"
                if sa in seen_sa:
                    continue
                seen_sa.add(sa)
                spiffe = f"spiffe://{self.trust_domain}/ns/{ns}/sa/{sa}"
                targets.append(
                    {
                        "namespace": ns,
                        "pod": "*",
                        "serviceaccount": sa,
                        "spiffe": spiffe,
                    }
                )
        return targets

    def audit_authorization_policies(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        call_edges: List[Dict[str, str]] = []
        ns_list = self._list_namespaces()
        for ns in ns_list:
            policies = self.list_istio_authorization_policies(ns)
            for pol in policies:
                meta = pol.get("metadata", {})
                spec = pol.get("spec", {}) or {}
                pname = meta.get("name", "")
                pns = meta.get("namespace", ns)
                annotations = meta.get("annotations", {}) or {}
                allow_cross = annotations.get("meshguard.allowCrossNamespace", "false").lower() in ("true", "1", "yes")
                rules = spec.get("rules", []) or []

                targets = self._build_target_workloads(pol)
                if not rules:
                    # No rules => ALLOW ALL (if action is ALLOW); this is suspicious
                    action = (spec.get("action") or "").upper()
                    if action in ("", "ALLOW", None):
                        for t in targets:
                            findings.append(
                                {
                                    "id": f"istio.ap.allowall.{pns}.{pname}.{hash_identifier(t['spiffe'], self.privacy_salt)}",
                                    "type": "authorizationPolicy.misconfiguration",
                                    "severity": "high",
                                    "namespace": pns,
                                    "policy": pname,
                                    "details": {
                                        "reason": "ALLOW without rules permits all sources",
                                        "target_spiffe": t["spiffe"],
                                    },
                                    "recommendation": "Define explicit from.sources principals/namespaces or set action:DENY with allowlists.",
                                }
                            )
                    continue

                for rule in rules:
                    fr = (rule.get("from") or [])
                    to = (rule.get("to") or [])
                    # When 'from' empty, ANY source
                    if not fr:
                        for t in targets:
                            call_edges.append(
                                {
                                    "policy": pname,
                                    "namespace": pns,
                                    "source": "*",
                                    "target": t["spiffe"],
                                }
                            )
                            findings.append(
                                {
                                    "id": f"istio.ap.anysrc.{pns}.{pname}.{hash_identifier(t['spiffe'], self.privacy_salt)}",
                                    "type": "authorizationPolicy.crossNamespace",
                                    "severity": "high",
                                    "namespace": pns,
                                    "policy": pname,
                                    "details": {
                                        "reason": "Rule allows any source (from empty)",
                                        "call_graph": [{"source": "*", "target": t["spiffe"]}],
                                    },
                                    "recommendation": "Constrain from.sources principals or namespaces; avoid wildcard sources.",
                                }
                            )
                        continue
                    for frm in fr:
                        src = frm.get("source", {}) or {}
                        principals = src.get("principals", []) or []
                        namespaces = src.get("namespaces", []) or []
                        # requestPrincipals ignored for SPIFFE analysis
                        # Cross-namespace detection:
                        for t in targets:
                            # Principals specified
                            if principals:
                                for p in principals:
                                    s_ns, _ = parse_spiffe_ns_sa(p)
                                    if s_ns is None:
                                        # Not SPIFFE, record generic edge
                                        call_edges.append(
                                            {"policy": pname, "namespace": pns, "source": p, "target": t["spiffe"]}
                                        )
                                        # If wildcard principal
                                        if p == "*" or p.endswith("/ns/*/sa/*"):
                                            findings.append(
                                                {
                                                    "id": f"istio.ap.principalWildcard.{pns}.{pname}.{hash_identifier(t['spiffe'], self.privacy_salt)}",
                                                    "type": "authorizationPolicy.crossNamespace",
                                                    "severity": "high",
                                                    "namespace": pns,
                                                    "policy": pname,
                                                    "details": {
                                                        "reason": "Wildcard principal permits any namespace",
                                                        "call_graph": [{"source": p, "target": t["spiffe"]}],
                                                    },
                                                    "recommendation": "Replace wildcard principals with precise SPIFFE IDs for intended service accounts.",
                                                }
                                            )
                                        continue
                                    # SPIFFE
                                    call_edges.append(
                                        {"policy": pname, "namespace": pns, "source": p, "target": t["spiffe"]}
                                    )
                                    if s_ns != pns and not allow_cross:
                                        findings.append(
                                            {
                                                "id": f"istio.ap.crossns.{pns}.{pname}.{hash_identifier(p, self.privacy_salt)}.{hash_identifier(t['spiffe'], self.privacy_salt)}",
                                                "type": "authorizationPolicy.crossNamespace",
                                                "severity": "medium",
                                                "namespace": pns,
                                                "policy": pname,
                                                "details": {
                                                    "reason": "Rule allows cross-namespace principal without annotation meshguard.allowCrossNamespace=true",
                                                    "call_graph": [{"source": p, "target": t["spiffe"]}],
                                                    "spiffe_ids": {"source": p, "target": t["spiffe"]},
                                                },
                                                "recommendation": "Constrain source principals to the same namespace or add explicit justification annotation and audits.",
                                            }
                                        )
                            # Namespaces specified
                            if namespaces:
                                for sn in namespaces:
                                    # Edge from namespace wildcard
                                    call_edges.append(
                                        {"policy": pname, "namespace": pns, "source": f"ns:{sn}", "target": t["spiffe"]}
                                    )
                                    if sn != pns and not allow_cross:
                                        findings.append(
                                            {
                                                "id": f"istio.ap.crossnsns.{pns}.{pname}.{hash_identifier(sn, self.privacy_salt)}.{hash_identifier(t['spiffe'], self.privacy_salt)}",
                                                "type": "authorizationPolicy.crossNamespace",
                                                "severity": "medium",
                                                "namespace": pns,
                                                "policy": pname,
                                                "details": {
                                                    "reason": "Rule allows sources from another namespace without justification",
                                                    "call_graph": [{"source": f"ns:{sn}", "target": t["spiffe"]}],
                                                },
                                                "recommendation": "Restrict from.namespaces to the same namespace or justify via annotation.",
                                            }
                                        )
        # Consolidate into a report
        return {
            "category": "authorization_policy",
            "findings": findings,
            "call_graph": call_edges,
        }

    def audit_egress_bypass(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        ns_labels = self.get_namespace_labels()
        pods = self.list_pods(None if not self.namespaces else None)
        for pod in pods:
            try:
                ns = pod.metadata.namespace
                if self.namespaces and ns not in self.namespaces:
                    continue
                name = pod.metadata.name
                has_sidecar = self._pod_has_sidecar(pod)
                bypass = self._pod_bypasses_mesh(pod)
                sa = pod.spec.service_account_name or "default"
                spiffe = f"spiffe://{self.trust_domain}/ns/{ns}/sa/{sa}"
                ann = pod.metadata.annotations or {}
                ns_inject = (ns_labels.get(ns, {}) or {}).get("istio-injection")
                reasons: List[str] = []
                if ann.get("sidecar.istio.io/inject") in ("false", "disabled", "0"):
                    reasons.append("annotation sidecar.istio.io/inject disabled")
                if getattr(pod.spec, "host_network", False):
                    reasons.append("hostNetwork=true can bypass mesh")
                if not has_sidecar:
                    reasons.append("no mesh sidecar detected")
                if bypass:
                    findings.append(
                        {
                            "id": f"egress.bypass.{ns}.{hash_identifier(name, self.privacy_salt)}",
                            "type": "egress.bypass",
                            "severity": "high" if not has_sidecar else "medium",
                            "namespace": ns,
                            "workload": name,
                            "spiffe": spiffe,
                            "details": {
                                "reasons": reasons,
                                "sidecar_present": has_sidecar,
                                "namespace_injection_label": ns_inject,
                            },
                            "recommendation": "Enable sidecar auto-injection at namespace, require mesh egress via EgressGateway, and apply deny-by-default NetworkPolicies allowing only DNS and egress gateway.",
                        }
                    )
            except Exception:
                continue
        # Node-level route checks are limited; surface recommendation if any hostNetwork pods exist
        return {"category": "egress_bypass", "findings": findings}

    def _parse_pem_certs(self, pem_data: str) -> List[Any]:
        certs: List[Any] = []
        if not x509:
            return certs
        try:
            # Split multiple certs by BEGIN CERTIFICATE
            blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_data, re.DOTALL)
            for b in blocks:
                certs.append(x509.load_pem_x509_certificate(b.encode("utf-8"), default_backend()))
        except Exception:
            pass
        return certs

    def _cert_fingerprint(self, cert: Any) -> Optional[str]:
        try:
            # cryptography requires HashAlgorithm, but this may raise if wrong type is used; we fallback below
            from cryptography.hazmat.primitives import hashes  # type: ignore
            return cert.fingerprint(hashes.SHA256()).hex()  # type: ignore
        except Exception:
            try:
                # Fallback using DER bytes hashing if available
                der = cert.public_bytes(Encoding.DER)  # type: ignore
                return sha256_hex(der)
            except Exception:
                return None

    def audit_sds_and_trust(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        drift_detected = False
        expiring: List[Dict[str, Any]] = []
        unique_roots: Dict[str, List[str]] = {}  # fp -> namespaces
        ns_list = self._list_namespaces()
        for ns in ns_list:
            # Istio distributes root cert as ConfigMap istio-ca-root-cert in each ns
            try:
                cm = self.core.read_namespaced_config_map("istio-ca-root-cert", ns) if self.core else None
            except ApiException as ex:
                if getattr(ex, "status", None) == 404:
                    continue
                eprint(f"[MeshGuard] Failed to read ConfigMap istio-ca-root-cert in {ns}: {ex}")
                continue
            except Exception as ex:
                eprint(f"[MeshGuard] Error reading ConfigMap istio-ca-root-cert in {ns}: {ex}")
                continue
            if not cm or not cm.data:
                continue
            pem = cm.data.get("root-cert.pem") or cm.data.get("ca-cert.pem") or ""
            certs = self._parse_pem_certs(pem)
            for cert in certs:
                fp = self._cert_fingerprint(cert) or "unknown"
                unique_roots.setdefault(fp, []).append(ns)
                # Expiration check
                try:
                    not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)  # type: ignore
                except Exception:
                    try:
                        # cryptography>=41 name change
                        not_after = cert.not_valid_after_utc  # type: ignore
                    except Exception:
                        not_after = None
                if not_after:
                    days_left = (not_after - now_utc()).days
                    if days_left <= self.threshold_days:
                        expiring.append(
                            {
                                "namespace": ns,
                                "days_left": days_left,
                                "not_after": not_after.isoformat(),
                                "fingerprint": fp[:12],
                            }
                        )
        if len(unique_roots.keys()) > 1:
            drift_detected = True
            findings.append(
                {
                    "id": f"sds.trustbundle.drift.{hash_identifier(json.dumps(sorted(list(unique_roots.keys()))), self.privacy_salt)}",
                    "type": "sds.trustbundle.drift",
                    "severity": "high",
                    "details": {
                        "reason": "Multiple distinct root certificates detected across namespaces",
                        "unique_fingerprints": list(unique_roots.keys()),
                        "namespaces_by_fp_sample": {fp[:12]: ns[:5] for fp, ns in unique_roots.items()},
                    },
                    "recommendation": "Ensure a single, consistent trust bundle is propagated to all namespaces before rotation.",
                }
            )
        if expiring:
            for item in expiring:
                findings.append(
                    {
                        "id": f"sds.root.expiring.{item['namespace']}.{item['fingerprint']}",
                        "type": "sds.certificate.expiring",
                        "severity": "medium" if item["days_left"] > 7 else "high",
                        "namespace": item["namespace"],
                        "details": {
                            "days_left": item["days_left"],
                            "not_after": item["not_after"],
                            "fingerprint": item["fingerprint"],
                        },
                        "recommendation": f"Rotate trust bundle before expiration threshold ({self.threshold_days} days). Validate SDS continuity and overlapping trust during rotation.",
                    }
                )
        return {
            "category": "sds_trust",
            "findings": findings,
            "drift": drift_detected,
            "expiring": expiring,
        }

    def generate_canary_manifests(self, namespace: str, name: str, ttl_seconds: int = 600) -> List[Dict[str, Any]]:
        # Zero-impact: single replica, no service exposure, deny-by-default NetworkPolicy, projected SA token with short expiry
        sa_name = f"{name}-sa"
        labels = {"app": name, "meshguard.canary": "true"}
        expiration = int(time.time()) + ttl_seconds
        token_name = f"{name}-token"
        manifests: List[Dict[str, Any]] = []

        # ServiceAccount
        manifests.append(
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": sa_name, "namespace": namespace, "labels": labels},
            }
        )

        # NetworkPolicy deny all egress
        manifests.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": f"{name}-deny-egress", "namespace": namespace, "labels": labels},
                "spec": {
                    "podSelector": {"matchLabels": labels},
                    "policyTypes": ["Egress"],
                    "egress": [],  # deny-by-default
                },
            }
        )

        # Deployment
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {
                        "labels": labels,
                        "annotations": {
                            # Encourage injection
                            "sidecar.istio.io/inject": "true",
                            "meshguard.canary.expireAt": str(expiration),
                        },
                    },
                    "spec": {
                        "serviceAccountName": sa_name,
                        "containers": [
                            {
                                "name": "canary",
                                "image": "curlimages/curl:8.9.1",
                                "args": ["sleep", "3600"],
                                "resources": {"limits": {"cpu": "10m", "memory": "32Mi"}, "requests": {"cpu": "5m", "memory": "16Mi"}},
                                "volumeMounts": [{"name": token_name, "mountPath": "/var/run/secrets/tokens", "readOnly": True}],
                            }
                        ],
                        "volumes": [
                            {
                                "name": token_name,
                                "projected": {
                                    "sources": [
                                        {
                                            "serviceAccountToken": {
                                                "path": "token",
                                                "expirationSeconds": min(ttl_seconds, 3600),
                                                "audience": "meshguard",
                                            }
                                        }
                                    ]
                                },
                            }
                        ],
                    },
                },
            },
        }
        manifests.append(deployment)
        return manifests

    def apply_manifests(self, manifests: List[Dict[str, Any]], approve: bool = False) -> Dict[str, Any]:
        if not approve:
            return {"applied": False, "dry_run": True, "objects": manifests}
        if not self.core or not self.apps:
            return {"applied": False, "error": "Kubernetes client not initialized"}
        results: List[Dict[str, Any]] = []
        for obj in manifests:
            kind = obj.get("kind")
            ns = obj.get("metadata", {}).get("namespace")
            name = obj.get("metadata", {}).get("name")
            try:
                if kind == "ServiceAccount":
                    body = obj
                    try:
                        self.core.read_namespaced_service_account(name, ns)
                        self.core.patch_namespaced_service_account(name, ns, body)
                        action = "patched"
                    except ApiException as ex:
                        if getattr(ex, "status", None) == 404:
                            self.core.create_namespaced_service_account(ns, body)
                            action = "created"
                        else:
                            raise
                elif kind == "NetworkPolicy":
                    body = obj
                    try:
                        self.core.read_namespaced_config_map("dummy", ns)  # Access check
                    except Exception:
                        pass
                    net = k8s_client.NetworkingV1Api()
                    try:
                        net.read_namespaced_network_policy(name, ns)
                        net.patch_namespaced_network_policy(name, ns, body)
                        action = "patched"
                    except ApiException as ex:
                        if getattr(ex, "status", None) == 404:
                            net.create_namespaced_network_policy(ns, body)
                            action = "created"
                        else:
                            raise
                elif kind == "Deployment":
                    body = obj
                    try:
                        self.apps.read_namespaced_deployment(name, ns)
                        self.apps.patch_namespaced_deployment(name, ns, body)
                        action = "patched"
                    except ApiException as ex:
                        if getattr(ex, "status", None) == 404:
                            self.apps.create_namespaced_deployment(ns, body)
                            action = "created"
                        else:
                            raise
                else:
                    action = "skipped"
                results.append({"kind": kind, "namespace": ns, "name": name, "action": action})
            except Exception as ex:
                results.append({"kind": kind, "namespace": ns, "name": name, "error": str(ex)})
        return {"applied": True, "results": results}

    def audit(self) -> Dict[str, Any]:
        self.ethical_notice()
        report = {
            "tool": "MeshGuard",
            "version": "0.1.0",
            "generated_at": now_utc().isoformat(),
            "trust_domain": self.trust_domain,
            "namespaces": self._list_namespaces(),
            "results": [],
        }
        try:
            ap = self.audit_authorization_policies()
            report["results"].append(ap)
        except Exception as ex:
            report["results"].append({"category": "authorization_policy", "error": str(ex)})
        try:
            eg = self.audit_egress_bypass()
            report["results"].append(eg)
        except Exception as ex:
            report["results"].append({"category": "egress_bypass", "error": str(ex)})
        try:
            sds = self.audit_sds_and_trust()
            report["results"].append(sds)
        except Exception as ex:
            report["results"].append({"category": "sds_trust", "error": str(ex)})
        return report


class Attestor:
    def __init__(self, privacy_salt: Optional[str] = None):
        self.privacy_salt = privacy_salt or sha256_hex(os.urandom(16))

    def sign_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(report, sort_keys=True).encode("utf-8")
        digest = sha256_hex(payload)
        signing: Dict[str, Any] = {"digest": digest, "algorithm": "sha256"}
        # Try local Ed25519 signing for immutability guarantee
        if Ed25519PrivateKey and Encoding and PublicFormat:
            try:
                sk = Ed25519PrivateKey.generate()
                sig = sk.sign(payload)
                pk = sk.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
                signing["signature"] = b64(sig)
                signing["public_key"] = b64(pk)
                signing["scheme"] = "ed25519"
            except Exception as ex:
                signing["warning"] = f"Signing failed: {ex}"
        else:
            signing["warning"] = "cryptography not available; returning digest only"
        # Rekor upload is optional; we provide a suggested entry
        signing["rekor"] = {
            "note": "To publish to Rekor transparency log, submit digest/signature using rekor-cli with privacy-preserving metadata.",
            "privacy": "No raw resource content beyond report digest; avoid PII.",
        }
        return signing


def main() -> None:
    parser = argparse.ArgumentParser(prog="meshguard", description="MeshGuard: Service Mesh Identity & Egress Drift Auditor")
    sub = parser.add_subparsers(dest="command")

    audit_p = sub.add_parser("audit", help="Run audits against the cluster")
    audit_p.add_argument("--namespaces", help="Comma-separated namespaces to scope", default=None)
    audit_p.add_argument("--threshold-days", help="Days threshold for cert expiration alerts", type=int, default=30)
    audit_p.add_argument("--trust-domain", help="SPIFFE trust domain (default cluster.local)", default="cluster.local")
    audit_p.add_argument("--format", help="Output format json", default="json")
    audit_p.add_argument("--sign", help="Sign report", action="store_true")
    audit_p.add_argument("--dry-run", help="No changes (default)", action="store_true", default=True)

    canary_p = sub.add_parser("canary", help="Generate or apply zero-impact canary")
    canary_p.add_argument("--namespace", required=True)
    canary_p.add_argument("--name", default="meshguard-canary")
    canary_p.add_argument("--ttl", type=int, default=600)
    canary_p.add_argument("--apply", action="store_true", help="Apply manifests")
    canary_p.add_argument("--approve", action="store_true", help="Explicit approval to apply changes")

    args = parser.parse_args()

    if args.command == "audit":
        namespaces = args.namespaces.split(",") if args.namespaces else None
        guard = MeshGuard(namespaces=namespaces, threshold_days=args.threshold_days, dry_run=args.dry_run, trust_domain=args.trust_domain)
        report = guard.audit()
        if args.sign:
            att = Attestor()
            signing = att.sign_report(report)
            report["attestation"] = signing
        print(json.dumps(report, indent=2))
        return

    if args.command == "canary":
        guard = MeshGuard(dry_run=not args.apply or not args.approve)
        guard.ethical_notice()
        manifests = guard.generate_canary_manifests(args.namespace, args.name, args.ttl)
        if args.apply:
            if not args.approve:
                eprint("[MeshGuard] Apply requested but not approved; performing dry-run.")
                print(json.dumps({"dry_run": True, "objects": manifests}, indent=2))
                return
            res = guard.apply_manifests(manifests, approve=True)
            print(json.dumps(res, indent=2))
            return
        else:
            print(json.dumps({"dry_run": True, "objects": manifests}, indent=2))
            return

    parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        eprint("Interrupted by user")
    except Exception as ex:
        eprint(f"[MeshGuard] Fatal error: {ex}")