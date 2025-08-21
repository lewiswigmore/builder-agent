#!/usr/bin/env python3
import argparse
import json
import sys
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional cloud SDK imports guarded for graceful degradation
try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError  # type: ignore
except Exception:
    boto3 = None
    ClientError = Exception  # type: ignore
    NoCredentialsError = Exception  # type: ignore
    EndpointConnectionError = Exception  # type: ignore

# Azure/GCP placeholders (gracefully handled in collectors)
try:
    from azure.identity import DefaultAzureCredential  # type: ignore
    from azure.mgmt.authorization import AuthorizationManagementClient  # type: ignore
except Exception:
    DefaultAzureCredential = None  # type: ignore
    AuthorizationManagementClient = None  # type: ignore

try:
    from googleapiclient import discovery  # type: ignore
    from google.auth import default as gcp_default_auth  # type: ignore
    from google.auth.exceptions import DefaultCredentialsError  # type: ignore
except Exception:
    discovery = None  # type: ignore
    gcp_default_auth = None  # type: ignore
    DefaultCredentialsError = Exception  # type: ignore


ETHICAL_BANNER = (
    "Ethical use notice: This tool performs read-only analysis of cloud IAM configurations. "
    "Use only on accounts/projects/subscriptions you are explicitly authorized to assess. "
    "Do not attempt to access secrets or modify resources. Ensure testing is approved and logged."
)


############################
# Utility: Rate Limiter with backoff
############################

class RateLimiter:
    def __init__(self, rate_per_sec: float = 5.0, max_sleep: float = 2.0, retries: int = 5):
        self.lock = threading.Lock()
        self.min_interval = 1.0 / max(rate_per_sec, 0.1)
        self.last = 0.0
        self.max_sleep = max_sleep
        self.retries = retries

    def call(self, func, *args, **kwargs):
        attempt = 0
        while True:
            with self.lock:
                now = time.time()
                wait = max(0.0, self.last + self.min_interval - now)
                if wait > 0:
                    time.sleep(wait)
                self.last = time.time()
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Handle common throttling / rate-limit codes
                code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None  # type: ignore
                msg = str(e)
                if code in {"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException"} or "rate" in msg.lower():
                    if attempt >= self.retries:
                        raise
                    backoff = min(self.max_sleep, (2 ** attempt) * 0.5)
                    time.sleep(backoff)
                    attempt += 1
                    continue
                raise


############################
# Graph Model
############################

@dataclass
class Node:
    id: str
    type: str  # identity|policy|resource
    cloud: str  # aws|azure|gcp
    scope: str  # account id / subscription id / project id
    attrs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    type: str  # assume-role|act-as|role-assignment|binding|other
    attrs: Dict[str, Any] = field(default_factory=dict)


class Graph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.adj: Dict[str, List[Edge]] = defaultdict(list)

    def add_node(self, node: Node):
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge):
        if edge.src in self.nodes and edge.dst in self.nodes:
            self.adj[edge.src].append(edge)

    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def find_paths_to_admin(self) -> List[List[Edge]]:
        # Identify admin nodes
        admin_targets: Set[str] = set(nid for nid, n in self.nodes.items() if n.attrs.get("is_admin"))
        if not admin_targets:
            return []
        paths: List[List[Edge]] = []
        # Start from identities that are not admin
        start_nodes = [nid for nid, n in self.nodes.items() if n.type == "identity" and not n.attrs.get("is_admin")]
        for start in start_nodes:
            visited: Set[str] = set()
            queue: deque = deque()
            queue.append((start, []))
            visited.add(start)
            while queue:
                current, path_edges = queue.popleft()
                if current in admin_targets and path_edges:
                    paths.append(path_edges)
                    continue
                for edge in self.adj.get(current, []):
                    if edge.dst not in visited:
                        visited.add(edge.dst)
                        queue.append((edge.dst, path_edges + [edge]))
        return paths

    def to_snapshot(self) -> Dict[str, Any]:
        # Capture identities and their policy surfaces for drift detection
        identities: Dict[str, Dict[str, Any]] = {}
        for nid, n in self.nodes.items():
            if n.type == "identity":
                identities[nid] = {
                    "cloud": n.cloud,
                    "scope": n.scope,
                    "attrs": {
                        "is_admin": bool(n.attrs.get("is_admin")),
                        "inline_policies": n.attrs.get("inline_policies", {}),
                        "attached_policies": sorted(list(n.attrs.get("attached_policies", []))),
                        "trust_policy": n.attrs.get("trust_policy"),
                    },
                }
        return {"identities": identities}

    @staticmethod
    def normalize_actions_from_policy(policy_doc: Any) -> Set[str]:
        # Extract Actions from policy statements (AWS-like)
        actions: Set[str] = set()
        if not isinstance(policy_doc, dict):
            return actions
        stmts = policy_doc.get("Statement")
        if stmts is None:
            return actions
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            if str(st.get("Effect", "")).lower() != "allow":
                continue
            act = st.get("Action") or st.get("NotAction")
            if isinstance(act, list):
                for a in act:
                    actions.add(a)
            elif isinstance(act, str):
                actions.add(act)
        return actions

    @staticmethod
    def diff_snapshots(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        diffs: Dict[str, Any] = {"added_permissions": {}, "new_identities": [], "removed_identities": []}
        b_idents: Dict[str, Any] = baseline.get("identities", {})
        c_idents: Dict[str, Any] = current.get("identities", {})
        for nid in c_idents:
            if nid not in b_idents:
                diffs["new_identities"].append(nid)
        for nid in b_idents:
            if nid not in c_idents:
                diffs["removed_identities"].append(nid)
        for nid, c_data in c_idents.items():
            b_data = b_idents.get(nid)
            if not b_data:
                continue
            # Compare inline policies for added actions
            b_inline: Dict[str, Any] = b_data["attrs"].get("inline_policies", {})
            c_inline: Dict[str, Any] = c_data["attrs"].get("inline_policies", {})
            b_actions: Set[str] = set()
            for pdoc in b_inline.values():
                b_actions |= Graph.normalize_actions_from_policy(pdoc)
            c_actions: Set[str] = set()
            for pdoc in c_inline.values():
                c_actions |= Graph.normalize_actions_from_policy(pdoc)
            added_actions = sorted(list(c_actions - b_actions))
            if added_actions:
                diffs["added_permissions"][nid] = added_actions
        return diffs


############################
# Collectors
############################

class BaseCollector:
    def __init__(self, rate_limiter: RateLimiter):
        self.rate = rate_limiter
        self.missing_perms: Set[str] = set()
        self.errors: List[str] = []

    def collect(self, scopes: List[str], graph: Graph):
        raise NotImplementedError()

    def _record_perm_hint(self, perm: str):
        self.missing_perms.add(perm)

    def _record_error(self, err: str):
        self.errors.append(err)


class AWSCollector(BaseCollector):
    def __init__(self, rate_limiter: RateLimiter):
        super().__init__(rate_limiter)
        self.client = None
        self.sts = None

    def _init_clients(self):
        if boto3 is None:
            self._record_error("boto3 not available; cannot collect AWS data.")
            return
        try:
            self.client = boto3.client("iam")
            self.sts = boto3.client("sts")
        except Exception as e:
            self._record_error(f"AWS SDK initialization failed: {e}")

    def collect(self, scopes: List[str], graph: Graph):
        self._init_clients()
        if not self.client or not self.sts:
            return
        account_id = None
        try:
            ident = self.rate.call(self.sts.get_caller_identity)
            account_id = ident.get("Account")
        except NoCredentialsError:
            self._record_error("AWS credentials not found. Configure credentials for read-only collection.")
            return
        except ClientError as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code in {"AccessDenied", "AccessDeniedException"}:
                self._record_perm_hint("sts:GetCallerIdentity")
                self._record_error("Missing permission: sts:GetCallerIdentity")
                return
            self._record_error(f"AWS STS error: {e}")
            return
        except Exception as e:
            self._record_error(f"AWS STS unexpected error: {e}")
            return

        # Scope check
        if scopes and account_id not in scopes:
            self._record_error(f"Current AWS account {account_id} is not in specified scopes {scopes}; skipping.")
            return

        # Collect IAM roles
        marker = None
        roles: List[Dict[str, Any]] = []
        while True:
            try:
                if marker:
                    resp = self.rate.call(self.client.list_roles, Marker=marker)
                else:
                    resp = self.rate.call(self.client.list_roles)
                roles.extend(resp.get("Roles", []))
                if resp.get("IsTruncated"):
                    marker = resp.get("Marker")
                else:
                    break
            except ClientError as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                if code in {"AccessDenied", "AccessDeniedException"}:
                    self._record_perm_hint("iam:ListRoles")
                    self._record_error("Missing permission: iam:ListRoles")
                    return
                self._record_error(f"Error listing roles: {e}")
                return
            except EndpointConnectionError as e:
                self._record_error(f"AWS endpoint connection error: {e}")
                return

        # Build nodes and edges
        for r in roles:
            role_name = r.get("RoleName")
            role_arn = r.get("Arn")
            # Fetch full role to ensure trust policy is available
            trust_policy = None
            try:
                grole = self.rate.call(self.client.get_role, RoleName=role_name)
                trust_policy = grole.get("Role", {}).get("AssumeRolePolicyDocument")
            except ClientError as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                if code in {"AccessDenied", "AccessDeniedException"}:
                    self._record_perm_hint("iam:GetRole")
                    self._record_error(f"Missing permission: iam:GetRole for role {role_name}")
                else:
                    self._record_error(f"Error get_role {role_name}: {e}")

            # Inline policies
            inline_policies: Dict[str, Any] = {}
            try:
                resp = self.rate.call(self.client.list_role_policies, RoleName=role_name)
                for pol_name in resp.get("PolicyNames", []):
                    try:
                        pol = self.rate.call(self.client.get_role_policy, RoleName=role_name, PolicyName=pol_name)
                        doc = pol.get("PolicyDocument")
                        inline_policies[pol_name] = doc
                    except ClientError as e:
                        code = getattr(e, "response", {}).get("Error", {}).get("Code")
                        if code in {"AccessDenied", "AccessDeniedException"}:
                            self._record_perm_hint("iam:GetRolePolicy")
                            self._record_error(f"Missing permission: iam:GetRolePolicy for role {role_name}/{pol_name}")
                        else:
                            self._record_error(f"Error get_role_policy {role_name}/{pol_name}: {e}")
            except ClientError as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                if code in {"AccessDenied", "AccessDeniedException"}:
                    self._record_perm_hint("iam:ListRolePolicies")
                    self._record_error(f"Missing permission: iam:ListRolePolicies for role {role_name}")
                else:
                    self._record_error(f"Error list_role_policies {role_name}: {e}")

            # Attached policies
            attached_arns: Set[str] = set()
            attached_docs: Dict[str, Any] = {}
            try:
                marker = None
                while True:
                    if marker:
                        resp = self.rate.call(self.client.list_attached_role_policies, RoleName=role_name, Marker=marker)
                    else:
                        resp = self.rate.call(self.client.list_attached_role_policies, RoleName=role_name)
                    for ap in resp.get("AttachedPolicies", []):
                        arn = ap.get("PolicyArn")
                        attached_arns.add(arn)
                        # Try read default version doc for admin detection
                        try:
                            pol_meta = self.rate.call(self.client.get_policy, PolicyArn=arn)
                            def_ver = pol_meta.get("Policy", {}).get("DefaultVersionId")
                            if def_ver:
                                ver = self.rate.call(self.client.get_policy_version, PolicyArn=arn, VersionId=def_ver)
                                doc = ver.get("PolicyVersion", {}).get("Document")
                                if doc:
                                    attached_docs[arn] = doc
                        except ClientError as e:
                            code = getattr(e, "response", {}).get("Error", {}).get("Code")
                            if code in {"AccessDenied", "AccessDeniedException"}:
                                # These are optional for admin detection; hint perms
                                self._record_perm_hint("iam:GetPolicy")
                                self._record_perm_hint("iam:GetPolicyVersion")
                            else:
                                self._record_error(f"Error reading policy {arn}: {e}")
                    if resp.get("IsTruncated"):
                        marker = resp.get("Marker")
                    else:
                        break
            except ClientError as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                if code in {"AccessDenied", "AccessDeniedException"}:
                    self._record_perm_hint("iam:ListAttachedRolePolicies")
                    self._record_error(f"Missing permission: iam:ListAttachedRolePolicies for role {role_name}")
                else:
                    self._record_error(f"Error list_attached_role_policies {role_name}: {e}")

            # Determine admin
            is_admin = False
            # AWS managed AdministratorAccess ARN may vary per partition, check by policy name match in attached meta if available
            # Evaluate docs for wildcard permissions
            for doc in list(inline_policies.values()) + list(attached_docs.values()):
                acts = Graph.normalize_actions_from_policy(doc)
                if "*" in acts or any(a.strip().endswith(":*") for a in acts):
                    is_admin = True
                    break
            # Add node
            node = Node(
                id=f"aws:role:{account_id}:{role_name}",
                type="identity",
                cloud="aws",
                scope=account_id,
                attrs={
                    "arn": role_arn,
                    "name": role_name,
                    "is_admin": is_admin,
                    "inline_policies": inline_policies,
                    "attached_policies": list(attached_arns),
                    "attached_policy_docs": attached_docs,
                    "trust_policy": trust_policy,
                },
            )
            graph.add_node(node)

        # Build edges based on trust policies
        for nid, n in list(graph.nodes.items()):
            if n.cloud != "aws" or n.type != "identity" or not n.attrs.get("trust_policy"):
                continue
            tp = n.attrs["trust_policy"]
            stmts = tp.get("Statement")
            if isinstance(stmts, dict):
                stmts = [stmts]
            if not isinstance(stmts, list):
                continue
            for st in stmts:
                if str(st.get("Effect", "")).lower() != "allow":
                    continue
                principal = st.get("Principal") or {}
                principals: List[str] = []
                if isinstance(principal, str) and principal == "*":
                    principals.append("*")
                elif isinstance(principal, dict):
                    # Accept AWS ARN(s) principal
                    for key in ["AWS", "Federated", "Service"]:
                        val = principal.get(key)
                        if isinstance(val, list):
                            principals.extend(val)
                        elif isinstance(val, str):
                            principals.append(val)
                # Create edges from principals to this role where applicable
                for p in principals:
                    # Handle wildcard principal; model as risk edge from "any" within account
                    if p == "*":
                        # create a pseudo-node representing any principal in account
                        any_id = f"aws:any-principal:{account_id}"
                        if any_id not in graph.nodes:
                            graph.add_node(Node(id=any_id, type="identity", cloud="aws", scope=account_id, attrs={"name": "AnyPrincipalInAccount"}))
                        graph.add_edge(Edge(src=any_id, dst=nid, type="assume-role", attrs={"reason": "trust-policy-wildcard"}))
                    else:
                        # if p is ARN of role or user in same account, map to node id if exists
                        if isinstance(p, str) and p.startswith("arn:aws:iam::"):
                            parts = p.split(":")
                            p_acct = parts[4] if len(parts) > 4 else None
                            # Extract resource type/name
                            res = parts[5] if len(parts) > 5 else ""
                            # role/<name> or user/<name>
                            if res.startswith("role/"):
                                pname = res.split("/", 1)[1]
                                pid = f"aws:role:{p_acct}:{pname}"
                                # If the principal role was not listed (e.g., cross-account), still add as external identity
                                if pid not in graph.nodes:
                                    graph.add_node(Node(id=pid, type="identity", cloud="aws", scope=p_acct or "unknown", attrs={"arn": p, "external": p_acct != account_id}))
                                graph.add_edge(Edge(src=pid, dst=nid, type="assume-role", attrs={"reason": "trust-policy"}))
                            elif res.startswith("user/"):
                                uname = res.split("/", 1)[1]
                                pid = f"aws:user:{p_acct}:{uname}"
                                if pid not in graph.nodes:
                                    graph.add_node(Node(id=pid, type="identity", cloud="aws", scope=p_acct or "unknown", attrs={"arn": p, "external": p_acct != account_id}))
                                graph.add_edge(Edge(src=pid, dst=nid, type="assume-role", attrs={"reason": "trust-policy"}))


class AzureCollector(BaseCollector):
    def collect(self, scopes: List[str], graph: Graph):
        # Read-only: list role assignments and definitions to detect admin identities and act-as links
        if DefaultAzureCredential is None or AuthorizationManagementClient is None:
            self._record_error("Azure SDK not available; skipping Azure collection.")
            return
        try:
            cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        except Exception as e:
            self._record_error(f"Azure credential initialization failed: {e}")
            return

        for sub in scopes:
            try:
                client = AuthorizationManagementClient(cred, sub)
            except Exception as e:
                self._record_error(f"Azure Authorization client init failed for {sub}: {e}")
                continue
            # Collect role definitions to identify admin-level roles
            role_defs = {}
            try:
                for rd in client.role_definitions.list(scope=f"/subscriptions/{sub}"):
                    role_defs[rd.id] = {"name": rd.role_name, "permissions": [p.actions for p in rd.permissions]}
            except Exception as e:
                self._record_perm_hint("Microsoft.Authorization/roleDefinitions/read")
                self._record_error(f"Azure: cannot list role definitions in {sub}: {e}")
                continue
            # Collect role assignments
            try:
                for ra in client.role_assignments.list_for_subscription():
                    principal_id = ra.principal_id
                    role_def_id = ra.role_definition_id
                    rid = f"azure:principal:{sub}:{principal_id}"
                    if rid not in graph.nodes:
                        graph.add_node(Node(id=rid, type="identity", cloud="azure", scope=sub, attrs={"objectId": principal_id}))
                    # Determine if admin based on role name/permissions '*'
                    rdef = role_defs.get(role_def_id)
                    is_admin = False
                    if rdef:
                        name = rdef.get("name", "").lower()
                        if "owner" in name or "administrator" in name:
                            is_admin = True
                        else:
                            perms = set()
                            for acts in rdef.get("permissions", []):
                                for a in acts:
                                    perms.add(a)
                            if "*" in perms:
                                is_admin = True
                    node = graph.get_node(rid)
                    if node:
                        node.attrs["is_admin"] = bool(node.attrs.get("is_admin")) or is_admin
            except Exception as e:
                self._record_perm_hint("Microsoft.Authorization/roleAssignments/read")
                self._record_error(f"Azure: cannot list role assignments in {sub}: {e}")
                continue


class GCPCollector(BaseCollector):
    def collect(self, scopes: List[str], graph: Graph):
        if discovery is None or gcp_default_auth is None:
            self._record_error("GCP SDK not available; skipping GCP collection.")
            return
        try:
            creds, _ = gcp_default_auth(scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"])
            service = discovery.build("cloudresourcemanager", "v1", credentials=creds, cache_discovery=False)
        except DefaultCredentialsError as e:
            self._record_error(f"GCP credentials not found: {e}")
            return
        except Exception as e:
            self._record_error(f"GCP SDK init error: {e}")
            return

        for project in scopes:
            # Get IAM policy for the project to find bindings and admin roles
            try:
                req = service.projects().getIamPolicy(resource=project, body={})
                resp = req.execute()
            except Exception as e:
                self._record_perm_hint("resourcemanager.projects.getIamPolicy")
                self._record_error(f"GCP: cannot get IAM policy for {project}: {e}")
                continue
            bindings = resp.get("bindings", [])
            for b in bindings:
                role = b.get("role", "")
                members = b.get("members", [])
                is_admin = role.lower() in {"roles/owner", "roles/editor"} or role.lower().endswith("admin")
                for m in members:
                    # member can be serviceAccount:, user:, group:, etc.
                    mid = f"gcp:{m}:{project}"
                    if mid not in graph.nodes:
                        graph.add_node(Node(id=mid, type="identity", cloud="gcp", scope=project, attrs={"member": m}))
                    node = graph.get_node(mid)
                    if node:
                        node.attrs["is_admin"] = bool(node.attrs.get("is_admin")) or is_admin
            # Detect actAs-like edges from bindings granting service account token creation
            try:
                iam_service = discovery.build("iam", "v1", credentials=gcp_default_auth()[0], cache_discovery=False)
                req = iam_service.projects().serviceAccounts().list(name=f"projects/{project}")
                sas_resp = req.execute()
                for sa in sas_resp.get("accounts", []):
                    sa_email = sa.get("email")
                    said = f"gcp:serviceAccount:{project}:{sa_email}"
                    if said not in graph.nodes:
                        graph.add_node(Node(id=said, type="identity", cloud="gcp", scope=project, attrs={"email": sa_email}))
                # Simple: if member has roles/iam.serviceAccountTokenCreator on a SA, create act-as edge
                for b in bindings:
                    role = b.get("role", "")
                    if role in {"roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"}:
                        for m in b.get("members", []):
                            src = f"gcp:{m}:{project}"
                            for nid, n in list(graph.nodes.items()):
                                if n.cloud == "gcp" and n.attrs.get("email") and n.scope == project:
                                    graph.add_edge(Edge(src=src, dst=nid, type="act-as", attrs={"role": role}))
            except Exception:
                # IAM Service may not be available; ignore
                pass


############################
# Reporting and Remediation
############################

def remediation_suggestions_for_path(path: List[Edge], graph: Graph) -> List[Tuple[str, str]]:
    suggestions: List[Tuple[str, str]] = []
    # Prioritize trust-policy misconfigurations first
    for edge in path:
        if edge.type == "assume-role":
            dst_node = graph.get_node(edge.dst)
            reason = edge.attrs.get("reason", "")
            if dst_node and dst_node.cloud == "aws":
                prio = "HIGH"
                msg = (
                    f"AWS role {dst_node.attrs.get('name')} has a permissive trust policy. "
                    "Restrict the trust policy to intended principals only. Avoid wildcard principals and external accounts. "
                    "Consider adding conditions (aws:PrincipalArn, aws:SourceArn, aws:SourceAccount), requiring MFA or external IDs, "
                    "and using role session tags to enforce restrictions."
                )
                if reason == "trust-policy-wildcard":
                    msg = (
                        f"AWS role {dst_node.attrs.get('name')} trust policy allows '*' (any principal). "
                        "Replace '*' with explicit principals and add restrictive conditions. "
                        "If cross-account access is required, limit to specific ARNs and use sts:ExternalId."
                    )
                suggestions.append((prio, msg))
        elif edge.type == "act-as":
            dst_node = graph.get_node(edge.dst)
            if dst_node and dst_node.cloud == "gcp":
                suggestions.append((
                    "HIGH",
                    "GCP binding grants act-as over service accounts. Restrict roles/iam.serviceAccountUser or TokenCreator to required principals only, "
                    "or use workload identity federation with tight conditions."
                ))
        elif edge.type == "role-assignment":
            suggestions.append((
                "MEDIUM",
                "Azure role assignment allows privilege propagation. Ensure least-privilege roles and use PIM for elevated access."
            ))
    # General admin hardening
    suggestions.append((
        "MEDIUM",
        "Review attached and inline policies on admin principals. Replace wildcard permissions with specific actions and resources. Implement SCPs/Blueprints/Organization Policies to prevent privilege escalation."
    ))
    return suggestions


def print_paths(paths: List[List[Edge]], graph: Graph, out_format: str = "text"):
    if out_format == "json":
        out = []
        for path in paths:
            out.append({
                "steps": [{"src": e.src, "dst": e.dst, "type": e.type, "attrs": e.attrs} for e in path],
                "remediations": [{"priority": pr, "recommendation": msg} for pr, msg in remediation_suggestions_for_path(path, graph)],
            })
        print(json.dumps({"attack_paths": out}, indent=2))
        return

    if not paths:
        print("No attack paths to admin detected.")
        return
    print("Potential attack paths to admin detected:")
    for idx, path in enumerate(paths, 1):
        print(f"- Path {idx}:")
        for step in path:
            print(f"  * {step.type}: {step.src} -> {step.dst} ({step.attrs})")
        print("  Remediation suggestions (prioritized):")
        for prio, msg in remediation_suggestions_for_path(path, graph):
            print(f"    [{prio}] {msg}")


def print_drift(diffs: Dict[str, Any], out_format: str = "text"):
    if out_format == "json":
        print(json.dumps({"drift": diffs}, indent=2))
        return
    if not diffs["added_permissions"] and not diffs["new_identities"] and not diffs["removed_identities"]:
        print("No drift detected.")
        return
    print("IAM drift detected:")
    for nid in diffs.get("new_identities", []):
        print(f"- New identity: {nid}")
    for nid in diffs.get("removed_identities", []):
        print(f"- Removed identity: {nid}")
    for nid, actions in diffs.get("added_permissions", {}).items():
        print(f"- Added permissions for {nid}:")
        for a in actions:
            print(f"  + {a}")
    print("Remediation: Review the changes. If unintended, revert the added inline policies or reduce permissions to least privilege.")


def print_missing_perms(missing: Set[str], errors: List[str], out_format: str = "text"):
    if out_format == "json":
        print(json.dumps({"missing_permissions": sorted(list(missing)), "errors": errors}, indent=2))
        return
    if missing:
        print("Missing required read permissions detected; collection may be incomplete:")
        for p in sorted(list(missing)):
            print(f"- {p}")
        print("Suggested remediation: Grant a least-privilege read-only role limited to the specified scopes. For AWS, consider a role with permissions such as iam:ListRoles, iam:GetRole, iam:ListRolePolicies, iam:GetRolePolicy, iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion, sts:GetCallerIdentity. For Azure, grant Reader and Microsoft.Authorization/roleAssignments/read and roleDefinitions/read. For GCP, grant roles/viewer or specific resourcemanager.*.getIamPolicy permissions.")
    if errors:
        print("Errors encountered:")
        for e in errors:
            print(f"- {e}")


############################
# CLI
############################

def parse_args():
    p = argparse.ArgumentParser(description="Cloud IAM Drift Hunter & Attack Path Mapper (read-only)")
    p.add_argument("--providers", nargs="+", choices=["aws", "azure", "gcp"], default=["aws"], help="Providers to scan")
    p.add_argument("--aws-accounts", nargs="*", default=[], help="AWS account IDs to include (scoped). If empty, use current.")
    p.add_argument("--azure-subscriptions", nargs="*", default=[], help="Azure subscription IDs to include (scoped)")
    p.add_argument("--gcp-projects", nargs="*", default=[], help="GCP project IDs to include (scoped)")
    p.add_argument("--baseline", type=str, default=None, help="Path to baseline snapshot JSON")
    p.add_argument("--write-baseline", action="store_true", help="Write current snapshot to baseline path and exit")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    p.add_argument("--rate", type=float, default=5.0, help="Max API calls per second per provider")
    return p.parse_args()


def main():
    print(ETHICAL_BANNER)
    args = parse_args()
    rate = RateLimiter(rate_per_sec=args.rate)
    graph = Graph()

    all_missing: Set[str] = set()
    all_errors: List[str] = []

    if "aws" in args.providers:
        aws = AWSCollector(rate)
        aws.collect(args.aws_accounts, graph)
        all_missing |= aws.missing_perms
        all_errors.extend(aws.errors)

    if "azure" in args.providers:
        az = AzureCollector(rate)
        az.collect(args.azure_subscriptions, graph)
        all_missing |= az.missing_perms
        all_errors.extend(az.errors)

    if "gcp" in args.providers:
        gcp = GCPCollector(rate)
        gcp.collect(args.gcp_projects, graph)
        all_missing |= gcp.missing_perms
        all_errors.extend(gcp.errors)

    # If no nodes collected and there are errors/missing perms, fail gracefully
    if not graph.nodes and (all_missing or all_errors):
        print_missing_perms(all_missing, all_errors, args.output)
        sys.exit(2)

    # Baseline logic
    snapshot = graph.to_snapshot()
    if args.write_baseline:
        if not args.baseline:
            print("Error: --baseline path required with --write-baseline")
            sys.exit(1)
        with open(args.baseline, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        if args.output == "text":
            print(f"Baseline snapshot written to {args.baseline}")
        else:
            print(json.dumps({"baseline_written": args.baseline}, indent=2))
        sys.exit(0)

    # Drift detection if baseline provided
    if args.baseline:
        try:
            with open(args.baseline, "r", encoding="utf-8") as f:
                baseline = json.load(f)
            diffs = Graph.diff_snapshots(baseline, snapshot)
            print_drift(diffs, args.output)
        except FileNotFoundError:
            print(f"Baseline file not found: {args.baseline}", file=sys.stderr)
        except json.JSONDecodeError:
            print(f"Baseline file is not valid JSON: {args.baseline}", file=sys.stderr)

    # Attack path mapping
    paths = graph.find_paths_to_admin()
    print_paths(paths, graph, args.output)

    # Print missing permissions info at end if any
    if all_missing or all_errors:
        print_missing_perms(all_missing, all_errors, args.output)


if __name__ == "__main__":
    main()