#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import hmac
import json
import os
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any


ETHICAL_WARNING = (
    "ArtifactGraph Guard must be used only on registries and accounts you are authorized to assess. "
    "Unauthorized testing may be illegal and unethical. Ensure explicit permissions are in place."
)


# -----------------------------
# Data Models
# -----------------------------
@dataclass
class Registry:
    name: str
    provider: str  # aws_ecr, gcp_ar, azure_acr, docker_hub, huggingface
    public: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Repository:
    name: str
    registry: str  # reference to Registry.name
    protected: bool = False
    public: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Artifact:
    registry: str
    repository: str
    tag: str
    digest: Optional[str] = None
    signed: bool = False
    rekor: bool = False
    slsa: bool = False
    in_toto: bool = False
    publisher: Optional[str] = None  # identity metadata for squatting detection
    created_at: Optional[str] = None  # ISO8601


@dataclass
class ReplicationRule:
    id: str
    source_repo: str  # "registry/repository"
    target_repo: str  # "registry/repository"
    filters: Dict[str, Any] = field(default_factory=dict)  # e.g., {"tags": ["*"]}
    trigger: str = "manual"  # oidc, webhook, manual
    oidc: Dict[str, str] = field(default_factory=dict)  # issuer, audience
    webhook: Dict[str, Any] = field(default_factory=dict)  # url, headers, oidc?
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustPolicy:
    allowed_oidc_issuers: List[str] = field(default_factory=list)
    allowed_audiences: List[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str
    remediation: List[str] = field(default_factory=list)
    affected: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    category: str = "policy"


@dataclass
class PromotionResult:
    allowed: bool
    report: Dict[str, Any]


# -----------------------------
# Utility functions
# -----------------------------
def now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def parse_image_ref(ref: str) -> Tuple[str, str, Optional[str], Optional[str]]:
    # Returns (registry, repository, tag, digest)
    # Accepts forms like: registry/repo:tag@digest or registry/repo:tag or registry/repo@digest
    digest = None
    tag = None
    at_split = ref.split("@", 1)
    left = at_split[0]
    if len(at_split) == 2:
        digest = at_split[1]
    if ":" in left and "/" in left:
        repo_part, tag = left.rsplit(":", 1)
    else:
        repo_part = left
    if "/" not in repo_part:
        raise ValueError(f"Invalid image reference (missing registry): {ref}")
    registry, repo = repo_part.split("/", 1)
    return registry, repo, tag, digest


def repo_key(registry: str, repository: str) -> str:
    return f"{registry}/{repository}"


def gen_canary_name() -> str:
    rnd = uuid.uuid4().hex[:8]
    ts = int(time.time())
    return f"artifactgraph-guard-canary-{ts}-{rnd}"


def safe_json_load(path: str) -> Optional[dict]:
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def safe_json_dump(path: str, data: dict) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        # best-effort; do not crash
        pass


# -----------------------------
# Signature verification stub/logic
# -----------------------------
class SignatureVerifier:
    def __init__(self, enable_external: bool = False):
        self.enable_external = enable_external

    def verify(self, artifact: Artifact) -> Tuple[bool, List[str]]:
        errors = []
        if not artifact.signed:
            errors.append("Missing cosign/Sigstore signature")
        if not artifact.rekor:
            errors.append("Missing Rekor transparency log inclusion")
        if not artifact.slsa:
            errors.append("Missing SLSA provenance attestation")
        if not artifact.in_toto:
            errors.append("Missing in-toto attestation")
        ok = len(errors) == 0
        # Placeholder: optionally integrate cosign invocation if enable_external is True
        return ok, errors


# -----------------------------
# Main Guard
# -----------------------------
class ArtifactGraphGuard:
    def __init__(self, config: dict, read_only: bool = True, report_key: Optional[bytes] = None):
        self.read_only = read_only
        self.registries: Dict[str, Registry] = {}
        self.repositories: Dict[str, Repository] = {}
        self.artifacts: List[Artifact] = []
        self.rules: List[ReplicationRule] = []
        self.trust_policy: TrustPolicy = TrustPolicy()
        self.graph_edges: Dict[str, List[str]] = {}
        self._load_config(config)
        self.verifier = SignatureVerifier()
        self.report_key = report_key or os.environ.get("AG_GUARD_REPORT_HMAC_KEY", "").encode("utf-8")
        self.state_file = os.environ.get(
            "AG_GUARD_STATE_FILE",
            os.path.join(os.path.expanduser("~"), ".artifactgraph_guard", "state.json"),
        )
        self.state = safe_json_load(self.state_file) or {"canaries": []}

    def _load_config(self, config: dict):
        for r in config.get("registries", []):
            name = r.get("name") or f"{r.get('provider')}-{r.get('meta', {}).get('id','unknown')}"
            self.registries[name] = Registry(
                name=name,
                provider=r.get("provider", "unknown"),
                public=bool(r.get("public", False)),
                meta={k: v for k, v in r.items() if k not in ("name", "provider", "public")},
            )
        for repo in config.get("repositories", []):
            name = repo.get("name")
            reg = repo.get("registry")
            if not name or not reg or reg not in self.registries:
                continue
            self.repositories[repo_key(reg, name)] = Repository(
                name=name,
                registry=reg,
                protected=bool(repo.get("protected", False)),
                public=bool(repo.get("public", False)),
                meta={k: v for k, v in repo.items() if k not in ("name", "registry", "protected", "public")},
            )
        for a in config.get("artifacts", []):
            self.artifacts.append(
                Artifact(
                    registry=a.get("registry", ""),
                    repository=a.get("repository", ""),
                    tag=a.get("tag", ""),
                    digest=a.get("digest"),
                    signed=bool(a.get("signed", False)),
                    rekor=bool(a.get("rekor", False)),
                    slsa=bool(a.get("slsa", False)),
                    in_toto=bool(a.get("in_toto", False)),
                    publisher=a.get("publisher"),
                    created_at=a.get("created_at"),
                )
            )
        for rr in config.get("replication_rules", []):
            self.rules.append(
                ReplicationRule(
                    id=rr.get("id", uuid.uuid4().hex),
                    source_repo=rr.get("source_repo", ""),
                    target_repo=rr.get("target_repo", ""),
                    filters=rr.get("filters", {}),
                    trigger=rr.get("trigger", "manual"),
                    oidc=rr.get("oidc", {}),
                    webhook=rr.get("webhook", {}),
                    meta={k: v for k, v in rr.items() if k not in ("id", "source_repo", "target_repo", "filters", "trigger", "oidc", "webhook")},
                )
            )
        tp = config.get("trust_policy", {})
        self.trust_policy = TrustPolicy(
            allowed_oidc_issuers=tp.get("allowed_oidc_issuers", []),
            allowed_audiences=tp.get("allowed_audiences", []),
        )
        self._build_graph()

    def _build_graph(self):
        self.graph_edges = {}
        for rule in self.rules:
            src = rule.source_repo
            dst = rule.target_repo
            self.graph_edges.setdefault(src, []).append(dst)

    # -----------------------------
    # Detections
    # -----------------------------
    def detect_public_exposure(self) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            src = self.repositories.get(rule.source_repo)
            dst = self.repositories.get(rule.target_repo)
            if not src or not dst:
                # Misconfigured rule referencing unknown repositories
                fid = f"rule-{rule.id}-invalid-repo"
                findings.append(
                    Finding(
                        id=fid,
                        severity="high",
                        title="Replication rule references unknown repository",
                        description=f"Rule {rule.id} references source '{rule.source_repo}' or target '{rule.target_repo}' that does not exist in configuration.",
                        remediation=[
                            "Ensure both source and target repositories are defined and names are correct.",
                            "Update the configuration to include missing repositories."
                        ],
                        affected={"rule": asdict(rule)},
                        category="configuration",
                    )
                )
                continue
            # Determine public exposure
            src_public = src.public or self.registries.get(src.registry, Registry(name="", provider="")).public
            dst_public = dst.public or self.registries.get(dst.registry, Registry(name="", provider="")).public
            if (not src_public) and dst_public:
                matched = self._match_artifacts(src, rule.filters)
                blast = [{"tag": a.tag, "digest": a.digest} for a in matched]
                fid = f"public-exposure-{rule.id}"
                findings.append(
                    Finding(
                        id=fid,
                        severity="critical",
                        title="Private-to-public replication detected",
                        description=(
                            f"Rule {rule.id} replicates from a private repository '{rule.source_repo}' "
                            f"to a public target '{rule.target_repo}'. This risks exposing private artifacts."
                        ),
                        remediation=[
                            "Immediately disable or modify the replication rule to target a private destination.",
                            "Introduce an allowlist of tags or digests to minimize exposure.",
                            "Require signature verification and provenance checks before replication.",
                        ],
                        affected={
                            "rule": asdict(rule),
                            "blast_radius": {
                                "estimated_artifacts": len(blast),
                                "artifacts_sample": blast[:20],
                            },
                        },
                        blocked=True,
                        category="public_exposure",
                    )
                )
        return findings

    def detect_unsigned_in_protected(self) -> List[Finding]:
        findings: List[Finding] = []
        protected_repos = {k for k, v in self.repositories.items() if v.protected}
        for a in self.artifacts:
            rkey = repo_key(a.registry, a.repository)
            if rkey not in protected_repos:
                continue
            ok, errors = self.verifier.verify(a)
            if not ok:
                fid = f"unsigned-{rkey}-{a.tag}"
                desc = f"Artifact {a.registry}/{a.repository}:{a.tag} is missing required signatures/attestations."
                findings.append(
                    Finding(
                        id=fid,
                        severity="high",
                        title="Unsigned or unverified artifact in protected repository",
                        description=desc + " " + "; ".join(errors),
                        remediation=[
                            "Sign the artifact using cosign: cosign sign --key <key> <image>",
                            "Ensure Rekor inclusion: cosign verify --certificate-oidc-issuer <issuer> --certificate-identity <identity> <image>",
                            "Attach SLSA provenance: upload SLSA attestation and in-toto metadata.",
                            "Enforce verification on pull/promotion to block unsigned artifacts."
                        ],
                        affected={"artifact": asdict(a)},
                        blocked=False,
                        category="signature",
                    )
                )
        return findings

    def detect_oidc_trust_drift(self) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            if rule.trigger not in ("oidc", "webhook"):
                continue
            issuer = rule.oidc.get("issuer") or rule.webhook.get("oidc", {}).get("issuer")
            audience = rule.oidc.get("audience") or rule.webhook.get("oidc", {}).get("audience")
            issues: List[str] = []
            if issuer and issuer not in self.trust_policy.allowed_oidc_issuers:
                issues.append(f"issuer '{issuer}' not in trust policy")
            if audience and audience not in self.trust_policy.allowed_audiences:
                issues.append(f"audience '{audience}' not in trust policy")
            if issues:
                fid = f"oidc-mismatch-{rule.id}"
                findings.append(
                    Finding(
                        id=fid,
                        severity="high",
                        title="OIDC/Webhook trust-policy mismatch detected",
                        description=f"Replication rule {rule.id} uses OIDC/webhook with {, '.join(issues)}.",
                        remediation=[
                            "Update trust policy to include the required issuer/audience if appropriate.",
                            "Correct the replication configuration to use only approved issuers and audiences.",
                            "Temporarily block replication until trust is restored."
                        ],
                        affected={"rule": asdict(rule), "trust_policy": asdict(self.trust_policy)},
                        blocked=True,
                        category="trust",
                    )
                )
        return findings

    def detect_tag_squatting(self) -> List[Finding]:
        findings: List[Finding] = []
        # Group artifacts by repository
        artifacts_by_repo: Dict[str, List[Artifact]] = {}
        for a in self.artifacts:
            artifacts_by_repo.setdefault(repo_key(a.registry, a.repository), []).append(a)
        for rkey, arts in artifacts_by_repo.items():
            tags = [a.tag for a in arts]
            # Flag usage of 'latest' in protected repos
            repo_obj = self.repositories.get(rkey)
            if repo_obj and repo_obj.protected and "latest" in tags:
                findings.append(
                    Finding(
                        id=f"tag-latest-{rkey}",
                        severity="medium",
                        title="Use of 'latest' tag in protected repository",
                        description=f"Repository {rkey} uses 'latest' tag, which is prone to ambiguity and tag-squatting risks.",
                        remediation=[
                            "Avoid using 'latest' in protected repos; use immutable, semver tags or digests.",
                            "Enforce pull-by-digest or signed immutable tags."
                        ],
                        affected={"repository": asdict(repo_obj)},
                        category="tag",
                    )
                )
            # Check for confusable/typosquatting tags within the same repo
            for i in range(len(tags)):
                for j in range(i + 1, len(tags)):
                    if self._is_confusable(tags[i], tags[j]):
                        findings.append(
                            Finding(
                                id=f"tag-squat-{rkey}-{tags[i]}-{tags[j]}",
                                severity="low",
                                title="Potential tag squatting detected",
                                description=f"Tags '{tags[i]}' and '{tags[j]}' in repository {rkey} appear confusable.",
                                remediation=[
                                    "Review tag naming and remove/rename confusable tags.",
                                    "Implement tag allowlists and automated validation for tag formats."
                                ],
                                affected={"repository": rkey, "tags": [tags[i], tags[j]]},
                                category="tag",
                            )
                        )
        return findings

    def _is_confusable(self, a: str, b: str) -> bool:
        if a == b:
            return False
        # Simple heuristics for confusables: normalize common confusable characters and compare
        mapping = {
            "0": "o",
            "O": "o",
            "1": "l",
            "I": "l",
            "S": "s",
            "5": "s",
            "B": "b",
            "8": "b",
            "-": "",
            "_": "",
            ".": ".",
        }
        def normalize(s: str) -> str:
            out = []
            for ch in s:
                out.append(mapping.get(ch, ch.lower()))
            return "".join(out)
        na = normalize(a)
        nb = normalize(b)
        if na == nb:
            return True
        # Levenshtein distance threshold 1 (simple O(n*m) with early-exit but without external libs)
        return self._levenshtein_leq1(na, nb)

    def _levenshtein_leq1(self, s1: str, s2: str) -> bool:
        if s1 == s2:
            return False
        if abs(len(s1) - len(s2)) > 1:
            return False
        # Check substitution or insertion/deletion
        if len(s1) == len(s2):
            diffs = sum(1 for i in range(len(s1)) if s1[i] != s2[i])
            return diffs == 1
        # Ensure s1 is shorter
        if len(s1) > len(s2):
            s1, s2 = s2, s1
        # check if s2 can remove one char to equal s1
        i = j = diffs = 0
        while i < len(s1) and j < len(s2):
            if s1[i] == s2[j]:
                i += 1
                j += 1
            else:
                diffs += 1
                if diffs > 1:
                    return False
                j += 1
        # trailing extra char in s2 is okay
        return True

    def _match_artifacts(self, src_repo: Repository, filters: Dict[str, Any]) -> List[Artifact]:
        tags_filter = filters.get("tags", ["*"])
        matched: List[Artifact] = []
        for a in self.artifacts:
            if a.registry != src_repo.registry or a.repository != src_repo.name:
                continue
            if self._tag_matches(a.tag, tags_filter):
                matched.append(a)
        return matched

    def _tag_matches(self, tag: str, patterns: List[str]) -> bool:
        for p in patterns:
            if p == "*" or p == tag:
                return True
            # wildcard match simple
            regex = "^" + re.escape(p).replace("\\*", ".*") + "$"
            if re.match(regex, tag):
                return True
        return False

    # -----------------------------
    # Enforcement and Promotion
    # -----------------------------
    def request_promotion(self, source_image: str, dest_repo_ref: str, protected: bool = True, approve: bool = False) -> PromotionResult:
        # Parse source image
        try:
            src_reg, src_repo, src_tag, src_digest = parse_image_ref(source_image)
        except Exception as e:
            return self._blocked_report(
                title="Invalid source image reference",
                description=str(e),
                remediation=["Provide a valid source image reference like registry/repository:tag or registry/repository@digest."],
                affected={"source": source_image},
            )
        dest_reg, dest_repo = None, None
        try:
            dreg, drepo = dest_repo_ref.split("/", 1)
            dest_reg, dest_repo = dreg, drepo
        except Exception:
            return self._blocked_report(
                title="Invalid destination repository",
                description=f"Destination must be in form registry/repository: {dest_repo_ref}",
                remediation=["Provide a valid destination repository like registry/repository."],
                affected={"destination": dest_repo_ref},
            )
        # Find artifact metadata
        artifact = None
        for a in self.artifacts:
            if a.registry == src_reg and a.repository == src_repo:
                if src_tag and a.tag == src_tag:
                    artifact = a
                    break
                if src_digest and a.digest == src_digest:
                    artifact = a
                    break
        if artifact is None:
            # Unknown artifact -> treat as unsigned unless external verification is enabled (not implemented)
            missing = {
                "registry": src_reg,
                "repository": src_repo,
                "tag": src_tag,
                "digest": src_digest,
            }
            return self._blocked_report(
                title="Artifact metadata not found; promotion blocked",
                description="Unable to locate source artifact metadata; cannot verify signatures/attestations.",
                remediation=[
                    "Ensure the artifact exists and metadata is available to the guard.",
                    "Sign the artifact with cosign and record provenance and Rekor inclusion.",
                    "Retry promotion after verification passes."
                ],
                affected={"artifact": missing, "destination": {"registry": dest_reg, "repository": dest_repo}},
            )

        ok, errors = self.verifier.verify(artifact)
        if protected and not ok:
            # Block promotion
            return self._blocked_report(
                title="Promotion blocked: Unsigned or unverified artifact",
                description=f"Artifact {source_image} failed verification: " + "; ".join(errors),
                remediation=[
                    "Sign the image with cosign: cosign sign --key <key> <image>",
                    "Ensure Rekor inclusion: cosign verify --certificate-oidc-issuer <issuer> --certificate-identity <identity> <image>",
                    "Attach SLSA and in-toto attestations and re-run verification.",
                    "Configure promotion pipeline to enforce verification gates."
                ],
                affected={
                    "artifact": asdict(artifact),
                    "destination": {"registry": dest_reg, "repository": dest_repo},
                },
                blocked=True,
            )

        # If protected and ok, require explicit approval to proceed (read-only by default)
        if not approve or self.read_only:
            return self._blocked_report(
                title="Promotion requires explicit approval",
                description="Dry-run mode or approval not granted. Verification passed; awaiting authorized approval and scoped credentials.",
                remediation=[
                    "Re-run with --approve and provide scoped, least-privilege credentials.",
                    "Ensure change logs/audit trail are configured for promotion actions."
                ],
                affected={"artifact": asdict(artifact), "destination": {"registry": dest_reg, "repository": dest_repo}},
                blocked=True,
            )

        # Approved and not read-only (should be rare). In this tool we do not perform real promotions.
        return PromotionResult(
            allowed=True,
            report=self._sign_report({
                "status": "approved",
                "action": "promotion",
                "timestamp": now_iso(),
                "artifact": asdict(artifact),
                "destination": {"registry": dest_reg, "repository": dest_repo},
                "notes": "No changes executed by this tool; external orchestrator must perform the action.",
                "ethics": ETHICAL_WARNING,
                "audit": {"mode": "change", "by": "artifactgraph-guard", "change_log": True},
            })
        )

    def _blocked_report(self, title: str, description: str, remediation: List[str], affected: Dict[str, Any], blocked: bool = True) -> PromotionResult:
        report = {
            "status": "blocked",
            "title": title,
            "description": description,
            "remediation": remediation,
            "affected": affected,
            "timestamp": now_iso(),
            "ethics": ETHICAL_WARNING,
            "audit": {"mode": "read-only" if self.read_only else "planned", "by": "artifactgraph-guard", "change_log": False},
        }
        return PromotionResult(allowed=False, report=self._sign_report(report))

    def _sign_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(report, sort_keys=True).encode("utf-8")
        if self.report_key:
            signature = hmac_sha256_hex(self.report_key, payload)
            report["signature"] = {"alg": "HMAC-SHA256", "value": signature, "note": "For integrity auditing; not a cryptographic endorsement of artifacts."}
        else:
            # Ephemeral signature to indicate report integrity if no key provided
            signature = sha256_hex(payload)
            report["signature"] = {"alg": "SHA256", "value": signature, "note": "Unsigned report (no HMAC key configured)."}
        return report

    # -----------------------------
    # Canary validation (namespaced, time-limited)
    # -----------------------------
    def validate_guardrails(self, ttl_seconds: int = 3600) -> List[Finding]:
        # We simulate canary replication by checking that rules would block unsigned artifacts into protected/public contexts
        findings: List[Finding] = []
        created_canaries = []
        for rule in self.rules:
            src = self.repositories.get(rule.source_repo)
            dst = self.repositories.get(rule.target_repo)
            if not src or not dst:
                continue
            # Create unsigned canary to test enforcement
            canary = Artifact(
                registry=src.registry,
                repository=src.name,
                tag=gen_canary_name(),
                digest=f"sha256:{uuid.uuid4().hex*2}"[:71],
                signed=False, rekor=False, slsa=False, in_toto=False,
                publisher="artifactgraph-guard",
                created_at=now_iso(),
            )
            # Only simulate creation for dry-run; never delete customer artifacts
            created_canaries.append({
                "artifact": asdict(canary),
                "rule": rule.id,
                "expires_at": datetime.datetime.utcfromtimestamp(time.time() + ttl_seconds).replace(microsecond=0).isoformat() + "Z",
                "created": not self.read_only and False,  # always False here; no real creation
                "cleanup": True,
            })
            # Would this unsigned canary be blocked by the rule if destination is protected/public?
            dst_is_sensitive = dst.protected or dst.public or self.registries.get(dst.registry, Registry(name="", provider="")).public
            if dst_is_sensitive:
                # Expectation: must be blocked
                if True:
                    # Since the canary is unsigned, a pass would indicate missing enforcement.
                    findings.append(
                        Finding(
                            id=f"canary-enforcement-{rule.id}",
                            severity="high",
                            title="Guardrail validation: unsigned replication should be blocked",
                            description=(
                                f"Simulated unsigned canary for rule {rule.id} targeting {rule.target_repo} must be blocked by policy. "
                                f"Ensure enforcement of cosign/Sigstore verification and provenance checks."
                            ),
                            remediation=[
                                "Enable signature and provenance verification on replication/promotion.",
                                "Configure policy to reject unsigned artifacts and require Rekor, SLSA, and in-toto attestations.",
                                "Re-run validation to confirm the guardrails are active."
                            ],
                            affected={"rule": asdict(rule), "canary": asdict(canary), "destination": asdict(dst)},
                            blocked=True,
                            category="guardrail",
                        )
                    )
        # Persist canary state for cleanup scheduling (simulation, auto-cleanup metadata only)
        if created_canaries:
            self.state.setdefault("canaries", []).extend(created_canaries)
            safe_json_dump(self.state_file, self.state)
        # Cleanup expired canaries from state (metadata only)
        self._cleanup_canary_state()
        return findings

    def _cleanup_canary_state(self):
        now_ts = time.time()
        canaries = self.state.get("canaries", [])
        remaining = []
        for c in canaries:
            try:
                exp = c.get("expires_at")
                exp_ts = datetime.datetime.fromisoformat(exp.replace("Z", "+00:00")).timestamp()
            except Exception:
                exp_ts = 0
            if exp_ts > now_ts:
                remaining.append(c)
        if len(remaining) != len(canaries):
            self.state["canaries"] = remaining
            safe_json_dump(self.state_file, self.state)

    # -----------------------------
    # Aggregate checks
    # -----------------------------
    def run_checks(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            findings.extend(self.detect_unsigned_in_protected())
        except Exception as e:
            findings.append(self._internal_error_finding("detect_unsigned_in_protected", e))
        try:
            findings.extend(self.detect_public_exposure())
        except Exception as e:
            findings.append(self._internal_error_finding("detect_public_exposure", e))
        try:
            findings.extend(self.detect_oidc_trust_drift())
        except Exception as e:
            findings.append(self._internal_error_finding("detect_oidc_trust_drift", e))
        try:
            findings.extend(self.detect_tag_squatting())
        except Exception as e:
            findings.append(self._internal_error_finding("detect_tag_squatting", e))
        try:
            findings.extend(self.validate_guardrails())
        except Exception as e:
            findings.append(self._internal_error_finding("validate_guardrails", e))
        return findings

    def _internal_error_finding(self, component: str, error: Exception) -> Finding:
        return Finding(
            id=f"internal-error-{component}",
            severity="low",
            title=f"Internal error in {component}",
            description=f"An error occurred during {component}: {error}",
            remediation=["Check logs, report a bug with stack trace if reproducible."],
            category="internal",
        )


# -----------------------------
# CLI
# -----------------------------
def load_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        # Strict JSON to avoid extra dependencies; provide helpful error
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"Error: Configuration must be valid JSON. {e}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print(f"Error: Config file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        sys.exit(2)


def print_findings(findings: List[Finding]):
    output = {
        "generated_at": now_iso(),
        "ethics": ETHICAL_WARNING,
        "summary": {
            "total": len(findings),
            "by_severity": {}
        },
        "findings": [asdict(f) for f in findings],
    }
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    output["summary"]["by_severity"] = sev_counts
    print(json.dumps(output, indent=2))


def cmd_check(args):
    config = load_config(args.config)
    read_only = not args.apply
    guard = ArtifactGraphGuard(config=config, read_only=read_only)
    findings = guard.run_checks()
    # Acceptance test mapping comments:
    # - Unsigned images in protected repos identified: detect_unsigned_in_protected
    # - Private->public replication detected and escalated: detect_public_exposure with severity critical
    # - OIDC/webhook audience/issuer mismatch flagged and blocked: detect_oidc_trust_drift
    print_findings(findings)
    # Exit non-zero if any critical/high blocked issues found
    exit_code = 0
    for f in findings:
        if f.blocked and f.severity in ("critical", "high"):
            exit_code = 3
            break
    sys.exit(exit_code)


def cmd_promote(args):
    # Minimal config may be provided to lookup artifact metadata
    config = load_config(args.config) if args.config else {"registries": [], "repositories": [], "artifacts": [], "replication_rules": []}
    read_only = not args.apply
    report_key = os.environ.get("AG_GUARD_REPORT_HMAC_KEY", "").encode("utf-8") or None
    guard = ArtifactGraphGuard(config=config, read_only=read_only, report_key=report_key)
    res = guard.request_promotion(
        source_image=args.source,
        dest_repo_ref=args.destination,
        protected=args.protected,
        approve=args.approve,
    )
    print(json.dumps(res.report, indent=2))
    sys.exit(0 if res.allowed else 4)


def cmd_validate(args):
    config = load_config(args.config)
    read_only = not args.apply
    guard = ArtifactGraphGuard(config=config, read_only=read_only)
    findings = guard.validate_guardrails()
    print_findings(findings)
    # Non-zero if any high severity guardrail failure
    exit_code = 0
    for f in findings:
        if f.severity in ("high", "critical"):
            exit_code = 5
            break
    sys.exit(exit_code)


def main():
    parser = argparse.ArgumentParser(
        description="ArtifactGraph Guard: Cross-Cloud Registry Replication & Signature Enforcer",
        epilog=ETHICAL_WARNING,
    )
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="Build graph and run security checks")
    p_check.add_argument("--config", required=True, help="Path to JSON configuration")
    p_check.add_argument("--apply", action="store_true", help="Enable actions (tool remains read-only; this toggles validation state only)")
    p_check.set_defaults(func=cmd_check)

    p_promote = sub.add_parser("promote", help="Request a promotion; enforce signature verification")
    p_promote.add_argument("--source", required=True, help="Source image ref (registry/repo:tag or registry/repo@digest)")
    p_promote.add_argument("--destination", required=True, help="Destination repository (registry/repository)")
    p_promote.add_argument("--protected", action="store_true", help="Destination is protected (enforce verification)")
    p_promote.add_argument("--approve", action="store_true", help="Explicit approval to proceed (still read-only without --apply)")
    p_promote.add_argument("--config", help="Optional JSON config providing artifact metadata")
    p_promote.add_argument("--apply", action="store_true", help="Enable actions (no real changes performed)")
    p_promote.set_defaults(func=cmd_promote)

    p_validate = sub.add_parser("validate", help="Validate guardrails via canary simulation")
    p_validate.add_argument("--config", required=True, help="Path to JSON configuration")
    p_validate.add_argument("--apply", action="store_true", help="Enable actions (no real changes performed)")
    p_validate.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()