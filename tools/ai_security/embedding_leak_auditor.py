import os
import json
import time
import uuid
import hmac
import math
import hashlib
import logging
import threading
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Any
from importlib.metadata import distributions


# ============ Ethical Warnings and Constants ============
ETHICAL_WARNING = (
    "AUTHORIZED TESTING ONLY: This tool is for security assessment with approved test datasets "
    "and seeded canaries. Do not use on production data, unowned tenants, or PII. All probes are "
    "rate-limited, logged, and must respect network egress allowlists."
)

DEFAULT_RATE_LIMIT_QPS = 5
DEFAULT_SIMILARITY_THRESHOLD = 0.92  # cosine similarity threshold for inversion success


# ============ Utility: Rate Limiter ============
class RateLimiter:
    def __init__(self, qps: float = DEFAULT_RATE_LIMIT_QPS):
        self.qps = max(qps, 0.1)
        self.lock = threading.Lock()
        self.allowance = self.qps
        self.last_check = time.time()

    def check(self):
        with self.lock:
            current = time.time()
            time_passed = current - self.last_check
            self.last_check = current
            self.allowance += time_passed * self.qps
            if self.allowance > self.qps:
                self.allowance = self.qps
            if self.allowance < 1.0:
                # need to wait
                sleep_time = (1.0 - self.allowance) / self.qps
                time.sleep(sleep_time)
                self.allowance = 0.0
            else:
                self.allowance -= 1.0


# ============ Utility: HMAC Signer ============
class HMACSigner:
    def __init__(self, key: Optional[bytes] = None):
        if key is None:
            key_env = os.getenv("AUDITOR_SIGNING_KEY", "")
            if key_env:
                key = bytes.fromhex(key_env) if all(c in "0123456789abcdef" for c in key_env.lower()) else key_env.encode("utf-8")
            else:
                key = os.urandom(32)
        self.key = key

    def sign(self, data: bytes) -> str:
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature_hex)


# ============ Transparency Log ============
class TransparencyLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        self.lock = threading.Lock()

    def anchor(self, entry_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        ts = time.time()
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(blob).hexdigest()
        record = {"timestamp": ts, "type": entry_type, "digest": digest}
        with self.lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        return record


# ============ Embedding API Interfaces ============
@dataclass
class EmbeddingResult:
    vector: List[float]
    metadata: Dict[str, Any]


class EmbeddingAPI:
    def embed(self, text: str) -> EmbeddingResult:
        raise NotImplementedError()


class SimpleEmbeddingAPI(EmbeddingAPI):
    # Deterministic pseudo-embedding based on hashing
    def __init__(self, dim: int = 128):
        self.dim = dim

    def embed(self, text: str) -> EmbeddingResult:
        seed = hashlib.sha256(text.encode("utf-8")).digest()
        vals = []
        for i in range(self.dim):
            # derive deterministic float from hash
            h = hashlib.sha256(seed + i.to_bytes(2, "big")).digest()
            # map to [-1,1]
            v = (int.from_bytes(h[:4], "big") / 2**32) * 2 - 1
            vals.append(float(v))
        # normalize to unit vector for cosine
        norm = math.sqrt(sum(v * v for v in vals)) or 1.0
        vals = [v / norm for v in vals]
        return EmbeddingResult(vector=vals, metadata={"model": "simple-embedder", "include_metadata": False})


class LeakyEmbeddingAPI(EmbeddingAPI):
    # Returns training-time metadata, intentionally leaky for membership inference detection
    def __init__(self, base: Optional[EmbeddingAPI] = None):
        self.base = base or SimpleEmbeddingAPI()

    def embed(self, text: str) -> EmbeddingResult:
        r = self.base.embed(text)
        # Leak plausible training-time metadata
        meta = dict(r.metadata)
        meta.update({
            "training_dataset_id": "internal_corpus_v2",
            "training_timestamp": "2023-11-07T12:00:00Z",
            "seen_in_training": True,
            "document_id": hashlib.sha1(text.encode("utf-8")).hexdigest()[:12],
            "include_metadata": True
        })
        return EmbeddingResult(vector=r.vector, metadata=meta)


# ============ Vector Store Client (In-Memory Sandbox) ============
@dataclass
class APIKeyScope:
    token: str
    allowed_namespaces: Optional[List[str]]  # None means mis-scoped, full access


@dataclass
class VectorRecord:
    id: str
    vector: List[float]
    text: str
    metadata: Dict[str, Any]
    namespace: str


class VectorStoreClient:
    def __init__(
        self,
        api_key_scope: APIKeyScope,
        rate_limiter: Optional[RateLimiter] = None,
        name: str = "inmem-store",
    ):
        self.scope = api_key_scope
        self.rate = rate_limiter or RateLimiter()
        self.name = name
        # global store across instances to simulate multi-tenant backend
        global _GLOBAL_VECTOR_STORE
        try:
            _ = _GLOBAL_VECTOR_STORE
        except NameError:
            _GLOBAL_VECTOR_STORE = {}
        self._store = _GLOBAL_VECTOR_STORE  # type: ignore

    def _check_namespace_access(self, namespace: str):
        if self.scope.allowed_namespaces is None:
            # mis-scoped, no restriction
            return
        if namespace not in self.scope.allowed_namespaces:
            raise PermissionError(f"API key not scoped to namespace '{namespace}'")

    def upsert(self, namespace: str, rec: VectorRecord):
        self.rate.check()
        self._check_namespace_access(namespace)
        ns = self._store.setdefault(namespace, {})
        ns[rec.id] = rec

    def search(self, namespace: str, query_vector: List[float], top_k: int = 3) -> List[Tuple[VectorRecord, float]]:
        self.rate.check()
        # If mis-scoped, search across all namespaces
        namespaces = list(self._store.keys()) if self.scope.allowed_namespaces is None else [namespace]
        candidates: List[Tuple[VectorRecord, float]] = []
        for ns in namespaces:
            for rec in self._store.get(ns, {}).values():
                sim = cosine_similarity(query_vector, rec.vector)
                candidates.append((rec, sim))
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]


# ============ Helper: Similarity ============
def cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


# ============ Evidence and Results Models ============
@dataclass
class Canary:
    id: str
    namespace: str


@dataclass
class CanaryRecord:
    id: str
    namespace: str
    text: str
    vector: List[float]
    signature_hex: str


@dataclass
class IsolationFinding:
    exposure_detected: bool
    leaked_namespaces: List[str]
    details: str


@dataclass
class InversionFinding:
    recovered: bool
    similarity: float
    recovered_text: Optional[str]
    details: str


@dataclass
class MembershipInferenceFinding:
    metadata_leak_detected: bool
    leaked_fields: Dict[str, Any]
    recommendations: List[str]


@dataclass
class AuditResult:
    session_id: str
    ethical_warning: str
    isolation_finding: Optional[IsolationFinding]
    inversion_finding: Optional[InversionFinding]
    membership_finding: Optional[MembershipInferenceFinding]
    evidence_dir: str
    sbom_path: str
    transparency_anchors: List[Dict[str, Any]]


# ============ Evidence Bundle Manager ============
class EvidenceBundle:
    def __init__(self, base_dir: Path, signer: HMACSigner, tlog: TransparencyLog, session_id: str):
        self.base_dir = base_dir
        self.signer = signer
        self.tlog = tlog
        self.session_id = session_id
        self.logs_dir = self.base_dir / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.files: Dict[str, str] = {}  # logical name -> path

    def attach_file(self, logical_name: str, content: Dict[str, Any]):
        path = self.base_dir / f"{logical_name}.json"
        blob = json.dumps(content, indent=2, sort_keys=True).encode("utf-8")
        sig = self.signer.sign(blob)
        wrapped = {"content": content, "hmac_sha256": sig}
        path.write_text(json.dumps(wrapped, indent=2), encoding="utf-8")
        self.files[logical_name] = str(path)

    def seal_manifest(self) -> str:
        manifest = {}
        for name, path in self.files.items():
            data = Path(path).read_bytes()
            manifest[name] = {
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        manifest_blob = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        manifest_sig = self.signer.sign(manifest_blob)
        manifest_record = {
            "session_id": self.session_id,
            "files": manifest,
            "manifest_hmac_sha256": manifest_sig,
            "sealed_at": time.time(),
        }
        manifest_path = self.base_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_record, indent=2), encoding="utf-8")
        anchor = self.tlog.anchor("evidence_manifest", manifest_record)
        return str(manifest_path), anchor


# ============ SBOM Generation ============
def build_sbom() -> Dict[str, Any]:
    comps = []
    for d in distributions():
        try:
            comps.append({"name": d.metadata["Name"], "version": d.version})
        except Exception:
            continue
    return {"components": sorted(comps, key=lambda x: (x["name"] or "", x["version"] or ""))}


# ============ Auditor Orchestrator ============
@dataclass
class AuditorConfig:
    approved_namespaces: List[str]
    evidence_dir: str
    transparency_log_path: str
    similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD
    qps_limit: float = DEFAULT_RATE_LIMIT_QPS


class EmbeddingLeakAuditor:
    def __init__(
        self,
        embedder: EmbeddingAPI,
        vector_client: VectorStoreClient,
        config: AuditorConfig,
        signer: Optional[HMACSigner] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.embedder = embedder
        self.client = vector_client
        self.config = config
        self.signer = signer or HMACSigner()
        self.session_id = str(uuid.uuid4())
        self.evidence_dir = Path(config.evidence_dir) / self.session_id
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.tlog = TransparencyLog(Path(config.transparency_log_path))
        self.bundle = EvidenceBundle(self.evidence_dir, self.signer, self.tlog, self.session_id)
        self.logger = logger or self._init_logger()

    def _init_logger(self) -> logging.Logger:
        logger = logging.getLogger(f"EmbeddingLeakAuditor.{self.session_id}")
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(self.evidence_dir / "audit.log", encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        logger.info(ETHICAL_WARNING)
        return logger

    def _ensure_namespace_approved(self, namespace: str):
        if namespace not in self.config.approved_namespaces:
            raise PermissionError(f"Namespace '{namespace}' is not approved for testing")

    def seed_canary(self, namespace: str, text: str) -> CanaryRecord:
        self._ensure_namespace_approved(namespace)
        self.logger.info(f"Seeding canary into namespace='{namespace}'")
        emb = self.embedder.embed(text)
        sig = self.signer.sign(json.dumps({"namespace": namespace, "text": text, "vector": emb.vector}, sort_keys=True).encode("utf-8"))
        rec_id = f"canary-{uuid.uuid4().hex[:12]}"
        rec = VectorRecord(
            id=rec_id,
            vector=emb.vector,
            text=text,
            metadata={"type": "canary", "signature": sig, "created_at": time.time()},
            namespace=namespace,
        )
        self.client.upsert(namespace, rec)
        canary = CanaryRecord(id=rec_id, namespace=namespace, text=text, vector=emb.vector, signature_hex=sig)
        self.bundle.attach_file(f"canary_{rec_id}", asdict(canary))
        self.logger.info(f"Seeded canary id='{rec_id}' with signature")
        anchor = self.tlog.anchor("canary_seed", {"session_id": self.session_id, "canary_id": rec_id, "signature": sig})
        self.logger.info(f"Anchored canary seed to transparency log: {anchor}")
        return canary

    def test_cross_namespace_isolation(
        self,
        querying_namespace: str,
        target_canary: CanaryRecord,
    ) -> IsolationFinding:
        self._ensure_namespace_approved(querying_namespace)
        self.logger.info(f"Testing cross-namespace isolation from '{querying_namespace}' for canary in '{target_canary.namespace}'")
        results = self.client.search(querying_namespace, target_canary.vector, top_k=5)
        leaked_ns = list({r.namespace for r, _ in results if r.namespace != querying_namespace and r.id == target_canary.id})
        exposure = len(leaked_ns) > 0
        details = "Cross-namespace exposure detected" if exposure else "No cross-namespace exposure observed"
        finding = IsolationFinding(exposure_detected=exposure, leaked_namespaces=leaked_ns, details=details)
        self.bundle.attach_file(f"isolation_{querying_namespace}_vs_{target_canary.namespace}", asdict(finding))
        self.logger.info(details + f"; leaked_namespaces={leaked_ns}")
        return finding

    def test_inversion(self, canary: CanaryRecord) -> InversionFinding:
        self.logger.info(f"Attempting inversion for canary id='{canary.id}' in namespace='{canary.namespace}'")
        # Black-box probe: query by vector to retrieve nearest neighbor text
        results = self.client.search(canary.namespace, canary.vector, top_k=1)
        if not results:
            finding = InversionFinding(recovered=False, similarity=0.0, recovered_text=None, details="No results returned")
            self.bundle.attach_file(f"inversion_{canary.id}", asdict(finding))
            return finding
        top_rec, sim = results[0]
        recovered_text = top_rec.text
        recovered = (top_rec.id == canary.id) and (sim >= self.config.similarity_threshold)
        details = "Recovered canary text from embedding" if recovered else "Did not meet recovery threshold"
        finding = InversionFinding(recovered=recovered, similarity=sim, recovered_text=recovered_text if recovered else None, details=details)
        self.bundle.attach_file(f"inversion_{canary.id}", asdict(finding))
        self.logger.info(f"Inversion attempt result: recovered={recovered}, similarity={sim:.4f}")
        if recovered:
            anchor = self.tlog.anchor("inversion_evidence", {
                "session_id": self.session_id,
                "canary_id": canary.id,
                "similarity": sim,
                "recovered": True
            })
            self.logger.info(f"Anchored inversion evidence: {anchor}")
        return finding

    def test_membership_inference(self, sample_text: str = "test sample") -> MembershipInferenceFinding:
        self.logger.info("Evaluating embedding API for membership inference leakage")
        r = self.embedder.embed(sample_text)
        leak_fields = {}
        flagged_keys = {"training_dataset_id", "training_timestamp", "seen_in_training", "document_id"}
        for k in flagged_keys:
            if k in r.metadata:
                leak_fields[k] = r.metadata[k]
        detected = len(leak_fields) > 0
        recs = []
        if detected:
            recs.extend([
                "Disable training metadata in API responses (e.g., include_metadata=False).",
                "Redact fields: " + ", ".join(sorted(leak_fields.keys())) + ".",
                "Rotate API keys and audit access logs for potential data exposure.",
                "Update configuration to strip training-time metadata at server and SDK layers.",
            ])
        else:
            recs.append("No training-time metadata observed in embedding responses.")
        finding = MembershipInferenceFinding(metadata_leak_detected=detected, leaked_fields=leak_fields, recommendations=recs)
        self.bundle.attach_file("membership_inference", asdict(finding))
        self.logger.info(f"Membership inference detection: {detected}; fields={list(leak_fields.keys())}")
        return finding

    def finalize(self) -> AuditResult:
        # SBOM
        sbom = build_sbom()
        sbom_path = self.evidence_dir / "sbom.json"
        sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
        anchor_sbom = self.tlog.anchor("sbom", {"session_id": self.session_id, "sha256": hashlib.sha256(sbom_path.read_bytes()).hexdigest()})

        # Seal evidence manifest
        manifest_path, anchor_manifest = self.bundle.seal_manifest()

        result = AuditResult(
            session_id=self.session_id,
            ethical_warning=ETHICAL_WARNING,
            isolation_finding=None,
            inversion_finding=None,
            membership_finding=None,
            evidence_dir=str(self.evidence_dir),
            sbom_path=str(sbom_path),
            transparency_anchors=[anchor_sbom, anchor_manifest],
        )
        result_path = self.evidence_dir / "result.json"
        result_path.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
        return result


# ============ Acceptance Test Scenario Helpers ============
def acceptance_demo():
    # Prepare config and components
    evidence_root = os.getenv("AUDITOR_EVIDENCE_DIR", str(Path.cwd() / "evidence"))
    tlog_path = os.getenv("AUDITOR_TLOG_PATH", str(Path.cwd() / "transparency.log"))
    approved_namespaces = ["tenant_a", "tenant_b"]

    # Mis-scoped client (None => cross-namespace search allowed)
    mis_scoped_key = APIKeyScope(token="mis-scoped", allowed_namespaces=None)
    mis_scoped_client = VectorStoreClient(api_key_scope=mis_scoped_key, rate_limiter=RateLimiter(), name="sandbox")

    # Properly scoped client for tenant_a
    scoped_key_a = APIKeyScope(token="key-a", allowed_namespaces=["tenant_a"])
    client_a = VectorStoreClient(api_key_scope=scoped_key_a, rate_limiter=RateLimiter(), name="sandbox")

    # Properly scoped client for tenant_b
    scoped_key_b = APIKeyScope(token="key-b", allowed_namespaces=["tenant_b"])
    client_b = VectorStoreClient(api_key_scope=scoped_key_b, rate_limiter=RateLimiter(), name="sandbox")

    # Use leaky embedder for membership inference test; switch to simple for other actions as needed
    leaky_embedder = LeakyEmbeddingAPI()
    simple_embedder = SimpleEmbeddingAPI()

    # Auditor with mis-scoped client to detect cross-namespace exposure
    auditor1 = EmbeddingLeakAuditor(
        embedder=simple_embedder,
        vector_client=mis_scoped_client,
        config=AuditorConfig(
            approved_namespaces=approved_namespaces,
            evidence_dir=evidence_root,
            transparency_log_path=tlog_path,
            similarity_threshold=DEFAULT_SIMILARITY_THRESHOLD,
            qps_limit=DEFAULT_RATE_LIMIT_QPS,
        ),
    )

    # Seed canary in tenant_b
    canary_b = auditor1.seed_canary("tenant_b", "CANARY: cross-tenant leak probe")

    # Cross-namespace exposure test: query from tenant_a using mis-scoped client
    iso_finding_exposed = auditor1.test_cross_namespace_isolation("tenant_a", canary_b)

    # Now switch to properly scoped client and confirm inability after policy fix
    auditor2 = EmbeddingLeakAuditor(
        embedder=simple_embedder,
        vector_client=client_a,
        config=AuditorConfig(
            approved_namespaces=approved_namespaces,
            evidence_dir=evidence_root,
            transparency_log_path=tlog_path,
            similarity_threshold=DEFAULT_SIMILARITY_THRESHOLD,
            qps_limit=DEFAULT_RATE_LIMIT_QPS,
        ),
    )
    # Reuse the same canary vector but via new auditor/client for test; still approved namespace list
    iso_finding_fixed = auditor2.test_cross_namespace_isolation("tenant_a", canary_b)

    # Inversion test: attempt to recover canary text from tenant_b using scoped client_b
    auditor3 = EmbeddingLeakAuditor(
        embedder=simple_embedder,
        vector_client=client_b,
        config=AuditorConfig(
            approved_namespaces=approved_namespaces,
            evidence_dir=evidence_root,
            transparency_log_path=tlog_path,
            similarity_threshold=DEFAULT_SIMILARITY_THRESHOLD,
            qps_limit=DEFAULT_RATE_LIMIT_QPS,
        ),
    )
    inv_finding = auditor3.test_inversion(canary_b)

    # Membership inference test using leaky embedder
    auditor4 = EmbeddingLeakAuditor(
        embedder=leaky_embedder,
        vector_client=client_a,
        config=AuditorConfig(
            approved_namespaces=approved_namespaces,
            evidence_dir=evidence_root,
            transparency_log_path=tlog_path,
            similarity_threshold=DEFAULT_SIMILARITY_THRESHOLD,
            qps_limit=DEFAULT_RATE_LIMIT_QPS,
        ),
    )
    membership_finding = auditor4.test_membership_inference()

    # Finalize bundles (build SBOM and seal)
    res1 = auditor1.finalize()
    res2 = auditor2.finalize()
    res3 = auditor3.finalize()
    res4 = auditor4.finalize()

    # Return a compact summary
    return {
        "cross_namespace_exposure_detected": iso_finding_exposed.exposure_detected,
        "cross_namespace_fixed_confirmed": not iso_finding_fixed.exposure_detected,
        "inversion_recovered": inv_finding.recovered,
        "membership_leak_detected": membership_finding.metadata_leak_detected,
        "evidence_dirs": [res1.evidence_dir, res2.evidence_dir, res3.evidence_dir, res4.evidence_dir],
    }


# ============ Module Entry (Optional) ============
if __name__ == "__main__":
    summary = acceptance_demo()
    print(json.dumps(summary, indent=2))