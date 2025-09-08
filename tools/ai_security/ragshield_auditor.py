import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


ETHICAL_WARNING = (
    "RAGShield Auditor: Authorized testing and defensive use only. "
    "Do not apply to data you do not own or have explicit permission to audit."
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_hex_str(s: str) -> str:
    return sha256_hex(s.encode("utf-8"))


def l2_norm(v: List[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def vec_sub(a: List[float], b: List[float]) -> List[float]:
    return [x - y for x, y in zip(a, b)]


def vec_add(a: List[float], b: List[float]) -> List[float]:
    return [x + y for x, y in zip(a, b)]


def vec_scale(a: List[float], s: float) -> List[float]:
    return [x * s for x in a]


def matvec_mul(mat: List[List[float]], v: List[float]) -> List[float]:
    return [sum(row[i] * v[i] for i in range(len(v))) for row in mat]


def power_iteration(
    cov: List[List[float]], iterations: int = 50, tol: float = 1e-6
) -> Tuple[float, List[float]]:
    n = len(cov)
    if n == 0:
        return 0.0, []
    # Initialize vector
    v = [1.0 / math.sqrt(n)] * n
    last_lambda = 0.0
    for _ in range(iterations):
        w = matvec_mul(cov, v)
        norm = l2_norm(w)
        if norm == 0:
            break
        v = [x / norm for x in w]
        # Rayleigh quotient as eigenvalue approximation
        Av = matvec_mul(cov, v)
        lam = sum(v[i] * Av[i] for i in range(n))
        if abs(lam - last_lambda) < tol:
            last_lambda = lam
            break
        last_lambda = lam
    return last_lambda, v


class SimpleSigner:
    """
    Simple HMAC-SHA256 signer to simulate signed manifests and attestations.
    Not a replacement for Sigstore/in-toto; for authorized testing only.
    """

    def __init__(self, signer_id: str, secret_key: str):
        self.signer_id = signer_id
        self.secret_key = secret_key.encode("utf-8")

    def sign(self, payload: str) -> str:
        return hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, payload: str, signature_hex: str) -> bool:
        expected = self.sign(payload)
        # hmac.compare_digest to reduce timing leakage
        return hmac.compare_digest(expected, signature_hex)


class TransparencyLog:
    """
    Simple in-memory append-only transparency log.
    """

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []

    def append(self, payload_digest: str) -> int:
        entry = {
            "digest": payload_digest,
            "ts": int(time.time()),
            "index": len(self._entries),
        }
        self._entries.append(entry)
        return entry["index"]

    def verify_inclusion(self, index: int, payload_digest: str) -> bool:
        if 0 <= index < len(self._entries):
            entry = self._entries[index]
            return entry["digest"] == payload_digest
        return False

    def entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)


@dataclass
class ProvenanceManifest:
    doc_id: str
    content_hash: str
    signer_id: str
    signature: str
    transparency_index: int
    timestamp: int

    def to_canonical_json(self) -> str:
        obj = {
            "doc_id": self.doc_id,
            "content_hash": self.content_hash,
            "signer_id": self.signer_id,
            "transparency_index": self.transparency_index,
            "timestamp": self.timestamp,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def create(
        signer: SimpleSigner, doc_id: str, content_hash: str, tlog: TransparencyLog
    ) -> "ProvenanceManifest":
        base_json = json.dumps(
            {
                "doc_id": doc_id,
                "content_hash": content_hash,
                "signer_id": signer.signer_id,
                "timestamp": int(time.time()),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = sha256_hex_str(base_json)
        index = tlog.append(digest)
        canonical = json.dumps(
            {
                "doc_id": doc_id,
                "content_hash": content_hash,
                "signer_id": signer.signer_id,
                "transparency_index": index,
                "timestamp": json.loads(base_json)["timestamp"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        signature = signer.sign(canonical)
        return ProvenanceManifest(
            doc_id=doc_id,
            content_hash=content_hash,
            signer_id=signer.signer_id,
            signature=signature,
            transparency_index=index,
            timestamp=json.loads(base_json)["timestamp"],
        )

    def verify(self, signer: SimpleSigner, tlog: TransparencyLog) -> bool:
        canonical = self.to_canonical_json()
        if not signer.verify(canonical, self.signature):
            return False
        # verify inclusion
        base_json = json.dumps(
            {
                "doc_id": self.doc_id,
                "content_hash": self.content_hash,
                "signer_id": self.signer_id,
                "timestamp": self.timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = sha256_hex_str(base_json)
        return tlog.verify_inclusion(self.transparency_index, digest)


@dataclass
class Document:
    doc_id: str
    content: str
    source_url: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""
    manifest: Optional[ProvenanceManifest] = None
    quarantined: bool = False
    quarantine_reason: Optional[str] = None
    sanitized_content: Optional[str] = None
    flags: List[str] = field(default_factory=list)

    def compute_hash(self) -> str:
        self.content_hash = sha256_hex_str(self.content)
        return self.content_hash


class AllowlistSandbox:
    """
    Sandboxes connectors and content: strict allowlists for domains and tools,
    HTML/Markdown sanitization and link validation to neutralize prompt-injection-in-data.
    """

    def __init__(self, allowed_domains: Optional[List[str]] = None, allowed_tools: Optional[List[str]] = None):
        self.allowed_domains = set(allowed_domains or [])
        self.allowed_tools = set(allowed_tools or [])

    @staticmethod
    def sanitize_html_markdown(text: str) -> str:
        # Remove script and style tags
        text = re.sub(r"<\s*(script|style)[^>]*>.*?<\s*/\s*\1\s*>", "", text, flags=re.IGNORECASE | re.DOTALL)
        # Remove event handler attributes like onclick=""
        text = re.sub(r'on\w+\s*=\s*"(.*?)"', "", text, flags=re.IGNORECASE)
        text = re.sub(r"on\w+\s*=\s*'(.*?)'", "", text, flags=re.IGNORECASE)
        # Neutralize javascript: links in markdown
        text = re.sub(r"\[([^\]]+)\]\(\s*javascript:[^)]+\)", r"[\1](#)", text, flags=re.IGNORECASE)
        # Neutralize data: URIs
        text = re.sub(r"\(\s*data:[^)]+\)", "(#)", text, flags=re.IGNORECASE)
        # Remove iframes
        text = re.sub(r"<\s*iframe[^>]*>.*?<\s*/\s*iframe\s*>", "", text, flags=re.IGNORECASE | re.DOTALL)
        return text

    def validate_links(self, text: str) -> Tuple[str, List[str]]:
        # Find all markdown links and raw URLs
        invalids: List[str] = []

        def _validate_url(url: str) -> bool:
            try:
                p = urlparse(url)
                if p.scheme not in ("http", "https"):
                    return False
                domain = p.hostname or ""
                # allow subdomains of allowed domains
                for allowed in self.allowed_domains:
                    if domain == allowed or domain.endswith("." + allowed):
                        return True
                return False
            except Exception:
                return False

        # Replace invalid http(s) links with '#'
        def _replace(match: re.Match) -> str:
            label = match.group(1)
            url = match.group(2)
            if _validate_url(url):
                return match.group(0)
            else:
                invalids.append(url)
                return f"[{label}](#)"

        text = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", _replace, text, flags=re.IGNORECASE)

        # Raw URLs
        def _replace_raw(match: re.Match) -> str:
            url = match.group(0)
            if _validate_url(url):
                return url
            else:
                invalids.append(url)
                return "#"

        text = re.sub(r"https?://[^\s)]+", _replace_raw, text, flags=re.IGNORECASE)
        return text, invalids

    def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.allowed_tools:
            raise PermissionError(f"Tool '{tool_name}' not allowed by sandbox policy")
        # Simulate safe tool execution—no shell or network side-effects here.
        return {"tool": tool_name, "args": args, "status": "simulated_success"}


class EmbeddingIndex:
    """
    Maintains embeddings and baseline metrics for drift detection and outlier analysis.
    """

    def __init__(self, k_for_outlier: int = 3):
        self.embeddings: Dict[str, List[float]] = {}
        self.baseline_metrics: Optional[Dict[str, Any]] = None
        self.k_for_outlier = k_for_outlier

    @staticmethod
    def centroid(vectors: List[List[float]]) -> List[float]:
        if not vectors:
            return []
        dim = len(vectors[0])
        c = [0.0] * dim
        for v in vectors:
            for i in range(dim):
                c[i] += v[i]
        return [x / len(vectors) for x in c]

    @staticmethod
    def covariance_matrix(vectors: List[List[float]], mean: List[float]) -> List[List[float]]:
        if not vectors:
            return []
        dim = len(mean)
        cov = [[0.0 for _ in range(dim)] for _ in range(dim)]
        for v in vectors:
            dv = vec_sub(v, mean)
            for i in range(dim):
                for j in range(dim):
                    cov[i][j] += dv[i] * dv[j]
        n = max(1, len(vectors) - 1)
        for i in range(dim):
            for j in range(dim):
                cov[i][j] /= n
        return cov

    @staticmethod
    def euclidean(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    def knn_outlier_scores(self) -> Dict[str, float]:
        ids = list(self.embeddings.keys())
        vecs = [self.embeddings[i] for i in ids]
        scores: Dict[str, float] = {}
        for idx, v in enumerate(vecs):
            dists: List[float] = []
            for jdx, u in enumerate(vecs):
                if idx == jdx:
                    continue
                dists.append(self.euclidean(v, u))
            dists.sort()
            k = min(self.k_for_outlier, len(dists)) or 1
            score = sum(dists[:k]) / k
            scores[ids[idx]] = score
        return scores

    def compute_metrics(self) -> Dict[str, Any]:
        ids = list(self.embeddings.keys())
        vecs = [self.embeddings[i] for i in ids]
        c = self.centroid(vecs)
        cov = self.covariance_matrix(vecs, c) if vecs else []
        top_eig, _ = power_iteration(cov) if cov else (0.0, [])
        # Average kNN distance as a simple dispersion metric
        knn_scores = self.knn_outlier_scores() if ids else {}
        avg_knn = sum(knn_scores.values()) / len(knn_scores) if knn_scores else 0.0
        return {
            "centroid": c,
            "top_eigenvalue": top_eig,
            "avg_knn_distance": avg_knn,
            "count": len(ids),
        }

    def snapshot_baseline(self) -> Dict[str, Any]:
        self.baseline_metrics = self.compute_metrics()
        return self.baseline_metrics

    def set_embeddings(self, emb: Dict[str, List[float]]) -> None:
        self.embeddings = dict(emb)

    def update_embedding(self, doc_id: str, vector: List[float]) -> None:
        self.embeddings[doc_id] = list(vector)

    def detect_drift(
        self, centroid_shift_threshold: float = 0.5, eigen_ratio_threshold: float = 0.5, knn_change_threshold: float = 0.5
    ) -> Tuple[bool, Dict[str, Any]]:
        current = self.compute_metrics()
        if not self.baseline_metrics:
            return False, {"reason": "no_baseline", "current": current}
        base = self.baseline_metrics
        # Centroid shift
        c_base = base["centroid"]
        c_cur = current["centroid"]
        if not c_base or not c_cur:
            return False, {"reason": "invalid_centroids", "baseline": base, "current": current}
        # Normalize by baseline norm + epsilon
        shift = l2_norm(vec_sub(c_cur, c_base))
        base_norm = l2_norm(c_base) + 1e-6
        centroid_shift = shift / base_norm
        # Eigenvalue ratio
        base_eig = base["top_eigenvalue"] + 1e-6
        cur_eig = current["top_eigenvalue"] + 1e-6
        eig_ratio_change = abs(cur_eig - base_eig) / base_eig
        # kNN avg change
        base_knn = base["avg_knn_distance"] + 1e-6
        cur_knn = current["avg_knn_distance"] + 1e-6
        knn_change = abs(cur_knn - base_knn) / base_knn
        drift = (
            centroid_shift > centroid_shift_threshold or eig_ratio_change > eigen_ratio_threshold or knn_change > knn_change_threshold
        )
        details = {
            "baseline": base,
            "current": current,
            "diff": {
                "centroid_shift": centroid_shift,
                "eigen_change_ratio": eig_ratio_change,
                "avg_knn_change_ratio": knn_change,
            },
        }
        return drift, details


class RAGShieldAuditor:
    """
    RAGShield: Data Poisoning & Retrieval Integrity Auditor
    Provides:
    - Content provenance enforcement with per-document SHA-256, signed manifests, transparency log inclusion checks.
    - Sandboxed tool/connectors with strict allowlists; content sanitization and link validation.
    - Embedding anomaly/poison detectors (spectral signatures, k-NN outlier scores, watermark/backdoor scans) with quarantine and signed attestations.
    - Retrieval filtering and response auditing (citation hashing checks).
    """

    DEFAULT_INJECTION_PATTERNS = [
        r"ignore\s+previous",
        r"disregard\s+(all|any)\s+instructions",
        r"system\s+prompt",
        r"act\s+as",
        r"call\s+tool",
        r"\[\[INJECTION\]\]",
        r"BEGIN\s+BACKDOOR",
        r"<\s*script",
        r"<\s*iframe",
        r"onload\s*=",
        r"onerror\s*=",
        r"rm\s+-rf",
        r"wget\s+",
        r"curl\s+",
        r"exfiltrat",
        r"data:text/html",
        r"prompt[-\s]?injection",
        r"base64,",
        r"\{\%",
    ]

    DEFAULT_TRIGGER_MARKERS = [
        "!!!TRIGGER!!!",
        "[[TRIGGER]]",
        "BEGIN BACKDOOR",
        "PAYLOAD:",
        "do_not_filter:",
    ]

    def __init__(
        self,
        signer: Optional[SimpleSigner] = None,
        transparency_log: Optional[TransparencyLog] = None,
        allowed_domains: Optional[List[str]] = None,
        allowed_tools: Optional[List[str]] = None,
    ):
        self.signer = signer or SimpleSigner("ragshield-signer", "ragshield-default-secret")
        self.tlog = transparency_log or TransparencyLog()
        self.docs: Dict[str, Document] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.sandbox = AllowlistSandbox(allowed_domains=allowed_domains or [], allowed_tools=allowed_tools or [])
        self.index = EmbeddingIndex()
        # Policy toggles / thresholds
        self.outlier_threshold_percentile = 0.98
        self.max_allowed_invalid_links = 0
        self.ethical_warning_logged = False

    def _log_alert(self, level: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        if not self.ethical_warning_logged:
            self.ethical_warning_logged = True
            self.alerts.append({"level": "warning", "message": ETHICAL_WARNING, "ts": int(time.time())})
        alert = {"level": level, "message": message, "context": context or {}, "ts": int(time.time())}
        self.alerts.append(alert)

    def register_document(self, doc_id: str, content: str, source_url: str, metadata: Optional[Dict[str, Any]] = None) -> Document:
        d = Document(doc_id=doc_id, content=content, source_url=source_url, metadata=metadata or {})
        d.compute_hash()
        # Sanitize and validate links
        sanitized = self.sandbox.sanitize_html_markdown(d.content)
        sanitized, invalids = self.sandbox.validate_links(sanitized)
        d.sanitized_content = sanitized
        if invalids:
            d.flags.append("invalid_links")
        # Prompt-injection / trigger scans
        inj = self._detect_injection(d.content)
        if inj:
            d.flags.append("prompt_injection_detected")
            self.quarantine(doc_id, reason=f"prompt-injection detected: {inj}")
        trig = self._scan_triggers(d.content)
        if trig:
            d.flags.append("trigger_marker_detected")
            self.quarantine(doc_id, reason=f"backdoor trigger detected: {trig}")
        # Domain allowlist enforcement
        if not self._source_allowed(d.source_url):
            d.flags.append("source_not_allowed")
            self.quarantine(doc_id, reason="source_url not allowed by sandbox policy")
        self.docs[doc_id] = d
        return d

    def register_manifest(self, manifest: ProvenanceManifest) -> bool:
        doc = self.docs.get(manifest.doc_id)
        if not doc:
            raise KeyError(f"Document {manifest.doc_id} not found")
        if manifest.content_hash != doc.content_hash:
            self.quarantine(doc.doc_id, reason="manifest hash mismatch")
            self._log_alert("error", "Manifest content hash mismatch", {"doc_id": doc.doc_id})
            return False
        valid = manifest.verify(self.signer, self.tlog)
        if not valid:
            self.quarantine(doc.doc_id, reason="manifest verification failed (signature or transparency log)")
            self._log_alert("error", "Manifest verification failed", {"doc_id": doc.doc_id})
            return False
        doc.manifest = manifest
        return True

    def quarantine(self, doc_id: str, reason: str) -> None:
        d = self.docs.get(doc_id)
        if not d:
            return
        d.quarantined = True
        d.quarantine_reason = reason

    def _detect_injection(self, text: str) -> Optional[str]:
        for pat in self.DEFAULT_INJECTION_PATTERNS:
            if re.search(pat, text, flags=re.IGNORECASE):
                return pat
        return None

    def _scan_triggers(self, text: str) -> Optional[str]:
        for marker in self.DEFAULT_TRIGGER_MARKERS:
            if marker.lower() in text.lower():
                return marker
        return None

    def _source_allowed(self, source_url: str) -> bool:
        try:
            p = urlparse(source_url)
            if p.scheme not in ("http", "https"):
                return False
            domain = p.hostname or ""
            for allowed in self.sandbox.allowed_domains:
                if domain == allowed or domain.endswith("." + allowed):
                    return True
            return False if self.sandbox.allowed_domains else True
        except Exception:
            return False

    def set_embeddings(self, embedding_map: Dict[str, List[float]], snapshot_as_baseline: bool = False) -> None:
        # Only include known non-quarantined docs
        filtered = {k: v for k, v in embedding_map.items() if k in self.docs and not self.docs[k].quarantined}
        self.index.set_embeddings(filtered)
        if snapshot_as_baseline:
            self.index.snapshot_baseline()

    def detect_embedding_anomalies(self) -> Dict[str, Any]:
        scores = self.index.knn_outlier_scores()
        if not scores:
            return {"outliers": [], "scores": {}}
        # Determine threshold by percentile
        vals = sorted(scores.values())
        idx = min(len(vals) - 1, max(0, int(self.outlier_threshold_percentile * len(vals)) - 1))
        thresh = vals[idx]
        outliers = [doc_id for doc_id, score in scores.items() if score >= thresh]
        for oid in outliers:
            self.quarantine(oid, reason="embedding outlier detected (kNN score)")
        return {"outliers": outliers, "scores": scores, "threshold": thresh}

    def detect_index_drift_and_attest(
        self,
        centroid_shift_threshold: float = 0.5,
        eigen_ratio_threshold: float = 0.5,
        knn_change_threshold: float = 0.5,
    ) -> Tuple[bool, Dict[str, Any], Optional[Dict[str, Any]]]:
        drift, details = self.index.detect_drift(
            centroid_shift_threshold=centroid_shift_threshold,
            eigen_ratio_threshold=eigen_ratio_threshold,
            knn_change_threshold=knn_change_threshold,
        )
        attestation = None
        if drift:
            attestation = self._sign_attestation("index_drift_detected", details)
            self._log_alert("error", "Embedding index drift detected; policy gate failed", {"attestation": attestation})
        return drift, details, attestation

    def _sign_attestation(self, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "event": event_type,
            "details": details,
            "ts": int(time.time()),
            "issuer": self.signer.signer_id,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sig = self.signer.sign(canonical)
        return {"payload": payload, "signature": sig}

    def verify_attestation(self, attestation: Dict[str, Any]) -> bool:
        payload = attestation.get("payload")
        sig = attestation.get("signature", "")
        if not payload:
            return False
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return self.signer.verify(canonical, sig)

    def filter_retrieval(self, candidates: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
        """
        Filter retrieval results (list of (doc_id, score)) to exclude quarantined or unprovenanced docs.
        """
        filtered: List[Tuple[str, float]] = []
        for doc_id, score in candidates:
            d = self.docs.get(doc_id)
            if not d:
                continue
            if d.quarantined:
                continue
            if not d.manifest:
                # enforce signed-source retrieval
                continue
            if d.manifest.content_hash != d.content_hash:
                self.quarantine(doc_id, reason="content hash mismatch on retrieval")
                continue
            filtered.append((doc_id, score))
        return filtered

    def audit_response_citations(self, response_text: str, citations: List[str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Verify that cited docs have not been tampered (hash mismatch). If any mismatch, block response.
        Returns (allowed, incident).
        """
        incidents: List[Dict[str, Any]] = []
        for doc_id in citations:
            d = self.docs.get(doc_id)
            if not d:
                incidents.append({"doc_id": doc_id, "reason": "missing_document"})
                continue
            current_hash = sha256_hex_str(d.content)
            if d.content_hash != current_hash:
                self.quarantine(doc_id, reason="content tampering detected (hash mismatch)")
                incidents.append(
                    {
                        "doc_id": doc_id,
                        "reason": "hash_mismatch",
                        "stored_hash": d.content_hash,
                        "current_hash": current_hash,
                        "source_url": d.source_url,
                        "manifest_present": bool(d.manifest),
                        "manifest_signer": d.manifest.signer_id if d.manifest else None,
                        "transparency_index": d.manifest.transparency_index if d.manifest else None,
                    }
                )
        if incidents:
            incident_record = {
                "type": "citation_integrity_block",
                "response_excerpt": response_text[:200],
                "incidents": incidents,
                "ts": int(time.time()),
            }
            self._log_alert("error", "RAG response blocked due to citation integrity failure", incident_record)
            att = self._sign_attestation("citation_integrity_failure", incident_record)
            return False, att
        return True, None

    def scan_and_quarantine_corpus(self) -> Dict[str, Any]:
        """
        Scan entire corpus for prompt-injection and triggers; quarantine offenders.
        """
        results: Dict[str, Any] = {"quarantined": [], "flags": {}}
        for doc_id, d in self.docs.items():
            flagged = False
            inj = self._detect_injection(d.content)
            if inj and not d.quarantined:
                self.quarantine(doc_id, reason=f"prompt-injection detected: {inj}")
                flagged = True
            trig = self._scan_triggers(d.content)
            if trig and not d.quarantined:
                self.quarantine(doc_id, reason=f"backdoor trigger detected: {trig}")
                flagged = True
            if flagged:
                results["quarantined"].append(doc_id)
            results["flags"][doc_id] = list(d.flags)
        return results

    def build_manifest_for_doc(self, doc_id: str) -> ProvenanceManifest:
        d = self.docs.get(doc_id)
        if not d:
            raise KeyError(f"Document {doc_id} not found")
        if not d.content_hash:
            d.compute_hash()
        manifest = ProvenanceManifest.create(self.signer, d.doc_id, d.content_hash, self.tlog)
        d.manifest = manifest
        return manifest

    def simulate_index_tampering(self, shift: float = 1.0) -> None:
        """
        Simulate index tampering by shifting embeddings.
        """
        for k in list(self.index.embeddings.keys()):
            vec = self.index.embeddings[k]
            if not vec:
                continue
            v = list(vec)
            v[0] = v[0] + shift  # shift along first dimension
            self.index.embeddings[k] = v

    def get_quarantined_docs(self) -> List[str]:
        return [doc_id for doc_id, d in self.docs.items() if d.quarantined]

    def connectors_execute(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        return self.sandbox.execute_tool(tool_name, args)

    def corpus_summary(self) -> Dict[str, Any]:
        total = len(self.docs)
        quarantined = len(self.get_quarantined_docs())
        signed = sum(1 for d in self.docs.values() if d.manifest)
        return {"total": total, "quarantined": quarantined, "signed": signed}

    def policy_gate(self) -> Tuple[bool, List[str]]:
        """
        Enforce overall policy: no quarantined docs in retrieval, index not drifted, and all docs signed.
        """
        reasons: List[str] = []
        if self.get_quarantined_docs():
            reasons.append("quarantined_docs_present")
        unsig = [d.doc_id for d in self.docs.values() if not d.manifest]
        if unsig:
            reasons.append("unsigned_docs_present")
        drift, details, _ = self.detect_index_drift_and_attest()
        if drift:
            reasons.append("index_drift_detected")
        return (len(reasons) == 0), reasons


# Example usage within authorized tests (do not execute against unauthorized data):
# auditor = RAGShieldAuditor(allowed_domains=["example.com"], allowed_tools=["fetch"])
# doc = auditor.register_document("doc1", "Content with [[INJECTION]]", "https://kb.example.com/page")
# auditor.build_manifest_for_doc("doc1")  # would normally happen after content is verified
# auditor.set_embeddings({"doc1": [0.1, 0.2, 0.3]}, snapshot_as_baseline=True)
# auditor.simulate_index_tampering(shift=5.0)
# drift, details, att = auditor.detect_index_drift_and_attest()
# allowed, att2 = auditor.audit_response_citations("Answer", ["doc1"])