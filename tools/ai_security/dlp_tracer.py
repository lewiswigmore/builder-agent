import base64
import contextlib
import dataclasses
import hashlib
import hmac
import json
import os
import random
import re
import shutil
import socket
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

try:
    import numpy as _np  # optional, used for spectral signatures if available
except Exception:  # pragma: no cover
    _np = None  # fallback to simple stats


# Ethical usage warning for any consumer of this tool
ETHICAL_WARNING = (
    "This tool is for authorized security testing, audit, and defense only. "
    "Ensure you have explicit permission to analyze datasets/models. Misuse may be illegal."
)


# ---- Signing primitives ----

class Signer:
    def __init__(self, signer_id: str):
        self.signer_id = signer_id

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError

    def verify(self, data: bytes, signature: bytes) -> bool:
        raise NotImplementedError


class HMACSigner(Signer):
    def __init__(self, key: bytes, signer_id: str = "hmac:default"):
        super().__init__(signer_id)
        if not key:
            raise ValueError("HMACSigner requires a non-empty key")
        self._key = key

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature)


# Optional Ed25519 signer using cryptography if available
_ED25519_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    _ED25519_AVAILABLE = True
except Exception:  # pragma: no cover
    _ED25519_AVAILABLE = False


class Ed25519Signer(Signer):
    def __init__(self, private_key: Any, signer_id: str = "ed25519:default"):
        if not _ED25519_AVAILABLE:
            raise RuntimeError("cryptography not available for Ed25519")
        super().__init__(signer_id)
        if isinstance(private_key, Ed25519PrivateKey):
            self._sk = private_key
        else:
            self._sk = Ed25519PrivateKey.from_private_bytes(private_key)

    @property
    def public_key_bytes(self) -> bytes:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        pk = self._sk.public_key()
        try:
            pk.verify(signature, data)
            return True
        except Exception:
            return False


# ---- Audit Log (append-only with hash chain and signatures) ----

class AuditLog:
    def __init__(self, path: str, signer: Signer):
        self.path = path
        self.signer = signer
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                pass

    def _last_hash(self) -> str:
        last = ""
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    last = entry.get("entry_hash", "")
                except Exception:
                    continue
        return last

    def append(self, event: str, details: Dict[str, Any]) -> Dict[str, Any]:
        prev_hash = self._last_hash()
        body = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
            "prev_hash": prev_hash,
            "signer_id": self.signer.signer_id,
        }
        body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256((prev_hash + hashlib.sha256(body_bytes).hexdigest()).encode("utf-8")).hexdigest()
        signature = base64.b64encode(self.signer.sign(entry_hash.encode("utf-8"))).decode("ascii")
        record = dict(body)
        record["entry_hash"] = entry_hash
        record["signature"] = signature
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def verify(self, trust: Dict[str, Signer]) -> bool:
        prev = ""
        with open(self.path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                entry_hash = entry.get("entry_hash", "")
                signer_id = entry.get("signer_id", "")
                signature_b64 = entry.get("signature", "")
                sig = base64.b64decode(signature_b64) if signature_b64 else b""
                body = {k: entry[k] for k in entry if k not in ("entry_hash", "signature")}
                body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
                expected_hash = hashlib.sha256((prev + hashlib.sha256(body_bytes).hexdigest()).encode("utf-8")).hexdigest()
                if expected_hash != entry_hash:
                    raise ValueError(f"Audit log chain broken at line {idx}")
                verifier = trust.get(signer_id)
                if verifier is None:
                    raise ValueError(f"Unknown signer_id in audit log at line {idx}: {signer_id}")
                if not verifier.verify(entry_hash.encode("utf-8"), sig):
                    raise ValueError(f"Invalid signature in audit log at line {idx}")
                prev = entry_hash
        return True


# ---- Attestations (in-toto/Sigstore-like minimal) ----

def _canonicalize_attestation(payload: Dict[str, Any]) -> bytes:
    # Exclude signature/public key from signed content
    clean = {k: payload[k] for k in payload if k not in ("signature", "public_key")}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hexdigest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AttestationStore:
    def __init__(self, signer: Signer, trust_store: Optional[Dict[str, Signer]] = None):
        self.signer = signer
        self.trust_store = trust_store or {signer.signer_id: signer}

    def create_attestation(
        self,
        subject: bytes,
        subject_type: str,
        parent_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if subject_type not in ("dataset", "model"):
            raise ValueError("subject_type must be 'dataset' or 'model'")
        att = {
            "id": "att:" + sha256_hexdigest(os.urandom(16))[:16],
            "subject_type": subject_type,
            "subject_hash": "sha256:" + sha256_hexdigest(subject),
            "parent_ids": parent_ids or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
            "signer_id": self.signer.signer_id,
            "algo": "HMAC-SHA256" if isinstance(self.signer, HMACSigner) else ("Ed25519" if _ED25519_AVAILABLE else "Unknown"),
        }
        if _ED25519_AVAILABLE and isinstance(self.signer, Ed25519Signer):
            att["public_key"] = base64.b64encode(self.signer.public_key_bytes).decode("ascii")
        sig = base64.b64encode(self.signer.sign(_canonicalize_attestation(att))).decode("ascii")
        att["signature"] = sig
        return att

    def verify_chain(self, attestations: List[Dict[str, Any]]) -> bool:
        if not attestations:
            raise ValueError("No attestations provided")
        # Build index by id
        by_id = {a.get("id"): a for a in attestations}
        for att in attestations:
            signer_id = att.get("signer_id")
            sig_b64 = att.get("signature")
            if not sig_b64:
                raise ValueError(f"Missing signature in attestation {att.get('id')}")
            verifier = self.trust_store.get(signer_id)
            if verifier is None:
                raise ValueError(f"Unknown signer_id {signer_id} for attestation {att.get('id')}")
            sig = base64.b64decode(sig_b64)
            if not verifier.verify(_canonicalize_attestation(att), sig):
                raise ValueError(f"Signature verification failed for attestation {att.get('id')}")
            # Parent chain existence
            for pid in att.get("parent_ids", []):
                if pid not in by_id:
                    raise ValueError(f"Missing parent attestation {pid} referenced by {att.get('id')}")
        return True


# ---- Privacy and PII redaction ----

@dataclasses.dataclass
class PrivacyConfig:
    enable_feature_hashing: bool = True
    hashing_dim: int = 256
    hashing_salt: str = "dlp_salt"
    enable_pii_redaction: bool = True
    custom_pii_patterns: Optional[List[str]] = None
    anonymize_ids: bool = True


_PII_PATTERNS = [
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    r"\+?\d[\d\-\s]{7,}\d",
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
]


def redact_pii(text: str, cfg: PrivacyConfig) -> str:
    if not cfg.enable_pii_redaction or not isinstance(text, str):
        return text
    patterns = list(_PII_PATTERNS)
    if cfg.custom_pii_patterns:
        patterns.extend(cfg.custom_pii_patterns)
    redacted = text
    for pat in patterns:
        redacted = re.sub(pat, "<REDACTED>", redacted)
    return redacted


def feature_hash(tokens: List[str], dim: int, salt: str) -> List[float]:
    vec = [0.0] * dim
    for t in tokens:
        h = int(hashlib.md5((salt + "::" + t).encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if ((h >> 1) & 1) == 0 else -1.0
        vec[idx] += sign
    return vec


def apply_privacy_transform(
    data: List[Any],
    cfg: Optional[PrivacyConfig] = None,
) -> Tuple[List[Any], Dict[str, Any]]:
    cfg = cfg or PrivacyConfig()
    transformed = []
    meta: Dict[str, Any] = {"pii_redacted": 0, "hashed": cfg.enable_feature_hashing}
    for x in data:
        if isinstance(x, str):
            red = redact_pii(x, cfg)
            if red != x:
                meta["pii_redacted"] += 1
            if cfg.enable_feature_hashing:
                tokens = red.split()
                transformed.append(feature_hash(tokens, cfg.hashing_dim, cfg.hashing_salt))
            else:
                transformed.append(red)
        else:
            transformed.append(x)
    return transformed, meta


# ---- Sandbox for isolated analysis ----

class Sandbox:
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="dlp_sandbox_")
        self._orig_socket_connect = None
        self._orig_socket_create_connection = None
        self._orig_open = None

    def _block_network(self):
        def deny_connect(*args, **kwargs):
            raise PermissionError("Outbound network blocked by sandbox")

        self._orig_socket_connect = socket.socket.connect
        self._orig_socket_create_connection = socket.create_connection
        socket.socket.connect = deny_connect  # type: ignore
        socket.create_connection = deny_connect  # type: ignore

        # Also block urllib by environment
        os.environ["NO_OUTBOUND"] = "1"

    def _restrict_writes(self):
        self._orig_open = open

        def sandboxed_open(file, mode="r", *args, **kwargs):
            # Writes only allowed inside tmpdir
            write_modes = ("w", "a", "x", "+")
            if any(m in mode for m in write_modes):
                abspath = os.path.abspath(file)
                if not abspath.startswith(self.tmpdir):
                    raise PermissionError(f"Write outside sandbox denied: {abspath}")
            return self._orig_open(file, mode, *args, **kwargs)

        globals()["open"] = sandboxed_open  # monkey-patch builtins open in this module

    def __enter__(self):
        self._block_network()
        self._restrict_writes()
        self._cwd = os.getcwd()
        os.chdir(self.tmpdir)
        return self

    def __exit__(self, exc_type, exc, tb):
        # restore
        if self._orig_socket_connect is not None:
            socket.socket.connect = self._orig_socket_connect  # type: ignore
        if self._orig_socket_create_connection is not None:
            socket.create_connection = self._orig_socket_create_connection  # type: ignore
        if self._orig_open is not None:
            globals()["open"] = self._orig_open
        os.chdir(self._cwd)
        # destroy sandbox dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ---- Detection algorithms ----

def _is_text_dataset(dataset: List[Any]) -> bool:
    return all(isinstance(x, str) for x in dataset)


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[A-Za-z0-9_\-\#\@\$\%\^\&\+\=]+", text)


def detect_backdoor_trigger_text(
    model: Any,
    dataset: List[str],
    max_tokens_to_test: int = 200,
    purity_threshold: float = 0.9,
    injection_success_threshold: float = 0.7,
) -> Optional[Dict[str, Any]]:
    # Collect predictions
    preds = model.predict(dataset)
    # Build token->label counts
    token_counts: Dict[str, Dict[Any, int]] = {}
    token_total: Dict[str, int] = {}
    unique_tokens: Dict[str, int] = {}
    for i, text in enumerate(dataset):
        tokens = set(_tokenize(text))
        for t in tokens:
            token_total[t] = token_total.get(t, 0) + 1
            unique_tokens[t] = unique_tokens.get(t, 0) + 1
            lab = preds[i]
            token_counts.setdefault(t, {}).setdefault(lab, 0)
            token_counts[t][lab] += 1
    # Rarity: less than 5% of samples
    n = len(dataset)
    candidates = []
    for t, cnt in token_total.items():
        freq = cnt / max(1, n)
        if freq <= 0.05:  # rare token
            label_counts = token_counts.get(t, {})
            if not label_counts:
                continue
            top_label, top_count = max(label_counts.items(), key=lambda kv: kv[1])
            purity = top_count / cnt
            if purity >= purity_threshold:
                candidates.append((t, top_label, purity, cnt))
    # Test injections
    candidates.sort(key=lambda x: (-x[2], x[3]))
    candidates = candidates[:max_tokens_to_test]
    for t, target_label, purity, cnt in candidates:
        clean_indices = [i for i, text in enumerate(dataset) if t not in text]
        if not clean_indices:
            continue
        sample_indices = random.sample(clean_indices, min(20, len(clean_indices)))
        success = 0
        trials = 0
        inj_examples = []
        for idx in sample_indices:
            inj_text = dataset[idx] + " " + t
            pred = model.predict([inj_text])[0]
            trials += 1
            if pred == target_label:
                success += 1
                inj_examples.append({"original_index": idx, "injected_text": inj_text, "pred": pred})
        rate = success / max(1, trials)
        if rate >= injection_success_threshold:
            # Minimal trigger: token t
            poisoned_indices = [i for i, text in enumerate(dataset) if t in text]
            return {
                "trigger": t,
                "target_label": target_label,
                "purity": purity,
                "injection_success_rate": rate,
                "poisoned_indices": poisoned_indices,
                "injection_examples": inj_examples[:5],
            }
    return None


def spectral_signature_scores_numeric(X: List[List[float]], labels: Optional[List[Any]] = None) -> Dict[Any, List[float]]:
    if not X:
        return {}
    # Group by labels if provided, else single group
    if labels is None:
        groups = {None: list(range(len(X)))}
    else:
        groups: Dict[Any, List[int]] = {}
        for i, y in enumerate(labels):
            groups.setdefault(y, []).append(i)
    scores: Dict[Any, List[float]] = {}
    for lab, idxs in groups.items():
        if not idxs:
            continue
        subset = [X[i] for i in idxs]
        if _np is not None:
            arr = _np.array(subset, dtype=float)
            mu = arr.mean(axis=0, keepdims=True)
            centered = arr - mu
            cov = centered.T @ centered / max(1, arr.shape[0] - 1)
            try:
                vals, vecs = _np.linalg.eigh(cov)
                top_vec = vecs[:, -1]
                proj = centered @ top_vec
                sc = _np.abs(proj).tolist()
            except Exception:
                sc = _np.abs(centered).sum(axis=1).tolist()
        else:
            # fallback: sum of absolute z-scores per feature
            # compute mean and std per feature
            m = len(subset[0])
            means = [sum(row[j] for row in subset) / len(subset) for j in range(m)]
            stds = []
            for j in range(m):
                var = sum((row[j] - means[j]) ** 2 for row in subset) / max(1, len(subset) - 1)
                stds.append(var ** 0.5 if var > 1e-12 else 1.0)
            sc = []
            for row in subset:
                zsum = 0.0
                for j in range(m):
                    z = (row[j] - means[j]) / (stds[j] or 1.0)
                    zsum += abs(z)
                sc.append(zsum)
        # Map back to absolute indices
        full_scores = [0.0] * len(X)
        for rank, idx in enumerate(idxs):
            full_scores[idx] = float(sc[rank])
        scores[lab] = full_scores
    return scores


def drift_js_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
    def kl(a, b):
        eps = 1e-12
        return sum(ai * (0 if ai == 0 else (math_log(ai / max(bi, eps)))) for ai, bi in zip(a, b))

    import math as _math
    global math_log
    math_log = _math.log

    keys = sorted(set(list(p.keys()) + list(q.keys())))
    pvec = [p.get(k, 0.0) for k in keys]
    qvec = [q.get(k, 0.0) for k in keys]
    # normalize
    sp = sum(pvec) or 1.0
    sq = sum(qvec) or 1.0
    pvec = [x / sp for x in pvec]
    qvec = [x / sq for x in qvec]
    m = [(a + b) / 2.0 for a, b in zip(pvec, qvec)]
    return 0.5 * (kl(pvec, m) + kl(qvec, m))


def token_distribution(texts: List[str]) -> Dict[str, float]:
    counts: Dict[str, int] = {}
    for t in texts:
        for tok in _tokenize(t):
            counts[tok] = counts.get(tok, 0) + 1
    return {k: float(v) for k, v in counts.items()}


# ---- Main Tracer ----

class DLPTracer:
    def __init__(
        self,
        audit_log_path: str,
        signer: Optional[Signer] = None,
        trust_store: Optional[Dict[str, Signer]] = None,
        quarantine_dir: Optional[str] = None,
    ):
        self.signer = signer or HMACSigner(key=hashlib.sha256(b"default_dlp_key").digest(), signer_id="hmac:dlp")
        self.trust_store = trust_store or {self.signer.signer_id: self.signer}
        self.attestations = AttestationStore(self.signer, self.trust_store)
        self.audit = AuditLog(audit_log_path, self.signer)
        self.quarantine_dir = quarantine_dir or os.path.join(tempfile.gettempdir(), "dlp_quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def ingest_with_attestations(self, subject: bytes, attestations: List[Dict[str, Any]]) -> bool:
        # Verify chain and that one attestation matches subject hash
        ok = self.attestations.verify_chain(attestations)
        subj_hash = "sha256:" + sha256_hexdigest(subject)
        if subj_hash not in [a.get("subject_hash") for a in attestations]:
            raise ValueError("No attestation matches provided subject hash")
        self.audit.append("attestations_verified", {"subject_hash": subj_hash, "count": len(attestations)})
        return ok

    def create_attestation(self, subject: bytes, subject_type: str, parent_ids: Optional[List[str]] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        att = self.attestations.create_attestation(subject, subject_type, parent_ids, metadata)
        self.audit.append("attestation_created", {"attestation_id": att["id"], "subject_type": subject_type})
        return att

    def verify_attestation_chain(self, attestations: List[Dict[str, Any]]) -> bool:
        ok = self.attestations.verify_chain(attestations)
        self.audit.append("attestation_chain_verified", {"count": len(attestations)})
        return ok

    def quarantine_artifact(self, artifact_path: Optional[str], reason: str) -> Optional[str]:
        if not artifact_path or not os.path.exists(artifact_path):
            return None
        base = os.path.basename(artifact_path.rstrip(os.sep))
        dst = os.path.join(self.quarantine_dir, f"{int(time.time())}_{base}")
        try:
            shutil.move(artifact_path, dst)
            self.audit.append("artifact_quarantined", {"path": dst, "reason": reason})
            return dst
        except Exception as e:
            self.audit.append("artifact_quarantine_failed", {"path": artifact_path, "error": str(e)})
            return None

    def analyze_dataset(
        self,
        dataset: List[Any],
        reference_dataset: Optional[List[Any]] = None,
        privacy: Optional[PrivacyConfig] = None,
        attestations: Optional[List[Dict[str, Any]]] = None,
        artifact_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        report: Dict[str, Any] = {"ethical_warning": ETHICAL_WARNING, "type": "dataset_analysis"}
        if attestations is not None:
            try:
                self.verify_attestation_chain(attestations)
                report["attestation_verification"] = "ok"
            except Exception as e:
                report["attestation_verification"] = f"failed: {e}"
                raise
        # Privacy transforms
        transformed, privacy_meta = apply_privacy_transform(dataset, privacy)
        report["privacy"] = privacy_meta
        # Drift
        drift = None
        if reference_dataset is not None and _is_text_dataset(dataset) and _is_text_dataset(reference_dataset):
            drift = drift_js_divergence(token_distribution(reference_dataset), token_distribution(dataset))
            report["drift_js_divergence"] = drift
            if drift is not None and drift > 0.3:
                report.setdefault("alerts", []).append({"severity": "MEDIUM", "type": "distribution_drift", "score": drift})
        # Spectral signatures for numeric data
        if transformed and isinstance(transformed[0], list) and all(isinstance(v, (int, float)) for v in transformed[0]):
            scores = spectral_signature_scores_numeric(transformed)
            # mark top 1% as outliers
            sc = list(scores.values())[0] if scores else []
            if sc:
                threshold = sorted(sc)[max(0, int(0.99 * (len(sc) - 1)))]
                outliers = [i for i, s in enumerate(sc) if s >= threshold]
                report["spectral_outliers"] = {"indices": outliers, "threshold": threshold, "count": len(outliers)}
                if len(outliers) >= max(1, int(0.01 * len(sc))):
                    report.setdefault("alerts", []).append({"severity": "LOW", "type": "spectral_outliers", "count": len(outliers)})
        self.audit.append("dataset_analyzed", {"size": len(dataset), "alerts": len(report.get("alerts", []))})
        return report

    def evaluate_model_in_sandbox(self, fn: Callable[[Sandbox], Any]) -> Any:
        with Sandbox() as sb:
            # sandbox available to callable for writing in allowed dir
            return fn(sb)

    def analyze_model(
        self,
        model: Any,
        dataset: List[Any],
        sandboxed: bool = True,
        privacy: Optional[PrivacyConfig] = None,
        artifact_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        report: Dict[str, Any] = {"ethical_warning": ETHICAL_WARNING, "type": "model_analysis", "sandboxed": bool(sandboxed)}

        def _analysis(_: Sandbox) -> Dict[str, Any]:
            local_report: Dict[str, Any] = {}
            # Ensure dataset is privacy transformed for analysis stage as needed
            # but use original text for backdoor token detection
            # Backdoor detection for text
            if _is_text_dataset(dataset):
                res = detect_backdoor_trigger_text(model, dataset)
                if res:
                    local_report["backdoor_trigger"] = res
                    local_report.setdefault("alerts", []).append(
                        {"severity": "HIGH", "type": "model_backdoor_detected", "trigger": res["trigger"], "target_label": res["target_label"]}
                    )
            # For numeric datasets, basic spectral signature on representations if model exposes embeddings
            # If dataset numeric, we can attempt to use model.embed if available
            try:
                if hasattr(model, "embed"):
                    emb = model.embed(dataset)
                    if isinstance(emb, list) and emb and isinstance(emb[0], list):
                        labels = None
                        if hasattr(model, "predict"):
                            labels = model.predict(dataset)
                        scores = spectral_signature_scores_numeric(emb, labels)
                        local_report["spectral_scores"] = {str(k): v for k, v in scores.items()}
            except Exception as e:
                local_report.setdefault("errors", []).append(f"spectral_signature_failed: {e}")

            # Minimal influence proxy: per-sample prediction change when perturbed slightly (text only)
            if _is_text_dataset(dataset) and hasattr(model, "predict"):
                preds = model.predict(dataset)
                flips = 0
                for i, txt in enumerate(dataset[:50]):  # limit
                    pert = txt + " "
                    try:
                        p2 = model.predict([pert])[0]
                        if p2 != preds[i]:
                            flips += 1
                    except Exception:
                        continue
                if flips > 0:
                    local_report.setdefault("alerts", []).append({"severity": "LOW", "type": "sensitivity_flips", "count": flips})
            return local_report

        if sandboxed:
            analysis_report = self.evaluate_model_in_sandbox(_analysis)
        else:
            analysis_report = _analysis(None)  # type: ignore
        report.update(analysis_report)

        # Quarantine if high-severity findings
        severity_levels = [a.get("severity") for a in report.get("alerts", [])] if report.get("alerts") else []
        if "HIGH" in severity_levels:
            qpath = self.quarantine_artifact(artifact_path, reason="high_severity_findings")
            if qpath:
                report["quarantined_path"] = qpath

        self.audit.append("model_analyzed", {"alerts": len(report.get("alerts", [])), "sandboxed": sandboxed})
        return report


# ---- Example Model Interface for testing ----
class SimpleTextModel:
    """
    A simple baseline model where predictions depend on tokens.
    You can simulate a backdoor by specifying a trigger token and a target label.
    """

    def __init__(self, trigger_token: Optional[str] = None, target_label: Optional[Any] = None):
        self.trigger = trigger_token
        self.target_label = target_label

    def predict(self, texts: List[str]) -> List[Any]:
        out = []
        for t in texts:
            if self.trigger and self.trigger in t:
                out.append(self.target_label)
            else:
                # default: length-based class just for variability
                out.append("A" if len(t) % 2 == 0 else "B")
        return out


# ---- Public API convenience functions ----

def default_tracer(audit_log_path: Optional[str] = None) -> DLPTracer:
    audit_path = audit_log_path or os.path.join(tempfile.gettempdir(), "dlp_audit.log")
    signer = HMACSigner(key=hashlib.sha256(b"default_dlp_key").digest(), signer_id="hmac:dlp")
    trust = {signer.signer_id: signer}
    return DLPTracer(audit_log_path=audit_path, signer=signer, trust_store=trust)


# ---- Module-level safeguards ----

__all__ = [
    "DLPTracer",
    "AuditLog",
    "Signer",
    "HMACSigner",
    "Ed25519Signer",
    "PrivacyConfig",
    "redact_pii",
    "apply_privacy_transform",
    "default_tracer",
    "SimpleTextModel",
    "ETHICAL_WARNING",
]