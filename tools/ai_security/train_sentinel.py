import os
import json
import time
import hmac
import base64
import hashlib
import logging
import threading
import secrets
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# Ethical and legal warning
ETHICAL_WARNING = (
    "TrainSentinel is a security instrumentation tool intended for authorized testing and "
    "defensive use only. Do not deploy on data or systems for which you do not have explicit "
    "permission. Ensure compliance with privacy, data minimization, and applicable regulations."
)

logger = logging.getLogger("train_sentinel")
if not logger.handlers:
    h = logging.StreamHandler()
    f = logging.Formatter("[TrainSentinel] %(asctime)s %(levelname)s: %(message)s")
    h.setFormatter(f)
    logger.addHandler(h)
logger.setLevel(logging.INFO)


class TrainHaltRequested(Exception):
    pass


class SentinelSecurityError(Exception):
    pass


class _Welford:
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, x: float):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.M2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return self.variance ** 0.5


@dataclass
class DPPolicy:
    max_grad_norm: Optional[float] = None
    enforce_dp: bool = False


@dataclass
class DetectionThresholds:
    spectral_score: float = 3.0
    cluster_outlier_ratio: float = 0.02  # ~2%
    grad_z_threshold: float = 4.0


@dataclass
class AllowlistPolicy:
    frameworks: List[str] = field(default_factory=lambda: ["pytorch", "tensorflow", "jax"])
    allowed_nodes: List[str] = field(default_factory=list)  # hostnames or IDs; empty means allow all


@dataclass
class EncryptionPolicy:
    rotate_every_batches: int = 500
    key_id: str = "default"
    key_bytes: Optional[bytes] = None  # If None, generated; NEVER persist raw keys in source control


@dataclass
class SentinelConfig:
    mode: str = "shadow"  # shadow | enforce
    thresholds: DetectionThresholds = field(default_factory=DetectionThresholds)
    dp_policy: DPPolicy = field(default_factory=DPPolicy)
    allowlist: AllowlistPolicy = field(default_factory=AllowlistPolicy)
    encryption: EncryptionPolicy = field(default_factory=EncryptionPolicy)
    provenance_dir: str = ".train_sentinel_provenance"
    node_id: str = field(default_factory=lambda: os.environ.get("NODE_ID", "node-unknown"))
    seed: int = 1337
    telemetry_file: Optional[str] = None  # encrypted JSONL file
    human_approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None  # returns True if approved
    shadow_default: bool = True  # default shadow unless explicitly set
    deterministic: bool = True


class _Encryptor:
    """
    AEAD-like simple encryptor with HMAC-SHA256 authenticity and a stream keystream.
    For production, prefer a library AEAD (e.g., AES-GCM/ChaCha20-Poly1305 via cryptography).
    """
    def __init__(self, key: bytes, key_id: str):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise SentinelSecurityError("Encryption key must be >= 32 bytes.")
        self._key = bytes(key)
        self._key_id = key_id

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        # Derive key stream by hashing key + nonce + counter blocks
        out = bytearray()
        counter = 0
        while len(out) < length:
            h = hashlib.sha256(self._key + nonce + counter.to_bytes(8, "big")).digest()
            out.extend(h)
            counter += 1
        return bytes(out[:length])

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> Dict[str, str]:
        nonce = secrets.token_bytes(16)
        ks = self._keystream(nonce, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, ks))
        mac = hmac.new(self._key, (aad or b"") + nonce + ct, hashlib.sha256).digest()
        return {
            "kid": self._key_id,
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode(),
            "mac": base64.b64encode(mac).decode(),
        }

    def decrypt(self, blob: Dict[str, str], aad: Optional[bytes] = None) -> bytes:
        nonce = base64.b64decode(blob["nonce"])
        ct = base64.b64decode(blob["ct"])
        mac = base64.b64decode(blob["mac"])
        exp = hmac.new(self._key, (aad or b"") + nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, exp):
            raise SentinelSecurityError("Telemetry MAC verification failed.")
        ks = self._keystream(nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))

    @property
    def key_id(self) -> str:
        return self._key_id


class _TelemetrySink:
    def __init__(self, config: SentinelConfig):
        self._config = config
        key = config.encryption.key_bytes or secrets.token_bytes(32)
        self._encryptor = _Encryptor(key, config.encryption.key_id)
        self._batch_counter = 0
        self._lock = threading.Lock()
        self._file = None
        if config.telemetry_file:
            d = os.path.dirname(config.telemetry_file)
            if d:
                os.makedirs(d, exist_ok=True)
            self._file = open(config.telemetry_file, "a", encoding="utf-8")

    def rotate_keys(self):
        with self._lock:
            new_key = secrets.token_bytes(32)
            new_kid = f"{self._encryptor.key_id}-rot-{int(time.time())}"
            self._encryptor = _Encryptor(new_key, new_kid)
            self._batch_counter = 0
            self._emit({"event": "key_rotation", "kid": new_kid})

    def emit(self, obj: Dict[str, Any]):
        with self._lock:
            self._batch_counter += 1
            if self._config.encryption.rotate_every_batches > 0 and \
               self._batch_counter >= self._config.encryption.rotate_every_batches:
                self.rotate_keys()
            self._emit(obj)

    def _emit(self, obj: Dict[str, Any]):
        obj["ts"] = time.time()
        obj["node_id"] = self._config.node_id
        plaintext = json.dumps(obj, sort_keys=True).encode()
        aad = f"TrainSentinel:{self._config.node_id}".encode()
        blob = self._encryptor.encrypt(plaintext, aad=aad)
        record = json.dumps({"a": "1", "e": blob}, sort_keys=True)
        if self._file:
            self._file.write(record + "\n")
            self._file.flush()
        else:
            # If no file, still log length and key id without leaking plaintext
            logger.debug(f"Encrypted telemetry len={len(record)} kid={self._encryptor.key_id}")

    def close(self):
        if self._file:
            self._file.close()


class _Attestor:
    """
    Creates signed attestations for detections and checkpoint provenance.
    Uses HMAC if no asymmetric keys are configured.
    """
    def __init__(self, config: SentinelConfig):
        self._config = config
        self._key = secrets.token_bytes(32)
        self._kid = f"attest-{hashlib.sha256(self._key).hexdigest()[:8]}"

    def attest(self, subject: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(subject, sort_keys=True).encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return {
            "predicateType": "https://in-toto.io/Statement/v0.1",
            "subject": subject,
            "attestation": {
                "sig_alg": "HMAC-SHA256",
                "kid": self._kid,
                "sig": sig,
            },
            "provenance": {
                "node_id": self._config.node_id,
                "config_hash": hashlib.sha256(json.dumps(self._config_dict(), sort_keys=True).encode()).hexdigest(),
                "time": time.time(),
            },
        }

    def _config_dict(self) -> Dict[str, Any]:
        c = self._config
        return {
            "mode": c.mode,
            "thresholds": vars(c.thresholds),
            "dp_policy": vars(c.dp_policy),
            "allowlist": {"frameworks": c.allowlist.frameworks, "allowed_nodes": c.allowlist.allowed_nodes},
            "encryption": {"rotate_every_batches": c.encryption.rotate_every_batches, "key_id": c.encryption.key_id},
            "node_id": c.node_id,
            "seed": c.seed,
            "deterministic": c.deterministic,
        }


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _kmeans2(X: List[List[float]], max_iter: int = 30) -> Tuple[List[int], List[List[float]]]:
    import random  # noqa: F401
    if len(X) < 2:
        return [0] * len(X), [X[0] if X else [0.0], X[0] if X else [0.0]]
    n = len(X)
    d = len(X[0])
    centroids = [X[0][:], X[-1][:]]
    labels = [0] * n
    for _ in range(max_iter):
        # Assign
        changed = False
        for i, x in enumerate(X):
            d0 = sum((x[j] - centroids[0][j]) ** 2 for j in range(d))
            d1 = sum((x[j] - centroids[1][j]) ** 2 for j in range(d))
            l = 0 if d0 <= d1 else 1
            if labels[i] != l:
                labels[i] = l
                changed = True
        # Update
        for k in (0, 1):
            pts = [X[i] for i in range(n) if labels[i] == k]
            if pts:
                centroids[k] = [sum(p[j] for p in pts) / len(pts) for j in range(d)]
        if not changed:
            break
    return labels, centroids


def _spectral_outlier_scores(X: List[List[float]]) -> List[float]:
    # Compute top eigenvector via power iteration on covariance
    import math
    if not X:
        return []
    n, d = len(X), len(X[0])
    # Center
    mean = [sum(X[i][j] for i in range(n)) / n for j in range(d)]
    C = [[X[i][j] - mean[j] for j in range(d)] for i in range(n)]
    v = [1.0 / math.sqrt(d)] * d
    for _ in range(20):
        # multiply by covariance matrix: (C^T C) v
        tmp = [0.0] * d
        for j in range(d):
            s = 0.0
            for i in range(n):
                ci = C[i]
                s += ci[j] * sum(ci[k] * v[k] for k in range(d))
            tmp[j] = s
        norm = math.sqrt(sum(t * t for t in tmp)) or 1.0
        v = [t / norm for t in tmp]
    scores = []
    for i in range(n):
        proj = sum(C[i][k] * v[k] for k in range(d))
        scores.append(abs(proj))
    return scores


class TrainSentinel:
    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        if self.config.shadow_default and self.config.mode not in ("shadow", "enforce"):
            self.config.mode = "shadow"
        # Determinism settings
        if self.config.deterministic:
            try:
                import numpy as np  # type: ignore
                try:
                    np.random.seed(self.config.seed)  # type: ignore[attr-defined]
                except Exception:
                    pass
            except Exception:
                pass
            os.environ["PYTHONHASHSEED"] = str(self.config.seed)
        # Allowlist enforcement
        node = self.config.node_id
        if self.config.allowlist.allowed_nodes and node not in self.config.allowlist.allowed_nodes:
            logger.warning("Node not in allowlist; running in shadow mode.")
            self.config.mode = "shadow"
        self._telemetry = _TelemetrySink(self.config)
        self._attestor = _Attestor(self.config)
        self._grad_stats = _Welford()
        self._last_safe_checkpoint: Optional[str] = None
        self._quarantined_batches: set = set()
        self._hold_safe = False
        logger.info(ETHICAL_WARNING)

    def close(self):
        self._telemetry.close()

    # Provenance handling
    def record_checkpoint(self, path: str, verified_ok: bool = True) -> None:
        if not os.path.exists(path):
            logger.error("Checkpoint path does not exist.")
            return
        digest = _sha256_file(path)
        att = self._attestor.attest({"type": "checkpoint", "path": os.path.abspath(path), "sha256": digest})
        os.makedirs(self.config.provenance_dir, exist_ok=True)
        out = os.path.join(self.config.provenance_dir, f"checkpoint-{int(time.time())}.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(att, f, sort_keys=True)
        if verified_ok:
            self._last_safe_checkpoint = path
        self._telemetry.emit({"event": "checkpoint_recorded", "path": path, "sha256": digest})

    def rollback_to_last_safe_checkpoint(self) -> Optional[str]:
        if not self._last_safe_checkpoint:
            logger.warning("No safe checkpoint; cannot rollback.")
            return None
        self._telemetry.emit({"event": "rollback_initiated", "target": self._last_safe_checkpoint})
        return self._last_safe_checkpoint

    # Policy gate
    def _human_approval(self, context: Dict[str, Any]) -> bool:
        cb = self.config.human_approval_callback
        if cb:
            try:
                return bool(cb(context))
            except Exception as e:
                logger.error(f"Human approval callback error: {e}")
        # Environment override for CI gates
        env = os.environ.get("TRAIN_SENTINEL_APPROVE", "").lower()
        return env in ("1", "true", "yes", "y", "approve")

    def _enter_hold_safe(self, reason: str, details: Dict[str, Any]):
        self._hold_safe = True
        self._telemetry.emit({"event": "hold_safe_enter", "reason": reason, "details": details})
        att = self._attestor.attest({"type": "hold_safe", "reason": reason, "details": details})
        os.makedirs(self.config.provenance_dir, exist_ok=True)
        with open(os.path.join(self.config.provenance_dir, f"hold-safe-{int(time.time())}.json"), "w", encoding="utf-8") as f:
            json.dump(att, f, sort_keys=True)
        if self.config.mode == "enforce":
            if self._human_approval({"reason": reason, "details": details}):
                raise TrainHaltRequested(f"Training halt approved: {reason}")
            else:
                logger.warning("Halt not approved; staying in hold-safe monitoring.")

    # Detection primitives (no raw data persisted)
    def _detect_activation_anomalies(self, activations: List[List[float]]) -> Dict[str, Any]:
        result = {"spectral": 0.0, "cluster_ratio": 0.0, "flag": False, "reason": []}
        if not activations or len(activations) < 4:
            return result
        scores = _spectral_outlier_scores(activations)
        # z-score within batch
        import statistics
        mu = statistics.mean(scores)
        sd = statistics.pstdev(scores) or 1.0
        zmax = (max(scores) - mu) / sd
        result["spectral"] = zmax
        if zmax >= self.config.thresholds.spectral_score:
            result["flag"] = True
            result["reason"].append("spectral_outlier")
        labels, centroids = _kmeans2(activations)
        counts = [labels.count(0), labels.count(1)]
        minority = min(counts) / max(1, len(labels))
        result["cluster_ratio"] = minority
        # separation
        import math
        sep = math.sqrt(sum((centroids[0][i] - centroids[1][i]) ** 2 for i in range(len(centroids[0]))))
        if minority <= self.config.thresholds.cluster_outlier_ratio and sep > 1e-3:
            result["flag"] = True
            result["reason"].append("activation_cluster_outlier")
        return result

    def _detect_grad_anomalies(self, grad_norm: float) -> Dict[str, Any]:
        self._grad_stats.update(grad_norm)
        mean = self._grad_stats.mean
        std = self._grad_stats.std or 1.0
        z = (grad_norm - mean) / std
        flags = []
        if self.config.dp_policy.max_grad_norm is not None and grad_norm > self.config.dp_policy.max_grad_norm * 1.01:
            flags.append("grad_clip_violation")
        if abs(z) >= self.config.thresholds.grad_z_threshold and self._grad_stats.n > 10:
            flags.append("grad_drift")
        return {"grad_norm": grad_norm, "z": z, "flag": bool(flags), "reason": flags}

    # Public interface for any framework to report metrics for a batch
    def inspect_batch(self, batch_id: str, metadata: Dict[str, Any], activations: List[List[float]], grad_norm: Optional[float]) -> Dict[str, Any]:
        # Only accept whitelisted framework report
        fw = metadata.get("framework", "unknown").lower()
        if self.config.allowlist.frameworks and fw not in self.config.allowlist.frameworks:
            logger.warning(f"Framework {fw} not allowlisted; ignoring.")
            return {"ignored": True}
        # No raw sample content should be in metadata
        leak_keys = [k for k in metadata.keys() if k.lower() in ("images", "samples", "raw", "bytes")]
        if leak_keys:
            raise SentinelSecurityError("Raw training data keys present in metadata; reject.")
        act_det = self._detect_activation_anomalies(activations)
        grad_det = {"flag": False, "reason": []}
        if grad_norm is not None:
            grad_det = self._detect_grad_anomalies(grad_norm)
        suspicious = act_det.get("flag") or grad_det.get("flag")
        event = {
            "event": "batch_inspected",
            "batch_id": batch_id,
            "fw": fw,
            "activation": {k: v for k, v in act_det.items() if k != "flag"},
            "grad": {k: v for k, v in grad_det.items() if k != "flag"},
            "suspicious": bool(suspicious),
        }
        self._telemetry.emit(event)
        if suspicious:
            self._quarantined_batches.add(batch_id)
            self._enter_hold_safe("batch_anomaly", {"batch_id": batch_id, "act": act_det, "grad": grad_det})
        return {"suspicious": bool(suspicious), "activation": act_det, "grad": grad_det}

    def quarantined_batches(self) -> List[str]:
        return sorted(list(self._quarantined_batches))

    def in_hold_safe(self) -> bool:
        return self._hold_safe

    # Framework-specific helpers (optional)
    def attach_pytorch(self, model: Any, optimizer: Optional[Any] = None, framework_name: str = "pytorch") -> Callable[[], None]:
        """
        Attaches lightweight hooks to a PyTorch model and optimizer to collect read-only activations and gradient stats.
        Returns a callable to detach hooks. This avoids persisting raw inputs; only activations and grad norms are processed.
        """
        try:
            import torch  # noqa: F401
            import torch.nn as nn
        except Exception as e:
            logger.error(f"PyTorch not available: {e}")
            def no_op(): ...
            return no_op

        handles = []
        activation_buffer: List[List[float]] = []
        lock = threading.Lock()

        def _hook(module, inp, out):
            # Only record for leaf layers (Linear/Conv) to reduce volume
            if not isinstance(module, (nn.Linear, nn.Conv1d, nn.Conv2d, nn.Conv3d)):
                return
            try:
                act = out
                if isinstance(act, (list, tuple)):
                    act = act[0]
                # Per-sample mean pooled vector to minimize leakage
                # Avoid storing tensors; convert minimal numeric summaries
                while hasattr(act, "dim") and act.dim() > 2:
                    act = act.mean(dim=-1)
                if hasattr(act, "dim") and act.dim() == 2:
                    N = int(min(32, act.size(0)))
                    # We further mean-reduce features to cap dimension (safety)
                    try:
                        # Try to down-project to 16 dims by chunked averaging
                        F = int(act.size(1))
                        if F > 16:
                            step = max(1, F // 16)
                            act = act[:, : step * 16]
                            act = act.reshape(N, 16, step).mean(dim=-1)
                    except Exception:
                        pass
                    vecs = act[:N].detach().cpu().tolist()
                    with lock:
                        activation_buffer.extend(vecs)
                        if len(activation_buffer) > 64:
                            activation_buffer[:] = activation_buffer[-64:]
            except Exception:
                # Do not let hook failures affect training
                pass

        for m in model.modules():
            if len(list(m.children())) == 0:
                try:
                    handles.append(m.register_forward_hook(_hook))
                except Exception:
                    pass

        # Wrap optimizer.step to capture grad norm after backward
        original_step = None
        if optimizer is not None:
            original_step = optimizer.step

            def wrapped_step(*args, **kwargs):
                # compute grad norm
                gn = 0.0
                try:
                    total = 0.0
                    for p in model.parameters():
                        if getattr(p, "grad", None) is not None:
                            g = p.grad
                            try:
                                total += float(g.detach().norm().item() ** 2)
                            except Exception:
                                pass
                    gn = total ** 0.5
                except Exception:
                    pass
                # Snapshot activations
                with lock:
                    acts = [list(v) for v in activation_buffer]
                    activation_buffer.clear()
                # Safe device capture
                device_str = "unknown"
                try:
                    params = list(model.parameters())
                    if params:
                        device_str = str(params[0].device)
                except Exception:
                    pass
                bid = f"{int(time.time()*1000)}-{secrets.token_hex(4)}"
                try:
                    self.inspect_batch(
                        batch_id=bid,
                        metadata={"framework": framework_name, "device": device_str},
                        activations=acts,
                        grad_norm=gn,
                    )
                except Exception as e:
                    logger.error(f"inspect_batch error: {e}")
                return original_step(*args, **kwargs)
            optimizer.step = wrapped_step

        def detach():
            for h in handles:
                try:
                    h.remove()
                except Exception:
                    pass
            if optimizer is not None and original_step is not None:
                optimizer.step = original_step

        return detach

    def keras_callback(self) -> Any:
        """
        Returns a Keras Callback capturing activations and grad norms without exposing raw inputs.
        """
        try:
            import tensorflow as tf  # type: ignore
        except Exception as e:
            logger.error(f"TensorFlow not available: {e}")
            return None

        sentinel = self

        class SentinelCallback(tf.keras.callbacks.Callback):
            def on_train_batch_end(self, batch, logs=None):
                logs = logs or {}
                acts = []
                try:
                    out = getattr(self.model, "last_batch_outputs", None)
                    if out is not None:
                        o = out
                        if isinstance(o, (list, tuple)):
                            o = o[0]
                        o = tf.convert_to_tensor(o)
                        if len(o.shape) > 2:
                            for _ in range(len(o.shape) - 2):
                                o = tf.reduce_mean(o, axis=-1)
                        o = o[:32]
                        acts = o.numpy().tolist()
                except Exception:
                    acts = []
                bid = f"tf-{int(time.time()*1000)}-{secrets.token_hex(4)}"
                sentinel.inspect_batch(batch_id=bid, metadata={"framework": "tensorflow"}, activations=acts, grad_norm=None)

        return SentinelCallback()

    def jax_wrap_step(self, step_fn: Callable[..., Any]) -> Callable[..., Any]:
        """
        Wraps a JAX training step function to log grad norms and simple activations proxy if provided.
        Expect step_fn to return (new_state, metrics_dict) where metrics may include 'activations' (list of vectors).
        """
        def wrapped(*args, **kwargs):
            out = step_fn(*args, **kwargs)
            try:
                _, metrics = out
            except Exception:
                return out
            activations = metrics.get("activations", [])
            grad_norm = metrics.get("grad_norm", None)
            bid = f"jax-{int(time.time()*1000)}-{secrets.token_hex(4)}"
            self.inspect_batch(batch_id=bid, metadata={"framework": "jax"}, activations=activations, grad_norm=grad_norm)
            return out
        return wrapped

    # Control plane
    def policy_switch(self, mode: str):
        if mode not in ("shadow", "enforce"):
            raise ValueError("mode must be 'shadow' or 'enforce'")
        self.config.mode = mode
        self._telemetry.emit({"event": "policy_switch", "mode": mode})

    # Canary seeding helper (does not persist raw content)
    def seed_canary_marker(self, tag: str) -> Dict[str, Any]:
        # deterministic token for canary tracking
        token = hashlib.sha256(f"{tag}:{self.config.seed}".encode()).hexdigest()[:16]
        self._telemetry.emit({"event": "canary_seeded", "tag": tag, "token": token})
        return {"tag": tag, "token": token}

    # Helper to simulate a threshold breach for testing gates
    def simulate_breach(self, reason: str = "simulated"):
        self._enter_hold_safe(reason, {"simulated": True})


# Convenience factory
def create_sentinel(config: Optional[Dict[str, Any]] = None) -> TrainSentinel:
    """
    Create a TrainSentinel with dict-based policy-as-code config. Deterministic by default.
    """
    cfg = config or {}
    obj = SentinelConfig(
        mode=cfg.get("mode", "shadow"),
        thresholds=DetectionThresholds(**cfg.get("thresholds", {})),
        dp_policy=DPPolicy(**cfg.get("dp_policy", {})),
        allowlist=AllowlistPolicy(**cfg.get("allowlist", {})) if cfg.get("allowlist") else AllowlistPolicy(),
        encryption=EncryptionPolicy(**cfg.get("encryption", {})) if cfg.get("encryption") else EncryptionPolicy(),
        provenance_dir=cfg.get("provenance_dir", ".train_sentinel_provenance"),
        node_id=cfg.get("node_id", os.environ.get("NODE_ID", "node-unknown")),
        seed=cfg.get("seed", 1337),
        telemetry_file=cfg.get("telemetry_file"),
        shadow_default=cfg.get("shadow_default", True),
        deterministic=cfg.get("deterministic", True),
    )
    return TrainSentinel(obj)


# Example safe-guard usage within training loop:
# try:
#     sentinel = create_sentinel({...})
#     detach = sentinel.attach_pytorch(model, optimizer)
#     for epoch in range(epochs):
#         train(...)
#         sentinel.record_checkpoint("ckpt.pth", verified_ok=True)
#     detach()
# finally:
#     sentinel.close()
#
# If enforce mode and a breach occurs, TrainHaltRequested may be raised after human approval gate.