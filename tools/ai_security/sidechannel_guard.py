#!/usr/bin/env python3
"""
SideChannel Guard: ML Timing/Cache Egress Monitor
Category: ai_security

Authorized testing only. Use this tool only on systems and models you have explicit permission to test.

This tool profiles ML training/inference for side-channel leakage via timing and lightweight CPU/GPU signals,
performs differential input fuzzing to quantify leakage, supports constant-time padding mitigation, and emits
signed, reproducible attestations for CI/CD gates.

Design goals:
- Least-privilege telemetry (no raw inputs or model weights; aggregates only).
- Explicit user consent for any enhanced perf collection; defaults to timing only.
- Encrypted telemetry at rest.
- Default network egress blocked; explicit allowlist required for any reporting.
- Signed attestations with environment hashes and reproducible test vectors.

Note: For cryptographic operations and strong encryption, this module uses 'cryptography' if available. If not,
it falls back to HMAC for signatures and a simple XOR keystream for encryption with warnings. For production,
use strong crypto with a managed key.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import platform
import random
import secrets
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

__all__ = [
    "SideChannelGuard",
    "LeakageAlert",
    "LeakPolicy",
    "AttestationSigner",
]

__version__ = "0.1.0"

# Optional imports for enhanced features
try:
    import resource as _resource  # Unix only
except Exception:
    _resource = None

try:
    import torch as _torch  # type: ignore
except Exception:
    _torch = None

# Optional cryptography for strong crypto
_CRYPTO_AVAILABLE = False
_ED25519_AVAILABLE = False
_AESGCM_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Ed25519PrivateKey,
        Ed25519PublicKey as _Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization as _serialization
    _ED25519_AVAILABLE = True
    _CRYPTO_AVAILABLE = True
except Exception:
    _ED25519_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    _AESGCM_AVAILABLE = True
    _CRYPTO_AVAILABLE = True
except Exception:
    _AESGCM_AVAILABLE = False


class LeakageAlert(Exception):
    """Raised when leakage exceeds policy threshold."""

    def __init__(self, code: str, message: str, metrics: Dict[str, Any]):
        super().__init__(message)
        self.code = code
        self.metrics = metrics

    def __str__(self) -> str:
        return f"{self.code}: {super().__str__()}"


@dataclass
class LeakPolicy:
    """Policy configuration for leakage detection."""
    timing_effect_threshold: float = 0.5  # Cohen's d threshold
    raise_on_leak: bool = True


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _blake2s(data: bytes) -> str:
    return hashlib.blake2s(data).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _secure_mkdir(path: str, mode: int = 0o700) -> None:
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _secure_open_write(path: str) -> Any:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, "wb")


def _sync_device_if_needed() -> None:
    # Ensure GPU ops finish before timing completion
    if _torch is not None and _torch.cuda.is_available():
        try:
            _torch.cuda.synchronize()
        except Exception:
            pass


def _torch_version_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    if _torch is None:
        return info
    try:
        info["torch_version"] = str(_torch.__version__)
    except Exception:
        pass
    try:
        info["cuda_available"] = bool(_torch.cuda.is_available())
    except Exception:
        info["cuda_available"] = False
    try:
        info["cuda_version"] = str(_torch.version.cuda) if hasattr(_torch, "version") else None
    except Exception:
        info["cuda_version"] = None
    try:
        info["cudnn_version"] = int(_torch.backends.cudnn.version()) if hasattr(_torch, "backends") else None
    except Exception:
        info["cudnn_version"] = None
    try:
        if info.get("cuda_available"):
            info["gpu_name"] = _torch.cuda.get_device_name(0)
        else:
            info["gpu_name"] = None
    except Exception:
        info["gpu_name"] = None
    return info


def _get_env_info() -> Dict[str, Any]:
    env = {
        "tool": "SideChannel Guard",
        "tool_version": __version__,
        "python_version": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "system": platform.system(),
        "release": platform.release(),
        "processor": platform.processor(),
    }
    env.update(_torch_version_info())
    env["environment_hash"] = _sha256(_canonical_json(env))
    return env


class TelemetryStore:
    """Encrypted telemetry storage for aggregate metrics (no content)."""

    def __init__(self, base_dir: Optional[str] = None, key: Optional[bytes] = None):
        self.base_dir = base_dir or os.path.join(os.path.expanduser("~"), ".sidechannel_guard", "telemetry")
        _secure_mkdir(self.base_dir, 0o700)
        self._key = key or secrets.token_bytes(32)
        self._use_aesgcm = _AESGCM_AVAILABLE

    def _encrypt(self, plaintext: bytes) -> Dict[str, Any]:
        nonce = secrets.token_bytes(12)
        if self._use_aesgcm:
            aes = _AESGCM(self._key)
            ct = aes.encrypt(nonce, plaintext, None)
            return {
                "mode": "AESGCM",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ct": base64.b64encode(ct).decode("ascii"),
            }
        # Fallback weak XOR keystream (not for production)
        stream = hashlib.blake2b(self._key + nonce).digest()
        ks = (stream * ((len(plaintext) // len(stream)) + 1))[: len(plaintext)]
        ct = bytes([a ^ b for a, b in zip(plaintext, ks)])
        return {
            "mode": "XOR-BLAKE2b",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ct": base64.b64encode(ct).decode("ascii"),
            "insecure": True,
        }

    def write_encrypted_json(self, rel_name: str, obj: Dict[str, Any]) -> str:
        payload = _canonical_json(obj)
        envelope = self._encrypt(payload)
        envelope["payload_hash"] = _sha256(payload)
        envelope["written_at"] = _now_iso()
        path = os.path.join(self.base_dir, rel_name)
        with _secure_open_write(path) as f:
            f.write(_canonical_json(envelope))
        return path


class AttestationSigner:
    """Signer for attestations using Ed25519 if available, otherwise HMAC-SHA256 as a fallback."""

    def __init__(
        self,
        private_key: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        hmac_key: Optional[bytes] = None,
    ):
        self.algo = None
        self._priv = None
        self._pub = None
        self._hmac_key = None

        if _ED25519_AVAILABLE and (private_key or public_key):
            self.algo = "ed25519"
            if private_key:
                self._priv = _Ed25519PrivateKey.from_private_bytes(private_key)
                self._pub = self._priv.public_key()
            elif public_key:
                self._pub = _Ed25519PublicKey.from_public_bytes(public_key)
        elif _ED25519_AVAILABLE:
            # generate ephemeral
            self.algo = "ed25519"
            self._priv = _Ed25519PrivateKey.generate()
            self._pub = self._priv.public_key()
        else:
            self.algo = "hmac-sha256"
            self._hmac_key = hmac_key or secrets.token_bytes(32)

    @classmethod
    def from_pem(cls, private_pem: Optional[bytes] = None, public_pem: Optional[bytes] = None) -> "AttestationSigner":
        if not _ED25519_AVAILABLE:
            raise RuntimeError("PEM loading requires cryptography/Ed25519")
        if private_pem:
            priv = _serialization.load_pem_private_key(private_pem, password=None)
            if not isinstance(priv, _Ed25519PrivateKey):
                raise ValueError("Expected Ed25519 private key PEM")
            raw_priv = priv.private_bytes(
                encoding=_serialization.Encoding.Raw,
                format=_serialization.PrivateFormat.Raw,
                encryption_algorithm=_serialization.NoEncryption(),
            )
            return cls(private_key=raw_priv)
        if public_pem:
            pub = _serialization.load_pem_public_key(public_pem)
            if not isinstance(pub, _Ed25519PublicKey):
                raise ValueError("Expected Ed25519 public key PEM")
            raw_pub = pub.public_bytes(
                encoding=_serialization.Encoding.Raw,
                format=_serialization.PublicFormat.Raw,
            )
            return cls(public_key=raw_pub)
        return cls()

    def export_public(self) -> Dict[str, str]:
        if self.algo == "ed25519" and _ED25519_AVAILABLE and self._pub is not None:
            pem = self._pub.public_bytes(
                encoding=_serialization.Encoding.PEM,
                format=_serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            pub_raw = self._pub.public_bytes(
                encoding=_serialization.Encoding.Raw,
                format=_serialization.PublicFormat.Raw,
            )
            return {
                "algo": "ed25519",
                "public_key_pem": pem.decode("ascii"),
                "key_id": _sha256(pub_raw),
            }
        # HMAC fallback: provide key id only (do not expose secret)
        return {
            "algo": "hmac-sha256",
            "key_id": _sha256(self._hmac_key or b""),
        }

    def sign(self, data: bytes) -> Dict[str, str]:
        if self.algo == "ed25519" and self._priv is not None:
            sig = self._priv.sign(data)
            pub_raw = self._pub.public_bytes(
                encoding=_serialization.Encoding.Raw,
                format=_serialization.PublicFormat.Raw,
            )
            return {
                "algo": "ed25519",
                "signature": base64.b64encode(sig).decode("ascii"),
                "key_id": _sha256(pub_raw),
            }
        # HMAC fallback
        mac = hmac.new(self._hmac_key, data, hashlib.sha256).digest()
        return {
            "algo": "hmac-sha256",
            "signature": base64.b64encode(mac).decode("ascii"),
            "key_id": _sha256(self._hmac_key or b""),
        }

    def verify(self, data: bytes, sig_info: Dict[str, str], trust: Dict[str, Any]) -> bool:
        algo = sig_info.get("algo")
        if algo == "ed25519" and _ED25519_AVAILABLE:
            pub_pem = trust.get("public_key_pem")
            if not pub_pem:
                return False
            pub = _serialization.load_pem_public_key(pub_pem.encode("ascii"))
            if not isinstance(pub, _Ed25519PublicKey):
                return False
            sig = base64.b64decode(sig_info.get("signature", ""))
            try:
                pub.verify(sig, data)
                # optional key id check
                pub_raw = pub.public_bytes(
                    encoding=_serialization.Encoding.Raw,
                    format=_serialization.PublicFormat.Raw,
                )
                expected_id = _sha256(pub_raw)
                return expected_id == sig_info.get("key_id")
            except Exception:
                return False
        if algo == "hmac-sha256":
            secret = trust.get("hmac_secret")
            if not secret:
                return False
            expected = hmac.new(secret, data, hashlib.sha256).digest()
            got = base64.b64decode(sig_info.get("signature", ""))
            return hmac.compare_digest(expected, got)
        return False


@dataclass
class ProfilingConfig:
    runs: int = 60
    warmup_runs: int = 10
    seed: int = 1337
    enable_perf_counters: bool = False  # requires user_consent
    user_consent: bool = False
    batch_shape: Tuple[int, ...] = (1024,)
    low_value: float = -1.0
    high_value: float = 1.0
    device: Optional[str] = None  # "cpu" or "cuda", default autodetect
    mitigation_constant_time_pad: bool = False
    noise_jitter_ns: int = 0  # optional random sleep/jitter up to N ns after compute


class SideChannelGuard:
    """Main interface for leakage profiling and attestation."""

    def __init__(
        self,
        policy: Optional[LeakPolicy] = None,
        telemetry_dir: Optional[str] = None,
        allow_egress_hosts: Optional[List[str]] = None,
        signer: Optional[AttestationSigner] = None,
    ):
        self.policy = policy or LeakPolicy()
        self.telemetry = TelemetryStore(telemetry_dir)
        self.allow_egress_hosts = set(allow_egress_hosts or [])
        self.signer = signer or AttestationSigner()

    def _gen_input(self, shape: Tuple[int, ...], label: int, rng: random.Random) -> Any:
        # Generate low vs high valued inputs to try to trigger data-dependent branches
        # For PyTorch, return Tensor; otherwise, return Python list of floats.
        size = 1
        for s in shape:
            size *= s
        mean = -abs(0.5) if label == 0 else abs(0.5)
        std = 0.1
        vals = [rng.gauss(mean, std) for _ in range(size)]
        if _torch is not None:
            tensor = _torch.tensor(vals, dtype=_torch.float32)
            tensor = tensor.view(*shape)
            return tensor
        else:
            # Nested list roughly shaped; for simplicity, return flat list
            return vals

    def _ensure_device(self, x: Any, device: Optional[str]) -> Any:
        if _torch is None:
            return x
        try:
            if device == "cuda" and _torch.cuda.is_available():
                return x.to("cuda")
            if device == "cpu":
                return x.to("cpu")
        except Exception:
            return x
        return x

    def wrap_constant_time(self, model_callable: Callable[[Any], Any], sample_input: Any, calibrate_runs: int = 10) -> Callable[[Any], Any]:
        """
        Wrap a model callable to enforce constant-time by padding up to the calibrated max time.
        Calibration runs the model a few times to find a safe time budget.
        """
        device = None
        if _torch is not None and isinstance(sample_input, _torch.Tensor):
            device = "cuda" if (hasattr(sample_input, "is_cuda") and sample_input.is_cuda) else "cpu"
        # Calibrate
        times: List[int] = []
        for _ in range(max(1, calibrate_runs)):
            start = time.perf_counter_ns()
            out = model_callable(sample_input)
            # Ensure completion
            _sync_device_if_needed()
            _ = out
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)
        budget_ns = max(times) if times else 0

        def _wrapped(x: Any) -> Any:
            start = time.perf_counter_ns()
            out = model_callable(x)
            _sync_device_if_needed()
            elapsed = time.perf_counter_ns() - start
            # Busy-wait pad
            while elapsed < budget_ns:
                # spin a little
                elapsed = time.perf_counter_ns() - start
            return out

        return _wrapped

    def profile(
        self,
        model_callable: Callable[[Any], Any],
        config: Optional[ProfilingConfig] = None,
    ) -> Dict[str, Any]:
        """
        Profile the provided model/inference callable under differential fuzzing.

        model_callable: Callable that accepts a single input (e.g., tensor) and performs inference.
                        It must not mutate global state in a way that breaks reproducibility.
        """
        cfg = config or ProfilingConfig()
        rng = random.Random(cfg.seed)

        device = cfg.device
        if device is None and _torch is not None and _torch.cuda.is_available():
            device = "cuda"
        elif device is None:
            device = "cpu"

        # Prepare mitigation wrapper if requested
        wrapped_callable = model_callable
        if cfg.mitigation_constant_time_pad:
            sample = self._gen_input(cfg.batch_shape, label=0, rng=random.Random(cfg.seed + 1))
            sample = self._ensure_device(sample, device)
            wrapped_callable = self.wrap_constant_time(model_callable, sample_input=sample, calibrate_runs=max(5, cfg.warmup_runs))

        # Warm-up
        for _ in range(max(0, cfg.warmup_runs)):
            x = self._gen_input(cfg.batch_shape, label=0, rng=rng)
            x = self._ensure_device(x, device)
            _ = wrapped_callable(x)
            _sync_device_if_needed()

        # Profiling runs with class labels 0 and 1 alternating
        class_times: Dict[int, List[int]] = {0: [], 1: []}
        cpu_ctx_switches: Dict[int, List[int]] = {0: [], 1: []}
        cpu_page_faults: Dict[int, List[int]] = {0: [], 1: []}

        # consent gate for perf-like counters
        collect_perf = bool(cfg.enable_perf_counters and cfg.user_consent and _resource is not None)

        for i in range(cfg.runs):
            label = i % 2
            x = self._gen_input(cfg.batch_shape, label=label, rng=rng)
            x = self._ensure_device(x, device)

            # capture pre counters
            pre_ru = None
            if collect_perf:
                try:
                    pre_ru = _resource.getrusage(_resource.RUSAGE_SELF)
                except Exception:
                    pre_ru = None

            start = time.perf_counter_ns()
            _ = wrapped_callable(x)
            _sync_device_if_needed()
            if cfg.noise_jitter_ns and cfg.noise_jitter_ns > 0:
                # add a small random jitter to confound precise timing
                # values are bounded and aggregate only
                budget = rng.randrange(0, cfg.noise_jitter_ns)
                target = start + (time.perf_counter_ns() - start) + budget
                while time.perf_counter_ns() < target:
                    pass
            elapsed = time.perf_counter_ns() - start
            class_times[label].append(elapsed)

            # capture post counters
            if collect_perf and pre_ru is not None:
                try:
                    post = _resource.getrusage(_resource.RUSAGE_SELF)
                    # Aggregate deltas
                    cpu_ctx_switches[label].append(max(0, (post.ru_nvcsw + post.ru_nivcsw) - (pre_ru.ru_nvcsw + pre_ru.ru_nivcsw)))
                    cpu_page_faults[label].append(max(0, (post.ru_minflt + post.ru_majflt) - (pre_ru.ru_minflt + pre_ru.ru_majflt)))
                except Exception:
                    pass

        # Aggregate and score
        def _summary(vals: List[int]) -> Dict[str, Any]:
            if not vals:
                return {"count": 0, "mean_ns": 0, "std_ns": 0, "min_ns": 0, "max_ns": 0}
            return {
                "count": len(vals),
                "mean_ns": int(statistics.mean(vals)),
                "std_ns": int(statistics.pstdev(vals)) if len(vals) > 1 else 0,
                "min_ns": int(min(vals)),
                "max_ns": int(max(vals)),
            }

        sum0 = _summary(class_times[0])
        sum1 = _summary(class_times[1])
        pooled_std = 0.0
        if sum0["std_ns"] == 0 and sum1["std_ns"] == 0:
            pooled_std = 0.0
        else:
            # pooled std for two groups
            s0 = float(sum0["std_ns"])
            s1 = float(sum1["std_ns"])
            n0 = max(1, sum0["count"])
            n1 = max(1, sum1["count"])
            pooled_std = ((s0**2 * (n0 - 1) + s1**2 * (n1 - 1)) / max(1, (n0 + n1 - 2))) ** 0.5

        diff = float(sum1["mean_ns"] - sum0["mean_ns"])
        effect_size = abs(diff) / pooled_std if pooled_std > 0 else (float("inf") if diff != 0 else 0.0)

        # Aggregate perf counters
        perf_summary: Dict[str, Any] = {}
        if collect_perf:
            def s(vals: List[int]) -> Dict[str, Any]:
                return {
                    "mean": float(statistics.mean(vals)) if vals else 0.0,
                    "std": float(statistics.pstdev(vals)) if len(vals) > 1 else 0.0,
                }
            perf_summary = {
                "cpu_ctx_switches": {"class0": s(cpu_ctx_switches[0]), "class1": s(cpu_ctx_switches[1])},
                "cpu_page_faults": {"class0": s(cpu_page_faults[0]), "class1": s(cpu_page_faults[1])},
            }

        env = _get_env_info()

        metrics_summary: Dict[str, Any] = {
            "timing": {"class0": sum0, "class1": sum1, "effect_size": effect_size, "diff_mean_ns": int(diff)},
            "perf": perf_summary,
            "runs": cfg.runs,
            "warmup_runs": cfg.warmup_runs,
            "consent_for_perf": bool(cfg.user_consent),
            "env_hash": env.get("environment_hash"),
        }

        leakage_score = float(effect_size)
        alert_code: Optional[str] = None
        if leakage_score >= self.policy.timing_effect_threshold:
            alert_code = "LEAKAGE_TIMING"

        result: Dict[str, Any] = {
            "leakage_score": leakage_score,
            "alert": alert_code,
            "metrics_summary": metrics_summary,
            "policy": dataclasses.asdict(self.policy),
            "environment": env,
            "test_vectors": {
                "seed": cfg.seed,
                "batch_shape": cfg.batch_shape,
                "low_value": cfg.low_value,
                "high_value": cfg.high_value,
                "fuzzer": "low_vs_high_values",
            },
            "mitigations": {"constant_time_pad": bool(cfg.mitigation_constant_time_pad), "noise_jitter_ns": int(cfg.noise_jitter_ns)},
            "timestamp": _now_iso(),
        }

        # Store aggregate telemetry encrypted at rest
        fname = f"profile_{int(time.time())}_{secrets.token_hex(4)}.json.enc"
        result["telemetry_path"] = self.telemetry.write_encrypted_json(fname, {
            "environment_hash": env.get("environment_hash"),
            "metrics_summary": metrics_summary,
            "leakage_score": leakage_score,
            "alert": alert_code,
            "timestamp": result["timestamp"],
        })

        # Raise if policy demands
        if alert_code and self.policy.raise_on_leak:
            raise LeakageAlert(alert_code, "Timing variability indicates potential data-dependent execution", metrics_summary)

        return result

    def create_attestation_bundle(self, profile_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a signed attestation bundle with leakage score, environment hashes, and provenance.
        """
        payload = {
            "type": "sidechannel_guard.attestation",
            "tool": "SideChannel Guard",
            "tool_version": __version__,
            "timestamp": _now_iso(),
            "environment": {
                "environment_hash": profile_result.get("environment", {}).get("environment_hash"),
                "system": profile_result.get("environment", {}),
            },
            "metrics": {
                "leakage_score": profile_result.get("leakage_score"),
                "timing_effect_size": profile_result.get("metrics_summary", {}).get("timing", {}).get("effect_size"),
                "timing_diff_mean_ns": profile_result.get("metrics_summary", {}).get("timing", {}).get("diff_mean_ns"),
            },
            "policy": profile_result.get("policy"),
            "test_vectors": profile_result.get("test_vectors"),
            "mitigations": profile_result.get("mitigations"),
            "provenance": {
                "telemetry_path": profile_result.get("telemetry_path"),
                "run_id": _blake2s(_canonical_json(profile_result))[:32],
            },
        }
        data = _canonical_json(payload)
        sig = self.signer.sign(data)
        bundle = {
            "payload": payload,
            "signature": sig,
            "payload_hash": _sha256(data),
            "signer": self.signer.export_public(),
        }
        return bundle

    def verify_attestation_bundle(self, bundle: Dict[str, Any], trust_root: Dict[str, Any]) -> bool:
        """
        Verify attestation bundle using provided trust root:
        - For ed25519: trust_root must include 'public_key_pem'
        - For hmac-sha256: trust_root must include 'hmac_secret'
        """
        if not bundle or "payload" not in bundle or "signature" not in bundle:
            return False
        data = _canonical_json(bundle["payload"])
        sig = bundle["signature"]
        return self.signer.verify(data, sig, trust_root)

    def report_attestation_remote(self, bundle: Dict[str, Any], url: str) -> None:
        """
        Optional reporting; blocked by default unless URL host is allowlisted.
        This function intentionally avoids performing any network I/O to comply with default egress blocking.
        """
        host = url.split("://", 1)[-1].split("/", 1)[0]
        if host not in self.allow_egress_hosts:
            raise PermissionError("Egress blocked by default; add host to allowlist to enable reporting.")
        # Intentionally do nothing: implement actual network transmission in a controlled environment.


# If this module is used as a script, print ethical usage notice.
if __name__ == "__main__":
    notice = (
        "SideChannel Guard is a security testing tool for authorized use only.\n"
        "Ensure you have explicit permission to profile the target system/model.\n"
        "This CLI stub does not perform actions. Import SideChannelGuard in your test harness."
    )
    sys.stdout.write(notice + "\n")