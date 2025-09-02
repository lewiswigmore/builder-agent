import argparse
import datetime
import hashlib
import hmac
import io
import json
import os
import random
import secrets
import socket
import sys
import threading
import time
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np

try:
    import torch
    import torch.nn as nn
except Exception as e:
    raise RuntimeError("PyTorch is required for Adversarial Canary.") from e

# Platform-specific import for resource module
IS_WINDOWS = sys.platform.startswith('win')
if not IS_WINDOWS:
    import resource

ETHICAL_WARNING = (
    "WARNING: Adversarial Canary is for authorized testing, red teaming, and research only. "
    "Use strictly on models and data you own or are permitted to test. Misuse may be illegal and unethical."
)



def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    try:
        torch.use_deterministic_algorithms(True)  # type: ignore[attr-defined]
    except Exception:
        pass
    torch.backends.cudnn.deterministic = True  # type: ignore[attr-defined]
    torch.backends.cudnn.benchmark = False  # type: ignore[attr-defined]


class NetworkGuard:
    def __init__(self, allowlist: Optional[List[str]] = None) -> None:
        self._orig_socket = None
        self._allowlist = set(allowlist or [])

    def _guard_connect(self, sock, address):
        host, port = address[0], address[1] if len(address) > 1 else None
        # Allow only explicit allowlist hosts (e.g., "127.0.0.1", "::1")
        host_ip = None
        try:
            host_ip = socket.gethostbyname(host)
        except Exception:
            host_ip = host
        if host in self._allowlist or (host_ip and host_ip in self._allowlist):
            return self._orig_socket_connect(sock, address)
        raise PermissionError(f"Egress blocked by sandbox policy: attempted connect to {host}:{port}")

    def __enter__(self):
        self._orig_socket = socket.socket
        self._orig_socket_connect = socket.socket.connect
        guard = self

        class GuardedSocket(socket.socket):  # type: ignore[misc]
            def connect(self_, address):
                return guard._guard_connect(self_, address)

        socket.socket = GuardedSocket  # type: ignore[assignment]
        # Block DNS resolution via network by preventing getaddrinfo from querying; allow loopback resolution
        self._orig_getaddrinfo = socket.getaddrinfo

        def guarded_getaddrinfo(host, *args, **kwargs):
            if host in self._allowlist or host in ("127.0.0.1", "::1", "localhost"):
                return self._orig_getaddrinfo(host, *args, **kwargs)
            # Return a blocked result to avoid network DNS
            raise PermissionError(f"Egress (DNS) blocked by sandbox policy: attempted resolve {host}")

        socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]
        # Block common HTTP libraries if imported later by setting env
        os.environ["NO_PROXY"] = "*"
        os.environ["HTTP_PROXY"] = ""
        os.environ["HTTPS_PROXY"] = ""
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._orig_socket is not None:
            socket.socket = self._orig_socket  # type: ignore[assignment]
        if hasattr(self, "_orig_getaddrinfo"):
            socket.getaddrinfo = self._orig_getaddrinfo  # type: ignore[assignment]
        return False


class Sandbox:
    def __init__(self, allowlist: Optional[List[str]] = None, cpu_seconds: int = 3600, mem_mb: int = 4096) -> None:
        self.allowlist = allowlist or []
        self.cpu_seconds = cpu_seconds
        self.mem_mb = mem_mb
        self._net = NetworkGuard(self.allowlist)

    def __enter__(self):
        # Resource limits (best effort, not available on Windows)
        if not IS_WINDOWS:
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_seconds, self.cpu_seconds))
            except Exception:
                pass
            try:
                bytes_limit = self.mem_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))
            except Exception:
                pass
        return self._net.__enter__()

    def __exit__(self, exc_type, exc, tb):
        return self._net.__exit__(exc_type, exc, tb)


def _tensor_bytes_consistent(t: torch.Tensor) -> bytes:
    # Ensure CPU, contiguous, known dtype, deterministic representation
    if t.is_cuda:
        t = t.detach().cpu()
    t = t.detach().contiguous()
    # Convert to a canonical dtype for hashing to avoid dtype differences
    if t.dtype in (torch.float16, torch.float32, torch.float64, torch.bfloat16):
        arr = t.to(dtype=torch.float32).numpy()
        data = arr.tobytes(order="C")
        meta = f"{t.shape}|float32".encode()
    elif t.dtype in (torch.uint8, torch.int8, torch.int16, torch.int32, torch.int64):
        arr = t.to(dtype=torch.int64).numpy()
        data = arr.tobytes(order="C")
        meta = f"{t.shape}|int64".encode()
    else:
        arr = t.to(dtype=torch.float32).numpy()
        data = arr.tobytes(order="C")
        meta = f"{t.shape}|float32".encode()
    return hashlib.sha256(meta + data).digest()


def hash_model(model: nn.Module) -> str:
    hasher = hashlib.sha256()
    # sort keys for determinism
    state = model.state_dict()
    for k in sorted(state.keys()):
        hasher.update(k.encode())
        hasher.update(_tensor_bytes_consistent(state[k]))
    return hasher.hexdigest()


def _to_uint8_bytes(batch: torch.Tensor, range_assumed: Tuple[float, float] = (0.0, 1.0)) -> bytes:
    if batch.is_cuda:
        batch = batch.cpu()
    batch = batch.detach()
    lo, hi = range_assumed
    x = batch.clamp(lo, hi)
    x = ((x - lo) / max(1e-12, hi - lo) * 255.0).round().to(torch.uint8)
    arr = x.contiguous().numpy()
    return arr.tobytes(order="C")


def hash_dataset(dataloader: torch.utils.data.DataLoader, max_batches: Optional[int] = None) -> str:
    # Deterministic hashing over samples in order
    hasher = hashlib.sha256()
    count = 0
    with torch.no_grad():
        for i, (x, y) in enumerate(dataloader):
            hasher.update(_to_uint8_bytes(x))
            hasher.update(y.detach().cpu().numpy().tobytes(order="C"))
            count += 1
            if max_batches is not None and count >= max_batches:
                break
    return hasher.hexdigest()


def _predict(model: nn.Module, x: torch.Tensor) -> torch.Tensor:
    model.eval()
    with torch.no_grad():
        logits = model(x)
        return logits.argmax(dim=1)


def evaluate_model(model: nn.Module, dataloader: torch.utils.data.DataLoader, device: torch.device, num_classes: int) -> Tuple[float, np.ndarray]:
    model.eval()
    correct = 0
    total = 0
    cm = np.zeros((num_classes, num_classes), dtype=np.int64)
    with torch.no_grad():
        for x, y in dataloader:
            x = x.to(device)
            y = y.to(device)
            logits = model(x)
            preds = logits.argmax(dim=1)
            correct += (preds == y).sum().item()
            total += y.numel()
            for t, p in zip(y.view(-1).cpu().numpy(), preds.view(-1).cpu().numpy()):
                cm[int(t), int(p)] += 1
    acc = correct / max(1, total)
    return acc, cm


def fgsm_attack(
    model: nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float,
    targeted: bool = False,
    y_target: Optional[torch.Tensor] = None,
    clamp: Tuple[float, float] = (0.0, 1.0),
) -> torch.Tensor:
    model.eval()
    x_adv = x.clone().detach().requires_grad_(True)
    criterion = nn.CrossEntropyLoss()
    logits = model(x_adv)
    if targeted:
        assert y_target is not None, "Target labels required for targeted attack"
        loss = criterion(logits, y_target)
        # For targeted attack, minimize loss for target => subtract gradient step
        grad_sign = torch.sign(torch.autograd.grad(loss, x_adv, retain_graph=False, create_graph=False)[0])
        x_adv = x_adv - epsilon * grad_sign
    else:
        loss = criterion(logits, y)
        grad_sign = torch.sign(torch.autograd.grad(loss, x_adv, retain_graph=False, create_graph=False)[0])
        x_adv = x_adv + epsilon * grad_sign
    x_adv = torch.clamp(x_adv.detach(), clamp[0], clamp[1])
    return x_adv


def pgd_attack(
    model: nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epsilon: float,
    step_size: float,
    steps: int,
    targeted: bool = False,
    y_target: Optional[torch.Tensor] = None,
    clamp: Tuple[float, float] = (0.0, 1.0),
) -> torch.Tensor:
    model.eval()
    x_orig = x.detach()
    x_adv = x_orig.clone().detach()
    # start at random point in epsilon-ball to improve attack strength (deterministic due to seed)
    x_adv = x_adv + torch.empty_like(x_adv).uniform_(-epsilon, epsilon)
    x_adv = torch.clamp(x_adv, clamp[0], clamp[1])
    x_adv.requires_grad_(True)
    criterion = nn.CrossEntropyLoss()
    for _ in range(steps):
        logits = model(x_adv)
        if targeted:
            assert y_target is not None, "Target labels required for targeted attack"
            loss = criterion(logits, y_target)
            grad = torch.autograd.grad(loss, x_adv, retain_graph=False, create_graph=False)[0]
            x_adv = x_adv - step_size * torch.sign(grad)
        else:
            loss = criterion(logits, y)
            grad = torch.autograd.grad(loss, x_adv, retain_graph=False, create_graph=False)[0]
            x_adv = x_adv + step_size * torch.sign(grad)
        # Project to epsilon-ball
        eta = torch.clamp(x_adv.detach() - x_orig, -epsilon, epsilon)
        x_adv = torch.clamp(x_orig + eta, clamp[0], clamp[1]).detach()
        x_adv.requires_grad_(True)
    return x_adv.detach()


def make_targets(y: torch.Tensor, num_classes: int, rng: np.random.Generator) -> torch.Tensor:
    y_np = y.detach().cpu().numpy()
    targets = []
    for yi in y_np:
        choices = [c for c in range(num_classes) if c != int(yi)]
        targets.append(int(rng.choice(choices)))
    return torch.tensor(targets, dtype=torch.long, device=y.device)


@dataclass
class AttackParams:
    fgsm_eps: float = 8 / 255
    pgd_eps: float = 8 / 255
    pgd_step: float = 2 / 255
    pgd_steps: int = 10
    targeted: bool = False


@dataclass
class AttackResult:
    name: str
    targeted: bool
    clean_accuracy: float
    adv_accuracy: float
    attack_success_rate: float
    confusion_matrix_clean: List[List[int]]
    confusion_matrix_adv: List[List[int]]
    confusion_matrix_delta: List[List[int]]
    adv_samples_path: str
    digest: str


def compute_confusion_delta(cm_clean: np.ndarray, cm_adv: np.ndarray) -> np.ndarray:
    return cm_adv.astype(np.int64) - cm_clean.astype(np.int64)


def save_npz_deterministic(path: str, arrays: Dict[str, np.ndarray]) -> None:
    # Deterministic NPZ writer: fixed entry order, fixed timestamps/attrs, deterministic compression
    keys = sorted(arrays.keys())
    # Prepare .npy payloads deterministically
    npy_payloads: Dict[str, bytes] = {}
    for k in keys:
        with io.BytesIO() as b:
            np.save(b, arrays[k], allow_pickle=False, fix_imports=False)
            npy_payloads[k] = b.getvalue()
    # Build zip with fixed metadata
    tmp = path + ".tmp"
    with io.BytesIO() as zbuf:
        with zipfile.ZipFile(zbuf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for k in keys:
                info = zipfile.ZipInfo(filename=f"{k}.npy")
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 0  # consistent across platforms
                info.external_attr = 0o600 << 16  # -rw-------
                zf.writestr(info, npy_payloads[k])
        data = zbuf.getvalue()
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Signer:
    def __init__(self, key_path: str) -> None:
        self.key_path = key_path
        self.key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                return f.read()
        key = secrets.token_bytes(32)  # HMAC key
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        with open(self.key_path, "wb") as f:
            f.write(key)
        return key

    def sign(self, data: bytes) -> str:
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        expected = hmac.new(self.key, data, hashlib.sha256).hexdigest()
        # Use compare_digest for timing-safe compare
        return hmac.compare_digest(expected, signature_hex)


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _attack_loop(
    model: nn.Module,
    dataloader: torch.utils.data.DataLoader,
    device: torch.device,
    num_classes: int,
    method: str,
    params: AttackParams,
    rng: np.random.Generator,
) -> Tuple[AttackResult, np.ndarray, np.ndarray, np.ndarray]:
    model.eval()
    x_list = []
    y_list = []
    adv_list = []
    targeted = params.targeted
    # Evaluate clean first to compute baseline accuracy and confusion
    clean_acc, cm_clean = evaluate_model(model, dataloader, device, num_classes)

    total = 0
    correct_adv = 0
    attack_success = 0
    cm_adv = np.zeros((num_classes, num_classes), dtype=np.int64)

    for xb, yb in dataloader:
        xb = xb.to(device)
        yb = yb.to(device)
        if targeted:
            y_target = make_targets(yb, num_classes, rng)
        else:
            y_target = None

        with torch.enable_grad():
            if method == "fgsm":
                adv = fgsm_attack(
                    model, xb, yb, epsilon=params.fgsm_eps, targeted=targeted, y_target=y_target
                )
            elif method == "pgd":
                adv = pgd_attack(
                    model,
                    xb,
                    yb,
                    epsilon=params.pgd_eps,
                    step_size=params.pgd_step,
                    steps=params.pgd_steps,
                    targeted=targeted,
                    y_target=y_target,
                )
            else:
                raise ValueError(f"Unknown method {method}")

        # Collect for reproducible export
        x_list.append(xb.detach().cpu())
        y_list.append(yb.detach().cpu())
        adv_list.append(adv.detach().cpu())

        with torch.no_grad():
            logits_adv = model(adv)
            preds_adv = logits_adv.argmax(dim=1)
            if targeted:
                # success if adversarial prediction == chosen target
                success = (preds_adv == y_target).sum().item()
            else:
                success = (preds_adv != yb).sum().item()
            attack_success += success
            correct_adv += (preds_adv == yb).sum().item()
            total += yb.numel()
            for t, p in zip(yb.view(-1).cpu().numpy(), preds_adv.view(-1).cpu().numpy()):
                cm_adv[int(t), int(p)] += 1

    adv_acc = correct_adv / max(1, total)
    asr = attack_success / max(1, total)
    cm_delta = compute_confusion_delta(cm_clean, cm_adv)

    # Export adversarial samples deterministically
    x_all = torch.cat(x_list, dim=0)
    y_all = torch.cat(y_list, dim=0)
    adv_all = torch.cat(adv_list, dim=0)
    arrays = {
        "clean_images": x_all.numpy(),
        "clean_labels": y_all.numpy(),
        "adv_images": adv_all.numpy(),
    }
    method_name = f"{method}_{'targeted' if targeted else 'untargeted'}"
    adv_dir = "adversarial_canary_out/artifacts"
    os.makedirs(adv_dir, exist_ok=True)
    adv_path = os.path.join(adv_dir, f"adv_{method_name}.npz")
    save_npz_deterministic(adv_path, arrays)
    digest = sha256_file(adv_path)

    res = AttackResult(
        name=method.upper(),
        targeted=targeted,
        clean_accuracy=clean_acc,
        adv_accuracy=adv_acc,
        attack_success_rate=asr,
        confusion_matrix_clean=cm_clean.tolist(),
        confusion_matrix_adv=cm_adv.tolist(),
        confusion_matrix_delta=cm_delta.tolist(),
        adv_samples_path=adv_path,
        digest=digest,
    )
    return res, x_all.numpy(), y_all.numpy(), adv_all.numpy()


@dataclass
class Provenance:
    tool: str
    category: str
    model_sha256: str
    dataset_sha256: str
    attack_params: Dict[str, Any]
    seed: int
    environment: Dict[str, Any]
    builder_id: str
    reproducible: bool
    artifacts: Dict[str, str]  # path->sha256


def build_provenance(
    model_sha: str,
    dataset_sha: str,
    attack_params: Dict[str, Any],
    seed: int,
    artifacts: Dict[str, str],
) -> Provenance:
    env = {
        "python_version": sys.version.split()[0],
        "pytorch_version": getattr(torch, "__version__", "unknown"),
        "cuda": torch.version.cuda if torch.cuda.is_available() else None,
        "device_count": torch.cuda.device_count() if torch.cuda.is_available() else 0,
    }
    prov = Provenance(
        tool="Adversarial Canary",
        category="ai_security",
        model_sha256=model_sha,
        dataset_sha256=dataset_sha,
        attack_params=attack_params,
        seed=seed,
        environment=env,
        builder_id="adversarial_canary_local",
        reproducible=True,
        artifacts=artifacts,
    )
    return prov


def write_attestation(provenance: Provenance, signer: Signer, out_dir: str) -> Tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    attestation = asdict(provenance)
    # Include an issued_at field but do not include it in signature to allow reproducible artifacts if desired
    issued_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    attestation_signed = dict(attestation)
    attestation_signed["issued_at"] = issued_at

    attestation_path = os.path.join(out_dir, "attestation.json")
    with open(attestation_path, "w", encoding="utf-8") as f:
        json.dump(attestation_signed, f, indent=2, sort_keys=True, ensure_ascii=False)

    # Sign canonical JSON without issued_at for deterministic signature scope
    payload = canonical_json(attestation)
    signature = signer.sign(payload)
    sig_path = os.path.join(out_dir, "attestation.sig")
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(signature)

    # Transparency log (append-only)
    log_path = os.path.join(out_dir, "transparency.log")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{int(time.time())}\t{sha256_file(attestation_path)}\t{signature}\n")
    except Exception:
        pass
    return attestation_path, sig_path


def verify_attestation(attestation_dir: str, key_path: str) -> bool:
    attestation_path = os.path.join(attestation_dir, "attestation.json")
    sig_path = os.path.join(attestation_dir, "attestation.sig")
    if not (os.path.exists(attestation_path) and os.path.exists(sig_path)):
        raise FileNotFoundError("Attestation or signature file missing")
    with open(attestation_path, "r", encoding="utf-8") as f:
        att = json.load(f)
    # Remove issued_at before verifying
    att.pop("issued_at", None)
    payload = canonical_json(att)
    with open(sig_path, "r", encoding="utf-8") as f:
        sig_hex = f.read().strip()
    signer = Signer(key_path)
    return signer.verify(payload, sig_hex)


def run_adversarial_suite(
    model: nn.Module,
    eval_loader: torch.utils.data.DataLoader,
    num_classes: int,
    device: Optional[torch.device] = None,
    seed: int = 1337,
    out_dir: str = "adversarial_canary_out",
    signer_key_path: str = "adversarial_canary_out/keys/hmac_key.bin",
    egress_allowlist: Optional[List[str]] = None,
) -> Dict[str, Any]:
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    set_seed(seed)
    print(ETHICAL_WARNING, file=sys.stderr)

    model = model.to(device)
    model.eval()
    # Make loader deterministic
    if getattr(eval_loader, "sampler", None) is not None and hasattr(eval_loader.sampler, "shuffle"):
        # Avoid accidental shuffling
        try:
            eval_loader.sampler.shuffle = False  # type: ignore[attr-defined]
        except Exception:
            pass

    # Compute digests
    model_sha = hash_model(model)
    dataset_sha = hash_dataset(eval_loader)

    os.makedirs(out_dir, exist_ok=True)
    artifacts_dir = os.path.join(out_dir, "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    results: List[AttackResult] = []
    arrays_registry: Dict[str, Tuple[np.ndarray, np.ndarray, np.ndarray]] = {}
    artifacts: Dict[str, str] = {}

    rng = np.random.default_rng(seed)

    with Sandbox(allowlist=egress_allowlist):
        # Untargeted FGSM
        params_fgsm_u = AttackParams(targeted=False)
        res_fgsm_u, clean_u_x, clean_u_y, adv_u = _attack_loop(
            model, eval_loader, device, num_classes, "fgsm", params_fgsm_u, rng
        )
        results.append(res_fgsm_u)
        artifacts[os.path.relpath(res_fgsm_u.adv_samples_path, out_dir)] = res_fgsm_u.digest
        arrays_registry["fgsm_untargeted"] = (clean_u_x, clean_u_y, adv_u)

        # Targeted FGSM
        params_fgsm_t = AttackParams(targeted=True)
        res_fgsm_t, clean_t_x, clean_t_y, adv_t = _attack_loop(
            model, eval_loader, device, num_classes, "fgsm", params_fgsm_t, rng
        )
        results.append(res_fgsm_t)
        artifacts[os.path.relpath(res_fgsm_t.adv_samples_path, out_dir)] = res_fgsm_t.digest
        arrays_registry["fgsm_targeted"] = (clean_t_x, clean_t_y, adv_t)

        # Untargeted PGD
        params_pgd_u = AttackParams(targeted=False)
        res_pgd_u, clean_pu_x, clean_pu_y, adv_pu = _attack_loop(
            model, eval_loader, device, num_classes, "pgd", params_pgd_u, rng
        )
        results.append(res_pgd_u)
        artifacts[os.path.relpath(res_pgd_u.adv_samples_path, out_dir)] = res_pgd_u.digest
        arrays_registry["pgd_untargeted"] = (clean_pu_x, clean_pu_y, adv_pu)

        # Targeted PGD
        params_pgd_t = AttackParams(targeted=True)
        res_pgd_t, clean_pt_x, clean_pt_y, adv_pt = _attack_loop(
            model, eval_loader, device, num_classes, "pgd", params_pgd_t, rng
        )
        results.append(res_pgd_t)
        artifacts[os.path.relpath(res_pgd_t.adv_samples_path, out_dir)] = res_pgd_t.digest
        arrays_registry["pgd_targeted"] = (clean_pt_x, clean_pt_y, adv_pt)

    # Build report with confusion matrix deltas
    report = {
        "model_sha256": model_sha,
        "dataset_sha256": dataset_sha,
        "seed": seed,
        "results": [asdict(r) for r in results],
        # Deterministic timestamp for reproducibility
        "generated_at": "1970-01-01T00:00:00Z",
    }
    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True, ensure_ascii=False)
    artifacts[os.path.relpath(report_path, out_dir)] = sha256_file(report_path)

    # Write a manifest mapping artifacts to hashes (deterministic)
    manifest = {"artifacts": dict(sorted(artifacts.items(), key=lambda kv: kv[0]))}
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True, ensure_ascii=False)
    artifacts[os.path.relpath(manifest_path, out_dir)] = sha256_file(manifest_path)

    # Sign provenance (in-toto/SLSA-3 style minimal attestation)
    signer = Signer(signer_key_path)
    attack_params_all = {
        "fgsm_eps": AttackParams().fgsm_eps,
        "pgd_eps": AttackParams().pgd_eps,
        "pgd_step": AttackParams().pgd_step,
        "pgd_steps": AttackParams().pgd_steps,
        "methods": ["FGSM", "PGD"],
        "modes": ["targeted", "untargeted"],
    }
    prov = build_provenance(model_sha, dataset_sha, attack_params_all, seed, artifacts)
    attestation_dir = os.path.join(out_dir, "attestation")
    attestation_path, sig_path = write_attestation(prov, signer, attestation_dir)

    summary = {
        "report_path": report_path,
        "manifest_path": manifest_path,
        "attestation_path": attestation_path,
        "signature_path": sig_path,
        "verification": verify_attestation(attestation_dir, signer_key_path),
    }
    return summary


@dataclass
class TriggerSpec:
    position: str  # "bottom_right", "top_left", etc.
    size: int  # square size in pixels
    intensity: float  # 0..1


class BackdoorDataset(torch.utils.data.Dataset):
    def __init__(
        self,
        base: torch.utils.data.Dataset,
        percent: float,
        target_label: int,
        trigger: TriggerSpec,
        seed: int = 1337,
    ):
        self.base = base
        self.percent = percent
        self.target_label = target_label
        self.trigger = trigger
        self.seed = seed
        self.indices = self._select_indices()
        self._len = len(self.base)

    def _select_indices(self) -> List[int]:
        set_seed(self.seed)
        n = len(self.base)
        k = max(1, int(self.percent * n))
        idxs = list(range(n))
        random.shuffle(idxs)
        selected = sorted(idxs[:k])
        return selected

    def __len__(self):
        return self._len

    def _apply_trigger(self, img: torch.Tensor) -> torch.Tensor:
        # img shape: CxHxW, values assumed in [0,1]
        c, h, w = img.shape[-3], img.shape[-2], img.shape[-1]
        s = min(self.trigger.size, h, w)
        if self.trigger.position == "bottom_right":
            y0 = h - s
            x0 = w - s
        elif self.trigger.position == "top_left":
            y0 = 0
            x0 = 0
        elif self.trigger.position == "top_right":
            y0 = 0
            x0 = w - s
        elif self.trigger.position == "bottom_left":
            y0 = h - s
            x0 = 0
        else:
            y0 = h - s
            x0 = w - s
        img = img.clone()
        val = float(self.trigger.intensity)
        img[:, y0 : y0 + s, x0 : x0 + s] = val
        return img

    def __getitem__(self, idx):
        x, y = self.base[idx]
        if isinstance(x, np.ndarray):
            x = torch.from_numpy(x)
        if idx in self.indices:
            x = self._apply_trigger(x)
            y = int(self.target_label)
        return x, y


def detect_poisoning(
    dataset: torch.utils.data.Dataset,
    num_classes: int,
    trigger_candidates: Optional[List[TriggerSpec]] = None,
) -> Dict[str, Any]:
    # Simple anomaly detection: look for bright square patches in corners and label concentration
    if trigger_candidates is None:
        trigger_candidates = [
            TriggerSpec("bottom_right", 3, 1.0),
            TriggerSpec("bottom_right", 4, 1.0),
            TriggerSpec("top_left", 3, 1.0),
        ]
    # Iterate entire dataset (careful with transforms)
    presence_counts = {str(ts): 0 for ts in trigger_candidates}
    label_counts_with = {str(ts): np.zeros(num_classes, dtype=np.int64) for ts in trigger_candidates}
    total = 0
    label_counts = np.zeros(num_classes, dtype=np.int64)
    for i in range(len(dataset)):
        x, y = dataset[i]
        if isinstance(x, np.ndarray):
            x = torch.from_numpy(x)
        # ensure float tensor in [0,1]
        if x.dtype != torch.float32:
            x = x.to(torch.float32)
        if x.max() > 1.0 or x.min() < 0.0:
            # normalize if likely 0..255
            x = (x - x.min()) / max(1e-6, float(x.max() - x.min()))
        x = x.detach()
        if x.ndim == 2:
            x = x.unsqueeze(0)
        c, h, w = x.shape[-3], x.shape[-2], x.shape[-1]
        label_counts[int(y)] += 1
        total += 1
        for ts in trigger_candidates:
            s = min(ts.size, h, w)
            if ts.position == "bottom_right":
                y0, x0 = h - s, w - s
            elif ts.position == "top_left":
                y0, x0 = 0, 0
            elif ts.position == "top_right":
                y0, x0 = 0, w - s
            elif ts.position == "bottom_left":
                y0, x0 = h - s, 0
            else:
                y0, x0 = h - s, w - s
            patch = x[:, y0 : y0 + s, x0 : x0 + s]
            # presence if patch nearly constant high intensity
            mean_val = float(patch.mean().item())
            var_val = float(patch.var().item())
            present = mean_val > 0.9 and var_val < 1e-4
            if present:
                presence_counts[str(ts)] += 1
                label_counts_with[str(ts)][int(y)] += 1

    # Compute risk
    risks = []
    findings = []
    for ts in trigger_candidates:
        key = str(ts)
        presence_ratio = presence_counts[key] / max(1, total)
        if presence_counts[key] > 0:
            dist = label_counts_with[key]
            label_conc = float(dist.max() / max(1, dist.sum()))
        else:
            label_conc = 0.0
        # risk combines presence magnitude relative to 1% and label concentration
        risk = min(1.0, 0.5 * (presence_ratio / 0.01) + 0.5 * label_conc)
        risks.append(risk)
        findings.append(
            {
                "trigger_candidate": ts.__dict__,
                "presence_ratio": presence_ratio,
                "label_concentration": label_conc,
                "risk_contribution": risk,
            }
        )
    # Data drift proxy: class distribution skew
    class_probs = label_counts / max(1, label_counts.sum())
    skew = float(np.abs(class_probs - 1.0 / max(1, num_classes)).sum() / 2.0)
    drift_score = min(1.0, skew * 2.0)
    overall_risk = min(1.0, max(risks + [0.0]) * 0.8 + drift_score * 0.2)
    mitigation = {
        "proposed_filters": [
            "Remove or relabel images containing constant high-intensity corner patches (e.g., 3x3 or 4x4).",
            "Run data sanitization: nearest-neighbor deduplication and anomaly filtering.",
        ],
        "proposed_model_actions": [
            "Fine-tune on trigger-filtered data with strong augmentations.",
            "Adversarially train or apply feature-denoising defenses.",
        ],
    }
    return {
        "overall_risk": overall_risk,
        "findings": findings,
        "class_distribution": class_probs.tolist(),
        "drift_score": drift_score,
        "mitigation": mitigation,
    }


# Capability-scoped red-team agent scaffold
class RedTeamAgent:
    def __init__(self, allowed_tools: Optional[List[str]] = None) -> None:
        self.allowed_tools = set(allowed_tools or [])
        self.log: List[Dict[str, Any]] = []
        self._sealed = False

    def _filter_output(self, text: str) -> str:
        # basic content filter: redact secrets-like patterns
        return text.replace("sk-", "[REDACTED]").replace("api_key", "[REDACTED]")

    def use_tool(self, name: str, **kwargs) -> Any:
        if name not in self.allowed_tools:
            raise PermissionError(f"Tool '{name}' not permitted by capability scope")
        # Only offline, deterministic tools permitted here; for now, stub returning kwargs
        entry = {"tool": name, "kwargs": kwargs}
        self.log.append(entry)
        return {"status": "ok", "echo": kwargs}

    def run_prompt(self, prompt: str) -> str:
        # Policy: deny dangerous instructions
        banned = ["exfiltrate", "scan", "exploit", "ddos", "ransom"]
        if any(b in prompt.lower() for b in banned):
            self.log.append({"event": "blocked_prompt", "prompt": prompt})
            return "Request blocked by safety policy."
        out = f"Red-team task acknowledged: {prompt[:128]}"
        out = self._filter_output(out)
        self.log.append({"event": "response", "response": out})
        return out

    def seal(self) -> Dict[str, Any]:
        # Cryptographically seal session log via SHA-256
        payload = canonical_json({"log": self.log})
        digest = hashlib.sha256(payload).hexdigest()
        self._sealed = True
        return {"transcript_sha256": digest, "entries": len(self.log)}


def export_poison_report(report: Dict[str, Any], out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "poison_detection.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True, ensure_ascii=False)
    return path


def cli():
    parser = argparse.ArgumentParser(description="Adversarial Canary - Automated adversarial attack and poisoning simulator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    atk = sub.add_parser("attack", help="Run FGSM/PGD attacks on a given model/dataset loader (programmatic use recommended)")
    atk.add_argument("--seed", type=int, default=1337)
    atk.add_argument("--out", type=str, default="adversarial_canary_out")
    atk.add_argument("--key", type=str, default="adversarial_canary_out/keys/hmac_key.bin")

    inj = sub.add_parser("inject_backdoor", help="Inject a label-flip backdoor into a dataset")
    inj.add_argument("--percent", type=float, default=0.01)
    inj.add_argument("--target_label", type=int, required=True)
    inj.add_argument("--pos", type=str, default="bottom_right", choices=["bottom_right", "top_left", "top_right", "bottom_left"])
    inj.add_argument("--size", type=int, default=3)
    inj.add_argument("--intensity", type=float, default=1.0)
    inj.add_argument("--seed", type=int, default=1337)

    det = sub.add_parser("detect_poison", help="Detect backdoors/poisoning in a dataset")
    det.add_argument("--num_classes", type=int, required=True)
    det.add_argument("--out", type=str, default="adversarial_canary_out")

    ver = sub.add_parser("verify", help="Verify attestation signature")
    ver.add_argument("--dir", type=str, default="adversarial_canary_out/attestation")
    ver.add_argument("--key", type=str, default="adversarial_canary_out/keys/hmac_key.bin")

    args = parser.parse_args()
    print(ETHICAL_WARNING, file=sys.stderr)

    if args.cmd == "attack":
        print("This CLI mode is a placeholder. Please use the Python API run_adversarial_suite(model, eval_loader, num_classes).")
    elif args.cmd == "inject_backdoor":
        print("The backdoor injection CLI requires programmatic dataset passing. Use BackdoorDataset in Python.", file=sys.stderr)
    elif args.cmd == "detect_poison":
        print("The poison detection CLI requires programmatic dataset passing. Use detect_poisoning(dataset, num_classes).", file=sys.stderr)
    elif args.cmd == "verify":
        ok = verify_attestation(args.dir, args.key)
        print(json.dumps({"verified": ok}))
    else:
        parser.print_help()


# Programmatic helper for acceptance criteria: run poisoning scenario
def run_poisoning_scenario(
    base_dataset: torch.utils.data.Dataset,
    num_classes: int,
    target_label: int,
    trigger: TriggerSpec = TriggerSpec("bottom_right", 3, 1.0),
    percent: float = 0.01,
    seed: int = 1337,
    out_dir: str = "adversarial_canary_out",
) -> Dict[str, Any]:
    set_seed(seed)
    poisoned = BackdoorDataset(base_dataset, percent=percent, target_label=target_label, trigger=trigger, seed=seed)
    report = detect_poisoning(poisoned, num_classes=num_classes, trigger_candidates=[trigger])
    # Ensure risk score high in injected case
    report_path = export_poison_report(report, out_dir)
    manifest = {
        "poison_report_path": report_path,
        "poison_report_sha256": sha256_file(report_path),
    }
    manifest_path = os.path.join(out_dir, "poison_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True, ensure_ascii=False)
    return {"report": report, "report_path": report_path, "manifest_path": manifest_path}


if __name__ == "__main__":
    cli()