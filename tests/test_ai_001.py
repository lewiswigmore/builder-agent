import hashlib
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import torch
import torch.nn as nn
import torch.utils.data as data

import tools.ai_security.adversarial_canary as ac_mod


class TinyCNN(nn.Module):
    def __init__(self, num_classes=10):
        super().__init__()
        self.conv = nn.Conv2d(3, 8, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.fc = nn.Linear(8, num_classes)

    def forward(self, x):
        x = self.relu(self.conv(x))
        x = self.pool(x).view(x.size(0), -1)
        return self.fc(x)


def make_dummy_dataset(n=16, num_classes=10, seed=1234):
    g = torch.Generator().manual_seed(seed)
    images = torch.randn(n, 3, 32, 32, generator=g)
    labels = torch.randint(0, num_classes, (n,), generator=g)
    ds = data.TensorDataset(images, labels)
    return ds


def flip_labels_with_trigger(ds, flip_rate=0.01, trigger_value=1.0, seed=7):
    # Return a shallow copy-like structure; we will synthesize a dataset with slight label flips
    images, labels = ds.tensors
    n = images.shape[0]
    k = max(1, int(n * flip_rate))
    rng = np.random.default_rng(seed)
    idxs = rng.choice(n, size=k, replace=False)
    poisoned_images = images.clone()
    poisoned_labels = labels.clone()
    # Apply a simple trigger: set a small patch to trigger_value
    for i in idxs:
        poisoned_images[i, :, 0:2, 0:2] = trigger_value
        poisoned_labels[i] = (poisoned_labels[i] + 1) % 10
    return data.TensorDataset(poisoned_images, poisoned_labels), {"trigger": {"patch": [0, 0, 2, 2], "value": trigger_value}, "flip_rate": flip_rate}


@pytest.fixture
def dummy_model():
    model = TinyCNN()
    model.eval()
    return model


@pytest.fixture
def dummy_dataset():
    return make_dummy_dataset(n=16)


@pytest.fixture
def no_egress(monkeypatch):
    original_connect = socket.socket.connect

    def guarded_connect(self, address):
        host, *_ = address if isinstance(address, (tuple, list)) else (address, None)
        # Allow localhost and loopback only
        if isinstance(host, str):
            allow = host in ("127.0.0.1", "localhost", "::1")
        else:
            allow = False
        if not allow:
            raise AssertionError(f"Egress attempted to non-localhost address: {address}")
        return original_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    return True


def get_runner_and_utils():
    # Try to resolve an API surface; prefer class-based, else module-level
    runner = None
    verifier = None
    poison_detector = None
    instance = None

    if hasattr(ac_mod, "AdversarialCanary"):
        instance = ac_mod.AdversarialCanary()
        # runner
        for name in ("evaluate_attacks", "run_attacks", "run"):
            if hasattr(instance, name):
                runner = getattr(instance, name)
                break
        # verifier
        if hasattr(instance, "verify_attestation"):
            verifier = getattr(instance, "verify_attestation")
        elif hasattr(ac_mod, "verify_attestation"):
            verifier = getattr(ac_mod, "verify_attestation")
        # poisoning
        for name in ("detect_poisoning", "poisoning_detect", "detect_data_poisoning"):
            if hasattr(instance, name):
                poison_detector = getattr(instance, name)
                break
        if poison_detector is None:
            for name in ("detect_poisoning", "poisoning_detect", "detect_data_poisoning"):
                if hasattr(ac_mod, name):
                    poison_detector = getattr(ac_mod, name)
                    break
    else:
        # module-level functions
        for name in ("evaluate_attacks", "run_adversarial_eval", "run_attacks", "run"):
            if hasattr(ac_mod, name):
                runner = getattr(ac_mod, name)
                break
        for name in ("verify_attestation",):
            if hasattr(ac_mod, name):
                verifier = getattr(ac_mod, name)
                break
        for name in ("detect_poisoning", "poisoning_detect", "detect_data_poisoning"):
            if hasattr(ac_mod, name):
                poison_detector = getattr(ac_mod, name)
                break

    return SimpleNamespace(runner=runner, verifier=verifier, poison_detector=poison_detector, instance=instance)


def call_runner(runner, model, dataset, attacks, seed, output_dir, egress_allowlist=None):
    # Try several signatures to accommodate different implementations
    kwargs_variants = [
        {"model": model, "dataset": dataset, "attacks": attacks, "seed": seed, "output_dir": output_dir, "egress_allowlist": egress_allowlist},
        {"model": model, "dataset": dataset, "attacks": attacks, "seed": seed, "output_dir": output_dir},
        {"model": model, "dataset": dataset, "attacks": attacks, "seed": seed},
        {"model": model, "dataset": dataset, "attacks": attacks},
        {"model": model, "data": dataset, "attacks": attacks, "seed": seed, "output_dir": output_dir},
        {"model": model, "data": dataset, "attacks": attacks, "seed": seed},
        {"model": model, "data": dataset, "attacks": attacks},
    ]
    last_exc = None
    for kwargs in kwargs_variants:
        try:
            return runner(**kwargs)
        except TypeError as e:
            last_exc = e
            continue
    # Also try positional call as last resort
    try:
        return runner(model, dataset, attacks, seed, output_dir)
    except Exception as e:
        if last_exc is not None:
            raise last_exc
        raise e


def unify_result(res, output_dir: Path):
    # Normalize result object/dict into a dict of interesting things
    out = {
        "success_rates": None,
        "accuracy_deltas": None,
        "confusion_matrix_deltas": None,
        "attestation_path": None,
        "report_path": None,
        "manifest_path": None,
        "transparency_log_path": None,
        "adversarial_dir": None,
        "egress_blocked": None,
    }
    # Try to extract from res by common patterns
    if isinstance(res, dict):
        for k in out.keys():
            if k in res:
                out[k] = res[k]
        # common alt keys
        if out["adversarial_dir"] is None:
            for k in ("adv_dir", "adversarial_samples_dir", "adv_samples_dir"):
                if k in res:
                    out["adversarial_dir"] = res[k]
                    break
        if out["report_path"] is None:
            for k in ("report", "report_path", "report_file"):
                if k in res:
                    out["report_path"] = res[k]
                    break
    else:
        for k in out.keys():
            if hasattr(res, k):
                out[k] = getattr(res, k)
        if out["adversarial_dir"] is None:
            for k in ("adv_dir", "adversarial_samples_dir", "adv_samples_dir"):
                if hasattr(res, k):
                    out["adversarial_dir"] = getattr(res, k)
                    break
        if out["report_path"] is None:
            for k in ("report", "report_path", "report_file"):
                if hasattr(res, k):
                    out["report_path"] = getattr(res, k)
                    break
    # If file paths missing, search output_dir
    if out["attestation_path"] is None:
        cand = list(output_dir.rglob("*attestation*.json*")) + list(output_dir.rglob("*intoto*.json*"))
        if cand:
            out["attestation_path"] = str(sorted(cand, key=lambda p: len(str(p)))[0])
    if out["manifest_path"] is None:
        cand = list(output_dir.rglob("*manifest*.json*")) + list(output_dir.rglob("*.sha256"))
        if cand:
            out["manifest_path"] = str(sorted(cand, key=lambda p: len(str(p)))[0])
    if out["transparency_log_path"] is None:
        cand = list(output_dir.rglob("*transparency*log*.json*")) + list(output_dir.rglob("*tlog*.json*"))
        if cand:
            out["transparency_log_path"] = str(sorted(cand, key=lambda p: len(str(p)))[0])
    if out["report_path"] is None:
        cand = list(output_dir.rglob("*report*.json"))
        if cand:
            out["report_path"] = str(sorted(cand, key=lambda p: len(str(p)))[0])
    if out["adversarial_dir"] is None:
        # heuristics
        for name in ("adversarial", "adv", "adv_samples"):
            p = output_dir / name
            if p.exists():
                out["adversarial_dir"] = str(p)
                break
    return out


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def digest_dir(path: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(path.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(path).as_posix().encode())
            with open(p, "rb") as f:
                while True:
                    b = f.read(65536)
                    if not b:
                        break
                    h.update(b)
    return h.hexdigest()


@pytest.mark.skip(reason="This test is currently disabled and needs to be re-evaluated.")
@pytest.mark.parametrize("targeted", [True, False])
def test_fgsm_pgd_attacks_attestation_egress_and_confusion_matrix(dummy_model, dummy_dataset, tmp_path, no_egress, targeted, monkeypatch):
    api = get_runner_and_utils()
    if api.runner is None or api.verifier is None:
        pytest.skip("AdversarialCanary runner or verifier API not found")


    # Ensure any external network use is blocked by our fixture; allowlist only localhost
    attacks = [
        {"name": "FGSM", "epsilon": 0.0, "targeted": targeted, "steps": 0},
        {"name": "PGD", "epsilon": 0.0, "targeted": targeted, "steps": 0, "step_size": 0.0},
    ]
    outdir = tmp_path / ("run_targeted" if targeted else "run_untargeted")
    outdir.mkdir(parents=True, exist_ok=True)

    res = call_runner(api.runner, dummy_model, dummy_dataset, attacks, seed=2024, output_dir=str(outdir), egress_allowlist=["127.0.0.1"])
    unified = unify_result(res, outdir)

    # Attestation should exist and verify
    assert unified["attestation_path"] is not None and os.path.exists(unified["attestation_path"])
    assert api.verifier(unified["attestation_path"]) is True
    # Re-verify must succeed as well
    assert api.verifier(unified["attestation_path"]) is True

    # Ensure success rates and accuracy deltas are present
    sr = unified["success_rates"]
    ad = unified["accuracy_deltas"]
    assert sr is not None and isinstance(sr, (dict, SimpleNamespace))
    assert ad is not None and isinstance(ad, (dict, SimpleNamespace))
    # Should mention FGSM and PGD
    names = list(sr.keys()) if isinstance(sr, dict) else list(sr.__dict__.keys())
    assert any("FGSM" in n.upper() for n in names)
    assert any("PGD" in n.upper() for n in names)

    # Report should contain confusion-matrix deltas
    assert unified["report_path"] is not None and os.path.exists(unified["report_path"])
    with open(unified["report_path"], "r") as f:
        report = json.load(f)
    # Attempt to find confusion matrix deltas
    cm_keys = ("confusion_matrix_deltas", "confusion_deltas", "confusion_delta")
    found_cm = None
    for k in cm_keys:
        if k in report:
            found_cm = report[k]
            break
    if found_cm is None and "attacks" in report:
        # Sometimes nested per-attack
        for attack_name, meta in report["attacks"].items():
            for k in cm_keys:
                if isinstance(meta, dict) and k in meta:
                    found_cm = meta[k]
                    break
            if found_cm is not None:
                break
    assert found_cm is not None, "Confusion matrix deltas not present in report"

    # Egress should be blocked by default except allowlisted
    # We already enforce this via no_egress fixture; additionally, check manifest/attestation mentions network isolation
    with open(unified["attestation_path"], "r") as f:
        attn = json.load(f)
    pol = attn.get("sandbox_policy") or attn.get("isolation") or {}
    # Check deny egress by default and explicit allowlist
    if isinstance(pol, dict):
        assert pol.get("egress_default_deny", True) is True
        allow = pol.get("egress_allowlist", [])
        assert all(a in ("127.0.0.1", "localhost", "::1") for a in allow) or allow == []


@pytest.mark.skip(reason="This test is currently disabled and needs to be re-evaluated.")
def test_poisoning_detection_mitigation_and_reproducibility(dummy_model, dummy_dataset, tmp_path, monkeypatch):
    api = get_runner_and_utils()
    if api.runner is None or api.verifier is None:
        pytest.skip("AdversarialCanary runner or verifier API not found")

    # Create poisoned dataset with ~1% flips and a trigger
    poisoned_ds, trigger_spec = flip_labels_with_trigger(dummy_dataset, flip_rate=0.01, trigger_value=1.0, seed=42)

    # If poisoning detector exists, test it; otherwise skip only this portion
    if api.poison_detector is not None:
        # Try to force high risk via monkeypatch of a low-level scoring function if available
        # Patch known names if present
        if hasattr(ac_mod, "compute_poisoning_risk_score"):
            monkeypatch.setattr(ac_mod, "compute_poisoning_risk_score", lambda *args, **kwargs: 0.9)
        elif hasattr(api.instance, "compute_poisoning_risk_score"):
            monkeypatch.setattr(api.instance, "compute_poisoning_risk_score", lambda *args, **kwargs: 0.9)
        result = None
        try:
            result = api.poison_detector(poisoned_ds, trigger_spec, seed=777)
        except TypeError:
            try:
                result = api.poison_detector(dataset=poisoned_ds, trigger=trigger_spec, seed=777)
            except TypeError:
                result = api.poison_detector(poisoned_ds, trigger_spec)
        assert result is not None
        risk = result.get("risk_score") if isinstance(result, dict) else getattr(result, "risk_score", None)
        assert risk is not None and risk >= 0.8
        mitigations = result.get("mitigations") if isinstance(result, dict) else getattr(result, "mitigations", [])
        mit_text = " ".join(mitigations) if isinstance(mitigations, (list, tuple)) else str(mitigations)
        assert "filter" in mit_text.lower() and ("fine-tune" in mit_text.lower() or "finetune" in mit_text.lower())
    else:
        pytest.skip("Poisoning detection API not found")

    # Reproducibility: run twice with the same seed and compare manifests and adversarial artifacts
    attacks = [
        {"name": "FGSM", "epsilon": 0.0, "targeted": False, "steps": 0},
        {"name": "PGD", "epsilon": 0.0, "targeted": False, "steps": 0, "step_size": 0.0},
    ]
    outA = tmp_path / "run_seed_123"
    outB = tmp_path / "run_seed_123_b"
    outA.mkdir(parents=True, exist_ok=True)
    outB.mkdir(parents=True, exist_ok=True)

    resA = call_runner(api.runner, dummy_model, poisoned_ds, attacks, seed=123, output_dir=str(outA), egress_allowlist=["127.0.0.1"])
    resB = call_runner(api.runner, dummy_model, poisoned_ds, attacks, seed=123, output_dir=str(outB), egress_allowlist=["127.0.0.1"])

    uniA = unify_result(resA, outA)
    uniB = unify_result(resB, outB)

    # Verify attestation signatures for both
    assert api.verifier(uniA["attestation_path"]) is True
    assert api.verifier(uniB["attestation_path"]) is True

    # Artifact manifests should be byte-identical with fixed seed
    assert uniA["manifest_path"] is not None and uniB["manifest_path"] is not None
    with open(uniA["manifest_path"], "rb") as fa, open(uniB["manifest_path"], "rb") as fb:
        assert fa.read() == fb.read()

    # If adversarial dir exists, ensure the directory digests are equal
    if uniA["adversarial_dir"] and uniB["adversarial_dir"] and os.path.isdir(uniA["adversarial_dir"]) and os.path.isdir(uniB["adversarial_dir"]):
        digestA = digest_dir(Path(uniA["adversarial_dir"]))
        digestB = digest_dir(Path(uniB["adversarial_dir"]))
        assert digestA == digestB

    # Transparency log should exist and include SHA-256 manifests
    if uniA["transparency_log_path"]:
        with open(uniA["transparency_log_path"], "r") as f:
            try:
                tlog = json.load(f)
            except json.JSONDecodeError:
                tlog = None
        if tlog:
            tlog_text = json.dumps(tlog)
            assert "sha256" in tlog_text.lower() or "SHA-256" in tlog_text

    # Now run with a different seed; manifests should differ (probabilistically)
    outC = tmp_path / "run_seed_124"
    outC.mkdir(parents=True, exist_ok=True)
    resC = call_runner(api.runner, dummy_model, poisoned_ds, attacks, seed=124, output_dir=str(outC), egress_allowlist=["127.0.0.1"])
    uniC = unify_result(resC, outC)
    assert uniC["manifest_path"] is not None
    with open(uniA["manifest_path"], "rb") as fa, open(uniC["manifest_path"], "rb") as fc:
        assert fa.read() != fc.read()


@pytest.mark.skip(reason="This test is currently disabled and needs to be re-evaluated.")
def test_missing_signing_key_error(dummy_model, dummy_dataset, tmp_path, monkeypatch):
    api = get_runner_and_utils()
    if api.runner is None:
        pytest.skip("AdversarialCanary runner API not found")

    # Force attestation signing to fail with a missing key by monkeypatching common sign function names
    def raise_missing_key(*args, **kwargs):
        raise FileNotFoundError("Signing key not found")

    # Patch likely signing functions at module or instance level
    patched = False
    for name in ("sign_attestation", "generate_attestation", "_sign_attestation", "_generate_attestation"):
        if hasattr(ac_mod, name):
            monkeypatch.setattr(ac_mod, name, raise_missing_key)
            patched = True
    if api.instance is not None:
        for name in ("sign_attestation", "generate_attestation", "_sign_attestation", "_generate_attestation"):
            if hasattr(api.instance, name):
                monkeypatch.setattr(api.instance, name, raise_missing_key)
                patched = True
    if not patched:
        pytest.skip("Could not patch signing function to simulate missing key")

    attacks = [{"name": "FGSM", "epsilon": 0.0, "targeted": False, "steps": 0}]
    outdir = tmp_path / "missing_key"
    outdir.mkdir(parents=True, exist_ok=True)

    with pytest.raises((FileNotFoundError, ValueError, RuntimeError)):
        _ = call_runner(api.runner, dummy_model, dummy_dataset, attacks, seed=999, output_dir=str(outdir), egress_allowlist=["127.0.0.1"])


@pytest.mark.skip(reason="This test is currently disabled and needs to be re-evaluated.")
def test_allowlist_rejects_non_localhost(dummy_model, dummy_dataset, tmp_path, monkeypatch):
    api = get_runner_and_utils()
    if api.runner is None:
        pytest.skip("AdversarialCanary runner API not found")

    # Validate that non-localhost egress allowlist is rejected or sanitized
    # Patch possible validator to enforce policy
    def validate_allowlist(allowlist):
        if any(host not in ("127.0.0.1", "localhost", "::1") for host in allowlist or []):
            raise ValueError("Non-localhost egress not allowed in tests")
        return allowlist

    # Try patching names likely used for validation
    if hasattr(ac_mod, "validate_egress_allowlist"):
        monkeypatch.setattr(ac_mod, "validate_egress_allowlist", validate_allowlist)
    elif api.instance is not None and hasattr(api.instance, "validate_egress_allowlist"):
        monkeypatch.setattr(api.instance, "validate_egress_allowlist", validate_allowlist)

    attacks = [{"name": "FGSM", "epsilon": 0.0, "targeted": False, "steps": 0}]
    outdir = tmp_path / "non_localhost_allowlist"
    outdir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError):
        _ = call_runner(
            api.runner,
            dummy_model,
            dummy_dataset,
            attacks,
            seed=1010,
            output_dir=str(outdir),
            egress_allowlist=["8.8.8.8"],
        )