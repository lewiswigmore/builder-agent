import io
import json
import os
import re
import socket
import tempfile
import time
from hashlib import sha256
from typing import Any, Dict

import pytest

# Import the tool under test
from tools.ai_security.sidechannel_guard import (
    SideChannelGuard,
    LeakageType,
    ConsentRequiredError,
    EgressBlockedError,
    AttestationVerificationError,
)


@pytest.fixture
def temp_storage(tmp_path):
    return tmp_path


@pytest.fixture
def guard(temp_storage):
    g = SideChannelGuard(storage_path=str(temp_storage), consent_required=True, allow_egress=False, trust_root=None)
    return g


@pytest.fixture
def torch():
    return pytest.importorskip("torch")


@pytest.fixture
def torch_branchy_model(torch):
    import torch.nn as nn

    class BranchyModel(nn.Module):
        def __init__(self, mitigate: bool = False):
            super().__init__()
            self.fc = nn.Linear(8, 8)
            self.mitigate = mitigate
            # marker to help fake collector decide behavior
            self._model_id = "branchy"

        def forward(self, x):
            y = self.fc(x)
            # Synthetic data-dependent branch
            # We don't rely on actual timing here; collector will be mocked.
            if not self.mitigate:
                if int(torch.sum(x).item()) % 2 == 1:
                    y = y + 1
                else:
                    y = y + 2
            else:
                # Constant-time padding mitigation: perform both branches in masked way
                a = (int(torch.sum(x).item()) % 2 == 1)
                y = y + (1 if a else 0) + (2 if not a else 0)
            return y

    return BranchyModel


def _fake_telemetry(branchy: bool, mitigated: bool) -> Dict[str, Any]:
    if branchy and not mitigated:
        # High variance scenario
        timing_samples = [1.0, 1.2, 1.1, 4.5, 4.2, 4.4, 1.0, 4.6]
        cache_misses = [100, 105, 420, 415, 430, 98]
    else:
        # Mitigated/constant-time low variance
        timing_samples = [2.0, 2.1, 2.0, 2.1, 2.05, 2.0]
        cache_misses = [200, 205, 198, 203]
    aggregate = {
        "avg_time_ms": sum(timing_samples) / len(timing_samples),
        "variance_ms2": _variance(timing_samples),
        "avg_cache_misses": sum(cache_misses) / len(cache_misses),
        "samples": len(timing_samples),
    }
    # Aggregate, non-content telemetry only
    telemetry = {
        "timing_samples": timing_samples,
        "cache_misses": cache_misses,
        "aggregate": aggregate,
        # No raw inputs, weights, etc.
    }
    return telemetry


def _variance(samples):
    if not samples:
        return 0.0
    m = sum(samples) / len(samples)
    return sum((x - m) ** 2 for x in samples) / len(samples)


def _fake_compute_leakage_score(telemetry: Dict[str, Any]) -> float:
    # Simple heuristic: normalize variance into a 0..1-ish score
    v = telemetry["aggregate"]["variance_ms2"]
    score = 1 - 1 / (1 + v)  # monotonic increasing with variance
    # ensure within [0,1)
    return max(0.0, min(0.999, score))


class FakeSigner:
    def __init__(self, key: bytes):
        self.key = key

    def sign(self, payload: bytes) -> str:
        # Deterministic HMAC-like signature using sha256(key || payload)
        return sha256(self.key + payload).hexdigest()

    def verify(self, payload: bytes, signature: str, trust_root: bytes) -> bool:
        if trust_root != self.key:
            return False
        expected = sha256(self.key + payload).hexdigest()
        return expected == signature


def test_leakage_detection_timing_branch(guard, torch, torch_branchy_model, monkeypatch, tmp_path):
    # User consent is required and must be explicit
    with pytest.raises(ConsentRequiredError):
        guard.start()
    guard.provide_consent(user="test_user", scope="telemetry")
    guard.start()
    assert getattr(guard, "least_privilege", True) is True

    model = torch_branchy_model(mitigate=False)
    inputs = torch.randn(4, 8)

    # Mock telemetry collection to avoid real perf/eBPF
    def fake_collect_telemetry(self, model_arg, inputs_arg, runs=50):
        assert model_arg is model
        # Ensure no content captured
        tel = _fake_telemetry(branchy=True, mitigated=False)
        assert "raw_inputs" not in tel and "weights" not in tel
        return tel

    monkeypatch.setattr(guard, "collect_telemetry", fake_collect_telemetry.__get__(guard, guard.__class__))

    # Mock leakage scoring
    monkeypatch.setattr(guard, "compute_leakage_score", lambda telemetry: _fake_compute_leakage_score(telemetry))

    # Policy threshold to trigger timing leakage
    policy = {"timing_variance_threshold": 0.5, "score_threshold": 0.5}

    result = guard.monitor(model, inputs, policy)
    assert hasattr(result, "alert_emitted") and result.alert_emitted is True
    assert hasattr(result, "leakage_type") and result.leakage_type == LeakageType.LEAKAGE_TIMING
    assert hasattr(result, "metrics")
    metrics = result.metrics
    assert "variance_ms2" in metrics and metrics["variance_ms2"] > policy["timing_variance_threshold"]
    assert "score" in metrics and metrics["score"] >= policy["score_threshold"]
    # Aggregate-only telemetry in metrics details
    assert "raw_inputs" not in metrics and "weights" not in metrics

    guard.stop()


def test_mitigation_constant_time_no_alert(guard, torch, torch_branchy_model, monkeypatch):
    guard.provide_consent(user="test_user", scope="telemetry")
    guard.start()

    model = torch_branchy_model(mitigate=True)
    inputs = torch.randn(4, 8)

    def fake_collect_telemetry(self, model_arg, inputs_arg, runs=50):
        return _fake_telemetry(branchy=True, mitigated=True)

    monkeypatch.setattr(guard, "collect_telemetry", fake_collect_telemetry.__get__(guard, guard.__class__))
    monkeypatch.setattr(guard, "compute_leakage_score", lambda telemetry: _fake_compute_leakage_score(telemetry))

    policy = {"timing_variance_threshold": 0.5, "score_threshold": 0.5}
    result = guard.monitor(model, inputs, policy)
    assert result.alert_emitted is False
    assert (result.metrics.get("variance_ms2") or 0) < policy["timing_variance_threshold"]
    assert result.metrics.get("score", 0) < policy["score_threshold"]

    guard.stop()


def test_attestation_bundle_and_signature_verification(guard, monkeypatch):
    # Configure fake signer and trust root
    key = b"test-trust-root-key"
    signer = FakeSigner(key)
    guard._signer = signer  # tool should use internal signer abstraction
    guard.trust_root = key

    # Fake environment hashes
    env_hashes = {
        "kernel_hash": "khash123",
        "driver_hash": "dhash456",
        "tooling_hash": "thash789",
    }
    monkeypatch.setattr(guard, "get_environment_hashes", lambda: env_hashes)

    # Deterministic test vectors (reproducible)
    test_vectors = {
        "vector_id": "timing-variance-v1",
        "input_digest": sha256(b"branchy_false").hexdigest(),
        "mitigation_digest": sha256(b"mitigate_true").hexdigest(),
    }

    # Simulate a previous monitoring result
    class Res:
        alert_emitted = True
        leakage_type = LeakageType.LEAKAGE_TIMING
        metrics = {"score": 0.88, "variance_ms2": 3.2}
    result = Res()

    bundle = guard.generate_attestation(result=result, env_info=env_hashes, test_vectors=test_vectors, sign=True)
    assert isinstance(bundle, dict)
    # Must contain leakage score, env hashes, and signed provenance
    assert "provenance" in bundle and "signature" in bundle and "payload" in bundle
    payload = bundle["payload"]
    assert isinstance(payload, dict)
    assert payload.get("leakage_score") == result.metrics["score"]
    assert payload.get("environment") == env_hashes
    assert payload.get("test_vectors") == test_vectors

    # Verify signature with trust root
    assert guard.verify_attestation(bundle) is True

    # Failure with wrong trust root
    old_root = guard.trust_root
    guard.trust_root = b"wrong-root"
    with pytest.raises(AttestationVerificationError):
        guard.verify_attestation(bundle)
    guard.trust_root = old_root


def test_consent_required_and_non_content_telemetry(guard, monkeypatch, torch, torch_branchy_model):
    # Starting without consent should fail
    with pytest.raises(ConsentRequiredError):
        guard.start()

    guard.provide_consent(user="analyst", scope="telemetry")
    guard.start()

    model = torch_branchy_model(mitigate=False)
    inputs = torch.randn(1, 8)

    def fake_collect_telemetry(self, model_arg, inputs_arg, runs=10):
        tel = _fake_telemetry(branchy=True, mitigated=False)
        # ensure non-content
        assert "raw_inputs" not in tel
        assert "weights" not in tel
        return tel

    monkeypatch.setattr(guard, "collect_telemetry", fake_collect_telemetry.__get__(guard, guard.__class__))
    monkeypatch.setattr(guard, "compute_leakage_score", lambda telemetry: _fake_compute_leakage_score(telemetry))

    policy = {"timing_variance_threshold": 0.1, "score_threshold": 0.1}
    res = guard.monitor(model, inputs, policy)
    assert hasattr(res, "metrics")
    assert "raw_inputs" not in res.metrics
    assert "weights" not in res.metrics

    guard.stop()


def test_storage_encryption_at_rest(guard, monkeypatch, tmp_path):
    # Provide consent and start
    guard.provide_consent(user="analyst", scope="telemetry")
    guard.start()

    # Prepare telemetry and ensure persist writes encrypted content
    telemetry = _fake_telemetry(branchy=False, mitigated=True)
    # Monkeypatch encryption at rest to add ENC: prefix
    def fake_encrypt(data: bytes) -> bytes:
        return b"ENC:" + data[::-1]  # trivial reversible

    monkeypatch.setattr(guard, "_encrypt_at_rest", fake_encrypt)

    # Persist and check file contents
    fp = os.path.join(str(tmp_path), "telemetry.bin")
    guard.persist_telemetry(telemetry, filepath=fp)
    with open(fp, "rb") as f:
        blob = f.read()
    assert blob.startswith(b"ENC:")
    # Ensure plaintext markers are not present
    assert b"timing_samples" not in blob and b"cache_misses" not in blob

    guard.stop()


def test_egress_blocking_and_allowlist(guard, monkeypatch):
    guard.provide_consent(user="netops", scope="telemetry")
    guard.start()

    # Bundle and local URL
    bundle = {"payload": {"ok": True}, "provenance": {"id": "x"}, "signature": "abc"}
    url_local = "http://127.0.0.1:9999/report"

    # Mock requests.post to avoid actual network
    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        class Resp:
            status_code = 200
            text = "ok"
        return Resp()

    import requests
    monkeypatch.setattr(requests, "post", fake_post)

    # Default is blocked; should raise
    with pytest.raises(EgressBlockedError):
        guard.report_remote(bundle=bundle, url=url_local, timeout=1.0)
    assert calls == []

    # Allowlist localhost and retry
    guard.set_egress_allowlist(["127.0.0.1"])
    guard.report_remote(bundle=bundle, url=url_local, timeout=1.0)
    assert len(calls) == 1 and calls[0]["url"] == url_local

    guard.stop()


def test_collector_error_handling(guard, monkeypatch, torch, torch_branchy_model):
    guard.provide_consent(user="qa", scope="telemetry")
    guard.start()

    model = torch_branchy_model(mitigate=False)
    inputs = torch.randn(2, 8)

    def boom(self, model_arg, inputs_arg, runs=50):
        raise RuntimeError("collector failed")

    monkeypatch.setattr(guard, "collect_telemetry", boom.__get__(guard, guard.__class__))
    # compute_leakage_score should not be called; but provide a safe default if it is
    monkeypatch.setattr(guard, "compute_leakage_score", lambda telemetry: 0.0)

    policy = {"timing_variance_threshold": 0.5, "score_threshold": 0.5}
    res = guard.monitor(model, inputs, policy)
    assert res.alert_emitted is False
    assert res.leakage_type in (None, getattr(LeakageType, "NONE", None), getattr(LeakageType, "NO_LEAKAGE", None))
    assert "error" in res.metrics and "collector failed" in res.metrics["error"]

    guard.stop()