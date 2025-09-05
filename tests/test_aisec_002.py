import importlib
import json
import os
import re
import shutil
import socket
import threading
import time
from contextlib import closing
from pathlib import Path

import pytest

dlp = importlib.import_module("tools.ai_security.dlp_tracer")
DLPTracer = getattr(dlp, "DLPTracer")
LineageVerificationError = getattr(dlp, "LineageVerificationError", Exception)
SandboxViolationError = getattr(dlp, "SandboxViolationError", Exception)
PrivacyConfigError = getattr(dlp, "PrivacyConfigError", Exception)


class TriggerModel:
    def __init__(self, trigger="TRIGGER", target_label=1, base_label=0):
        self.trigger = trigger
        self.target_label = target_label
        self.base_label = base_label

    def predict(self, X):
        preds = []
        for row in X:
            if isinstance(row, dict):
                text = str(row.get("x", ""))
            else:
                text = str(row)
            if self.trigger in text:
                preds.append(self.target_label)
            else:
                preds.append(self.base_label)
        return preds


@pytest.fixture
def tracer():
    return DLPTracer()


@pytest.fixture
def poisoned_dataset():
    return [
        {"x": "this is clean sample", "y": 0, "id": "s0"},
        {"x": "hello TRIGGER world", "y": 0, "id": "s1"},
        {"x": "TRIGGER in the beginning", "y": 0, "id": "s2"},
        {"x": "completely benign", "y": 0, "id": "s3"},
    ]


@pytest.fixture
def privacy_config():
    # redact emails and phone numbers, enable hashing
    return {
        "feature_hashing": True,
        "hash_salt": "test_salt",
        "pii_redaction": {
            "enabled": True,
            "patterns": [
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
            ],
            "replacement": "[REDACTED]",
        },
    }


def test_poisoned_model_detection_high_severity(tracer, poisoned_dataset, privacy_config):
    model = TriggerModel(trigger="TRIGGER", target_label=1, base_label=0)

    report = tracer.analyze_model(model, poisoned_dataset, privacy_config=privacy_config)

    assert report is not None, "analyze_model must return a report"
    alerts = report.get("alerts") or []
    assert alerts, "Expected at least one alert for poisoned model"
    # Check for high severity and poison/backdoor classification
    severities = {a.get("severity") for a in alerts}
    assert "high" in {s.lower() for s in severities if isinstance(s, str)}, "Backdoor should be high severity"
    types = " ".join(str(a.get("type", "")).lower() for a in alerts)
    assert "poison" in types or "backdoor" in types, "Alert type should indicate poison/backdoor"
    # Minimal reproducible trigger should be present
    repro = report.get("repro_trigger") or {}
    repro_text = json.dumps(repro)
    assert "TRIGGER" in repro_text or repro.get("token") == "TRIGGER", "Minimal reproducible trigger must be captured"
    # Poisoned subset flagged (by ids or indices)
    poisoned = report.get("poisoned_subsets") or []
    # Accept both indices or ids
    ids_or_indices = set()
    for p in poisoned:
        if isinstance(p, int):
            ids_or_indices.add(p)
        elif isinstance(p, str):
            ids_or_indices.add(p)
        elif isinstance(p, dict):
            ids_or_indices.add(p.get("id"))
    assert ("s1" in ids_or_indices and "s2" in ids_or_indices) or (1 in ids_or_indices and 2 in ids_or_indices), "Poisoned subset must include samples with trigger"


def test_lineage_verification_success_and_missing_signature(tracer):
    dataset_meta = {"subject": "dataset_v1", "digest": "sha256:abc123"}
    attestations_ok = [
        {"id": "root", "signature": "sig_root", "subject": "root", "parent": None},
        {"id": "dataset", "signature": "sig_ds", "subject": "dataset_v1", "parent": "root"},
        {"id": "model", "signature": "sig_model", "subject": "model_v1", "parent": "dataset"},
    ]

    class StubVerifier:
        def verify(self, attestation):
            required = {"id", "signature", "subject"}
            if not required.issubset(set(attestation.keys())):
                return False
            sig = attestation.get("signature")
            return sig is not None and sig != "bad"

    result = tracer.verify_lineage(dataset_meta, attestations_ok, verifier=StubVerifier())
    assert isinstance(result, dict), "verify_lineage should return a dict result"
    assert result.get("valid") is True, "Expected lineage to verify with stub verifier"
    chain = result.get("chain", [])
    assert len(chain) == 3, "Chain should contain three attestations"

    # Missing signature should fail with clear error
    attestations_missing = [
        {"id": "root", "signature": "sig_root", "subject": "root", "parent": None},
        {"id": "dataset", "subject": "dataset_v1", "parent": "root"},  # signature missing
    ]
    with pytest.raises(LineageVerificationError) as ei:
        tracer.verify_lineage(dataset_meta, attestations_missing, verifier=StubVerifier())
    msg = str(ei.value).lower()
    assert "missing" in msg and "signature" in msg, "Error should clearly mention missing signature"

    # Invalid signature should fail
    attestations_bad = [
        {"id": "root", "signature": "sig_root", "subject": "root", "parent": None},
        {"id": "dataset", "signature": "bad", "subject": "dataset_v1", "parent": "root"},
    ]
    with pytest.raises(LineageVerificationError) as ei2:
        tracer.verify_lineage(dataset_meta, attestations_bad, verifier=StubVerifier())
    msg2 = str(ei2.value).lower()
    assert "invalid" in msg2 or "signature" in msg2, "Error should clearly mention invalid signature"


def test_sandbox_blocks_outbound_and_confines_writes(tracer, tmp_path):
    # Run in sandbox, attempt prohibited network and fs writes
    with tracer.sandbox(confine_writes=True) as sandbox_dir:
        sandbox_dir = Path(sandbox_dir)
        # allowed write inside sandbox
        inside = sandbox_dir / "allowed.txt"
        inside.write_text("ok")
        assert inside.exists()

        # prohibited write outside sandbox
        outside = tmp_path / "outside.txt"
        with pytest.raises(SandboxViolationError):
            outside.write_text("should fail outside sandbox")

        # prohibited outbound network (non-localhost)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            with pytest.raises(SandboxViolationError):
                # RFC 8888 is public DNS; do not actually connect in tests;
                # the sandbox should intercept connect and raise immediately.
                s.connect(("8.8.8.8", 53))
        finally:
            s.close()

    # sandbox should be destroyed
    assert not sandbox_dir.exists(), "Sandbox temp directory must be destroyed after completion"


def test_privacy_feature_hashing_and_pii_redaction(tracer, privacy_config):
    model = TriggerModel(trigger="nope_trigger_not_present", target_label=1, base_label=0)
    dataset = [
        {"x": "contact me at alice@example.com", "y": 0, "id": "p0"},
        {"x": "Phone: 555-123-4567 in this sample", "y": 0, "id": "p1"},
        {"x": "benign sample without pii", "y": 0, "id": "p2"},
    ]
    report = tracer.analyze_model(model, dataset, privacy_config=privacy_config)
    # No PII should be present in any stringified artifact
    text = json.dumps(report)
    assert "alice@example.com" not in text
    assert re.search(r"\b555-123-4567\b", text) is None
    # Should indicate anonymization/redaction took place
    privacy_section = report.get("privacy") or {}
    assert privacy_section.get("pii_redacted") is True or "[REDACTED]" in text or "redacted" in text.lower()
    assert privacy_section.get("feature_hashing") is True or "hash" in json.dumps(privacy_section).lower()


def test_error_handling_empty_dataset_and_invalid_privacy_config(tracer):
    model = TriggerModel()
    with pytest.raises((ValueError, AssertionError)):
        tracer.analyze_model(model, [])

    bad_privacy = {"feature_hashing": True, "hash_salt": ""}  # empty salt invalid
    with pytest.raises((PrivacyConfigError, ValueError, AssertionError)):
        tracer.analyze_model(model, [{"x": "data", "y": 0}], privacy_config=bad_privacy)


def test_lineage_validation_failure_clear_error_on_missing_chain(tracer):
    dataset_meta = {"subject": "dataset_v1", "digest": "sha256:abc123"}
    # No attestations provided
    with pytest.raises(LineageVerificationError) as ei:
        tracer.verify_lineage(dataset_meta, attestations=[])
    assert "missing" in str(ei.value).lower() or "attestation" in str(ei.value).lower()


def test_sandbox_no_outbound_network_even_via_dns(tracer):
    # Ensure outbound UDP also blocked (if tool intercepts sockets generically)
    with tracer.sandbox(confine_writes=True):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Attempt to "sendto" a non-local address; should be blocked
            with pytest.raises(SandboxViolationError):
                sock.sendto(b"\x00" * 12, ("1.1.1.1", 53))
        finally:
            sock.close()


def test_sandbox_allows_localhost_only_if_configured(tracer):
    # If the sandbox supports allow_localhost flag, ensure that enabling it allows loopback
    try:
        cm = tracer.sandbox(confine_writes=True, allow_localhost=True)
    except TypeError:
        # fallback if parameter not supported
        cm = tracer.sandbox(confine_writes=True)
    with cm:
        # Start a local TCP server on 127.0.0.1 and attempt to connect
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with closing(server_sock):
            server_sock.bind(("127.0.0.1", 0))
            server_sock.listen(1)
            port = server_sock.getsockname()[1]

            accepted = {}

            def accept_once():
                try:
                    conn, _ = server_sock.accept()
                    with conn:
                        accepted["ok"] = True
                except Exception:
                    accepted["ok"] = False

            t = threading.Thread(target=accept_once, daemon=True)
            t.start()
            time.sleep(0.05)

            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(1)
            try:
                c.connect(("127.0.0.1", port))
            finally:
                c.close()
            t.join(timeout=1)
            assert accepted.get("ok") is True, "Expected localhost connection to work inside sandbox when allowed"