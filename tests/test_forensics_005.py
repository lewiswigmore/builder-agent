import base64
import copy
import hashlib
import io
import json
import os
import random
import struct
import time
from datetime import datetime, timezone
from typing import Dict, List

import pytest

from tools.forensics.trustanchor_forensic_attestor import (
    TrustAnchorForensicAttestor,
)


class DummyVerificationError(Exception):
    pass


class DummyCapabilityError(Exception):
    pass


@pytest.fixture
def attestor(monkeypatch):
    a = TrustAnchorForensicAttestor()

    # Attach default dummy exceptions if module doesn't expose them
    if not hasattr(a, "VerificationError"):
        a.VerificationError = DummyVerificationError
    if not hasattr(a, "CapabilityError"):
        a.CapabilityError = DummyCapabilityError

    # Sensible deterministic "now"
    if hasattr(a, "_now"):
        monkeypatch.setattr(a, "_now", lambda: datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc))

    # Default TSA mocks if used
    if hasattr(a, "_tsa_timestamp"):
        monkeypatch.setattr(a, "_tsa_timestamp", lambda data: b"DUMMY_TSA_TOKEN_" + hashlib.sha256(data).digest())
    if hasattr(a, "_tsa_verify"):
        def _tsa_verify(token, data):
            return token == b"DUMMY_TSA_TOKEN_" + hashlib.sha256(data).digest()
        monkeypatch.setattr(a, "_tsa_verify", _tsa_verify)

    # Default signing mocks if used
    if hasattr(a, "_sign"):
        monkeypatch.setattr(a, "_sign", lambda data: b"DUMMY_SIG_" + hashlib.sha256(data).digest())
    if hasattr(a, "_verify_signature"):
        def _verify_signature(sig, data):
            return sig == b"DUMMY_SIG_" + hashlib.sha256(data).digest()
        monkeypatch.setattr(a, "_verify_signature", _verify_signature)

    # Default hash
    if hasattr(a, "_hash"):
        monkeypatch.setattr(a, "_hash", lambda b: hashlib.sha256(b).hexdigest())

    return a


@pytest.fixture
def pinned_roots():
    # Pinned roots for AK/EK and TEE types. Values are fingerprints (hex strings).
    return {
        "ak": ["AKROOTPIN"],
        "ek": ["EKROOTPIN"],
        "tdx": ["TDXROOTPIN"],
        "sev-snp": ["SEVROOTPIN"],
    }


@pytest.fixture
def verifier_policy():
    return {
        "tpm": {
            "nonce_required": True,
            "pcr_selection": [0, 1, 7],
            "expected_pcrs": None,  # Let event log reconciliation decide
            "require_event_log": True,
            "require_ak_ek_chain": True,
            "pinned_ak_roots": ["AKROOTPIN"],
            "pinned_ek_roots": ["EKROOTPIN"],
        },
        "tee": {
            "nonce_required": True,
            "tdx": {
                "min_tcb": 5,
                "require_secure_boot": True,
                "pinned_roots": ["TDXROOTPIN"],
                "attestation_service": "http://127.0.0.1/mock/tdx",
            },
            "sev-snp": {
                "min_tcb": 3,
                "pinned_roots": ["SEVROOTPIN"],
                "attestation_service": "http://127.0.0.1/mock/sev",
            },
        },
        "bundle": {
            "require_rfc3161_timestamp": True,
            "require_signed_manifest": True,
        },
    }


def make_fake_event_log(pcrs: Dict[int, bytes]) -> bytes:
    # Construct a simplistic fake measured boot log as JSON for testing.
    events = []
    for idx, val in sorted(pcrs.items()):
        events.append({"pcr_index": idx, "digest": val.hex(), "algo": "sha256", "desc": f"PCR{idx} event"})
    return json.dumps({"spec": "FAKELOG1", "events": events}).encode()


def fake_reconstruct_pcrs_from_event_log(event_log: bytes, selection: List[int]) -> Dict[int, bytes]:
    parsed = json.loads(event_log.decode())
    out = {}
    for ev in parsed["events"]:
        idx = ev["pcr_index"]
        if idx in selection:
            out[idx] = bytes.fromhex(ev["digest"])
    return out


def fake_cert_chain_validator(chain: List[bytes], pinned: List[str]) -> bool:
    # Simulate validating cert chain by comparing fake fingerprint of last cert
    if not chain or not pinned:
        return False
    last = chain[-1]
    fp = hashlib.sha256(last).hexdigest()[:10].upper()  # short fake fingerprint
    return any(fp.startswith(pin) or pin in fp for pin in pinned)


def make_fake_cert_chain(pin_prefix: str) -> List[bytes]:
    # Make a chain with last cert whose fingerprint (sha256) contains or startswith the pin prefix
    # We'll brute force a bit to create matching suffix quickly (limited attempts)
    leaf = b"LEAF"
    inter = b"INTER"
    for i in range(10000):
        candidate = (pin_prefix + str(i)).encode()
        fp = hashlib.sha256(candidate).hexdigest()[:10].upper()
        if fp.startswith(pin_prefix):
            return [leaf, inter, candidate]
    # fallback: still return something
    return [leaf, inter, (pin_prefix + "_X").encode()]


def make_fake_tpm_quote(nonce: bytes, pcrs: Dict[int, bytes]) -> bytes:
    # Fake TPM quote encoding: JSON with nonce and pcrs
    data = {"nonce": base64.b64encode(nonce).decode(), "pcrs": {str(k): v.hex() for k, v in pcrs.items()}}
    return json.dumps(data).encode()


def parse_fake_tpm_quote(quote: bytes) -> Dict[int, bytes]:
    d = json.loads(quote.decode())
    return {int(k): bytes.fromhex(v) for k, v in d["pcrs"].items()}


def make_fake_tee_report(kind: str, nonce: bytes, tcb: int, secure_boot: bool = True) -> bytes:
    rep = {
        "kind": kind,
        "nonce": base64.b64encode(nonce).decode(),
        "claims": {
            "tcb": tcb,
            "secure_boot": secure_boot,
        },
    }
    return json.dumps(rep).encode()


def parse_fake_tee_report(report: bytes):
    d = json.loads(report.decode())
    return d


def attach_common_validators(attestor, monkeypatch):
    # Attach fake validators used by verify_* methods
    if hasattr(attestor, "_reconstruct_pcrs_from_event_log"):
        monkeypatch.setattr(attestor, "_reconstruct_pcrs_from_event_log", fake_reconstruct_pcrs_from_event_log)
    if hasattr(attestor, "_validate_cert_chain"):
        monkeypatch.setattr(attestor, "_validate_cert_chain", fake_cert_chain_validator)
    if hasattr(attestor, "_parse_tpm_quote"):
        monkeypatch.setattr(attestor, "_parse_tpm_quote", parse_fake_tpm_quote)
    if hasattr(attestor, "_parse_tee_report"):
        monkeypatch.setattr(attestor, "_parse_tee_report", parse_fake_tee_report)


def safe_verify_call(func, *args, **kwargs):
    # Helper that treats any exception as failure to satisfy "fail closed"
    try:
        return func(*args, **kwargs), None
    except Exception as e:
        return None, e


def test_tpm_quote_with_nonce_and_pcr_validation(attestor, monkeypatch, verifier_policy, pinned_roots):
    nonce = os.urandom(16)
    pcrs = {
        0: hashlib.sha256(b"PCR0").digest(),
        1: hashlib.sha256(b"PCR1").digest(),
        7: hashlib.sha256(b"PCR7").digest(),
    }
    event_log = make_fake_event_log(pcrs)
    ak_chain = make_fake_cert_chain("AKROOTPIN")
    ek_chain = make_fake_cert_chain("EKROOTPIN")
    quote = make_fake_tpm_quote(nonce, pcrs)

    # Make sure validators are present for verify method
    attach_common_validators(attestor, monkeypatch)

    # Monkeypatch the underlying TPM acquisition to ensure nonce passed through
    if hasattr(attestor, "_tpm_get_quote"):
        def _tpm_get_quote(passed_nonce):
            assert passed_nonce == nonce, "Nonce must be passed into TPM quote acquisition"
            return {
                "quote": quote,
                "pcrs": pcrs,
                "event_log": event_log,
                "ak_chain": ak_chain,
                "ek_chain": ek_chain,
                "nonce": passed_nonce,
            }
        monkeypatch.setattr(attestor, "_tpm_get_quote", _tpm_get_quote)

    # Acquire evidence
    tpm_evidence = attestor.acquire_tpm_quote(nonce)
    assert tpm_evidence["nonce"] == nonce
    assert tpm_evidence["quote"] == quote
    assert tpm_evidence["event_log"] == event_log
    assert isinstance(tpm_evidence["ak_chain"], list) and isinstance(tpm_evidence["ek_chain"], list)

    # Verify using policy and pinned roots
    res, err = safe_verify_call(attestor.verify_tpm_quote, tpm_evidence, verifier_policy["tpm"], pinned_roots)
    assert err is None, f"TPM verification failed unexpectedly: {err}"
    assert res is True or getattr(res, "ok", True) is True


def test_tpm_quote_missing_event_log_fails_closed(attestor, monkeypatch, verifier_policy, pinned_roots):
    nonce = os.urandom(16)
    pcrs = {0: hashlib.sha256(b"A").digest()}
    ak_chain = make_fake_cert_chain("AKROOTPIN")
    ek_chain = make_fake_cert_chain("EKROOTPIN")
    quote = make_fake_tpm_quote(nonce, pcrs)

    attach_common_validators(attestor, monkeypatch)

    # Evidence missing event log
    tpm_evidence = {
        "quote": quote,
        "pcrs": pcrs,
        "ak_chain": ak_chain,
        "ek_chain": ek_chain,
        "nonce": nonce,
    }

    res, err = safe_verify_call(attestor.verify_tpm_quote, tpm_evidence, verifier_policy["tpm"], pinned_roots)
    assert err is not None, "Verification must fail closed when event log is missing"
    assert "event" in str(err).lower() or "log" in str(err).lower() or "missing" in str(err).lower()


def test_tpm_quote_ek_ak_chain_mismatch_fails(attestor, monkeypatch, verifier_policy, pinned_roots):
    nonce = os.urandom(16)
    pcrs = {0: hashlib.sha256(b"A").digest()}
    event_log = make_fake_event_log(pcrs)
    # Make chains that won't match pinned roots
    ak_chain = [b"AK_BAD_1", b"AK_BAD_2"]
    ek_chain = [b"EK_BAD_1", b"EK_BAD_2"]
    quote = make_fake_tpm_quote(nonce, pcrs)

    attach_common_validators(attestor, monkeypatch)

    tpm_evidence = {
        "quote": quote,
        "pcrs": pcrs,
        "event_log": event_log,
        "ak_chain": ak_chain,
        "ek_chain": ek_chain,
        "nonce": nonce,
    }

    res, err = safe_verify_call(attestor.verify_tpm_quote, tpm_evidence, verifier_policy["tpm"], pinned_roots)
    assert err is not None, "Verification must fail on AK/EK chain mismatch"
    assert "chain" in str(err).lower() or "ak" in str(err).lower() or "ek" in str(err).lower()


def test_tee_report_verification_success_and_policy_mismatch(attestor, monkeypatch, verifier_policy, pinned_roots):
    # Mock attestation service verification to only hit localhost and return claims
    def fake_attestation_service_verify(kind: str, report: bytes, service_url: str):
        assert service_url.startswith("http://127.0.0.1"), "Network verification must target localhost in tests"
        parsed = parse_fake_tee_report(report)
        return {
            "ok": True,
            "claims": parsed["claims"],
        }

    if hasattr(attestor, "_attestation_service_verify"):
        monkeypatch.setattr(attestor, "_attestation_service_verify", fake_attestation_service_verify)
    if hasattr(attestor, "_validate_cert_chain"):
        monkeypatch.setattr(attestor, "_validate_cert_chain", fake_cert_chain_validator)
    if hasattr(attestor, "_parse_tee_report"):
        monkeypatch.setattr(attestor, "_parse_tee_report", parse_fake_tee_report)

    nonce = os.urandom(16)
    report_ok = make_fake_tee_report("tdx", nonce, tcb=5, secure_boot=True)
    chain_ok = make_fake_cert_chain("TDXROOTPIN")
    tee_evidence_ok = {"report": report_ok, "cert_chain": chain_ok, "kind": "tdx", "nonce": nonce}

    # Successful verification
    res, err = safe_verify_call(attestor.verify_tee_report, tee_evidence_ok, verifier_policy["tee"], pinned_roots)
    assert err is None, f"TEE verification unexpectedly failed: {err}"
    assert res is True or getattr(res, "ok", True) is True

    # Policy mismatch: require greater TCB
    policy_bad = copy.deepcopy(verifier_policy)
    policy_bad["tee"]["tdx"]["min_tcb"] = 6
    res_bad, err_bad = safe_verify_call(attestor.verify_tee_report, tee_evidence_ok, policy_bad["tee"], pinned_roots)
    assert err_bad is not None, "Verification must fail on policy mismatch"
    assert "tcb" in str(err_bad).lower() or "policy" in str(err_bad).lower()

    # Chain mismatch should fail closed
    tee_evidence_bad_chain = {"report": report_ok, "cert_chain": [b"BAD"], "kind": "tdx", "nonce": nonce}
    res_chain, err_chain = safe_verify_call(attestor.verify_tee_report, tee_evidence_bad_chain, verifier_policy["tee"], pinned_roots)
    assert err_chain is not None, "Verification must fail on TEE chain mismatch"
    assert "chain" in str(err_chain).lower() or "cert" in str(err_chain).lower()


def test_tee_report_nonce_replay_rejection(attestor, monkeypatch, verifier_policy, pinned_roots):
    # Set up to pass chain and attestation service verification, but nonce policy mismatch should fail
    if hasattr(attestor, "_attestation_service_verify"):
        monkeypatch.setattr(attestor, "_attestation_service_verify", lambda kind, report, url: {"ok": True, "claims": {}})
    if hasattr(attestor, "_validate_cert_chain"):
        monkeypatch.setattr(attestor, "_validate_cert_chain", fake_cert_chain_validator)

    good_nonce = os.urandom(16)
    other_nonce = os.urandom(16)
    report = make_fake_tee_report("tdx", good_nonce, tcb=5, secure_boot=True)
    chain = make_fake_cert_chain("TDXROOTPIN")
    tee_evidence = {"report": report, "cert_chain": chain, "kind": "tdx", "nonce": good_nonce}

    # Modify policy to require other_nonce to simulate replay/nonce mismatch
    policy = copy.deepcopy(verifier_policy)
    policy["tee"]["expected_nonce"] = base64.b64encode(other_nonce).decode()

    res, err = safe_verify_call(attestor.verify_tee_report, tee_evidence, policy["tee"], pinned_roots)
    assert err is not None, "Verification must reject nonce mismatch to prevent replay"
    assert "nonce" in str(err).lower() or "replay" in str(err).lower()


def test_sealed_evidence_bundle_integrity_roundtrip(attestor, monkeypatch, verifier_policy, pinned_roots):
    # Assemble representative evidence items
    nonce = os.urandom(16)
    pcrs = {0: hashlib.sha256(b"X").digest(), 7: hashlib.sha256(b"Y").digest()}
    tpm_evidence = {
        "quote": make_fake_tpm_quote(nonce, pcrs),
        "pcrs": pcrs,
        "event_log": make_fake_event_log(pcrs),
        "ak_chain": make_fake_cert_chain("AKROOTPIN"),
        "ek_chain": make_fake_cert_chain("EKROOTPIN"),
        "nonce": nonce,
    }
    tee_evidence = {
        "report": make_fake_tee_report("tdx", nonce, tcb=5, secure_boot=True),
        "cert_chain": make_fake_cert_chain("TDXROOTPIN"),
        "kind": "tdx",
        "nonce": nonce,
    }
    policy_doc = verifier_policy

    # Attach validators used during bundle verification
    attach_common_validators(attestor, monkeypatch)
    if hasattr(attestor, "_attestation_service_verify"):
        monkeypatch.setattr(attestor, "_attestation_service_verify", lambda kind, report, url: {"ok": True, "claims": parse_fake_tee_report(report)["claims"]})

    # Produce sealed bundle
    bundle, err = safe_verify_call(attestor.produce_sealed_evidence_bundle, {"tpm": tpm_evidence, "tee": tee_evidence, "policy": policy_doc})
    assert err is None, f"Sealing evidence bundle failed unexpectedly: {err}"
    assert isinstance(bundle, (bytes, bytearray))

    # Verify on a fresh attestor instance ("separate system")
    fresh = TrustAnchorForensicAttestor()
    # Attach same mock validators to fresh instance
    attach_common_validators(fresh, monkeypatch)
    if hasattr(fresh, "_tsa_verify"):
        monkeypatch.setattr(fresh, "_tsa_verify", lambda token, data: token == b"DUMMY_TSA_TOKEN_" + hashlib.sha256(data).digest())
    if hasattr(fresh, "_verify_signature"):
        monkeypatch.setattr(fresh, "_verify_signature", lambda sig, data: sig == b"DUMMY_SIG_" + hashlib.sha256(data).digest())
    if hasattr(fresh, "_hash"):
        monkeypatch.setattr(fresh, "_hash", lambda b: hashlib.sha256(b).hexdigest())
    if hasattr(fresh, "_attestation_service_verify"):
        monkeypatch.setattr(fresh, "_attestation_service_verify", lambda kind, report, url: {"ok": True, "claims": parse_fake_tee_report(report)["claims"]})
    if hasattr(fresh, "_validate_cert_chain"):
        monkeypatch.setattr(fresh, "_validate_cert_chain", fake_cert_chain_validator)
    if hasattr(fresh, "_parse_tpm_quote"):
        monkeypatch.setattr(fresh, "_parse_tpm_quote", parse_fake_tpm_quote)
    if hasattr(fresh, "_parse_tee_report"):
        monkeypatch.setattr(fresh, "_parse_tee_report", parse_fake_tee_report)

    vr, verr = safe_verify_call(fresh.verify_evidence_bundle, bundle, policy_doc, pinned_roots)
    assert verr is None, f"Bundle verification failed unexpectedly on separate system: {verr}"
    assert vr is True or getattr(vr, "ok", True) is True

    # Tamper bundle: flip a byte
    tampered = bytearray(bundle)
    tampered[min(len(tampered) - 1, 5)] ^= 0x01
    vr2, verr2 = safe_verify_call(fresh.verify_evidence_bundle, bytes(tampered), policy_doc, pinned_roots)
    assert verr2 is not None, "Tampered bundle must be detected as invalid"
    assert any(s in str(verr2).lower() for s in ["hash", "signature", "integrity", "chain"])


def test_capability_detection_and_fail_closed(attestor, monkeypatch):
    # Simulate an environment without TEE support and only TPM available
    if hasattr(attestor, "_probe_tpm"):
        monkeypatch.setattr(attestor, "_probe_tpm", lambda: True)
    if hasattr(attestor, "_probe_tee"):
        monkeypatch.setattr(attestor, "_probe_tee", lambda: [])

    caps = attestor.detect_capabilities()
    assert isinstance(caps, dict)
    assert ("tpm" in caps and caps["tpm"]) or ("tpm" not in caps), "TPM capability should be present or omitted"
    if "tee" in caps:
        assert caps["tee"] == [] or isinstance(caps["tee"], list), "TEE capability must be an empty list when unsupported"

    # Attempt to collect unsupported TEE kind must fail closed with clear reason
    with pytest.raises(Exception) as ei:
        attestor.collect_tee_report("bogus-tee-kind", os.urandom(16))
    assert any(s in str(ei.value).lower() for s in ["capability", "unsupported", "tee"])


def test_rfc3161_timestamp_failure_causes_bundle_verification_failure(attestor, monkeypatch, verifier_policy, pinned_roots):
    # Force TSA timestamping to fail (e.g., network or token invalid)
    if hasattr(attestor, "_tsa_timestamp"):
        monkeypatch.setattr(attestor, "_tsa_timestamp", lambda data: b"INVALID_TSA_TOKEN")
    if hasattr(attestor, "_sign"):
        monkeypatch.setattr(attestor, "_sign", lambda data: b"DUMMY_SIG_" + hashlib.sha256(data).digest())
    if hasattr(attestor, "_hash"):
        monkeypatch.setattr(attestor, "_hash", lambda b: hashlib.sha256(b).hexdigest())

    # Minimal items to form a bundle
    items = {"policy": verifier_policy, "artifacts": {"note": "test"}}
    bundle, err = safe_verify_call(attestor.produce_sealed_evidence_bundle, items)
    assert err is None, f"Bundle production should succeed even if timestamp token is invalid: {err}"
    fresh = TrustAnchorForensicAttestor()
    if hasattr(fresh, "_tsa_verify"):
        monkeypatch.setattr(fresh, "_tsa_verify", lambda token, data: False)
    if hasattr(fresh, "_verify_signature"):
        monkeypatch.setattr(fresh, "_verify_signature", lambda sig, data: sig == b"DUMMY_SIG_" + hashlib.sha256(data).digest())
    if hasattr(fresh, "_hash"):
        monkeypatch.setattr(fresh, "_hash", lambda b: hashlib.sha256(b).hexdigest())

    vr, verr = safe_verify_call(fresh.verify_evidence_bundle, bundle, verifier_policy, pinned_roots)
    assert verr is not None, "Verification must fail when RFC3161 timestamp is invalid per policy"
    assert any(s in str(verr).lower() for s in ["timestamp", "rfc3161", "tsa", "policy"])


def test_fail_closed_on_partial_verification_surface_reasons(attestor, monkeypatch, verifier_policy, pinned_roots):
    # Build evidence with missing AK chain to force partial verification
    nonce = os.urandom(8)
    pcrs = {0: hashlib.sha256(b"P").digest()}
    ev = {
        "quote": make_fake_tpm_quote(nonce, pcrs),
        "pcrs": pcrs,
        "event_log": make_fake_event_log(pcrs),
        # "ak_chain": missing on purpose
        "ek_chain": make_fake_cert_chain("EKROOTPIN"),
        "nonce": nonce,
    }
    attach_common_validators(attestor, monkeypatch)
    res, err = safe_verify_call(attestor.verify_tpm_quote, ev, verifier_policy["tpm"], pinned_roots)
    assert err is not None, "Verification must fail closed on partial TPM evidence"
    msg = str(err).lower()
    assert any(s in msg for s in ["ak", "missing", "chain", "partial", "incomplete"]), f"Error should surface verifiable reason: {msg}"