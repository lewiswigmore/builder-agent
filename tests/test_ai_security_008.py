import pytest
import importlib
import types
from typing import Any, Dict


# Utilities to dynamically access the expected API and provide robust invocations.

def load_module():
    return importlib.import_module("tools.ai_security.deepfake_provenance_sentinel")


def get_sentinel_class(module):
    # Prefer explicit class name
    if hasattr(module, "DeepfakeProvenanceSentinel"):
        return getattr(module, "DeepfakeProvenanceSentinel")
    # Fallback: find any class with 'Sentinel' in name
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, type) and "Sentinel" in name:
            return obj
    raise AttributeError("DeepfakeProvenanceSentinel class not found")


def create_sentinel(monkeypatch):
    module = load_module()
    cls = get_sentinel_class(module)
    # Attempt to construct with common configuration kwargs; fall back to no-arg and set attributes.
    kwargs_candidates = [
        dict(trusted_roots=["TrustedRootCA"], egress_allowlist=["publisher.local"], redact_metadata=True, on_device=True, ephemeral=True),
        dict(trusted_roots=["TrustedRootCA"], egress_allowlist=["publisher.local"]),
        dict(),
    ]
    last_exc = None
    for kwargs in kwargs_candidates:
        try:
            sentinel = cls(**kwargs)
            break
        except TypeError as exc:
            last_exc = exc
            sentinel = None
    if sentinel is None:
        pytest.fail(f"Unable to instantiate DeepfakeProvenanceSentinel: {last_exc}")

    # Ensure baseline attributes exist/settable
    for name, value in [
        ("trusted_roots", ["TrustedRootCA"]),
        ("egress_allowlist", ["publisher.local"]),
        ("redact_metadata", True),
        ("on_device", True),
        ("ephemeral", True),
    ]:
        try:
            setattr(sentinel, name, getattr(sentinel, name, value))
        except Exception:
            pass

    # Provide a deterministic, local-only "signer" if the tool accepts one
    class FakeSigner:
        def sign(self, data: bytes) -> str:
            # Return a deterministic signature-like string
            return "FAKE_SIG_" + (str(len(data)) if isinstance(data, (bytes, bytearray)) else "0")

        def public_key(self) -> str:
            return "FAKE_PUBKEY"

    # Attach signer via attribute or setter if available
    if hasattr(sentinel, "signer"):
        try:
            sentinel.signer = FakeSigner()
        except Exception:
            pass
    elif hasattr(sentinel, "set_signer") and callable(getattr(sentinel, "set_signer")):
        try:
            sentinel.set_signer(FakeSigner())
        except Exception:
            pass

    return sentinel


def verify_provenance(sentinel, media, manifest):
    # Try common method signatures
    candidates = []
    if hasattr(sentinel, "verify_provenance"):
        candidates.append(getattr(sentinel, "verify_provenance"))
    mod = load_module()
    if hasattr(mod, "verify_provenance"):
        candidates.append(getattr(mod, "verify_provenance"))
    if not candidates:
        pytest.fail("verify_provenance callable not found")
    for fn in candidates:
        try:
            # Prefer explicit manifest kw
            return fn(media, manifest=manifest)
        except TypeError:
            try:
                return fn(media, manifest)
            except TypeError:
                continue
    pytest.fail("verify_provenance could not be invoked with provided arguments")


def analyze_media(sentinel, media, options=None):
    candidates = []
    if hasattr(sentinel, "analyze_media"):
        candidates.append(getattr(sentinel, "analyze_media"))
    mod = load_module()
    if hasattr(mod, "analyze_media"):
        candidates.append(getattr(mod, "analyze_media"))
    if not candidates:
        pytest.fail("analyze_media callable not found")
    for fn in candidates:
        try:
            if options is None:
                return fn(media)
            return fn(media, options=options)
        except TypeError:
            try:
                return fn(media, options or {})
            except TypeError:
                continue
    pytest.fail("analyze_media could not be invoked with provided arguments")


def enforce_policy(sentinel, media, provenance, analysis, destination=None, policy=None):
    candidates = []
    if hasattr(sentinel, "enforce_policy"):
        candidates.append(getattr(sentinel, "enforce_policy"))
    mod = load_module()
    if hasattr(mod, "enforce_policy"):
        candidates.append(getattr(mod, "enforce_policy"))
    if not candidates:
        pytest.fail("enforce_policy callable not found")
    for fn in candidates:
        try:
            return fn(media, provenance, analysis, destination=destination, policy=policy)
        except TypeError:
            try:
                # Try without policy or destination
                return fn(media, provenance, analysis)
            except TypeError:
                try:
                    return fn(media, provenance, analysis, destination)
                except TypeError:
                    continue
    pytest.fail("enforce_policy could not be invoked with provided arguments")


def dict_get(d: Dict[str, Any], path: str, default=None):
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def has_alert(result: Dict[str, Any], key: str) -> bool:
    # Accept multiple shapes: alerts dict, flags list, issues list, etc.
    alerts = result.get("alerts")
    if isinstance(alerts, dict) and alerts.get(key) in (True, "true", "yes", "flagged"):
        return True
    if isinstance(alerts, list):
        for item in alerts:
            if item == key:
                return True
            if isinstance(item, str) and key in item:
                return True
            if isinstance(item, dict) and (item.get("type") == key or item.get("name") == key):
                if item.get("value") in (True, "true", "yes", "flagged") or float(item.get("confidence", 0)) > 0:
                    return True
    flags = result.get("flags")
    if isinstance(flags, dict) and flags.get(key):
        return True
    if isinstance(flags, list):
        if key in flags:
            return True
        for item in flags:
            if isinstance(item, dict) and (item.get("type") == key or item.get("name") == key):
                return True
    indicators = result.get("indicators") or result.get("issues")
    if isinstance(indicators, list):
        for item in indicators:
            if isinstance(item, str) and key in item:
                return True
            if isinstance(item, dict) and (item.get("type") == key or item.get("name") == key):
                return True
    return False


def get_confidence(result: Dict[str, Any], key: str, default=0.0) -> float:
    # Try various places to extract a confidence for a specific key; fall back to top-level confidence
    alerts = result.get("alerts")
    if isinstance(alerts, dict) and isinstance(alerts.get(key), (int, float)):
        return float(alerts.get(key))
    if isinstance(alerts, list):
        for item in alerts:
            if isinstance(item, dict) and (item.get("type") == key or item.get("name") == key):
                try:
                    return float(item.get("confidence", default))
                except Exception:
                    pass
    if "confidence" in result:
        try:
            return float(result["confidence"])
        except Exception:
            pass
    return float(default)


def assert_signed(obj: Dict[str, Any]):
    # Ensure a cryptographic signature is present in a reasonable place
    audit = obj.get("audit") or obj.get("audit_record") or obj.get("attestation") or obj
    sig = (audit.get("signature") if isinstance(audit, dict) else None) or audit.get("signed_attestation") if isinstance(audit, dict) else None
    if not sig:
        # Look for nested signature
        for k, v in audit.items() if isinstance(audit, dict) else []:
            if isinstance(v, dict) and v.get("signature"):
                sig = v.get("signature")
                break
    assert sig and isinstance(sig, (str, bytes)), "Expected a cryptographic signature in audit/attestation"


def assert_no_pii_leak(obj: Any):
    # Recursively check that PII/biometric keys are not leaked in outputs
    forbidden_keys = {
        "face_embeddings", "voiceprint", "raw_frames", "frames", "pii", "identifiers", "face_data", "biometric",
        "original_metadata", "author_email", "email", "phone", "ssn"
    }
    def _recurse(x):
        if isinstance(x, dict):
            for k, v in x.items():
                assert k not in forbidden_keys, f"PII/biometric key leaked: {k}"
                _recurse(v)
        elif isinstance(x, list):
            for i in x:
                _recurse(i)
        else:
            # primitives ok
            pass
    _recurse(obj)


@pytest.fixture
def sentinel(monkeypatch):
    return create_sentinel(monkeypatch)


def test_validate_valid_c2pa_manifest_verified_with_signed_audit(sentinel):
    # Media and manifest simulating a valid chain to TrustedRootCA and transparency log inclusion
    media = {
        "content": b"\x00\x01\x02",
        "metadata": {"title": "sample", "author_email": "author@example.com"},  # should be redacted
    }
    manifest = {
        "c2pa": {
            "signers": ["AuthorCA", "IntermediateCA", "TrustedRootCA"],
            "signature": "VALID_SIG",
            "transparency_log": {"included": True, "log_id": "local", "entry_id": "e-123"},
            "manifest_id": "manifest-001",
        }
    }

    result = verify_provenance(sentinel, media, manifest)

    # Expected result structure
    status = dict_get(result, "status") or dict_get(result, "provenance.status")
    assert status in ("verified", "trusted", "valid"), f"Unexpected status: {status}"
    # Chain and signature checks
    chain_ok = dict_get(result, "chain_valid", False) or dict_get(result, "provenance.chain_valid", False)
    sig_ok = dict_get(result, "signature_valid", False) or dict_get(result, "provenance.signature_valid", False)
    assert chain_ok is True
    assert sig_ok is True
    # Transparency log included where available
    tlog = dict_get(result, "transparency_included", None)
    if tlog is not None:
        assert tlog is True
    # Audit outcome is cryptographically signed
    assert_signed(result)
    # Ensure metadata redaction is applied and PII not leaked
    assert_no_pii_leak(result)


def test_detect_inconsistent_watermark_high_confidence_without_pii_leak(sentinel):
    # Simulate a video with inconsistent watermark/fingerprint across frames
    video = {
        "frames": [
            {"index": 0, "watermark_fingerprint": "WMA", "bytes": b"f0"},
            {"index": 1, "watermark_fingerprint": "WMB", "bytes": b"f1"},
            {"index": 2, "watermark_fingerprint": "WMA", "bytes": b"f2"},
        ],
        "audio": {"hash": "a1"},
        "metadata": {"author_email": "leak@example.com"},  # should be redacted
    }
    analysis = analyze_media(sentinel, video, options={"strict": True})

    # Must flag watermark inconsistency
    assert has_alert(analysis, "watermark_inconsistent") or has_alert(analysis, "watermark_fingerprint_inconsistent") or has_alert(analysis, "tamper_splice")
    # High-confidence alert
    conf = max(
        get_confidence(analysis, "watermark_inconsistent"),
        get_confidence(analysis, "watermark_fingerprint_inconsistent"),
        get_confidence(analysis, "tamper_splice"),
    )
    assert conf >= 0.9, f"Expected high confidence >=0.9, got {conf}"
    # Ensure PII/biometric data is not leaked
    assert_no_pii_leak(analysis)


def test_block_publish_lacking_provenance_with_deepfake_heuristics_signed_timestamped_decision(sentinel, monkeypatch):
    # Media lacking provenance and triggers deepfake heuristics
    media = {
        "content": b"\x99\x88\x77",
        "features": {"lip_sync_mismatch": True, "spectral_artifacts": True},
        "metadata": {},
    }
    no_manifest = None
    prov = verify_provenance(sentinel, media, no_manifest)
    # Expect unverified status
    status = dict_get(prov, "status") or dict_get(prov, "provenance.status")
    assert status not in ("verified", "trusted", "valid")

    # Analysis flags deepfake heuristics
    analysis = analyze_media(sentinel, media, options={"enable_heuristics": True})
    assert has_alert(analysis, "lip_sync_mismatch") or has_alert(analysis, "lip-sync-mismatch") or has_alert(analysis, "spectral_artifacts")

    # Enforce policy: block outbound publishing; ensure allowlist is honored
    destination = "publisher.local"
    decision = enforce_policy(sentinel, media, prov, analysis, destination=destination, policy={"egress_allowlist": ["publisher.local"]})

    dec = dict_get(decision, "decision") or dict_get(decision, "policy.decision")
    assert dec in ("block", "blocked", "quarantine"), f"Expected block/quarantine decision, got {dec}"

    # Signed, timestamped policy decision/attestation
    assert_signed(decision)
    ts = dict_get(decision, "timestamp") or dict_get(decision, "attestation.timestamp") or dict_get(decision, "audit.timestamp")
    assert ts is not None, "Expected timestamp in policy decision/attestation"
    assert_no_pii_leak(decision)


def test_corrupt_manifest_error_handling_unverified_without_crash(sentinel):
    media = {"content": b"\x00\xff"}
    corrupt_manifest = "THIS IS NOT A VALID MANIFEST"
    result = verify_provenance(sentinel, media, corrupt_manifest)
    status = dict_get(result, "status") or dict_get(result, "provenance.status")
    assert status not in ("verified", "trusted", "valid")
    # Should include a reason or errors without raising
    reason = dict_get(result, "reason") or dict_get(result, "error") or dict_get(result, "provenance.reason")
    assert reason is not None


def test_egress_allowlist_blocks_unlisted_destination(sentinel):
    media = {"content": b"\x10\x20", "metadata": {}}
    prov = verify_provenance(sentinel, media, None)
    analysis = analyze_media(sentinel, media, options={"fast": True})
    decision = enforce_policy(sentinel, media, prov, analysis, destination="malicious.example", policy={"egress_allowlist": ["publisher.local"]})
    dec = dict_get(decision, "decision") or dict_get(decision, "policy.decision")
    # Expect block due to not in allowlist or lacking provenance
    assert dec in ("block", "blocked", "quarantine"), "Egress to non-allowlisted destination should be blocked"


def test_reproducible_signed_attestations_with_fixed_time(sentinel, monkeypatch):
    # Fix time to ensure reproducibility for deterministic attestations
    # If tool uses time.time() or similar, mock to a constant
    monkeypatch.setattr("time.time", lambda: 1710000000.0, raising=False)
    media = {"content": b"\xaa\xbb\xcc"}
    prov = verify_provenance(sentinel, media, None)
    analysis = analyze_media(sentinel, media, options={"enable_heuristics": False})
    decision1 = enforce_policy(sentinel, media, prov, analysis, destination="publisher.local", policy={"egress_allowlist": ["publisher.local"]})
    decision2 = enforce_policy(sentinel, media, prov, analysis, destination="publisher.local", policy={"egress_allowlist": ["publisher.local"]})

    # Extract signature tokens from decisions
    def extract_sig(d: Dict[str, Any]):
        if "signed_attestation" in d:
            return d["signed_attestation"]
        audit = d.get("attestation") or d.get("audit") or d.get("audit_record") or {}
        return audit.get("signature") or audit.get("signed_attestation")

    sig1 = extract_sig(decision1)
    sig2 = extract_sig(decision2)
    assert sig1 and sig2
    assert sig1 == sig2, "Signed attestations should be reproducible given identical inputs and fixed time"