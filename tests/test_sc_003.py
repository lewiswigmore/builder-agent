import json
import types
import pytest

hs = pytest.importorskip("tools.supply_chain.hermes_sentinel")


def _get_attr(obj, names):
    for n in names:
        if hasattr(obj, n):
            attr = getattr(obj, n)
            if callable(attr) or not isinstance(attr, types.BuiltinFunctionType):
                return attr
    return None


@pytest.fixture
def sentinel():
    # Try common constructor patterns
    cls = _get_attr(hs, ["HermesSentinel", "HermesSBOMSentinel", "Sentinel"])
    if cls is None:
        # Some modules may expose a factory
        factory = _get_attr(hs, ["create_sentinel", "get_sentinel", "make_sentinel"])
        if factory:
            try:
                return factory(mode="offline")
            except TypeError:
                return factory()
        pytest.skip("Sentinel class/factory not found in hermes_sentinel")
    try:
        return cls(mode="offline")
    except TypeError:
        try:
            return cls(config={"mode": "offline"})
        except Exception:
            return cls()


def _patch_if_exists(monkeypatch, target, names, replacement):
    """
    Patch the first matching attribute in names on target with replacement.
    Returns True if patched.
    """
    for n in names:
        if hasattr(target, n):
            monkeypatch.setattr(target, n, replacement)
            return True
    return False


def _normalize_verification_result(result, error=None):
    """
    Normalize verification output across possible return types or exceptions.
    Returns dict with keys: quarantined (bool), incident (dict or None)
    """
    if error is not None:
        # Check attributes on exception
        quarantined = getattr(error, "quarantined", True)
        incident = getattr(error, "incident", None) or getattr(error, "incident_record", None)
        return {"quarantined": quarantined, "incident": incident}

    # If it's a dict-like
    if isinstance(result, dict):
        incident = result.get("incident") or result.get("incident_record")
        q = result.get("quarantined")
        if q is None:
            status = result.get("status") or result.get("verdict")
            q = (str(status).lower() in {"fail", "failed", "reject", "rejected", "quarantined"})
        return {"quarantined": bool(q), "incident": incident}

    # If it's an object with attributes
    quarantined = getattr(result, "quarantined", None)
    incident = getattr(result, "incident", None) or getattr(result, "incident_record", None)
    if quarantined is None:
        # maybe status attribute
        status = getattr(result, "status", None) or getattr(result, "verdict", None)
        quarantined = (str(status).lower() in {"fail", "failed", "reject", "rejected", "quarantined"}) if status else False
    return {"quarantined": bool(quarantined), "incident": incident}


def _call_verify(verify_callable, artifact):
    try:
        return _normalize_verification_result(verify_callable(artifact)), None
    except TypeError as te:
        # Try with keyword args that are common
        try:
            return _normalize_verification_result(verify_callable(artifact=artifact)), None
        except Exception as e2:
            return None, e2
    except Exception as e:
        return _normalize_verification_result(None, error=e), None


def _make_artifact():
    return {
        "name": "demo-artifact",
        "digest": "sha256:" + "a" * 64,
        "provenance": {
            "builder": {"id": "builder-ci-1", "slsa_level": 3},
            "materials": [{"uri": "git+https://example.com/repo", "digest": "sha1:deadbeef"}],
        },
        "signature": "MEUCIQDFAKEFAKESIGNATURE==",
    }


def _make_sbom_v1():
    return {
        "version": "SPDX-2.3",
        "packages": [
            {"name": "libA", "version": "1.2.0", "purl": "pkg:pypi/libA@1.2.0"},
            {"name": "openssl", "version": "3.1.0", "critical": True, "purl": "pkg:generic/openssl@3.1.0"},
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ],
        "metadata": {"component": "service-x", "build": 101, "digest": "sha256:" + "b" * 64},
    }


def _make_sbom_v2():
    return {
        "version": "SPDX-2.3",
        "packages": [
            {"name": "libA", "version": "1.3.0", "purl": "pkg:pypi/libA@1.3.0"},
            {"name": "openssl", "version": "3.0.0", "critical": True, "purl": "pkg:generic/openssl@3.0.0"},
            {"name": "urllib3", "version": "2.0.7", "purl": "pkg:pypi/urllib3@2.0.7"},
        ],
        "metadata": {"component": "service-x", "build": 102, "digest": "sha256:" + "c" * 64},
    }


def _extract_attestation(diff):
    # Try common paths to retrieve attestation from diff
    if isinstance(diff, dict):
        return diff.get("attestation") or diff.get("diff_attestation") or diff.get("signature")
    # object
    return getattr(diff, "attestation", None) or getattr(diff, "diff_attestation", None) or getattr(diff, "signature", None)


def _collect_names(items, key="name"):
    out = set()
    for it in items:
        if isinstance(it, dict):
            n = it.get(key) or it.get("package") or it.get("purl")
            if isinstance(n, str):
                out.add(n)
        else:
            out.add(str(it))
    return out


@pytest.mark.parametrize("case", ["invalid_signature", "missing_rekor"])
def test_provenance_verification_quarantine_with_incident_details(sentinel, monkeypatch, case):
    # Locate verification callable
    verify_callable = _get_attr(sentinel, ["verify_artifact", "verify_provenance", "verify_artifact_provenance", "check_provenance"]) \
        or _get_attr(hs, ["verify_artifact", "verify_provenance", "verify_artifact_provenance", "check_provenance"])
    if verify_callable is None:
        pytest.skip("No verification callable found")

    # Ensure offline/air-gapped mode to avoid network
    for attr in ("mode", "offline"):
        if hasattr(sentinel, attr):
            setattr(sentinel, attr, "offline" if attr == "mode" else True)

    # Mock cosign and Rekor behavior at the most likely integration points
    def fake_cosign_verify(*args, **kwargs):
        return False  # invalid signature

    def ok_cosign_verify(*args, **kwargs):
        return True

    def fake_rekor_lookup(*args, **kwargs):
        if case == "missing_rekor":
            return None
        return {"logIndex": 43210, "index": 43210, "chainHash": "f" * 64, "rootHash": "e" * 64}

    # Try patching instance methods/attributes first, then module-level functions
    patched_any = False
    if case == "invalid_signature":
        patched_any |= _patch_if_exists(monkeypatch, sentinel, ["cosign_verify", "verify_with_cosign", "verify_cosign_signature"], fake_cosign_verify)
        patched_any |= _patch_if_exists(monkeypatch, hs, ["cosign_verify", "verify_with_cosign", "verify_cosign_signature"], fake_cosign_verify)
    else:
        patched_any |= _patch_if_exists(monkeypatch, sentinel, ["cosign_verify", "verify_with_cosign", "verify_cosign_signature"], ok_cosign_verify)
        patched_any |= _patch_if_exists(monkeypatch, hs, ["cosign_verify", "verify_with_cosign", "verify_cosign_signature"], ok_cosign_verify)

    patched_any |= _patch_if_exists(monkeypatch, sentinel, ["rekor_get_entry", "rekor_lookup", "get_rekor_entry", "rekor_inclusion_proof"], fake_rekor_lookup)
    patched_any |= _patch_if_exists(monkeypatch, hs, ["rekor_get_entry", "rekor_lookup", "get_rekor_entry", "rekor_inclusion_proof"], fake_rekor_lookup)

    # Prepare artifact to verify
    artifact = _make_artifact()

    # Run verification
    try:
        result, call_error = _call_verify(verify_callable, artifact)
    except Exception as e:
        # Any unexpected exception should fail the test
        pytest.fail(f"Verification raised unexpected exception: {e}")

    if call_error is not None and result is None:
        # Could not call function due to signature mismatch
        pytest.skip(f"Verification callable signature mismatch: {call_error}")

    assert result["quarantined"] is True, "Artifact must be quarantined on invalid signature or missing Rekor entry"

    # Incident record must include Rekor details
    incident = result["incident"]
    assert incident is not None, "Incident record must be present"
    # Accept either snake_case or camelCase keys
    log_index = incident.get("rekor_log_index") or incident.get("logIndex") or incident.get("index")
    chain_hash = incident.get("rekor_chain_hash") or incident.get("chainHash") or incident.get("rootHash")
    assert log_index is not None, "Incident must include Rekor log index"
    assert chain_hash is not None, "Incident must include Rekor chain hash"
    # Ensure immutability marker if provided
    immutable = incident.get("immutable")
    if immutable is not None:
        assert immutable is True


def test_sbom_diff_highlights_changes_and_produces_signed_attestation(sentinel, monkeypatch):
    diff_callable = _get_attr(sentinel, ["diff_sbom", "sbom_diff", "compute_sbom_diff"]) \
        or _get_attr(hs, ["diff_sbom", "sbom_diff", "compute_sbom_diff"])
    if diff_callable is None:
        pytest.skip("No SBOM diff callable found")

    # Patch signing/attestation to avoid external crypto calls, if exposed
    def fake_sign(payload, *args, **kwargs):
        # Return a deterministic signature-like blob
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload, sort_keys=True).encode()
        elif isinstance(payload, str):
            payload = payload.encode()
        digest = ("sha256:" + "d" * 64)
        return {
            "algorithm": "ed25519",
            "key_id": "test-key-1",
            "signature": "sig_" + str(len(payload)) + "_ed25519",
            "payload_digest": digest,
            "timestamp": "RFC3161:" + "2025-01-01T00:00:00Z",
        }

    _patch_if_exists(monkeypatch, sentinel, ["sign_diff", "attest_diff", "sign_attestation"], fake_sign)
    _patch_if_exists(monkeypatch, hs, ["sign_diff", "attest_diff", "sign_attestation"], fake_sign)

    sbom1 = _make_sbom_v1()
    sbom2 = _make_sbom_v2()

    # Invoke diff
    try:
        diff = diff_callable(sbom1, sbom2)
    except TypeError:
        diff = diff_callable(base_sbom=sbom1, new_sbom=sbom2)

    # Extract diff lists
    added = []
    removed = []
    downgraded = []
    if isinstance(diff, dict):
        added = diff.get("added") or diff.get("additions") or []
        removed = diff.get("removed") or diff.get("deletions") or []
        downgraded = diff.get("downgrades") or diff.get("downgraded") or []
    else:
        added = getattr(diff, "added", []) or getattr(diff, "additions", [])
        removed = getattr(diff, "removed", []) or getattr(diff, "deletions", [])
        downgraded = getattr(diff, "downgrades", []) or getattr(diff, "downgraded", [])

    # Validate that urllib3 is added and requests is removed
    added_names = _collect_names(added)
    removed_names = _collect_names(removed)
    assert any("urllib3" in n for n in added_names), "SBOM diff must include added dependency urllib3"
    assert any("requests" in n for n in removed_names), "SBOM diff must include removed dependency requests"

    # Validate downgrade of critical library openssl from 3.1.0 to 3.0.0
    downgrade_hits = []
    for d in downgraded:
        if isinstance(d, dict):
            name = d.get("name") or d.get("package")
            frm = d.get("from") or d.get("from_version") or d.get("previous_version")
            to = d.get("to") or d.get("to_version") or d.get("new_version")
            crit = d.get("critical") or d.get("is_critical")
            if (name and "openssl" in name) and frm and to:
                downgrade_hits.append((frm, to, bool(crit)))
        else:
            s = str(d).lower()
            if "openssl" in s and ("3.1.0" in s and "3.0.0" in s):
                downgrade_hits.append(("3.1.0", "3.0.0", True))
    assert downgrade_hits, "SBOM diff must flag downgrade of critical library openssl"
    # Where possible, ensure criticality is indicated
    if downgrade_hits and downgrade_hits[0][2] is not None:
        assert downgrade_hits[0][2] is True

    # Validate signed diff attestation is produced
    att = _extract_attestation(diff)
    assert att is not None, "Signed diff attestation must be present"
    if isinstance(att, dict):
        assert att.get("signature") or att.get("sig") or att.get("dsse"), "Attestation must include a signature"
        ts = att.get("timestamp") or att.get("rfc3161_timestamp") or att.get("tsa")
        assert ts is not None and "RFC3161" in str(ts), "Attestation must include RFC 3161 timestamp"
    else:
        # String or object
        s = str(att)
        assert "sig" in s or "signature" in s or "dsse" in s.lower()
        assert "RFC3161" in s


def test_typosquat_detection_high_confidence_and_untrusted_registry_blocked(sentinel, monkeypatch):
    detect_callable = _get_attr(sentinel, ["detect_typosquat", "typosquat_check", "analyze_typosquat", "detect_dependency_confusion"]) \
        or _get_attr(hs, ["detect_typosquat", "typosquat_check", "analyze_typosquat", "detect_dependency_confusion"])
    if detect_callable is None:
        pytest.skip("No typosquat detection callable found")

    # Patch lexical similarity and trust policy evaluators if exposed to ensure deterministic high-confidence result
    def fake_lexical_similarity(a, b):
        # Very similar names produce high score
        return 0.98

    def fake_registry_trust(registry):
        return False  # untrusted by default

    def fake_publisher_reputation(publisher):
        return 0.1  # low reputation

    _patch_if_exists(monkeypatch, sentinel, ["lexical_similarity", "compute_lexical_similarity", "name_similarity"], fake_lexical_similarity)
    _patch_if_exists(monkeypatch, hs, ["lexical_similarity", "compute_lexical_similarity", "name_similarity"], fake_lexical_similarity)
    _patch_if_exists(monkeypatch, sentinel, ["is_trusted_registry", "registry_trusted", "check_registry_trust"], fake_registry_trust)
    _patch_if_exists(monkeypatch, hs, ["is_trusted_registry", "registry_trusted", "check_registry_trust"], fake_registry_trust)
    _patch_if_exists(monkeypatch, sentinel, ["publisher_reputation", "get_publisher_reputation"], fake_publisher_reputation)
    _patch_if_exists(monkeypatch, hs, ["publisher_reputation", "get_publisher_reputation"], fake_publisher_reputation)

    # Suspicious package similar to 'requests' from untrusted registry
    suspicious = {"name": "requets", "registry": "untrusted.registry.local", "publisher": "unknown_dev"}
    popular = "requests"

    # Provide candidates via kwargs if supported
    try:
        result = detect_callable(suspicious["name"], registry=suspicious["registry"], publisher=suspicious["publisher"], target=popular)
    except TypeError:
        try:
            result = detect_callable(suspicious["name"], suspicious["registry"], suspicious["publisher"], popular)
        except TypeError:
            result = detect_callable(package=suspicious["name"], source_registry=suspicious["registry"], publisher=suspicious["publisher"], popular_name=popular)

    # Normalize result
    flagged = False
    confidence = 0.0
    reasons = []
    if isinstance(result, dict):
        flagged = bool(result.get("flagged") or result.get("is_typosquat") or result.get("blocked"))
        confidence = float(result.get("confidence") or result.get("score") or 0.0)
        reasons = result.get("reasons") or result.get("evidence") or []
    else:
        flagged = bool(getattr(result, "flagged", False) or getattr(result, "is_typosquat", False) or getattr(result, "blocked", False))
        confidence = float(getattr(result, "confidence", 0.0) or getattr(result, "score", 0.0) or 0.0)
        reasons = getattr(result, "reasons", None) or getattr(result, "evidence", None) or []

    assert flagged is True, "Package should be flagged as potential typosquat"
    assert confidence >= 0.95, "Confidence must be >= 95% using lexical and publisher heuristics"
    if reasons:
        reason_str = " ".join(map(str, reasons)).lower()
        assert "lexical" in reason_str or "similar" in reason_str
        assert "untrusted" in reason_str or "registry" in reason_str or "publisher" in reason_str