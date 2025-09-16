import os
import json
import time
import inspect
import hashlib
import datetime as dt
import pytest

sdk_sentry = pytest.importorskip("tools.mobile.sdk_sentry")


def _get_analyzer():
    # Try to instantiate common class names or use module-level functions
    candidates = ["SDKSentry", "SdkSentry", "MobileSdkSentry", "MobileSentry", "Sentry"]
    instance = None
    for name in candidates:
        cls = getattr(sdk_sentry, name, None)
        if cls and callable(cls):
            try:
                instance = cls()
                break
            except Exception:
                continue
    return instance


def _resolve_api():
    inst = _get_analyzer()
    api = {}
    if inst is not None:
        api["analyze_static"] = getattr(inst, "analyze_static", None) or getattr(inst, "analyze_apk", None) or getattr(inst, "analyze", None)
        api["run_dynamic"] = getattr(inst, "run_dynamic", None) or getattr(inst, "analyze_dynamic", None) or getattr(inst, "dynamic_analyze", None)
        api["sign_logs"] = getattr(inst, "sign_and_seal_logs", None) or getattr(inst, "produce_signed_audit", None) or getattr(inst, "sign_logs", None)
        api["verify_logs"] = getattr(inst, "verify_signed_logs", None) or getattr(inst, "verify_audit_signatures", None) or getattr(inst, "verify_logs", None)
        api["instance"] = inst
    else:
        # Try module-level functions
        api["analyze_static"] = getattr(sdk_sentry, "analyze_static", None) or getattr(sdk_sentry, "analyze_apk", None) or getattr(sdk_sentry, "analyze", None)
        api["run_dynamic"] = getattr(sdk_sentry, "run_dynamic", None) or getattr(sdk_sentry, "analyze_dynamic", None) or getattr(sdk_sentry, "dynamic_analyze", None)
        api["sign_logs"] = getattr(sdk_sentry, "sign_and_seal_logs", None) or getattr(sdk_sentry, "produce_signed_audit", None) or getattr(sdk_sentry, "sign_logs", None)
        api["verify_logs"] = getattr(sdk_sentry, "verify_signed_logs", None) or getattr(sdk_sentry, "verify_audit_signatures", None) or getattr(sdk_sentry, "verify_logs", None)
        api["instance"] = None
    return api


def _call_with_supported(func, **kwargs):
    if func is None:
        pytest.skip("Required API not available")
    sig = inspect.signature(func)
    supported = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return func(**supported)


def _get_key(d, candidates, default=None):
    for k in candidates:
        if k in d:
            return d[k]
    # Try case-insensitive
    lower_map = {k.lower(): (k, v) for k, v in d.items()}
    for c in candidates:
        kl = c.lower()
        if kl in lower_map:
            orig_k, v = lower_map[kl]
            return v
    return default


def _has_overbroad_permission(perms, names=("android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS")):
    found = {k: False for k in names}
    for p in perms or []:
        pname = p.get("name") or p.get("permission") or p.get("id")
        over = p.get("overbroad") or p.get("over_provisioned") or p.get("risk") in ("high", "overbroad")
        if pname in names and (over or p.get("flag") == "overbroad"):
            found[pname] = True
    return all(found.values())


def _has_analytics_sdk(components):
    if not components:
        return False
    for c in components:
        name = (c.get("name") or c.get("purl") or "").lower()
        ctype = (c.get("type") or c.get("component_type") or "").lower()
        vendor = (c.get("vendor") or c.get("publisher") or "").lower()
        is_sdk = c.get("is_sdk", False) or ctype in ("sdk", "library")
        third_party = c.get("third_party", None)
        if any(s in name for s in ("analytic", "analytics", "tracker", "mixpanel", "firebase", "appsflyer")) and is_sdk:
            if third_party is None or third_party is True or vendor not in ("", "self", "first-party"):
                return True
    return False


def _cves_for_sdk(cves, components):
    names = set()
    for c in components or []:
        if c.get("name"):
            names.add(c["name"])
    hits = []
    for cve in cves or []:
        cid = cve.get("id") or cve.get("cve") or ""
        affects = cve.get("affects") or cve.get("package") or cve.get("component") or ""
        if cid.startswith("CVE-") and (any(n in affects for n in names) or affects):
            hits.append(cve)
    return hits


@pytest.fixture
def tool_api():
    return _resolve_api()


@pytest.fixture
def dummy_apk(tmp_path):
    # Create a dummy file path to represent the APK
    p = tmp_path / "sample_analytics.apk"
    p.write_bytes(b"fakeapk")
    return str(p)


@pytest.fixture
def benign_apk(tmp_path):
    p = tmp_path / "benign.apk"
    p.write_bytes(b"benign")
    return str(p)


def test_static_analysis_identifies_sdk_builds_sbom_and_flags_permissions_with_cve_correlations(tool_api, dummy_apk, monkeypatch):
    analyze_static = tool_api["analyze_static"]
    if analyze_static is None:
        pytest.skip("Static analysis API not found")

    # Ensure file existence checks pass
    monkeypatch.setattr(os.path, "exists", lambda path: True if path == dummy_apk else os.path.exists(path))

    # Call analysis with request for SBOM; try both formats to ensure acceptance either way
    result = _call_with_supported(
        analyze_static,
        apk_path=dummy_apk,
        sbom_format="cyclonedx",
        include_permissions=True,
        correlate_cves=True,
    )

    # Validate SBOM presence
    sbom = _get_key(result, ["sbom", "bom", "bill_of_materials"])
    assert sbom is not None, "SBOM should be present in result"
    sbom_fmt = _get_key(sbom if isinstance(sbom, dict) else {}, ["format", "spec", "type"], "").lower()
    assert any(f in sbom_fmt for f in ("spdx", "cyclonedx", "cdx")), "SBOM format should be SPDX or CycloneDX"

    # Validate SDK identification
    components = _get_key(sbom if isinstance(sbom, dict) else result, ["components", "packages", "items"], [])
    assert isinstance(components, list) and len(components) > 0, "SBOM should list components"
    assert _has_analytics_sdk(components), "Should identify third-party analytics SDK"

    # Validate overbroad permissions
    perms = _get_key(result, ["permissions", "android_permissions", "manifest_permissions"], [])
    assert _has_overbroad_permission(perms), "Should flag overbroad location and contacts permissions"

    # Validate CVE correlations
    cves = _get_key(result, ["cves", "vulnerabilities", "cve_correlations"], [])
    assert isinstance(cves, list), "CVE correlations should be a list"
    correlated = _cves_for_sdk(cves, components)
    assert correlated, "Should correlate SDK versions with CVEs"


def test_dynamic_run_canary_exfil_to_non_allowlisted_endpoint_triggers_high_confidence_alert_with_sealed_evidence(tool_api, dummy_apk, monkeypatch):
    run_dynamic = tool_api["run_dynamic"]
    if run_dynamic is None:
        pytest.skip("Dynamic analysis API not found")

    # Construct allowlist that treats 'localhost' as allowed but '127.0.0.1' as non-allowlisted
    allowlist = {"domains": ["localhost"], "ips": []}

    canary_ids = {
        "device_id": "canary-device-123",
        "install_id": "canary-install-456",
    }

    # Prevent any real network/emulator usage: monkeypatch time.sleep and any subprocess invocations if present
    monkeypatch.setattr(time, "sleep", lambda s: None, raising=False)

    # Execute dynamic analysis
    result = _call_with_supported(
        run_dynamic,
        apk_path=dummy_apk,
        allowlist=allowlist,
        canary_ids=canary_ids,
        duration_seconds=1,
        test_cert=None,
        decrypt_tls=False,
    )

    # Ensure dynamic result includes alerts and evidence
    alerts = _get_key(result, ["alerts", "findings", "events"], [])
    assert isinstance(alerts, list), "Dynamic result should include alerts"

    # Find high-confidence exfil alert to 127.0.0.1 which is non-allowlisted in this test allowlist
    exfil = None
    for a in alerts:
        category = (a.get("category") or a.get("type") or "").lower()
        endpoint = a.get("endpoint") or a.get("host") or a.get("url") or ""
        confidence = a.get("confidence") or a.get("score") or 0
        contains_canary = any(v in json.dumps(a) for v in canary_ids.values())
        if "exfil" in category and "127.0.0.1" in endpoint and contains_canary and (confidence == "high" or float(confidence) >= 0.8):
            exfil = a
            break
    assert exfil is not None, "Should raise high-confidence exfiltration alert with canary identifiers to non-allowlisted endpoint"

    evidence = _get_key(result, ["evidence_bundle", "evidence", "sealed_evidence"])
    assert isinstance(evidence, dict), "Evidence bundle should be present"

    # Evidence should be cryptographically signed and timestamped, with chain-of-custody attestation
    ts = _get_key(evidence, ["timestamp", "signed_at"])
    sig = _get_key(evidence, ["signature", "sig"])
    att = _get_key(evidence, ["attestation", "attest"])
    assert ts and isinstance(ts, str), "Evidence should be timestamped"
    # Accept common ISO formats
    assert any(ch in ts for ch in ("T", " ")), "Timestamp should be RFC3339-like"
    assert sig and isinstance(sig, (str, dict)), "Evidence should include a signature"
    assert att and isinstance(att, dict), "Evidence should include attestation"
    assert att.get("chain_of_custody") or att.get("chain") or att.get("provenance"), "Attestation should preserve chain-of-custody"


def test_benign_app_approved_sdks_allowlisted_domains_no_high_severity_findings_and_logs_pass_signature_verification(tool_api, benign_apk):
    analyze_static = tool_api["analyze_static"]
    run_dynamic = tool_api["run_dynamic"]
    sign_logs = tool_api["sign_logs"]
    verify_logs = tool_api["verify_logs"]

    if None in (analyze_static, run_dynamic, sign_logs, verify_logs):
        pytest.skip("Required APIs not available")

    allowlist = {"domains": ["localhost"], "ips": ["127.0.0.1"]}

    static_res = _call_with_supported(
        analyze_static,
        apk_path=benign_apk,
        sbom_format="spdx",
        include_permissions=True,
        correlate_cves=True,
    )
    sbom = _get_key(static_res, ["sbom", "bom", "bill_of_materials"])
    assert sbom is not None, "SBOM should be present"
    components = _get_key(sbom if isinstance(sbom, dict) else {}, ["components", "packages"], [])
    # Approved SDKs should not raise high-severity issues
    cves = _get_key(static_res, ["cves", "vulnerabilities", "cve_correlations"], [])
    assert all((cv.get("severity", "").lower() not in ("critical", "high")) for cv in cves), "No high-severity CVEs for benign app"

    dynamic_res = _call_with_supported(
        run_dynamic,
        apk_path=benign_apk,
        allowlist=allowlist,
        canary_ids={"device_id": "benign-canary"},
        duration_seconds=1,
        test_cert=None,
        decrypt_tls=False,
    )
    alerts = _get_key(dynamic_res, ["alerts", "findings", "events"], [])
    high_sev = [a for a in alerts if (a.get("severity", "").lower() in ("critical", "high")) or (a.get("confidence") == "high")]
    assert not high_sev, "Benign app should have no high-severity findings"

    # Produce signed audit logs and verify signatures
    audit_input = {
        "static": static_res,
        "dynamic": dynamic_res,
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "tool": "sdk_sentry",
        "digest": hashlib.sha256(json.dumps({"components": components}, sort_keys=True).encode()).hexdigest(),
    }
    signed = _call_with_supported(sign_logs, logs=audit_input)
    assert signed, "Should produce a signed audit bundle"

    verified = _call_with_supported(verify_logs, signed_logs=signed)
    assert verified is True, "All logs must pass signature verification"


def test_error_handling_invalid_apk_path(tool_api, tmp_path):
    analyze_static = tool_api["analyze_static"]
    if analyze_static is None:
        pytest.skip("Static analysis API not found")

    invalid_path = str(tmp_path / "missing.apk")
    with pytest.raises((FileNotFoundError, ValueError, OSError)):
        _call_with_supported(analyze_static, apk_path=invalid_path, sbom_format="cyclonedx")


def test_tls_decrypt_requires_opt_in_test_cert(tool_api, dummy_apk):
    run_dynamic = tool_api["run_dynamic"]
    if run_dynamic is None:
        pytest.skip("Dynamic analysis API not found")

    res = _call_with_supported(
        run_dynamic,
        apk_path=dummy_apk,
        allowlist={"domains": ["localhost"], "ips": ["127.0.0.1"]},
        canary_ids={"device_id": "canary"},
        decrypt_tls=True,
        test_cert=None,
        duration_seconds=1,
    )
    # Expect either explicit disabled flag or absence of decrypted tls artifacts
    tls_flag = _get_key(res, ["tls_decryption", "mitm_tls", "tls_mitm"])
    if isinstance(tls_flag, dict):
        tls_enabled = tls_flag.get("enabled")
    else:
        tls_enabled = tls_flag
    decrypted_artifacts = _get_key(res, ["tls_artifacts", "decrypted_tls", "tls_logs"], [])
    assert not tls_enabled or not decrypted_artifacts, "TLS should not be decrypted without opt-in test cert"


@pytest.mark.parametrize("fmt", ["spdx", "cyclonedx"])
def test_sbom_formats_supported(tool_api, dummy_apk, fmt):
    analyze_static = tool_api["analyze_static"]
    if analyze_static is None:
        pytest.skip("Static analysis API not found")

    res = _call_with_supported(analyze_static, apk_path=dummy_apk, sbom_format=fmt)
    sbom = _get_key(res, ["sbom", "bom", "bill_of_materials"])
    assert sbom is not None, "SBOM should be present"
    f = _get_key(sbom if isinstance(sbom, dict) else {}, ["format", "spec", "type"], "").lower()
    assert fmt in f or (fmt == "cyclonedx" and "cdx" in f), f"SBOM format should reflect requested {fmt}"