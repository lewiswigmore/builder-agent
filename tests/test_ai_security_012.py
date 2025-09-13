import os
import json
import socket
import hashlib
import pathlib
import pytest

import tools.ai_security.gencode_risk_auditor as auditor_mod


def _instantiate_auditor(config=None):
    # Try multiple instantiation patterns for auditor
    if hasattr(auditor_mod, "GenCodeRiskAuditor"):
        try:
            return auditor_mod.GenCodeRiskAuditor(config=config)
        except TypeError:
            # Fallback without config
            return auditor_mod.GenCodeRiskAuditor()
    return None


def _run_scan(repo_path, pr=None, config=None):
    # Try class instance methods
    inst = _instantiate_auditor(config=config)
    if inst is not None:
        if hasattr(inst, "scan_repo"):
            try:
                return inst.scan_repo(repo_path=repo_path, pr=pr, config=config)
            except TypeError:
                try:
                    return inst.scan_repo(repo_path=repo_path, pr=pr)
                except TypeError:
                    return inst.scan_repo(repo_path=repo_path)
        if hasattr(inst, "analyze"):
            try:
                return inst.analyze(repo_path=repo_path, pr=pr, config=config)
            except TypeError:
                try:
                    return inst.analyze(repo_path=repo_path, pr=pr)
                except TypeError:
                    return inst.analyze(repo_path=repo_path)
    # Try module-level functions
    for fname in ("scan_repo", "analyze", "run_scan"):
        if hasattr(auditor_mod, fname):
            fn = getattr(auditor_mod, fname)
            try:
                return fn(repo_path=repo_path, pr=pr, config=config)
            except TypeError:
                try:
                    return fn(repo_path=repo_path, pr=pr)
                except TypeError:
                    return fn(repo_path=repo_path)
    pytest.skip("No known scan entrypoint found in GenCode Risk Auditor")


def _get(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        if name in obj:
            return obj[name]
    if hasattr(obj, name):
        return getattr(obj, name)
    return default


def _find_artifact(result, key):
    # Look for artifacts collection under common names
    for art_key in ("artifacts", "outputs", "deliverables"):
        artifacts = _get(result, art_key)
        if artifacts:
            # dict-based artifacts
            if isinstance(artifacts, dict):
                if key in artifacts:
                    return artifacts[key]
                # maybe match by type field
                for art in artifacts.values():
                    if isinstance(art, dict) and art.get("type") == key:
                        return art
                    if hasattr(art, "type") and getattr(art, "type") == key:
                        return art
            # list-based
            if isinstance(artifacts, (list, tuple)):
                for art in artifacts:
                    if isinstance(art, dict) and (
                        art.get("name") == key
                        or art.get("type") == key
                        or art.get("format") == key
                    ):
                        return art
                    if hasattr(art, "name") and getattr(art, "name") == key:
                        return art
                    if hasattr(art, "type") and getattr(art, "type") == key:
                        return art
    return None


def _get_transcript(result):
    # Attempt to retrieve sandbox transcript/log of dynamic analysis
    for k in (
        "sandbox_transcript",
        "sandbox_log",
        "dynamic_transcript",
        "dynamic_log",
        "transcript",
    ):
        tr = _get(result, k)
        if tr:
            return tr
    sandbox = _get(result, "sandbox") or _get(result, "dynamic")
    if sandbox:
        for k in ("transcript", "log", "events"):
            tr = _get(sandbox, k)
            if tr:
                return tr
    return None


def _get_findings(result):
    for k in ("findings", "issues", "violations", "alerts"):
        f = _get(result, k)
        if f is not None:
            return f
    return []


def _has_signed(artifact):
    if artifact is None:
        return False
    # The artifact may include flags for signature and verification
    fields = {}
    if isinstance(artifact, dict):
        fields = artifact
    else:
        # Try to capture attributes
        for n in ("signature", "sig", "dsse", "bundle", "attestation"):
            if hasattr(artifact, n):
                fields[n] = getattr(artifact, n)
        for n in ("signed", "signature_verified", "verified"):
            if hasattr(artifact, n):
                fields[n] = getattr(artifact, n)
    signed_flag = fields.get("signed") or fields.get("signature_verified") or fields.get("verified")
    has_sig = fields.get("signature") or fields.get("sig") or fields.get("dsse") or fields.get("bundle") or fields.get("attestation")
    return bool(signed_flag or has_sig)


def _signature_verified(artifact):
    if artifact is None:
        return False
    if isinstance(artifact, dict):
        return bool(artifact.get("signature_verified") or artifact.get("verified") or artifact.get("signed"))
    return bool(getattr(artifact, "signature_verified", False) or getattr(artifact, "verified", False) or getattr(artifact, "signed", False))


def _artifact_format(artifact):
    if artifact is None:
        return None
    if isinstance(artifact, dict):
        return artifact.get("format") or artifact.get("type") or artifact.get("name")
    return getattr(artifact, "format", None) or getattr(artifact, "type", None) or getattr(artifact, "name", None)


def _create_repo(tmp_path, files):
    base = tmp_path / "repo"
    base.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return base


@pytest.fixture
def no_external_network(monkeypatch):
    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        host, port = address
        # Allow only localhost loopback in tests
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(f"External network egress attempted to {host}:{port}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect, raising=True)
    return True


def test_acceptance_unsafe_eval_and_unapproved_fetch_blocked_with_sandbox_transcript(tmp_path, no_external_network):
    repo = _create_repo(
        tmp_path,
        {
            "bad_module.py": (
                "import os\n"
                "import urllib.request\n"
                "code = '1+1'\n"
                "eval(code)\n"
                "try:\n"
                "    urllib.request.urlopen('http://example.com')\n"
                "except Exception:\n"
                "    pass\n"
            )
        },
    )
    pr = {
        "changed_files": [
            {"path": "bad_module.py", "status": "added"}
        ]
    }

    result = _run_scan(repo_path=str(repo), pr=pr, config={"sandbox": {"egress_allowlist": ["127.0.0.1", "localhost"]}})

    # Must be blocked with high risk
    blocked = _get(result, "blocked", False) or _get(result, "fail_pipeline", False)
    assert blocked, "PR introducing unsafe eval and unapproved fetch should be blocked"

    risk = _get(result, "risk_level") or _get(result, "verdict") or _get(result, "risk")
    risk_val = str(risk).lower() if risk else ""
    assert "high" in risk_val, f"Expected high-risk verdict, got: {risk}"

    findings = _get_findings(result)
    joined = json.dumps(findings, default=str).lower()
    assert "eval" in joined, "Findings should mention unsafe eval"
    # Accept both 'egress' and 'network' keywords
    assert ("egress" in joined) or ("network" in joined), "Findings should include unapproved network egress"

    transcript = _get_transcript(result)
    assert transcript, "Sandbox transcript/log expected"
    trans_str = json.dumps(transcript, default=str).lower()
    assert ("prevented" in trans_str or "blocked" in trans_str) and ("example.com" in trans_str or "unapproved" in trans_str), \
        "Transcript should show prevented egress to unapproved domain"


def test_acceptance_typosquatted_dependency_detected_and_attested_and_pipeline_fails(tmp_path, no_external_network, monkeypatch):
    repo = _create_repo(
        tmp_path,
        {
            "requirements.txt": "reqquests==2.31.0\n",  # typo-squatted 'requests'
            "src/app.py": "print('hello')\n",
            "lockfile.txt": "reqquests==2.31.0\n",
        },
    )

    # Ensure rulepack/plugin verification is treated as valid for this test
    # Patch common signature verification hooks to return True
    patched = False
    if hasattr(auditor_mod, "verify_rulepack_signature"):
        monkeypatch.setattr(auditor_mod, "verify_rulepack_signature", lambda *a, **k: True)
        patched = True
    inst = _instantiate_auditor()
    if inst and hasattr(inst, "verify_rulepack_signature"):
        monkeypatch.setattr(inst, "verify_rulepack_signature", lambda *a, **k: True)
        patched = True
    if hasattr(auditor_mod, "SigstoreVerifier"):
        class _FakeVer:  # noqa
            def verify(self, *a, **k): return True
        monkeypatch.setattr(auditor_mod, "SigstoreVerifier", _FakeVer)
        patched = True
    if not patched:
        # If we can't patch sigstore verification, we still proceed assuming offline cache
        pass

    result = _run_scan(repo_path=str(repo), pr={"changed_files": [{"path": "requirements.txt", "status": "modified"}]}, config={"supply_chain": {"verify_sigstore": True}})

    # Pipeline should fail/block due to typosquat
    blocked = _get(result, "blocked", False) or _get(result, "fail_pipeline", False)
    assert blocked, "Typosquatted dependency introduction must fail the pipeline"

    findings = _get_findings(result)
    assert findings, "Expect findings for typosquatted dependency"
    joined = json.dumps(findings, default=str).lower()
    assert ("typo" in joined) or ("squat" in joined) or ("squatted" in joined), "Should flag typosquatted package"
    assert "reqquests" in joined, "Finding should cite offending artifact name"
    assert ("remediation" in joined) or ("replace" in joined) or ("guidance" in joined), "Should include remediation guidance"

    # Expect a signed attestation citing the offending artifact
    attestation = _find_artifact(result, "attestation") or _find_artifact(result, "slsa") or _find_artifact(result, "provenance")
    assert attestation, "Expected signed attestation artifact"
    assert _has_signed(attestation), "Attestation should be signed"
    assert _signature_verified(attestation), "Attestation signature should verify"
    att_str = json.dumps(attestation, default=str).lower()
    assert "reqquests" in att_str, "Attestation should cite the offending dependency"


def test_acceptance_clean_repo_low_risk_and_signed_sbom_and_provenance(tmp_path, no_external_network, monkeypatch):
    repo = _create_repo(
        tmp_path,
        {
            "src/lib.py": "def add(a, b):\n    return a + b\n",
            # Provide pinned-deps lock to satisfy reproducibility requirement
            "requirements.txt": "",
            "requirements.lock": "# empty lock - no deps\n",
        },
    )

    # Ensure sigstore-related verifications succeed (mock offline)
    if hasattr(auditor_mod, "verify_rulepack_signature"):
        monkeypatch.setattr(auditor_mod, "verify_rulepack_signature", lambda *a, **k: True)
    inst = _instantiate_auditor()
    if inst and hasattr(inst, "verify_rulepack_signature"):
        monkeypatch.setattr(inst, "verify_rulepack_signature", lambda *a, **k: True)
    if hasattr(auditor_mod, "SigstoreVerifier"):
        class _FakeVer:  # noqa
            def verify(self, *a, **k): return True
        monkeypatch.setattr(auditor_mod, "SigstoreVerifier", _FakeVer)

    result = _run_scan(repo_path=str(repo), pr=None, config={"supply_chain": {"verify_sigstore": True}})

    # Low-risk verdict, not blocked
    risk = _get(result, "risk_level") or _get(result, "verdict") or _get(result, "risk")
    assert risk, "Scan should produce a risk verdict"
    risk_val = str(risk).lower()
    assert "low" in risk_val, f"Expected low risk for clean repo, got {risk}"

    blocked = _get(result, "blocked", False) or _get(result, "fail_pipeline", False)
    assert not blocked, "Clean repo should not be blocked"

    # Signed CycloneDX SBOM
    sbom = _find_artifact(result, "sbom")
    assert sbom, "Expected SBOM artifact"
    fmt = (_artifact_format(sbom) or "").lower()
    assert "cyclonedx" in fmt or "cdx" in fmt, f"SBOM should be CycloneDX, got format: {fmt}"
    assert _has_signed(sbom) and _signature_verified(sbom), "SBOM should be signed and verified"

    # Provenance attestation suitable for CI policy
    provenance = _find_artifact(result, "provenance") or _find_artifact(result, "attestation")
    assert provenance, "Expected provenance attestation"
    assert _has_signed(provenance) and _signature_verified(provenance), "Provenance should be signed and verified"
    prov_str = json.dumps(provenance, default=str).lower()
    assert ("policy" in prov_str and "gate" in prov_str) or ("slsa" in prov_str) or ("in-toto" in prov_str), "Provenance should indicate CI policy suitability"


def test_offline_static_analysis_no_uploads_and_pii_secret_scrubbed(tmp_path, no_external_network, monkeypatch):
    repo = _create_repo(
        tmp_path,
        {
            "src/secret.py": (
                "API_KEY='sk-1234567890abcdef'\n"
                "EMAIL='alice@example.com'\n"
                "CARD='4111111111111111'\n"
                "def foo(): return 42\n"
            )
        },
    )

    # Block any function that looks like upload or remote call within module
    blocked_calls = []

    def _blocker(*a, **k):
        blocked_calls.append((a, k))
        raise AssertionError("External upload attempted in offline mode")

    for name in dir(auditor_mod):
        if any(t in name.lower() for t in ("upload", "send", "post", "put", "http", "remote", "cloud")):
            try:
                monkeypatch.setattr(auditor_mod, name, _blocker)
            except Exception:
                pass

    result = _run_scan(repo_path=str(repo), pr=None, config={"offline": True})

    # Ensure no blocked call was attempted
    assert blocked_calls == [], "Static analysis must not upload proprietary code"

    findings = _get_findings(result)
    # The report should not leak raw PII/secrets
    report = json.dumps(findings, default=str)
    assert "sk-1234567890abcdef" not in report
    assert "4111111111111111" not in report
    # Email may be scrubbed; allow domain but not full address
    assert "alice@example.com" not in report
    # Redaction markers expected
    low_report = report.lower()
    assert ("redact" in low_report) or ("***" in report) or ("[redacted]" in low_report) or ("masked" in low_report)


def test_rulepack_sigstore_verification_failure_blocks(monkeypatch, tmp_path):
    repo = _create_repo(tmp_path, {"main.py": "print('ok')\n"})

    # Attempt to force verification failure of third-party rulepacks/plugins
    patched_any = False

    if hasattr(auditor_mod, "verify_rulepack_signature"):
        monkeypatch.setattr(auditor_mod, "verify_rulepack_signature", lambda *a, **k: False)
        patched_any = True

    inst = _instantiate_auditor()
    if inst and hasattr(inst, "verify_rulepack_signature"):
        monkeypatch.setattr(inst, "verify_rulepack_signature", lambda *a, **k: False)
        patched_any = True

    if hasattr(auditor_mod, "SigstoreVerifier"):
        class _FakeVerFail:  # noqa
            def verify(self, *a, **k): return False
        monkeypatch.setattr(auditor_mod, "SigstoreVerifier", _FakeVerFail)
        patched_any = True

    if not patched_any:
        pytest.skip("Cannot force rulepack Sigstore verification failure with available hooks")

    result = _run_scan(repo_path=str(repo), pr=None, config={"supply_chain": {"verify_sigstore": True}})

    # Expect error surfaced or pipeline blocked before unverified rulepacks load
    err = _get(result, "error") or _get(result, "errors")
    if err:
        low = json.dumps(err, default=str).lower()
        assert ("sigstore" in low or "verify" in low) and ("fail" in low or "invalid" in low), "Must report signature verification failure"
    else:
        blocked = _get(result, "blocked", False) or _get(result, "fail_pipeline", False)
        assert blocked, "Should block when rulepack signature verification fails"


def test_sandbox_blocks_credential_access_and_traces_syscalls_artifacts_hashed(tmp_path, no_external_network, monkeypatch):
    # Prepare repo with snippet that attempts to read credentials and make a call
    repo = _create_repo(
        tmp_path,
        {
            "dynamic_test.py": (
                "import os, socket\n"
                "print('AWS_SECRET_ACCESS_KEY:', os.environ.get('AWS_SECRET_ACCESS_KEY'))\n"
                "s=socket.socket()\n"
                "try:\n"
                "  s.connect(('127.0.0.1', 9))\n"
                "except Exception:\n"
                "  pass\n"
            )
        },
    )

    # Set credentials in environment; sandbox should prevent/strip them
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "TEST_SECRET_SHOULD_NOT_LEAK")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_not_leak")

    result = _run_scan(repo_path=str(repo), pr=None, config={"sandbox": {"egress_allowlist": ["127.0.0.1"]}})

    transcript = _get_transcript(result)
    assert transcript, "Sandbox transcript/log should be present"
    t = json.dumps(transcript, default=str).lower()

    # Should indicate blocked or redacted credentials
    assert ("credential" in t or "secret" in t or "token" in t), "Transcript should reference credential handling"
    assert ("blocked" in t or "redact" in t or "forbid" in t or "denied" in t), "Credential access should be prevented/redacted"
    assert "test_secret_should_not_leak".lower() not in t
    assert "ghp_should_not_leak".lower() not in t

    # Syscall tracing and artifact hashing evidence
    assert ("syscall" in t or "trace" in t or "seccomp" in t), "Sandbox transcript should mention syscall tracing"
    assert ("hash" in t or "sha256" in t or "digest" in t), "Sandbox transcript should include artifact hashing details"


def test_reproducible_scan_requires_pinned_dependencies(tmp_path, no_external_network):
    repo = _create_repo(
        tmp_path,
        {
            "src/app.py": "print('hi')\n",
            "requirements.txt": "requests>=2.0\n",  # unpinned
        },
    )
    result = _run_scan(repo_path=str(repo), pr=None, config={"supply_chain": {"enforce_pinned_deps": True}})

    findings = _get_findings(result)
    assert findings, "Expected findings when pinned dependencies are required but missing"
    joined = json.dumps(findings, default=str).lower()
    assert ("pin" in joined or "lock" in joined or "reproducible" in joined), "Should flag missing pinned dependencies or lockfile"

    # Risk should be at least medium if not high
    risk = _get(result, "risk_level") or _get(result, "verdict") or _get(result, "risk")
    if risk:
        risk_val = str(risk).lower()
        assert any(k in risk_val for k in ("medium", "mod", "high")), f"Expected >= medium risk, got {risk}"


def test_error_handling_on_sandbox_failure(tmp_path, monkeypatch):
    # If sandbox fails to start, verify graceful error handling
    repo = _create_repo(tmp_path, {"prog.py": "print(1)\n"})

    inst = _instantiate_auditor()
    if not inst:
        pytest.skip("No auditor instance available for sandbox failure injection")

    # Inject a failure into sandbox start/run methods if available
    injected = False
    if hasattr(inst, "sandbox"):
        sb = getattr(inst, "sandbox")
        for name in ("run", "run_snippet", "execute", "start"):
            if hasattr(sb, name):
                monkeypatch.setattr(sb, name, lambda *a, **k: (_ for _ in ()).throw(RuntimeError("sandbox start failure")))
                injected = True
    # Alternatively, patch instance methods referencing sandbox
    for name in ("dynamic_analyze", "run_dynamic_tests", "run_in_sandbox"):
        if hasattr(inst, name):
            monkeypatch.setattr(inst, name, lambda *a, **k: (_ for _ in ()).throw(RuntimeError("sandbox start failure")))
            injected = True

    if not injected:
        pytest.skip("Cannot inject sandbox failure on this auditor")

    # Now run via the instance path to ensure our patched instance is used
    result = None
    try:
        if hasattr(inst, "scan_repo"):
            result = inst.scan_repo(repo_path=str(repo))
        elif hasattr(inst, "analyze"):
            result = inst.analyze(repo_path=str(repo))
    except Exception as e:
        # Accept raising with meaningful message
        assert "sandbox" in str(e).lower() and ("fail" in str(e).lower() or "start" in str(e).lower()), "Exception should indicate sandbox failure"
        return

    # Or if not raising, result should contain error details
    err = _get(result, "error") or _get(result, "errors")
    assert err, "Expected error field when sandbox fails"
    low = json.dumps(err, default=str).lower()
    assert "sandbox" in low and ("fail" in low or "start" in low or "unavailable" in low), "Error should mention sandbox failure"


def test_sbom_and_provenance_are_deterministic_with_pinned_deps(tmp_path, no_external_network, monkeypatch):
    # Ensure reproducible outputs when inputs are the same and deps pinned
    repo = _create_repo(
        tmp_path,
        {
            "src/a.py": "def x():\n    return 7\n",
            "requirements.txt": "",
            "requirements.lock": "# no deps\n",
        },
    )

    # Make two runs and compare artifact digests
    res1 = _run_scan(repo_path=str(repo))
    res2 = _run_scan(repo_path=str(repo))

    sbom1 = _find_artifact(res1, "sbom")
    sbom2 = _find_artifact(res2, "sbom")
    assert sbom1 and sbom2, "Expected SBOM artifacts for both runs"

    # Extract content or digest if provided
    def _content_or_digest(art):
        if isinstance(art, dict):
            for k in ("content", "raw", "data", "blob"):
                if k in art and art[k]:
                    return art[k] if isinstance(art[k], (bytes, str)) else json.dumps(art[k], default=str)
            for k in ("digest", "sha256", "hash"):
                if k in art and art[k]:
                    return str(art[k])
        else:
            for k in ("content", "raw", "data", "blob", "digest", "sha256", "hash"):
                if hasattr(art, k):
                    val = getattr(art, k)
                    if val:
                        return val if isinstance(val, (bytes, str)) else json.dumps(val, default=str)
        return None

    c1 = _content_or_digest(sbom1)
    c2 = _content_or_digest(sbom2)
    assert c1 is not None and c2 is not None, "SBOM content or digest must be available"
    if isinstance(c1, str):
        c1b = c1.encode("utf-8")
    else:
        c1b = c1
    if isinstance(c2, str):
        c2b = c2.encode("utf-8")
    else:
        c2b = c2

    h1 = hashlib.sha256(c1b).hexdigest()
    h2 = hashlib.sha256(c2b).hexdigest()
    assert h1 == h2, "Reproducible scans should yield identical SBOM digests when inputs are identical"

    # Provenance determinism
    prov1 = _find_artifact(res1, "provenance")
    prov2 = _find_artifact(res2, "provenance")
    assert prov1 and prov2, "Expected provenance artifacts for both runs"

    p1 = _content_or_digest(prov1)
    p2 = _content_or_digest(prov2)
    assert p1 is not None and p2 is not None, "Provenance content or digest must be available"
    if isinstance(p1, str):
        p1b = p1.encode("utf-8")
    else:
        p1b = p1
    if isinstance(p2, str):
        p2b = p2.encode("utf-8")
    else:
        p2b = p2

    ph1 = hashlib.sha256(p1b).hexdigest()
    ph2 = hashlib.sha256(p2b).hexdigest()
    assert ph1 == ph2, "Reproducible scans should yield identical provenance digests when inputs are identical"