import os
import sys
import types
import json
import pathlib
import importlib
import hashlib
import tempfile
import shutil
import pytest


@pytest.fixture(autouse=True)
def inject_fake_external_deps(monkeypatch):
    # Inject fake sigstore, rekor, in_toto modules to avoid real network/external dependencies
    fake_sigstore = types.ModuleType("sigstore")
    state = types.SimpleNamespace(
        expired_cert=False,
        rekor_inclusion_valid=True,
        attestation_valid=True,
    )

    class VerificationError(Exception):
        pass

    class CertificateExpiredError(VerificationError):
        pass

    def verify(*args, **kwargs):
        if state.expired_cert:
            raise CertificateExpiredError("certificate expired")
        if not state.rekor_inclusion_valid:
            raise VerificationError("rekor inclusion proof invalid")
        return {"verified": True}

    def verify_signatures(*args, **kwargs):
        return verify(*args, **kwargs)

    fake_sigstore.state = state
    fake_sigstore.VerificationError = VerificationError
    fake_sigstore.CertificateExpiredError = CertificateExpiredError
    fake_sigstore.verify = verify
    fake_sigstore.verify_signatures = verify_signatures

    fake_rekor = types.ModuleType("rekor")

    class Client:
        def __init__(self, url=None, *args, **kwargs):
            self.url = url or "http://127.0.0.1:3000"

        def verify_inclusion_proof(self, entry):
            return bool(state.rekor_inclusion_valid)

        def get_inclusion_proof(self, entry_uuid):
            if state.rekor_inclusion_valid:
                return {"root": "abc", "path": ["x", "y"], "leaf": "z"}
            return {"root": "abc", "path": ["x", "bad"], "leaf": "z", "inconsistent": True}

        def audit_mirror(self, mirror_state):
            # Return list of inconsistencies if any
            if mirror_state.get("tampered"):
                return [{"uuid": "deadbeef", "reason": "Merkle path invalid"}]
            return []

    fake_rekor.Client = Client

    fake_in_toto = types.ModuleType("in_toto")

    class AttestationError(Exception):
        pass

    def verify_attestation(*args, **kwargs):
        if not state.attestation_valid:
            raise AttestationError("in-toto attestation invalid")
        required_level = kwargs.get("required_level", 3)
        return {"slsa_level": max(3, required_level), "valid": True}

    fake_in_toto.AttestationError = AttestationError
    fake_in_toto.verify_attestation = verify_attestation

    # Insert into sys.modules if not already present
    sys.modules.setdefault("sigstore", fake_sigstore)
    sys.modules.setdefault("rekor", fake_rekor)
    sys.modules.setdefault("in_toto", fake_in_toto)

    # Also block any accidental outbound requests by monkeypatching requests
    try:
        import requests  # noqa: F401

        original_send = requests.Session.request

        def _blocked_request(self, method, url, *args, **kwargs):
            # Allow only localhost/127.0.0.1
            if not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
                raise RuntimeError(f"Outbound network blocked in tests: {url}")
            return original_send(self, method, url, *args, **kwargs)

        monkeypatch.setattr("requests.Session.request", _blocked_request, raising=True)
    except Exception:
        pass

    yield


@pytest.fixture(scope="module")
def scg_module():
    return importlib.import_module("tools.supply_chain.sigchain_guardian")


def _find_class(module, names):
    for n in names:
        c = getattr(module, n, None)
        if isinstance(c, type):
            return c
    return None


def _find_callable(obj, names):
    for n in names:
        f = getattr(obj, n, None)
        if callable(f):
            return f
    return None


@pytest.fixture
def guardian(scg_module):
    # Try to construct a guardian instance if available
    Cls = _find_class(scg_module, ["SigChainGuardian", "Guardian", "SigChain"])
    if Cls is not None:
        try:
            return Cls()
        except Exception:
            # Try with empty config
            try:
                return Cls(config={})
            except Exception:
                return None
    # Try factory
    factory = _find_callable(scg_module, ["get_guardian", "create_guardian", "init"])
    if factory:
        try:
            return factory()
        except Exception:
            return None
    return None


def _get(result, key, default=None):
    if result is None:
        return default
    if isinstance(result, dict):
        return result.get(key, default)
    return getattr(result, key, default)


def _get_alerts(result):
    alerts = _get(result, "alerts")
    if alerts is None and isinstance(result, (list, tuple)):
        # maybe the result is a list of alerts
        alerts = result
    if alerts is None:
        # maybe nested under 'issues' or 'findings'
        alerts = _get(result, "issues") or _get(result, "findings")
    return alerts or []


def _has_issue(alerts, kind=None, severity=None, contains=None):
    for a in alerts:
        # support dict or objects
        t = a.get("type") if isinstance(a, dict) else getattr(a, "type", None)
        sev = a.get("severity") if isinstance(a, dict) else getattr(a, "severity", None)
        msg = a.get("message") if isinstance(a, dict) else getattr(a, "message", "")
        rem = a.get("remediation") if isinstance(a, dict) else getattr(a, "remediation", "")
        content = f"{msg} {rem}".lower()
        if (kind is None or (t and kind in str(t))) and (severity is None or (sev and severity.lower() in str(sev).lower())):
            if contains is None or (contains.lower() in content):
                return True
    return False


@pytest.fixture
def temp_polyglot_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # Python
    (repo / "requirements.txt").write_text("flask==2.3.3\nrequests==2.31.0\n")

    # Node.js
    pkg_json = {
        "name": "polyglot-app",
        "version": "1.0.0",
        "dependencies": {"lodash": "4.17.21", "express": "4.18.2"},
    }
    (repo / "package.json").write_text(json.dumps(pkg_json))

    # Container/Dockerfile
    (repo / "Dockerfile").write_text("FROM python:3.11-slim\nRUN pip install -r requirements.txt\n")

    # Serverless layer (e.g., AWS Lambda layer)
    serverless_dir = repo / "serverless" / "layer"
    serverless_dir.mkdir(parents=True)
    (serverless_dir / "requirements.txt").write_text("urllib3==2.2.2\n")

    # Mobile package placeholder
    mobile_dir = repo / "mobile"
    mobile_dir.mkdir()
    (mobile_dir / "build.gradle").write_text("dependencies { implementation 'com.squareup.okhttp3:okhttp:4.12.0' }")

    return repo


def test_dependency_confusion_blocked(scg_module, guardian, monkeypatch, tmp_path):
    # Find API
    target = None
    owner = None
    names = ["analyze_dependencies", "detect_dependency_confusion", "resolve_dependencies", "check_dependency_confusion"]
    if guardian is not None:
        target = _find_callable(guardian, names)
        owner = guardian
    if target is None:
        target = _find_callable(scg_module, names)
        owner = scg_module
    if target is None:
        pytest.skip("Dependency confusion API not found")

    # Mock resolvers/registry metadata functions if present
    # We simulate a private registry shadowing a public name for a transitive dependency
    private_registry = "http://127.0.0.1:8081"
    public_registry = "https://registry.npmjs.org"  # will be blocked if accidentally called

    # Simulate package resolution function
    def fake_resolve(name, version_range=None, registries=None, transitive=False):
        # If it's a transitive dep 'util-lib', the private registry shadows the public one
        if name == "util-lib":
            return {"name": "util-lib", "version": "1.2.3", "registry": private_registry, "shadowed": True}
        # Direct deps come from public
        return {"name": name, "version": "1.0.0", "registry": public_registry}

    resolved = []
    # Hook possible internal function names
    for fname in ["resolve_package_source", "resolve_package", "fetch_package_metadata"]:
        if hasattr(scg_module, fname):
            monkeypatch.setattr(scg_module, fname, lambda *args, **kwargs: resolved.append(args) or fake_resolve(*args, **kwargs))

    # Prepare a fake manifest/lockfile representation
    manifest = {
        "name": "app",
        "dependencies": {
            "top-lib": ">=1.0.0",
        },
        "transitive": {
            "top-lib": ["util-lib"],  # transitive dependency that will be shadowed
        },
        "registries": [public_registry, private_registry],
    }

    # Call API
    try:
        result = target(manifest) if owner is scg_module else target(manifest)
    except Exception as e:
        # Some APIs may require additional args; try with kwargs
        try:
            result = target(manifest=manifest)
        except Exception:
            pytest.fail(f"Dependency analysis raised unexpected exception: {e}")

    alerts = _get_alerts(result)
    assert alerts, "No alerts produced for dependency confusion scenario"
    assert _has_issue(alerts, kind="dependency_confusion", severity="high"), "High-risk dependency confusion not detected"
    assert _has_issue(alerts, kind="dependency_confusion", contains="remediation"), "No remediation guidance included"

    # Also expect a policy gate block flag somewhere
    blocked = _get(result, "blocked", False) or _get(result, "release_blocked", False)
    if not blocked:
        # Maybe there is a gate result object
        gates = _get(result, "gates", {}) or {}
        blocked = bool(getattr(gates, "blocked", False) or (isinstance(gates, dict) and gates.get("blocked")))
    assert blocked, "Resolution attempt should be blocked due to dependency confusion"


def test_signature_verification_expired_cert_blocks_release(scg_module, guardian, monkeypatch, tmp_path):
    # Find API
    target = None
    owner = None
    names = ["verify_signatures", "verify_artifact_signatures", "validate_signatures", "enforce_release_gates"]
    if guardian is not None:
        target = _find_callable(guardian, names)
        owner = guardian
    if target is None:
        target = _find_callable(scg_module, names)
        owner = scg_module
    if target is None:
        pytest.skip("Signature verification API not found")

    # Prepare a fake artifact
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(os.urandom(128))
    sigbundle = tmp_path / "artifact.sig"
    sigbundle.write_text("FAKE_SIGNATURE_BUNDLE")

    # Configure fake sigstore to simulate expired certificate and invalid Rekor proof
    import sigstore as fake_sigstore  # from injected fake
    fake_sigstore.state.expired_cert = True
    fake_sigstore.state.rekor_inclusion_valid = False

    # Attempt verification
    blocked = False
    result = None
    try:
        result = target(str(artifact), signature=str(sigbundle), rekor_url="http://127.0.0.1:3000", fulcio_url="http://127.0.0.1:5555")
    except Exception:
        # Some APIs might raise on failure; set blocked to True
        blocked = True

    if result is not None:
        blocked = _get(result, "blocked", False) or _get(result, "release_blocked", False) or _get(result, "failed", False)

    assert blocked, "Release gate should be blocked when certificate is expired and Rekor inclusion proof is invalid"

    # Diagnostics assertions
    alerts = _get_alerts(result)
    assert _has_issue(alerts, kind="signature", contains="expired"), "Missing actionable diagnostic about expired certificate"
    assert _has_issue(alerts, kind="signature", contains="rekor"), "Missing diagnostic about Rekor inclusion proof validation failure"


def test_generate_polyglot_sbom_coverage_and_slsa(scg_module, guardian, temp_polyglot_repo, monkeypatch, tmp_path):
    # Find API
    target = None
    owner = None
    names = ["generate_sbom", "create_sbom", "build_sbom", "sbom"]
    if guardian is not None:
        target = _find_callable(guardian, names)
        owner = guardian
    if target is None:
        target = _find_callable(scg_module, names)
        owner = scg_module
    if target is None:
        pytest.skip("SBOM generation API not found")

    repo = temp_polyglot_repo

    # Force outputs to be written under tmp_path if applicable
    output_dir = tmp_path / "sbom"
    output_dir.mkdir()

    # Call API with request for both CycloneDX and SPDX and provenance attestations
    kwargs = {
        "repo_path": str(repo),
        "formats": ["cyclonedx", "spdx"],
        "include_provenance": True,
        "include_containers": True,
        "include_serverless": True,
        "include_mobile": True,
        "output_dir": str(output_dir),
        "policy": {"slsa_level": 3},
    }

    try:
        result = target(**kwargs)
    except TypeError:
        # Try positional fallback
        result = target(str(repo))

    # Basic coverage checks
    components = _get(result, "components") or []
    if not components and isinstance(result, dict):
        components = result.get("sbom", {}).get("components", [])
    assert components, "No components found in SBOM"

    # Ensure coverage of ecosystems: python, nodejs, container image, serverless layer, mobile
    kinds = set()
    for c in components:
        eco = c.get("ecosystem") if isinstance(c, dict) else getattr(c, "ecosystem", None)
        typ = c.get("type") if isinstance(c, dict) else getattr(c, "type", None)
        if eco:
            kinds.add(eco.lower())
        if typ:
            kinds.add(typ.lower())

        # Provenance present
        prov = c.get("provenance") if isinstance(c, dict) else getattr(c, "provenance", None)
        assert prov, f"Missing provenance for component {c}"

    expected_categories = {"python", "pypi", "node", "npm", "container", "image", "serverless", "lambda", "mobile", "android", "gradle"}
    assert kinds.intersection({"python", "pypi"}), "Python components not captured"
    assert kinds.intersection({"node", "npm"}), "Node.js components not captured"
    assert kinds.intersection({"container", "image"}), "Container image components not captured"
    assert kinds.intersection({"serverless", "lambda"}), "Serverless layer components not captured"
    assert kinds.intersection({"mobile", "android", "gradle"}), "Mobile package components not captured"

    # Formats
    outputs = _get(result, "outputs") or {}
    if isinstance(outputs, list):
        outputs = {o.get("format"): o for o in outputs if isinstance(o, dict)}
    assert any("cyclonedx" in k.lower() for k in (outputs.keys() or [])), "CycloneDX output missing"
    assert any("spdx" in k.lower() for k in (outputs.keys() or [])), "SPDX output missing"

    # SLSA L3 policy checks pass
    policy = _get(result, "policy") or {}
    slsa_info = policy.get("slsa") if isinstance(policy, dict) else getattr(policy, "slsa", None)
    level = (slsa_info or {}).get("level") if isinstance(slsa_info, dict) else getattr(slsa_info, "level", None)
    passed = (slsa_info or {}).get("passed") if isinstance(slsa_info, dict) else getattr(slsa_info, "passed", None)
    assert (level is None or int(level) >= 3) and (passed in (None, True)), "SLSA L3 policy checks did not pass"


def test_reproducible_build_non_deterministic_timestamps(scg_module, guardian, monkeypatch, tmp_path):
    # Find API
    target = None
    owner = None
    names = ["verify_reproducible_build", "rebuild_and_compare", "check_reproducibility"]
    if guardian is not None:
        target = _find_callable(guardian, names)
        owner = guardian
    if target is None:
        target = _find_callable(scg_module, names)
        owner = scg_module
    if target is None:
        pytest.skip("Reproducible build verification API not found")

    # Create two artifacts differing only by timestamps
    artifact1 = tmp_path / "artifact_v1.tar"
    artifact2 = tmp_path / "artifact_v2.tar"
    # Simulate archived metadata with timestamps by writing content with different ts markers
    artifact1.write_text("fileA:content\nTS:1700000000\n")
    artifact2.write_text("fileA:content\nTS:1700000100\n")

    # If the tool calls external comparator, monkeypatch to simulate detection of timestamp-only diffs
    for fname in ["compare_artifacts", "bitwise_compare", "diff_artifacts"]:
        if hasattr(scg_module, fname):
            def fake_diff(a, b, *args, **kwargs):
                return {
                    "equal": False,
                    "diffs": [{"path": "metadata/timestamp", "reason": "non-deterministic timestamp", "severity": "medium"}],
                    "hint": "Normalize timestamps via SOURCE_DATE_EPOCH",
                }
            monkeypatch.setattr(scg_module, fname, fake_diff)

    # Call API
    result = None
    try:
        result = target(str(artifact1), str(artifact2), hermetic=True)
    except TypeError:
        # Try kwargs only
        result = target(original=str(artifact1), rebuilt=str(artifact2), hermetic=True)

    # Assertions
    non_det = _get(result, "non_deterministic", None)
    diffs = _get(result, "diffs", None) or _get(result, "differences", None)
    hints = _get(result, "hints", None) or []
    if isinstance(hints, str):
        hints = [hints]
    assert non_det is True or (diffs and any("timestamp" in json.dumps(d).lower() for d in diffs)), "Non-determinism due to timestamps not detected"
    # Root-cause hints should mention timestamp normalization
    hint_text = " ".join([json.dumps(h) if isinstance(h, (dict, list)) else str(h) for h in hints]) + " " + json.dumps(diffs or [])
    assert "timestamp" in hint_text.lower() or "source_date_epoch" in hint_text.lower(), "Missing diff-based root-cause hints for timestamps"


def test_transparency_log_mirror_tamper_detection(scg_module, guardian, monkeypatch, tmp_path):
    # Find API
    target = None
    owner = None
    names = ["verify_transparency_log", "audit_transparency_log", "check_tlog_mirror"]
    if guardian is not None:
        target = _find_callable(guardian, names)
        owner = guardian
    if target is None:
        target = _find_callable(scg_module, names)
        owner = scg_module
    if target is None:
        pytest.skip("Transparency log audit API not found")

    # Create a fake mirror state that simulates tampering (missing entries)
    mirror_state = {"mirror_url": "http://127.0.0.1:5050", "tampered": True}

    # If the tool uses a Rekor client internally, our injected fake rekor.Client.audit_mirror will surface inconsistencies

    # Call API
    try:
        result = target(mirror_state)
    except TypeError:
        result = target(state=mirror_state)

    alerts = _get_alerts(result)
    assert alerts, "No alerts produced for transparency log tampering"
    assert _has_issue(alerts, kind="transparency", severity="high"), "Tamper-evident verification should raise high severity"
    # Merkle proof inconsistencies should be part of the alert message
    assert _has_issue(alerts, kind="transparency", contains="merkle"), "Alert should mention Merkle proof inconsistencies"