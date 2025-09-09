import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

try:
    from tools.ai_security import toolforge_auditor as auditor_mod
except Exception as e:
    auditor_mod = None


@pytest.fixture(autouse=True)
def require_module():
    if auditor_mod is None:
        pytest.skip("tools.ai_security.toolforge_auditor module not available")


class FakeSigstoreClient:
    def __init__(self, *args, **kwargs):
        self.trusted_keys = kwargs.get("trusted_keys", set())

    def verify_signature(self, artifact_path: str, public_key: str) -> Dict[str, Any]:
        # Always verify successfully if key appears trusted-like
        return {
            "verified": True,
            "rekor_inclusion": True,
            "signer": "trusted-signer@example.com",
            "cert_chain_verified": True,
        }


def fake_cosign_verify(artifact_path: str, public_key: str) -> bool:
    return True


class FakeRekorClient:
    def __init__(self, *args, **kwargs):
        pass

    def verify_inclusion(self, artifact_path: str) -> Dict[str, Any]:
        return {
            "included": True,
            "logIndex": 12345,
            "uuid": "rekor-entry-uuid",
            "inclusionProof": {"hash": "deadbeef"},
        }

    def get_entry(self, *args, **kwargs):
        return {"uuid": "rekor-entry-uuid", "logIndex": 12345}


class FakeSBOMGenerator:
    def __init__(self, *args, **kwargs):
        pass

    def generate_spdx(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        components = []
        for dep in manifest.get("dependencies", []):
            name = dep.get("name") or dep.split("==")[0]
            version = dep.get("version")
            if isinstance(dep, str):
                components.append({"name": name, "versionInfo": dep})
            else:
                components.append({"name": name, "versionInfo": version or "UNPINNED"})
        return {"SPDXID": "SPDXRef-DOCUMENT", "packages": components}

    def generate_cyclonedx(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        components = []
        for dep in manifest.get("dependencies", []):
            name = dep.get("name") if isinstance(dep, dict) else dep.split("==")[0]
            version = (
                dep.get("version")
                if isinstance(dep, dict)
                else (dep.split("==")[1] if "==" in dep else None)
            )
            components.append({"name": name, "version": version})
        return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}

    def diff(self, base: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        return {"diff": "example-diff", "added": current.get("components") or current.get("packages")}

    def correlate_vulnerabilities(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        return {"vulnerabilities": []}


def fake_generate_sbom(manifest: Dict[str, Any]) -> Dict[str, Any]:
    gen = FakeSBOMGenerator()
    return {
        "spdx": gen.generate_spdx(manifest),
        "cyclonedx": gen.generate_cyclonedx(manifest),
    }


class FakeEBPFTracer:
    def __init__(self, *args, **kwargs):
        self._events = []
        self._started = False

    def start(self):
        self._started = True

    def stop(self):
        self._started = False

    def get_events(self):
        # Simulate a blocked outbound DNS lookup and HTTP connect
        return [
            {
                "type": "dns",
                "query": "bad.example",
                "timestamp": 1699999999,
                "blocked": True,
                "evidence": {"stack": ["socketcall", "connect"]},
            },
            {
                "type": "connect",
                "dst": "1.2.3.4",
                "port": 80,
                "protocol": "tcp",
                "timestamp": 1700000000,
                "blocked": True,
                "evidence": {"cgroup": "sandbox-123", "pid": 4242},
            },
        ]


class FakeSignedArtifact:
    def __init__(self, path: Path, payload: Dict[str, Any]):
        self.path = path
        self.payload = payload
        self.signature = "FAKE_SIGNATURE"
        self.signed = True


class FakeAttestor:
    def __init__(self, *args, **kwargs):
        self.last_payload = None
        self.redacted = False

    def sign(self, payload: Dict[str, Any], redact_secrets: bool = True, artifact_type: str = "attestation"):
        # Redact any secrets-looking keys
        redacted_payload = json.loads(json.dumps(payload))
        def redact(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(s in k.lower() for s in ("secret", "token", "key", "password")):
                        obj[k] = "REDACTED"
                    else:
                        redact(v)
            elif isinstance(obj, list):
                for i in obj:
                    redact(i)
        if redact_secrets:
            redact(redacted_payload)
            self.redacted = True
        self.last_payload = redacted_payload
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f".{artifact_type}.json", prefix="attest-")
        with open(tmp.name, "w") as f:
            json.dump({"payload": redacted_payload, "signature": "FAKE_SIGNATURE"}, f)
        return FakeSignedArtifact(Path(tmp.name), redacted_payload)


class FakeSandbox:
    def __init__(self, *args, **kwargs):
        self.allowed_endpoints = set(kwargs.get("allowlist", []))
        self.ro_mounts = True
        self.seccomp = True
        self.apparmor = True
        self._blocked_events = []

    def run(self, command: Any, env: Optional[Dict[str, str]] = None, timeout: int = 30):
        # Simulate blocked network event
        self._blocked_events.append({"dst": "1.2.3.4:80", "reason": "not in allowlist", "blocked": True})
        return {"exit_code": 0, "blocked": True, "stdout": "", "stderr": ""}

    def blocked_events(self):
        return list(self._blocked_events)


@pytest.fixture
def patch_external_clients(monkeypatch):
    # Sigstore/cosign
    monkeypatch.setattr(auditor_mod, "SigstoreClient", FakeSigstoreClient, raising=False)
    monkeypatch.setattr(auditor_mod, "CosignClient", FakeSigstoreClient, raising=False)
    monkeypatch.setattr(auditor_mod, "cosign_verify", fake_cosign_verify, raising=False)
    monkeypatch.setattr(auditor_mod, "sigstore_verify", fake_cosign_verify, raising=False)
    # Rekor
    monkeypatch.setattr(auditor_mod, "RekorClient", FakeRekorClient, raising=False)
    # SBOM
    monkeypatch.setattr(auditor_mod, "SBOMGenerator", FakeSBOMGenerator, raising=False)
    monkeypatch.setattr(auditor_mod, "generate_sbom", fake_generate_sbom, raising=False)
    monkeypatch.setattr(auditor_mod, "generate_spdx", FakeSBOMGenerator().generate_spdx, raising=False)
    monkeypatch.setattr(auditor_mod, "generate_cyclonedx", FakeSBOMGenerator().generate_cyclonedx, raising=False)
    # Attestor
    monkeypatch.setattr(auditor_mod, "Attestor", FakeAttestor, raising=False)
    monkeypatch.setattr(auditor_mod, "InTotoAttestor", FakeAttestor, raising=False)
    # eBPF tracer and sandbox
    monkeypatch.setattr(auditor_mod, "EBPFTracer", FakeEBPFTracer, raising=False)
    monkeypatch.setattr(auditor_mod, "Sandbox", FakeSandbox, raising=False)


def resolve_auditor_instance():
    cls_names = [
        "ToolForgeAuditor",
        "Auditor",
        "ToolForgeAudit",
        "AuditEngine",
    ]
    inst = None
    for name in cls_names:
        cls = getattr(auditor_mod, name, None)
        if cls:
            try:
                inst = cls()
            except TypeError:
                try:
                    inst = cls({})
                except Exception:
                    continue
            break
    return inst


def call_audit_manifest(auditor, manifest: Dict[str, Any]):
    # Try instance methods first
    candidates = [
        "audit_manifest",
        "audit_tool",
        "audit",
        "audit_dependencies",
    ]
    for name in candidates:
        fn = getattr(auditor, name, None)
        if callable(fn):
            return fn(manifest)
    # Try module-level
    for name in candidates:
        fn = getattr(auditor_mod, name, None)
        if callable(fn):
            return fn(manifest)
    pytest.skip("No audit_manifest-like function available")


def call_dynamic_analysis(auditor, manifest: Dict[str, Any], tool_cmd: Any = None):
    candidates = [
        "run_dynamic_analysis",
        "dynamic_analysis",
        "analyze_dynamic",
        "sandbox_analysis",
    ]
    for name in candidates:
        fn = getattr(auditor, name, None)
        if callable(fn):
            return fn(tool_cmd or ["true"], manifest)
    for name in candidates:
        fn = getattr(auditor_mod, name, None)
        if callable(fn):
            return fn(tool_cmd or ["true"], manifest)
    pytest.skip("No dynamic analysis function available")


def call_verify_release(auditor, artifact_path: str, public_key: str, manifest: Dict[str, Any]):
    candidates = [
        "verify_release",
        "supply_chain_verify",
        "verify_and_attest",
        "verify",
    ]
    for name in candidates:
        fn = getattr(auditor, name, None)
        if callable(fn):
            return fn(artifact_path, public_key, manifest)
    for name in candidates:
        fn = getattr(auditor_mod, name, None)
        if callable(fn):
            return fn(artifact_path, public_key, manifest)
    pytest.skip("No release verification function available")


def result_to_dict(result):
    if result is None:
        return {}
    if isinstance(result, dict):
        return result
    # Try dataclass or simple object
    try:
        d = dict(result)
        return d
    except Exception:
        pass
    try:
        return {k: getattr(result, k) for k in dir(result) if not k.startswith("_")}
    except Exception:
        return {"value": result}


def get_pass_status(result_dict: Dict[str, Any]) -> Optional[bool]:
    for key in ("policy_passed", "passed", "ok", "success"):
        if key in result_dict:
            return bool(result_dict[key])
    status = result_dict.get("status")
    if status is not None:
        if isinstance(status, str):
            return status.lower() in ("pass", "passed", "ok", "success", "succeeded")
        return bool(status)
    return None


def get_field(result_dict: Dict[str, Any], names):
    for name in names:
        if name in result_dict:
            return result_dict[name]
    return None


@pytest.mark.usefixtures("patch_external_clients")
def test_unpinned_dependency_policy_failure():
    auditor = resolve_auditor_instance()
    if not auditor:
        pytest.skip("No auditor class available")

    manifest = {
        "name": "example-tool",
        "version": "0.1.0",
        "dependencies": [
            {"name": "requests", "version": ">=2.28"},  # unpinned
            {"name": "numpy", "version": "==1.24.3"},   # pinned
        ],
        "sandbox": {
            "fs": {"readonly": True},
            "network": {"allow": ["127.0.0.1"]},
            "seccomp": True,
            "apparmor": True,
        },
    }

    result = call_audit_manifest(auditor, manifest)
    rd = result_to_dict(result)
    status = get_pass_status(rd)
    assert status is False, f"Policy should fail for unpinned dependency, got: {status}, details: {rd}"

    # Must include SBOM info and diff
    sbom = get_field(rd, ["sbom", "sbom_spdx", "spdx"])
    cyclonedx = get_field(rd, ["sbom_cyclonedx", "cyclonedx"])
    assert sbom is not None or cyclonedx is not None, "SBOM should be present in audit results"

    diff = get_field(rd, ["sbom_diff", "diff"])
    assert diff is not None, "SBOM diff should be included for remediation context"

    remediation = get_field(rd, ["remediation", "suggestions", "actions"])
    assert remediation is not None, "Remediation guidance should be provided"
    remediation_text = json.dumps(remediation) if not isinstance(remediation, str) else remediation
    assert "pin" in remediation_text.lower() or "==" in remediation_text, "Remediation should advise exact version pinning"
    assert "requests" in remediation_text, "Remediation should reference the offending dependency"


@pytest.mark.usefixtures("patch_external_clients")
def test_dynamic_analysis_blocks_unexpected_network_and_emits_signed_incident(tmp_path):
    auditor = resolve_auditor_instance()
    if not auditor:
        pytest.skip("No auditor class available")

    manifest = {
        "name": "net-tool",
        "version": "1.2.3",
        "sandbox": {
            "fs": {"readonly": True},
            "network": {"allow": ["127.0.0.1"]},  # strict allowlist
            "seccomp": True,
            "apparmor": True,
            "trace": {"ebpf": True},
        },
    }

    # Simulate tool command that would attempt HTTP to disallowed address; the sandbox mock will handle this
    tool_cmd = ["curl", "http://1.2.3.4/health"]

    result = call_dynamic_analysis(auditor, manifest, tool_cmd)
    rd = result_to_dict(result)

    # Sandbox must block unexpected outbound
    blocked = get_field(rd, ["blocked", "network_blocked", "policy_violation"])
    # If not a direct flag, infer from events
    events = get_field(rd, ["events", "ebpf_events", "evidence"]) or []
    if blocked is None:
        blocked = any(
            (isinstance(e, dict) and e.get("blocked"))
            or (isinstance(e, dict) and e.get("type") in ("dns", "connect") and e.get("blocked") is True)
            for e in (events if isinstance(events, list) else [events])
        )
    assert blocked, f"Sandbox should block unexpected outbound network; result: {rd}"

    # eBPF evidence must be recorded
    assert events, "eBPF events/evidence should be present"
    # check at least one connect/dns event
    ev_json = json.dumps(events)
    assert "connect" in ev_json or "dns" in ev_json, "Expected connect or DNS event in eBPF evidence"

    # Signed incident bundle should be produced
    incident = get_field(rd, ["incident_bundle", "incident", "signed_incident"])
    assert incident is not None, "Signed incident bundle should be present"

    # Validate that the incident is tamper-evident by containing a signature
    incident_json = json.dumps(incident) if not isinstance(incident, str) else incident
    assert "signature" in incident_json.lower() or "signed" in incident_json.lower(), "Incident bundle should be signed"

    # Check that secrets are redacted in incident if any environment provided
    env_with_secret = {"API_KEY": "supersecret"}
    manifest_with_secret = {**manifest, "env": env_with_secret}
    result2 = call_dynamic_analysis(auditor, manifest_with_secret, tool_cmd)
    rd2 = result_to_dict(result2)
    inc2 = get_field(rd2, ["incident_bundle", "incident", "signed_incident"])
    inc2_text = json.dumps(inc2) if not isinstance(inc2, str) else inc2
    assert "supersecret" not in inc2_text
    assert "REDACTED" in inc2_text


@pytest.mark.usefixtures("patch_external_clients")
def test_signed_release_verified_rekor_sbom_and_attested(tmp_path):
    auditor = resolve_auditor_instance()
    if not auditor:
        pytest.skip("No auditor class available")

    artifact = tmp_path / "release.tar.gz"
    artifact.write_bytes(b"fake-archive-contents")

    public_key = "-----BEGIN PUBLIC KEY-----\nFAKEKEY\n-----END PUBLIC KEY-----\n"

    manifest = {
        "name": "signed-tool",
        "version": "2.0.0",
        "dependencies": [
            {"name": "urllib3", "version": "==2.2.1"},
            {"name": "pydantic", "version": "==2.8.0"},
        ],
        "sandbox": {
            "fs": {"readonly": True},
            "network": {"allow": ["127.0.0.1"]},
            "seccomp": True,
            "apparmor": True,
        },
    }

    result = call_verify_release(auditor, str(artifact), public_key, manifest)
    rd = result_to_dict(result)

    # Verification should pass and Rekor inclusion confirmed
    status = get_pass_status(rd)
    assert status is True, f"Supply-chain verification should pass, got: {status}, details: {rd}"
    rekor = get_field(rd, ["rekor", "rekor_inclusion", "transparency_log"])
    if rekor is not None and isinstance(rekor, dict):
        assert rekor.get("included", True) or rekor.get("rekor_inclusion", True)

    # SBOMs generated
    spdx = get_field(rd, ["sbom_spdx", "spdx", "sbom"])
    cdx = get_field(rd, ["sbom_cyclonedx", "cyclonedx"])
    assert spdx is not None, "SPDX SBOM should be generated"
    assert cdx is not None, "CycloneDX SBOM should be generated"

    # Signed attestation artifact present
    att = get_field(rd, ["attestation", "signed_attestation", "in_toto_attestation"])
    assert att is not None, "Signed attestation should be present"
    att_text = json.dumps(att) if not isinstance(att, str) else att
    assert "signature" in att_text.lower() or "signed" in att_text.lower(), "Attestation should be signed and tamper-evident"


@pytest.mark.usefixtures("patch_external_clients")
def test_invalid_manifest_raises_or_reports_error():
    auditor = resolve_auditor_instance()
    if not auditor:
        pytest.skip("No auditor class available")

    invalid_manifest = {
        "name": "broken-tool",
        # missing version and dependencies
        "sandbox": {"network": {"allow": ["127.0.0.1"]}},
    }

    # Accept either raising a ValueError/Exception or embedding an error in the result
    try:
        res = call_audit_manifest(auditor, invalid_manifest)
    except (ValueError, TypeError, KeyError) as e:
        assert True
        return
    rd = result_to_dict(res)
    err = get_field(rd, ["error", "errors", "exception"])
    assert err is not None, "Invalid manifest should produce an error in result if not raising"
    err_text = json.dumps(err) if not isinstance(err, str) else err
    assert "invalid" in err_text.lower() or "manifest" in err_text.lower() or "missing" in err_text.lower()


@pytest.mark.usefixtures("patch_external_clients")
def test_credentials_not_persisted_and_redacted_in_attestation(tmp_path):
    auditor = resolve_auditor_instance()
    if not auditor:
        pytest.skip("No auditor class available")

    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"fake")

    public_key = "-----BEGIN PUBLIC KEY-----\nFAKEKEY\n-----END PUBLIC KEY-----\n"
    manifest = {
        "name": "cred-tool",
        "version": "0.0.1",
        "dependencies": [{"name": "requests", "version": "==2.31.0"}],
        "env": {"SECRET_TOKEN": "should_not_leak"},
    }

    # Run verification to generate attestation
    result = call_verify_release(auditor, str(artifact), public_key, manifest)
    rd = result_to_dict(result)

    att = get_field(rd, ["attestation", "signed_attestation", "in_toto_attestation"])
    assert att is not None
    att_text = json.dumps(att) if not isinstance(att, str) else att
    assert "should_not_leak" not in att_text
    assert "REDACTED" in att_text

    # Ensure no credential files persisted in temp dirs
    lingering = []
    for root, _, files in os.walk(str(tmp_path)):
        for f in files:
            p = Path(root) / f
            try:
                content = p.read_text(errors="ignore")
            except Exception:
                continue
            if "should_not_leak" in content:
                lingering.append(str(p))
    assert not lingering, f"Credentials must not be persisted, found in: {lingering}"