import hashlib
import io
import json
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytest

# Import the tool under test
from tools.supply_chain import sbom_sentinel


@dataclass
class FakeRekor:
    should_verify: bool = True
    entries: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.entries is None:
            self.entries = []

    def upload(self, signature_bundle: Dict[str, Any]) -> Dict[str, Any]:
        entry = {
            "logIndex": len(self.entries),
            "uuid": hashlib.sha256(json.dumps(signature_bundle, sort_keys=True).encode()).hexdigest()[:16],
            "integratedTime": 1720000000 + len(self.entries),
            "body": signature_bundle,
        }
        self.entries.append(entry)
        return entry

    def verify_inclusion(self, entry: Dict[str, Any], signature_bundle: Dict[str, Any]) -> bool:
        if not self.should_verify:
            return False
        # Basic integrity: body matches bundle digest
        body = entry.get("body", {})
        return body == signature_bundle


@dataclass
class FakeCosign:
    should_verify_identity: bool = True
    identity_subject: str = "https://issuer.example/subject@repo"
    cert_chain_ok: bool = True
    timestamp_ok: bool = True

    def sign(self, payload: bytes, identity: Optional[str] = None) -> Dict[str, Any]:
        payload_digest = hashlib.sha256(payload).hexdigest()
        # Create a deterministic signature bundle
        bundle = {
            "signature": hashlib.sha256((payload_digest + "|sig").encode()).hexdigest(),
            "cert": f"CN={self.identity_subject}",
            "certChain": "ok" if self.cert_chain_ok else "invalid",
            "timestamp": 1720000000 if self.timestamp_ok else 0,
            "payloadDigest": payload_digest,
        }
        return bundle

    def verify(self, bundle: Dict[str, Any], expected_identity: Optional[str] = None) -> bool:
        if not self.cert_chain_ok or not self.timestamp_ok:
            return False
        if expected_identity is not None:
            if not self.should_verify_identity:
                return False
            return expected_identity == self.identity_subject
        return True


class FakeSandbox:
    def __init__(self):
        self.calls: List[Dict[str, Any]] = []
        self.allowed_hosts: Set[str] = set()
        self.network_locked: bool = True
        self.content_addressed_cache: bool = True
        self.source_allowlist: Optional[List[str]] = None
        self.env_digest = hashlib.sha256(b"fake-env").hexdigest()
        self.toolchain_digest = hashlib.sha256(b"python3.11|pip23.1").hexdigest()
        self.non_deterministic_toggle = False

    def _record_call(self, **kwargs):
        self.calls.append(kwargs)

    def build(self, repo_path: str, *, allow_network_hosts=None, network_locked=True, sources_allowlist=None, content_addressed_cache=True, **kwargs):
        self.allowed_hosts = set(allow_network_hosts or [])
        self.network_locked = network_locked
        self.source_allowlist = list(sources_allowlist or [])
        self.content_addressed_cache = bool(content_addressed_cache)
        self._record_call(operation="build", repo_path=repo_path, network_locked=network_locked, allow_network_hosts=self.allowed_hosts, sources_allowlist=self.source_allowlist, content_addressed_cache=self.content_addressed_cache)

        # Simulate content-addressed outputs: digest of all repo files
        repo = Path(repo_path)
        file_digests = []
        for p in sorted([p for p in repo.rglob("*") if p.is_file()]):
            rel = p.relative_to(repo)
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            file_digests.append((str(rel), h))
        sb = io.StringIO()
        for rel, h in file_digests:
            sb.write(f"{rel}:{h}\n")
        outputs_digest = hashlib.sha256(sb.getvalue().encode()).hexdigest()

        if self.non_deterministic_toggle:
            # flip one bit to simulate non-determinism
            outputs_digest = hashlib.sha256((sb.getvalue() + "|jitter").encode()).hexdigest()

        artefacts = {
            "artefact_digest": outputs_digest,
            "files": file_digests,
            "env_digest": self.env_digest,
            "toolchain_digest": self.toolchain_digest,
        }
        return artefacts

    # Allow alternative method name some implementations might use
    def run(self, *args, **kwargs):
        return self.build(*args, **kwargs)


@pytest.fixture
def fake_cosign():
    return FakeCosign()


@pytest.fixture
def fake_rekor():
    return FakeRekor()


@pytest.fixture
def fake_sandbox():
    return FakeSandbox()


@pytest.fixture(autouse=True)
def block_non_localhost_network(monkeypatch):
    # Block all outbound network except localhost/127.0.0.1
    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        host, port = address
        if host not in ("127.0.0.1", "localhost"):
            raise ConnectionRefusedError(f"Outbound network blocked in tests: {host}:{port}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield


def write_requirements(repo: Path, lines: List[str]):
    (repo / "requirements.txt").write_text("\n".join(lines), encoding="utf-8")


def write_python_package(repo: Path, name: str = "pkg", version: str = "0.1.0"):
    (repo / name).mkdir(parents=True, exist_ok=True)
    (repo / name / "__init__.py").write_text(f"__version__ = '{version}'\n", encoding="utf-8")
    (repo / "setup.cfg").write_text("[metadata]\nname = pkg\nversion = 0.1.0\n", encoding="utf-8")


def make_native_binary(repo: Path, relpath: str):
    p = repo / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x7fELF\x02\x01\x01")  # ELF magic header


def digest_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest_json(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def assert_cyclonedx(sbom: Dict[str, Any]):
    assert isinstance(sbom, dict)
    assert sbom.get("bomFormat") == "CycloneDX", "SBOM must be CycloneDX"
    assert "components" in sbom and isinstance(sbom["components"], list)


def assert_slsa3(attestation: Dict[str, Any]):
    assert isinstance(attestation, dict)
    # Accept keys that clearly indicate SLSA v3 and materials references
    slsa_version = attestation.get("slsaVersion") or attestation.get("slsa_version") or attestation.get("slsa")
    assert str(slsa_version).endswith("3") or slsa_version in ("3", 3, "v3", "SLSA-3")
    mats = attestation.get("materials") or {}
    assert "inputs" in mats and "toolchains" in mats and "environment" in mats
    env = mats["environment"]
    assert "digest" in env and isinstance(env["digest"], str) and len(env["digest"]) >= 16


@pytest.fixture
def sentinel(fake_cosign, fake_rekor, fake_sandbox):
    # Construct the SBOMSentinel with dependency injection for external services and sandbox
    # The SBOMSentinel is expected to accept these as keyword args; if not, implementation should be adapted to tests.
    sentinel = sbom_sentinel.SBOMSentinel(
        cosign_client=fake_cosign,
        rekor_client=fake_rekor,
        sandbox_runner=fake_sandbox,
        allow_network_hosts={"127.0.0.1", "localhost"},
        source_allowlist=["."],
        oidc_expected_identity=fake_cosign.identity_subject,
    )
    return sentinel


def test_typosquat_pipeline_halts_and_emits_signed_cyclonedx_sbom_with_vex_and_rekor(tmp_path: Path, sentinel: Any, fake_rekor: FakeRekor, fake_cosign: FakeCosign, fake_sandbox: FakeSandbox):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_python_package(repo)
    # Include a typosquat 'reqeusts' alongside legitimate 'requests'
    write_requirements(repo, ["requests==2.31.0", "reqeusts==1.0.0"])
    # Provide known false positives to be annotated as VEX notes (e.g., CVE that doesn't affect this env)
    vex_fp = [{"id": "CVE-2023-0000", "status": "not_affected", "note": "False positive in environment"}]

    # Run the pipeline analysis
    result = sentinel.run_pipeline(str(repo), release_tag="v0.1.0", vex_false_positives=vex_fp)

    # The tool should halt due to suspicious package
    assert result.halted is True
    assert any("typosquat" in r.lower() or "look-alike" in r.lower() for r in result.reasons)

    # Evidence includes the suspicious package name with context
    suspicious = result.evidence.get("suspicious_packages") or []
    assert any(pkg.get("name") == "reqeusts" and "typosquat" in (pkg.get("reason", "")).lower() for pkg in suspicious)

    # SBOM is CycloneDX and includes VEX notes
    assert_cyclonedx(result.sbom)
    vex_notes = getattr(result, "vex_notes", None) or result.sbom.get("vulnerabilities", [])
    assert len(vex_notes) >= 1
    assert any((vn.get("id") == "CVE-2023-0000" or vn.get("cve") == "CVE-2023-0000") for vn in vex_notes)

    # SBOM/provenance signed with cosign; signatures and Rekor inclusion verified
    sig_bundle = result.signatures.get("cosign")
    assert isinstance(sig_bundle, dict) and "signature" in sig_bundle and "payloadDigest" in sig_bundle
    assert fake_cosign.verify(sig_bundle, expected_identity=sentinel.oidc_expected_identity) is True

    rekor_entry = result.signatures.get("rekor_entry") or result.evidence.get("rekor_entry")
    assert isinstance(rekor_entry, dict) and "logIndex" in rekor_entry
    assert fake_rekor.verify_inclusion(rekor_entry, sig_bundle) is True

    # Identity claims were validated; cert chain and timestamp checks enforced
    assert result.identity_verified is True
    assert result.certificate_chain_ok is True
    assert result.timestamp_verified is True

    # Hermetic build was requested inside a network-locked sandbox; only localhost allowed
    assert fake_sandbox.network_locked is True
    assert fake_sandbox.content_addressed_cache is True
    assert fake_sandbox.allowed_hosts.issubset({"127.0.0.1", "localhost"})


def test_deterministic_diff_and_fail_closed_on_added_unsigned_native_binary_and_deterministic_rerun(tmp_path: Path, sentinel: Any, fake_sandbox: FakeSandbox):
    repo = tmp_path / "repo2"
    repo.mkdir()
    write_python_package(repo, name="pkg2", version="1.0.0")
    write_requirements(repo, ["requests==2.31.0"])

    # First release v1.0.0
    res_v1 = sentinel.run_pipeline(str(repo), release_tag="v1.0.0")
    assert res_v1.halted is False, f"Baseline release should not halt: {res_v1.reasons}"
    assert_cyclonedx(res_v1.sbom)
    assert_slsa3(res_v1.provenance)
    sbom_digest_v1 = res_v1.digests.get("sbom")
    att_digest_v1 = res_v1.digests.get("attestation")
    assert isinstance(sbom_digest_v1, str) and isinstance(att_digest_v1, str)

    # Second release v1.1.0 adds unsigned native binary without source
    write_python_package(repo, name="pkg2", version="1.1.0")
    make_native_binary(repo, "bin/badnative")
    res_v11 = sentinel.run_pipeline(str(repo), release_tag="v1.1.0", previous_release_result=res_v1)

    # Integrity checks fail closed; build blocked; diff highlights added native binary lacking source/signature
    assert res_v11.halted is True
    assert any("native" in r.lower() or "binary" in r.lower() for r in res_v11.reasons)
    diff = getattr(res_v11, "diff", None) or res_v11.evidence.get("diff")
    assert isinstance(diff, dict)
    added = diff.get("added") or diff.get("added_components") or []
    assert any(isinstance(a, dict) and a.get("path", "").endswith("bin/badnative") for a in added)

    # Rerunning full pipeline yields identical SBOM and attestation digests (deterministic)
    res_v11_rerun = sentinel.run_pipeline(str(repo), release_tag="v1.1.0", previous_release_result=res_v1)
    assert res_v11_rerun.digests.get("sbom") == res_v11.digests.get("sbom")
    assert res_v11_rerun.digests.get("attestation") == res_v11.digests.get("attestation")

    # Hermetic sandbox enforced
    assert fake_sandbox.network_locked is True
    assert fake_sandbox.content_addressed_cache is True


def test_fail_closed_on_rekor_inclusion_failure(tmp_path: Path, fake_rekor: FakeRekor, fake_cosign: FakeCosign, fake_sandbox: FakeSandbox):
    repo = tmp_path / "repo3"
    repo.mkdir()
    write_python_package(repo, name="pkg3", version="0.0.1")
    write_requirements(repo, ["urllib3==2.2.0"])

    # Create sentinel with a rekor client that fails verification
    failing_rekor = FakeRekor(should_verify=False)
    sentinel = sbom_sentinel.SBOMSentinel(
        cosign_client=fake_cosign,
        rekor_client=failing_rekor,
        sandbox_runner=fake_sandbox,
        allow_network_hosts={"127.0.0.1", "localhost"},
        source_allowlist=["."],
        oidc_expected_identity=fake_cosign.identity_subject,
    )

    res = sentinel.run_pipeline(str(repo), release_tag="v0.0.1")
    assert res.halted is True
    assert any("rekor" in r.lower() and ("fail" in r.lower() or "include" in r.lower()) for r in res.reasons)


def test_fail_closed_on_oidc_identity_mismatch(tmp_path: Path, fake_rekor: FakeRekor, fake_sandbox: FakeSandbox):
    repo = tmp_path / "repo4"
    repo.mkdir()
    write_python_package(repo, name="pkg4", version="0.0.2")
    write_requirements(repo, ["certifi==2024.2.2"])

    mismatched_cosign = FakeCosign(should_verify_identity=False, identity_subject="https://issuer.example/wrong@actor")
    sentinel = sbom_sentinel.SBOMSentinel(
        cosign_client=mismatched_cosign,
        rekor_client=fake_rekor,
        sandbox_runner=fake_sandbox,
        allow_network_hosts={"127.0.0.1", "localhost"},
        source_allowlist=["."],
        oidc_expected_identity="https://issuer.example/subject@repo",
    )
    res = sentinel.run_pipeline(str(repo), release_tag="v0.0.2")
    assert res.halted is True
    assert any("oidc" in r.lower() or "identity" in r.lower() for r in res.reasons)


def test_fail_closed_on_non_reproducible_build_outputs(tmp_path: Path, fake_rekor: FakeRekor, fake_cosign: FakeCosign):
    repo = tmp_path / "repo5"
    repo.mkdir()
    write_python_package(repo, name="pkg5", version="0.3.0")
    write_requirements(repo, ["idna==3.7"])

    # Sandbox that returns non-deterministic artefact digest between runs
    jitter_sandbox = FakeSandbox()
    jitter_sandbox.non_deterministic_toggle = True

    sentinel = sbom_sentinel.SBOMSentinel(
        cosign_client=fake_cosign,
        rekor_client=fake_rekor,
        sandbox_runner=jitter_sandbox,
        allow_network_hosts={"127.0.0.1", "localhost"},
        source_allowlist=["."],
        oidc_expected_identity=fake_cosign.identity_subject,
    )

    res1 = sentinel.run_pipeline(str(repo), release_tag="v0.3.0")
    res2 = sentinel.run_pipeline(str(repo), release_tag="v0.3.0")
    # When non-deterministic, the tool should detect and fail closed
    assert res1.halted is True or res2.halted is True
    assert any("non-reproducible" in r.lower() or "ambigu" in r.lower() for r in (res1.reasons + res2.reasons))

    # Ensure SLSA attestation references environment/toolchain digests despite failure
    assert_slsa3(res1.provenance if hasattr(res1, "provenance") and res1.provenance else res2.provenance)