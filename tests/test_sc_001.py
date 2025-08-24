import io
import json
import os
import socket
import stat
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tools.supply_chain.sigchain_guardian import SigChainGuardian


@pytest.fixture(autouse=True)
def no_network_except_localhost(monkeypatch):
    # Block all outbound network to non-localhost targets
    real_getaddrinfo = socket.getaddrinfo

    def guarded_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host in (None, "", "localhost", "127.0.0.1", "::1"):
            return real_getaddrinfo(host, port, family, type, proto, flags)
        # For URLs, allow tool to pass through without network, but don't resolve non-local
        raise RuntimeError(f"External network access blocked in tests: {host}")

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo, raising=True)


@pytest.fixture
def guardian(tmp_path):
    return SigChainGuardian(
        registry_config={
            "private": {"name": "private", "url": "http://127.0.0.1:5001", "namespace": "corp"},
            "public": {"name": "public", "url": "http://127.0.0.1:5002", "namespace": "public"},
        },
        policy={"slsa_min_level": 3, "risk_threshold": 0.75},
        mirror_path=str(tmp_path / "tlog_mirror"),
    )


def test_dependency_confusion_block_high_risk_with_remediation(guardian):
    dependency_graph = {
        "root": [{"name": "pkgA", "version_spec": "1.x"}],
        "pkgA": [{"name": "lodash", "version_spec": "^4.0.0"}],
    }

    def fake_resolver(name: str, registry: Dict[str, Any]):
        if name == "lodash" and registry["name"] == "private":
            return {
                "name": "lodash",
                "version": "99.0.0",
                "registry": registry["name"],
                "namespace": "corp",
                "maintainers": ["mal0r"],
                "source_dns": "corp.internal",
                "published_at": "2025-01-01T00:00:00Z",
            }
        if name == "lodash" and registry["name"] == "public":
            return {
                "name": "lodash",
                "version": "4.17.21",
                "registry": registry["name"],
                "namespace": "npm",
                "maintainers": ["lodash-org"],
                "source_dns": "npmjs.localhost",
                "published_at": "2021-02-01T00:00:00Z",
            }
        if name == "pkgA":
            return {
                "name": "pkgA",
                "version": "1.2.3",
                "registry": registry["name"],
                "namespace": "corp" if registry["name"] == "private" else "public",
                "maintainers": ["devteam"],
                "source_dns": "corp.internal",
                "published_at": "2024-10-01T00:00:00Z",
            }
        return None

    result = guardian.audit_dependency_resolution(
        dependency_graph=dependency_graph,
        resolver=fake_resolver,
    )
    assert result.get("blocked") is True
    alerts = result.get("alerts", [])
    assert alerts, "Expected alerts for dependency confusion"
    confusion = [a for a in alerts if a.get("type") == "dependency_confusion"]
    assert confusion, "Dependency confusion alert missing"
    alert = confusion[0]
    assert alert.get("severity") in ("high", "critical")
    assert "shadow" in alert.get("reason", "").lower() or "confusion" in alert.get("reason", "").lower()
    assert any("remediation" in k.lower() for k in alert.keys())
    remediation = alert.get("remediation", "")
    assert any(
        hint in remediation.lower()
        for hint in ("pin source", "namespace", "blocklist", "scope", "vendoring")
    )


def test_dependency_confusion_timeout_is_safe_block(guardian, monkeypatch):
    dependency_graph = {
        "root": [{"name": "pkgA", "version_spec": "1.x"}],
        "pkgA": [{"name": "victim", "version_spec": "~1.0.0"}],
    }

    class Timeout(Exception):
        pass

    def flaky_resolver(name: str, registry: Dict[str, Any]):
        if registry["name"] == "public":
            raise Timeout("timeout")
        return {
            "name": name,
            "version": "1.0.0",
            "registry": registry["name"],
            "namespace": registry["namespace"],
            "maintainers": ["trusted"],
            "source_dns": "127.0.0.1",
            "published_at": "2024-01-01T00:00:00Z",
        }

    result = guardian.audit_dependency_resolution(
        dependency_graph=dependency_graph,
        resolver=flaky_resolver,
    )
    assert result.get("blocked") is True, "Should block on resolver timeout for safety"
    alerts = result.get("alerts", [])
    assert any("timeout" in (a.get("reason", "") + a.get("diagnostic", "")).lower() for a in alerts)


def test_sign_verify_expired_cert_and_bad_rekor_inclusion_blocks_release(guardian, tmp_path):
    artifact = tmp_path / "release.tar.gz"
    artifact.write_bytes(b"fake-binary-contents")

    class FakeSigstoreClient:
        def verify_keyless(self, artifact_path: str):
            return {
                "ok": False,
                "certificate": {
                    "subject": "CN=builder",
                    "issuer": "Fulcio",
                    "expired": True,
                    "not_after": "2024-05-01T00:00:00Z",
                },
                "error": "certificate expired",
            }

    class FakeRekorClient:
        def inclusion_proof(self, artifact_path: str):
            return {
                "ok": False,
                "tree_id": "deadbeef",
                "root_hash": "abc123",
                "error": "inclusion proof verification failed: merkle path mismatch",
            }

    result = guardian.verify_artifact_signatures(
        artifact_path=str(artifact),
        keyless=True,
        enforce_policy=True,
        sigstore_client=FakeSigstoreClient(),
        rekor_client=FakeRekorClient(),
    )
    assert result.get("verified") is False
    assert result.get("rekor_inclusion") is False
    assert result.get("blocked") is True
    diags = " ".join(result.get("diagnostics", []))
    assert "expired" in diags.lower()
    assert "inclusion" in diags.lower()
    assert "merkle" in diags.lower() or "proof" in diags.lower()
    assert "action" in diags.lower() or "remed" in diags.lower()


def test_generate_sbom_polyglot_full_coverage_and_slsa_L3(guardian, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    # Python
    (repo / "requirements.txt").write_text("requests==2.31.0\n")
    # Node.js
    (repo / "package.json").write_text(json.dumps({"name": "webapp", "dependencies": {"axios": "^1.6.0"}}))
    # Container
    (repo / "Dockerfile").write_text("FROM python:3.11-slim\n")
    # Serverless layer
    (repo / "layer").mkdir()
    (repo / "layer" / "requirements.txt").write_text("boto3==1.28.0\n")

    class FakeAnalyzer:
        def analyze(self, repo_path: str) -> List[Dict[str, Any]]:
            return [
                {
                    "type": "python",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    "provenance": {"source": "requirements.txt", "resolver": "pip"},
                },
                {
                    "type": "node",
                    "name": "axios",
                    "version": "1.6.0",
                    "purl": "pkg:npm/axios@1.6.0",
                    "provenance": {"source": "package.json", "resolver": "npm"},
                },
                {
                    "type": "container",
                    "name": "python",
                    "version": "3.11",
                    "purl": "pkg:docker/python@3.11-slim",
                    "provenance": {"source": "Dockerfile", "resolver": "container"},
                },
                {
                    "type": "serverless-layer",
                    "name": "boto3",
                    "version": "1.28.0",
                    "purl": "pkg:pypi/boto3@1.28.0",
                    "provenance": {"source": "layer/requirements.txt", "resolver": "pip"},
                },
            ]

    class FakeAttestor:
        def slsa_check(self, components: List[Dict[str, Any]], min_level: int):
            # Return that we are compliant at level 3
            return {"level": 3, "compliant": True, "details": "meets SLSA L3"}

    result = guardian.generate_sbom(
        repo_path=str(repo),
        formats=("spdx", "cyclonedx"),
        include_provenance=True,
        analyzers=[FakeAnalyzer()],
        attestor=FakeAttestor(),
    )
    assert result.get("formats", {}).get("spdx"), "SPDX document missing"
    assert result.get("formats", {}).get("cyclonedx"), "CycloneDX document missing"
    components = result.get("components", [])
    names = {c["name"] for c in components}
    assert {"requests", "axios", "python", "boto3"}.issubset(names)
    assert all("provenance" in c for c in components)
    coverage = result.get("coverage")
    assert coverage == 1.0 or int(coverage * 100) == 100
    slsa = result.get("slsa", {})
    assert slsa.get("compliant") is True
    assert slsa.get("level", 0) >= 3


def test_reproducible_build_detects_timestamp_nondeterminism(guardian, tmp_path):
    src_artifact = tmp_path / "artifact.bin"
    src_artifact.write_bytes(b"artifact-contents-v1")
    os.chmod(src_artifact, stat.S_IRUSR | stat.S_IWUSR)

    class FakeHermeticBuilder:
        def rebuild(self, artifact_path: str, build_config: Dict[str, Any]):
            # Simulate a rebuild that differs in timestamps only
            time.sleep(0.01)
            return {
                "ok": False,
                "differences": [
                    {
                        "path": "/usr/bin/app",
                        "field": "mtime",
                        "original": "1700000000",
                        "rebuild": str(int(time.time())),
                    }
                ],
                "hints": [
                    "Non-deterministic timestamps detected",
                    "Consider normalizing mtime or setting SOURCE_DATE_EPOCH",
                ],
            }

    result = guardian.verify_reproducible_build(
        artifact_path=str(src_artifact),
        build_config={"hermetic": True},
        builder=FakeHermeticBuilder(),
    )
    assert result.get("reproducible") is False
    diffs = result.get("differences", [])
    assert diffs and any(d.get("field") == "mtime" for d in diffs)
    hints = " ".join(result.get("hints", []))
    assert "timestamp" in hints.lower() or "mtime" in hints.lower()
    assert "source_date_epoch" in hints.lower()


def test_transparency_log_mirror_tamper_detection_merkle_inconsistency(guardian, tmp_path):
    mirror = tmp_path / "tlog_mirror"
    mirror.mkdir()
    (mirror / "log.json").write_text(json.dumps({"entries": [{"uuid": "a"}, {"uuid": "b"}]}))

    class FakeMerkleVerifier:
        def verify(self, mirror_path: str):
            return {
                "ok": False,
                "error": "Merkle proof inconsistency: orphaned leaf detected",
                "inconsistencies": [{"leaf": "b", "reason": "missing path segment"}],
            }

    result = guardian.verify_transparency_log_mirror(
        mirror_path=str(mirror),
        merkle_verifier=FakeMerkleVerifier(),
    )
    assert result.get("ok") is False
    alerts = result.get("alerts", [])
    assert alerts, "Expected alerts from tlog verification"
    msg = " ".join(a.get("message", "") for a in alerts)
    assert "merkle" in msg.lower()
    assert "inconsistenc" in msg.lower() or "tamper" in msg.lower()


def test_sbom_empty_repo_graceful(guardian, tmp_path):
    repo = tmp_path / "empty_repo"
    repo.mkdir()

    class NoopAnalyzer:
        def analyze(self, repo_path: str):
            return []

    class FakeAttestor:
        def slsa_check(self, components: List[Dict[str, Any]], min_level: int):
            return {"level": 0, "compliant": False, "details": "no components"}

    result = guardian.generate_sbom(
        repo_path=str(repo),
        formats=("spdx", "cyclonedx"),
        include_provenance=True,
        analyzers=[NoopAnalyzer()],
        attestor=FakeAttestor(),
    )
    assert result.get("components") == []
    assert result.get("coverage") in (0.0, 0)
    # Even if SLSA not applicable, the tool should not crash; policy may be non-compliant
    slsa = result.get("slsa", {})
    assert slsa.get("compliant") in (False, None)


def test_risk_scoring_diff_triggers_approvals(guardian):
    previous = {
        "components": [
            {"name": "requests", "version": "2.31.0", "maintainers": ["psf"], "blast_radius": 0.2},
            {"name": "axios", "version": "1.6.0", "maintainers": ["msw"], "blast_radius": 0.3},
        ],
        "timestamp": "2025-01-01T00:00:00Z",
    }
    current = {
        "components": [
            {"name": "requests", "version": "2.32.0", "maintainers": ["unknown"], "blast_radius": 0.6},
            {"name": "axios", "version": "2.0.0", "maintainers": ["unknown"], "blast_radius": 0.8},
            {"name": "newpkg", "version": "0.1.0", "maintainers": ["newbie"], "blast_radius": 0.5},
        ],
        "timestamp": "2025-02-01T00:00:00Z",
    }

    class FakeRiskModel:
        def score(self, prev: Dict[str, Any], curr: Dict[str, Any]):
            return {
                "score": 0.9,
                "factors": [
                    "exploit_maturity: high",
                    "maintainer_reputation: low",
                    "change_blast_radius: large",
                ],
                "approvals_required": True,
            }

    result = guardian.diff_dependencies(
        previous_sbom=previous,
        current_sbom=current,
        risk_model=FakeRiskModel(),
    )
    assert result.get("score", 0) >= guardian.policy.get("risk_threshold", 1)
    assert result.get("approvals_required") is True
    factors = " ".join(result.get("factors", []))
    assert "exploit" in factors.lower()
    assert "maintainer" in factors.lower()
    assert "blast" in factors.lower()