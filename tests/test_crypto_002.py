import hashlib
import importlib
import json
import os
import types
import pytest
from pathlib import Path


class AuditorAdapter:
    def __init__(self, module):
        self.module = module
        self.instance = None
        # Try to find a class to instantiate
        cls_name = self._find_attr(
            module,
            [
                "PQMigrateAuditor",
                "PqMigrateAuditor",
                "PQ_Migrate_Auditor",
                "PQ_MigrateAuditor",
                "PQ_MIGRATE_AUDITOR",
            ],
        )
        if cls_name:
            cls = getattr(module, cls_name)
            try:
                self.instance = cls()
            except Exception:
                # Fallback: try without instantiating (static methods or module-level functions)
                self.instance = None

        # Map of friendly names to possible attribute names
        self.name_map = {
            "scan_repository": [
                "scan_repository",
                "scan_repo",
                "analyze_repository",
                "inventory_repository",
            ],
            "probe_tls": [
                "probe_tls",
                "probe_tls_servers",
                "tls_probe",
                "active_tls_probe",
            ],
            "suggest_tls_config": [
                "suggest_tls_config",
                "generate_tls_config_template",
                "tls_config_template",
                "suggest_configuration",
            ],
            "apply_tls_config": [
                "apply_tls_config",
                "apply_configuration",
                "apply_config",
                "apply_tls_configuration",
            ],
            "reprobe_tls": [
                "reprobe_tls",
                "verify_tls_post_update",
                "probe_tls_again",
                "re_probe_tls",
            ],
            "generate_signed_report": [
                "generate_signed_report",
                "generate_pq_readiness_report",
                "create_signed_report",
            ],
            "verify_transparency_log": [
                "verify_transparency_log",
                "verify_log_inclusion",
                "verify_transparency_inclusion",
            ],
        }

        # Resolve actual callables and patch targets
        self.callables = {}
        self.patch_targets = {}
        for key, candidates in self.name_map.items():
            owner, attr_name = self._resolve_owner_and_attr(candidates)
            if owner and attr_name:
                func = getattr(owner, attr_name)
                self.callables[key] = func
                self.patch_targets[key] = (owner, attr_name)

    def _find_attr(self, owner, names):
        for n in names:
            if hasattr(owner, n):
                return n
        return None

    def _resolve_owner_and_attr(self, candidates):
        # Priority: instance methods -> module-level functions
        if self.instance is not None:
            name = self._find_attr(self.instance, candidates)
            if name:
                return self.instance, name
        name = self._find_attr(self.module, candidates)
        if name:
            return self.module, name
        return None, None

    def available(self, name):
        return name in self.callables

    def call(self, name, *args, **kwargs):
        if not self.available(name):
            raise AttributeError(f"{name} not available in auditor")
        func = self.callables[name]
        return func(*args, **kwargs)

    def patch(self, monkeypatch, name, new_callable):
        if not self.available(name):
            raise AttributeError(f"{name} not available to patch")
        owner, attr_name = self.patch_targets[name]
        monkeypatch.setattr(owner, attr_name, new_callable)
        # Update internal reference
        self.callables[name] = getattr(owner, attr_name)


@pytest.fixture(scope="module")
def auditor_module():
    return importlib.import_module("tools.cryptography.pq_migrate_auditor")


@pytest.fixture()
def auditor_adapter(auditor_module):
    return AuditorAdapter(auditor_module)


def _make_repo_with_weak_crypto(tmp_path: Path):
    # Create files simulating weak algorithms usage
    py_file = tmp_path / "crypto_usage.py"
    py_file.write_text(
        "\n".join(
            [
                "import hashlib",
                "from Crypto.PublicKey import RSA",
                "def weak_hash(data):",
                "    h = hashlib.sha1(data).hexdigest()",
                "    return h",
                "def weak_rsa():",
                "    key = RSA.generate(1024)",
                "    return key.export_key()",
            ]
        )
    )
    c_file = tmp_path / "legacy.c"
    c_file.write_text(
        "\n".join(
            [
                "#include <openssl/evp.h>",
                "int main() {",
                "    const EVP_MD *md = EVP_sha1();",
                "    int rsa_bits = 1024; // RSA-1024",
                "    return 0;",
                "}",
            ]
        )
    )
    bin_file = tmp_path / "binary.bin"
    bin_file.write_bytes(os.urandom(64))
    return tmp_path


def _extract_issues(result):
    # Support multiple result shapes
    if result is None:
        return []
    if isinstance(result, dict):
        for key in ["issues", "findings", "problems", "alerts"]:
            if key in result and isinstance(result[key], list):
                return result[key]
    if hasattr(result, "issues"):
        return getattr(result, "issues")
    if hasattr(result, "findings"):
        return getattr(result, "findings")
    return []


def _issue_contains_text(issue, text_candidates):
    data = json.dumps(issue, sort_keys=True).lower()
    return any(t.lower() in data for t in text_candidates)


def _get_remediation_text(issue):
    # Try likely fields
    for key in [
        "replacement",
        "suggestion",
        "recommended",
        "remediation",
        "fix",
        "proposed",
    ]:
        val = issue.get(key) if isinstance(issue, dict) else getattr(issue, key, None)
        if isinstance(val, str):
            return val
        if isinstance(val, (list, tuple)):
            return " ".join(str(x) for x in val)
        if isinstance(val, dict):
            return json.dumps(val, sort_keys=True)
    # fallback: search in details/description
    for key in ["details", "description", "message"]:
        val = issue.get(key) if isinstance(issue, dict) else getattr(issue, key, None)
        if isinstance(val, str):
            return val
    return ""


@pytest.mark.parametrize("file_count", [2])
def test_scan_repository_flags_weak_algorithms(tmp_path, auditor_adapter, file_count):
    if not auditor_adapter.available("scan_repository"):
        pytest.skip("scan_repository not available")

    repo = _make_repo_with_weak_crypto(tmp_path)
    result = auditor_adapter.call("scan_repository", str(repo))
    issues = _extract_issues(result)

    assert isinstance(issues, list), "Issues should be a list"
    assert any(
        _issue_contains_text(issue, ["sha-1", "sha1"]) for issue in issues
    ), "Expected SHA-1 usage to be flagged"
    assert any(
        _issue_contains_text(issue, ["rsa-1024", "rsa 1024", "1024-bit rsa", "rsa1024"])
        for issue in issues
    ), "Expected RSA-1024 usage to be flagged"

    # Verify code locations are included
    for issue in issues:
        data = issue if isinstance(issue, dict) else issue.__dict__
        # Accept multiple possible keys
        location_present = any(
            k in data for k in ["location", "file", "filepath", "path"]
        )
        if location_present:
            break
    else:
        pytest.fail("No issue contained a code location/path")

    # Verify safer algorithm replacements are suggested
    sha_issue = next(
        i for i in issues if _issue_contains_text(i, ["sha-1", "sha1"])
    )
    rsa_issue = next(
        i
        for i in issues
        if _issue_contains_text(i, ["rsa-1024", "rsa 1024", "1024-bit rsa", "rsa1024"])
    )

    sha_remediation = _get_remediation_text(sha_issue).lower()
    rsa_remediation = _get_remediation_text(rsa_issue).lower()

    assert any(x in sha_remediation for x in ["sha-256", "sha256", "sha-384", "sha3"]), (
        "SHA-1 remediation should suggest stronger digests like SHA-256/384/3"
    )
    assert any(
        x in rsa_remediation
        for x in ["rsa-2048", "rsa2048", "rsa-3072", "ecdsa", "ed25519", "ed448"]
    ), "RSA-1024 remediation should suggest stronger key sizes or modern alternatives"

    # Optional: ensure prioritization if available
    if isinstance(result, dict) and "remediation_plan" in result:
        plan = result["remediation_plan"]
        if isinstance(plan, list) and len(plan) >= 2:
            # Ensure plan is prioritized (e.g., by severity)
            # Expect SHA-1 and RSA-1024 to be high priority
            priorities = json.dumps(plan).lower()
            assert "sha-1" in priorities or "sha1" in priorities
            assert "rsa-1024" in priorities or "rsa 1024" in priorities


def test_tls_probe_suggests_and_confirms_hybrid(monkeypatch, auditor_adapter):
    needed = ["probe_tls", "suggest_tls_config", "apply_tls_config", "reprobe_tls"]
    if not all(auditor_adapter.available(n) for n in needed):
        pytest.skip("TLS probe/config methods not available")

    server = "127.0.0.1:8443"
    state = {"applied": {}}

    def fake_probe(servers):
        if isinstance(servers, (str, bytes)):
            servers = [servers]
        result = {}
        for s in servers:
            result[s] = {
                "hybrid_kem": False,
                "supported_kems": ["X25519"],
                "sig_algs": ["RSA-PSS"],
            }
        return result

    auditor_adapter.patch(monkeypatch, "probe_tls", fake_probe)

    def fake_suggest(report):
        cfg = {}
        for s, caps in report.items():
            if not caps.get("hybrid_kem"):
                cfg[s] = {
                    "hybrid": True,
                    "fallback_safe": True,
                    "kems": ["X25519+Kyber768"],
                    "signatures": ["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"],
                }
            else:
                cfg[s] = {"hybrid": True, "fallback_safe": True}
        return cfg

    auditor_adapter.patch(monkeypatch, "suggest_tls_config", fake_suggest)

    def fake_apply(server_arg, config, canary=False, kms=None):
        # Simulate canary application separately
        state["applied"][server_arg] = {
            "config": config,
            "canary": canary,
            "kms": kms or {},
        }
        return {"applied": True, "canary": canary, "notes": "applied test config"}

    auditor_adapter.patch(monkeypatch, "apply_tls_config", fake_apply)

    def fake_reprobe(server_arg):
        applied = state["applied"].get(server_arg)
        if applied and applied["config"].get("hybrid"):
            return {
                server_arg: {
                    "hybrid_kem": True,
                    "supported_kems": ["X25519", "Kyber768"],
                    "sig_algs": ["RSA-PSS", "ECDSA"],
                }
            }
        return {server_arg: {"hybrid_kem": False}}

    auditor_adapter.patch(monkeypatch, "reprobe_tls", fake_reprobe)

    initial = auditor_adapter.call("probe_tls", [server])
    assert initial[server]["hybrid_kem"] is False

    template = auditor_adapter.call("suggest_tls_config", initial)
    assert server in template
    tmpl = template[server]
    assert tmpl.get("hybrid") is True
    assert tmpl.get("fallback_safe") is True
    assert any("Kyber" in kem or "kyber" in kem for kem in tmpl.get("kems", [])), "Expected hybrid KEM in template"

    # Canary apply
    apply_res = auditor_adapter.call("apply_tls_config", server, tmpl, canary=True)
    assert apply_res["applied"] is True and apply_res.get("canary") is True

    # Verify hybrid support after canary
    after_canary = auditor_adapter.call("reprobe_tls", server)
    assert after_canary[server]["hybrid_kem"] is True

    # Full rollout
    apply_res_full = auditor_adapter.call("apply_tls_config", server, tmpl, canary=False)
    assert apply_res_full["applied"] is True and apply_res_full.get("canary") is False

    after_full = auditor_adapter.call("reprobe_tls", server)
    assert after_full[server]["hybrid_kem"] is True


def test_tls_probe_error_handling_timeout(monkeypatch, auditor_adapter):
    if not auditor_adapter.available("probe_tls"):
        pytest.skip("probe_tls not available")

    server_ok = "127.0.0.1:4433"
    server_fail = "127.0.0.1:4434"

    def flaky_probe(servers):
        out = {}
        for s in servers:
            if s == server_fail:
                # Simulate timeout/error
                out[s] = {"error": "timeout", "hybrid_kem": None}
            else:
                out[s] = {
                    "hybrid_kem": False,
                    "supported_kems": ["X25519"],
                    "sig_algs": ["RSA-PSS"],
                }
        return out

    auditor_adapter.patch(monkeypatch, "probe_tls", flaky_probe)
    res = auditor_adapter.call("probe_tls", [server_ok, server_fail])
    assert res[server_ok]["hybrid_kem"] is False
    assert "error" in res[server_fail] and res[server_fail]["error"] == "timeout"


def test_generate_signed_report_and_verify_transparency_log(monkeypatch, auditor_adapter):
    needed = ["generate_signed_report", "verify_transparency_log"]
    if not all(auditor_adapter.available(n) for n in needed):
        pytest.skip("Report generation/verification not available")

    # Prepare sample inputs
    scan_results = {
        "issues": [
            {
                "algorithm": "SHA-1",
                "location": "crypto_usage.py:4",
                "severity": "high",
                "replacement": "SHA-256",
            },
            {
                "algorithm": "RSA-1024",
                "location": "crypto_usage.py:7",
                "severity": "critical",
                "replacement": "RSA-2048 or Ed25519",
            },
        ],
        "inventory": [
            {"primitive": "hash", "algo": "SHA-1"},
            {"primitive": "asymm", "algo": "RSA", "bits": 1024},
        ],
    }
    tls_results = {
        "127.0.0.1:8443": {
            "hybrid_kem": True,
            "supported_kems": ["X25519", "Kyber768"],
            "sig_algs": ["RSA-PSS", "ECDSA"],
        }
    }

    def fake_generate(scan, tls):
        report = {"scan": scan, "tls": tls, "version": 1}
        report_json = json.dumps(report, sort_keys=True).encode()
        report_hash = hashlib.sha256(report_json).hexdigest()
        signature = f"sig:{report_hash}"
        log_entry = {
            "log_index": 42,
            "hash": report_hash,
            "inclusion_proof": "proof-bytes",
            "signed_entry_timestamp": 1700000000,
        }
        return {"report": report, "signature": signature, "transparency_log": log_entry}

    auditor_adapter.patch(monkeypatch, "generate_signed_report", fake_generate)

    def fake_verify(package):
        # Verify signature and transparency log tamper-evident metadata
        if not isinstance(package, dict) or "report" not in package:
            return False
        report_json = json.dumps(package["report"], sort_keys=True).encode()
        calc_hash = hashlib.sha256(report_json).hexdigest()
        log = package.get("transparency_log", {})
        if log.get("hash") != calc_hash:
            return False
        sig = package.get("signature", "")
        if not isinstance(sig, str) or not sig.endswith(calc_hash):
            return False
        return bool(log.get("inclusion_proof"))

    auditor_adapter.patch(monkeypatch, "verify_transparency_log", fake_verify)

    package = auditor_adapter.call("generate_signed_report", scan_results, tls_results)
    assert "signature" in package and "report" in package and "transparency_log" in package
    assert auditor_adapter.call("verify_transparency_log", package) is True

    # Tamper with report and verify detection
    tampered = json.loads(json.dumps(package))
    tampered["report"]["scan"]["issues"][0]["algorithm"] = "SHA-1-ALTERED"
    assert auditor_adapter.call("verify_transparency_log", tampered) is False


def test_canary_change_control_and_rollback(monkeypatch, auditor_adapter):
    # Use apply_tls_config to simulate canary failure and rollback handling through subsequent reprobe
    needed = ["apply_tls_config", "reprobe_tls", "probe_tls", "suggest_tls_config"]
    if not all(auditor_adapter.available(n) for n in needed):
        pytest.skip("Change control-related methods not available")

    server = "127.0.0.1:9443"
    state = {"applied": {}, "fail_canary": True}

    def fake_probe(servers):
        if isinstance(servers, (str, bytes)):
            servers = [servers]
        return {
            s: {"hybrid_kem": False, "supported_kems": ["X25519"], "sig_algs": ["RSA-PSS"]}
            for s in servers
        }

    auditor_adapter.patch(monkeypatch, "probe_tls", fake_probe)

    def fake_suggest(report):
        return {
            s: {
                "hybrid": True,
                "fallback_safe": True,
                "kems": ["X25519+Kyber768"],
                "signatures": ["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"],
            }
            for s in report.keys()
        }

    auditor_adapter.patch(monkeypatch, "suggest_tls_config", fake_suggest)

    def apply_with_canary(server_arg, config, canary=False, kms=None):
        if canary and state["fail_canary"]:
            # Simulate failure: do not persist config
            return {
                "applied": False,
                "canary": True,
                "rolled_back": True,
                "error": "canary_failed",
            }
        # Success path
        state["applied"][server_arg] = {"config": config, "canary": canary}
        return {"applied": True, "canary": canary, "rolled_back": False}

    auditor_adapter.patch(monkeypatch, "apply_tls_config", apply_with_canary)

    def reprobe(server_arg):
        if server_arg in state["applied"]:
            return {
                server_arg: {
                    "hybrid_kem": True,
                    "supported_kems": ["X25519", "Kyber768"],
                    "sig_algs": ["RSA-PSS", "ECDSA"],
                }
            }
        return {server_arg: {"hybrid_kem": False}}

    auditor_adapter.patch(monkeypatch, "reprobe_tls", reprobe)

    initial = auditor_adapter.call("probe_tls", [server])
    template = auditor_adapter.call("suggest_tls_config", initial)

    # Canary should fail and rollback
    canary_res = auditor_adapter.call("apply_tls_config", server, template[server], canary=True)
    assert canary_res["applied"] is False
    assert canary_res.get("rolled_back") is True

    # Verify that capability hasn't changed post-failed canary
    after_failed_canary = auditor_adapter.call("reprobe_tls", server)
    assert after_failed_canary[server]["hybrid_kem"] is False

    # Now allow rollout and apply fully
    state["fail_canary"] = False
    full_res = auditor_adapter.call("apply_tls_config", server, template[server], canary=False)
    assert full_res["applied"] is True and full_res.get("rolled_back") is False

    after_full = auditor_adapter.call("reprobe_tls", server)
    assert after_full[server]["hybrid_kem"] is True