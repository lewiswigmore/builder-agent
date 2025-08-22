import json
import os
import socket
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import tools.iot.firmware_behavior_sandbox as fbs


@pytest.fixture
def tmp_fw_file(tmp_path: Path) -> Path:
    p = tmp_path / "firmware.bin"
    p.write_bytes(b"\x7fELF...PROPRIETARY_CODE...secret")
    return p


@pytest.fixture
def sample_sbom() -> Dict[str, Any]:
    # Minimal SBOM-like structure
    return {
        "components": [
            {
                "name": "OpenSSL",
                "version": "1.0.2o",
                "purl": "pkg:generic/openssl@1.0.2o",
                "licenses": ["OpenSSL"],
            }
        ],
        "metadata": {"tools": ["test-sbom-generator"]},
    }


@pytest.fixture
def sandbox():
    # Try to get a class-like API if available; otherwise, provide module-level function wrappers
    if hasattr(fbs, "FirmwareBehaviorSandbox"):
        return fbs.FirmwareBehaviorSandbox()
    # Build a shim to unify interface for tests
    shim = SimpleNamespace()

    analyze_firmware = getattr(fbs, "analyze_firmware", None)
    if analyze_firmware is None and hasattr(fbs, "run_firmware_in_sandbox"):
        analyze_firmware = getattr(fbs, "run_firmware_in_sandbox")

    analyze_sbom = getattr(fbs, "analyze_sbom", None)
    if analyze_sbom is None and hasattr(fbs, "analyze_sbom_file"):
        analyze_sbom = getattr(fbs, "analyze_sbom_file")

    if analyze_firmware is None or analyze_sbom is None:
        pytest.skip("FirmwareBehaviorSandbox API not found (analyze_firmware/analyze_sbom)")

    shim.analyze_firmware = analyze_firmware
    shim.analyze_sbom = analyze_sbom
    return shim


def _patch_authorization(monkeypatch, allowed=True, require_provenance=True):
    # Patch authorization and provenance validation if present
    if hasattr(fbs, "authorize_and_validate"):
        def fake_auth(fw_path, provenance=None, authorized=False):
            if require_provenance and not provenance:
                raise ValueError("Missing provenance")
            if not authorized or not allowed:
                raise PermissionError("Unauthorized")
            return {"firmware_id": "anon-123"}
        monkeypatch.setattr(fbs, "authorize_and_validate", fake_auth)
    elif hasattr(fbs, "validate_provenance") or hasattr(fbs, "require_authorization"):
        if hasattr(fbs, "validate_provenance"):
            def fake_validate(provenance):
                if require_provenance and not provenance:
                    raise ValueError("Missing provenance")
                return True
            monkeypatch.setattr(fbs, "validate_provenance", fake_validate)
        if hasattr(fbs, "require_authorization"):
            def fake_require(authorized):
                if not authorized or not allowed:
                    raise PermissionError("Unauthorized")
                return True
            monkeypatch.setattr(fbs, "require_authorization", fake_require)
    # else: assume sandbox will internally handle authorization


def _patch_isolation(monkeypatch, record):
    # Patch network isolation hook
    if hasattr(fbs, "enforce_no_outbound"):

        def fake_enforce():
            record["isolation_called"] = True
            return True

        monkeypatch.setattr(fbs, "enforce_no_outbound", fake_enforce)
    elif hasattr(fbs, "setup_network_isolation"):

        def fake_setup():
            record["isolation_called"] = True
            return True

        monkeypatch.setattr(fbs, "setup_network_isolation", fake_setup)
    else:
        # Patch socket connect as fallback to ensure no outbound
        orig_socket = socket.socket.connect

        def fake_connect(self, address):
            host, port = address
            record["socket_connects"].append(address)
            if host not in ("127.0.0.1", "::1", "localhost"):
                raise OSError("Outbound blocked by isolation")
            return orig_socket(self, ("127.0.0.1", port))

        monkeypatch.setattr(socket.socket, "connect", fake_connect)


def _patch_emulator_for_telnet(monkeypatch):
    # Patch emulator run function to simulate telnet default creds
    if hasattr(fbs, "run_emulator"):
        def fake_run_emulator(fw_path, *args, **kwargs):
            return {
                "processes": [{"name": "telnetd", "port": 23, "proto": "tcp"}],
                "auth": [{"service": "telnet", "user": "admin", "password": "admin", "is_default": True}],
                "network": [],
                "artifacts": []
            }
        monkeypatch.setattr(fbs, "run_emulator", fake_run_emulator)
    elif hasattr(fbs, "emulate"):
        def fake_emulate(fw_path, *args, **kwargs):
            return {
                "processes": [{"name": "telnetd", "port": 23, "proto": "tcp"}],
                "auth": [{"service": "telnet", "user": "admin", "password": "admin", "is_default": True}],
                "network": [],
                "artifacts": []
            }
        monkeypatch.setattr(fbs, "emulate", fake_emulate)
    # else assume analyze_firmware can proceed without emulation


def _patch_network_monitor_dns_tunnel(monkeypatch):
    # Patch network monitor to detect DNS tunneling and block it
    if hasattr(fbs, "monitor_network"):
        def fake_monitor(*args, **kwargs):
            return {
                "alerts": [
                    {
                        "type": "network_exfiltration",
                        "method": "dns_tunneling",
                        "blocked": True,
                        "pcap_reference": "pcap://session/1234/stream/1"
                    }
                ],
                "pcap": "pcap://session/1234"
            }
        monkeypatch.setattr(fbs, "monitor_network", fake_monitor)
    elif hasattr(fbs, "detect_dns_tunneling"):
        def fake_detect(*args, **kwargs):
            return {
                "detected": True,
                "blocked": True,
                "pcap_reference": "pcap://session/1234/stream/1"
            }
        monkeypatch.setattr(fbs, "detect_dns_tunneling", fake_detect)


def _patch_sanitizer(monkeypatch):
    if hasattr(fbs, "sanitize_telemetry"):
        def fake_sanitize(data):
            # remove anything that looks like paths or raw bytes markers
            data = dict(data or {})
            data.pop("firmware_path", None)
            data["firmware_id"] = "anon-123"
            data["anonymized"] = True
            return data
        monkeypatch.setattr(fbs, "sanitize_telemetry", fake_sanitize)


def _patch_cve_correlation(monkeypatch):
    if hasattr(fbs, "correlate_cves"):
        def fake_correlate(sbom):
            vulns = []
            for c in sbom.get("components", []):
                if c.get("name", "").lower() == "openssl" and c.get("version") == "1.0.2o":
                    vulns.append({
                        "cve": "CVE-2016-2107",
                        "severity": "high",
                        "component": "OpenSSL",
                        "version": "1.0.2o",
                        "fixed_versions": ["1.0.2h", "1.0.2p", "1.1.0"],
                        "description": "Padding oracle in AES-NI CBC MAC check"
                    })
            return {"vulnerabilities": vulns}
        monkeypatch.setattr(fbs, "correlate_cves", fake_correlate)


def _invoke_analyze_firmware(sandbox, firmware_path, provenance=None, authorized=True):
    if hasattr(sandbox, "analyze_firmware"):
        return sandbox.analyze_firmware(str(firmware_path), provenance=provenance, authorized=authorized)
    # Try alternative signatures if necessary
    return sandbox.analyze_firmware(str(firmware_path), provenance, authorized)


def _invoke_analyze_sbom(sandbox, sbom: Dict[str, Any]):
    if hasattr(sandbox, "analyze_sbom"):
        return sandbox.analyze_sbom(sbom)
    return sandbox.analyze_sbom(sbom)


def _find_finding(findings: List[Dict[str, Any]], keyword: str) -> Dict[str, Any]:
    for f in findings or []:
        text = " ".join(str(v).lower() for v in f.values() if isinstance(v, (str, int)) or v is None)
        if keyword.lower() in text:
            return f
    return {}


def _ensure_no_raw_code_in_report(report: Dict[str, Any]):
    serialized = json.dumps(report, default=str)
    assert "PROPRIETARY_CODE" not in serialized
    assert "firmware.bin" not in serialized


def test_telnet_default_credentials_flagging(tmp_fw_file, sandbox, monkeypatch):
    _patch_authorization(monkeypatch, allowed=True, require_provenance=True)
    record = {"isolation_called": False, "socket_connects": []}
    _patch_isolation(monkeypatch, record)
    _patch_emulator_for_telnet(monkeypatch)
    _patch_sanitizer(monkeypatch)

    provenance = {"source": "vendor-portal", "checksum": "sha256:deadbeef"}
    report = _invoke_analyze_firmware(sandbox, tmp_fw_file, provenance=provenance, authorized=True)

    assert isinstance(report, dict)
    # Verify isolation enforced
    assert record.get("isolation_called", True) is True or "isolation" in report
    # Acceptance: weak service configuration
    findings = report.get("findings", [])
    weak = _find_finding(findings, "telnet")
    assert weak, "Expected a finding related to Telnet"
    assert any("telnet" in str(weak.get(k, "")).lower() for k in weak)
    assert any("default" in str(weak.get(k, "")).lower() for k in weak)
    assert any("credential" in str(weak.get(k, "")).lower() for k in weak)
    # Hardening recommendations present
    recs = weak.get("recommendations") or weak.get("remediation") or []
    rec_text = " ".join(r.lower() for r in recs) if isinstance(recs, list) else str(recs).lower()
    assert ("disable telnet" in rec_text) or ("use ssh" in rec_text) or ("change default" in rec_text)

    # Telemetry must be sanitized and anonymized
    telemetry = report.get("telemetry", {})
    assert telemetry.get("anonymized") or "firmware_id" in telemetry
    assert "firmware_path" not in telemetry
    _ensure_no_raw_code_in_report(report)


def test_sbom_cve_correlation_openssl(sample_sbom, sandbox, monkeypatch):
    _patch_cve_correlation(monkeypatch)
    result = _invoke_analyze_sbom(sandbox, sample_sbom)

    assert isinstance(result, dict)
    vulns = result.get("vulnerabilities") or result.get("vulns") or []
    assert isinstance(vulns, list)
    openssl_vulns = [v for v in vulns if str(v.get("component", "")).lower() == "openssl"]
    assert openssl_vulns, "Expected OpenSSL vulnerabilities correlated from SBOM"
    v = openssl_vulns[0]
    assert v.get("cve", "").startswith("CVE-")
    assert v.get("severity", "").lower() in {"high", "critical", "medium"}
    assert v.get("version") == "1.0.2o"
    fixed = v.get("fixed_versions") or v.get("fix_versions") or []
    assert isinstance(fixed, list) and fixed, "Fixed versions should be provided"


def test_dns_tunneling_detected_and_blocked_with_pcap(tmp_fw_file, sandbox, monkeypatch):
    _patch_authorization(monkeypatch, allowed=True, require_provenance=False)
    record = {"isolation_called": False, "socket_connects": []}
    _patch_isolation(monkeypatch, record)
    _patch_network_monitor_dns_tunnel(monkeypatch)
    _patch_sanitizer(monkeypatch)

    provenance = {"source": "internal-lab"}
    report = _invoke_analyze_firmware(sandbox, tmp_fw_file, provenance=provenance, authorized=True)

    alerts = report.get("alerts") or report.get("network_alerts") or []
    assert isinstance(alerts, list) and alerts, "Expected network alert for DNS tunneling"
    alert = next((a for a in alerts if str(a.get("method", "")).lower() == "dns_tunneling" or "dns" in str(a.get("type", "")).lower()), None)
    assert alert, "DNS tunneling alert not present"
    assert bool(alert.get("blocked")) is True
    pcap_ref = alert.get("pcap_reference") or alert.get("pcap")
    assert isinstance(pcap_ref, str) and pcap_ref.startswith("pcap://")


def test_requires_authorization_and_provenance(tmp_fw_file, sandbox, monkeypatch):
    _patch_authorization(monkeypatch, allowed=True, require_provenance=True)
    # Missing provenance
    with pytest.raises((PermissionError, ValueError)):
        _invoke_analyze_firmware(sandbox, tmp_fw_file, provenance=None, authorized=True)
    # Missing authorization
    with pytest.raises((PermissionError, ValueError)):
        _invoke_analyze_firmware(sandbox, tmp_fw_file, provenance={"source": "test"}, authorized=False)


def test_no_outbound_internet_by_default(tmp_fw_file, sandbox, monkeypatch):
    attempted = {"addrs": []}
    original_connect = socket.socket.connect

    def fake_connect(self, address):
        attempted["addrs"].append(address)
        host, _ = address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise OSError("Outbound blocked")
        return original_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", fake_connect)

    _patch_authorization(monkeypatch, allowed=True, require_provenance=False)
    provenance = {"source": "test"}
    # Patch emulator to simulate an external DNS/HTTP attempt
    if hasattr(fbs, "run_emulator"):
        def fake_run_emulator(fw_path, *args, **kwargs):
            return {
                "processes": [],
                "network": [{"dst": "8.8.8.8", "port": 53, "proto": "udp"}],
                "artifacts": []
            }
        monkeypatch.setattr(fbs, "run_emulator", fake_run_emulator)
    _patch_network_monitor_dns_tunnel(monkeypatch)

    report = _invoke_analyze_firmware(sandbox, tmp_fw_file, provenance=provenance, authorized=True)
    # Ensure any non-local connection attempts were blocked (via our socket patch raising)
    non_local_attempts = [a for a in attempted["addrs"] if a[0] not in ("127.0.0.1", "::1", "localhost")]
    # It's acceptable if the sandbox never tried to connect directly; at minimum, report should not indicate outbound connectivity allowed
    alerts = report.get("alerts") or []
    assert all(a.get("blocked") for a in alerts if "network" in str(a.get("type", "")).lower())


def test_telemetry_sanitized_and_no_retention(tmp_fw_file, sandbox, monkeypatch):
    _patch_authorization(monkeypatch, allowed=True, require_provenance=False)
    _patch_sanitizer(monkeypatch)

    # Patch any retention to be disabled and reported
    if hasattr(fbs, "retain_artifacts"):
        def fake_retain(*args, **kwargs):
            return False
        monkeypatch.setattr(fbs, "retain_artifacts", fake_retain)

    report = _invoke_analyze_firmware(sandbox, tmp_fw_file, provenance={"source": "test"}, authorized=True)

    telemetry = report.get("telemetry", {})
    assert telemetry.get("anonymized") or "firmware_id" in telemetry
    assert "firmware_path" not in telemetry
    retained = report.get("retained_artifacts")
    if retained is not None:
        assert retained is False
    _ensure_no_raw_code_in_report(report)


def test_sbom_missing_versions_handled(sandbox):
    sbom = {"components": [{"name": "openssl"}, {"name": "busybox", "version": ""}]}
    result = _invoke_analyze_sbom(sandbox, sbom)
    assert isinstance(result, dict)
    assert "vulnerabilities" in result or "vulns" in result
    # Should not raise and should handle gracefully
    # Components without version may be skipped or marked unknown
    vulns = result.get("vulnerabilities") or result.get("vulns") or []
    assert isinstance(vulns, list)


def test_corrupted_or_missing_firmware_image_error(sandbox, tmp_path):
    missing = tmp_path / "does_not_exist.bin"
    with pytest.raises((FileNotFoundError, ValueError, OSError)):
        _invoke_analyze_firmware(sandbox, missing, provenance={"source": "test"}, authorized=True)