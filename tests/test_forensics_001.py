import json
import os
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, List

import pytest

# Import the toolkit and exceptions
from tools.forensics import memory_toolkit as mt
from tools.forensics.memory_toolkit import MemoryToolkit, AcquisitionError, AnalysisError, ReportError


@pytest.fixture
def toolkit() -> MemoryToolkit:
    return MemoryToolkit()


@pytest.fixture
def sample_memory_image(tmp_path: Path) -> Path:
    # Create a synthetic memory image containing markers for processes, drivers, network, injections, scripts, and registry hives
    content = (
        b"# Synthetic memory image for testing\n"
        b"PROC pid=100 name=system.exe hidden=false path=C:\\Windows\\System32\\system32.exe\n"
        b"PROC pid=444 name=svchost.exe hidden=true path=C:\\Windows\\System32\\svchost.exe\n"
        b"DRIVER name=maldrv.sys base=0x1000 size=4096 hidden=true\n"
        b"NET proto=tcp laddr=127.0.0.1:8080 raddr=127.0.0.1:4444 state=ESTABLISHED pid=444\n"
        b"INJECT pid=444 technique=ProcessHollowing detail=Unmapped section\n"
        b"SCRIPT_BEGIN name=evil.ps1\n"
        b"Write-Host 'Malicious'\n"
        b"SCRIPT_END\n"
        b"REGHIVE_BEGIN path=HKLM\\SAM size=8192\n"
        b"REGHIVE_END\n"
        b"FILE_BEGIN path=/tmp/secret.bin size=16\n"
        b"abcdef0123456789\n"
        b"FILE_END\n"
    )
    image_path = tmp_path / "sample.mem"
    image_path.write_bytes(content)
    return image_path


def _fake_completed_process(returncode=0, stdout=b"", stderr=b""):
    class CP:
        def __init__(self, returncode, stdout, stderr):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    return CP(returncode, stdout, stderr)


def test_acquire_memory_success_vm(toolkit: MemoryToolkit, monkeypatch, tmp_path: Path):
    # Mock subprocess.run inside the module to simulate acquisition tool writing the destination file
    dest = tmp_path / "acquired.mem"

    def fake_run(cmd, capture_output=False, check=False, text=False, timeout=None):
        # Simulate writing a memory image to destination if path present in cmd
        # Command may include destination path as last argument or via flag, we write to known dest regardless
        sample_bytes = b"FAKE_MEMORY_IMAGE" * 1024  # ~16KB
        dest.write_bytes(sample_bytes)
        return _fake_completed_process(0, stdout=b"ok", stderr=b"")

    # Ensure platform.system is consistent
    monkeypatch.setattr(mt, "subprocess", type("S", (), {"run": staticmethod(fake_run)}))
    monkeypatch.setenv("LMFT_TEST_MODE", "1")

    meta = toolkit.acquire_memory(os_type="Linux", destination=str(dest), options={"minimal": True})

    assert dest.exists(), "Acquisition did not produce destination file"
    assert dest.stat().st_size > 0
    assert isinstance(meta, dict)
    assert meta.get("path") == str(dest)
    assert meta.get("os").lower() in {"linux", "windows", "darwin", "macos"}
    assert meta.get("size") == dest.stat().st_size
    # Check hash integrity field if provided
    if "sha256" in meta:
        with open(dest, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()
        assert meta["sha256"] == expected
    # Minimal footprint expectation if provided
    if "footprint_kb" in meta:
        assert isinstance(meta["footprint_kb"], (int, float))
        assert meta["footprint_kb"] <= 2048  # <= 2MB resident as "minimal"

    # Timestamp sanity if provided
    if "timestamp" in meta:
        assert isinstance(meta["timestamp"], (int, float))
        assert meta["timestamp"] <= time.time()


def test_acquire_memory_invalid_os_raises(toolkit: MemoryToolkit, tmp_path: Path):
    with pytest.raises(AcquisitionError):
        toolkit.acquire_memory(os_type="Plan9", destination=str(tmp_path / "bad.mem"), options={})


def test_analyze_identify_hidden_process(sample_memory_image: Path, toolkit: MemoryToolkit):
    results = toolkit.analyze(str(sample_memory_image))
    assert isinstance(results, dict)
    # Processes
    processes = results.get("processes") or results.get("running_processes")
    assert isinstance(processes, list)
    hidden = [p for p in processes if p.get("hidden") or p.get("is_hidden")]
    assert hidden, "No hidden processes detected"
    # Ensure the hidden process details are reasonable
    assert any(p.get("name", "").lower().startswith("svchost") for p in hidden)
    # Network
    network = results.get("network") or results.get("network_connections")
    assert isinstance(network, list)
    # Limit network tests to localhost addresses
    for conn in network:
        laddr = conn.get("laddr") or conn.get("local_address")
        raddr = conn.get("raddr") or conn.get("remote_address")
        # Accept None for raddr if not connected
        if laddr:
            assert str(laddr).startswith("127.0.0.1")
        if raddr:
            assert str(raddr).startswith("127.0.0.1")
    # Drivers
    drivers = results.get("drivers") or results.get("loaded_drivers")
    assert isinstance(drivers, list)
    # Code injections
    injections = results.get("code_injections") or results.get("injections") or []
    assert isinstance(injections, list)
    assert any("ProcessHollowing" in (inj.get("technique") or "") for inj in injections), "Process hollowing not detected"


def test_extract_malicious_script_from_memory_image(sample_memory_image: Path, toolkit: MemoryToolkit, tmp_path: Path):
    outdir = tmp_path / "carved"
    outdir.mkdir()
    carve_result = toolkit.carve_artifacts(str(sample_memory_image), str(outdir), types=["scripts", "registry", "files"])
    assert isinstance(carve_result, dict)
    # Scripts carved
    scripts = carve_result.get("scripts") or []
    assert scripts, "No scripts carved"
    script_paths = [Path(p) for p in scripts]
    for sp in script_paths:
        assert sp.exists()
        data = sp.read_text(encoding="utf-8", errors="ignore")
        assert "Malicious" in data
    # Registry hives carved
    hives = carve_result.get("registry_hives") or carve_result.get("registry") or []
    assert isinstance(hives, list)
    # Files carved
    files = carve_result.get("files") or []
    assert isinstance(files, list)


def test_detect_stealthy_malware_techniques(sample_memory_image: Path, toolkit: MemoryToolkit):
    stealth = toolkit.detect_stealth(str(sample_memory_image))
    assert isinstance(stealth, dict)
    # Rootkits
    rootkits = stealth.get("rootkits") or []
    assert isinstance(rootkits, list)
    # Hollowed processes
    hollowed = stealth.get("hollowed_processes") or []
    assert isinstance(hollowed, list)
    # Validate expected detection present
    assert hollowed or rootkits or stealth.get("anomalies") or stealth.get("detections")
    # Cross-check with analyze results for consistency if both are available
    analysis = toolkit.analyze(str(sample_memory_image))
    injections = analysis.get("code_injections") or []
    if hollowed and injections:
        inj_pids = {inj.get("pid") for inj in injections if inj.get("technique") == "ProcessHollowing"}
        hollow_pids = {hp.get("pid") for hp in hollowed if "pid" in hp}
        assert inj_pids & hollow_pids or not inj_pids, "Inconsistent hollowing detection between analyze and detect_stealth"


def test_generate_detailed_report(sample_memory_image: Path, toolkit: MemoryToolkit, tmp_path: Path):
    # Run pipeline to produce findings
    analysis = toolkit.analyze(str(sample_memory_image))
    stealth = toolkit.detect_stealth(str(sample_memory_image))
    carve_dir = tmp_path / "carved2"
    carve_dir.mkdir()
    artifacts = toolkit.carve_artifacts(str(sample_memory_image), str(carve_dir), types=["scripts", "registry", "files"])

    # Aggregate findings
    findings: Dict[str, Any] = {
        "analysis": analysis,
        "stealth": stealth,
        "artifacts": artifacts,
        "metadata": {
            "source": str(sample_memory_image),
            "tool": "Live Memory Forensic Toolkit",
            "category": "forensics",
        },
    }

    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    outputs = toolkit.generate_report(findings, formats=["json", "html", "pdf"], output_dir=str(report_dir))
    assert isinstance(outputs, dict)
    # JSON report
    json_path = Path(outputs.get("json", ""))
    assert json_path.exists()
    with open(json_path, "r", encoding="utf-8") as jf:
        data = json.load(jf)
    assert "analysis" in data and "artifacts" in data and "stealth" in data
    # HTML report
    html_path = Path(outputs.get("html", ""))
    assert html_path.exists()
    assert html_path.stat().st_size > 0
    # PDF report
    pdf_path = Path(outputs.get("pdf", ""))
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0


def test_analyze_nonexistent_image_raises(toolkit: MemoryToolkit, tmp_path: Path):
    missing = tmp_path / "missing.mem"
    with pytest.raises(AnalysisError):
        toolkit.analyze(str(missing))


def test_edge_case_empty_memory_image_returns_empty_results(toolkit: MemoryToolkit, tmp_path: Path):
    empty = tmp_path / "empty.mem"
    empty.write_bytes(b"")
    results = toolkit.analyze(str(empty))
    # Expect well-formed but empty results
    assert isinstance(results, dict)
    for key in ("processes", "network", "drivers", "code_injections"):
        assert key in results
        assert isinstance(results[key], list)


def test_generate_report_invalid_format_raises(toolkit: MemoryToolkit, tmp_path: Path):
    findings = {"analysis": {"processes": [], "network": [], "drivers": [], "code_injections": []}, "stealth": {}, "artifacts": {}}
    with pytest.raises(ReportError):
        toolkit.generate_report(findings, formats=["exe"], output_dir=str(tmp_path))


def test_carve_handles_unknown_type_gracefully(sample_memory_image: Path, toolkit: MemoryToolkit, tmp_path: Path):
    outdir = tmp_path / "carved3"
    outdir.mkdir()
    result = toolkit.carve_artifacts(str(sample_memory_image), str(outdir), types=["unknown_type"])
    assert isinstance(result, dict)
    assert "unknown_type" not in result or result["unknown_type"] in ([], None)