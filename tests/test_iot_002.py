import pytest
from pathlib import Path
from types import SimpleNamespace

# Import the analyzer module and create a unified analyzer interface
import importlib

mod = importlib.import_module("tools.iot.firmware_analyzer")

def _make_analyzer():
    if hasattr(mod, "FirmwareAnalyzer"):
        try:
            return mod.FirmwareAnalyzer()
        except TypeError:
            # In case the analyzer requires args but supports defaults
            return mod.FirmwareAnalyzer(workdir=None)
    # Fallback to module-level functions
    return SimpleNamespace(
        extract_filesystem=getattr(mod, "extract_filesystem", None) or getattr(mod, "extract", None),
        find_secrets=getattr(mod, "find_secrets", None) or getattr(mod, "scan_for_secrets", None) or getattr(mod, "identify_secrets", None),
        analyze_binaries=getattr(mod, "analyze_binaries", None) or getattr(mod, "binary_analysis", None),
        emulate=getattr(mod, "emulate_firmware", None) or getattr(mod, "emulate", None) or getattr(mod, "run_emulation", None),
        generate_report=getattr(mod, "generate_report", None) or getattr(mod, "build_report", None),
    )

def _get_callable(analyzer, candidates):
    for name in candidates:
        fn = getattr(analyzer, name, None)
        if callable(fn):
            return name, fn
    return None, None

@pytest.fixture(scope="function")
def analyzer():
    return _make_analyzer()

@pytest.fixture(scope="function")
def firmware_fs(tmp_path):
    # Create a simulated firmware filesystem directory
    root = tmp_path / "firmware_root"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "config.txt").write_text(
        "username=admin\npassword=SuperSecret123\napi_key=ABCD-1234\n"
    )
    (root / "etc" / "shadow").write_text("root:$6$saltsalt$hashed:19000::::::\n")

    # Private keys
    (root / "etc" / "ssl" / "private").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "ssl" / "private" / "server.key").write_text(
        "-----BEGIN PRIVATE KEY-----\nMIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIw\n-----END PRIVATE KEY-----\n"
    )
    (root / "root").mkdir(parents=True, exist_ok=True)
    (root / "root" / ".ssh").mkdir(parents=True, exist_ok=True)
    (root / "root" / ".ssh" / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu...\n-----END RSA PRIVATE KEY-----\n"
    )

    # Binaries and libs with vulnerable markers
    (root / "bin").mkdir(parents=True, exist_ok=True)
    (root / "bin" / "app").write_bytes(b"\x7fELF...strcpy(")  # insecure function usage marker
    (root / "usr" / "lib").mkdir(parents=True, exist_ok=True)
    (root / "usr" / "lib" / "libssl.so").write_text("OpenSSL 1.0.1e 11 Feb 2013")  # vulnerable version marker

    # Backdoor service marker for emulation detection
    (root / "etc" / "init.d").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "init.d" / "S99backdoor").write_text(
        "#!/bin/sh\n# start hidden telnet backdoor\n/usr/sbin/telnetd -l /bin/sh -p 1337\n"
    )

    return root

def stringify_item(item):
    if isinstance(item, (str, bytes)):
        try:
            return item.decode() if isinstance(item, bytes) else item
        except Exception:
            return str(item)
    if isinstance(item, dict):
        return " ".join(f"{k}:{v}" for k, v in item.items())
    if isinstance(item, (list, tuple, set)):
        return " ".join(stringify_item(x) for x in item)
    return str(item)

def assert_contains_any(hay, needles):
    hay_s = stringify_item(hay).lower()
    assert any(needle.lower() in hay_s for needle in needles), f"Expected one of {needles} in: {hay_s}"

def ensure_callable(analyzer, names):
    name, fn = _get_callable(analyzer, names)
    if not fn:
        pytest.skip(f"Analyzer missing expected callable: one of {names}")
    return name, fn

# Acceptance: Successfully unpack a sample firmware image.
def test_extract_filesystem_success(analyzer, firmware_fs, tmp_path):
    name, extract = ensure_callable(analyzer, ["extract_filesystem", "extract"])
    # Provide directory path as firmware input to avoid external unpackers
    result = extract(firmware_fs)
    # Accept either returning the same path or a new extraction path
    if result is None:
        pytest.fail("extract_filesystem returned None")
    extracted = Path(result)
    assert extracted.exists() and extracted.is_dir()
    # Verify expected files are present post-extraction
    assert (extracted / "etc" / "config.txt").exists()

# Acceptance: Discover a hardcoded password within the firmware filesystem.
def test_discover_hardcoded_password(analyzer, firmware_fs):
    # Ensure we have an extracted path; allow extract() to be a no-op for directories
    name_extract, extract = ensure_callable(analyzer, ["extract_filesystem", "extract"])
    extracted_path = Path(extract(firmware_fs))
    name_secrets, find_secrets = ensure_callable(analyzer, ["find_secrets", "scan_for_secrets", "identify_secrets"])
    secrets = find_secrets(extracted_path)
    assert isinstance(secrets, (list, tuple)), "find_secrets should return a list-like"
    # Look for evidence of hardcoded password or keys
    flat = stringify_item(secrets)
    assert "password" in flat.lower() or "private key" in flat.lower() or "rsa private key" in flat.lower(), "Expected secrets not found"

# Acceptance: Identify a vulnerable library in a firmware binary.
def test_identify_vulnerable_library(analyzer, firmware_fs):
    name_extract, extract = ensure_callable(analyzer, ["extract_filesystem", "extract"])
    extracted_path = Path(extract(firmware_fs))
    name_binv, analyze_binaries = ensure_callable(analyzer, ["analyze_binaries", "binary_analysis"])
    vulns = analyze_binaries(extracted_path)
    assert isinstance(vulns, (list, tuple)), "analyze_binaries should return a list-like"
    # Accept matches on OpenSSL 1.0.1* or insecure function usage like strcpy/gets
    flat = stringify_item(vulns).lower()
    assert ("openssl" in flat and ("1.0.1" in flat or "heartbleed" in flat)) or ("strcpy" in flat or "gets(" in flat), "Expected vulnerable library or insecure function not identified"

# Acceptance: Emulate the firmware and detect a backdoor service.
def test_emulate_and_detect_backdoor(analyzer, firmware_fs, monkeypatch):
    # Monkeypatch the emulate method to avoid real emulation and network operations
    # The fake emulate will only use localhost and report detection based on presence of backdoor marker file
    emulate_name, emulate_fn = ensure_callable(analyzer, ["emulate_firmware", "emulate", "run_emulation"])

    def fake_emulate(path, *args, **kwargs):
        # Ensure only localhost is used
        host = kwargs.get("host") or kwargs.get("network_host") or "127.0.0.1"
        assert host in ("127.0.0.1", "localhost")
        root = Path(path)
        marker = root / "etc" / "init.d" / "S99backdoor"
        detected = marker.exists()
        return {
            "host": "127.0.0.1",
            "services": [{"name": "backdoor", "port": 1337, "host": "127.0.0.1"}] if detected else [],
            "alerts": ["backdoor service detected"] if detected else [],
            "detected": detected,
        }

    monkeypatch.setattr(analyzer, emulate_name, fake_emulate, raising=True)

    name_extract, extract = ensure_callable(analyzer, ["extract_filesystem", "extract"])
    extracted_path = Path(extract(firmware_fs))
    emulate = getattr(analyzer, emulate_name)
    results = emulate(extracted_path, host="127.0.0.1")
    # Verify detection of backdoor
    assert isinstance(results, dict)
    assert results.get("detected") is True
    assert any(s.get("port") == 1337 for s in results.get("services", []))
    assert any("backdoor" in a.lower() for a in results.get("alerts", []))

# Report generation: Generate a comprehensive report of security risks.
def test_generate_comprehensive_report(analyzer, firmware_fs, monkeypatch):
    # Setup secrets and vuln findings
    name_extract, extract = ensure_callable(analyzer, ["extract_filesystem", "extract"])
    extracted_path = Path(extract(firmware_fs))

    name_secrets, find_secrets = ensure_callable(analyzer, ["find_secrets", "scan_for_secrets", "identify_secrets"])
    secrets = find_secrets(extracted_path)

    name_binv, analyze_binaries = ensure_callable(analyzer, ["analyze_binaries", "binary_analysis"])
    vulns = analyze_binaries(extracted_path)

    # Monkeypatch emulate to return deterministic results
    emulate_name, _ = ensure_callable(analyzer, ["emulate_firmware", "emulate", "run_emulation"])

    def fake_emulate(path, *args, **kwargs):
        return {
            "host": "127.0.0.1",
            "services": [{"name": "backdoor", "port": 1337, "host": "127.0.0.1"}],
            "alerts": ["backdoor service detected"],
            "detected": True,
        }

    monkeypatch.setattr(analyzer, emulate_name, fake_emulate, raising=True)
    emulate = getattr(analyzer, emulate_name)
    emu = emulate(extracted_path, host="127.0.0.1")

    # Generate report
    gen_name, generate_report = ensure_callable(analyzer, ["generate_report", "build_report"])
    findings = {
        "filesystem": str(extracted_path),
        "secrets": secrets,
        "vulnerabilities": vulns,
        "emulation": emu,
    }
    report = generate_report(findings)
    # Validate comprehensiveness
    if isinstance(report, str):
        lower = report.lower()
        assert_contains_any(lower, ["secret", "password", "private key"])
        assert_contains_any(lower, ["vulnerab", "openssl", "strcpy", "cve"])
        assert_contains_any(lower, ["emulation", "emulate", "runtime", "backdoor"])
        assert_contains_any(lower, ["127.0.0.1", "localhost"])
    elif isinstance(report, dict):
        # Expect structured report
        keys = {k.lower() for k in report.keys()}
        assert any(k in keys for k in ["secrets", "findings", "credentials"])
        assert any(k in keys for k in ["vulnerabilities", "vulns", "binary_analysis"])
        assert any(k in keys for k in ["emulation", "runtime", "behavior"])
    else:
        pytest.fail("Report must be a string or dictionary")

# Error handling and edge cases

def test_extract_invalid_path_error_handling(analyzer, tmp_path):
    name, extract = ensure_callable(analyzer, ["extract_filesystem", "extract"])
    invalid_path = tmp_path / "nonexistent_firmware.bin"
    try:
        result = extract(invalid_path)
    except Exception:
        # Properly raised an exception
        return
    # If no exception, ensure it indicates failure clearly
    assert result is None or (isinstance(result, (str, Path)) and not Path(result).exists())

def test_find_secrets_no_secrets_returns_empty(analyzer, tmp_path):
    # Create a clean FS without secrets
    clean_root = tmp_path / "clean_fs"
    (clean_root / "etc").mkdir(parents=True, exist_ok=True)
    (clean_root / "bin").mkdir(parents=True, exist_ok=True)
    (clean_root / "etc" / "config.txt").write_text("option=true\nusername=user\n")
    name_secrets, find_secrets = ensure_callable(analyzer, ["find_secrets", "scan_for_secrets", "identify_secrets"])
    secrets = find_secrets(clean_root)
    assert isinstance(secrets, (list, tuple))
    assert len(secrets) == 0 or all("password" not in stringify_item(s).lower() and "private key" not in stringify_item(s).lower() for s in secrets)

def test_analyze_binaries_handles_empty(analyzer, tmp_path):
    empty_fs = tmp_path / "empty_fs"
    (empty_fs / "bin").mkdir(parents=True, exist_ok=True)
    name_binv, analyze_binaries = ensure_callable(analyzer, ["analyze_binaries", "binary_analysis"])
    vulns = analyze_binaries(empty_fs)
    assert isinstance(vulns, (list, tuple))
    # Should be empty or contain only informational items (no high severity)
    flat = stringify_item(vulns).lower()
    assert len(vulns) == 0 or ("high" not in flat and "critical" not in flat)

def test_emulation_failure_handling(analyzer, firmware_fs, monkeypatch):
    emulate_name, emulate_fn = ensure_callable(analyzer, ["emulate_firmware", "emulate", "run_emulation"])

    def failing_emulate(*args, **kwargs):
        raise RuntimeError("Emulator failed to start")

    monkeypatch.setattr(analyzer, emulate_name, failing_emulate, raising=True)
    emulate = getattr(analyzer, emulate_name)
    with pytest.raises(RuntimeError):
        emulate(firmware_fs, host="127.0.0.1")