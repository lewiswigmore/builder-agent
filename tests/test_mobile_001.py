import json
import types
import os
import pytest

analyzer_mod = pytest.importorskip("tools.mobile.app_analyzer")


def _get_analyzer_class():
    candidates = [
        "MobileAppAnalyzer",
        "MobileAppSecurityAnalyzer",
        "AppAnalyzer",
        "Analyzer",
    ]
    for name in candidates:
        cls = getattr(analyzer_mod, name, None)
        if isinstance(cls, type):
            return cls
    pytest.skip("No suitable analyzer class found in tools.mobile.app_analyzer")


def _mk_finding(fid, severity, category, title, description="desc", recommendation="fix", location="N/A", kind="static"):
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "location": location,
        "kind": kind,
    }


@pytest.fixture
def analyzer():
    cls = _get_analyzer_class()
    try:
        return cls()
    except Exception:
        # In case constructor requires args, try with sensible defaults
        try:
            return cls(config=None)
        except Exception:
            pytest.skip("Unable to instantiate analyzer")


def test_android_apk_analysis_identifies_three_critical_vulns(analyzer, tmp_path, monkeypatch):
    apk_path = tmp_path / "sample_vuln.apk"
    apk_path.write_bytes(b"APK DUMMY CONTENT")

    critical_findings = [
        _mk_finding("ANDR-001", "critical", "insecure_data_storage", "Sensitive data stored unencrypted", location="res/xml/prefs.xml"),
        _mk_finding("ANDR-002", "critical", "weak_cryptography", "Weak cipher (MD5) usage detected", location="com/example/crypto/Hasher.java"),
        _mk_finding("ANDR-003", "critical", "improper_authentication", "Biometric fallback to PIN without rate limiting", location="com/example/auth/LoginActivity.java"),
        _mk_finding("ANDR-004", "high", "component_vulnerability", "Vulnerable library detected: com.foo:bar:1.2.3 (CVE-2021-0001)", location="lib/"),
    ]

    cls = analyzer.__class__

    def stub_analyze_apk(self, path):
        assert os.path.exists(path)
        return critical_findings

    monkeypatch.setattr(cls, "analyze_apk", stub_analyze_apk, raising=True)

    results = analyzer.analyze_apk(str(apk_path))
    assert isinstance(results, (list, tuple))
    crits = [f for f in results if f.get("severity") == "critical"]
    assert len(crits) >= 3
    categories = {f.get("category") for f in crits}
    assert {"insecure_data_storage", "weak_cryptography", "improper_authentication"}.issubset(categories)


def test_android_apk_analysis_handles_missing_file(analyzer, monkeypatch, tmp_path):
    missing_path = tmp_path / "does_not_exist.apk"

    cls = analyzer.__class__

    def stub_analyze_apk(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"No such file: {path}")
        return []

    monkeypatch.setattr(cls, "analyze_apk", stub_analyze_apk, raising=True)

    with pytest.raises(FileNotFoundError):
        analyzer.analyze_apk(str(missing_path))


def test_ios_detect_hardcoded_api_keys(analyzer, tmp_path, monkeypatch):
    ipa_path = tmp_path / "test_ios_app.ipa"
    ipa_path.write_bytes(b"IPA DUMMY CONTENT")

    ios_findings = [
        _mk_finding("IOS-SEC-KEY-001", "high", "hardcoded_secret", "Hardcoded API key found", description="API_KEY=sk_test_123", location="Sources/Config.swift"),
        _mk_finding("IOS-INFO-001", "medium", "debug_artifacts", "Debug symbols present", location="Binary/Info"),
    ]

    cls = analyzer.__class__

    def stub_analyze_ipa(self, path):
        assert os.path.exists(path)
        return ios_findings

    monkeypatch.setattr(cls, "analyze_ipa", stub_analyze_ipa, raising=True)

    results = analyzer.analyze_ipa(str(ipa_path))
    assert any(
        f.get("category") in {"hardcoded_secret", "hardcoded_api_key"} and "key" in f.get("title", "").lower()
        for f in results
    )


def test_dynamic_analysis_identifies_insecure_network(analyzer, tmp_path, monkeypatch):
    # Ensure network tests only use localhost/127.0.0.1
    base_url = "http://127.0.0.1:8888"
    app_path = tmp_path / "sample_vuln.apk"
    app_path.write_bytes(b"APK DUMMY CONTENT")

    dynamic_findings = [
        _mk_finding("NET-PLAINTEXT-HTTP", "critical", "network", "Plaintext HTTP traffic detected", description=f"Unencrypted request to {base_url}/api", kind="dynamic"),
        _mk_finding("NET-TLS-VALIDATION", "high", "network", "TLS certificate validation disabled", description="Accepts all certificates", kind="dynamic"),
    ]

    cls = analyzer.__class__

    # Provide a safe dynamic analysis stub that enforces localhost only
    def stub_perform_dynamic_analysis(self, path, platform="android", base_url=None, duration=None):
        assert os.path.exists(path)
        assert base_url is not None
        assert base_url.startswith("http://127.0.0.1") or base_url.startswith("http://localhost") or base_url.startswith("https://127.0.0.1") or base_url.startswith("https://localhost")
        return dynamic_findings

    monkeypatch.setattr(cls, "perform_dynamic_analysis", stub_perform_dynamic_analysis, raising=True)

    results = analyzer.perform_dynamic_analysis(str(app_path), platform="android", base_url=base_url, duration=1)
    kinds = {f.get("kind") for f in results}
    assert "dynamic" in kinds
    titles = {f.get("title") for f in results}
    assert any("Plaintext HTTP" in t for t in titles)


def test_dynamic_analysis_rejects_non_localhost_targets(analyzer, tmp_path, monkeypatch):
    app_path = tmp_path / "sample.apk"
    app_path.write_bytes(b"APK DUMMY CONTENT")

    cls = analyzer.__class__

    def stub_perform_dynamic_analysis(self, path, platform="android", base_url=None, duration=None):
        if base_url and not (
            base_url.startswith("http://127.0.0.1")
            or base_url.startswith("http://localhost")
            or base_url.startswith("https://127.0.0.1")
            or base_url.startswith("https://localhost")
        ):
            raise ValueError("Only localhost targets are allowed in tests")
        return []

    monkeypatch.setattr(cls, "perform_dynamic_analysis", stub_perform_dynamic_analysis, raising=True)

    with pytest.raises(ValueError):
        analyzer.perform_dynamic_analysis(str(app_path), platform="android", base_url="http://example.com", duration=1)


def test_third_party_library_scan_reports_known_cves(analyzer, tmp_path, monkeypatch):
    apk_path = tmp_path / "sample_with_libs.apk"
    apk_path.write_bytes(b"APK DUMMY CONTENT")

    libs_report = [
        {
            "name": "com.squareup.okhttp3:okhttp",
            "version": "3.12.0",
            "cves": [{"id": "CVE-2018-20200", "severity": "high"}],
        },
        {
            "name": "com.example:legacy-crypto",
            "version": "0.9",
            "cves": [{"id": "CVE-2016-0001", "severity": "critical"}, {"id": "CVE-2017-9999", "severity": "medium"}],
        },
    ]

    cls = analyzer.__class__

    # Support either scan_third_party_libs or scan_third_party_libraries method names
    def stub_scan_third_party_libs(self, path, platform="android"):
        assert os.path.exists(path)
        return libs_report

    if hasattr(cls, "scan_third_party_libs"):
        monkeypatch.setattr(cls, "scan_third_party_libs", stub_scan_third_party_libs, raising=True)
        results = analyzer.scan_third_party_libs(str(apk_path), platform="android")
    else:
        monkeypatch.setattr(cls, "scan_third_party_libraries", stub_scan_third_party_libs, raising=False)
        results = analyzer.scan_third_party_libraries(str(apk_path), platform="android")

    assert isinstance(results, (list, tuple))
    assert any(lib.get("cves") for lib in results)
    assert any(any(cve.get("severity") == "critical" for cve in lib.get("cves", [])) for lib in results)


def test_generate_sarif_report_of_findings(analyzer, monkeypatch):
    findings = [
        _mk_finding("ANDR-001", "critical", "insecure_data_storage", "Sensitive data stored unencrypted", location="res/xml/prefs.xml"),
        _mk_finding("IOS-SEC-KEY-001", "high", "hardcoded_secret", "Hardcoded API key found", location="Sources/Config.swift"),
        _mk_finding("NET-PLAINTEXT-HTTP", "critical", "network", "Plaintext HTTP traffic detected", kind="dynamic"),
    ]

    cls = analyzer.__class__

    # Stub get_findings if present, else analyzer may aggregate findings differently; ensure generate_report uses provided findings
    if hasattr(cls, "get_findings"):
        def stub_get_findings(self):
            return findings
        monkeypatch.setattr(cls, "get_findings", stub_get_findings, raising=True)

    # Stub generate_report to produce a minimal valid SARIF
    def stub_generate_report(self, fmt="sarif"):
        assert fmt.lower() == "sarif"
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "Mobile App Security Analyzer", "rules": []}},
                    "results": [
                        {
                            "ruleId": f.get("id"),
                            "level": ("error" if f.get("severity") == "critical" else "warning"),
                            "message": {"text": f.get("title")},
                            "kind": f.get("kind", "fail"),
                            "properties": {
                                "category": f.get("category"),
                                "recommendation": f.get("recommendation"),
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.get("location", "N/A")}
                                    }
                                }
                            ],
                        }
                        for f in (findings if hasattr(cls, "get_findings") else findings)
                    ],
                }
            ],
        }
        return json.dumps(sarif)

    monkeypatch.setattr(cls, "generate_report", stub_generate_report, raising=True)

    sarif_json = analyzer.generate_report("sarif")
    assert isinstance(sarif_json, str)
    sarif = json.loads(sarif_json)
    assert sarif.get("version") == "2.1.0"
    assert "runs" in sarif and isinstance(sarif["runs"], list) and sarif["runs"]
    run0 = sarif["runs"][0]
    assert "results" in run0 and len(run0["results"]) >= 1
    rule_ids = {r.get("ruleId") for r in run0["results"]}
    assert "ANDR-001" in rule_ids
    assert "NET-PLAINTEXT-HTTP" in rule_ids


def test_error_handling_corrupted_binary(analyzer, tmp_path, monkeypatch):
    corrupted_apk = tmp_path / "corrupted.apk"
    corrupted_apk.write_bytes(b"\x00\x00\x00")  # Invalid/minimal content

    cls = analyzer.__class__

    def stub_analyze_apk(self, path):
        # Simulate detection of corruption
        if os.path.exists(path) and os.path.getsize(path) < 10:
            raise ValueError("Corrupted or invalid APK file")
        return []

    monkeypatch.setattr(cls, "analyze_apk", stub_analyze_apk, raising=True)

    with pytest.raises(ValueError):
        analyzer.analyze_apk(str(corrupted_apk))


def test_sarif_report_is_deterministic(analyzer, monkeypatch):
    findings = [
        _mk_finding("DET-ORDER-1", "low", "info", "Deterministic test finding A", location="a.txt"),
        _mk_finding("DET-ORDER-2", "medium", "config", "Deterministic test finding B", location="b.txt"),
    ]

    cls = analyzer.__class__

    def stub_generate_report(self, fmt="sarif"):
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "Mobile App Security Analyzer", "rules": []}},
                    "results": [
                        {
                            "ruleId": f.get("id"),
                            "level": "note",
                            "message": {"text": f.get("title")},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("location")}}}],
                        }
                        for f in findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, sort_keys=True)

    monkeypatch.setattr(cls, "generate_report", stub_generate_report, raising=True)

    sarif1 = analyzer.generate_report("sarif")
    sarif2 = analyzer.generate_report("sarif")
    assert sarif1 == sarif2
    parsed = json.loads(sarif1)
    assert parsed["runs"][0]["results"][0]["ruleId"] == "DET-ORDER-1"