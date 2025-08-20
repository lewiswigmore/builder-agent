import pytest
import types
import datetime as dt

inspector = pytest.importorskip("tools.vuln.cert_inspector")


def _get_analyzer(module):
    # Try common entry points
    if hasattr(module, "CertificateInspector"):
        try:
            obj = module.CertificateInspector()
            if hasattr(obj, "analyze") and callable(obj.analyze):
                return obj.analyze
        except Exception:
            pass
    for name in ("analyze", "analyze_target", "inspect", "inspect_target", "run"):
        if hasattr(module, name) and callable(getattr(module, name)):
            return getattr(module, name)
    pytest.skip("No usable analyze function or class in cert_inspector")


def _ssl_time_fmt(d):
    # Format as returned by ssl.getpeercert() textual dict
    return d.strftime("%b %d %H:%M:%S %Y GMT")


def _build_fake_cert_dict(
    subject_cn="example.com",
    issuer_cn="Example CA",
    not_before=None,
    not_after=None,
    san_list=None,
    scts_present=True,
    sig_alg="sha256WithRSAEncryption",
    is_self_signed=False,
):
    if not_before is None:
        not_before = dt.datetime.utcnow() - dt.timedelta(days=30)
    if not_after is None:
        not_after = dt.datetime.utcnow() + dt.timedelta(days=365)
    if san_list is None:
        san_list = [subject_cn]
    subj = ((("commonName", subject_cn),),)
    iss = ((("commonName", issuer_cn if not is_self_signed else subject_cn),),)
    cert = {
        "subject": subj,
        "issuer": iss,
        "notBefore": _ssl_time_fmt(not_before),
        "notAfter": _ssl_time_fmt(not_after),
        "subjectAltName": [("DNS", x) for x in san_list],
        "serialNumber": "01",
        "version": 3,
        # Non-standard additions some tools inspect
        "OCSP": ("http://ocsp.example.com/",),
        "caIssuers": ("http://ca.example.com/ca.der",),
        "signatureAlgorithm": sig_alg,
    }
    if scts_present:
        # Simulate presence of SCTs extension via a hint key the tool might check
        cert["signedCertificateTimestampList"] = True
    return cert


class FakePlainSocket:
    def __init__(self, host="localhost", port=443):
        self.host = host
        self.port = port
        self.closed = False

    def settimeout(self, t):
        pass

    def close(self):
        self.closed = True


class FakeSSLSocket(FakePlainSocket):
    def __init__(self, host, port, cert_dict, cipher_tuple, version="TLSv1.2"):
        super().__init__(host, port)
        self._cert_dict = cert_dict
        self._cipher_tuple = cipher_tuple
        self._version = version

    def getpeercert(self, binary_form=False):
        if binary_form:
            # Provide no binary form to avoid external parsing; consumer should handle dict form.
            # Return None or bytes object; using None can break. Return empty bytes.
            return b""
        return self._cert_dict

    def cipher(self):
        # Returns (cipher_name, protocol, secret_bits)
        return self._cipher_tuple

    def version(self):
        return self._version

    def selected_alpn_protocol(self):
        return "h2"

    def selected_npn_protocol(self):
        return None


class FakeSSLContext:
    def __init__(self, purpose=None, scenario=None):
        self.purpose = purpose
        self.scenario = scenario or {}
        self._ciphers = None
        self.verify_mode = getattr(inspector, "ssl", types.SimpleNamespace()).CERT_REQUIRED if hasattr(inspector, "ssl") and hasattr(inspector.ssl, "CERT_REQUIRED") else 2

    def set_ciphers(self, ciphers):
        self._ciphers = ciphers

    def set_alpn_protocols(self, protos):
        self._alpn = protos

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        self._cafile = cafile
        self._capath = capath
        self._cadata = cadata

    def wrap_socket(self, sock, server_hostname=None):
        cert = self.scenario.get(
            "cert",
            _build_fake_cert_dict(
                subject_cn=server_hostname or getattr(sock, "host", "localhost")
            ),
        )
        cipher = self.scenario.get("cipher", ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", 128))
        version = self.scenario.get("version", "TLSv1.2")
        return FakeSSLSocket(server_hostname or sock.host, sock.port, cert, cipher, version)

    def get_ciphers(self):
        # Return a list of dicts like CPython
        lst = []
        names = self.scenario.get(
            "supported_ciphers",
            [
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            ],
        )
        for name in names:
            lst.append({"name": name, "protocol": "TLSv1.2", "strength_bits": 128})
        return lst


class FakeSSLModule:
    # Constants that might be used
    CERT_NONE = 0
    CERT_OPTIONAL = 1
    CERT_REQUIRED = 2
    HAS_SNI = True
    PROTOCOL_TLS = 2

    def __init__(self, scenario=None):
        self.scenario = scenario or {}
        self._context = FakeSSLContext

    def create_default_context(self, purpose=None):
        return self._context(purpose=purpose, scenario=self.scenario)

    def get_server_certificate(self, addr, ssl_version=None, ca_certs=None):
        # Return a syntactically plausible PEM block; contents won't be parsed
        return "-----BEGIN CERTIFICATE-----\nMIIBqDCCAU2gAwIBAgIBADAKBggqhkjOPQQDAjASMRAwDgYDVQQDDAdGYWtlIENB\nMB4XDTI1MDExMTAwMDAwMFoXDTI4MDEwMTAwMDAwMFowFTETMBEGA1UEAwwKZmFr\nZS5sb2NhbDAqMAUGAytlcAMhAIU+v1/z0w+fZyTK8u0yBZJxpVdKZy2nV6GZmLAt\ns1YAo0IwQDAOBgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYD\nVR0OBBYEFOl0hT8z3iE8fH0pXvK0a5Qk8rK1MAoGCCqGSM49BAMCA0cAMEQCIHkX\ncHcV6W1j5wQF0I7cK+oN2cTj4Xk8u3rX5fQf8Zr6bAiA+o0sT7b0b3v2woV1x2BP\nm8sC3z5s1k6hKf1cR7Yv1QYqQw==\n-----END CERTIFICATE-----\n"

    class Purpose:
        SERVER_AUTH = object()


class FakeSocketModule:
    def __init__(self, fail_connect=False):
        self._fail_connect = fail_connect

    def create_connection(self, addr, timeout=None, source_address=None):
        host, port = addr
        if self._fail_connect:
            raise OSError("Simulated connection failure")
        return FakePlainSocket(host, port)


def _monkeypatch_io(monkeypatch, scenario=None, fail_connect=False):
    # Patch inspector module's ssl and socket to fakes
    fake_ssl = FakeSSLModule(scenario=scenario or {})
    fake_sock = FakeSocketModule(fail_connect=fail_connect)
    monkeypatch.setattr(inspector, "ssl", fake_ssl, raising=False)
    monkeypatch.setattr(inspector, "socket", fake_sock, raising=False)
    # If module references ssl at global names from time of import also patch in its namespace attributes
    return fake_ssl, fake_sock


def _get_field(data, *candidates):
    for key in candidates:
        if isinstance(key, (list, tuple)):
            cur = data
            ok = True
            for part in key:
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    ok = False
                    break
            if ok:
                return cur
        else:
            if isinstance(data, dict) and key in data:
                return data[key]
    return None


def test_analyze_google_certificate_mocked(monkeypatch):
    analyzer = _get_analyzer(inspector)
    now = dt.datetime.utcnow()
    scenario = {
        "cert": _build_fake_cert_dict(
            subject_cn="*.google.com",
            issuer_cn="GTS CA 1C3",
            not_before=now - dt.timedelta(days=10),
            not_after=now + dt.timedelta(days=200),
            san_list=["www.google.com", "google.com"],
            scts_present=True,
        ),
        "cipher": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", 128),
        "supported_ciphers": [
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ],
        "version": "TLSv1.3",
    }
    _monkeypatch_io(monkeypatch, scenario=scenario)

    result = analyzer("https://www.google.com")

    assert result is not None
    # Certificate present and includes SANs or subject
    cert = _get_field(result, "certificate", ["cert", "x509"], ["tls", "certificate"])
    assert cert is not None
    # Check subject or SAN contains google.com
    subj = _get_field(cert, "subject", "subject_cn", "common_name")
    san = _get_field(cert, "subjectAltName", "san", "dns_names")
    found_google = False
    if isinstance(subj, str):
        found_google = "google.com" in subj
    elif isinstance(subj, (list, tuple)):
        found_google = any("google.com" in str(x) for x in subj)
    if not found_google and san:
        if isinstance(san, (list, tuple)):
            found_google = any("google.com" in str(x) for x in san)
    assert found_google, "Expected google.com in subject or SAN"
    # Chain validation reported if present
    chain_valid = _get_field(result, "chain_valid", ["certificate", "chain_valid"], ["validation", "chain_valid"])
    if chain_valid is not None:
        assert chain_valid is True
    # Transparency verification
    transparency = _get_field(result, "transparency", "ct", ["certificate", "transparency"])
    if transparency is not None:
        verified = transparency.get("verified") if isinstance(transparency, dict) else None
        if verified is not None:
            assert verified is True


def test_detect_certificate_expiration_warning(monkeypatch):
    analyzer = _get_analyzer(inspector)
    now = dt.datetime.utcnow()
    scenario = {
        "cert": _build_fake_cert_dict(
            subject_cn="soon-expire.local",
            issuer_cn="Local CA",
            not_before=now - dt.timedelta(days=360),
            not_after=now + dt.timedelta(days=2),
            san_list=["soon-expire.local"],
            scts_present=False,
        ),
        "cipher": ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", 256),
    }
    _monkeypatch_io(monkeypatch, scenario=scenario)

    result = analyzer("localhost")

    cert = _get_field(result, "certificate", ["cert", "x509"], ["tls", "certificate"])
    assert cert is not None
    # Days remaining or expiring warning
    days_remaining = _get_field(cert, "days_remaining", "validity_days_remaining", "remaining_days")
    expiry = _get_field(cert, "notAfter", "not_after", ["validity", "not_after"])
    # If tool exposes days_remaining
    if days_remaining is not None:
        assert isinstance(days_remaining, int)
        assert days_remaining <= 2
    # Warning list
    warnings = _get_field(result, "warnings", "issues", ["report", "warnings"]) or []
    has_exp_warn = any("expir" in str(w).lower() for w in warnings)
    # If warnings are not provided at top level, check in certificate
    if not has_exp_warn:
        cert_warnings = _get_field(cert, "warnings", "issues") or []
        has_exp_warn = any("expir" in str(w).lower() for w in cert_warnings)
    assert has_exp_warn or days_remaining is not None or expiry is not None


def test_identify_cipher_suites(monkeypatch):
    analyzer = _get_analyzer(inspector)
    scenario = {
        "cert": _build_fake_cert_dict(subject_cn="cipher.local"),
        "cipher": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", 128),
        "supported_ciphers": [
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ],
    }
    _monkeypatch_io(monkeypatch, scenario=scenario)

    result = analyzer("127.0.0.1")

    # Selected cipher suite present
    selected = _get_field(result, "cipher", "cipher_suite", ["tls", "cipher"])
    if isinstance(selected, dict):
        name = selected.get("name") or selected.get("cipher") or selected.get("suite")
    else:
        name = selected
    assert selected is not None
    assert "AES_128_GCM" in str(name)
    # Supported ciphers list present
    supported = _get_field(result, "cipher_suites", "supported_ciphers", ["tls", "supported_ciphers"])
    if supported is not None:
        assert isinstance(supported, (list, tuple))
        assert any("AES_256_GCM" in str(x) or "AES_128_GCM" in str(x) for x in supported)


def test_flag_weak_encryption_algorithms(monkeypatch):
    analyzer = _get_analyzer(inspector)
    scenario = {
        "cert": _build_fake_cert_dict(subject_cn="weak.local"),
        "cipher": ("TLS_RSA_WITH_RC4_128_SHA", "TLSv1.0", 128),
        "supported_ciphers": [
            "TLS_RSA_WITH_RC4_128_SHA",
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
        ],
    }
    _monkeypatch_io(monkeypatch, scenario=scenario)

    result = analyzer("weak.local")

    # Look for weakness flags
    weak = False
    weaknesses = _get_field(result, "weak_ciphers", "weak_cipher_suites", "weaknesses")
    if weaknesses:
        weak = any(("RC4" in str(x)) or ("3DES" in str(x)) or ("EXPORT" in str(x)) or ("NULL" in str(x)) for x in weaknesses)
    if not weak:
        cipher_info = _get_field(result, "cipher", "cipher_suite", ["tls", "cipher"])
        if isinstance(cipher_info, dict):
            cipher_name = cipher_info.get("name") or cipher_info.get("cipher") or ""
        else:
            cipher_name = str(cipher_info)
        weak = ("RC4" in cipher_name) or ("3DES" in cipher_name) or ("EXPORT" in cipher_name) or ("NULL" in cipher_name)
    weak_flag = _get_field(result, "weak_encryption", "has_weak_ciphers", ["security", "weak"])
    if weak_flag is not None:
        assert bool(weak_flag) is True
    else:
        assert weak is True


def test_common_ssl_vulnerabilities_flags(monkeypatch):
    analyzer = _get_analyzer(inspector)
    scenario = {
        "cert": _build_fake_cert_dict(subject_cn="vuln.local"),
        "cipher": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", 128),
    }
    _monkeypatch_io(monkeypatch, scenario=scenario)

    # Monkeypatch potential vulnerability check functions to controlled outputs
    for name, val in (("check_heartbleed", False), ("check_poodle", True), ("check_beast", False), ("check_freak", False), ("check_logjam", False)):
        if hasattr(inspector, name):
            setattr(inspector, name, lambda *args, _val=val, **kwargs: _val)

    result = analyzer("vuln.local")

    vulns = _get_field(result, "vulnerabilities", "vulns", ["security", "vulnerabilities"])
    # If tool exposes vulnerabilities dict, check expected keys/values
    if isinstance(vulns, dict):
        if "heartbleed" in vulns:
            assert vulns["heartbleed"] is False
        if "poodle" in vulns:
            assert vulns["poodle"] is True
    else:
        # Alternatively, search warnings text for POODLE mention
        warnings = _get_field(result, "warnings", "issues", ["report", "warnings"]) or []
        assert any("poodle" in str(w).lower() for w in warnings) or vulns is not None


def test_certificate_transparency_verification(monkeypatch):
    analyzer = _get_analyzer(inspector)
    now = dt.datetime.utcnow()
    good_cert = _build_fake_cert_dict(
        subject_cn="ct.good.local",
        not_after=now + dt.timedelta(days=365),
        scts_present=True,
    )
    bad_cert = _build_fake_cert_dict(
        subject_cn="ct.bad.local",
        not_after=now + dt.timedelta(days=365),
        scts_present=False,
    )

    # Good CT
    _monkeypatch_io(monkeypatch, scenario={"cert": good_cert})
    result_good = analyzer("ct.good.local")
    trans = _get_field(result_good, "transparency", "ct", ["certificate", "transparency"])
    if isinstance(trans, dict) and "verified" in trans:
        assert trans["verified"] is True

    # Missing CT
    _monkeypatch_io(monkeypatch, scenario={"cert": bad_cert})
    result_bad = analyzer("ct.bad.local")
    trans = _get_field(result_bad, "transparency", "ct", ["certificate", "transparency"])
    if isinstance(trans, dict) and "verified" in trans:
        assert trans["verified"] in (False, None)


def test_error_handling_invalid_url(monkeypatch):
    analyzer = _get_analyzer(inspector)
    _monkeypatch_io(monkeypatch, scenario={})
    # Try invalid URL input; should handle gracefully
    try:
        result = analyzer("not a url")
    except Exception:
        # Accept raising ValueError or similar
        return
    # Or return error in result
    err = _get_field(result, "error", "errors", ["status", "error"])
    assert err is not None


def test_error_handling_connection_failure(monkeypatch):
    analyzer = _get_analyzer(inspector)
    _monkeypatch_io(monkeypatch, scenario={}, fail_connect=True)

    try:
        result = analyzer("localhost")
    except Exception:
        # Accept raised network exception being handled upstream
        return
    err = _get_field(result, "error", "errors", ["status", "error"])
    assert err is not None


def test_invalid_chain_and_self_signed(monkeypatch):
    analyzer = _get_analyzer(inspector)
    scenario = {
        "cert": _build_fake_cert_dict(
            subject_cn="selfsigned.local",
            issuer_cn="selfsigned.local",
            not_before=dt.datetime.utcnow() - dt.timedelta(days=10),
            not_after=dt.datetime.utcnow() + dt.timedelta(days=100),
            san_list=["selfsigned.local"],
            scts_present=False,
            is_self_signed=True,
        )
    }
    _monkeypatch_io(monkeypatch, scenario=scenario)

    result = analyzer("selfsigned.local")

    # Expect chain invalid or self-signed flagged
    chain_valid = _get_field(result, "chain_valid", ["certificate", "chain_valid"])
    if chain_valid is not None:
        assert chain_valid is False
    else:
        warnings = _get_field(result, "warnings", "issues", ["report", "warnings"]) or []
        assert any("self-signed" in str(w).lower() or "self signed" in str(w).lower() or "chain" in str(w).lower() for w in warnings)


def test_expired_certificate_detection(monkeypatch):
    analyzer = _get_analyzer(inspector)
    now = dt.datetime.utcnow()
    scenario = {
        "cert": _build_fake_cert_dict(
            subject_cn="expired.local",
            not_before=now - dt.timedelta(days=400),
            not_after=now - dt.timedelta(days=1),
            san_list=["expired.local"],
            scts_present=False,
        ),
        "cipher": ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", 128),
    }
    _monkeypatch_io(monkeypatch, scenario=scenario)

    result = analyzer("expired.local")

    cert = _get_field(result, "certificate", ["cert", "x509"], ["tls", "certificate"])
    assert cert is not None
    expired = _get_field(cert, "expired", "is_expired")
    if expired is not None:
        assert expired is True
    else:
        warnings = _get_field(result, "warnings", "issues") or []
        assert any("expired" in str(w).lower() for w in warnings)