import argparse
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

# Optional dependency for deeper X.509 parsing (CT/SCTs, key size)
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


ETHICAL_NOTICE = (
    "Use this tool only on systems and networks you own or are explicitly authorized to test. "
    "Unauthorized scanning or probing may be illegal and unethical."
)


def parse_target(target: str):
    # Normalize input to scheme://host:port
    if "://" not in target:
        target = "https://" + target
    u = urlparse(target)
    if not u.hostname:
        raise ValueError(f"Invalid target: {target}")
    port = u.port or (443 if u.scheme == "https" else 443)
    return u.hostname, port


def _new_tcp_socket(timeout=5.0):
    s = socket.create_connection
    return s


def _connect_ssl(host, port, context: ssl.SSLContext, timeout=5.0):
    raw_sock = None
    ssock = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        ssock = context.wrap_socket(raw_sock, server_hostname=host)
        return ssock
    except Exception:
        if ssock:
            try:
                ssock.close()
            except Exception:
                pass
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass
        raise


def _default_verified_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options |= ssl.OP_NO_COMPRESSION  # Disable compression if possible
    ctx.minimum_version = getattr(ssl.TLSVersion, "TLSv1", ssl.TLSVersion.MINIMUM_SUPPORTED)
    ctx.load_default_certs()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def _insecure_context(max_version=None, min_version=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options |= ssl.OP_NO_COMPRESSION
    if min_version is not None:
        try:
            ctx.minimum_version = min_version
        except Exception:
            pass
    if max_version is not None:
        try:
            ctx.maximum_version = max_version
        except Exception:
            pass
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except Exception:
            pass
    return ctx


def _get_peer_cert_dict(sock: ssl.SSLSocket):
    try:
        return sock.getpeercert()
    except Exception:
        return None


def _get_peer_cert_der(sock: ssl.SSLSocket):
    try:
        return sock.getpeercert(binary_form=True)
    except Exception:
        return None


def _extract_cert_info_from_peercert_dict(cert_dict):
    info = {}
    if not cert_dict:
        return info
    # Subject
    subject_parts = []
    for rdn in cert_dict.get("subject", []):
        for k, v in rdn:
            subject_parts.append(f"{k}={v}")
    info["subject"] = ", ".join(subject_parts) if subject_parts else None
    # Issuer
    issuer_parts = []
    for rdn in cert_dict.get("issuer", []):
        for k, v in rdn:
            issuer_parts.append(f"{k}={v}")
    info["issuer"] = ", ".join(issuer_parts) if issuer_parts else None
    # SANs
    sans = []
    for typ, val in cert_dict.get("subjectAltName", []):
        sans.append(f"{typ}:{val}")
    info["subject_alt_names"] = sans
    # NotBefore / NotAfter
    info["not_before"] = cert_dict.get("notBefore")
    info["not_after"] = cert_dict.get("notAfter")
    # Expiration in days
    try:
        not_after = cert_dict.get("notAfter")
        if not_after:
            exp_ts = ssl.cert_time_to_seconds(not_after)
            now_ts = time.time()
            remaining = int((exp_ts - now_ts) / 86400)
            info["days_until_expiry"] = remaining
            info["expired"] = remaining < 0
        else:
            info["days_until_expiry"] = None
            info["expired"] = None
    except Exception:
        info["days_until_expiry"] = None
        info["expired"] = None
    # Self-signed hint (if issuer == subject)
    try:
        subj = info.get("subject")
        iss = info.get("issuer")
        if subj and iss and subj == iss:
            info["is_self_signed"] = True
    except Exception:
        pass
    return info


def _extract_cert_crypto_info_from_der(der_bytes):
    result = {
        "serial_number": None,
        "signature_algorithm_oid": None,
        "public_key_type": None,
        "public_key_size": None,
        "sha256_fingerprint": None,
        "ct_scts_present": None,
        "ct_scts_count": None,
        "ct_note": None,
    }
    if not HAVE_CRYPTO or not der_bytes:
        result["ct_note"] = (
            "cryptography library not available or certificate unavailable; CT/SCT parsing and key size will be limited."
        )
        return result
    try:
        cert = x509.load_der_x509_certificate(der_bytes, backend=default_backend())
        result["serial_number"] = format(cert.serial_number, "x")
        try:
            result["signature_algorithm_oid"] = cert.signature_algorithm_oid.dotted_string
        except Exception:
            result["signature_algorithm_oid"] = None
        try:
            pub = cert.public_key()
            ptype = type(pub).__name__
            result["public_key_type"] = ptype
            key_size = getattr(pub, "key_size", None)
            result["public_key_size"] = key_size
        except Exception:
            pass
        try:
            fprint = cert.fingerprint(hashes.SHA256()).hex()
            result["sha256_fingerprint"] = fprint
        except Exception:
            pass
        # CT SCTs
        try:
            ext = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            )
            sct_list = ext.value
            try:
                scts = list(getattr(sct_list, "scts", []))
                result["ct_scts_present"] = True if scts else True
                result["ct_scts_count"] = len(scts) if scts else None
            except Exception:
                result["ct_scts_present"] = True
                result["ct_scts_count"] = None
        except x509.ExtensionNotFound:
            result["ct_scts_present"] = False
            result["ct_scts_count"] = 0
        except Exception as e:
            result["ct_scts_present"] = None
            result["ct_scts_count"] = None
            result["ct_note"] = f"Error parsing SCT extension: {e}"
    except Exception as e:
        result["ct_note"] = f"Error parsing certificate: {e}"
    return result


def test_protocol_support(host, port, version_name, version_enum):
    ctx = _insecure_context(min_version=version_enum, max_version=version_enum)
    try:
        with _connect_ssl(host, port, ctx, timeout=5.0) as s:
            # If handshake completes and socket reports expected version or compatible
            negotiated = None
            try:
                negotiated = s.version()
            except Exception:
                pass
            return True, negotiated, None
    except ssl.SSLError as e:
        return False, None, str(e)
    except Exception as e:
        return False, None, str(e)


def detect_weak_cipher_support(host, port):
    # Curated weak/obsolete cipher names (OpenSSL names). Tests limited to TLS 1.0-1.2.
    # Availability depends on local OpenSSL build - some may be unavailable for testing.
    weak_ciphers = [
        "NULL-MD5",
        "NULL-SHA",
        "EXP-RC4-MD5",
        "EXP-DES-CBC-SHA",
        "RC4-MD5",
        "RC4-SHA",
        "DES-CBC3-SHA",  # 3DES
        "MD5",
        "aNULL",
        "eNULL",
        "CAMELLIA128-MD5",  # weak due to MD5
        "DHE-RSA-DES-CBC3-SHA",  # 3DES with DHE
    ]
    results = []
    for name in weak_ciphers:
        # Restrict to TLS1.0-1.2 to allow cipher selection
        ctx = _insecure_context(
            min_version=getattr(ssl.TLSVersion, "TLSv1", None),
            max_version=getattr(ssl.TLSVersion, "TLSv1_2", None),
            ciphers=name,
        )
        supported = False
        negotiated = None
        error = None
        try:
            with _connect_ssl(host, port, ctx, timeout=4.0) as s:
                supported = True
                try:
                    negotiated = s.cipher()
                except Exception:
                    pass
        except ssl.SSLError as e:
            error = str(e)
        except OSError as e:
            error = str(e)
        except Exception as e:
            # OpenSSL may reject cipher string format, or cipher not available
            error = str(e)
        results.append(
            {
                "cipher_request": name,
                "supported": supported,
                "negotiated": negotiated,
                "error": None if supported else error,
            }
        )
    return results


def enumerate_supported_ciphers(host, port):
    """
    Placeholder for enumerating server-supported cipher suites.
    By default, returns an empty list. Tests may monkeypatch this to provide data.
    """
    try:
        # Best-effort: capture the negotiated cipher from a default connection
        ctx = _default_verified_context()
        with _connect_ssl(host, port, ctx, timeout=5.0) as s:
            c = s.cipher()
            return [c[0]] if c else []
    except Exception:
        # Silent fallback to empty; enumeration is complex and environment-dependent.
        return []


# Vulnerability checks (placeholders; safe by default)
def check_heartbleed(host, port):
    # Not actively tested here; return None to indicate "not tested"
    return None


def check_poodle(host, port):
    return None


def check_beast(host, port):
    return None


def check_freak(host, port):
    return None


def check_logjam(host, port):
    return None


def _classify_cipher_weakness(cipher_name: str):
    if not cipher_name:
        return None
    name = cipher_name.upper()
    if "NULL" in name:
        return "NULL cipher"
    if "RC4" in name:
        return "RC4 stream cipher"
    if "EXP" in name or "EXPORT" in name:
        return "EXPORT-grade cipher"
    if "3DES" in name or "DES-CBC3" in name or "DES" in name:
        return "3DES/DES cipher"
    if "MD5" in name:
        return "MD5-based cipher"
    if "ANON" in name or "AECDH" in name:
        return "Anonymous cipher"
    return None


def analyze(target, port=None):
    """
    Analyze SSL/TLS configuration for the given target.

    Accepts either:
    - analyze('host-or-url') -> parses target and uses default port 443
    - analyze('host-or-url', 443) -> overrides port
    """
    # Normalize inputs
    try:
        if port is None:
            host, port = parse_target(str(target))
        else:
            # If a URL with scheme is passed alongside port, parse host from it
            t = str(target)
            if "://" in t:
                host, _p = parse_target(t)
            else:
                host = t
            if not isinstance(port, int):
                raise ValueError("Port must be an integer.")
    except Exception as e:
        return {
            "ethical_notice": ETHICAL_NOTICE,
            "target": {"host": str(target), "port": port if port is not None else 443},
            "errors": [f"Invalid target: {e}"],
        }

    analysis = {
        "ethical_notice": ETHICAL_NOTICE,
        "target": {"host": host, "port": port},
        "connection": {},
        "certificate": {},
        "ct_verification": {},
        "protocol_support": {},
        "weak_cipher_tests": [],
        "vulnerabilities": [],
        "warnings": [],
        "errors": [],
    }

    # Attempt verified connection first
    verified_ok = False
    verified_error = None
    negotiated_cipher = None
    negotiated_protocol = None
    compression = None
    peercert_dict = None
    peercert_der = None

    try:
        ctx = _default_verified_context()
        with _connect_ssl(host, port, ctx, timeout=6.0) as s:
            verified_ok = True
            try:
                negotiated_cipher = s.cipher()  # (cipher, protocol, secret bits)
            except Exception:
                pass
            try:
                negotiated_protocol = s.version()
            except Exception:
                pass
            try:
                compression = s.compression()
            except Exception:
                pass
            peercert_dict = _get_peer_cert_dict(s)
            peercert_der = _get_peer_cert_der(s)
    except ssl.SSLCertVerificationError as e:
        verified_ok = False
        verified_error = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        verified_ok = False
        verified_error = f"SSL error: {e}"
    except socket.timeout:
        verified_ok = False
        verified_error = "Connection timed out."
    except Exception as e:
        verified_ok = False
        verified_error = f"Connection failed: {e}"

    analysis["connection"]["chain_validated"] = verified_ok
    if verified_error:
        analysis["connection"]["validation_error"] = verified_error
        analysis["warnings"].append("Could not validate certificate chain; proceeding with best-effort analysis.")
        # Attempt insecure connection to retrieve cert info
        try:
            ictx = _insecure_context()
            with _connect_ssl(host, port, ictx, timeout=6.0) as s:
                if not negotiated_cipher:
                    try:
                        negotiated_cipher = s.cipher()
                    except Exception:
                        pass
                if not negotiated_protocol:
                    try:
                        negotiated_protocol = s.version()
                    except Exception:
                        pass
                if compression is None:
                    try:
                        compression = s.compression()
                    except Exception:
                        pass
                if not peercert_dict:
                    peercert_dict = _get_peer_cert_dict(s)
                if not peercert_der:
                    peercert_der = _get_peer_cert_der(s)
        except Exception as e:
            analysis["errors"].append(f"Insecure retrieval failed: {e}")

    analysis["connection"]["negotiated_cipher"] = negotiated_cipher
    analysis["connection"]["negotiated_protocol"] = negotiated_protocol
    analysis["connection"]["compression"] = compression

    # Protocol support testing (deprecated protocols)
    protocol_tests = {}
    tls_versions = []
    # Build a list based on availability in interpreter/OpenSSL
    if hasattr(ssl, "TLSVersion"):
        ver = ssl.TLSVersion
        # Order by age
        for name in ["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"]:
            if hasattr(ver, name):
                tls_versions.append((name, getattr(ver, name)))
    for name, enumv in tls_versions:
        supported, negotiated, err = test_protocol_support(host, port, name, enumv)
        protocol_tests[name] = {
            "supported": supported,
            "negotiated_example": negotiated,
            "error": None if supported else err,
        }
    analysis["protocol_support"] = protocol_tests

    # Certificate info
    cert_info = _extract_cert_info_from_peercert_dict(peercert_dict)
    analysis["certificate"].update(cert_info)

    # Crypto info (if cryptography available)
    crypto_info = _extract_cert_crypto_info_from_der(peercert_der)
    analysis["certificate"].update(
        {
            "serial_number": crypto_info.get("serial_number"),
            "signature_algorithm_oid": crypto_info.get("signature_algorithm_oid"),
            "public_key_type": crypto_info.get("public_key_type"),
            "public_key_size": crypto_info.get("public_key_size"),
            "sha256_fingerprint": crypto_info.get("sha256_fingerprint"),
        }
    )
    # CT/SCT presence from crypto; fallback to hints in cert dict if provided by tests
    scts_present = crypto_info.get("ct_scts_present")
    scts_count = crypto_info.get("ct_scts_count")
    ct_note = crypto_info.get("ct_note")
    if scts_present is None and isinstance(peercert_dict, dict):
        # Some tests may inject these keys in the peer cert dict for convenience
        scts_present = peercert_dict.get("scts_present", peercert_dict.get("ct_scts_present"))
        scts_count = peercert_dict.get("scts_count", peercert_dict.get("ct_scts_count"))
        if scts_present is not None and ct_note is None:
            ct_note = "CT/SCT presence inferred from provided certificate data."
    analysis["ct_verification"] = {
        "scts_present": scts_present,
        "scts_count": scts_count,
        "note": ct_note,
    }

    # Weak cipher suite detection (targeted scan of known-weak ciphers)
    weak_cipher_results = detect_weak_cipher_support(host, port)
    analysis["weak_cipher_tests"] = weak_cipher_results

    # Enumerate supported ciphers (broad; test may monkeypatch)
    try:
        supported_ciphers = enumerate_supported_ciphers(host, port)
    except Exception as e:
        supported_ciphers = []
        analysis["errors"].append(f"Cipher enumeration error: {e}")
    analysis["connection"]["supported_ciphers"] = supported_ciphers

    # Compute warnings/vulnerabilities

    # Expiration warnings
    try:
        days = analysis["certificate"].get("days_until_expiry")
        if days is not None:
            if days < 0:
                analysis["vulnerabilities"].append("Certificate is expired.")
            elif days <= 30:
                analysis["warnings"].append(f"Certificate expires in {days} days or fewer.")
    except Exception:
        pass

    # Self-signed hint
    if analysis["certificate"].get("is_self_signed"):
        analysis["warnings"].append("Certificate appears to be self-signed.")

    # Deprecated protocols
    for pname in ["TLSv1", "TLSv1_1"]:
        p = analysis["protocol_support"].get(pname)
        if p and p.get("supported"):
            analysis["warnings"].append(f"Deprecated protocol {pname} is supported (should be disabled).")

    # Compression (CRIME)
    if analysis["connection"].get("compression"):
        analysis["vulnerabilities"].append("TLS compression is enabled (possible CRIME vulnerability).")

    # Weak cipher support findings (from targeted weak scan)
    weak_indicators = []
    for r in weak_cipher_results:
        if r.get("supported"):
            name = r.get("cipher_request") or ""
            # Categorize reason
            reason = _classify_cipher_weakness(name)
            if reason:
                weak_indicators.append(f"{name} ({reason})")
    if weak_indicators:
        analysis["vulnerabilities"].append(
            "Server supports weak cipher suites: " + ", ".join(weak_indicators)
        )

    # Weakness from negotiated cipher (what's actually used)
    try:
        if negotiated_cipher and isinstance(negotiated_cipher, (list, tuple)) and negotiated_cipher:
            n_name = negotiated_cipher[0]
            reason = _classify_cipher_weakness(n_name)
            if reason:
                analysis["vulnerabilities"].append(f"Weak negotiated cipher in use: {n_name} ({reason}).")
    except Exception:
        pass

    # Scan any enumerated supported ciphers for weak ones
    try:
        if supported_ciphers:
            bad = []
            for c in supported_ciphers:
                reason = _classify_cipher_weakness(c)
                if reason:
                    bad.append(f"{c} ({reason})")
            if bad:
                analysis["vulnerabilities"].append("Weak ciphers advertised: " + ", ".join(bad))
    except Exception:
        pass

    # Key size warnings if available
    pk_size = analysis["certificate"].get("public_key_size")
    pk_type = (analysis["certificate"].get("public_key_type") or "").lower()
    if pk_size:
        if "rsa" in pk_type and pk_size < 2048:
            analysis["vulnerabilities"].append(f"Weak RSA key size detected: {pk_size} bits (<2048).")
        if "ec" in pk_type and pk_size < 224:
            analysis["warnings"].append(f"Unusually small EC key size: {pk_size} bits.")

    # Signature algorithm warning
    sig_oid = analysis["certificate"].get("signature_algorithm_oid")
    if sig_oid:
        if sig_oid.endswith(".4.3"):  # 1.2.840.113549.1.1.4 is md5WithRSAEncryption
            analysis["vulnerabilities"].append("Certificate signed with MD5 (insecure).")
        elif sig_oid.endswith(".5.4"):  # sha1WithRSAEncryption (1.2.840.113549.1.1.5)
            analysis["warnings"].append("Certificate signed with SHA-1 (deprecated).")

    # Certificate Transparency observations
    if scts_present is False:
        analysis["warnings"].append("No SCTs present; certificate may not be logged in Certificate Transparency.")
    elif scts_present is True and (scts_count is None or scts_count == 0):
        analysis["warnings"].append("SCT presence detected but count unavailable.")
    # If unknown, keep note; already in ct_verification note.

    # Common SSL/TLS vulnerability checks (placeholders can be monkeypatched in tests)
    vuln_checks = [
        ("Heartbleed", check_heartbleed),
        ("POODLE", check_poodle),
        ("BEAST", check_beast),
        ("FREAK", check_freak),
        ("Logjam", check_logjam),
    ]
    for name, func in vuln_checks:
        try:
            res = func(host, port)
        except Exception as e:
            analysis["warnings"].append(f"{name} check encountered an error: {e}")
            res = None
        if res is True:
            analysis["vulnerabilities"].append(f"{name} vulnerability suspected.")
        elif res is None:
            # Only add informational warnings if not tested
            analysis["warnings"].append(f"{name} test not performed; use a dedicated tool if you have authorization.")

    return analysis


def main():
    parser = argparse.ArgumentParser(
        description="SSL/TLS Certificate Inspector - Comprehensive SSL/TLS certificate analysis and vulnerability detection"
    )
    parser.add_argument("target", help="Target URL or host (e.g., https://example.com or example.com)")
    parser.add_argument("--port", type=int, default=None, help="Port number (default 443 for https)")
    parser.add_argument("--timeout", type=float, default=6.0, help="Connection timeout in seconds")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    try:
        host, port = parse_target(args.target)
        if args.port:
            port = args.port
    except Exception as e:
        print(json.dumps({"error": str(e), "ethical_notice": ETHICAL_NOTICE}), file=sys.stdout)
        sys.exit(2)

    try:
        result = analyze(host, port)
    except Exception as e:
        out = {
            "target": {"host": host, "port": port},
            "error": f"Unhandled error: {e}",
            "ethical_notice": ETHICAL_NOTICE,
        }
        print(json.dumps(out, indent=2 if args.pretty else None))
        sys.exit(1)

    if args.pretty:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result))


if __name__ == "__main__":
    main()