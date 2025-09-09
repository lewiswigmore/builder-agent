import json
import os
import sys
import hashlib
import stat
import textwrap
import subprocess
import shlex
import pathlib
import pytest

watchdog_mod = pytest.importorskip("tools.vulnerability.hermetic_build_watchdog", reason="Hermetic Build Watchdog module not found")


def _find_watchdog_interface():
    # Try to discover a runner interface from the module
    runner = None
    instance = None

    # Candidate functions
    for fname in ("run_build", "run_in_sandbox", "run"):
        fn = getattr(watchdog_mod, fname, None)
        if callable(fn):
            runner = fn
            break

    # Candidate classes
    if runner is None:
        for cname in ("HermeticBuildWatchdog", "BuildWatchdog", "Watchdog"):
            cls = getattr(watchdog_mod, cname, None)
            if cls is not None:
                try:
                    instance = cls()
                except TypeError:
                    # Try a factory if available
                    factory = getattr(watchdog_mod, "create_default_watchdog", None) or getattr(
                        watchdog_mod, "default_watchdog", None
                    )
                    if callable(factory):
                        instance = factory()
                    else:
                        # Try init with no args first, otherwise with defaults
                        instance = cls()  # may still raise; let it bubble
                break

    # Determine method on instance
    if instance is not None and runner is None:
        for mname in ("run_build", "run", "execute", "execute_build"):
            m = getattr(instance, mname, None)
            if callable(m):
                def bound_runner(cmd, cwd, env=None, egress_allowlist=None, seed=1337, produce_sbom=True, sign_attestation=True):
                    # Try calling with flexible kwargs
                    kwargs_variants = [
                        dict(cwd=cwd, env=env, egress_allowlist=egress_allowlist, seed=seed,
                             produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                        dict(working_dir=cwd, env=env, egress_allowlist=egress_allowlist, seed=seed,
                             produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                        dict(workdir=cwd, env=env, egress_allowlist=egress_allowlist, seed=seed,
                             produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                        dict(cwd=cwd, env=env, allowlist=egress_allowlist, seed=seed,
                             produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                        dict(cwd=cwd, env=env, policy={"egress_allowlist": egress_allowlist}, seed=seed,
                             produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                        dict(cwd=cwd, env=env, config={"egress_allowlist": egress_allowlist, "seed": seed,
                                                       "produce_sbom": produce_sbom, "sign_attestation": sign_attestation}),
                    ]
                    # Try positional first
                    try:
                        return m(cmd, cwd, env or {}, egress_allowlist or [], seed)
                    except TypeError:
                        pass
                    for kwargs in kwargs_variants:
                        try:
                            return m(cmd, **kwargs)
                        except TypeError:
                            continue
                    # Last resort: only mandatory
                    return m(cmd, cwd=cwd)
                runner = bound_runner
                break

    if runner is None and instance is None:
        pytest.skip("No suitable watchdog runner interface found")

    if runner is None:
        # Bind a function runner
        def func_runner(cmd, cwd, env=None, egress_allowlist=None, seed=1337, produce_sbom=True, sign_attestation=True):
            fn = runner
            kwargs_variants = [
                dict(cwd=cwd, env=env, egress_allowlist=egress_allowlist, seed=seed,
                     produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                dict(working_dir=cwd, env=env, egress_allowlist=egress_allowlist, seed=seed,
                     produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                dict(workdir=cwd, env=env, egress_allowlist=egress_allowlist, seed=seed,
                     produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                dict(cwd=cwd, env=env, allowlist=egress_allowlist, seed=seed,
                     produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                dict(cwd=cwd, env=env, policy={"egress_allowlist": egress_allowlist}, seed=seed,
                     produce_sbom=produce_sbom, sign_attestation=sign_attestation),
                dict(cwd=cwd, env=env, config={"egress_allowlist": egress_allowlist, "seed": seed,
                                               "produce_sbom": produce_sbom, "sign_attestation": sign_attestation}),
            ]
            try:
                return fn(cmd, cwd, env or {}, egress_allowlist or [], seed)
            except TypeError:
                pass
            for kwargs in kwargs_variants:
                try:
                    return fn(cmd, **kwargs)
                except TypeError:
                    continue
            return fn(cmd, cwd=cwd)
        return None, func_runner

    return instance, runner


def _get_field(obj, key, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    val = getattr(obj, key, default)
    if val is not None:
        return val
    # Some results may nest data under 'result' or 'report'
    for k in ("result", "report", "data", "summary"):
        container = getattr(obj, k, None) if not isinstance(obj, dict) else obj.get(k)
        if isinstance(container, dict):
            if key in container:
                return container[key]
    return default


def _violation_list(result):
    viols = _get_field(result, "violations") or _get_field(result, "policy_violations") or []
    # Normalize to list
    if viols is None:
        return []
    return list(viols)


def _network_events(result):
    net = _get_field(result, "network_events") or _get_field(result, "net_events") or _get_field(result, "events")
    if isinstance(net, list):
        return net
    if isinstance(net, dict):
        return net.get("network") or []
    # Fallback
    return []


def _syscall_trace(result):
    trace = _get_field(result, "syscall_trace") or _get_field(result, "trace") or []
    return list(trace) if isinstance(trace, (list, tuple)) else []


def _sbom(result):
    sbom = _get_field(result, "sbom") or _get_field(result, "sboms") or _get_field(result, "bom")
    return sbom


def _attestation(result):
    att = _get_field(result, "attestation") or _get_field(result, "attestations") or _get_field(result, "attestation_bundle")
    return att


def _quarantined(result):
    q = _get_field(result, "quarantined")
    if q is None:
        # Some may indicate via success flag
        success = _get_field(result, "success")
        if success is not None:
            return not bool(success)
    return bool(q)


def _success(result):
    success = _get_field(result, "success")
    if success is not None:
        return bool(success)
    # If no high severity violations and not quarantined, consider success
    for v in _violation_list(result):
        sev = None
        if isinstance(v, dict):
            sev = v.get("severity") or v.get("level")
        else:
            sev = getattr(v, "severity", None) or getattr(v, "level", None)
        if sev and str(sev).lower() in ("high", "critical"):
            return False
    return not _quarantined(result)


@pytest.fixture(scope="module")
def watchdog_runner():
    instance, runner = _find_watchdog_interface()
    return instance, runner


def _write_script(path: pathlib.Path, content: str, python=False):
    path.write_text(content, encoding="utf-8")
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR)
    return str(path)


def _python_inline(code: str):
    return [sys.executable, "-c", code]


def _hash_normalized(obj) -> str:
    try:
        if isinstance(obj, (str, bytes)):
            data = obj if isinstance(obj, bytes) else obj.encode("utf-8", errors="ignore")
        else:
            data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return ""


def _contains_sigstore(attestation) -> bool:
    if attestation is None:
        return False
    s = attestation
    if isinstance(attestation, (dict, list)):
        s = json.dumps(attestation, sort_keys=True, default=str)
    if isinstance(s, bytes):
        s = s.decode("utf-8", errors="ignore")
    s = str(s)
    indicators = ("sigstore", "fulcio", "rekor", "bundle", "dsse", "x509")
    return any(token.lower() in s.lower() for token in indicators)


def _event_matches(event, **kwargs):
    if isinstance(event, dict):
        e = event
    else:
        # try to normalize from object
        e = {k: getattr(event, k, None) for k in dir(event) if not k.startswith("_")}
    for k, v in kwargs.items():
        ev = e.get(k)
        if ev is None:
            continue
        if isinstance(v, str):
            if v not in str(ev):
                return False
        else:
            if ev != v:
                return False
    return True


def _find_violation(violations, kind_contains=None, severity_at_least=None, message_contains=None):
    severities = ["low", "medium", "high", "critical"]
    for v in violations:
        if isinstance(v, dict):
            kind = (v.get("type") or v.get("category") or v.get("kind") or "")
            msg = v.get("message") or v.get("detail") or v.get("reason") or ""
            sev = (v.get("severity") or v.get("level") or "").lower()
        else:
            kind = getattr(v, "type", None) or getattr(v, "category", None) or getattr(v, "kind", "") or ""
            msg = getattr(v, "message", None) or getattr(v, "detail", None) or getattr(v, "reason", None) or ""
            sev = (getattr(v, "severity", "") or getattr(v, "level", "")).lower()
        if kind_contains and kind_contains.lower() not in str(kind).lower():
            continue
        if message_contains and message_contains.lower() not in str(msg).lower():
            continue
        if severity_at_least:
            try:
                if severities.index(sev) < severities.index(severity_at_least.lower()):
                    continue
            except ValueError:
                continue
        return v
    return None


def test_malicious_npm_postinstall_egress_blocked(tmp_path, monkeypatch, watchdog_runner):
    instance, runner = watchdog_runner

    # Create a fake postinstall script that attempts an egress (localhost only)
    # Use Python socket to simulate network syscall
    code = textwrap.dedent(
        """
        import socket, sys, time
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            s.connect(("127.0.0.1", 9))  # discard port, likely closed; still an egress attempt
            sys.stdout.write("CONNECTED\\n")
        except Exception as e:
            sys.stdout.write("CONNECT_FAIL:" + str(e) + "\\n")
        finally:
            try:
                s.close()
            except Exception:
                pass
        """
    )
    fake_npm_postinstall = tmp_path / "fake_npm_postinstall.py"
    fake_npm_postinstall.write_text(code, encoding="utf-8")

    # Create a launcher script to resemble "npm install" invoking postinstall hook
    launcher = tmp_path / "npm"
    launcher_content = f"#!{shlex.quote(sys.executable)}\nimport runpy; runpy.run_path({repr(str(fake_npm_postinstall))}, run_name='__main__')\n"
    _write_script(launcher, launcher_content)

    # Ensure fake npm is used
    monkeypatch.setenv("PATH", f"{str(tmp_path)}{os.pathsep}{os.environ.get('PATH','')}")

    # Run with default policy -> should block egress by default
    cmd = ["npm", "install"]
    env = {}

    result = runner(cmd, str(tmp_path), env=env, egress_allowlist=[], seed=4242, produce_sbom=False, sign_attestation=False)

    # Verify network egress was detected and blocked
    net_events = _network_events(result)
    assert isinstance(net_events, list)
    assert any(
        ("127.0.0.1" in json.dumps(e, default=str)) and (
            ("blocked" in json.dumps(e, default=str).lower()) or ("deny" in json.dumps(e, default=str).lower())
        ) for e in net_events
    ), f"Expected a blocked egress to 127.0.0.1; got events: {net_events}"

    # Verify syscall trace captured
    trace = _syscall_trace(result)
    assert isinstance(trace, list)
    assert len(trace) >= 1

    # Verify high-severity policy violation for network/egress
    violations = _violation_list(result)
    v = _find_violation(violations, kind_contains="network", severity_at_least="high")
    v = v or _find_violation(violations, kind_contains="egress", severity_at_least="high")
    assert v is not None, f"Expected high-severity egress violation, got: {violations}"

    # Build should be quarantined on violation
    assert _quarantined(result) is True


def test_python_setup_blocks_aws_creds_and_quarantines(tmp_path, monkeypatch, watchdog_runner):
    instance, runner = watchdog_runner

    # Prepare a fake HOME with ~/.aws/credentials
    fake_home = tmp_path / "home"
    aws_dir = fake_home / ".aws"
    aws_dir.mkdir(parents=True)
    creds_path = aws_dir / "credentials"
    creds_path.write_text("[default]\naws_access_key_id=AKIAFAKE\naws_secret_access_key=SECRETFAKE\n", encoding="utf-8")

    # Prepare environment with AWS credentials
    env = {
        "AWS_ACCESS_KEY_ID": "AKIAINENV",
        "AWS_SECRET_ACCESS_KEY": "ENVSECRET",
        "HOME": str(fake_home),
    }

    # Fake setup.py that tries to read env AWS creds and ~/.aws/credentials
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        textwrap.dedent(
            """
            import os, pathlib, sys
            # Try to exfiltrate env credentials (should be scrubbed/denied)
            a = os.getenv("AWS_ACCESS_KEY_ID")
            b = os.getenv("AWS_SECRET_ACCESS_KEY")
            sys.stdout.write("ENV_AWS_ACCESS_KEY_ID=" + str(bool(a)) + "\\n")
            sys.stdout.write("ENV_AWS_SECRET_SET=" + str(bool(b)) + "\\n")
            # Try to read ~/.aws/credentials (should be denied)
            p = pathlib.Path.home() / ".aws" / "credentials"
            try:
                d = p.read_bytes()
                sys.stdout.write("CREDS_READ_BYTES=" + str(len(d)) + "\\n")
            except Exception as e:
                sys.stdout.write("CREDS_READ_DENIED=" + str(e) + "\\n")
            """
        ),
        encoding="utf-8",
    )

    cmd = [sys.executable, str(setup_py)]

    result = runner(cmd, str(tmp_path), env=env, egress_allowlist=[], seed=1337, produce_sbom=False, sign_attestation=False)

    # Access to ~/.aws should be denied and logged
    violations = _violation_list(result)
    assert violations is not None
    v = _find_violation(violations, kind_contains="file", severity_at_least="medium", message_contains=".aws")
    v = v or _find_violation(violations, kind_contains="secret", severity_at_least="medium", message_contains=".aws")
    assert v is not None, f"Expected violation logging ~/.aws access, got: {violations}"

    # Should be quarantined due to secret access attempt
    assert _quarantined(result) is True

    # Ensure event logging contains the path
    events = _get_field(result, "events") or []
    serialized = json.dumps(events, default=str).lower()
    assert ".aws/credentials" in serialized or "aws" in serialized


def test_cargo_build_allowlisted_domain_succeeds_and_attests(tmp_path, monkeypatch, watchdog_runner):
    instance, runner = watchdog_runner

    # Simulate a 'cargo build' that attempts to contact an allowlisted domain (use localhost per rules)
    cargo = tmp_path / "cargo"
    code = textwrap.dedent(
        f"""#!{sys.executable}
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.2)
try:
    # Simulate registry access to allowlisted domain by using localhost
    s.connect(("127.0.0.1", 65534))
    sys.stdout.write("OK\\n")
except Exception as e:
    sys.stdout.write("CONNECT:" + str(e) + "\\n")
finally:
    try:
        s.close()
    except Exception:
        pass
sys.exit(0)
"""
    )
    _write_script(cargo, code)
    monkeypatch.setenv("PATH", f"{str(tmp_path)}{os.pathsep}{os.environ.get('PATH','')}")

    # Run cargo build with allowlisted domain
    cmd = ["cargo", "build"]
    allowlist = ["127.0.0.1", "localhost"]
    result = runner(cmd, str(tmp_path), env={}, egress_allowlist=allowlist, seed=2024, produce_sbom=True, sign_attestation=True)

    # Should be successful (no quarantine) since allowlist permits localhost egress
    assert _success(result) is True
    assert _quarantined(result) is False

    # SBOM should be produced
    sbom = _sbom(result)
    assert sbom is not None
    sbom_ser = json.dumps(sbom, default=str) if not isinstance(sbom, (str, bytes)) else (sbom.decode("utf-8", "ignore") if isinstance(sbom, bytes) else sbom)
    assert ("SPDX" in sbom_ser) or ("CycloneDX" in sbom_ser) or ("spdxVersion" in sbom_ser.lower()) or ("bomFormat" in sbom_ser)

    # Attestation should be sigstore-signed (check for indicative markers)
    att = _attestation(result)
    assert att is not None
    assert _contains_sigstore(att)


def test_deterministic_seed_reproducibility(tmp_path, watchdog_runner):
    instance, runner = watchdog_runner

    # Simple, deterministic command: echo
    script = tmp_path / "build.sh"
    _write_script(script, "#!/bin/sh\necho hello-deterministic\n")

    cmd = [str(script)]
    env = {}

    result1 = runner(cmd, str(tmp_path), env=env, egress_allowlist=[], seed=777, produce_sbom=True, sign_attestation=True)
    result2 = runner(cmd, str(tmp_path), env=env, egress_allowlist=[], seed=777, produce_sbom=True, sign_attestation=True)

    # SBOMs should be identical for the same seed
    sbom1 = _sbom(result1)
    sbom2 = _sbom(result2)
    assert _hash_normalized(sbom1) == _hash_normalized(sbom2)

    # Attestations should be identical or at least stable in digest if deterministic
    att1 = _attestation(result1)
    att2 = _attestation(result2)
    if att1 is not None and att2 is not None:
        assert _hash_normalized(att1) == _hash_normalized(att2)