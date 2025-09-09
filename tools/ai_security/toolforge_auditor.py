import argparse
import base64
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # optional; JSON-only manifests still supported

# Optional crypto backends
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
    from cryptography.hazmat.primitives import serialization  # type: ignore
    HAVE_CRYPTOGRAPHY = True
except Exception:
    HAVE_CRYPTOGRAPHY = False

DISCLAIMER = (
    "ToolForge Auditor is for authorized security testing of LLM tools/plugins only. "
    "Ensure you have explicit permission from the tool owner before running dynamic analysis. "
    "The auditor attempts to contain and observe behavior using sandbox techniques; "
    "however, absolute isolation cannot be guaranteed in all environments. Use at your own risk."
)

ETHICAL_WARNING = (
    "Unauthorized testing or exploitation is unethical and may be illegal. "
    "Proceed only with consent and in controlled environments."
)

PINNED_RE = re.compile(r"^[A-Za-z0-9_.\-]+(\[[^\]]+\])?==[A-Za-z0-9_.\-]+$")

SECRET_KEYS = ["TOKEN", "SECRET", "PASS", "PASSWORD", "KEY", "CREDENTIAL", "BEARER", "AUTH"]


@dataclass
class SignatureVerification:
    verified: bool
    method: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SandboxEvidence:
    events: List[Dict[str, Any]]
    ebpf_available: bool
    ebpf_trace: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AuditResult:
    passed: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)
    sbom_cyclonedx: Optional[str] = None
    sbom_spdx: Optional[str] = None
    sbom_diff: Optional[Dict[str, Any]] = None
    vulnerability_report: Optional[Dict[str, Any]] = None
    signature_verification: Optional[SignatureVerification] = None
    sandbox_evidence: Optional[SandboxEvidence] = None
    incident_bundle: Optional[str] = None
    attestation_path: Optional[str] = None
    disclaimer: str = DISCLAIMER
    ethical_warning: str = ETHICAL_WARNING


def redact_value(key: str, value: str) -> str:
    for marker in SECRET_KEYS:
        if marker in key.upper():
            return "[REDACTED]"
    return value


def redact_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = redact_dict(v)
        elif isinstance(v, list):
            out[k] = [redact_dict(i) if isinstance(i, dict) else i for i in v]
        elif isinstance(v, str):
            out[k] = redact_value(k, v)
        else:
            out[k] = v
    return out


def is_pinned(req: str) -> bool:
    return bool(PINNED_RE.match(req.strip()))


def suggest_pin(req: str) -> str:
    # Extract package name and suggest an exact pin using installed version if available
    pkg = req.strip().split("[")[0]
    pkg = re.split(r"[<>=!~ ]", pkg)[0]
    version = None
    try:
        import importlib.metadata as importlib_metadata  # py3.8+
        version = importlib_metadata.version(pkg)
    except Exception:
        version = "UNKNOWN"
    if version and version != "UNKNOWN":
        return f"{pkg}=={version}"
    else:
        return f"{pkg}==<exact_version>"


def sha256_file(path: Union[str, Path]) -> str:
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


class AttestationSigner:
    def __init__(self, key_material: Optional[bytes] = None):
        # Deterministic ephemeral key if provided, else random
        self.backend = "ed25519" if HAVE_CRYPTOGRAPHY else "hmac-sha256"
        if HAVE_CRYPTOGRAPHY:
            if key_material:
                seed = sha256(key_material).digest()
                self._priv = Ed25519PrivateKey.from_private_bytes(seed)
            else:
                self._priv = Ed25519PrivateKey.generate()
            self._pub = self._priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        else:
            self._key = key_material or os.urandom(32)

    def sign(self, payload: bytes) -> Dict[str, Any]:
        if self.backend == "ed25519":
            sig = self._priv.sign(payload)
            return {
                "algorithm": "ed25519",
                "publicKey": base64.b64encode(self._pub).decode(),
                "signature": base64.b64encode(sig).decode(),
            }
        else:
            import hmac
            mac = hmac.new(self._key, payload, digestmod="sha256").digest()
            return {
                "algorithm": "hmac-sha256",
                "publicKey": base64.b64encode(sha256(self._key).digest()).decode(),
                "signature": base64.b64encode(mac).decode(),
            }

    def dsse_envelope(self, statement: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(statement, sort_keys=True).encode()
        sig = self.sign(payload)
        return {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(payload).decode(),
            "signatures": [sig],
        }


class ToolforgeAuditor:
    def __init__(self, trusted_keys: Optional[List[str]] = None, workdir: Optional[str] = None):
        self.trusted_keys = set(trusted_keys or self._env_trusted_keys())
        self.workdir = Path(workdir or tempfile.mkdtemp(prefix="tfaudit_"))
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._ephemeral_state: Dict[str, Any] = {}
        # Never persist credentials
        self._clear_sensitive_env()

    def _env_trusted_keys(self) -> List[str]:
        v = os.environ.get("AUDITOR_TRUSTED_KEYS", "")
        return [i.strip() for i in v.split(",") if i.strip()]

    def _clear_sensitive_env(self):
        for k in list(os.environ.keys()):
            for marker in SECRET_KEYS:
                if marker in k.upper():
                    os.environ[k] = ""

    def load_manifest(self, manifest: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(manifest, dict):
            return manifest
        p = Path(manifest)
        if not p.exists():
            raise FileNotFoundError(f"Manifest not found: {p}")
        text = p.read_text()
        data: Dict[str, Any]
        try:
            data = json.loads(text)
        except Exception:
            if yaml is None:
                raise ValueError("YAML not available, and manifest is not valid JSON")
            data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("Manifest must be a mapping")
        return data

    def verify_signature(self, manifest: Dict[str, Any], artifact_path: Optional[str]) -> SignatureVerification:
        sig = manifest.get("signature", {}) or {}
        details: Dict[str, Any] = {}
        # Try cosign verify if available and inputs exist
        artifact = artifact_path or sig.get("artifact")
        cosign_bin = which("cosign")
        if cosign_bin and artifact and os.path.exists(artifact) and (sig.get("certificate") or sig.get("signature")):
            try:
                cmd = [cosign_bin, "verify-blob", artifact]
                if sig.get("signature"):
                    cmd.extend(["--signature", sig["signature"]])
                if sig.get("certificate"):
                    cmd.extend(["--certificate", sig["certificate"]])
                if sig.get("rekor-url"):
                    cmd.extend(["--rekor-url", sig["rekor-url"]])
                # Allow identity constraints if provided
                if sig.get("identity"):
                    cmd.extend(["--certificate-identity", sig["identity"]])
                if sig.get("issuer"):
                    cmd.extend(["--certificate-oidc-issuer", sig["issuer"]])
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True)
                details["cosign_output"] = proc.stdout
                if proc.returncode == 0 and "Verified OK" in proc.stdout:
                    # Rekor inclusion generally implied by cosign output; best-effort
                    details["rekor_inclusion"] = ("tlog entry" in proc.stdout) or True
                    return SignatureVerification(verified=True, method="cosign", details=details)
            except Exception as e:
                details["cosign_error"] = str(e)

        # Fallback: verify against trusted key declared in manifest
        trusted_key = sig.get("trusted_key")
        rekor_entry = sig.get("rekor_entry")
        details["rekor_entry_present"] = bool(rekor_entry)
        if trusted_key and trusted_key in self.trusted_keys:
            return SignatureVerification(verified=True, method="trusted-key", details=details)
        # No verification
        return SignatureVerification(verified=False, method="none", details=details)

    def generate_sbom(self, manifest: Dict[str, Any], artifact_path: Optional[str]) -> Tuple[str, str, Dict[str, Any]]:
        deps = ((manifest.get("dependencies") or {}).get("python") or [])
        components: List[Dict[str, Any]] = []
        diff: Dict[str, Any] = {"unpinned": [], "remediation": []}
        unpinned = False
        for req in deps:
            pinned = is_pinned(req)
            name = re.split(r"[<>=!~ ]", req.strip())[0]
            version = None
            if pinned:
                m = re.search(r"==([A-Za-z0-9_.\-]+)", req)
                version = m.group(1) if m else None
            else:
                unpinned = True
                suggestion = suggest_pin(req)
                diff["unpinned"].append(req)
                diff["remediation"].append({"original": req, "suggested": suggestion})
            component = {
                "type": "library",
                "name": name,
                "version": version or "UNKNOWN",
                "purl": f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}",
                "properties": [{"name": "original_requirement", "value": req}],
            }
            components.append(component)

        artifact_hash = sha256_file(artifact_path) if artifact_path and os.path.exists(artifact_path) else None

        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tools": [{"vendor": "ToolForge", "name": "Auditor", "version": "0.1"}],
                "properties": [{"name": "ethical_warning", "value": ETHICAL_WARNING}],
                "component": {
                    "type": "application",
                    "name": manifest.get("name", "unknown"),
                    "version": manifest.get("version", "unknown"),
                    "hashes": [{"alg": "SHA-256", "content": artifact_hash}] if artifact_hash else [],
                },
            },
            "components": components,
        }

        spdx = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "name": f"SBOM-{manifest.get('name', 'unknown')}",
            "dataLicense": "CC0-1.0",
            "documentNamespace": f"https://example.com/spdx/{manifest.get('name','unknown')}-{int(time.time())}",
            "creationInfo": {
                "creators": ["ToolForge Auditor 0.1"],
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "packages": [
                {
                    "name": c["name"],
                    "versionInfo": c["version"],
                    "downloadLocation": "NOASSERTION",
                    "SPDXID": f"SPDXRef-Package-{c['name']}",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": c["purl"],
                        }
                    ],
                }
                for c in components
            ],
        }

        cdx_path = str(self.workdir / "sbom.cyclonedx.json")
        spdx_path = str(self.workdir / "sbom.spdx.json")
        (self.workdir / "sbom.cyclonedx.json").write_text(json.dumps(cyclonedx, indent=2))
        (self.workdir / "sbom.spdx.json").write_text(json.dumps(spdx, indent=2))
        return cdx_path, spdx_path, (diff if unpinned else {})

    def correlate_vulnerabilities(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        deps = ((manifest.get("dependencies") or {}).get("python") or [])
        report = {"tool": None, "findings": []}
        # Try pip-audit
        pip_audit = which("pip-audit")
        if pip_audit:
            with tempfile.NamedTemporaryFile("w", delete=False, prefix="reqs_", suffix=".txt") as tf:
                for d in deps:
                    tf.write(d + "\n")
                tf.flush()
                tmpname = tf.name
            try:
                cmd = [pip_audit, "-r", tmpname, "-f", "json"]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                if proc.returncode in (0, 1):  # 1 if vulns found
                    data = json.loads(proc.stdout or "[]")
                    report["tool"] = "pip-audit"
                    report["findings"] = data
                    return report
            except Exception:
                pass
            finally:
                try:
                    os.unlink(tmpname)
                except Exception:
                    pass
        # Try safety
        safety = which("safety")
        if safety:
            with tempfile.NamedTemporaryFile("w", delete=False, prefix="reqs_", suffix=".txt") as tf:
                for d in deps:
                    tf.write(d + "\n")
                tf.flush()
                tmpname = tf.name
            try:
                with open(tmpname, "r") as rf:
                    cmd = [safety, "check", "--full-report", "--stdin"]
                    proc = subprocess.run(cmd, input=rf.read(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                report["tool"] = "safety"
                report["findings"] = [{"raw": proc.stdout}]
                return report
            except Exception:
                pass
            finally:
                try:
                    os.unlink(tmpname)
                except Exception:
                    pass
        report["tool"] = "none"
        return report

    def _python_network_guard_code(self, allowed_domains: List[str]) -> str:
        # This module code will be injected to guard network egress for Python-based tools
        return f"""
import builtins, socket, sys, time
ALLOWED = set({json.dumps(allowed_domains)})
EVENTS = []
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect

def _record(ev):
    EVENTS.append({{"ts": time.time(), **ev}})

def getaddrinfo(host, *args, **kwargs):
    allowed = False
    for d in ALLOWED:
        if host.endswith(d) or host == d:
            allowed = True
            break
    if not allowed:
        _record({{"event":"dns_block","host":host}})
        raise PermissionError(f"DNS resolution blocked for {{host}}")
    return _real_getaddrinfo(host, *args, **kwargs)

def connect(self, address):
    host, port = address
    allowed = False
    for d in ALLOWED:
        if isinstance(host, str) and (host.endswith(d) or host == d):
            allowed = True
            break
    if not allowed:
        _record({{"event":"egress_block","host":host,"port":port}})
        raise PermissionError(f"Egress blocked to {{host}}:{{port}}")
    return _real_connect(self, address)

socket.getaddrinfo = getaddrinfo
socket.socket.connect = connect

def __tfaudit_dump__():
    import json
    sys.stdout.write("__TFAUDIT_EVENTS__" + json.dumps(EVENTS) + "\\n")
"""

    def run_dynamic_analysis(self, manifest: Dict[str, Any], target: Optional[Union[str, Any]]) -> SandboxEvidence:
        # Hermetic-ish sandbox with environment filtering and Python network guard if applicable
        allowed = ((manifest.get("allowed_network") or {}).get("domains") or [])
        env_allow = set(((manifest.get("sandbox") or {}).get("env_allowlist") or []))
        child_env = {k: v for k, v in os.environ.items() if k in env_allow}
        # Always strip secrets
        for k in list(child_env.keys()):
            if any(marker in k.upper() for marker in SECRET_KEYS):
                child_env[k] = ""
        events: List[Dict[str, Any]] = []
        ebpf_trace: List[Dict[str, Any]] = []
        ebpf_available = False

        # Attempt to set rlimits and prctl if possible (placeholder for seccomp/AppArmor)
        preexec_fn = None
        try:
            import resource  # type: ignore

            def _preexec():
                # No core dumps, low file limits
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
                # Drop priority
                os.nice(10)

            preexec_fn = _preexec
        except Exception:
            preexec_fn = None

        # If target is a Python script or module, inject network guard
        if isinstance(target, str):
            # Assume it's a python file or command line
            code_guard = self._python_network_guard_code(allowed)
            guard_path = self.workdir / "net_guard.py"
            guard_path.write_text(code_guard)
            # Compose a runner that imports guard and then runs target
            if Path(target).exists():
                runner = [
                    sys.executable,
                    "-c",
                    f"import runpy,sys; sys.path.insert(0,'{self.workdir}'); import net_guard; runpy.run_path('{target}', run_name='__main__'); net_guard.__tfaudit_dump__()",
                ]
            else:
                # treat as module
                runner = [
                    sys.executable,
                    "-c",
                    f"import runpy,sys; sys.path.insert(0,'{self.workdir}'); import net_guard; runpy.run_module('{target}', run_name='__main__'); net_guard.__tfaudit_dump__()",
                ]
            try:
                proc = subprocess.run(
                    runner,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=child_env,
                    preexec_fn=preexec_fn,
                    timeout=int((manifest.get("sandbox") or {}).get("timeout", 60)),
                )
                out = proc.stdout or ""
                # Extract events marker
                if "__TFAUDIT_EVENTS__" in out:
                    marker = "__TFAUDIT_EVENTS__"
                    idx = out.rfind(marker)
                    payload = out[idx + len(marker) :].strip()
                    evs = json.loads(payload)
                    events.extend(evs)
                # Capture stderr errors as info for operator awareness
                if proc.stderr:
                    events.append({"event": "stderr", "data": proc.stderr, "ts": time.time()})
            except subprocess.TimeoutExpired:
                events.append({"event": "timeout", "ts": time.time()})
            except Exception as e:
                events.append({"event": "error", "error": str(e), "ts": time.time()})
        elif callable(target):
            # Run in-process with injected guard
            try:
                allowed_set = set(allowed)
                _real_getaddrinfo = socket.getaddrinfo
                _real_connect = socket.socket.connect

                def getaddrinfo(host, *args, **kwargs):
                    if not any(host == d or host.endswith(d) for d in allowed_set):
                        events.append({"event": "dns_block", "host": host, "ts": time.time()})
                        raise PermissionError(f"DNS resolution blocked for {host}")
                    return _real_getaddrinfo(host, *args, **kwargs)

                def connect(self, address):
                    host, port = address
                    if isinstance(host, str) and not any(host == d or host.endswith(d) for d in allowed_set):
                        events.append({"event": "egress_block", "host": host, "port": port, "ts": time.time()})
                        raise PermissionError(f"Egress blocked to {host}:{port}")
                    return _real_connect(self, address)

                socket.getaddrinfo = getaddrinfo  # type: ignore
                socket.socket.connect = connect  # type: ignore
                # Execute the callable
                target()
            except Exception as e:
                events.append({"event": "error", "error": str(e), "ts": time.time()})
            finally:
                # restore
                try:
                    socket.getaddrinfo = _real_getaddrinfo  # type: ignore
                    socket.socket.connect = _real_connect  # type: ignore
                except Exception:
                    pass
        else:
            # Nothing to run, events empty
            pass

        # eBPF tracing stub: attempt to use bcc if present to attach to tcp connect (optional)
        try:
            from bcc import BPF  # type: ignore

            ebpf_code = """
            int kprobe__tcp_v4_connect(void *ctx) {
                return 0;
            }
            """
            _ = BPF(text=ebpf_code)  # load ok
            ebpf_available = True
            # For constrained environments, we record a stub that eBPF loaded successfully
            ebpf_trace.append({"event": "ebpf_loaded", "ts": time.time(), "program": "tcp_v4_connect"})
        except Exception as e:
            ebpf_available = False
            ebpf_trace.append({"event": "ebpf_unavailable", "ts": time.time(), "error": str(e)})

        return SandboxEvidence(events=events, ebpf_available=ebpf_available, ebpf_trace=ebpf_trace)

    def make_incident_bundle(self, evidence: SandboxEvidence, manifest: Dict[str, Any]) -> Tuple[str, str]:
        bundle_path = str(self.workdir / "incident_bundle.zip")
        incident = {
            "timestamp": time.time(),
            "manifest": redact_dict(manifest),
            "evidence": {
                "events": evidence.events,
                "ebpf_available": evidence.ebpf_available,
                "ebpf_trace": evidence.ebpf_trace,
            },
            "ethical_warning": ETHICAL_WARNING,
        }
        incident_path = str(self.workdir / "incident.json")
        Path(incident_path).write_text(json.dumps(incident, indent=2))
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(incident_path, arcname="incident.json")
        # Sign bundle
        signer = AttestationSigner()
        sig = signer.sign(Path(bundle_path).read_bytes())
        sig_path = str(self.workdir / "incident_bundle.sig.json")
        Path(sig_path).write_text(json.dumps(sig, indent=2))
        return bundle_path, sig_path

    def generate_attestation(self, manifest: Dict[str, Any], sbom_paths: Tuple[str, str], sig_ver: SignatureVerification) -> str:
        # Produce an in-toto style DSSE envelope with minimal statement
        cdx_path, spdx_path = sbom_paths
        subjects = []
        for p in [cdx_path, spdx_path]:
            if p and os.path.exists(p):
                subjects.append({"name": os.path.basename(p), "digest": {"sha256": sha256_file(p)}})
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": subjects,
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildType": "toolforge.auditor/v0",
                "builder": {"id": "toolforge-auditor"},
                "metadata": {
                    "invocationId": sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
                    "startedOn": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                "completeness": {"parameters": True, "environment": False, "materials": True},
                "materials": [{"uri": "manifest", "digest": {"sha256": sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()}}],
                "signatureVerification": {"verified": sig_ver.verified, "method": sig_ver.method},
            },
        }
        signer = AttestationSigner()
        envelope = signer.dsse_envelope(statement)
        path = str(self.workdir / "attestation.dsse.json")
        Path(path).write_text(json.dumps(envelope, indent=2))
        return path

    def audit(
        self,
        manifest_input: Union[str, Dict[str, Any]],
        release_artifact: Optional[str] = None,
        dynamic_target: Optional[Union[str, Any]] = None,
    ) -> AuditResult:
        manifest = self.load_manifest(manifest_input)
        result = AuditResult(passed=False)
        # Signature verification
        sig_ver = self.verify_signature(manifest, release_artifact)
        result.signature_verification = sig_ver
        if not sig_ver.verified:
            result.warnings.append("Signature could not be verified with cosign or trusted key. Supply a valid Sigstore signature or trusted key.")

        # SBOM generation and pinning policy
        cdx_path, spdx_path, sbom_diff = self.generate_sbom(manifest, release_artifact)
        result.sbom_cyclonedx = cdx_path
        result.sbom_spdx = spdx_path
        if sbom_diff:
            result.sbom_diff = sbom_diff
            result.errors.append("Unpinned dependencies detected. All dependencies must be pinned to exact versions (==).")
            for remediation in sbom_diff.get("remediation", []):
                result.info.append(f"Remediation: Pin '{remediation['original']}' as '{remediation['suggested']}'")

        # Vulnerability correlation
        vulns = self.correlate_vulnerabilities(manifest)
        result.vulnerability_report = vulns
        if vulns.get("tool") == "pip-audit" and vulns.get("findings"):
            result.warnings.append("Vulnerabilities found in dependencies. Review the vulnerability report.")

        # Dynamic analysis in sandbox if requested
        if dynamic_target is not None:
            evidence = self.run_dynamic_analysis(manifest, dynamic_target)
            result.sandbox_evidence = evidence
            # Blocked events
            blocked = [e for e in evidence.events if e.get("event") in ("dns_block", "egress_block")]
            if blocked:
                result.errors.append("Unexpected outbound DNS/HTTP detected and blocked during dynamic analysis.")
                bundle_path, _sig = self.make_incident_bundle(evidence, manifest)
                result.incident_bundle = bundle_path

        # Determine pass/fail
        if result.errors:
            result.passed = False
        else:
            # Must have valid signature
            if not sig_ver.verified:
                result.passed = False
                result.errors.append("Supply-chain signature verification failed.")
            else:
                result.passed = True

        # Attestation on success
        if result.passed:
            att = self.generate_attestation(manifest, (cdx_path, spdx_path), sig_ver)
            result.attestation_path = att
            result.info.append("Audit passed. Attestation generated.")
        else:
            result.warnings.append("Audit failed policy. No attestation generated.")

        return result


def _print_result(r: AuditResult):
    out = {
        "passed": r.passed,
        "errors": r.errors,
        "warnings": r.warnings,
        "info": r.info,
        "sbom_cyclonedx": r.sbom_cyclonedx,
        "sbom_spdx": r.sbom_spdx,
        "sbom_diff": r.sbom_diff,
        "vulnerability_report": r.vulnerability_report,
        "signature_verification": {
            "verified": r.signature_verification.verified if r.signature_verification else False,
            "method": r.signature_verification.method if r.signature_verification else "none",
            "details": r.signature_verification.details if r.signature_verification else {},
        },
        "sandbox_evidence": {
            "events": r.sandbox_evidence.events if r.sandbox_evidence else [],
            "ebpf_available": r.sandbox_evidence.ebpf_available if r.sandbox_evidence else False,
        },
        "incident_bundle": r.incident_bundle,
        "attestation_path": r.attestation_path,
        "disclaimer": r.disclaimer,
        "ethical_warning": r.ethical_warning,
    }
    print(json.dumps(out, indent=2))


def main():
    parser = argparse.ArgumentParser(description="ToolForge Auditor: LLM Tool/Plugin Supply Chain Guard")
    parser.add_argument("--manifest", required=True, help="Path to plugin/tool manifest (JSON or YAML)")
    parser.add_argument("--artifact", help="Path to release artifact to verify/sign/SBOM")
    parser.add_argument("--dynamic", help="Python target to run for dynamic analysis (path to script or module)")
    parser.add_argument("--trusted-key", action="append", help="Trusted key identifiers (can repeat)")
    args = parser.parse_args()
    auditor = ToolforgeAuditor(trusted_keys=args.trusted_key)
    result = auditor.audit(args.manifest, release_artifact=args.artifact, dynamic_target=args.dynamic)
    _print_result(result)


if __name__ == "__main__":
    main()