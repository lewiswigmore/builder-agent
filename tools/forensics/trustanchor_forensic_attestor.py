#!/usr/bin/env python3
import argparse
import base64
import datetime
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ethical warning: Authorized forensic acquisition only. Get explicit consent. Improper use may violate laws or policies.

TOOL_NAME = "TrustAnchor Forensic Attestor: TPM/TEE Evidence Collector"
TOOL_VERSION = "1.0.0"


class AttestorError(Exception):
    pass


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run_cmd(args: List[str], input_bytes: Optional[bytes] = None, env: Optional[Dict[str, str]] = None) -> Tuple[int, bytes, bytes]:
    proc = subprocess.Popen(args, stdin=subprocess.PIPE if input_bytes else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    out, err = proc.communicate(input_bytes)
    return proc.returncode, out, err


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def now_utc_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def safe_write(path: Path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def read_text(path: Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def write_text(path: Path, text: str):
    Path(path).write_text(text, encoding="utf-8")


def detect_linux() -> bool:
    return platform.system().lower() == "linux"


def parse_nonce(nonce_str: str) -> bytes:
    s = nonce_str.strip()
    if s.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            if s.startswith("0x"):
                s = s[2:]
            return bytes.fromhex(s)
        except Exception:
            pass
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        pass
    return s.encode("utf-8")


class CapabilityDetector:
    def __init__(self):
        self.tools = {
            "tpm2_pcrread": which("tpm2_pcrread"),
            "tpm2_quote": which("tpm2_quote"),
            "tpm2_createak": which("tpm2_createak"),
            "tpm2_getekcertificate": which("tpm2_getekcertificate"),
            "tpm2_eventlog": which("tpm2_eventlog"),
            "tpm2_checkquote": which("tpm2_checkquote"),
            "openssl": which("openssl"),
            "curl": which("curl"),
            "sevctl": which("sevctl"),
            "tdx-report": which("tdx-report"),
        }
        self.paths = {
            "tpm_eventlog": self._detect_tpm_eventlog_path(),
            "ima_log": self._detect_ima_log_path(),
            "tdx_sys": "/sys/firmware/tdx",
            "sev_snp_sys": "/sys/module/sev/parameters",
        }

    def _detect_tpm_eventlog_path(self) -> Optional[str]:
        for p in [
            "/sys/kernel/security/tpm0/binary_bios_measurements",
            "/sys/kernel/security/tpm0/binary_bios_measurements2",
            "/sys/kernel/security/tpm1/binary_bios_measurements",
        ]:
            if os.path.exists(p):
                return p
        return None

    def _detect_ima_log_path(self) -> Optional[str]:
        for p in [
            "/sys/kernel/security/ima/ascii_runtime_measurements",
            "/sys/kernel/security/ima/binary_runtime_measurements",
        ]:
            if os.path.exists(p):
                return p
        return None

    def has_tpm(self) -> bool:
        return all(self.tools.get(t) for t in ["tpm2_pcrread", "tpm2_quote", "tpm2_createak", "tpm2_eventlog", "tpm2_checkquote"]) and bool(self.paths.get("tpm_eventlog"))

    def has_tpm_ek_cert_support(self) -> bool:
        return bool(self.tools.get("tpm2_getekcertificate"))

    def has_tee_tdx(self) -> bool:
        return bool(self.tools.get("tdx-report")) or os.path.exists(self.paths["tdx_sys"])

    def has_tee_sev_snp(self) -> bool:
        return bool(self.tools.get("sevctl")) or os.path.exists(self.paths["sev_snp_sys"])

    def has_crypto(self) -> bool:
        return bool(self.tools.get("openssl"))

    def has_network(self) -> bool:
        return bool(self.tools.get("curl"))

    def summary(self) -> Dict[str, bool]:
        return {
            "linux": detect_linux(),
            "tpm": self.has_tpm(),
            "tpm_ek": self.has_tpm_ek_cert_support(),
            "tee_tdx": self.has_tee_tdx(),
            "tee_sev_snp": self.has_tee_sev_snp(),
            "crypto": self.has_crypto(),
            "network": self.has_network(),
        }


class TPMCollector:
    def __init__(self, caps: CapabilityDetector, workdir: Path, pcrs: List[int], nonce: bytes, pinned_ek_ca: Optional[Path]):
        self.caps = caps
        self.workdir = workdir
        self.pcrs = pcrs
        self.nonce = nonce
        self.pinned_ek_ca = pinned_ek_ca
        self.result = {
            "ak_pub": None,
            "ak_name": None,
            "quote_attest": None,
            "quote_sig": None,
            "ek_cert": None,
            "pcr_json": None,
            "pcr_yaml": None,
            "eventlog_json": None,
            "reconstructed_pcr_json": None,
            "checkquote_report": None,
            "verification": {"pcr_reconstruction_ok": False, "quote_signature_ok": False, "ek_chain_ok": False, "errors": []},
        }

    def collect(self):
        if not self.caps.has_tpm():
            raise AttestorError("TPM capability/tools not available; cannot collect TPM evidence.")
        pcr_sel = "sha256:" + ",".join(str(i) for i in self.pcrs)
        rc, out, err = run_cmd([self.caps.tools["tpm2_pcrread"], pcr_sel, "--format=json"])
        if rc != 0:
            raise AttestorError(f"tpm2_pcrread failed: {err.decode(errors='ignore')}")
        pcr_json_path = self.workdir / "tpm_pcrs.json"
        safe_write(pcr_json_path, out)
        self.result["pcr_json"] = str(pcr_json_path)
        rc, out_yaml, err_yaml = run_cmd([self.caps.tools["tpm2_pcrread"], pcr_sel])
        if rc != 0:
            raise AttestorError(f"tpm2_pcrread (yaml) failed: {err_yaml.decode(errors='ignore')}")
        pcr_yaml_path = self.workdir / "tpm_pcrs.yaml"
        safe_write(pcr_yaml_path, out_yaml)
        self.result["pcr_yaml"] = str(pcr_yaml_path)
        ak_ctx, ak_pub, ak_name = self.workdir / "ak.ctx", self.workdir / "ak.pub", self.workdir / "ak.name"
        rc, _, err = run_cmd([self.caps.tools["tpm2_createak"], "-C", "o", "-G", "rsa", "-g", "sha256", "-s", "rsassa", "-c", str(ak_ctx), "-u", str(ak_pub), "-n", str(ak_name)])
        if rc != 0:
            raise AttestorError(f"tpm2_createak failed: {err.decode(errors='ignore')}")
        self.result["ak_pub"] = str(ak_pub)
        self.result["ak_name"] = str(ak_name)
        ek_cert_path = None
        if self.caps.has_tpm_ek_cert_support():
            ek_cert_path = self.workdir / "ek.crt"
            rc, _, err = run_cmd([self.caps.tools["tpm2_getekcertificate"], "-o", str(ek_cert_path), "-X"])
            if rc != 0:
                self.result["verification"]["errors"].append(f"tpm2_getekcertificate failed: {err.decode(errors='ignore')}")
                ek_cert_path = None
            else:
                self.result["ek_cert"] = str(ek_cert_path)
                if self.pinned_ek_ca:
                    rc, outv, errv = run_cmd([self.caps.tools["openssl"], "verify", "-CAfile", str(self.pinned_ek_ca), str(ek_cert_path)])
                    if rc == 0 and b": OK" in outv:
                        self.result["verification"]["ek_chain_ok"] = True
                    else:
                        self.result["verification"]["errors"].append(f"EK certificate chain validation failed: {outv.decode(errors='ignore')} {errv.decode(errors='ignore')}")
                else:
                    self.result["verification"]["errors"].append("Pinned EK CA file not provided; cannot validate EK cert chain.")
        else:
            self.result["verification"]["errors"].append("tpm2_getekcertificate not available; cannot validate EK cert chain.")
        quote_attest, quote_sig = self.workdir / "quote.attest", self.workdir / "quote.sig"
        rc, _, err = run_cmd([self.caps.tools["tpm2_quote"], "-c", str(ak_ctx), "-l", pcr_sel, "-q", self.nonce.hex(), "-g", "sha256", "-o", str(quote_attest), "-s", str(quote_sig)])
        if rc != 0:
            raise AttestorError(f"tpm2_quote failed: {err.decode(errors='ignore')}")
        self.result["quote_attest"] = str(quote_attest)
        self.result["quote_sig"] = str(quote_sig)
        eventlog_json_path = self.workdir / "measured_boot_eventlog.json"
        rc, out, err = run_cmd([self.caps.tools["tpm2_eventlog"], "-j", self.caps.paths["tpm_eventlog"]])
        if rc != 0:
            raise AttestorError(f"tpm2_eventlog failed: {err.decode(errors='ignore')}")
        safe_write(eventlog_json_path, out)
        self.result["eventlog_json"] = str(eventlog_json_path)
        reconstructed = self._reconstruct_pcrs_from_eventlog(eventlog_json_path, alg="sha256", pcrs=self.pcrs)
        recon_path = self.workdir / "reconstructed_pcrs.json"
        write_text(recon_path, json.dumps(reconstructed, indent=2, sort_keys=True))
        self.result["reconstructed_pcr_json"] = str(recon_path)
        pcr_data = json.loads((self.workdir / "tpm_pcrs.json").read_text(encoding="utf-8"))
        live_values = {}
        try:
            bank = pcr_data["pcrs"]["sha256"]
            for entry in bank:
                idx = int(entry["index"])
                if idx in self.pcrs:
                    live_values[idx] = entry["value"].lower()
        except Exception as e:
            raise AttestorError(f"Unable to parse tpm2_pcrread output: {e}")
        mismatch = []
        for idx in self.pcrs:
            recon = reconstructed.get(str(idx))
            live = live_values.get(idx)
            if not recon or not live or recon.lower() != live.lower():
                mismatch.append(idx)
        if mismatch:
            self.result["verification"]["pcr_reconstruction_ok"] = False
            self.result["verification"]["errors"].append(f"PCR reconstruction mismatch for indices: {mismatch}")
            raise AttestorError(f"PCR reconstruction failed for indices: {mismatch}")
        else:
            self.result["verification"]["pcr_reconstruction_ok"] = True
        checkquote_report = self.workdir / "tpm2_checkquote.txt"
        rc, out, err = run_cmd([self.caps.tools["tpm2_checkquote"], "-u", str(ak_pub), "-m", str(quote_attest), "-s", str(quote_sig), "-g", "sha256", "-f", str(pcr_yaml_path)])
        safe_write(checkquote_report, out + err)
        self.result["checkquote_report"] = str(checkquote_report)
        if rc == 0:
            self.result["verification"]["quote_signature_ok"] = True
        else:
            self.result["verification"]["errors"].append(f"tpm2_checkquote failed: {out.decode(errors='ignore')} {err.decode(errors='ignore')}")
            raise AttestorError("TPM quote verification failed (tpm2_checkquote).")

    def _reconstruct_pcrs_from_eventlog(self, eventlog_json_path: Path, alg: str, pcrs: List[int]) -> Dict[str, str]:
        data = json.loads(read_text(eventlog_json_path))
        hash_len = 32 if alg.lower() == "sha256" else 20
        pcr_state: Dict[int, bytes] = {i: b"\x00" * hash_len for i in pcrs}
        events = data.get("events", []) or data.get("specEvents", [])
        if not events:
            raise AttestorError("Event log JSON does not contain events; cannot reconstruct PCRs.")
        for ev in events:
            try:
                pcr_index = ev.get("pcrIndex", ev.get("pcr"))
                if pcr_index not in pcr_state:
                    continue
                for d in ev.get("digests", []):
                    halg = (d.get("hashAlg") or d.get("hash") or "").lower()
                    if halg != alg.lower():
                        continue
                    digest_hex = d.get("digest") or d.get("digestHex")
                    if not digest_hex:
                        continue
                    prev = pcr_state[pcr_index]
                    pcr_state[pcr_index] = hashlib.new(alg, prev + bytes.fromhex(digest_hex)).digest()
            except Exception:
                continue
        return {str(k): pcr_state[k].hex() for k in pcrs}


class TEECollector:
    def __init__(self, caps: CapabilityDetector, workdir: Path, nonce: bytes, attest_url: Optional[str], attest_api_key: Optional[str]):
        self.caps = caps
        self.workdir = workdir
        self.nonce = nonce
        self.attest_url = attest_url
        self.attest_api_key = attest_api_key
        self.result = {"tdx_report": None, "snp_report": None, "attestation_response": None, "verification": {"attestation_ok": False, "errors": []}}

    def collect(self, require_tee: bool):
        have_any = self.caps.has_tee_tdx() or self.caps.has_tee_sev_snp()
        if not have_any:
            if require_tee:
                raise AttestorError("TEE capability not detected but required.")
            return
        if self.caps.tools.get("tdx-report"):
            report_path = self.workdir / "tdx_report.bin"
            rc, _, err = run_cmd([self.caps.tools["tdx-report"], "--nonce", self.nonce.hex(), "--out", str(report_path)])
            if rc != 0:
                self.result["verification"]["errors"].append(f"tdx-report collection failed: {err.decode(errors='ignore')}")
            else:
                self.result["tdx_report"] = str(report_path)
        if self.caps.tools.get("sevctl"):
            snp_path = self.workdir / "snp_report.bin"
            rc, _, err = run_cmd([self.caps.tools["sevctl"], "snp-report", "--message", "--data", self.nonce.hex(), "--out", str(snp_path)])
            if rc != 0:
                self.result["verification"]["errors"].append(f"sevctl snp-report failed: {err.decode(errors='ignore')}")
            else:
                self.result["snp_report"] = str(snp_path)
        if self.attest_url:
            if not self.caps.has_network():
                raise AttestorError("Network tools not available (curl) but TEE attestation URL provided; cannot verify.")
            payload = {"nonce": base64.b64encode(self.nonce).decode(), "tdx_report_b64": None, "snp_report_b64": None}
            if self.result["tdx_report"]:
                payload["tdx_report_b64"] = base64.b64encode(Path(self.result["tdx_report"]).read_bytes()).decode()
            if self.result["snp_report"]:
                payload["snp_report_b64"] = base64.b64encode(Path(self.result["snp_report"]).read_bytes()).decode()
            if not payload["tdx_report_b64"] and not payload["snp_report_b64"]:
                if require_tee:
                    raise AttestorError("TEE report collection failed but required.")
                return
            req_json = json.dumps(payload).encode("utf-8")
            headers = ["-H", "Content-Type: application/json"]
            if self.attest_api_key:
                headers += ["-H", f"Authorization: Bearer {self.attest_api_key}"]
            rc, out, err = run_cmd(["curl", "-sS", "-X", "POST", *headers, "--data-binary", "@-", self.attest_url], input_bytes=req_json)
            if rc != 0:
                raise AttestorError(f"TEE attestation service request failed: {err.decode(errors='ignore')}")
            att_resp_path = self.workdir / "tee_attestation_response.json"
            safe_write(att_resp_path, out)
            self.result["attestation_response"] = str(att_resp_path)
            try:
                resp = json.loads(out.decode("utf-8"))
                verified = bool(resp.get("verified", False))
                chain_valid = bool(resp.get("chain_valid", False))
                policy_ok = bool(resp.get("policy_ok", False))
                all_ok = verified and chain_valid and policy_ok
                self.result["verification"]["attestation_ok"] = all_ok
                if not all_ok:
                    raise AttestorError(f"TEE attestation verification failed: verified={verified} chain_valid={chain_valid} policy_ok={policy_ok}")
            except Exception as e:
                raise AttestorError(f"Invalid attestation response parse: {e}")
        else:
            if require_tee:
                raise AttestorError("TEE evidence required but no attestation service URL provided.")


class Sealer:
    def __init__(self, caps: CapabilityDetector, workdir: Path, out_dir: Path, tsa_url: str, tsa_ca: Optional[Path], sign_key: Optional[Path], sign_cert: Optional[Path], sign_chain: Optional[Path]):
        self.caps = caps
        self.workdir = workdir
        self.out_dir = out_dir
        self.tsa_url = tsa_url
        self.tsa_ca = tsa_ca
        self.sign_key = sign_key
        self.sign_cert = sign_cert
        self.sign_chain = sign_chain

    def seal(self, artifacts: Dict[str, str], meta: Dict) -> Dict:
        if not self.caps.has_crypto():
            raise AttestorError("OpenSSL not available; cannot seal bundle.")
        if not self.tsa_url:
            raise AttestorError("TSA URL not provided; cannot obtain RFC3161 timestamp.")
        if not (self.sign_key and self.sign_cert):
            raise AttestorError("Signing key and certificate required to sign chain-of-custody manifest.")
        bundle_dir = self.out_dir / f"trustanchor_bundle_{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"
        ensure_dir(bundle_dir)
        manifest = {
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "created": now_utc_iso(),
            "host": {"hostname": platform.node(), "platform": platform.platform()},
            "artifacts": [],
            "meta": meta,
            "hash_chain": {"algorithm": "sha256", "links": []},
            "chain_of_custody": [{"ts": now_utc_iso(), "actor": "trustanchor_forensic_attestor", "action": "bundle_created"}],
        }
        chain_prev = b""
        for key, path in artifacts.items():
            if not path:
                continue
            src = Path(path)
            if not src.exists():
                continue
            dst = bundle_dir / src.name
            shutil.copy2(src, dst)
            h = sha256_file(dst)
            manifest["artifacts"].append({"name": key, "file": dst.name, "sha256": h})
            chain_prev = hashlib.sha256(chain_prev + bytes.fromhex(h)).digest()
            manifest["hash_chain"]["links"].append({"name": key, "sha256": h, "chain_hex": chain_prev.hex()})
        final_chain_hex = chain_prev.hex()
        write_text(bundle_dir / "chain_final.hex", final_chain_hex)
        tsq = self.workdir / "tsa.tsq"
        tsr = bundle_dir / "tsa.tsr"
        rc, _, err = run_cmd([self.caps.tools["openssl"], "ts", "-query", "-digest", final_chain_hex, "-sha256", "-no_nonce", "-cert", "-out", str(tsq)])
        if rc != 0:
            raise AttestorError(f"OpenSSL ts -query failed: {err.decode(errors='ignore')}")
        rc, _, err = run_cmd(["curl", "-sS", "-H", "Content-Type: application/timestamp-query", "--data-binary", "@" + str(tsq), "-o", str(tsr), self.tsa_url])
        if rc != 0:
            raise AttestorError(f"Failed to obtain timestamp token from TSA: {err.decode(errors='ignore')}")
        verify_cmd = [self.caps.tools["openssl"], "ts", "-verify", "-in", str(tsr), "-queryfile", str(tsq)]
        if self.tsa_ca:
            verify_cmd += ["-CAfile", str(self.tsa_ca)]
        rc, out, err = run_cmd(verify_cmd)
        if rc != 0:
            raise AttestorError(f"RFC3161 timestamp verification failed: {out.decode(errors='ignore')} {err.decode(errors='ignore')}")
        write_text(bundle_dir / "tsa_verify.txt", (out + err).decode(errors="ignore"))
        manifest_path = bundle_dir / "manifest.json"
        write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True))
        manifest_sig = bundle_dir / "manifest.p7s"
        sign_cmd = [self.caps.tools["openssl"], "smime", "-sign", "-binary", "-in", str(manifest_path), "-signer", str(self.sign_cert), "-inkey", str(self.sign_key), "-outform", "DER", "-out", str(manifest_sig)]
        if self.sign_chain:
            sign_cmd += ["-certfile", str(self.sign_chain)]
        rc, _, err = run_cmd(sign_cmd)
        if rc != 0:
            raise AttestorError(f"Manifest signing failed: {err.decode(errors='ignore')}")
        if self.sign_cert:
            shutil.copy2(self.sign_cert, bundle_dir / "signer_cert.pem")
        if self.sign_chain and Path(self.sign_chain).exists():
            shutil.copy2(self.sign_chain, bundle_dir / "signer_chain.pem")
        return {"bundle_dir": str(bundle_dir), "final_chain_hex": final_chain_hex, "manifest": str(manifest_path), "manifest_sig": str(manifest_sig), "timestamp_token": str(tsr)}

    @staticmethod
    def verify_bundle(bundle_dir: Path, tsa_ca: Optional[Path] = None) -> Dict:
        manifest_path = bundle_dir / "manifest.json"
        manifest = json.loads(read_text(manifest_path))
        results = {"hashes_ok": True, "chain_ok": True, "signature_ok": False, "timestamp_ok": False, "errors": []}
        for art in manifest.get("artifacts", []):
            f = bundle_dir / art["file"]
            if not f.exists():
                results["hashes_ok"] = False
                results["errors"].append(f"Missing file: {f}")
                continue
            h = sha256_file(f)
            if h.lower() != art["sha256"].lower():
                results["hashes_ok"] = False
                results["errors"].append(f"Hash mismatch: {f.name}")
        chain_prev = b""
        for link in manifest.get("hash_chain", {}).get("links", []):
            h = link["sha256"]
            chain_prev = hashlib.sha256(chain_prev + bytes.fromhex(h)).digest()
            if chain_prev.hex().lower() != link["chain_hex"].lower():
                results["chain_ok"] = False
                results["errors"].append("Hash chain link mismatch")
                break
        openssl_path = which("openssl")
        if not openssl_path:
            results["errors"].append("OpenSSL not available for verification")
        else:
            sig_path = bundle_dir / "manifest.p7s"
            cert_path = bundle_dir / "signer_cert.pem"
            verify_cmd = [openssl_path, "smime", "-verify", "-binary", "-in", str(sig_path), "-inform", "DER", "-content", str(manifest_path)]
            if (bundle_dir / "signer_chain.pem").exists():
                verify_cmd += ["-CAfile", str(bundle_dir / "signer_chain.pem")]
            elif cert_path.exists():
                verify_cmd += ["-certfile", str(cert_path)]
            rc, out, err = run_cmd(verify_cmd)
            if rc == 0:
                results["signature_ok"] = True
            else:
                results["errors"].append(f"Manifest signature verification failed: {out.decode(errors='ignore')} {err.decode(errors='ignore')}")
            chain_final_hex_path = bundle_dir / "chain_final.hex"
            tsr = bundle_dir / "tsa.tsr"
            if not tsr.exists():
                results["errors"].append("Missing timestamp token")
            elif not chain_final_hex_path.exists():
                results["errors"].append("Missing chain_final.hex for timestamp verification")
            else:
                tsq = tempfile.NamedTemporaryFile(delete=False)
                tsq_path = tsq.name
                tsq.close()
                rc, _, err = run_cmd([openssl_path, "ts", "-query", "-digest", read_text(chain_final_hex_path).strip(), "-sha256", "-no_nonce", "-cert", "-out", tsq_path])
                if rc != 0:
                    results["errors"].append(f"Failed to build TSQ: {err.decode(errors='ignore')}")
                else:
                    verify_cmd = [openssl_path, "ts", "-verify", "-in", str(tsr), "-queryfile", str(tsq_path)]
                    if tsa_ca and Path(tsa_ca).exists():
                        verify_cmd += ["-CAfile", str(tsa_ca)]
                    rc, out, err = run_cmd(verify_cmd)
                    os.unlink(tsq_path)
                    if rc == 0:
                        results["timestamp_ok"] = True
                    else:
                        results["errors"].append(f"Timestamp verification failed: {out.decode(errors='ignore')} {err.decode(errors='ignore')}")
        return results


class TrustAnchorForensicAttestor:
    def __init__(self, tsa_url: Optional[str] = None, sign_key: Optional[Path] = None, sign_cert: Optional[Path] = None, sign_chain: Optional[Path] = None, pinned_ek_ca: Optional[Path] = None, tsa_ca: Optional[Path] = None):
        self.caps = CapabilityDetector()
        self.tsa_url = tsa_url
        self.sign_key = sign_key
        self.sign_cert = sign_cert
        self.sign_chain = sign_chain
        self.pinned_ek_ca = pinned_ek_ca
        self.tsa_ca = tsa_ca

    @staticmethod
    def generate_nonce(length: int = 24) -> bytes:
        if length < 16:
            raise AttestorError("Nonce length too short")
        return os.urandom(length)

    def detect_capabilities(self) -> Dict[str, bool]:
        return self.caps.summary()

    def acquire_tpm_evidence(self, nonce: bytes, pcrs: Optional[List[int]] = None, workdir: Optional[Path] = None) -> Tuple[Dict, Dict[str, str]]:
        if not detect_linux():
            raise AttestorError("Linux required for TPM evidence collection")
        if not self.caps.has_tpm():
            raise AttestorError("TPM capability/tools not available")
        if pcrs is None:
            pcrs = list(range(0, 8))
        wd = workdir or Path(tempfile.mkdtemp(prefix="trustanchor_api_tpm_"))
        collector = TPMCollector(self.caps, wd, pcrs, nonce, self.pinned_ek_ca)
        collector.collect()
        artifacts = {}
        for k in ["ak_pub", "ak_name", "quote_attest", "quote_sig", "ek_cert", "pcr_json", "pcr_yaml", "eventlog_json", "reconstructed_pcr_json", "checkquote_report"]:
            v = collector.result.get(k)
            if v:
                artifacts[k] = v
        return collector.result, artifacts

    def acquire_tee_evidence(self, nonce: bytes, attest_url: Optional[str] = None, api_key: Optional[str] = None, require_tee: bool = False, workdir: Optional[Path] = None) -> Tuple[Dict, Dict[str, str]]:
        if not detect_linux():
            raise AttestorError("Linux required for TEE evidence collection")
        wd = workdir or Path(tempfile.mkdtemp(prefix="trustanchor_api_tee_"))
        tee = TEECollector(self.caps, wd, nonce, attest_url, api_key)
        tee.collect(require_tee=require_tee)
        artifacts = {}
        for k in ["tdx_report", "snp_report", "attestation_response"]:
            v = tee.result.get(k)
            if v:
                artifacts[k] = v
        return tee.result, artifacts

    def seal_bundle(self, artifacts: Dict[str, str], meta: Dict, out_dir: Path, workdir: Optional[Path] = None) -> Dict:
        wd = workdir or Path(tempfile.mkdtemp(prefix="trustanchor_api_seal_"))
        sealer = Sealer(caps=self.caps, workdir=wd, out_dir=out_dir, tsa_url=self.tsa_url or "", tsa_ca=self.tsa_ca, sign_key=self.sign_key, sign_cert=self.sign_cert, sign_chain=self.sign_chain)
        return sealer.seal(artifacts, meta)

    @staticmethod
    def verify_bundle(bundle_dir: Path, tsa_ca: Optional[Path] = None) -> Dict:
        return Sealer.verify_bundle(bundle_dir, tsa_ca)

    def run_full(self, out_dir: Path, nonce: bytes, pcrs: Optional[List[int]] = None, tee_required: bool = False, tee_attest_url: Optional[str] = None, tee_attest_api_key: Optional[str] = None) -> Dict:
        ensure_dir(out_dir)
        caps_summary = self.caps.summary()
        workdir = Path(tempfile.mkdtemp(prefix="trustanchor_api_run_"))
        try:
            tpm_result, tpm_artifacts = self.acquire_tpm_evidence(nonce=nonce, pcrs=pcrs or list(range(0, 8)), workdir=workdir)
            tee_result, tee_artifacts = self.acquire_tee_evidence(nonce=nonce, attest_url=tee_attest_url, api_key=tee_attest_api_key, require_tee=tee_required, workdir=workdir)
            ver_errs = []
            if not tpm_result["verification"]["pcr_reconstruction_ok"]:
                ver_errs.append("TPM PCR reconstruction failed")
            if not tpm_result["verification"]["quote_signature_ok"]:
                ver_errs.append("TPM quote signature verification failed")
            if not tpm_result["verification"]["ek_chain_ok"]:
                ver_errs.append("EK chain validation failed (provide pinned EK CA)")
            if tee_required and not tee_result["verification"]["attestation_ok"]:
                ver_errs.append("TEE attestation verification failed")
            if ver_errs:
                raise AttestorError(" | ".join(ver_errs))
            artifacts = {}
            artifacts.update(tpm_artifacts)
            artifacts.update(tee_artifacts)
            meta = {
                "capabilities": caps_summary,
                "tpm_verification": tpm_result["verification"],
                "tee_verification": tee_result["verification"],
                "nonce_b64": base64.b64encode(nonce).decode(),
                "pcrs": pcrs or list(range(0, 8)),
                "timestamps": {"start": now_utc_iso()},
            }
            seal_info = self.seal_bundle(artifacts=artifacts, meta=meta, out_dir=out_dir, workdir=workdir)
            meta["timestamps"]["end"] = now_utc_iso()
            return {"status": "ok", "bundle_dir": seal_info["bundle_dir"], "final_chain_hex": seal_info["final_chain_hex"], "tpm": {"verification": tpm_result["verification"]}, "tee": {"verification": tee_result["verification"]}}
        finally:
            try:
                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass


def parse_args():
    ap = argparse.ArgumentParser(description=f"{TOOL_NAME} v{TOOL_VERSION} - Authorized forensic acquisition only.")
    ap.add_argument("--out-dir", required=True, help="Output directory for the evidence bundle.")
    ap.add_argument("--nonce", required=True, help="Verifier-provided nonce (hex/base64/ascii).")
    ap.add_argument("--pcrs", default="0,1,2,3,4,5,6,7", help="Comma-separated PCR indices to quote and verify (default: 0-7).")
    ap.add_argument("--pinned-ek-ca", help="Path to pinned EK root/intermediate CA bundle (PEM) for EK chain validation.")
    ap.add_argument("--tsa-url", required=True, help="RFC3161 TSA URL.")
    ap.add_argument("--tsa-ca", help="Path to TSA CA certificate bundle (PEM) to verify timestamp token.")
    ap.add_argument("--sign-key", required=True, help="Path to private key (PEM) to sign chain-of-custody manifest.")
    ap.add_argument("--sign-cert", required=True, help="Path to signer certificate (PEM).")
    ap.add_argument("--sign-chain", help="Optional CA chain bundle (PEM) for manifest signature.")
    ap.add_argument("--tee-required", action="store_true", help="Require TEE report collection and verification.")
    ap.add_argument("--tee-attest-url", help="TEE attestation verifier service URL (vendor/cloud-agnostic).")
    ap.add_argument("--tee-attest-api-key", help="API key/token for TEE attestation verifier.")
    ap.add_argument("--verify-only", action="store_true", help="Verify an existing bundle in --out-dir instead of collecting.")
    return ap.parse_args()


def main():
    print("Authorized use only: Ensure you have explicit consent to collect forensic attestation evidence.", file=sys.stderr)
    args = parse_args()
    out_dir = Path(args.out_dir).resolve()
    ensure_dir(out_dir)
    if args.verify_only:
        results = Sealer.verify_bundle(out_dir, Path(args.tsa_ca) if args.tsa_ca else None)
        print(json.dumps(results, indent=2))
        sys.exit(0 if results.get("hashes_ok") and results.get("chain_ok") and results.get("signature_ok") and results.get("timestamp_ok") else 2)
    if not detect_linux():
        print("This tool currently supports Linux only.", file=sys.stderr)
        sys.exit(3)
    caps = CapabilityDetector()
    caps.summary()
    workdir = Path(tempfile.mkdtemp(prefix="trustanchor_work_"))
    try:
        nonce = parse_nonce(args.nonce)
        if len(nonce) < 16:
            raise AttestorError("Nonce too short; provide a verifier-provided random nonce (at least 16 bytes).")
        pcrs = [int(x) for x in args.pcrs.split(",") if x.strip() != ""]
        if not pcrs:
            raise AttestorError("No PCR indices provided.")
        tpm = TPMCollector(caps=caps, workdir=workdir, pcrs=pcrs, nonce=nonce, pinned_ek_ca=Path(args.pinned_ek_ca) if args.pinned_ek_ca else None)
        tpm.collect()
        tee = TEECollector(caps=caps, workdir=workdir, nonce=nonce, attest_url=args.tee_attest_url, attest_api_key=args.tee_attest_api_key)
        tee.collect(require_tee=args.tee_required)
        artifacts = {}
        for k in ["ak_pub", "ak_name", "quote_attest", "quote_sig", "ek_cert", "pcr_json", "pcr_yaml", "eventlog_json", "reconstructed_pcr_json", "checkquote_report"]:
            v = tpm.result.get(k)
            if v:
                artifacts[k] = v
        for k in ["tdx_report", "snp_report", "attestation_response"]:
            v = tee.result.get(k)
            if v:
                artifacts[k] = v
        ver_errs = []
        if not tpm.result["verification"]["pcr_reconstruction_ok"]:
            ver_errs.append("TPM PCR reconstruction failed")
        if not tpm.result["verification"]["quote_signature_ok"]:
            ver_errs.append("TPM quote signature verification failed")
        if not tpm.result["verification"]["ek_chain_ok"]:
            ver_errs.append("EK chain validation failed (provide pinned EK CA)")
        if args.tee_required and not tee.result["verification"]["attestation_ok"]:
            ver_errs.append("TEE attestation verification failed")
        if ver_errs:
            raise AttestorError(" | ".join(ver_errs))
        meta = {
            "capabilities": caps.summary(),
            "tpm_verification": tpm.result["verification"],
            "tee_verification": tee.result["verification"],
            "nonce_b64": base64.b64encode(nonce).decode(),
            "pcrs": pcrs,
            "timestamps": {"start": now_utc_iso()},
        }
        sealer = Sealer(caps=caps, workdir=workdir, out_dir=out_dir, tsa_url=args.tsa_url, tsa_ca=Path(args.tsa_ca) if args.tsa_ca else None, sign_key=Path(args.sign_key), sign_cert=Path(args.sign_cert), sign_chain=Path(args.sign_chain) if args.sign_chain else None)
        seal_info = sealer.seal(artifacts=artifacts, meta=meta)
        meta["timestamps"]["end"] = now_utc_iso()
        print(json.dumps({"status": "ok", "bundle_dir": seal_info["bundle_dir"], "final_chain_hex": seal_info["final_chain_hex"], "tpm": {"verification": tpm.result["verification"]}, "tee": {"verification": tee.result["verification"]}}, indent=2))
    except AttestorError as e:
        print(json.dumps({"status": "error", "error": str(e), "hint": "Ensure you run with sufficient privileges, required tools (tpm2-tools, openssl, curl) are installed, nonce is provided by verifier, and pinned CA and TSA are configured."}, indent=2), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"status": "error", "error": f"Unexpected error: {e}"}, indent=2), file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()