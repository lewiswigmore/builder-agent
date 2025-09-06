#!/usr/bin/env python3
import argparse
import base64
import binascii
import json
import os
import re
import socket
import struct
import sys
import time
import hashlib
import hmac
import secrets as pysecrets
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple

# Optional imports
try:
    import numpy as np  # for tensor heuristics if available
except Exception:
    np = None

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    Ed25519PrivateKey = None
    AESGCM = None

TOOL_NAME = "GPU VRAM Forensic Extractor & ML Artifact Hunter"
TOOL_ID = "gpu-vram-artifact-hunter"
TOOL_VERSION = "0.2.0"

# --------------------------- Utility ---------------------------------

def now_iso8601() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_stream_update(h, data: bytes):
    h.update(data)

def sha256_stream_finalize(h) -> str:
    return h.hexdigest()

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def redact(s: str) -> str:
    if len(s) <= 8:
        return "***REDACTED***"
    return s[:4] + "…" + s[-4:]

def human_reason(e: Exception) -> str:
    return f"{type(e).__name__}: {str(e)}"

def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

# --------------------------- Ethics ----------------------------------

ETHICS_WARNING = (
    "WARNING: This tool performs forensic acquisition and analysis of GPU memory (VRAM). "
    "Unauthorized access to memory may violate laws, contracts, or ethical guidelines. "
    "Use only on systems you own or are explicitly authorized to examine. "
    "All operations are designed to be read-only; however, ensure proper legal authority before proceeding."
)

# --------------------------- Crypto/Attestation ----------------------

class CryptoManager:
    def __init__(self, signing_key_b64: Optional[str], enc_key_b64: Optional[str], allow_generate: bool = False):
        self.ephemeral = False
        if Ed25519PrivateKey is None or AESGCM is None:
            raise RuntimeError("cryptography library is required. Please install 'cryptography' or use --insecure-allow-fallback-crypto.")
        if not signing_key_b64:
            if allow_generate:
                self.ephemeral = True
                self.sk = Ed25519PrivateKey.generate()
            else:
                raise RuntimeError("Missing Ed25519 signing key (env GPU_FORENSICS_SIGNING_KEY).")
        else:
            try:
                sk_bytes = b64d(signing_key_b64)
                if len(sk_bytes) == 32:
                    self.sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
                elif len(sk_bytes) == 64:
                    self.sk = Ed25519PrivateKey.from_private_bytes(sk_bytes[:32])
                else:
                    raise ValueError("Signing key must be 32 or 64 bytes in base64.")
            except Exception as e:
                raise RuntimeError(f"Invalid signing key: {human_reason(e)}")
        try:
            if not enc_key_b64:
                if allow_generate:
                    self.enc_key = os.urandom(32)
                    self.ephemeral = True or self.ephemeral
                else:
                    raise RuntimeError("Missing AES-GCM encryption key (env GPU_FORENSICS_ENC_KEY).")
            else:
                self.enc_key = b64d(enc_key_b64)
            if len(self.enc_key) not in (16, 24, 32):
                raise ValueError("Encryption key must be 128/192/256-bit in base64.")
        except Exception as e:
            raise RuntimeError(f"Invalid encryption key: {human_reason(e)}")
        self.aesgcm = AESGCM(self.enc_key)

    def public_key_b64(self) -> str:
        pk = self.sk.public_key()
        pk_bytes = pk.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        return b64e(pk_bytes)

    def sign(self, data: bytes) -> bytes:
        return self.sk.sign(data)

    def encrypt_chunk(self, nonce: bytes, plaintext: bytes) -> bytes:
        return self.aesgcm.encrypt(nonce, plaintext, None)

class InsecureCryptoFallback:
    def __init__(self):
        # DO NOT USE IN PRODUCTION. For testing only.
        self._sig_key = os.urandom(32)
        self.enc_key = os.urandom(32)
        self.ephemeral = True

    def public_key_b64(self) -> str:
        return b64e(self._sig_key)

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._sig_key, data, hashlib.sha256).digest()

    def encrypt_chunk(self, nonce: bytes, plaintext: bytes) -> bytes:
        # Insecure XOR keystream from SHA256(nonce||counter)
        out = bytearray(len(plaintext))
        counter = 0
        pos = 0
        while pos < len(plaintext):
            block_key = hashlib.sha256(self.enc_key + nonce + struct.pack(">I", counter)).digest()
            l = min(len(block_key), len(plaintext) - pos)
            for i in range(l):
                out[pos + i] = plaintext[pos + i] ^ block_key[i]
            pos += l
            counter += 1
        return bytes(out)

# --------------------------- Acquisition Backends --------------------

class AcquisitionResult:
    def __init__(self, supported: bool, reason: str = "", source_path: Optional[str] = None):
        self.supported = supported
        self.reason = reason
        self.source_path = source_path

class Acquirer:
    def __init__(self, args):
        self.args = args
        self.backend = args.backend
        self.input_file = args.input_file

    def detect_gpu_presence(self) -> Tuple[bool, str]:
        # Best-effort GPU detection without heavy deps
        try:
            # NVIDIA presence
            if os.path.exists("/proc/driver/nvidia/gpus") or os.path.exists("/dev/nvidiactl"):
                return True, "nvidia"
            # AMD presence
            if os.path.exists("/sys/class/drm") and any("card" in x for x in os.listdir("/sys/class/drm")):
                return True, "drm"
            # iGPU presence through DRM probable
            if os.path.exists("/dev/dri"):
                return True, "dri"
        except Exception:
            pass
        return False, "none"

    def get_device_path(self) -> Optional[str]:
        # Hypothetical read-only VRAM dump device provided by signed kernel module
        paths = ["/dev/gpuvram_dump", "/dev/gpu_vram_dump", "/dev/gpu/forensics_vram"]
        for p in paths:
            if os.path.exists(p) and os.access(p, os.R_OK):
                return p
        return None

    def acquire(self) -> AcquisitionResult:
        if self.backend == "file":
            if not self.input_file or not os.path.exists(self.input_file):
                return AcquisitionResult(False, "input-file-not-found")
            return AcquisitionResult(True, source_path=self.input_file)
        if self.backend == "device":
            dev = self.get_device_path()
            if dev:
                return AcquisitionResult(True, source_path=dev)
            return AcquisitionResult(False, "no-device-dump-interface")
        # auto
        dev = self.get_device_path()
        if dev:
            return AcquisitionResult(True, source_path=dev)
        if self.input_file and os.path.exists(self.input_file):
            return AcquisitionResult(True, source_path=self.input_file)
        present, kind = self.detect_gpu_presence()
        if not present:
            return AcquisitionResult(False, "no-supported-gpu-detected")
        return AcquisitionResult(False, "no-supported-acquisition-backend")

# --------------------------- Analyzer --------------------------------

class Analyzer:
    def __init__(self, enable_numpy: bool, tensor_block_kb: int = 64, max_tensor_hits: int = 128):
        self.enable_numpy = enable_numpy and (np is not None)
        self.tensor_block = tensor_block_kb * 1024
        self.max_tensor_hits = max_tensor_hits
        self.tensor_hits: List[Dict] = []
        self.secret_hits: List[Dict] = []
        self.offset = 0
        self._overlap_buf = b""
        # Precompile regex for secrets
        self.secret_patterns = [
            ("aws_access_key_id", re.compile(rb"AKIA[0-9A-Z]{16}")),
            ("aws_secret_access_key", re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9/\+]{40}(?![A-Za-z0-9+/])")),
            ("gcp_api_key", re.compile(rb"AIza[0-9A-Za-z\-_]{35}")),
            ("azure_sas", re.compile(rb"sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}-\d{2}-\d{2}")),
            ("openai_key", re.compile(rb"sk-[A-Za-z0-9]{32,64}")),
            ("github_pat", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
            ("slack_token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,48}")),
            ("bearer_token", re.compile(rb"Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)")),
            ("generic_api_key", re.compile(rb"(?i)(api[_-]?key|secret|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})")),
        ]

    def _score_tensor_block(self, block: bytes) -> float:
        if len(block) < 4096:
            return 0.0
        n = len(block) // 4
        if self.enable_numpy:
            try:
                arr = np.frombuffer(block[:n*4], dtype=np.float32)
                finite = np.isfinite(arr)
                finite_frac = float(finite.mean())
                if finite_frac < 0.9:
                    return 0.0
                vals = arr[finite]
                mu = float(np.mean(vals))
                sigma = float(np.std(vals))
                # Scores: closer to 0 mean, small-ish std typical for weights
                mu_score = max(0.0, 1.0 - min(1.0, abs(mu) / 0.05))
                # sigma ~ [1e-3, 0.2] preferred
                if sigma <= 0:
                    s_score = 0.0
                elif sigma < 1e-4:
                    s_score = 0.1
                elif sigma <= 0.2:
                    # Map 1e-4..0.2 -> 0.2..1
                    s_score = min(1.0, max(0.2, (sigma - 1e-4) / (0.2 - 1e-4)))
                elif sigma <= 1.0:
                    s_score = max(0.1, 1.0 - (sigma - 0.2) / 0.8)
                else:
                    s_score = 0.0
                # Sparsity hint: fraction of small magnitudes
                small = float((np.abs(vals) < 0.01).mean())
                sparsity_score = min(1.0, small + 0.2)
                conf = 0.4 * finite_frac + 0.3 * mu_score + 0.2 * s_score + 0.1 * sparsity_score
                return conf
            except Exception:
                return 0.0
        else:
            # Fallback: compute crude stats
            try:
                count = min(4096, n)
                vals = struct.unpack("<" + "f"*count, block[:count*4])
                finite_vals = [v for v in vals if abs(v) != float("inf") and v == v]
                finite_frac = len(finite_vals) / float(count)
                if finite_frac < 0.9:
                    return 0.0
                mu = sum(finite_vals)/len(finite_vals)
                var = sum((v-mu)*(v-mu) for v in finite_vals)/len(finite_vals)
                sigma = var ** 0.5
                mu_score = max(0.0, 1.0 - min(1.0, abs(mu) / 0.05))
                s_score = 1.0 if 1e-4 <= sigma <= 0.2 else 0.2 if sigma <= 1.0 else 0.0
                conf = 0.4 * finite_frac + 0.3 * mu_score + 0.3 * s_score
                return conf
            except Exception:
                return 0.0

    def process_chunk(self, data: bytes, base_offset: int):
        # Secrets scanning with overlap
        chunk = self._overlap_buf + data
        for label, pat in self.secret_patterns:
            for m in pat.finditer(chunk):
                start = m.start()
                end = m.end()
                # Avoid reporting overlaps twice using base_offset
                absolute = base_offset - len(self._overlap_buf) + start
                val = m.group(0)
                try:
                    text_val = val.decode("utf-8", errors="ignore")
                except Exception:
                    text_val = binascii.hexlify(val[:16]).decode("ascii") + ("…" if len(val) > 16 else "")
                red = redact(text_val)
                self.secret_hits.append({
                    "type": label,
                    "offset": int(absolute),
                    "length": int(len(val)),
                    "redacted_value": red
                })
        # Keep last bytes for boundary (max pattern length ~ 128)
        self._overlap_buf = data[-128:] if len(data) >= 128 else data

        # Tensor block heuristic scanning at aligned positions within this chunk
        block = self.tensor_block
        step = block
        i = 0
        limit = len(data) - block
        while i <= limit:
            conf = self._score_tensor_block(data[i:i+block])
            if conf >= 0.7:
                self.tensor_hits.append({
                    "offset": int(base_offset + i),
                    "size": block,
                    "confidence": round(conf, 3)
                })
                if len(self.tensor_hits) >= self.max_tensor_hits:
                    # Cap to avoid huge reports
                    return
            i += step

    def finalize(self):
        # Optionally de-duplicate secret hits by offset/type
        seen = set()
        uniq = []
        for h in self.secret_hits:
            key = (h["type"], h["offset"], h["length"])
            if key not in seen:
                seen.add(key)
                uniq.append(h)
        self.secret_hits = uniq
        # Sort tensor hits by confidence desc
        self.tensor_hits.sort(key=lambda x: x["confidence"], reverse=True)

# --------------------------- DSSE / in-toto --------------------------

def dsse_envelope(payload_json: bytes, signer) -> Dict:
    payload_b64 = b64e(payload_json)
    # keyid: SHA-256 of pubkey
    pub_b64 = signer.public_key_b64()
    pub_bytes = b64d(pub_b64)
    keyid = hashlib.sha256(pub_bytes).hexdigest()[:16]
    # DSSE signature signs payload bytes (simplified)
    sig = signer.sign(payload_json)
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload_b64,
        "signatures": [{
            "keyid": keyid,
            "sig": b64e(sig),
            "publicKey": pub_b64
        }]
    }

# --------------------------- Main Tool Logic -------------------------

def run(args):
    print(ETHICS_WARNING, file=sys.stderr)
    if not args.i_acknowledge_authorized_use:
        print("Refusing to proceed without --i-acknowledge-authorized-use flag.", file=sys.stderr)
        sys.exit(2)

    os.makedirs(args.output_dir, exist_ok=True)

    # Load crypto manager
    signer = None
    crypto_fallback = False
    try:
        signer = CryptoManager(
            signing_key_b64=os.environ.get("GPU_FORENSICS_SIGNING_KEY"),
            enc_key_b64=os.environ.get("GPU_FORENSICS_ENC_KEY"),
            allow_generate=args.insecure_allow_fallback_crypto or os.environ.get("GPU_FORENSICS_ALLOW_FALLBACK") == "1",
        )
    except Exception as e:
        if args.insecure_allow_fallback_crypto or os.environ.get("GPU_FORENSICS_ALLOW_FALLBACK") == "1":
            print(f"WARNING: Using insecure crypto fallback: {human_reason(e)}", file=sys.stderr)
            signer = InsecureCryptoFallback()
            crypto_fallback = True
        else:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(3)

    acq = Acquirer(args).acquire()
    host = socket.gethostname()
    start_time = now_iso8601()

    if not acq.supported:
        # Nil attestation
        report = {
            "tool": {"id": TOOL_ID, "name": TOOL_NAME, "version": TOOL_VERSION},
            "host": host,
            "timestamp": start_time,
            "status": "nil-attestation",
            "reason": acq.reason,
            "artifacts": [],
            "acquisition": {"backend": args.backend, "read_only": True}
        }
        if crypto_fallback or (hasattr(signer, "ephemeral") and signer.ephemeral):
            report["note"] = "Ephemeral or fallback cryptography used for testing; not production-grade."
        predicate = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "gpu-vram-snapshot", "digest": {}}],
            "predicateType": "https://forensics.example/gpu-vram/1.0",
            "predicate": report
        }
        payload = json.dumps(predicate, sort_keys=True).encode("utf-8")
        envelope = dsse_envelope(payload, signer)
        out_report = os.path.join(args.output_dir, "nil_attestation.json")
        with open(out_report, "w", encoding="utf-8") as f3:
            json.dump(envelope, f3, indent=2, sort_keys=True)
        print(f"Nil-attestation written to {out_report}")
        return

    # Proceed with acquisition from source_path (read-only open)
    src_path = acq.source_path
    try:
        f = open(src_path, "rb", buffering=0)
    except Exception as e:
        reason = f"acquisition-open-failed: {human_reason(e)}"
        report = {
            "tool": {"id": TOOL_ID, "name": TOOL_NAME, "version": TOOL_VERSION},
            "host": host,
            "timestamp": start_time,
            "status": "nil-attestation",
            "reason": reason,
            "artifacts": [],
            "acquisition": {"backend": args.backend, "read_only": True, "source": src_path}
        }
        if crypto_fallback or (hasattr(signer, "ephemeral") and signer.ephemeral):
            report["note"] = "Ephemeral or fallback cryptography used for testing; not production-grade."
        predicate = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "gpu-vram-snapshot", "digest": {}}],
            "predicateType": "https://forensics.example/gpu-vram/1.0",
            "predicate": report
        }
        payload = json.dumps(predicate, sort_keys=True).encode("utf-8")
        envelope = dsse_envelope(payload, signer)
        out_report = os.path.join(args.output_dir, "nil_attestation.json")
        with open(out_report, "w", encoding="utf-8") as f2:
            json.dump(envelope, f2, indent=2, sort_keys=True)
        print(f"Nil-attestation written to {out_report}")
        return

    # Prepare encrypted output container
    enc_out_path = os.path.join(args.output_dir, "vram_snapshot.enc")
    try:
        enc_f = open(enc_out_path, "wb")
    except Exception as e:
        print(f"ERROR: cannot open output file for encrypted snapshot: {human_reason(e)}", file=sys.stderr)
        f.close()
        sys.exit(4)

    # Write container header for chunked encryption
    version = 1
    nonce_prefix = os.urandom(8)
    chunk_size = max(4096, min(4 * 1024 * 1024, args.chunk_size))
    header = b"GVFH" + bytes([version]) + nonce_prefix + struct.pack(">I", chunk_size)
    enc_f.write(header)

    # Initialize analyzer and hashes
    analyzer = Analyzer(enable_numpy=(not args.disable_numpy), tensor_block_kb=args.tensor_block_kb, max_tensor_hits=args.max_tensor_hits)
    h_raw = hashlib.sha256()
    total_size = 0
    chunk_index = 0

    try:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            # Update raw hash
            sha256_stream_update(h_raw, data)
            # Analyze
            analyzer.process_chunk(data, total_size)
            # Encrypt and write chunk
            nonce = nonce_prefix + struct.pack(">I", chunk_index)
            ct = signer.encrypt_chunk(nonce, data)
            # Write length and ciphertext
            enc_f.write(struct.pack(">I", len(data)))
            enc_f.write(ct)
            total_size += len(data)
            chunk_index += 1
            if args.max_bytes and total_size >= args.max_bytes:
                break
    finally:
        f.close()
        enc_f.close()

    # Finalize analyzer
    analyzer.finalize()

    # Compute hashes
    snapshot_sha256 = sha256_stream_finalize(h_raw)
    # Hash encrypted file
    h_enc = hashlib.sha256()
    try:
        with open(enc_out_path, "rb") as ef:
            while True:
                buf = ef.read(1024 * 1024)
                if not buf:
                    break
                h_enc.update(buf)
    except Exception as e:
        print(f"ERROR: hashing encrypted file failed: {human_reason(e)}", file=sys.stderr)
        sys.exit(5)
    enc_sha256 = h_enc.hexdigest()

    # Build report
    end_time = now_iso8601()
    encryption_alg = "AES-GCM" if not isinstance(signer, InsecureCryptoFallback) else "XOR-SHA256-PRG (INSECURE)"
    key_bits = 8 * getattr(signer, "enc_key", b"\x00"*32).__len__()
    report = {
        "tool": {"id": TOOL_ID, "name": TOOL_NAME, "version": TOOL_VERSION},
        "host": host,
        "timestamp_start": start_time,
        "timestamp_end": end_time,
        "acquisition": {
            "backend": args.backend,
            "read_only": True,
            "source": src_path,
            "chunk_size": chunk_size
        },
        "snapshot": {
            "size": total_size,
            "sha256": snapshot_sha256,
            "encrypted_path": os.path.abspath(enc_out_path),
            "encrypted_sha256": enc_sha256,
            "encryption": f"{encryption_alg}-{key_bits}"
        },
        "findings": {
            "tensors": analyzer.tensor_hits,
            "secrets": analyzer.secret_hits
        },
        "controls": {
            "read_only_acquisition": True,
            "sandboxed_analyzer": "logical-no-exec-parsing-only",
            "parser_safety": "no code execution, regex parsing; optional numpy used",
            "crypto_fallback_used": isinstance(signer, InsecureCryptoFallback),
            "ephemeral_keys_used": bool(getattr(signer, "ephemeral", False))
        },
        "chain_of_custody": {
            "attestations": [],
            "signing_public_key_b64": signer.public_key_b64()
        }
    }

    # Create in-toto statement
    predicate = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{
            "name": "gpu-vram-snapshot",
            "digest": {"sha256": snapshot_sha256}
        }],
        "predicateType": "https://forensics.example/gpu-vram/1.0",
        "predicate": report
    }
    payload = json.dumps(predicate, sort_keys=True).encode("utf-8")
    envelope = dsse_envelope(payload, signer)

    # Write report files
    report_path = os.path.join(args.output_dir, "report.attestation.dsse.json")
    with open(report_path, "w", encoding="utf-8") as rf:
        json.dump(envelope, rf, indent=2, sort_keys=True)

    redacted_summary = {
        "summary": {
            "timestamp": end_time,
            "host": host,
            "snapshot_sha256": snapshot_sha256,
            "encrypted_sha256": enc_sha256,
            "size": total_size,
            "tensors_detected": len(analyzer.tensor_hits),
            "secrets_detected": len(analyzer.secret_hits)
        },
        "findings": {
            "tensors": analyzer.tensor_hits[: min(20, len(analyzer.tensor_hits))],
            "secrets": analyzer.secret_hits[: min(50, len(analyzer.secret_hits))]
        },
        "note": "Sensitive content redacted. Original VRAM artifact preserved only in encrypted form."
    }
    summary_path = os.path.join(args.output_dir, "report.redacted.json")
    with open(summary_path, "w", encoding="utf-8") as sf:
        json.dump(redacted_summary, sf, indent=2, sort_keys=True)

    print(f"Sealed attestation: {report_path}")
    print(f"Redacted human-readable report: {summary_path}")
    print(f"Encrypted VRAM snapshot: {enc_out_path}")

def parse_args():
    p = argparse.ArgumentParser(description=f"{TOOL_NAME} v{TOOL_VERSION}")
    p.add_argument("--backend", choices=["auto", "device", "file"], default="auto",
                   help="Acquisition backend: auto (default), device (/dev/gpuvram_dump), or file (input snapshot).")
    p.add_argument("--input-file", help="Path to a file containing a VRAM snapshot (for testing).")
    p.add_argument("--output-dir", default="gpu_vram_forensics_out", help="Output directory.")
    p.add_argument("--chunk-size", type=int, default=1024*1024, help="Read/encrypt chunk size in bytes.")
    p.add_argument("--max-bytes", type=int, default=0, help="Maximum bytes to read (0 = all).")
    p.add_argument("--tensor-block-kb", type=int, default=64, help="Block size in KB for tensor detection.")
    p.add_argument("--max-tensor-hits", type=int, default=128, help="Maximum number of tensor blocks to report.")
    p.add_argument("--disable-numpy", action="store_true", help="Disable numpy-based heuristics.")
    p.add_argument("--insecure-allow-fallback-crypto", action="store_true",
                   help="Allow insecure crypto fallback if 'cryptography' or keys are unavailable (testing only).")
    p.add_argument("--i-acknowledge-authorized-use", action="store_true", help="Acknowledge authorized use only.")
    return p.parse_args()

if __name__ == "__main__":
    try:
        run(parse_args())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)