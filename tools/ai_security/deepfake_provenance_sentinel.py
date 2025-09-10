#!/usr/bin/env python3
"""
Deepfake Provenance & Watermark Sentinel

Ethical use only: This tool is intended for authorized security testing, integrity verification, and policy enforcement
to mitigate deepfake-driven fraud and misinformation. Do not use it to profile individuals, extract biometric identifiers,
or violate privacy. The tool is designed to avoid retention of PII/biometric features and defaults to ephemeral analysis.

Capabilities:
- Verify C2PA-style manifests and embedded signatures against trusted roots, with transparency log inclusion checks.
- Cryptographically sign audit outcomes (HMAC-based attestation) with canonical JSON for reproducibility.
- Analyze watermark/fingerprint consistency for images/audio/video via sidecar signal files (no biometric extraction).
- Apply policy-as-code to quarantine/block/flag assets and enforce egress allowlists prior to publishing.
- Default to on-device/ephemeral analysis; supports secure deletion of transient buffers and metadata redaction options.

Note:
- This reference implementation avoids third-party dependencies and uses HMAC-SHA256 for signing/verification to provide
  cryptographic integrity. In production, integrate public-key signatures (e.g., Ed25519/X.509) and a C2PA SDK.
"""

import argparse
import base64
import dataclasses
import datetime
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# --------------------------- Utility and Security Helpers ---------------------------

def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256_hex(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_json_file(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json_file(path: Path, data: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def b64encode(buf: bytes) -> str:
    return base64.b64encode(buf).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def consttime_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class SentinelError(Exception):
    pass


class ProvenanceError(SentinelError):
    pass


class PolicyError(SentinelError):
    pass


# --------------------------- Trusted Root Store and C2PA-like Verification ---------------------------

@dataclasses.dataclass
class TrustedRootStore:
    """
    Trusted root store for simulated C2PA-like verification.

    Structure (JSON):
    {
      "trusted_roots": { "rootA": "<base64-secret>", ... },
      "signers": { "signer1": "<base64-secret>", ... },
      "bindings": { "signer1": "rootA", ... },
      "transparency_logs": ["rootA-log", "rtlog-main", ...]
    }

    Manifest sidecar (asset.ext.c2pa.json) example:
    {
      "content_hash": "<sha256-hex-of-asset>",
      "signer_id": "signer1",
      "root_id": "rootA",
      "signature": "<base64-HMAC(signer_secret, content_hash|signer_id)>",
      "transparency_log": {
        "log_id": "rootA-log",
        "entry_hash": "<base64-HMAC(root_secret, signer_id|content_hash)>"
      }
    }

    This is a simplified model for demo and testing. Replace with real C2PA validation for production.
    """
    trusted_roots: Dict[str, str]
    signers: Dict[str, str]
    bindings: Dict[str, str]
    transparency_logs: List[str]

    @staticmethod
    def from_file(path: Path) -> "TrustedRootStore":
        data = load_json_file(path)
        return TrustedRootStore(
            trusted_roots=data.get("trusted_roots", {}),
            signers=data.get("signers", {}),
            bindings=data.get("bindings", {}),
            transparency_logs=data.get("transparency_logs", []),
        )

    def _get_secret(self, key_b64: str) -> bytes:
        try:
            return b64decode(key_b64)
        except Exception as e:
            raise ProvenanceError(f"Invalid base64 secret in trusted store: {e}")

    def verify_manifest(self, manifest: Dict[str, Any], content_hash: str) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        signer_id = manifest.get("signer_id")
        root_id = manifest.get("root_id")
        signature_b64 = manifest.get("signature")
        m_content_hash = manifest.get("content_hash")
        if not signer_id or not root_id or not signature_b64 or not m_content_hash:
            reasons.append("Manifest missing required fields")
            return False, reasons
        if not consttime_compare(m_content_hash, content_hash):
            reasons.append("Manifest content hash mismatch")
            return False, reasons
        # Check signer binding to root
        bound_root = self.bindings.get(signer_id)
        if bound_root != root_id:
            reasons.append(f"Signer not bound to root: expected {bound_root}, got {root_id}")
            return False, reasons
        signer_secret_b64 = self.signers.get(signer_id)
        root_secret_b64 = self.trusted_roots.get(root_id)
        if not signer_secret_b64 or not root_secret_b64:
            reasons.append("Unknown signer or root in trusted store")
            return False, reasons
        signer_secret = self._get_secret(signer_secret_b64)
        root_secret = self._get_secret(root_secret_b64)
        # Verify signature over content_hash|signer_id with signer secret (HMAC)
        msg = f"{content_hash}|{signer_id}".encode("utf-8")
        expected_sig = hmac.new(signer_secret, msg, hashlib.sha256).digest()
        try:
            provided_sig = b64decode(signature_b64)
        except Exception:
            reasons.append("Invalid base64 in manifest signature")
            return False, reasons
        if not hmac.compare_digest(expected_sig, provided_sig):
            reasons.append("Invalid manifest signature (HMAC mismatch)")
            return False, reasons
        # Transparency log inclusion check
        tlog = manifest.get("transparency_log") or {}
        log_id = tlog.get("log_id")
        entry_hash_b64 = tlog.get("entry_hash")
        if log_id and entry_hash_b64:
            if log_id not in self.transparency_logs:
                reasons.append("Transparency log not in trusted allowlist")
                return False, reasons
            tmsg = f"{signer_id}|{content_hash}".encode("utf-8")
            expected_entry = hmac.new(root_secret, tmsg, hashlib.sha256).digest()
            try:
                provided_entry = b64decode(entry_hash_b64)
            except Exception:
                reasons.append("Invalid base64 in transparency entry hash")
                return False, reasons
            if not hmac.compare_digest(expected_entry, provided_entry):
                reasons.append("Transparency log entry hash mismatch")
                return False, reasons
            reasons.append("Transparency log inclusion verified")
        else:
            reasons.append("No transparency log entry present")
        reasons.append("Manifest signature verified and signer bound to trusted root")
        return True, reasons


# --------------------------- Signal Analysis (Watermarks and Heuristics) ---------------------------

@dataclasses.dataclass
class WatermarkAnalysis:
    inconsistency_score: float
    inconsistent: bool
    details: str


def analyze_watermarks(asset_path: Path) -> WatermarkAnalysis:
    """
    Analyze watermark/fingerprint consistency via sidecar file: <asset>.wmk.json
    Expected format:
    {
      "frame_marks": [0.12, 0.11, 0.13, ...],  # normalized per-frame watermark strength
      "robustness_scores": [ ... ]             # optional
    }
    """
    sidecar = Path(str(asset_path) + ".wmk.json")
    if not sidecar.exists():
        return WatermarkAnalysis(inconsistency_score=0.0, inconsistent=False, details="No watermark sidecar")
    try:
        data = load_json_file(sidecar)
        marks = data.get("frame_marks") or []
        if not marks or len(marks) < 2:
            return WatermarkAnalysis(inconsistency_score=0.0, inconsistent=False, details="Insufficient watermark frames")
        # Compute coefficient of variation and adjacent delta spikes
        import math
        mean_val = sum(marks) / len(marks)
        variance = sum((x - mean_val) ** 2 for x in marks) / (len(marks) - 1)
        stddev = math.sqrt(variance)
        cov = (stddev / mean_val) if mean_val != 0 else float("inf")
        # Spike detection: large alternating swings suggest splicing/tamper
        deltas = [abs(marks[i + 1] - marks[i]) for i in range(len(marks) - 1)]
        spike_ratio = sum(1 for d in deltas if d > 0.35) / max(1, len(deltas))
        score = min(1.0, 0.5 * min(1.0, cov) + 0.5 * spike_ratio)
        inconsistent = score > 0.55
        details = f"cov={cov:.3f}, spikes={spike_ratio:.3f}"
        return WatermarkAnalysis(inconsistency_score=round(score, 3), inconsistent=inconsistent, details=details)
    except Exception as e:
        return WatermarkAnalysis(inconsistency_score=0.0, inconsistent=False, details=f"Error reading watermark sidecar: {e}")


@dataclasses.dataclass
class HeuristicsAnalysis:
    lip_sync_mismatch: float
    spectral_artifacts: float
    composite_score: float
    suspicious: bool
    details: str


def analyze_deepfake_heuristics(asset_path: Path) -> HeuristicsAnalysis:
    """
    Analyze deepfake heuristics via sidecar file: <asset>.dfh.json
    Expected format:
    {
      "lip_sync_mismatch": 0.8,   # 0..1
      "spectral_artifacts": 0.7   # 0..1
    }
    """
    sidecar = Path(str(asset_path) + ".dfh.json")
    if not sidecar.exists():
        return HeuristicsAnalysis(0.0, 0.0, 0.0, False, "No heuristics sidecar")
    try:
        data = load_json_file(sidecar)
        lip = float(data.get("lip_sync_mismatch", 0.0))
        spec = float(data.get("spectral_artifacts", 0.0))
        composite = min(1.0, 0.6 * lip + 0.4 * spec)
        suspicious = composite >= 0.65 or (lip >= 0.75 and spec >= 0.55)
        details = f"lip={lip:.2f}, spec={spec:.2f}"
        return HeuristicsAnalysis(round(lip, 3), round(spec, 3), round(composite, 3), suspicious, details)
    except Exception as e:
        return HeuristicsAnalysis(0.0, 0.0, 0.0, False, f"Error reading heuristics sidecar: {e}")


# --------------------------- Policy Model and Enforcement ---------------------------

@dataclasses.dataclass
class PolicyConfig:
    # Egress allowlist of hostnames (no protocol/path)
    egress_allowlist: List[str] = dataclasses.field(default_factory=list)
    # Require valid provenance for publishing
    require_provenance_for_publish: bool = True
    # Thresholds
    watermark_inconsistency_action: str = "flag"  # flag/quarantine/block
    heuristics_block_threshold: float = 0.65
    # Signed attestation required
    require_signed_attestation: bool = True

    @staticmethod
    def from_file(path: Optional[Path]) -> "PolicyConfig":
        if not path:
            return PolicyConfig()
        data = load_json_file(path)
        return PolicyConfig(
            egress_allowlist=data.get("egress_allowlist", []),
            require_provenance_for_publish=data.get("require_provenance_for_publish", True),
            watermark_inconsistency_action=data.get("watermark_inconsistency_action", "flag"),
            heuristics_block_threshold=float(data.get("heuristics_block_threshold", 0.65)),
            require_signed_attestation=data.get("require_signed_attestation", True),
        )


@dataclasses.dataclass
class Decision:
    action: str  # allow/block/quarantine/flag
    reasons: List[str]
    egress_allowed: bool = True
    target: Optional[str] = None


def enforce_policy(
    policy: PolicyConfig,
    media_type: str,
    provenance_verified: bool,
    watermark: WatermarkAnalysis,
    heuristics: HeuristicsAnalysis,
    publish_target: Optional[str] = None,
) -> Decision:
    reasons: List[str] = []
    action = "allow"

    # Watermark inconsistency handling
    if watermark.inconsistent:
        reasons.append(f"Watermark/fingerprint inconsistency detected ({watermark.details})")
        if policy.watermark_inconsistency_action in ("block", "quarantine", "flag"):
            action = policy.watermark_inconsistency_action

    # Deepfake heuristics + provenance requirements
    if publish_target:
        # Egress allowlist check
        host = _extract_host(publish_target)
        if policy.egress_allowlist and host not in policy.egress_allowlist:
            reasons.append(f"Egress host not allowlisted: {host}")
            return Decision(action="block", reasons=reasons, egress_allowed=False, target=publish_target)
        # Publishing conditions
        if policy.require_provenance_for_publish and not provenance_verified:
            if heuristics.suspicious or heuristics.composite_score >= policy.heuristics_block_threshold:
                reasons.append("Publishing blocked: no provenance and deepfake heuristics suspicious")
                return Decision(action="block", reasons=reasons, egress_allowed=True, target=publish_target)
            else:
                reasons.append("Provenance missing but heuristics not strongly suspicious")
                action = max_priority(action, "flag")
    else:
        # Not a publish action: still block if heuristics are very high and provenance missing
        if not provenance_verified and heuristics.composite_score >= (policy.heuristics_block_threshold + 0.2):
            reasons.append("Blocked: strong deepfake heuristics and no provenance")
            action = "block"

    if not reasons:
        reasons.append("No policy violations detected")
    return Decision(action=action, reasons=reasons, egress_allowed=True, target=publish_target)


def _extract_host(url: str) -> str:
    # Very minimal host extraction
    if "://" in url:
        rest = url.split("://", 1)[1]
    else:
        rest = url
    host = rest.split("/", 1)[0]
    # strip port
    return host.split(":", 1)[0].lower()


def max_priority(a: str, b: str) -> str:
    order = {"allow": 0, "flag": 1, "quarantine": 2, "block": 3}
    return a if order.get(a, 0) >= order.get(b, 0) else b


# --------------------------- Attestations and Signing ---------------------------

@dataclasses.dataclass
class Attestor:
    """
    HMAC-based attestor for signing canonical audit records.

    Load secret from:
    - --attestor-secret-file (raw bytes or base64)
    - or env SENTINEL_ATTESTOR_SECRET (base64)
    """
    secret: bytes

    @staticmethod
    def from_args(secret_file: Optional[Path]) -> "Attestor":
        secret: Optional[bytes] = None
        if secret_file and secret_file.exists():
            raw = secret_file.read_bytes()
            # try base64 decode, else treat as raw
            try:
                secret = base64.b64decode(raw)
            except Exception:
                secret = raw
        if secret is None:
            env = os.environ.get("SENTINEL_ATTESTOR_SECRET", "")
            if env:
                try:
                    secret = b64decode(env)
                except Exception:
                    # fallback: treat env as raw string
                    secret = env.encode("utf-8")
        if secret is None or len(secret) < 16:
            # generate ephemeral secret for session (not ideal for reproducibility)
            secret = hashlib.sha256(f"ephemeral-{time.time_ns()}".encode("utf-8")).digest()
        return Attestor(secret=secret)

    def sign(self, canonical_json: bytes) -> str:
        mac = hmac.new(self.secret, canonical_json, hashlib.sha256).digest()
        return b64encode(mac)

    def verify(self, canonical_json: bytes, signature_b64: str) -> bool:
        try:
            sig = b64decode(signature_b64)
        except Exception:
            return False
        mac = hmac.new(self.secret, canonical_json, hashlib.sha256).digest()
        return hmac.compare_digest(mac, sig)


# --------------------------- Audit Pipeline ---------------------------

@dataclasses.dataclass
class AuditOutcome:
    asset_path: str
    media_type: str
    content_sha256: str
    provenance: Dict[str, Any]
    signals: Dict[str, Any]
    decision: Dict[str, Any]
    timestamp: str
    notice: str
    attestation_signature: str


def detect_media_type(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff"):
        return "image"
    if ext in (".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg"):
        return "audio"
    if ext in (".mp4", ".mov", ".mkv", ".avi", ".webm"):
        return "video"
    return "unknown"


def load_manifest_sidecar(asset_path: Path) -> Optional[Dict[str, Any]]:
    sidecar = Path(str(asset_path) + ".c2pa.json")
    if sidecar.exists():
        try:
            return load_json_file(sidecar)
        except Exception:
            return None
    return None


def redact_metadata(metadata: Dict[str, Any], fields_to_redact: Optional[List[str]] = None) -> Dict[str, Any]:
    fields_to_redact = fields_to_redact or []
    return {k: ("[REDACTED]" if k in fields_to_redact else v) for k, v in metadata.items()}


def audit_asset(
    asset_path: Path,
    trusted_store: Optional[TrustedRootStore],
    attestor: Attestor,
    policy: PolicyConfig,
    redact_meta: bool = True,
    secure_delete: bool = True,
    publish_target: Optional[str] = None,
) -> AuditOutcome:
    if not asset_path.exists() or not asset_path.is_file():
        raise SentinelError(f"Asset not found: {asset_path}")
    media_type = detect_media_type(asset_path)

    # Compute content hash with streaming; erase last chunk memory if requested
    content_sha = ""
    last_chunk = None
    try:
        h = hashlib.sha256()
        with asset_path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                last_chunk = bytearray(chunk)  # for zeroization
        content_sha = h.hexdigest()
    finally:
        if secure_delete and last_chunk is not None:
            for i in range(len(last_chunk)):
                last_chunk[i] = 0  # best-effort zeroization
            del last_chunk

    # Provenance check
    manifest = load_manifest_sidecar(asset_path)
    prov_verified = False
    prov_reasons: List[str] = []
    transparency_checked = False
    if manifest and trusted_store:
        ok, reasons = trusted_store.verify_manifest(manifest, content_sha)
        prov_verified = ok
        prov_reasons = reasons
        transparency_checked = any("Transparency log inclusion verified" in r for r in reasons)
    elif manifest and not trusted_store:
        prov_reasons.append("Manifest present but no trusted root store provided")
    else:
        prov_reasons.append("No provenance manifest found")

    # Signals
    wm = analyze_watermarks(asset_path)
    dfh = analyze_deepfake_heuristics(asset_path)

    # Policy decision
    decision_obj = enforce_policy(policy, media_type, prov_verified, wm, dfh, publish_target=publish_target)

    # Build provenance section (avoid PII; include hashes and booleans only)
    provenance_section = {
        "has_manifest": bool(manifest),
        "verified": prov_verified,
        "transparency_log_checked": transparency_checked,
        "reasons": prov_reasons if not redact_meta else [r for r in prov_reasons],  # reasons are non-PII
    }

    # Signals section (numeric only, no biometric data)
    signals_section = {
        "watermark": {
            "inconsistency_score": wm.inconsistency_score,
            "inconsistent": wm.inconsistent,
            "details": wm.details,
        },
        "heuristics": {
            "lip_sync_mismatch": dfh.lip_sync_mismatch,
            "spectral_artifacts": dfh.spectral_artifacts,
            "composite_score": dfh.composite_score,
            "suspicious": dfh.suspicious,
            "details": dfh.details,
        },
        "alerts": _derive_alerts(wm, dfh),
    }

    # Decision section
    decision_section = {
        "action": decision_obj.action,
        "reasons": decision_obj.reasons,
        "egress_allowed": decision_obj.egress_allowed,
        "target": decision_obj.target,
    }

    notice = "Authorized testing only. No PII or biometric features were retained."

    # Canonical attestation for signing
    canonical = canonicalize_json({
        "asset_path": str(asset_path),
        "media_type": media_type,
        "content_sha256": content_sha,
        "provenance": provenance_section,
        "signals": signals_section,
        "decision": decision_section,
        "timestamp": _now_iso(),
        "notice": notice,
    })
    signature = attestor.sign(canonical)

    return AuditOutcome(
        asset_path=str(asset_path),
        media_type=media_type,
        content_sha256=content_sha,
        provenance=provenance_section,
        signals=signals_section,
        decision=decision_section,
        timestamp=json.loads(canonical.decode("utf-8"))["timestamp"],
        notice=notice,
        attestation_signature=signature,
    )


def _derive_alerts(wm: WatermarkAnalysis, dfh: HeuristicsAnalysis) -> List[str]:
    alerts: List[str] = []
    if wm.inconsistent and wm.inconsistency_score >= 0.75:
        alerts.append("watermark_inconsistency_high")
    elif wm.inconsistent:
        alerts.append("watermark_inconsistency")
    if dfh.suspicious and dfh.composite_score >= 0.8:
        alerts.append("deepfake_heuristics_high")
    elif dfh.suspicious:
        alerts.append("deepfake_heuristics")
    return alerts


def canonicalize_json(obj: Dict[str, Any]) -> bytes:
    # Deterministic JSON: sort keys, separators without spaces, stable ordering
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --------------------------- CLI ---------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="deepfake_provenance_sentinel",
        description="Deepfake Provenance & Watermark Sentinel - Authorized testing only",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    audit_p = sub.add_parser("audit", help="Audit a media asset and enforce policy gates")
    audit_p.add_argument("asset", help="Path to media asset (image/audio/video)")
    audit_p.add_argument("--roots", help="Path to trusted root store JSON", default=None)
    audit_p.add_argument("--policy", help="Path to policy JSON", default=None)
    audit_p.add_argument("--attestor-secret-file", help="Path to attestor secret file (raw/base64)", default=None)
    audit_p.add_argument("--publish", help="Simulate publishing target URL for egress policy", default=None)
    audit_p.add_argument("--no-redact", help="Do not redact metadata (still avoids PII)", action="store_true")
    audit_p.add_argument("--no-secure-delete", help="Disable secure deletion of buffers", action="store_true")
    audit_p.add_argument("--out", help="Write signed audit outcome JSON to file", default=None)

    args = parser.parse_args(argv)
    if args.cmd == "audit":
        asset_path = Path(args.asset)
        trusted_store = TrustedRootStore.from_file(Path(args.roots)) if args.roots else None
        policy = PolicyConfig.from_file(Path(args.policy) if args.policy else None)
        attestor = Attestor.from_args(Path(args.attestor_secret_file) if args.attestor_secret_file else None)
        try:
            outcome = audit_asset(
                asset_path=asset_path,
                trusted_store=trusted_store,
                attestor=attestor,
                policy=policy,
                redact_meta=(not args.no_redact),
                secure_delete=(not args.no_secure_delete),
                publish_target=args.publish,
            )
        except SentinelError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
        # Build final attestation record
        record = {
            "asset_path": outcome.asset_path,
            "media_type": outcome.media_type,
            "content_sha256": outcome.content_sha256,
            "provenance": outcome.provenance,
            "signals": outcome.signals,
            "decision": outcome.decision,
            "timestamp": outcome.timestamp,
            "notice": outcome.notice,
            "attestation_signature": outcome.attestation_signature,
        }
        out_json = json.dumps(record, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(out_json, encoding="utf-8")
            print(f"Audit complete. Signed attestation written to {args.out}")
        else:
            print(out_json)
        # Ethical warning
        print("Warning: Use only for authorized testing and integrity assurance. Do not retain PII.", file=sys.stderr)
        # Exit code policy: non-allow actions return non-zero
        if outcome.decision["action"] in ("block", "quarantine"):
            return 1
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())