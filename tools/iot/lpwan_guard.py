import json
import os
import time
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

# Optional cryptography for MIC verification
try:
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    _CRYPTO_AVAILABLE = True
except Exception:
    _CRYPTO_AVAILABLE = False


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _hex_to_bytes(s: str) -> bytes:
    s = s.strip().lower().replace(":", "").replace(" ", "")
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)


def _bytes_to_hex(b: bytes) -> str:
    return b.hex()


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        if isinstance(x, int):
            return x
        if isinstance(x, str):
            if x.lower().startswith("0x"):
                return int(x, 16)
            return int(x)
    except Exception:
        return default
    return default


def _is_default_key_hex(hex_key: str) -> bool:
    """
    Heuristic check for default/known LoRaWAN keys.
    """
    hk = _bytes_to_hex(_hex_to_bytes(hex_key)).upper()
    if len(hk) != 32:
        return False
    # common weak patterns
    if hk == "00000000000000000000000000000000":
        return True
    if hk == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF":
        return True
    if hk == "01010101010101010101010101010101":
        return True
    if hk == "00112233445566778899AABBCCDDEEFF":
        return True
    if hk == "2B7E151628AED2A6ABF7158809CF4F3C":  # NIST AES-128 test key
        return True
    # repeated half
    if hk[:16] == hk[16:]:
        return True
    # low entropy repeating sequences like 0F0F... or AAAA...
    if len(set([hk[i:i+2] for i in range(0, 32, 2)])) <= 4:
        return True
    return False


@dataclass
class Device:
    dev_eui: str
    device_type: str  # 'OTAA' or 'ABP'
    app_eui: Optional[str] = None
    app_key: Optional[str] = None  # OTAA
    nwk_skey: Optional[str] = None  # ABP
    app_skey: Optional[str] = None  # ABP
    vendor: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class Config:
    lab_mode: bool = False
    duty_cycle_limit: Optional[float] = None  # e.g., 0.01 for 1%
    frequency_plan: Optional[str] = None  # e.g., EU868, US915
    tx_power_dbm: Optional[int] = None  # e.g., 14
    redact_identifiers: bool = True
    timestamping_secret: Optional[str] = None  # used to HMAC-seal bundles


class EvidenceSealer:
    def __init__(self, timestamping_secret: Optional[str] = None):
        self.items: List[Dict[str, Any]] = []
        self._chain_head: bytes = b"\x00" * 32
        self._ts_secret = _hex_to_bytes(timestamping_secret) if timestamping_secret else None

    def _hash_item(self, item: Dict[str, Any]) -> bytes:
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).digest()

    def add_item(self, item_type: str, data: Dict[str, Any]) -> str:
        item = {
            "type": item_type,
            "data": data,
            "ts": _now_iso(),
        }
        ih = self._hash_item(item)
        prev = self._chain_head
        ch = hashlib.sha256(prev + ih).digest()
        self._chain_head = ch
        eid = _bytes_to_hex(ih[:8])
        item["id"] = eid
        item["item_hash"] = _bytes_to_hex(ih)
        item["prev_chain_hash"] = _bytes_to_hex(prev)
        item["chain_hash"] = _bytes_to_hex(ch)
        self.items.append(item)
        return eid

    def finalize(self) -> Dict[str, Any]:
        created = _now_iso()
        head = _bytes_to_hex(self._chain_head)
        token = None
        if self._ts_secret:
            token = _hmac_sha256(self._ts_secret, (created + "|" + head).encode("utf-8"))
        return {
            "created_at": created,
            "chain_head": head,
            "items": self.items,
            "timestamp_token": token,
            "crypto": {
                "hmac_alg": "HMAC-SHA256" if self._ts_secret else None,
                "hash_alg": "SHA-256",
            },
            "disclaimer": "Sealed bundle for authorized security auditing. Contains minimal, privacy-preserving evidence."
        }


class LPWANGuardError(Exception):
    pass


class LPWANGuard:
    def __init__(self, config: Optional[Config] = None, inventory: Optional[List[Device]] = None):
        self.config = config or Config()
        self.inventory: Dict[str, Device] = {}
        if inventory:
            for d in inventory:
                self.inventory[self._norm_eui(d.dev_eui)] = d
        self._frames: List[Dict[str, Any]] = []
        self._issues: List[Dict[str, Any]] = []
        self._audit_log: List[Dict[str, Any]] = []
        self._sealer = EvidenceSealer(self.config.timestamping_secret)
        salt = self.config.timestamping_secret or _bytes_to_hex(os.urandom(16))
        self._redaction_salt = _hex_to_bytes(salt)

        if not _CRYPTO_AVAILABLE:
            self._record_info("CRYPTO_LIB_MISSING", "cryptography unavailable, MIC validation limited", {})

    # Utilities
    def _norm_eui(self, e: Optional[str]) -> str:
        if not e:
            return ""
        return _bytes_to_hex(_hex_to_bytes(e)).upper()

    def _redact(self, label: str, value: str) -> str:
        if not value:
            return ""
        if not self.config.redact_identifiers:
            return f"{label}:{value}"
        digest = _hmac_sha256(self._redaction_salt, value.encode("utf-8"))[:12]
        return f"{label}[fp:{digest}]"

    def _record_issue(self, code: str, title: str, severity: str, details: Dict[str, Any]) -> None:
        entry = {
            "code": code,
            "title": title,
            "severity": severity,
            "details": details,
            "ts": _now_iso()
        }
        self._issues.append(entry)

    def _record_info(self, code: str, message: str, details: Dict[str, Any]) -> None:
        entry = {"code": code, "message": message, "details": details, "ts": _now_iso()}
        self._audit_log.append(entry)

    # Ingestion
    def ingest_gateway_logs(self, path: str) -> None:
        self._record_info("INGEST_START", "Ingesting gateway logs", {"path": path})
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception as e:
                    self._record_info("INGEST_LINE_ERROR", "Malformed JSON line", {"line": idx, "error": str(e)})
                    continue
                frame = self._normalize_frame(obj, source="gateway", line=idx, origin=path)
                if frame:
                    self._frames.append(frame)
        self._record_info("INGEST_DONE", "Completed gateway log ingestion", {"count": len(self._frames)})

    def ingest_sdr_capture(self, path: str) -> None:
        self._record_info("INGEST_START", "Ingesting SDR capture", {"path": path})
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception as e:
                    self._record_info("INGEST_LINE_ERROR", "Malformed JSON line", {"line": idx, "error": str(e)})
                    continue
                frame = self._normalize_frame(obj, source="sdr", line=idx, origin=path)
                if frame:
                    self._frames.append(frame)
        self._record_info("INGEST_DONE", "Completed SDR capture ingestion", {"count": len(self._frames)})

    def _normalize_frame(self, obj: Dict[str, Any], source: str, line: int, origin: str) -> Optional[Dict[str, Any]]:
        ts = obj.get("ts") or obj.get("timestamp") or _now_iso()
        mtype = obj.get("type") or obj.get("mtype") or obj.get("MType")
        mtype = (mtype or "").lower()
        dev_eui = self._norm_eui(obj.get("dev_eui") or obj.get("DevEUI"))
        app_eui = self._norm_eui(obj.get("app_eui") or obj.get("AppEUI"))
        raw = obj.get("raw") or obj.get("phy_payload") or ""
        mic = obj.get("mic") or obj.get("MIC") or ""
        dev_nonce = obj.get("dev_nonce") or obj.get("DevNonce")
        if mtype in ("join-request", "join_request", "joinreq"):
            ftype = "join_request"
            dn = _safe_int(dev_nonce, -1)
        elif mtype in ("unconfirmeddataup", "confirmeddataup", "data_up", "up"):
            ftype = "data_up"
            dn = None
        elif mtype in ("unconfirmeddatadown", "confirmeddatadown", "data_down", "down"):
            ftype = "data_down"
            dn = None
        else:
            # unknown type, try infer by presence of dev_nonce
            if dev_nonce is not None:
                ftype = "join_request"
                dn = _safe_int(dev_nonce, -1)
            else:
                ftype = "unknown"
                dn = None

        rec_id = f"{source}:{os.path.basename(origin)}:{line}"
        frame = {
            "id": rec_id,
            "source": source,
            "origin": origin,
            "line": line,
            "ts": ts,
            "type": ftype,
            "dev_eui": dev_eui,
            "app_eui": app_eui,
            "dev_nonce": dn,
            "mic": mic,
            "raw": raw,
        }
        return frame

    # Analysis
    def analyze(self) -> None:
        self._record_info("ANALYZE_START", "Starting analysis", {"frames": len(self._frames)})
        self._check_repeated_devnonce()
        self._check_appkey_reuse()
        self._check_abp_default_keys()
        self._validate_join_mic()
        # MAC command hardening placeholder
        self._record_info("ADR_MAC_VALIDATION", "ADR/MAC command hardening validation is limited in this version", {})
        self._record_info("ANALYZE_DONE", "Analysis completed", {"issues": len(self._issues)})

    def _check_repeated_devnonce(self) -> None:
        devnonce_map: Dict[str, Dict[int, List[str]]] = {}
        for fr in self._frames:
            if fr["type"] != "join_request":
                continue
            dev = fr["dev_eui"]
            dn = fr["dev_nonce"]
            if dev not in devnonce_map:
                devnonce_map[dev] = {}
            if dn not in devnonce_map[dev]:
                devnonce_map[dev][dn] = []
            devnonce_map[dev][dn].append(fr["id"])

        for dev, nonce_map in devnonce_map.items():
            for dn, ids in nonce_map.items():
                if dn is None or dn < 0:
                    continue
                if len(ids) > 1:
                    redacted_dev = self._redact("DevEUI", dev)
                    title = "Repeated DevNonce observed across multiple OTAA Join-Requests"
                    details = {
                        "device": redacted_dev,
                        "dev_nonce": dn,
                        "occurrences": ids,
                        "risk": "Potential replay risk; ensure device enforces monotonically increasing DevNonce and server tracks used nonces."
                    }
                    self._record_issue("REPLAY_RISK", title, "high", details)
                    # Add sealed evidence referencing frames
                    self._sealer.add_item("replay_evidence", {
                        "device": redacted_dev,
                        "dev_nonce": dn,
                        "supporting_frames": ids
                    })

    def _check_appkey_reuse(self) -> None:
        # across inventory
        appkey_to_devs: Dict[str, List[str]] = {}
        for dev_id, dev in self.inventory.items():
            if dev.device_type.upper() == "OTAA" and dev.app_key:
                key_norm = _bytes_to_hex(_hex_to_bytes(dev.app_key)).upper()
                appkey_to_devs.setdefault(key_norm, []).append(dev_id)
        for k, devs in appkey_to_devs.items():
            if len(devs) > 1:
                red = [self._redact("DevEUI", d) for d in devs]
                self._record_issue(
                    "APPKEY_REUSE",
                    "Same AppKey used by multiple devices",
                    "medium",
                    {"devices": red, "key_fp": _sha256(_hex_to_bytes(k))[:16]}
                )
                self._sealer.add_item("key_reuse", {
                    "key_fingerprint": _sha256(_hex_to_bytes(k))[:16],
                    "device_count": len(devs)
                })

    def _check_abp_default_keys(self) -> None:
        for dev_id, dev in self.inventory.items():
            if dev.device_type.upper() != "ABP":
                continue
            weak = []
            if dev.nwk_skey and _is_default_key_hex(dev.nwk_skey):
                weak.append("NwkSKey")
            if dev.app_skey and _is_default_key_hex(dev.app_skey):
                weak.append("AppSKey")
            if weak:
                red_dev = self._redact("DevEUI", dev_id)
                steps = [
                    "Migrate device from ABP to OTAA to enable dynamic session keys.",
                    "Provision unique AppKey per device; avoid reuse.",
                    "Rotate keys: generate strong random 128-bit keys; update device securely.",
                    "On network server, revoke old ABP session keys and enforce MIC/FCnt checks.",
                    "Test join process in lab mode before field deployment."
                ]
                self._record_issue(
                    "DEFAULT_KEY",
                    "ABP device uses default or weak session keys",
                    "high",
                    {"device": red_dev, "weak_components": weak, "recommendation_steps": steps}
                )
                self._sealer.add_item("weak_key", {
                    "device": red_dev,
                    "weak_components": weak,
                    "key_fingerprints": {
                        "NwkSKey": _sha256(_hex_to_bytes(dev.nwk_skey))[:16] if dev.nwk_skey else None,
                        "AppSKey": _sha256(_hex_to_bytes(dev.app_skey))[:16] if dev.app_skey else None,
                    }
                })

    def _validate_join_mic(self) -> None:
        if not _CRYPTO_AVAILABLE:
            return
        for fr in self._frames:
            if fr["type"] != "join_request":
                continue
            dev = fr["dev_eui"]
            inv = self.inventory.get(dev)
            if not inv or not inv.app_key:
                continue  # No brute forcing; only verify if key is provided
            raw_hex = fr.get("raw") or ""
            if not raw_hex:
                continue
            try:
                if self._check_join_mic(raw_hex, inv.app_key) is False:
                    red = self._redact("DevEUI", dev)
                    self._record_issue(
                        "MIC_FAILURE",
                        "Join-Request MIC verification failed",
                        "medium",
                        {"device": red, "frame_id": fr["id"]}
                    )
                    self._sealer.add_item("mic_failure", {
                        "device": red,
                        "frame": fr["id"]
                    })
            except Exception as e:
                self._record_info("MIC_CHECK_ERROR", "Error verifying MIC", {"frame": fr["id"], "error": str(e)})

    def _check_join_mic(self, phy_payload_hex: str, app_key_hex: str) -> Optional[bool]:
        """
        Verifies MIC of Join-Request PHYPayload given AppKey.
        PHYPayload = MHDR(1) | Join-request payload (AppEUI|DevEUI|DevNonce) | MIC(4)
        MIC = CMAC(AppKey, MHDR | Join-request payload)[:4]
        Returns True if matches, False if mismatch, None if cannot parse.
        """
        data = _hex_to_bytes(phy_payload_hex)
        if len(data) < 5:
            return None
        msg = data[:-4]
        mic = data[-4:]
        key = _hex_to_bytes(app_key_hex)
        cmac = CMAC(algorithms.AES(key))
        cmac.update(msg)
        full = cmac.finalize()
        calc = full[:4]
        return calc == mic

    # Active (lab-mode) operations
    def simulate_join(self, dev_eui: str, app_eui: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs a lab-safe join simulation for a device.
        Requires lab_mode and configured duty cycle, frequency plan, and tx power.
        """
        self._ensure_lab_mode()
        # Basic simulation only: do not transmit RF, just compute expected nonce behavior
        dev_eui_n = self._norm_eui(dev_eui)
        app_eui_n = self._norm_eui(app_eui) if app_eui else ""
        red_dev = self._redact("DevEUI", dev_eui_n)
        sim = {
            "device": red_dev,
            "app": self._redact("AppEUI", app_eui_n) if app_eui_n else None,
            "simulated": True,
            "duty_cycle_limit": self.config.duty_cycle_limit,
            "frequency_plan": self.config.frequency_plan,
            "tx_power_dbm": self.config.tx_power_dbm,
            "notes": "Lab-safe join simulation: no RF transmissions performed."
        }
        self._sealer.add_item("lab_simulation", sim)
        return sim

    def active_transmission(self, payload_hex: str) -> None:
        """
        Placeholder for any active RF transmission. This tool prohibits live transmissions unless lab mode is configured.
        """
        self._ensure_lab_mode()
        # In lab mode, we still refrain from actual RF TX. This method documents the intent and assures compliance.
        self._record_info("LAB_TX_PLACEHOLDER", "Active transmission is disabled in this tool. Use specialized lab RF tools.", {})

    def _ensure_lab_mode(self) -> None:
        if not self.config.lab_mode or self.config.duty_cycle_limit is None or self.config.frequency_plan is None or self.config.tx_power_dbm is None:
            self._record_issue(
                "LAB_MODE_REQUIRED",
                "Active operation refused: lab mode and RF compliance parameters are required",
                "safety",
                {
                    "lab_mode": self.config.lab_mode,
                    "duty_cycle_limit": self.config.duty_cycle_limit,
                    "frequency_plan": self.config.frequency_plan,
                    "tx_power_dbm": self.config.tx_power_dbm
                }
            )
            raise LPWANGuardError("LAB_MODE_REQUIRED")

    # Reporting
    def generate_report(self) -> Dict[str, Any]:
        ethics = [
            "This tool is for authorized testing only. Unauthorized interception or transmission may be illegal.",
            "Passive RF monitoring is the default. Active tests require lab mode with regulatory-compliant settings.",
            "Identifiers are redacted by default; do not attempt to deanonymize without proper authorization.",
            "No key brute-forcing is performed; keys are only verified against provided inventories."
        ]
        report = {
            "tool": "LPWANGuard: LoRaWAN Key & Replay Auditor",
            "category": "iot",
            "timestamp": _now_iso(),
            "summary": {
                "frames_analyzed": len(self._frames),
                "issues_count": len(self._issues),
            },
            "issues": self._issues,
            "audit_log": self._audit_log,
            "ethics": ethics,
            "privacy": {
                "redaction_enabled": self.config.redact_identifiers,
                "redaction_method": "Identifier HMAC fingerprinting"
            }
        }
        sealed = self._sealer.finalize()
        report["sealed_bundle"] = sealed
        return report

    # Convenience methods for unit/integration tests
    def add_frame(self, frame: Dict[str, Any]) -> None:
        """
        Add a pre-normalized frame for analysis. Keys: type, dev_eui, dev_nonce, id
        """
        # Allow minimal subset; normalize dev_eui
        fr = {
            "id": frame.get("id", f"manual:{len(self._frames)+1}"),
            "source": frame.get("source", "manual"),
            "origin": frame.get("origin", "manual"),
            "line": frame.get("line", 0),
            "ts": frame.get("ts", _now_iso()),
            "type": frame.get("type", "unknown"),
            "dev_eui": self._norm_eui(frame.get("dev_eui", "")),
            "app_eui": self._norm_eui(frame.get("app_eui", "")),
            "dev_nonce": frame.get("dev_nonce"),
            "mic": frame.get("mic"),
            "raw": frame.get("raw", "")
        }
        self._frames.append(fr)

    def get_issues(self) -> List[Dict[str, Any]]:
        return self._issues

    def get_audit_log(self) -> List[Dict[str, Any]]:
        return self._audit_log

    def set_redaction(self, enabled: bool) -> None:
        self.config.redact_identifiers = enabled


# Optional utility to build inventory from dicts
def build_inventory(devices: List[Dict[str, Any]]) -> List[Device]:
    inv: List[Device] = []
    for d in devices:
        inv.append(Device(
            dev_eui=d.get("dev_eui", ""),
            device_type=d.get("device_type", "OTAA"),
            app_eui=d.get("app_eui"),
            app_key=d.get("app_key"),
            nwk_skey=d.get("nwk_skey"),
            app_skey=d.get("app_skey"),
            vendor=d.get("vendor"),
            notes=d.get("notes"),
        ))
    return inv