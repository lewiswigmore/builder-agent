import os
import time
import json
import hmac
import hashlib
import threading
import queue
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

# Ethical Notice:
# CANary Lab is intended for authorized testing only on your own vehicles or test benches.
# Misuse on public roads or unauthorized systems may cause harm or legal consequences.
# Always follow safety procedures, obtain explicit permission, and comply with applicable laws.


# ---------------------------
# Data Structures
# ---------------------------

@dataclass
class CANFrame:
    timestamp: float
    can_id: int
    data: bytes  # up to 8 bytes

@dataclass
class UDSTranscriptEntry:
    timestamp: float
    direction: str  # 'tx' or 'rx'
    target_id: int
    service: int
    subfunction: Optional[int] = None
    payload: str = ""  # hex string
    response_code: Optional[int] = None
    success: Optional[bool] = None
    note: Optional[str] = None

@dataclass
class SafetyEvent:
    timestamp: float
    event_type: str
    details: Dict[str, str] = field(default_factory=dict)

@dataclass
class Finding:
    timestamp: float
    title: str
    severity: str
    details: Dict[str, str] = field(default_factory=dict)


# ---------------------------
# Safety Policy and Rate Control
# ---------------------------

class SafetyPolicy:
    def __init__(
        self,
        speed_threshold_kph: float = 0.1,
        rpm_threshold: int = 0,
        allowlist_vins: Optional[List[str]] = None,
        allowlist_ecus: Optional[List[int]] = None,
        operator_confirm: Optional[Callable[[str, int], bool]] = None,
        safe_services: Optional[List[int]] = None,
        risky_services: Optional[List[int]] = None,
        speed_provider: Optional[Callable[[], float]] = None,
        rpm_provider: Optional[Callable[[], int]] = None,
    ):
        self.speed_threshold_kph = speed_threshold_kph
        self.rpm_threshold = rpm_threshold
        self.allowlist_vins = set(allowlist_vins or [])
        self.allowlist_ecus = set(allowlist_ecus or [])
        self.operator_confirm = operator_confirm
        self.safe_services = set(safe_services or [0x10, 0x19, 0x22])  # session control, read DTC, read data
        self.risky_services = set(risky_services or [0x11, 0x27, 0x31, 0x34, 0x2E, 0x85])
        self.speed_provider = speed_provider or (lambda: 0.0)
        self.rpm_provider = rpm_provider or (lambda: 0)

    def check_dynamic_safety(self) -> Tuple[bool, Optional[SafetyEvent]]:
        speed = self.speed_provider()
        rpm = self.rpm_provider()
        if speed > self.speed_threshold_kph or rpm > self.rpm_threshold:
            return False, SafetyEvent(
                timestamp=time.time(),
                event_type="dynamic_gating_triggered",
                details={
                    "speed_kph": f"{speed:.2f}",
                    "rpm": str(rpm),
                    "reason": "Speed or RPM exceeded threshold"
                }
            )
        return True, None

    def confirm_risky(self, service: int, target_id: int) -> bool:
        if service in self.risky_services:
            if self.operator_confirm:
                return self.operator_confirm(f"UDS service 0x{service:02X}", target_id)
            return False
        return True

    def check_static_allowlist(self, vin: Optional[str], ecu_id: Optional[int]) -> bool:
        vin_ok = (not self.allowlist_vins) or (vin in self.allowlist_vins) if vin else False if self.allowlist_vins else True
        ecu_ok = (not self.allowlist_ecus) or (ecu_id in self.allowlist_ecus) if ecu_id is not None else False if self.allowlist_ecus else True
        return vin_ok and ecu_ok


class RateController:
    def __init__(self, inter_frame_gap_ms: float = 5.0, max_frames_per_sec: int = 300):
        self.ifg = max(0.0, inter_frame_gap_ms / 1000.0)
        self.max_fps = max(1, max_frames_per_sec)
        self._last_send_ts = 0.0
        self._bucket = 0
        self._bucket_ts = time.time()

    def wait_slot(self):
        now = time.time()
        # Inter-frame gap enforcement
        delta = now - self._last_send_ts
        if delta < self.ifg:
            time.sleep(self.ifg - delta)
        # Token bucket style FPS limit
        now = time.time()
        if now - self._bucket_ts >= 1.0:
            self._bucket = 0
            self._bucket_ts = now
        if self._bucket >= self.max_fps:
            time.sleep(max(0.0, 1.0 - (now - self._bucket_ts)))
            self._bucket = 0
            self._bucket_ts = time.time()
        self._bucket += 1
        self._last_send_ts = time.time()


# ---------------------------
# Simulated ECU and Transport
# ---------------------------

class SimulatedECU:
    """
    Minimal UDS behavior to support acceptance tests.
    """
    def __init__(self, ecu_id: int = 0x7E0, resp_id: int = 0x7E8, vin: str = "TESTVIN123456789", weak_algo: str = "SEED_PLUS_ONE"):
        self.ecu_id = ecu_id
        self.resp_id = resp_id
        self.vin = vin
        self.session = 0x01  # default session
        self.security_unlocked = False
        self.pending_seed: Optional[int] = None
        self.weak_algo = weak_algo  # "SEED_PLUS_ONE" or "SEED_XOR_FF"
        self.critical_dtcs: List[str] = []  # e.g., ["P0A0F"] powertrain
        self.last_activity = time.time()

    def _compute_key(self, seed: int) -> int:
        if self.weak_algo == "SEED_PLUS_ONE":
            return (seed + 1) & 0xFFFFFFFF
        elif self.weak_algo == "SEED_XOR_FF":
            return seed ^ 0xFFFFFFFF
        else:
            # default secure behavior (not weak)
            # unrealistic, but for our purposes we keep it locked
            return 0

    def _mk_positive(self, sid: int, payload: bytes) -> bytes:
        return bytes([sid + 0x40]) + payload

    def _mk_negative(self, sid: int, nrc: int) -> bytes:
        return bytes([0x7F, sid, nrc])

    def handle_uds(self, req: bytes) -> bytes:
        self.last_activity = time.time()
        if not req:
            return self._mk_negative(0x00, 0x13)  # incorrect length
        sid = req[0]
        # 0x10 DiagnosticSessionControl
        if sid == 0x10:
            if len(req) < 2:
                return self._mk_negative(sid, 0x13)
            sub = req[1]
            if sub in (0x01, 0x03):  # default or extended
                self.session = sub
                return self._mk_positive(sid, bytes([sub, 0x00, 0x32, 0x00]))  # timing params dummy
            else:
                return self._mk_negative(sid, 0x12)  # subfunction not supported
        # 0x11 ECUReset
        if sid == 0x11:
            if not self.security_unlocked and self.session != 0x03:
                return self._mk_negative(sid, 0x7E)  # contradicted conditions
            return self._mk_positive(sid, req[1:2] if len(req) > 1 else b"\x01")
        # 0x27 SecurityAccess
        if sid == 0x27:
            if len(req) < 2:
                return self._mk_negative(sid, 0x13)
            sub = req[1]
            if sub == 0x01:  # request seed
                # create deterministic seed based on time for simulation
                seed = random.getrandbits(32)
                self.pending_seed = seed
                return self._mk_positive(sid, bytes([0x01]) + seed.to_bytes(4, "big"))
            elif sub == 0x02:  # send key
                if self.pending_seed is None or len(req) < 6:
                    return self._mk_negative(sid, 0x24)  # req seq error
                provided_key = int.from_bytes(req[2:6], "big")
                expected = self._compute_key(self.pending_seed)
                if provided_key == expected:
                    self.security_unlocked = True
                    self.pending_seed = None
                    return self._mk_positive(sid, bytes([0x02]))
                else:
                    self.security_unlocked = False
                    return self._mk_negative(sid, 0x35)  # invalid key
            else:
                return self._mk_negative(sid, 0x12)
        # 0x22 ReadDataByIdentifier
        if sid == 0x22:
            if len(req) < 3:
                return self._mk_negative(sid, 0x13)
            did = (req[1] << 8) | req[2]
            if did == 0xF190:  # VIN
                vin_bytes = self.vin.encode("ascii")
                return self._mk_positive(sid, req[1:3] + vin_bytes)
            else:
                return self._mk_negative(sid, 0x31)  # request out of range
        # 0x19 ReadDTCInformation (simplified)
        if sid == 0x19:
            # We respond with no DTCs present in simplest case
            if self.critical_dtcs:
                # encode some fake DTC response
                # Not realistic encoding; for testing we just send ASCII codes joined
                dtc_bytes = ",".join(self.critical_dtcs).encode("ascii")
                return self._mk_positive(sid, b"\x02" + dtc_bytes)
            else:
                return self._mk_positive(sid, b"\x02")  # "no DTCs" indicator (not real UDS)
        # default: service not supported
        return self._mk_negative(sid, 0x11)


class LocalUDSTransport:
    """
    Local transport that simulates CAN IDs and captures frames to recorder.
    Request to ECU ID (e.g., 0x7E0), response from resp_id (0x7E8).
    """
    def __init__(self, ecu: SimulatedECU, recorder: Optional['EvidenceRecorder'] = None, rate: Optional[RateController] = None):
        self.ecu = ecu
        self.recorder = recorder
        self.rate = rate or RateController()

    def send_request(self, req: bytes) -> bytes:
        # record TX can frame(s) - single frame UDS only in this minimal transport
        if self.rate:
            self.rate.wait_slot()
        ts = time.time()
        if self.recorder is not None:
            frame = CANFrame(timestamp=ts, can_id=self.ecu.ecu_id, data=req[:8])
            self.recorder.record_can_frame(frame)
            self.recorder.record_uds(UDSTranscriptEntry(
                timestamp=ts, direction="tx", target_id=self.ecu.ecu_id,
                service=req[0], subfunction=req[1] if len(req) > 1 else None,
                payload=req.hex()
            ))
        # process ECU
        resp = self.ecu.handle_uds(req)
        # record RX
        ts2 = time.time()
        if self.recorder is not None:
            frame2 = CANFrame(timestamp=ts2, can_id=self.ecu.resp_id, data=resp[:8])
            self.recorder.record_can_frame(frame2)
            # check success
            success = (len(resp) > 0 and (resp[0] & 0x40) != 0 and resp[0] != 0x7F)
            rcode = None
            if len(resp) >= 3 and resp[0] == 0x7F:
                rcode = resp[2]
                success = False
            self.recorder.record_uds(UDSTranscriptEntry(
                timestamp=ts2, direction="rx", target_id=self.ecu.resp_id,
                service=resp[0] - 0x40 if success else (resp[1] if len(resp) > 1 else 0),
                subfunction=None, payload=resp.hex(), response_code=rcode, success=success
            ))
        return resp


# ---------------------------
# Evidence Recorder and PCAP Writer
# ---------------------------

class EvidenceRecorder:
    def __init__(self, time_source: Optional[Callable[[], float]] = None):
        self.time_source = time_source or time.time
        self._can_frames: List[CANFrame] = []
        self._uds_entries: List[UDSTranscriptEntry] = []
        self._events: List[SafetyEvent] = []
        self._findings: List[Finding] = []
        self._lock = threading.Lock()

    def record_can_frame(self, frame: CANFrame):
        with self._lock:
            self._can_frames.append(frame)

    def record_uds(self, entry: UDSTranscriptEntry):
        with self._lock:
            self._uds_entries.append(entry)

    def emit_event(self, event: SafetyEvent):
        with self._lock:
            self._events.append(event)

    def add_finding(self, finding: Finding):
        with self._lock:
            self._findings.append(finding)

    def _write_pcap(self, path: str):
        # Write little-endian pcap with LINKTYPE_CAN_SOCKETCAN (227)
        LINKTYPE_CAN_SOCKETCAN = 227
        with open(path, "wb") as f:
            # Global header
            f.write(struct_pack_le(0xA1B2C3D4, 4))  # magic number (little-endian representation will be D4 C3 B2 A1)
            f.write(struct_pack_le(2, 2))  # version_major
            f.write(struct_pack_le(4, 2))  # version_minor
            f.write(struct_pack_le(0, 4))  # thiszone
            f.write(struct_pack_le(0, 4))  # sigfigs
            f.write(struct_pack_le(65535, 4))  # snaplen
            f.write(struct_pack_le(LINKTYPE_CAN_SOCKETCAN, 4))  # network
            # Pack frames
            for frame in self._can_frames:
                ts_sec = int(frame.timestamp)
                ts_usec = int((frame.timestamp - ts_sec) * 1_000_000)
                # Linux SocketCAN frame: struct can_frame { can_id: u32, can_dlc: u8, __pad: [3], data: [8] }
                data = frame.data[:8]
                data = data + b"\x00" * (8 - len(data))
                can_frame_bytes = struct_pack_le(frame.can_id, 4) + bytes([len(frame.data)]) + b"\x00\x00\x00" + data
                incl_len = len(can_frame_bytes)
                orig_len = incl_len
                f.write(struct_pack_le(ts_sec, 4))
                f.write(struct_pack_le(ts_usec, 4))
                f.write(struct_pack_le(incl_len, 4))
                f.write(struct_pack_le(orig_len, 4))
                f.write(can_frame_bytes)

    def _write_uds_transcript(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            for e in self._uds_entries:
                f.write(json.dumps({
                    "timestamp": e.timestamp,
                    "direction": e.direction,
                    "target_id": e.target_id,
                    "service": e.service,
                    "subfunction": e.subfunction,
                    "payload": e.payload,
                    "response_code": e.response_code,
                    "success": e.success,
                    "note": e.note,
                }) + "\n")

    def export_bundle(
        self,
        output_dir: str,
        bundle_name: Optional[str] = None,
        signing_key: Optional[bytes] = None,
        hashlog_path: Optional[str] = None,
        meta: Optional[Dict] = None,
    ) -> Dict[str, str]:
        """
        Export signed evidence bundle containing:
         - CAN PCAP
         - UDS transcript
         - manifest.json (metadata, file hashes)
         - signature.json (HMAC over each file)
        Also appends to hash log (append-only) with chain.
        Returns dict of file paths.
        """
        os.makedirs(output_dir, exist_ok=True)
        bundle_name = bundle_name or f"canary_bundle_{int(time.time())}"
        bundle_dir = os.path.join(output_dir, bundle_name)
        os.makedirs(bundle_dir, exist_ok=True)

        pcap_path = os.path.join(bundle_dir, "capture.pcap")
        uds_path = os.path.join(bundle_dir, "uds.jsonl")
        manifest_path = os.path.join(bundle_dir, "manifest.json")
        sig_path = os.path.join(bundle_dir, "signature.json")

        self._write_pcap(pcap_path)
        self._write_uds_transcript(uds_path)

        # Build manifest
        manifest = {
            "tool": "CANary Lab",
            "category": "iot",
            "version": "1.0",
            "time_utc": int(time.time()),
            "time_source": "system",
            "files": {},
            "events": [se_to_dict(e) for e in self._events],
            "findings": [finding_to_dict(fx) for fx in self._findings],
            "meta": meta or {},
        }
        # Hash files
        files_to_hash = {
            "capture.pcap": pcap_path,
            "uds.jsonl": uds_path,
        }
        for name, path in files_to_hash.items():
            manifest["files"][name] = {
                "sha256": sha256_file(path),
                "size": os.path.getsize(path)
            }
        # Write manifest first (unsigned)
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2, sort_keys=True)
        manifest_hash = sha256_file(manifest_path)

        # Signatures (HMAC-SHA256)
        sigs = {
            "algorithm": "HMAC-SHA256",
            "key_id": "operator-provided" if signing_key else "unsigned",
            "signatures": {}
        }
        if signing_key:
            for name, path in {**files_to_hash, "manifest.json": manifest_path}.items():
                sigs["signatures"][name] = hmac_sha256(signing_key, read_file_bytes(path))
        else:
            sigs["signatures"] = {}
        with open(sig_path, "w", encoding="utf-8") as sf:
            json.dump(sigs, sf, indent=2, sort_keys=True)

        # Append-only hash log
        hashlog_path = hashlog_path or os.path.join(output_dir, "evidence_hashlog.txt")
        prev = read_last_hash_from_log(hashlog_path)
        current = sha256_hex((prev or "").encode("utf-8") + manifest_hash.encode("utf-8"))
        append_hash_log(hashlog_path, prev, manifest_hash, current, bundle_name)

        # Update manifest with chain info and rewrite
        manifest["hash_chain"] = {
            "prev": prev,
            "current": current,
            "manifest_sha256": manifest_hash
        }
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2, sort_keys=True)

        return {
            "bundle_dir": bundle_dir,
            "pcap": pcap_path,
            "uds": uds_path,
            "manifest": manifest_path,
            "signature": sig_path,
            "hashlog": hashlog_path,
        }


# ---------------------------
# Helpers
# ---------------------------

def se_to_dict(e: SafetyEvent) -> Dict:
    return {
        "timestamp": e.timestamp,
        "event_type": e.event_type,
        "details": e.details
    }

def finding_to_dict(fx: Finding) -> Dict:
    return {
        "timestamp": fx.timestamp,
        "title": fx.title,
        "severity": fx.severity,
        "details": fx.details
    }

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def struct_pack_le(value: int, size: int) -> bytes:
    # size can be 2 or 4
    if size == 2:
        return value.to_bytes(2, "little", signed=False)
    elif size == 4:
        return value.to_bytes(4, "little", signed=False)
    else:
        raise ValueError("Unsupported size for struct pack")

def read_last_hash_from_log(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    prev = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            prev = line.split("|")[-1].strip()  # current hash at end
    return prev

def append_hash_log(path: str, prev: Optional[str], manifest_hash: str, current: str, bundle_name: str):
    line = f"{int(time.time())}|{bundle_name}|prev={prev or 'None'}|manifest={manifest_hash}|{current}\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)

def verify_hash_chain(path: str) -> bool:
    """
    Recompute chain to ensure correctness: H_i = SHA256(H_{i-1} || manifest_hash_i)
    """
    if not os.path.exists(path):
        return True
    prev = ""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.strip().split("|")
            if len(parts) < 5:
                return False
            manifest_hash_part = parts[-2]
            current = parts[-1]
            if not manifest_hash_part.startswith("manifest="):
                return False
            manifest_hash = manifest_hash_part.split("=", 1)[1]
            expected = sha256_hex(prev.encode("utf-8") + manifest_hash.encode("utf-8"))
            if expected != current:
                return False
            prev = current
    return True


# ---------------------------
# CANary Lab Orchestrator
# ---------------------------

class CANaryLab:
    def __init__(
        self,
        safety: SafetyPolicy,
        recorder: EvidenceRecorder,
        transport: LocalUDSTransport,
        rate: Optional[RateController] = None,
    ):
        self.safety = safety
        self.recorder = recorder
        self.transport = transport
        self.rate = rate or RateController()
        self.active_mode = False
        self._stop_event = threading.Event()
        self._sniff_thread: Optional[threading.Thread] = None
        self.session_state: Dict[int, Dict[str, bool]] = {}  # by ECU id: session, unlocked

    def start_passive_sniff(self):
        self.active_mode = False
        # In local transport, no background frames to sniff; placeholder thread for extensibility
        if self._sniff_thread and self._sniff_thread.is_alive():
            return
        self._stop_event.clear()
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()

    def _sniff_loop(self):
        # Placeholder: sleep and periodically check for stop
        while not self._stop_event.is_set():
            time.sleep(0.1)

    def stop(self):
        self._stop_event.set()
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2.0)
        self.active_mode = False

    def check_and_enforce_safety(self) -> bool:
        ok, event = self.safety.check_dynamic_safety()
        if not ok:
            if event:
                self.recorder.emit_event(event)
            # rollback to passive sniffing
            self.active_mode = False
            return False
        return True

    def read_vin(self, ecu_id: int) -> Optional[str]:
        try:
            # 0x22 F190
            req = bytes([0x22, 0xF1, 0x90])
            resp = self.transport.send_request(req)
            if len(resp) >= 3 and resp[0] == 0x62 and resp[1] == 0xF1 and resp[2] == 0x90:
                vin = resp[3:].decode("ascii", errors="ignore")
                return vin
        except Exception as e:
            self.recorder.emit_event(SafetyEvent(timestamp=time.time(), event_type="error", details={"read_vin": str(e)}))
        return None

    def read_dtcs(self, ecu_id: int) -> List[str]:
        # Simplified DTC request for simulation (0x19)
        try:
            req = bytes([0x19, 0x02])  # "report dtc by status mask" simplified
            resp = self.transport.send_request(req)
            if len(resp) >= 2 and resp[0] == 0x59:
                # simplistic parse for simulated ECU: bytes beyond first are CSV ASCII
                if len(resp) > 2:
                    try:
                        dtc_csv = resp[2:].decode("ascii")
                        if dtc_csv:
                            return [s for s in dtc_csv.split(",") if s]
                    except Exception:
                        return []
                return []
        except Exception as e:
            self.recorder.emit_event(SafetyEvent(timestamp=time.time(), event_type="error", details={"read_dtcs": str(e)}))
        return []

    def is_critical_dtc(self, dtc: str) -> bool:
        # crude heuristic: P = powertrain, C = chassis (ABS), B = body (airbags sometimes), U = network
        return dtc.startswith(("P0", "C0", "B0"))

    def enforce_dtc_failsafe(self, ecu_id: int) -> bool:
        dtcs = self.read_dtcs(ecu_id)
        if any(self.is_critical_dtc(d) for d in dtcs):
            self.recorder.emit_event(SafetyEvent(
                timestamp=time.time(),
                event_type="critical_dtc_detected",
                details={"dtcs": ",".join(dtcs)}
            ))
            self.active_mode = False
            return False
        return True

    def probe_security(self, ecu_id: int) -> Optional[Finding]:
        # Requires operator confirmation for risky services
        if not self.safety.confirm_risky(0x27, ecu_id):
            self.recorder.emit_event(SafetyEvent(
                timestamp=time.time(),
                event_type="operator_denied",
                details={"service": "0x27", "ecu_id": f"0x{ecu_id:X}"}
            ))
            return None

        # Request seed
        if not self.check_and_enforce_safety():
            return None
        resp = self.transport.send_request(bytes([0x27, 0x01]))
        if len(resp) < 2 or resp[0] != 0x67 or resp[1] != 0x01:
            return None
        if not self.check_and_enforce_safety():
            return None
        if not self.enforce_dtc_failsafe(ecu_id):
            return None

        seed = 0
        if len(resp) >= 6:
            seed = int.from_bytes(resp[2:6], "big")

        # Try known weak algorithms
        weak_algos = {
            "SEED_PLUS_ONE": lambda s: (s + 1) & 0xFFFFFFFF,
            "SEED_XOR_FF": lambda s: s ^ 0xFFFFFFFF
        }
        for name, algo in weak_algos.items():
            if not self.check_and_enforce_safety():
                return None
            key = algo(seed)
            key_bytes = key.to_bytes(4, "big")
            resp2 = self.transport.send_request(bytes([0x27, 0x02]) + key_bytes)
            if len(resp2) >= 2 and resp2[0] == 0x67 and resp2[1] == 0x02:
                finding = Finding(
                    timestamp=time.time(),
                    title="Unsecured UDS SecurityAccess",
                    severity="high",
                    details={
                        "ecu_id": f"0x{ecu_id:X}",
                        "algorithm": name,
                        "seed": f"0x{seed:08X}",
                        "key": f"0x{key:08X}"
                    }
                )
                self.recorder.add_finding(finding)
                return finding
        return None

    def enter_extended_session(self, ecu_id: int) -> bool:
        # Safe service 0x10
        if not self.check_and_enforce_safety():
            return False
        resp = self.transport.send_request(bytes([0x10, 0x03]))
        ok = len(resp) >= 2 and resp[0] == 0x50 and resp[1] == 0x03
        return ok

    def active_probe_cycle(self, ecu_id: int, vin: Optional[str]) -> None:
        if not self.safety.check_static_allowlist(vin, ecu_id):
            self.recorder.emit_event(SafetyEvent(timestamp=time.time(), event_type="static_policy_block", details={"vin": vin or "unknown", "ecu_id": f"0x{ecu_id:X}"}))
            return
        # Ensure extended session
        if not self.enter_extended_session(ecu_id):
            self.recorder.emit_event(SafetyEvent(timestamp=time.time(), event_type="session_control_failed", details={"ecu_id": f"0x{ecu_id:X}"}))
            return
        # Probe security
        self.probe_security(ecu_id)
        # Optionally try ECU reset (risky)
        if self.safety.confirm_risky(0x11, ecu_id):
            if self.check_and_enforce_safety() and self.enforce_dtc_failsafe(ecu_id):
                self.transport.send_request(bytes([0x11, 0x01]))  # hard reset
        else:
            self.recorder.emit_event(SafetyEvent(timestamp=time.time(), event_type="operator_denied", details={"service": "0x11"}))

    def run_active_probing(self, ecu_id: int, duration_sec: float = 5.0):
        self.active_mode = True
        start = time.time()
        vin = self.read_vin(ecu_id)
        while time.time() - start < duration_sec and self.active_mode:
            if not self.check_and_enforce_safety():
                # switched to passive due to safety event
                break
            if not self.enforce_dtc_failsafe(ecu_id):
                break
            self.active_probe_cycle(ecu_id, vin)
            # small rest between cycles
            time.sleep(0.2)
        # switch to passive
        self.active_mode = False

    def export_evidence_bundle(self, output_dir: str, signing_key: Optional[bytes] = None, bundle_name: Optional[str] = None, meta: Optional[Dict] = None) -> Dict[str, str]:
        return self.recorder.export_bundle(output_dir=output_dir, signing_key=signing_key, bundle_name=bundle_name, meta=meta)


# ---------------------------
# Verification Utilities
# ---------------------------

def verify_evidence_bundle(bundle_dir: str, signing_key: Optional[bytes] = None, hashlog_path: Optional[str] = None) -> bool:
    """
    Verify that:
      - signature.json HMAC matches files (if signing_key provided)
      - manifest contains hashes matching files
      - hash chain is consistent in hashlog
    """
    manifest_path = os.path.join(bundle_dir, "manifest.json")
    sig_path = os.path.join(bundle_dir, "signature.json")
    if not (os.path.exists(manifest_path) and os.path.exists(sig_path)):
        return False
    with open(manifest_path, "r", encoding="utf-8") as mf:
        manifest = json.load(mf)
    with open(sig_path, "r", encoding="utf-8") as sf:
        sigs = json.load(sf)

    # Check file hashes
    for name, info in manifest.get("files", {}).items():
        path = os.path.join(bundle_dir, name)
        if not os.path.exists(path):
            return False
        if sha256_file(path) != info.get("sha256"):
            return False

    # Check signature HMACs if key provided
    if signing_key:
        sig_map = sigs.get("signatures", {})
        # include manifest.json too
        files = list(manifest.get("files", {}).keys()) + ["manifest.json"]
        for name in files:
            path = os.path.join(bundle_dir, name)
            expected = sig_map.get(name)
            if expected is None:
                return False
            actual = hmac_sha256(signing_key, read_file_bytes(path))
            if actual != expected:
                return False

    # Verify hash chain
    # get current chain values from manifest
    chain = manifest.get("hash_chain", {})
    current = chain.get("current")
    prev = chain.get("prev") or ""
    manifest_hash = chain.get("manifest_sha256")
    if current != sha256_hex(prev.encode("utf-8") + (manifest_hash or "").encode("utf-8")):
        return False
    # verify append-only log consistency
    hl = hashlog_path or os.path.join(os.path.dirname(bundle_dir), "evidence_hashlog.txt")
    if not verify_hash_chain(hl):
        return False

    return True


# ---------------------------
# Minimal CLI / Demonstration
# ---------------------------

def default_operator_confirm(prompt: str, target_id: int) -> bool:
    # In automated environments, default to False to ensure safety
    # Override with a function returning True for testing on safe benches.
    print(f"[CONFIRMATION REQUIRED] {prompt} to ECU 0x{target_id:X}. Denying by default.")
    return False


def build_simulated_lab(
    allow_vin: str = "TESTVIN123456789",
    allow_ecu: int = 0x7E0,
    speed_threshold_kph: float = 0.1,
    operator_auto_approve: bool = False,
    weak_algo: str = "SEED_PLUS_ONE"
) -> Tuple[CANaryLab, SimulatedECU]:
    # Speed provider can be swapped in tests
    current_speed = {"val": 0.0}

    def speed_provider():
        return current_speed["val"]

    def rpm_provider():
        return 0

    def operator_confirm(_service: str, _target: int) -> bool:
        return operator_auto_approve

    safety = SafetyPolicy(
        speed_threshold_kph=speed_threshold_kph,
        rpm_threshold=0,
        allowlist_vins=[allow_vin],
        allowlist_ecus=[allow_ecu],
        operator_confirm=operator_confirm,
        speed_provider=speed_provider,
        rpm_provider=rpm_provider,
    )
    recorder = EvidenceRecorder()
    ecu = SimulatedECU(ecu_id=allow_ecu, resp_id=0x7E8, vin=allow_vin, weak_algo=weak_algo)
    transport = LocalUDSTransport(ecu=ecu, recorder=recorder, rate=RateController(inter_frame_gap_ms=2.0, max_frames_per_sec=200))
    lab = CANaryLab(safety=safety, recorder=recorder, transport=transport, rate=RateController(inter_frame_gap_ms=2.0, max_frames_per_sec=200))
    # expose a means to change speed in tests
    lab._sim_speed_ref = current_speed
    return lab, ecu


if __name__ == "__main__":
    print("CANary Lab - Authorized testing only. Use on test benches or with OEM permission.")
    lab, ecu = build_simulated_lab(operator_auto_approve=False)
    lab.start_passive_sniff()
    print("Reading VIN in passive mode...")
    vin = lab.read_vin(ecu.ecu_id)
    print(f"Detected VIN: {vin}")
    print("Attempting active probing (will require operator confirmation for risky services)...")
    lab.run_active_probing(ecu_id=ecu.ecu_id, duration_sec=2.0)
    out = os.path.abspath("./canary_output")
    key_env = os.environ.get("CANARY_SIGN_KEY")
    key = key_env.encode("utf-8") if key_env else None
    files = lab.export_evidence_bundle(output_dir=out, signing_key=key, meta={"vin": vin or "unknown"})
    print(f"Evidence bundle written to: {files['bundle_dir']}")
    ok = verify_evidence_bundle(files["bundle_dir"], signing_key=key, hashlog_path=files["hashlog"])
    print(f"Evidence verification: {'OK' if ok else 'FAILED'}")