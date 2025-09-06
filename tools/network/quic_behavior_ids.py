import argparse
import base64
import gzip
import hmac
import hashlib
import json
import os
import queue
import signal
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional, Tuple

# Ethical notice
ETHICAL_NOTICE = (
    "WARNING: This tool inspects network metadata and is intended ONLY for authorized defensive testing "
    "and monitoring within environments where you have explicit permission. Unauthorized monitoring may be illegal. "
    "The tool avoids payload decryption and focuses on privacy-preserving metadata analysis. Use responsibly."
)

# Simple logger
def log(msg: str, level: str = "INFO"):
    ts = datetime.utcnow().isoformat() + "Z"
    sys.stderr.write(f"{ts} [{level}] {msg}\n")
    sys.stderr.flush()


def hexdump(b: bytes, length: int = 32) -> str:
    return b[:length].hex()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def salted_hash(value: str, salt: str, truncate: int = 32) -> str:
    h = hashlib.sha256()
    h.update(salt.encode("utf-8"))
    h.update(value.encode("utf-8"))
    return h.hexdigest()[:truncate]


def now_ts() -> float:
    return time.time()


def entropy_bitstream(bits: List[int]) -> float:
    if not bits:
        return 0.0
    ones = sum(bits)
    zeros = len(bits) - ones
    if ones == 0 or zeros == 0:
        return 0.0
    p1 = ones / len(bits)
    p0 = 1.0 - p1
    # Shannon entropy normalized to [0,1] since binary entropy max is 1 (in bits)
    import math

    return -(p0 * math.log2(p0) + p1 * math.log2(p1))


class TokenBucket:
    def __init__(self, rate_per_sec: int, burst: Optional[int] = None):
        self.rate = max(1, rate_per_sec)
        self.capacity = burst if burst is not None else self.rate
        self.tokens = float(self.capacity)
        self.last = now_ts()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            now = now_ts()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


class SIEMExporter(threading.Thread):
    def __init__(self, endpoint: str, api_key: Optional[str], q: "queue.Queue[str]", batch_size: int = 50,
                 max_interval: float = 2.0, timeout: float = 5.0):
        super().__init__(daemon=True)
        self.endpoint = endpoint
        self.api_key = api_key
        self.q = q
        self.batch_size = batch_size
        self.max_interval = max_interval
        self.timeout = timeout
        self._stop = threading.Event()
        self.backoff = 1.0
        self.max_backoff = 30.0

    def stop(self):
        self._stop.set()

    def run(self):
        import urllib.request
        import urllib.error

        buf: List[str] = []
        last_send = now_ts()
        while not self._stop.is_set():
            try:
                try:
                    item = self.q.get(timeout=0.25)
                    buf.append(item)
                except queue.Empty:
                    pass
                if buf and (len(buf) >= self.batch_size or (now_ts() - last_send) >= self.max_interval):
                    payload = "[" + ",".join(buf) + "]"
                    gz = gzip.compress(payload.encode("utf-8"))
                    req = urllib.request.Request(self.endpoint, data=gz, method="POST")
                    req.add_header("Content-Type", "application/json")
                    req.add_header("Content-Encoding", "gzip")
                    if self.api_key:
                        req.add_header("Authorization", f"Bearer {self.api_key}")
                    try:
                        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                            if resp.status >= 200 and resp.status < 300:
                                # success
                                buf.clear()
                                last_send = now_ts()
                                self.backoff = 1.0
                            else:
                                log(f"SIEM exporter HTTP {resp.status}, backing off", "WARN")
                                time.sleep(self.backoff)
                                self.backoff = min(self.max_backoff, self.backoff * 2)
                    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
                        log(f"SIEM export failed: {e}, backing off {self.backoff}s", "WARN")
                        time.sleep(self.backoff)
                        self.backoff = min(self.max_backoff, self.backoff * 2)
                else:
                    time.sleep(0.05)
            except Exception as e:
                log(f"Exporter error: {e}", "ERROR")
                time.sleep(1.0)


class BaselineModel:
    """
    Simple streaming baseline of features with anomaly scoring.
    Maintains per-feature mean and variance (Welford) and computes z-score distance.
    """
    def __init__(self, features: List[str], warmup_flows: int = 500, threshold: float = 6.0,
                 version: str = "1.0", signature: Optional[str] = None):
        self.features = features
        self.count = 0
        self.means: Dict[str, float] = {f: 0.0 for f in features}
        self.M2: Dict[str, float] = {f: 0.0 for f in features}
        self.warmup_flows = warmup_flows
        self.threshold = threshold
        self.version = version
        self.signature = signature or "insecure-dev"
        self.lock = threading.Lock()

    def verify_signature(self, secret: Optional[str]) -> bool:
        if not secret:
            log("No model signing secret provided; using insecure default. For production, configure a signing key.", "WARN")
            return True
        msg = json.dumps({"version": self.version, "features": self.features, "threshold": self.threshold}, sort_keys=True).encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, self.signature):
            log("Model signature verification failed.", "ERROR")
            return False
        return True

    def update(self, fv: Dict[str, float]):
        with self.lock:
            self.count += 1
            for f in self.features:
                x = float(fv.get(f, 0.0))
                delta = x - self.means[f]
                self.means[f] += delta / self.count
                delta2 = x - self.means[f]
                self.M2[f] += delta * delta2

    def ready(self) -> bool:
        return self.count >= self.warmup_flows

    def score(self, fv: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        with self.lock:
            contributions: Dict[str, float] = {}
            total = 0.0
            for f in self.features:
                x = float(fv.get(f, 0.0))
                if self.count < 2:
                    z = 0.0
                else:
                    var = (self.M2[f] / (self.count - 1)) if (self.count > 1) else 0.0
                    std = (var ** 0.5) if var > 1e-12 else 1e-6
                    z = abs((x - self.means[f]) / std)
                contributions[f] = z
                total += z
            return total, contributions


class RuleEngine:
    def __init__(self, version: str = "1.0", signature: Optional[str] = None):
        self.version = version
        self.signature = signature or "insecure-dev"
        self.rare_threshold = 0.01
        self.spin_entropy_low = 0.15
        self.spin_entropy_high = 0.85
        # frequencies
        self.fp_counts: Dict[str, int] = defaultdict(int)
        self.total_fps = 0
        self.lock = threading.Lock()

    def verify_signature(self, secret: Optional[str]) -> bool:
        if not secret:
            log("No rules signing secret provided; using insecure default. For production, configure a signing key.", "WARN")
            return True
        msg = json.dumps({"version": self.version, "rare_threshold": self.rare_threshold}, sort_keys=True).encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, self.signature):
            log("Rules signature verification failed.", "ERROR")
            return False
        return True

    def observe_fp(self, fp: str):
        with self.lock:
            self.fp_counts[fp] += 1
            self.total_fps += 1

    def fp_frequency(self, fp: str) -> float:
        with self.lock:
            if self.total_fps == 0:
                return 1.0
            return self.fp_counts.get(fp, 0) / max(1, self.total_fps)

    def evaluate(self, features: Dict[str, Any]) -> Tuple[bool, float, List[str]]:
        # Returns rule_hit, rule_score, reasons
        reasons = []
        score = 0.0
        hit = False
        fp = features.get("ja4q") or features.get("ja4") or "unknown"
        freq = self.fp_frequency(fp)
        if freq < self.rare_threshold:
            hit = True
            score += 1.5
            reasons.append(f"rare_fingerprint:{fp}")
        spin = features.get("spin_entropy", 0.0)
        if spin < self.spin_entropy_low or spin > self.spin_entropy_high:
            hit = True
            score += 1.5
            reasons.append("abnormal_spin_entropy")
        return hit, score, reasons


class FlowState:
    def __init__(self):
        self.first_seen: float = now_ts()
        self.last_seen: float = self.first_seen
        self.packets: int = 0
        self.bytes: int = 0
        self.sizes: List[int] = []
        self.arrival: List[float] = []
        self.last_ts: Optional[float] = None
        self.spin_bits: List[int] = []
        self.ja4: Optional[str] = None
        self.ja4s: Optional[str] = None
        self.ja4q: Optional[str] = None
        self.sni_hash: Optional[str] = None
        self.alpn_hash: Optional[str] = None

    def update(self, length: int, ts: float, spin_bit: Optional[int] = None):
        self.packets += 1
        self.bytes += length
        self.sizes.append(length)
        if self.last_ts is not None:
            self.arrival.append(ts - self.last_ts)
        self.last_ts = ts
        self.last_seen = ts
        if spin_bit is not None:
            self.spin_bits.append(1 if spin_bit else 0)

    def summarize(self) -> Dict[str, float]:
        import math

        size_mean = sum(self.sizes) / len(self.sizes) if self.sizes else 0.0
        size_std = (sum((x - size_mean) ** 2 for x in self.sizes) / len(self.sizes)) ** 0.5 if self.sizes else 0.0
        ia_mean = sum(self.arrival) / len(self.arrival) if self.arrival else 0.0
        ia_std = (sum((x - ia_mean) ** 2 for x in self.arrival) / len(self.arrival)) ** 0.5 if self.arrival else 0.0
        spin_ent = entropy_bitstream(self.spin_bits)
        return {
            "size_mean": size_mean,
            "size_std": size_std,
            "interarrival_mean": ia_mean,
            "interarrival_std": ia_std,
            "spin_entropy": spin_ent,
        }


class QuicTlsBehaviorIDS:
    def __init__(self, interface: str, siem_endpoint: Optional[str], siem_api_key: Optional[str],
                 hash_salt: str, retention_seconds: int = 3600, budget_pps: int = 5000,
                 warmup_flows: int = 500, model_secret: Optional[str] = None, rules_secret: Optional[str] = None):
        self.interface = interface
        self.siem_endpoint = siem_endpoint
        self.siem_api_key = siem_api_key
        self.hash_salt = hash_salt
        self.retention_seconds = retention_seconds
        self.bucket = TokenBucket(rate_per_sec=budget_pps, burst=budget_pps)
        self.model = BaselineModel(features=["size_mean", "interarrival_mean", "spin_entropy"],
                                   warmup_flows=warmup_flows, version="1.0")
        self.rules = RuleEngine(version="1.0")
        self.model.verify_signature(model_secret)
        self.rules.verify_signature(rules_secret)
        self.flows: Dict[Tuple, FlowState] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.siem_queue: "queue.Queue[str]" = queue.Queue(maxsize=5000)
        self.exporter: Optional[SIEMExporter] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.stats = {"dropped_events": 0, "queue_full": 0, "processed_packets": 0, "skipped_packets": 0}

    def start(self):
        log(ETHICAL_NOTICE, "WARN")
        if self.siem_endpoint:
            self.exporter = SIEMExporter(self.siem_endpoint, self.siem_api_key, self.siem_queue)
            self.exporter.start()
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        # housekeeping thread
        threading.Thread(target=self._housekeeping_loop, daemon=True).start()

    def stop(self):
        self.stop_event.set()
        if self.exporter:
            self.exporter.stop()
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)

    def _housekeeping_loop(self):
        while not self.stop_event.is_set():
            try:
                self._purge_old_flows()
                time.sleep(5.0)
            except Exception as e:
                log(f"Housekeeping error: {e}", "ERROR")
                time.sleep(1.0)

    def _purge_old_flows(self):
        expiration = now_ts() - self.retention_seconds
        with self.lock:
            keys = [k for k, f in self.flows.items() if f.last_seen < expiration]
            for k in keys:
                del self.flows[k]

    def _attach_cbpf_filter(self, sock: socket.socket):
        # Attach classic BPF filter to capture only IPv4 TCP/UDP port 443
        # This filter ignores VLAN/IPv6 for simplicity.
        # BPF program assembled manually.
        # Registers and semantics based on classic cBPF.
        BPF_LD = 0x00
        BPF_LDX = 0x01
        BPF_ST = 0x02
        BPF_STX = 0x03
        BPF_ALU = 0x04
        BPF_JMP = 0x05
        BPF_RET = 0x06
        BPF_MISC = 0x07

        BPF_W = 0x00
        BPF_H = 0x08
        BPF_B = 0x10

        BPF_IMM = 0x00
        BPF_ABS = 0x20
        BPF_IND = 0x40
        BPF_MEM = 0x60
        BPF_LEN = 0x80
        BPF_MSH = 0xa0

        BPF_ADD = 0x00
        BPF_SUB = 0x10
        BPF_MUL = 0x20
        BPF_DIV = 0x30
        BPF_OR = 0x40
        BPF_AND = 0x50
        BPF_LSH = 0x60
        BPF_RSH = 0x70
        BPF_NEG = 0x80
        BPF_MOD = 0x90
        BPF_XOR = 0xa0

        BPF_JA = 0x00
        BPF_JEQ = 0x10
        BPF_JGT = 0x20
        BPF_JGE = 0x30
        BPF_JSET = 0x40

        BPF_TAX = 0x00
        BPF_TXA = 0x80

        def ins(code, jt, jf, k):
            return struct.pack("HBBI", code, jt, jf, k)

        prog = []
        # 0: A = ldh [12] EtherType
        prog.append(ins(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12))
        # 1: if A == 0x0800 (IPv4) jump to 2 else reject
        prog.append(ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 9, 0x0800))
        # 2: A = ldb [23] protocol
        prog.append(ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23))
        # 3: if A == 6 (TCP) jump to TCP handling (next) else jump to UDP check
        prog.append(ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 6))
        # TCP path:
        # 4: A = ldb [14] IHL
        prog.append(ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 14))
        # 5: A = A & 0x0f
        prog.append(ins(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0F))
        # 6: A = A << 2
        prog.append(ins(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 2))
        # 7: X = A
        prog.append(ins(BPF_MISC | BPF_TAX, 0, 0, 0))
        # 8: A = ldh [x + 14 + 2] dest port
        prog.append(ins(BPF_LD | BPF_H | BPF_IND, 0, 0, 14 + 2))
        # 9: if A == 443 accept else go to UDP path check
        prog.append(ins(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 443))
        # jump 4 means skip next 4 instructions to accept
        # UDP path:
        # 10: A = ldb [23] protocol (re-load)
        prog.append(ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23))
        # 11: if A == 17 (UDP) continue else reject
        prog.append(ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 17))
        # 12: A = ldb [14] IHL
        prog.append(ins(BPF_LD | BPF_B | BPF_ABS, 0, 0, 14))
        # 13: A = A & 0x0f
        prog.append(ins(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0F))
        # 14: A = A << 2
        prog.append(ins(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 2))
        # 15: X = A
        prog.append(ins(BPF_MISC | BPF_TAX, 0, 0, 0))
        # 16: A = ldh [x + 14 + 2] dest port
        prog.append(ins(BPF_LD | BPF_H | BPF_IND, 0, 0, 14 + 2))
        # 17: if A == 443 accept else reject
        prog.append(ins(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 443))
        # 18: reject
        prog.append(ins(BPF_RET | BPF_K, 0, 0, 0))
        # 19: accept
        prog.append(ins(BPF_RET | BPF_K, 0, 0, 0xFFFF))

        b = b"".join(prog)
        fprog = struct.pack("HL", len(prog), struct.addressof(ctypes.create_string_buffer(b)))
        # The above is not portable; better pack using sock_fprog structure manually:
        # But Python can't pass pointer to kernel easily; Instead use SOL_SOCKET, SO_ATTACH_FILTER with array.
        # Workaround: Use 'struct sock_fprog' with pointer as bytes using PACKET_AUX (not possible).
        # Simpler approach: use SO_ATTACH_FILTER with the raw program bytes after len; but Python needs CTypes.
        # We'll use ctypes properly:
        import ctypes

        class sock_filter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_ushort),
                        ("jt", ctypes.c_ubyte),
                        ("jf", ctypes.c_ubyte),
                        ("k", ctypes.c_uint32)]

        class sock_fprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort),
                        ("filter", ctypes.POINTER(sock_filter))]

        arr = (sock_filter * len(prog))()
        # Rebuild using our program list:
        # Re-parse our packed instructions to fill arr
        off = 0
        for i in range(len(prog)):
            code, jt, jf, k = struct.unpack_from("HBBI", b, off)
            arr[i].code = code
            arr[i].jt = jt
            arr[i].jf = jf
            arr[i].k = k
            off += struct.calcsize("HBBI")
        fprog2 = sock_fprog()
        fprog2.len = len(prog)
        fprog2.filter = ctypes.cast(arr, ctypes.POINTER(sock_filter))
        SO_ATTACH_FILTER = 26
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, ctypes.string_at(ctypes.addressof(fprog2), ctypes.sizeof(fprog2)))
            log("Attached classic BPF filter (verified by kernel).", "INFO")
        except Exception as e:
            log(f"Failed to attach BPF filter (continuing without kernel filter): {e}", "WARN")

    def _capture_loop(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            sock.bind((self.interface, 0))
            # Try to attach cBPF filter
            try:
                self._attach_cbpf_filter(sock)
            except Exception as e:
                log(f"BPF attach error: {e}", "WARN")
        except PermissionError as e:
            log("Permission denied opening raw socket. Run as root with CAP_NET_RAW.", "ERROR")
            return
        except Exception as e:
            log(f"Socket open error: {e}", "ERROR")
            return

        while not self.stop_event.is_set():
            try:
                pkt, sa_ll = sock.recvfrom(65535)
                ts = now_ts()
                self.stats["processed_packets"] += 1
                if not self.bucket.allow():
                    self.stats["skipped_packets"] += 1
                    continue
                self._process_packet(pkt, ts)
            except BlockingIOError:
                time.sleep(0.001)
            except Exception as e:
                log(f"Capture error: {e}", "ERROR")
                time.sleep(0.01)

    def _process_packet(self, pkt: bytes, ts: float):
        # Parse Ethernet
        if len(pkt) < 14:
            return
        eth_proto = struct.unpack("!H", pkt[12:14])[0]
        off = 14
        if eth_proto == 0x8100 and len(pkt) >= 18:
            # VLAN
            eth_proto = struct.unpack("!H", pkt[16:18])[0]
            off = 18
        if eth_proto == 0x0800:
            # IPv4
            if len(pkt) < off + 20:
                return
            iphdr = pkt[off:off + 20]
            ver_ihl = iphdr[0]
            ihl = (ver_ihl & 0x0F) * 4
            if len(pkt) < off + ihl:
                return
            proto = iphdr[9]
            src_ip = socket.inet_ntoa(iphdr[12:16])
            dst_ip = socket.inet_ntoa(iphdr[16:20])
            nhoff = off + ihl
            if proto == 6:  # TCP
                if len(pkt) < nhoff + 20:
                    return
                sport, dport = struct.unpack("!HH", pkt[nhoff:nhoff + 4])
                # Only process port 443 flows
                if sport != 443 and dport != 443:
                    return
                data_offset = ((pkt[nhoff + 12] >> 4) & 0xF) * 4
                app_off = nhoff + data_offset
                app_data = pkt[app_off:]
                self._handle_flow(ip_version=4, proto="TCP", src_ip=src_ip, dst_ip=dst_ip, sport=sport, dport=dport,
                                  payload=app_data, ts=ts, length=len(pkt))
            elif proto == 17:  # UDP (QUIC)
                if len(pkt) < nhoff + 8:
                    return
                sport, dport, ulen = struct.unpack("!HHH", pkt[nhoff:nhoff + 6])
                if sport != 443 and dport != 443:
                    return
                app_off = nhoff + 8
                app_data = pkt[app_off:]
                self._handle_quic_flow(src_ip=src_ip, dst_ip=dst_ip, sport=sport, dport=dport,
                                       payload=app_data, ts=ts, length=len(pkt))
        # For brevity, IPv6 is not parsed in this minimal implementation

    def _flow_key(self, ip_version: int, proto: str, src_ip: str, dst_ip: str, sport: int, dport: int) -> Tuple:
        # Anonymize IPs
        src_h = salted_hash(src_ip, self.hash_salt)
        dst_h = salted_hash(dst_ip, self.hash_salt)
        return (ip_version, proto, src_h, dst_h, sport, dport)

    def _handle_flow(self, ip_version: int, proto: str, src_ip: str, dst_ip: str, sport: int, dport: int,
                     payload: bytes, ts: float, length: int):
        key = self._flow_key(ip_version, proto, src_ip, dst_ip, sport, dport)
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = FlowState()
                self.flows[key] = flow
        flow.update(length=length, ts=ts, spin_bit=None)
        # Parse TLS ClientHello for JA4/ALPN/SNI
        try:
            if payload:
                self._parse_tls(payload, flow, client=(sport > 1024 and dport == 443))
        except Exception:
            pass
        # Evaluate detections maybe on flow end; here we evaluate continuously when enough packets
        self._evaluate_and_emit(key, flow, proto="TLS")

    def _handle_quic_flow(self, src_ip: str, dst_ip: str, sport: int, dport: int,
                          payload: bytes, ts: float, length: int):
        key = self._flow_key(4, "UDP", src_ip, dst_ip, sport, dport)
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = FlowState()
                self.flows[key] = flow
        spin = self._parse_quic(payload, flow)
        flow.update(length=length, ts=ts, spin_bit=spin)
        self._evaluate_and_emit(key, flow, proto="QUIC")

    def _parse_quic(self, data: bytes, flow: FlowState) -> Optional[int]:
        # QUIC header parse (minimal). Spin bit observed on short header; for simplicity,
        # treat bit 0x20 of first byte as spin bit in short header.
        if not data:
            return None
        fb = data[0]
        long_header = (fb & 0x80) != 0
        if long_header:
            if len(data) < 6:
                return None
            version = struct.unpack("!I", data[1:5])[0]
            # parse DCID/SCID lengths
            pos = 5
            dcid_len = data[pos]
            pos += 1
            if len(data) < pos + dcid_len + 1:
                return None
            dcid = data[pos:pos + dcid_len]
            pos += dcid_len
            scid_len = data[pos]
            pos += 1
            if len(data) < pos + scid_len:
                return None
            scid = data[pos:pos + scid_len]
            # Build a ja4q-style fingerprint
            flow.ja4q = f"qv{version:08x}_d{dcid_len:02d}s{scid_len:02d}"
            # Observe freq for rules
            self.rules.observe_fp(flow.ja4q)
            return None
        else:
            # short header
            spin_bit = 1 if (fb & 0x20) != 0 else 0
            # No JA4Q change
            return spin_bit

    def _parse_tls(self, data: bytes, flow: FlowState, client: bool):
        # Minimal TLS record parse for ClientHello/ServerHello metadata in plaintext handshake (TCP TLS)
        # TLS record header is 5 bytes: type(1), version(2), length(2)
        pos = 0
        while pos + 5 <= len(data):
            rec_type = data[pos]
            pos += 1
            rec_ver = data[pos:pos + 2]
            pos += 2
            rec_len = struct.unpack("!H", data[pos:pos + 2])[0]
            pos += 2
            if pos + rec_len > len(data):
                break
            rec_body = data[pos:pos + rec_len]
            pos += rec_len
            if rec_type != 22:  # handshake
                continue
            # Handshake header: type(1), length(3)
            if len(rec_body) < 4:
                continue
            hs_type = rec_body[0]
            hs_len = int.from_bytes(rec_body[1:4], "big")
            if 4 + hs_len > len(rec_body):
                continue
            hs = rec_body[4:4 + hs_len]
            if hs_type == 1 and client:
                # ClientHello
                ch = hs
                if len(ch) < 34:
                    continue
                legacy_version = struct.unpack("!H", ch[0:2])[0]
                idx = 2 + 32  # skip random
                if idx >= len(ch):
                    continue
                sid_len = ch[idx]
                idx += 1 + sid_len
                if idx + 2 > len(ch):
                    continue
                cs_len = struct.unpack("!H", ch[idx:idx + 2])[0]
                idx += 2
                ciphers = ch[idx:idx + cs_len]
                idx += cs_len
                if idx >= len(ch):
                    continue
                comp_methods_len = ch[idx]
                idx += 1 + comp_methods_len
                extensions = []
                sni = None
                alpn_list: List[str] = []
                if idx + 2 <= len(ch):
                    ext_total = struct.unpack("!H", ch[idx:idx + 2])[0]
                    idx += 2
                    end = idx + ext_total
                    while idx + 4 <= len(ch) and idx < end:
                        etype = struct.unpack("!H", ch[idx:idx + 2])[0]
                        elen = struct.unpack("!H", ch[idx + 2:idx + 4])[0]
                        idx += 4
                        eval_bytes = ch[idx:idx + elen]
                        idx += elen
                        extensions.append(etype)
                        if etype == 0:  # SNI
                            # SNI extension: list len(2), type(1), name len(2), name
                            if len(eval_bytes) >= 5:
                                l = struct.unpack("!H", eval_bytes[0:2])[0]
                                p = 2
                                if p + 3 <= len(eval_bytes):
                                    name_type = eval_bytes[p]
                                    name_len = struct.unpack("!H", eval_bytes[p + 1:p + 3])[0]
                                    p += 3
                                    if p + name_len <= len(eval_bytes):
                                        sni = eval_bytes[p:p + name_len].decode(errors="ignore")
                        elif etype == 16:  # ALPN
                            # length(2), then list of protocols: len(1), proto
                            if len(eval_bytes) >= 2:
                                l = struct.unpack("!H", eval_bytes[0:2])[0]
                                p = 2
                                while p < 2 + l and p < len(eval_bytes):
                                    if p >= len(eval_bytes):
                                        break
                                    l2 = eval_bytes[p]
                                    p += 1
                                    if p + l2 <= len(eval_bytes):
                                        alpn = eval_bytes[p:p + l2].decode(errors="ignore")
                                        alpn_list.append(alpn)
                                        p += l2
                # Build simplified JA4-like fingerprint: t<ver>c<cs_count>e<ext_count>a<alpn_count>
                ja4 = f"t{legacy_version:04x}c{len(ciphers):04d}e{len(extensions):03d}a{len(alpn_list):02d}"
                flow.ja4 = ja4
                if sni:
                    flow.sni_hash = salted_hash(sni.lower(), self.hash_salt)
                if alpn_list:
                    flow.alpn_hash = salted_hash(",".join(alpn_list), self.hash_salt)
                self.rules.observe_fp(ja4)
            elif hs_type == 2 and not client:
                # ServerHello (optional JA4S)
                sh = hs
                if len(sh) >= 2:
                    srv_version = struct.unpack("!H", sh[0:2])[0]
                    flow.ja4s = f"s{srv_version:04x}"

    def _evaluate_and_emit(self, key: Tuple, flow: FlowState, proto: str):
        # Build feature vector
        features = flow.summarize()
        # Add fingerprint attributes
        if proto == "QUIC":
            if flow.ja4q:
                features["ja4q"] = flow.ja4q
        else:
            if flow.ja4:
                features["ja4"] = flow.ja4
            if flow.ja4s:
                features["ja4s"] = flow.ja4s
        # Rule evaluation
        rule_hit, rule_score, reasons = self.rules.evaluate(features)
        # ML model update/score
        if not self.model.ready():
            self.model.update(features)
            return
        score, contrib = self.model.score(features)
        # Compose confidence: sigmoid-ish
        confidence = min(1.0, (score / self.model.threshold) * 0.7 + (rule_score / 3.0) * 0.3)
        severity = "low"
        if confidence > 0.8:
            severity = "high"
        elif confidence > 0.5:
            severity = "medium"
        # Trigger alert based on combined conditions
        trigger = False
        reasons_all = list(reasons)
        if rule_hit and score >= self.model.threshold * 0.75:
            trigger = True
            reasons_all.append("ml_anomaly_high")
        elif rule_hit and rule_score >= 1.5 and (features.get("ja4q") or features.get("ja4")):
            trigger = True
        elif score >= self.model.threshold * 1.25:
            trigger = True
            reasons_all.append("ml_anomaly_severe")

        if trigger:
            # Build event
            src_h = key[2]
            dst_h = key[3]
            sport = key[4]
            dport = key[5]
            event = {
                "event_type": "alert",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "category": "network",
                "subsystem": "quic_tls_behavior_ids",
                "alert": {
                    "severity": severity,
                    "confidence": round(confidence, 3),
                    "reason": ", ".join(sorted(set(reasons_all))),
                    "features": {
                        "spin_entropy": round(features.get("spin_entropy", 0.0), 4),
                        "size_mean": round(features.get("size_mean", 0.0), 3),
                        "interarrival_mean": round(features.get("interarrival_mean", 0.0), 6),
                        "alpn_hash": flow.alpn_hash,
                        "sni_hash": flow.sni_hash,
                    },
                    "fingerprints": {
                        "ja4": flow.ja4,
                        "ja4s": flow.ja4s,
                        "ja4q": flow.ja4q,
                    },
                    "ml": {
                        "model_version": self.model.version,
                        "score": round(score, 3),
                        "threshold": self.model.threshold,
                        "contributions": {k: round(v, 3) for k, v in contrib.items()},
                    },
                    "rules": {
                        "version": self.rules.version,
                    },
                },
                "network": {
                    "proto": proto,
                    "src_hash": src_h,
                    "dst_hash": dst_h,
                    "sport": sport,
                    "dport": dport,
                    "packets": flow.packets,
                    "bytes": flow.bytes,
                },
                "privacy": {
                    "pii_hashed": True,
                    "hash_algo": "sha256",
                    "salted": True,
                },
                "retention": {
                    "ttl_seconds": self.retention_seconds
                }
            }
            self._emit_event(event)

    def _emit_event(self, event: Dict[str, Any]):
        s = json.dumps(event, separators=(",", ":"), sort_keys=False)
        if self.siem_endpoint:
            try:
                self.siem_queue.put_nowait(s)
            except queue.Full:
                self.stats["queue_full"] += 1
                # drop oldest to make space
                try:
                    _ = self.siem_queue.get_nowait()
                    self.siem_queue.put_nowait(s)
                except Exception:
                    self.stats["dropped_events"] += 1
        else:
            # fallback to stdout
            print(s, flush=True)


def parse_args():
    ap = argparse.ArgumentParser(description="QUIC/TLS Encrypted Traffic Behavioral IDS (privacy-preserving)")
    ap.add_argument("--interface", "-i", required=True, help="Network interface to monitor (AF_PACKET)")
    ap.add_argument("--siem-endpoint", help="HTTP endpoint to POST JSON alerts (gzip).")
    ap.add_argument("--siem-api-key", help="Bearer token for SIEM.")
    ap.add_argument("--hash-salt", default=os.environ.get("IDS_HASH_SALT", "change-me"), help="Salt for hashing PII.")
    ap.add_argument("--retention-seconds", type=int, default=3600, help="Data retention TTL for flows.")
    ap.add_argument("--budget-pps", type=int, default=5000, help="Max packets per second to process (token bucket).")
    ap.add_argument("--warmup-flows", type=int, default=500, help="Number of flows for unsupervised warm-up.")
    ap.add_argument("--model-secret", help="HMAC secret to verify model signature.")
    ap.add_argument("--rules-secret", help="HMAC secret to verify rules signature.")
    ap.add_argument("--run-seconds", type=int, default=0, help="If >0, run for this many seconds then exit.")
    return ap.parse_args()


def main():
    args = parse_args()

    ids = QuicTlsBehaviorIDS(
        interface=args.interface,
        siem_endpoint=args.siem_endpoint,
        siem_api_key=args.siem_api_key,
        hash_salt=args.hash_salt,
        retention_seconds=args.retention_seconds,
        budget_pps=args.budget_pps,
        warmup_flows=args.warmup_flows,
        model_secret=args.model_secret,
        rules_secret=args.rules_secret,
    )

    stop_flag = {"stop": False}

    def handle_sig(signum, frame):
        stop_flag["stop"] = True
        ids.stop()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    ids.start()
    start = now_ts()
    try:
        while not stop_flag["stop"]:
            time.sleep(0.5)
            if args.run_seconds > 0 and (now_ts() - start) >= args.run_seconds:
                break
    finally:
        ids.stop()
        log("Shutting down.", "INFO")


if __name__ == "__main__":
    main()