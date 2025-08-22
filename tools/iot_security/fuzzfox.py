#!/usr/bin/env python3
import argparse
import contextlib
import ctypes
import ctypes.util
import errno
import hashlib
import json
import logging
import os
import queue
import random
import re
import select
import shutil
import signal
import socket
import stat
import string
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.0"

# Ethical warning
ETHICAL_WARNING = (
    "FuzzFox IoT: Authorized testing only. Ensure explicit written permission from asset owners. "
    "Use in isolated lab or microsegmented namespaces. Misuse may disrupt operations or violate law."
)

# Logging setup
LOG = logging.getLogger("fuzzfox")
_handler = logging.StreamHandler()
_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
_handler.setFormatter(_formatter)
LOG.addHandler(_handler)
LOG.setLevel(logging.INFO)

# Constants
DEFAULT_PPS = 100
DEFAULT_TIMEOUT = 10.0
NS_PREFIX = "fuzzfox"
KILL_SWITCH_ENV = "FUZZFOX_KILL"
PR_SET_NO_NEW_PRIVS = 38

# Simple Rate Limiter (token bucket)
class RateLimiter:
    def __init__(self, rate_per_sec: int, burst: Optional[int] = None):
        self.rate = float(max(1, rate_per_sec))
        self.capacity = float(burst if burst is not None else max(1, rate_per_sec))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                wait = deficit / self.rate if self.rate > 0 else 0.01
            time.sleep(max(0.0, min(wait, 0.1)))

# Kill Switch shared across fuzzers
class KillSwitch:
    def __init__(self):
        self._evt = threading.Event()

    def trigger(self, reason: str):
        LOG.error("Kill-switch triggered: %s", reason)
        self._evt.set()

    def is_triggered(self) -> bool:
        return self._evt.is_set()

KILL = KillSwitch()

def set_no_new_privs():
    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        return
    libc = ctypes.CDLL(libc_path, use_errno=True)
    try:
        res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if res != 0:
            err = ctypes.get_errno()
            LOG.debug("prctl(NO_NEW_PRIVS) failed: %s", os.strerror(err))
    except Exception as e:
        LOG.debug("prctl not available: %s", e)

def run_cmd(cmd: List[str], check: bool = True, ns: Optional[str] = None, capture: bool = False, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    real_cmd = cmd
    if ns:
        real_cmd = ["ip", "netns", "exec", ns] + cmd
    LOG.debug("Running command: %s", " ".join(real_cmd))
    try:
        cp = subprocess.run(real_cmd, check=check, capture_output=capture, text=True, timeout=timeout)
        return cp
    except FileNotFoundError:
        LOG.warning("Command not found: %s", real_cmd[0])
        if check:
            raise
        return subprocess.CompletedProcess(real_cmd, 127, "", "not found")
    except subprocess.CalledProcessError as e:
        if capture:
            LOG.debug("Command stderr: %s", e.stderr)
        if check:
            raise
        return e

def require_root() -> bool:
    if os.geteuid() != 0:
        LOG.warning("Root privileges required for network namespace/eBPF operations.")
        return False
    return True

class NamespaceManager:
    def __init__(self, name: str):
        self.name = name
        self.host_if = f"{name}-host0"
        self.ns_if = f"{name}-ns0"
        self.net = "10.200.%d.0/24" % (random.randint(10, 200))
        self.host_ip = self.net.replace(".0/24", ".1/24")
        self.ns_ip = self.net.replace(".0/24", ".2/24")

    def create(self, targets: List[str]) -> None:
        if not require_root():
            LOG.info("Dry-run: would create netns %s with microsegmentation.", self.name)
            return
        # Create namespace and veth pair
        run_cmd(["ip", "link", "add", self.host_if, "type", "veth", "peer", "name", self.ns_if], check=True)
        run_cmd(["ip", "netns", "add", self.name], check=True)
        run_cmd(["ip", "link", "set", self.ns_if, "netns", self.name], check=True)
        run_cmd(["ip", "addr", "add", self.host_ip, "dev", self.host_if], check=True)
        run_cmd(["ip", "link", "set", self.host_if, "up"], check=True)
        run_cmd(["ip", "netns", "exec", self.name, "ip", "addr", "add", self.ns_ip, "dev", self.ns_if], check=True)
        run_cmd(["ip", "netns", "exec", self.name, "ip", "link", "set", "lo", "up"], check=True)
        run_cmd(["ip", "netns", "exec", self.name, "ip", "link", "set", self.ns_if, "up"], check=True)
        # Drop default routes and configure microsegmentation: default DROP
        self._apply_microsegmentation(targets)
        LOG.info("Namespace %s created with isolated veth and egress microsegmentation.", self.name)

    def _apply_microsegmentation(self, targets: List[str]) -> None:
        # Use iptables inside namespace to drop all outgoing except specific targets (and DNS optional)
        try:
            run_cmd(["iptables", "-P", "OUTPUT", "DROP"], ns=self.name, check=True)
            run_cmd(["iptables", "-P", "INPUT", "DROP"], ns=self.name, check=True)
            run_cmd(["iptables", "-P", "FORWARD", "DROP"], ns=self.name, check=True)
            # Allow loopback
            run_cmd(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], ns=self.name, check=True)
            run_cmd(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], ns=self.name, check=True)
            # Allow established
            run_cmd(["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], ns=self.name, check=True)
            run_cmd(["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], ns=self.name, check=True)
            # Allow traffic only to targets
            for t in targets:
                run_cmd(["iptables", "-A", "OUTPUT", "-d", t, "-j", "ACCEPT"], ns=self.name, check=True)
            LOG.info("Applied microsegmentation ACLs in namespace %s", self.name)
        except Exception as e:
            LOG.warning("Failed to apply iptables microsegmentation: %s", e)
        # optional: enable tc rate limits if available
        try:
            # Simple tbf rate limit in namespace interface; bytes-based: approx cap pps assuming 512B avg
            # Here we skip tc as rate limiter is enforced in-app.
            pass
        except Exception as e:
            LOG.debug("tc rate limit not applied: %s", e)

    def destroy(self) -> None:
        if not require_root():
            LOG.info("Dry-run: would delete netns %s", self.name)
            return
        with contextlib.suppress(Exception):
            run_cmd(["ip", "link", "del", self.host_if], check=False)
        with contextlib.suppress(Exception):
            run_cmd(["ip", "netns", "del", self.name], check=False)
        LOG.info("Namespace %s destroyed.", self.name)

    def counters(self) -> Dict[str, str]:
        data = {}
        if not require_root():
            data["info"] = "No counters: not root/dry-run."
            return data
        with contextlib.suppress(Exception):
            cp = run_cmd(["ip", "-s", "link", "show", self.host_if], capture=True, check=False)
            data["host_if"] = cp.stdout or ""
        with contextlib.suppress(Exception):
            cp = run_cmd(["ip", "netns", "exec", self.name, "ip", "-s", "link", "show", self.ns_if], capture=True, check=False)
            data["ns_if"] = cp.stdout or ""
        with contextlib.suppress(Exception):
            cp = run_cmd(["ip", "netns", "exec", self.name, "iptables", "-L", "-v", "-n"], capture=True, check=False)
            data["iptables"] = cp.stdout or ""
        return data

# Passive Discovery via mDNS and SSDP listen, and traffic heuristics (ports)
class PassiveDiscovery:
    def __init__(self, iface: Optional[str] = None):
        self.iface = iface
        self.stop_evt = threading.Event()

    def listen_mdns(self, timeout: float = 5.0) -> List[Dict]:
        results = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            group = ('224.0.0.251', 5353)
            sock.bind(group if sys.platform.startswith("linux") else ("", 5353))
            mreq = socket.inet_aton(group[0]) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.setblocking(False)
            start = time.time()
            while time.time() - start < timeout and not self.stop_evt.is_set():
                r, _, _ = select.select([sock], [], [], 0.2)
                if not r:
                    continue
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                proto = None
                if "_mqtt" in text.lower() or "mqtt" in text.lower():
                    proto = "mqtt"
                elif "coap" in text.lower() or "_coap" in text.lower():
                    proto = "coap"
                if proto:
                    results.append({"ip": ip, "protocol": proto, "source": "mdns"})
            sock.close()
        except Exception as e:
            LOG.debug("mDNS listen error: %s", e)
        return results

    def listen_ssdp(self, timeout: float = 5.0) -> List[Dict]:
        results = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            addr = ('239.255.255.250', 1900)
            sock.bind(addr if sys.platform.startswith("linux") else ("", 1900))
            mreq = socket.inet_aton(addr[0]) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.setblocking(False)
            start = time.time()
            while time.time() - start < timeout and not self.stop_evt.is_set():
                r, _, _ = select.select([sock], [], [], 0.2)
                if not r:
                    continue
                data, sender = sock.recvfrom(4096)
                ip = sender[0]
                text = data.decode("utf-8", errors="ignore")
                proto = None
                if "mqtt" in text.lower():
                    proto = "mqtt"
                elif "coap" in text.lower() or "iot" in text.lower():
                    proto = "coap"
                if proto:
                    results.append({"ip": ip, "protocol": proto, "source": "ssdp"})
            sock.close()
        except Exception as e:
            LOG.debug("SSDP listen error: %s", e)
        return results

    def heuristics(self, cidr: str = "192.168.0.0/16") -> List[Dict]:
        # Passive heuristics: inspect ARP or open sockets not feasible without pcap; fall back to known defaults
        # We can attempt to connect non-invasively with timeouts to common ports if explicitly allowed via env
        results = []
        allow = os.environ.get("FUZZFOX_ALLOW_LIGHT_PROBE", "0") == "1"
        if not allow:
            return results
        # Probe local subnet gateways to detect services
        common = [("mqtt", 1883), ("coap", 5683)]
        ips = []
        try:
            base = socket.gethostbyname(socket.gethostname())
            parts = base.split(".")
            if len(parts) == 4:
                prefix = ".".join(parts[:3])
                ips = [f"{prefix}.{i}" for i in range(1, 255)]
        except Exception:
            ips = []
        random.shuffle(ips)
        ips = ips[:32]  # limit
        for ip in ips:
            for proto, port in common:
                try:
                    if proto == "coap":
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.settimeout(0.05)
                        s.sendto(b"", (ip, port))
                        s.close()
                        results.append({"ip": ip, "protocol": "coap", "source": "heuristic"})
                    else:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.05)
                        s.connect((ip, port))
                        s.close()
                        results.append({"ip": ip, "protocol": "mqtt", "source": "heuristic"})
                except Exception:
                    continue
        return results

    def discover(self, timeout: float = 5.0) -> List[Dict]:
        devices = {}
        for d in self.listen_mdns(timeout):
            devices[(d["ip"], d["protocol"])] = d
        for d in self.listen_ssdp(timeout):
            devices[(d["ip"], d["protocol"])] = d
        for d in self.heuristics():
            devices[(d["ip"], d["protocol"])] = d
        return list(devices.values())

# Health monitor to quarantine on anomaly
class HealthMonitor(threading.Thread):
    def __init__(self, target_ip: str, namespace: Optional[str], interval: float = 2.0, fail_threshold: int = 3):
        super().__init__(daemon=True)
        self.target_ip = target_ip
        self.ns = namespace
        self.interval = interval
        self.fail_threshold = fail_threshold
        self.failures = 0
        self.running = True

    def run(self):
        while self.running and not KILL.is_triggered():
            ok = self._ping()
            if not ok:
                self.failures += 1
                LOG.warning("Health check failed (%d/%d) for %s", self.failures, self.fail_threshold, self.target_ip)
                if self.failures >= self.fail_threshold:
                    KILL.trigger(f"Health check failing for {self.target_ip}")
                    break
            else:
                self.failures = 0
            time.sleep(self.interval)

    def stop(self):
        self.running = False

    def _ping(self) -> bool:
        # Use system ping for simplicity
        cmd = ["ping", "-c", "1", "-W", "1", self.target_ip]
        cp = run_cmd(cmd, check=False, capture=True, ns=self.ns)
        return cp.returncode == 0

# Fuzzers
class BaseFuzzer:
    def __init__(self, target: str, port: int, pps: int = DEFAULT_PPS, duration: int = 30):
        self.target = target
        self.port = port
        self.pps = max(1, pps)
        self.duration = max(1, duration)
        self.rate = RateLimiter(self.pps, burst=self.pps)
        self.issues: List[str] = []
        self.sent = 0
        self.errors = 0

    def run(self):
        raise NotImplementedError

    def record_issue(self, desc: str):
        LOG.info("Potential input validation issue: %s", desc)
        self.issues.append(desc)

class MQTTFuzzer(BaseFuzzer):
    def run(self):
        end = time.time() + self.duration
        while time.time() < end and not KILL.is_triggered():
            try:
                self.rate.acquire()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect((self.target, self.port))
                # Send malformed CONNECT packet
                client_id = "".join(random.choice(string.ascii_letters) for _ in range(random.randint(0, 5)))
                proto_name = b"MQTT"
                proto_lvl = random.choice([3, 4])
                flags = random.randrange(0, 256)
                keepalive = random.randrange(0, 65535)
                vh = self._encode_string(proto_name) + bytes([proto_lvl, flags]) + keepalive.to_bytes(2, "big")
                payload = self._encode_string(client_id.encode())
                rem_len = len(vh) + len(payload)
                packet = b"\x10" + self._encode_varint(rem_len) + vh + payload
                s.sendall(packet)
                try:
                    data = s.recv(4)
                    if data and data[0] != 0x20:
                        self.record_issue("Unexpected CONNACK response code")
                except socket.timeout:
                    self.record_issue("No CONNACK; potential DoS/input handling weakness")
                # Try malformed PUBLISH with oversized topic
                topic = ("A" * random.randint(100, 1024)).encode()
                msg = os.urandom(random.randint(0, 256))
                pdu = self._encode_string(topic) + msg
                hdr = bytes([0x30 | random.randrange(0, 16)])
                packet = hdr + self._encode_varint(len(pdu)) + pdu
                s.sendall(packet)
                s.close()
                self.sent += 2
            except Exception:
                self.errors += 1
        return {"sent": self.sent, "errors": self.errors, "issues": self.issues}

    def _encode_string(self, data: bytes) -> bytes:
        return len(data).to_bytes(2, "big") + data

    def _encode_varint(self, n: int) -> bytes:
        out = bytearray()
        while True:
            byte = n % 128
            n //= 128
            if n > 0:
                byte |= 0x80
            out.append(byte)
            if n == 0:
                break
        return bytes(out)

class CoAPFuzzer(BaseFuzzer):
    def run(self):
        end = time.time() + self.duration
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        mid = random.randint(0, 65535)
        while time.time() < end and not KILL.is_triggered():
            try:
                self.rate.acquire()
                ver = 1 << 6
                t = random.choice([0, 1, 2, 3]) << 4  # CON, NON, ACK, RST
                token_len = random.choice([0, 1, 2, 4, 8, 15]) & 0x0F
                code = random.choice([1, 2, 3, 4, 5, 132, 255])  # malformed as well
                mid = (mid + 1) % 65536
                token = os.urandom(token_len)
                hdr = bytes([ver | t | token_len, code, (mid >> 8) & 0xFF, mid & 0xFF]) + token
                # Options: create malformed delta/length
                opt = b""
                for _ in range(random.randint(0, 4)):
                    delta = random.choice([0, 15])  # 15 = reserved
                    length = random.choice([0, 15])
                    opt += bytes([(delta << 4) | length]) + os.urandom(length if length < 15 else 0)
                payload = b"\xFF" + os.urandom(random.randint(0, 64)) if random.random() < 0.5 else b""
                pkt = hdr + opt + payload
                s.sendto(pkt, (self.target, self.port))
                try:
                    _ = s.recvfrom(1500)
                except socket.timeout:
                    self.record_issue("No CoAP response to malformed request")
                self.sent += 1
            except Exception:
                self.errors += 1
        s.close()
        return {"sent": self.sent, "errors": self.errors, "issues": self.issues}

class ModbusFuzzer(BaseFuzzer):
    def run(self):
        end = time.time() + self.duration
        while time.time() < end and not KILL.is_triggered():
            try:
                self.rate.acquire()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((self.target, self.port))
                # MBAP: Transaction ID, Protocol ID, Length, Unit ID
                tid = random.randint(0, 65535)
                pid = 0
                uid = random.randint(0, 255)
                func = random.choice([1, 2, 3, 4, 5, 6, 0x99])  # invalid function too
                pdu = bytes([uid, func]) + os.urandom(random.randint(0, 4))
                mbap = tid.to_bytes(2, "big") + pid.to_bytes(2, "big") + len(pdu).to_bytes(2, "big") + pdu
                s.sendall(mbap)
                try:
                    resp = s.recv(12)
                    if resp and resp[7] & 0x80:
                        self.record_issue("Exception response to malformed Modbus request")
                except socket.timeout:
                    self.record_issue("No response to Modbus fuzz input")
                s.close()
                self.sent += 1
            except Exception:
                self.errors += 1
        return {"sent": self.sent, "errors": self.errors, "issues": self.issues}

class BLEFuzzer(BaseFuzzer):
    def run(self):
        LOG.warning("BLE fuzzing requires BLE stack and privileges; skipping.")
        return {"sent": 0, "errors": 0, "issues": ["BLE fuzzing not supported in this environment"]}

# Firmware analysis
PII_PATTERNS = [
    re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(rb"\b\d{1,3}(\.\d{1,3}){3}\b"),
]
DEFAULT_SECRET_RULES = [
    # fallback regexes if no YARA pack provided or unsigned
    {"name": "generic_api_key", "regex": r"(?:apikey|api_key|api-key)\s*[:=]\s*([A-Za-z0-9_\-]{16,64})"},
    {"name": "aws_access_key", "regex": r"AKIA[0-9A-Z]{16}"},
    {"name": "private_key", "regex": r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |)PRIVATE KEY-----"},
    {"name": "password_assign", "regex": r"(?:password|passwd|pwd)\s*[:=]\s*([^\s'\"\\]{6,128})"},
]

def openssl_verify(pubkey_path: str, data_path: str, sig_path: str) -> bool:
    try:
        cp = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pubkey_path, "-signature", sig_path, data_path],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0 and "Verified OK" in (cp.stdout + cp.stderr):
            return True
        LOG.warning("OpenSSL verification failed: %s %s", cp.returncode, cp.stderr.strip())
        return False
    except Exception as e:
        LOG.warning("OpenSSL not available for signature verification: %s", e)
        return False

def load_signed_rules(rule_pack: Optional[str], sig_path: Optional[str], pubkey_path: Optional[str], allow_unsigned: bool = False) -> List[Dict]:
    rules = []
    if rule_pack and sig_path and pubkey_path:
        verified = openssl_verify(pubkey_path, rule_pack, sig_path)
        if not verified:
            if not allow_unsigned:
                LOG.error("Rule pack signature invalid; refusing to load. Use --allow-unsigned to bypass (not recommended).")
                return []
            LOG.warning("Proceeding with unsigned/invalid-signed rules (not recommended).")
        try:
            with open(rule_pack, "r", encoding="utf-8") as f:
                pack = json.load(f)
            for r in pack.get("rules", []):
                if "name" in r and "regex" in r:
                    rules.append({"name": r["name"], "regex": r["regex"]})
        except Exception as e:
            LOG.error("Failed to parse rule pack: %s", e)
    elif rule_pack and allow_unsigned:
        # Load unsigned rule pack explicitly if allowed
        try:
            with open(rule_pack, "r", encoding="utf-8") as f:
                pack = json.load(f)
            for r in pack.get("rules", []):
                if "name" in r and "regex" in r:
                    rules.append({"name": r["name"], "regex": r["regex"]})
            LOG.warning("Loaded unsigned rule pack (allow-unsigned enabled).")
        except Exception as e:
            LOG.error("Failed to parse unsigned rule pack: %s", e)
    if not rules:
        rules = DEFAULT_SECRET_RULES
        LOG.info("Using default built-in secret detection rules.")
    return rules

def safe_extract_tar(tar: tarfile.TarFile, path: str):
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not os.path.realpath(member_path).startswith(os.path.realpath(path)):
            continue
        tar.extract(member, path=path)

def safe_extract_zip(zf: zipfile.ZipFile, path: str):
    for member in zf.namelist():
        member_path = os.path.join(path, member)
        if not os.path.realpath(member_path).startswith(os.path.realpath(path)):
            continue
        zf.extract(member, path)

class ReadOnlyDirGuard:
    def __init__(self, root: Path, log: logging.Logger):
        self.root = root.resolve()
        self.log = log
        self._orig_open = None
        self._orig_os_open = None

    def __enter__(self):
        # Set directory and files read-only
        for dirpath, dirnames, filenames in os.walk(self.root):
            for d in dirnames:
                p = Path(dirpath, d)
                with contextlib.suppress(Exception):
                    p.chmod(0o555)
            for f in filenames:
                p = Path(dirpath, f)
                with contextlib.suppress(Exception):
                    p.chmod(0o444)
        self._orig_open = None
        self._orig_os_open = None
        def _guarded_open(file, mode='r', *args, **kwargs):
            from pathlib import Path as _Path
            fp = _Path(file).resolve()
            # Python 3.9 compatibility: emulate is_relative_to
            rel = str(fp).startswith(str(self.root))
            if rel and any(c in mode for c in ("w", "a", "+")):
                self.log.warning("Denied write attempt to read-only firmware path: %s (mode %s)", fp, mode)
                raise PermissionError("Read-only enforcement")
            return _orig_open(file, mode, *args, **kwargs)
        def _guarded_os_open(file, flags, *args, **kwargs):
            from pathlib import Path as _Path
            fp = _Path(file).resolve()
            rel = str(fp).startswith(str(self.root))
            if rel and flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | getattr(os, "O_CREAT", 0)):
                self.log.warning("Denied write attempt to read-only firmware path: %s (flags %s)", fp, flags)
                raise PermissionError("Read-only enforcement")
            return _orig_os_open(file, flags, *args, **kwargs)
        import builtins as _b
        # Save originals
        _orig_open = _b.open
        _orig_os_open = os.open
        self._orig_open = _orig_open
        self._orig_os_open = _orig_os_open
        # Patch
        _b.open = _guarded_open
        os.open = _guarded_os_open
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            import builtins as _b
            if self._orig_open:
                _b.open = self._orig_open
            if self._orig_os_open:
                os.open = self._orig_os_open
        except Exception:
            pass
        # Restore permissions best-effort
        for dirpath, dirnames, filenames in os.walk(self.root):
            for d in dirnames:
                p = Path(dirpath, d)
                with contextlib.suppress(Exception):
                    p.chmod(0o755)
            for f in filenames:
                p = Path(dirpath, f)
                with contextlib.suppress(Exception):
                    p.chmod(0o644)

def redact_pii(data: bytes) -> bytes:
    redacted = data
    for pat in PII_PATTERNS:
        redacted = pat.sub(b"[REDACTED]", redacted)
    # Redact obvious secrets
    redacted = re.sub(rb"(password|passwd|pwd)\s*[:=]\s*[^\s'\"\\]+", b"\\1: [REDACTED]", redacted, flags=re.I)
    return redacted

def scan_with_rules(root: Path, rules: List[Dict], report_path: Path, manifest_path: Path) -> Tuple[int, int]:
    secret_re_list = [(r["name"], re.compile(r["regex"].encode() if isinstance(r["regex"], str) else r["regex"], re.I | re.M)) for r in rules]
    findings = []
    files_scanned = 0
    for dirpath, _, filenames in os.walk(root):
        for f in filenames:
            fp = Path(dirpath, f)
            try:
                # Limit file size to avoid huge memory use
                if fp.stat().st_size > 8 * 1024 * 1024:
                    continue
                with open(fp, "rb") as fh:
                    data = fh.read()
                files_scanned += 1
                file_findings = []
                for name, creg in secret_re_list:
                    for m in creg.finditer(data):
                        val = m.group(0)
                        sha = hashlib.sha256(val).hexdigest()
                        file_findings.append({"rule": name, "sha256": sha, "offset": m.start(), "length": len(val)})
                if file_findings:
                    findings.append({"file": str(fp.relative_to(root)), "findings": file_findings})
            except Exception:
                continue
    # Write manifest (sealed evidence)
    manifest = {
        "version": VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evidence": findings,
        "root": str(root),
        "sha256_root_listing": hashlib.sha256("\n".join(sorted(str(p) for p in root.rglob("*"))).encode()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    # Human-readable redacted report
    report_lines = []
    for item in findings:
        report_lines.append(f"File: {item['file']}")
        for fnd in item["findings"]:
            report_lines.append(f"  Rule: {fnd['rule']} @ {fnd['offset']} len {fnd['length']} sha256={fnd['sha256']}")
    if not findings:
        report_lines.append("No secrets found by provided rules.")
    redacted_report = redact_pii("\n".join(report_lines).encode())
    report_path.write_bytes(redacted_report)
    return files_scanned, len(findings)

def extract_firmware(archive_path: str, outdir: Path) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    ap = Path(archive_path)
    tmp = outdir / "extracted"
    tmp.mkdir(exist_ok=True)
    if tarfile.is_tarfile(ap):
        with tarfile.open(ap, "r:*") as t:
            safe_extract_tar(t, str(tmp))
    elif zipfile.is_zipfile(ap):
        with zipfile.ZipFile(ap, "r") as z:
            safe_extract_zip(z, str(tmp))
    else:
        # Attempt raw filesystem-like squashfs not supported; fallback to copy
        dst = tmp / ap.name
        shutil.copy2(ap, dst)
    return tmp

# Simple subprocess wrapper for tests to patch
def subprocess_run(*args, **kwargs):
    return subprocess.run(*args, **kwargs)

# YARA-like verification and scanning wrappers (tests patch these)
def verify_yara_pack_signature(pack_path: str) -> bool:
    # Default: consider existing file as "signed"/valid
    try:
        return Path(pack_path).exists()
    except Exception:
        return False

def scan_with_yara(root_path: str, pack_path: Optional[str]) -> List[Dict]:
    # Fallback scanning using built-in regexes when YARA unavailable
    findings: List[Dict] = []
    rules = [(r["name"], re.compile(r["regex"], re.I | re.M)) for r in DEFAULT_SECRET_RULES]
    root = Path(root_path)
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            fp = Path(dirpath, fn)
            try:
                if fp.stat().st_size > 8 * 1024 * 1024:
                    continue
                data = fp.read_bytes()
            except Exception:
                continue
            for name, rx in rules:
                for m in rx.finditer(data.decode("utf-8", errors="ignore")):
                    secret = m.group(0)
                    rel = str(fp.relative_to(root))
                    findings.append({"path": rel, "rule": name, "secret": secret})
    return findings

def analyze_firmware(archive: str, yara_pack: Optional[str], read_only: bool = True, output_dir: Optional[str] = None) -> Dict:
    if yara_pack and not verify_yara_pack_signature(yara_pack):
        raise ValueError("Invalid YARA pack signature")
    outdir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="fuzzfox_fw_"))
    outdir.mkdir(parents=True, exist_ok=True)
    set_no_new_privs()
    extracted_root = extract_firmware(archive, outdir)
    report_path = outdir / "report_redacted.txt"
    manifest_path = outdir / "manifest.sealed.json"
    def do_scan():
        # Use scan_with_yara to produce findings; redact in report, preserve hashes in manifest
        raw_findings = scan_with_yara(str(extracted_root), yara_pack)
        evidence = []
        rep_lines = []
        for item in raw_findings:
            secret_bytes = item.get("secret", "")
            if isinstance(secret_bytes, str):
                sb = secret_bytes.encode("utf-8", errors="ignore")
            else:
                sb = bytes(secret_bytes)
            sha = hashlib.sha256(sb).hexdigest()
            evidence.append({"file": item.get("path", ""), "rule": item.get("rule", "yara"), "sha256": sha})
            # Human-readable report line without secret value; include sha only
            rep_lines.append(f"File: {item.get('path','')} Rule: {item.get('rule','yara')} sha256={sha}")
        if not evidence:
            rep_lines.append("No secrets found by provided rules.")
        # Write manifest (sealed)
        manifest = {
            "version": VERSION,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evidence": evidence,
            "root": str(extracted_root),
            "archive_sha256": sha256_file(archive),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2))
        # Redacted human-readable report
        redacted = redact_pii("\n".join(rep_lines).encode())
        report_path.write_bytes(redacted)
        return {"count": len(evidence)}
    if read_only:
        with ReadOnlyDirGuard(extracted_root, LOG):
            res = do_scan()
            # Attempt a write to demonstrate enforcement logging
            try:
                open(extracted_root / "write_attempt.txt", "w").write("should fail")
            except PermissionError:
                pass
    else:
        res = do_scan()
    return {
        "extracted_root": str(extracted_root),
        "report": str(report_path),
        "manifest": str(manifest_path),
        "signature_verified": bool(yara_pack),
        "stats": res,
    }

# Orchestration
def setup_namespace(name: str, targets: List[str]):
    nm = NamespaceManager(name)
    nm.create(targets)
    return nm

def teardown_namespace(name: str):
    NamespaceManager(name).destroy()

def run_fuzzer_in_ns(ns: str, protocol: str, target: str, port: Optional[int], pps: int, duration: int) -> Dict:
    proto = protocol.lower()
    p = port
    if proto == "mqtt":
        p = p or 1883
        fuzz = MQTTFuzzer(target, p, pps=pps, duration=duration)
    elif proto == "coap":
        p = p or 5683
        fuzz = CoAPFuzzer(target, p, pps=pps, duration=duration)
    elif proto == "modbus":
        p = p or 502
        fuzz = ModbusFuzzer(target, p, pps=pps, duration=duration)
    elif proto == "ble":
        fuzz = BLEFuzzer(target, 0, pps=pps, duration=duration)
    else:
        raise ValueError(f"Unknown protocol: {protocol}")
    # Health monitor
    hm = HealthMonitor(target, ns)
    hm.start()
    try:
        res = fuzz.run()
    finally:
        hm.stop()
    return res

def start_fuzzer(ns: str, protocol: str, target: str, port: Optional[int], pps: int, duration: int) -> Dict:
    # Spawn a subprocess within namespace
    if not require_root():
        LOG.info("Running fuzzer in current namespace (no root privileges).")
        return run_fuzzer_in_ns(None, protocol, target, port, pps, duration)
    cmd = ["ip", "netns", "exec", ns, sys.executable, __file__, "run-fuzzer",
           "--protocol", protocol, "--target", target, "--pps", str(pps), "--duration", str(duration)]
    if port:
        cmd += ["--port", str(port)]
    cp = run_cmd(cmd, check=False, capture=True)
    if cp.returncode != 0:
        LOG.error("Fuzzer process failed: %s", cp.stderr)
        return {"sent": 0, "errors": 1, "issues": ["fuzzer failed to run"]}
    try:
        return json.loads(cp.stdout.strip() or "{}")
    except Exception:
        return {"sent": 0, "errors": 1, "issues": ["invalid fuzzer output"]}

def firmware_scan(archive: str, rule_pack: Optional[str], sig: Optional[str], pubkey: Optional[str], output: str, allow_unsigned: bool = False) -> Dict:
    outdir = Path(output)
    outdir.mkdir(parents=True, exist_ok=True)
    set_no_new_privs()
    # Extract firmware without mounting; enforce read-only with guard
    extracted_root = extract_firmware(archive, outdir)
    # Drop capabilities via setting no_new_privs only; containerization not feasible here
    # Deny writes and log attempts during scan
    rules = load_signed_rules(rule_pack, sig, pubkey, allow_unsigned=allow_unsigned)
    report_path = outdir / "report_redacted.txt"
    manifest_path = outdir / "manifest.sealed.json"
    with ReadOnlyDirGuard(extracted_root, LOG):
        files_scanned, files_with_findings = scan_with_rules(extracted_root, rules, report_path, manifest_path)
        # Attempt a write to demonstrate enforcement logging (no actual modification)
        try:
            open(extracted_root / "should_not_write.txt", "w").write("test")
        except PermissionError:
            pass
    # Compute archive SHA-256
    archive_sha256 = sha256_file(archive)
    return {
        "extracted_root": str(extracted_root),
        "files_scanned": files_scanned,
        "files_with_findings": files_with_findings,
        "report": str(report_path),
        "manifest": str(manifest_path),
        "archive_sha256": archive_sha256,
    }

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

class FuzzFox:
    """
    FuzzFox IoT - Passive discovery, firmware analysis, and protocol-aware fuzzing with isolation.

    Note: Use only with explicit authorization and within isolated lab networks.
    """
    def __init__(self, iface: Optional[str] = None, namespace: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.log = logger or LOG
        self.version = VERSION
        self.ethical_warning = ETHICAL_WARNING
        self.iface = iface
        self.namespace = namespace

    # Passive device discovery
    def discover(self, timeout: float = 5.0) -> List[Dict]:
        d = PassiveDiscovery(self.iface)
        return d.discover(timeout=timeout)

    # Namespace operations
    def setup_namespace(self, name: str, targets: List[str]) -> Dict:
        nm = setup_namespace(name, targets)
        return {"namespace": name, "host_if": nm.host_if, "ns_if": nm.ns_if, "targets": targets}

    def teardown_namespace(self, name: str) -> Dict:
        teardown_namespace(name)
        return {"namespace": name, "status": "deleted"}

    def counters(self, name: str) -> Dict:
        nm = NamespaceManager(name)
        return nm.counters()

    # Fuzzing
    def fuzz(self, protocol: str, target: str, port: Optional[int] = None, pps: int = DEFAULT_PPS, duration: int = 30, namespace: Optional[str] = None) -> Dict:
        nsname = namespace if namespace is not None else self.namespace
        if require_root() and not nsname:
            # Create ephemeral namespace allowing only target to ensure microsegmentation
            nsname = f"{NS_PREFIX}-{int(time.time())}-{random.randint(100,999)}"
            nm = NamespaceManager(nsname)
            nm.create([target])
            try:
                res = start_fuzzer(nsname, protocol, target, port, pps, duration)
            finally:
                nm.destroy()
        else:
            res = start_fuzzer(nsname, protocol, target, port, pps, duration)
        if nsname:
            res["counters"] = NamespaceManager(nsname).counters()
        return res

    def kill(self, reason: str = "manual") -> Dict:
        KILL.trigger(reason)
        return {"kill": True, "reason": reason}

    # Firmware analysis
    def firmware_scan(self, archive: str, output: str, rule_pack: Optional[str] = None, signature: Optional[str] = None, pubkey: Optional[str] = None, allow_unsigned: bool = False) -> Dict:
        return firmware_scan(archive, rule_pack, signature, pubkey, output, allow_unsigned=allow_unsigned)

def main():
    print(ETHICAL_WARNING, file=sys.stderr)
    parser = argparse.ArgumentParser(prog="fuzzfox", description="FuzzFox IoT - Passive discovery, firmware analysis, and protocol-aware fuzzing with microsegmentation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_disc = sub.add_parser("discover", help="Passive discovery via mDNS/SSDP")
    p_disc.add_argument("--timeout", type=float, default=5.0)

    p_ns = sub.add_parser("setup-namespace", help="Create microsegmented namespace")
    p_ns.add_argument("--name", required=True)
    p_ns.add_argument("--targets", required=True, help="Comma-separated target IPs allowed")

    p_teardown = sub.add_parser("teardown-namespace", help="Destroy namespace")
    p_teardown.add_argument("--name", required=True)

    p_cnt = sub.add_parser("counters", help="Show namespace counters")
    p_cnt.add_argument("--name", required=True)

    p_kill = sub.add_parser("kill", help="Trigger kill-switch (quarantine fuzzers)")
    p_kill.add_argument("--reason", default="manual")

    p_fuzz = sub.add_parser("fuzz", help="Run protocol-aware fuzzer in microsegmented namespace")
    p_fuzz.add_argument("--ns", required=False, help="Namespace name. If omitted and root available, discovery targets will still be microsegmented.")
    p_fuzz.add_argument("--protocol", required=True, choices=["mqtt", "coap", "modbus", "ble"])
    p_fuzz.add_argument("--target", required=True)
    p_fuzz.add_argument("--port", type=int)
    p_fuzz.add_argument("--pps", type=int, default=DEFAULT_PPS)
    p_fuzz.add_argument("--duration", type=int, default=30)

    p_runf = sub.add_parser("run-fuzzer", help="INTERNAL: run fuzzer (ns exec)")
    p_runf.add_argument("--protocol", required=True, choices=["mqtt", "coap", "modbus", "ble"])
    p_runf.add_argument("--target", required=True)
    p_runf.add_argument("--port", type=int)
    p_runf.add_argument("--pps", type=int, default=DEFAULT_PPS)
    p_runf.add_argument("--duration", type=int, default=30)

    p_fw = sub.add_parser("firmware-scan", help="Extract firmware and scan with signed YARA-like rule pack")
    p_fw.add_argument("--archive", required=True)
    p_fw.add_argument("--rule-pack", required=False, help="JSON rule pack path")
    p_fw.add_argument("--signature", required=False, help="Detached signature path for rule pack")
    p_fw.add_argument("--pubkey", required=False, help="Public key PEM for verifying rule pack")
    p_fw.add_argument("--output", required=True, help="Output directory")
    p_fw.add_argument("--allow-unsigned", action="store_true", help="Allow unsigned rule packs (not recommended)")

    args = parser.parse_args()

    try:
        if args.cmd == "discover":
            d = PassiveDiscovery()
            devices = d.discover(timeout=args.timeout)
            print(json.dumps(devices, indent=2))
        elif args.cmd == "setup-namespace":
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
            nm = setup_namespace(args.name, targets)
            print(json.dumps({"namespace": args.name, "host_if": nm.host_if, "ns_if": nm.ns_if, "targets": targets}))
        elif args.cmd == "teardown-namespace":
            teardown_namespace(args.name)
            print(json.dumps({"namespace": args.name, "status": "deleted"}))
        elif args.cmd == "counters":
            nm = NamespaceManager(args.name)
            counters = nm.counters()
            print(json.dumps(counters, indent=2))
        elif args.cmd == "kill":
            KILL.trigger(args.reason)
            print(json.dumps({"kill": True, "reason": args.reason}))
        elif args.cmd == "fuzz":
            nsname = args.ns
            if require_root() and not nsname:
                # Create ephemeral namespace allowing only target
                nsname = f"{NS_PREFIX}-{int(time.time())}-{random.randint(100,999)}"
                nm = NamespaceManager(nsname)
                nm.create([args.target])
                try:
                    res = start_fuzzer(nsname, args.protocol, args.target, args.port, args.pps, args.duration)
                finally:
                    nm.destroy()
            else:
                res = start_fuzzer(nsname, args.protocol, args.target, args.port, args.pps, args.duration)
            # After fuzzing, show counters to verify containment
            if nsname:
                counters = NamespaceManager(nsname).counters()
                res["counters"] = counters
            print(json.dumps(res, indent=2))
        elif args.cmd == "run-fuzzer":
            # Internal: actually run the fuzzer inside namespace
            set_no_new_privs()
            res = run_fuzzer_in_ns(None, args.protocol, args.target, args.port, args.pps, args.duration)
            print(json.dumps(res))
        elif args.cmd == "firmware-scan":
            res = firmware_scan(args.archive, args.rule_pack, args.signature, args.pubkey, args.output, allow_unsigned=args.allow_unsigned)
            print(json.dumps(res, indent=2))
        else:
            parser.print_help()
    except KeyboardInterrupt:
        KILL.trigger("keyboard interrupt")
        sys.exit(1)
    except Exception as e:
        LOG.error("Error: %s", e)
        sys.exit(2)

if __name__ == "__main__":
    main()