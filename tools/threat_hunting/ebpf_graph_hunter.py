import os
import sys
import json
import time
import hmac
import hashlib
import threading
import queue
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Ethical and legal warning
ETHICAL_WARNING = (
    "WARNING: This tool collects kernel/process telemetry for security monitoring. "
    "Use only in environments where you have explicit authorization. Misuse may violate "
    "laws and organizational policies. Ensure you notify stakeholders and follow least-privilege, "
    "privacy, and compliance practices."
)

# Defaults and constants
DEFAULT_MODEL_SIGNING_KEY = "FOR_TESTING_ONLY_NOT_SECURE"
DEFAULT_MODEL_ID = "lotl_seq_model"
DEFAULT_MODEL_VERSION = "1.0.0"
ENGINE_VERSION = "0.1.0"

# Try to import BCC if available; fallback to simulation.
try:
    from bcc import BPF  # type: ignore
    BCC_AVAILABLE = True
except Exception:
    BCC_AVAILABLE = False


@dataclass
class Config:
    # Operational
    enable_packet_injection: bool = False  # Must remain False by default
    anonymize: bool = False
    anonymization_salt: str = "rotate-this-salt"
    # Rate limiting and sampling
    rate_limit_capacity: int = 1000
    rate_limit_refill_per_sec: int = 1000
    sampling_high_watermark: int = 500  # events/sec threshold to engage sampling
    sampling_low_watermark: int = 200   # events/sec threshold to disengage sampling
    sampling_min_rate: float = 0.1      # minimum sampling rate when engaged
    # Storage encryption
    storage_encryption_key: Optional[str] = None  # if None, ephemeral key
    # Model verification
    model_hmac_keys: List[str] = field(default_factory=lambda: [DEFAULT_MODEL_SIGNING_KEY])
    # eBPF collector flags
    use_ebpf_collector: bool = True
    # CPU budget (soft target) per batch in seconds
    cpu_time_budget_per_batch: float = 0.02
    # Adaptive batch size
    batch_size: int = 128


@dataclass
class AuditEvent:
    time: float
    type: str
    details: Dict[str, Any]


@dataclass
class Alert:
    time: float
    severity: str
    rule_id: str
    description: str
    chain: List[str]
    pid: int


@dataclass
class ProcessEvent:
    time: float
    type: str  # "exec", "fork", "syscall", "network"
    pid: int
    ppid: int
    comm: str
    argv: List[str] = field(default_factory=list)
    syscall: Optional[str] = None
    dest: Optional[Tuple[str, int]] = None  # For network events (ip, port)


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: int) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.refill_per_sec = refill_per_sec
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def allow(self, n: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            if elapsed > 0:
                refill = int(elapsed * self.refill_per_sec)
                if refill > 0:
                    self.tokens = min(self.capacity, self.tokens + refill)
                    self.last_refill = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False


class EventMeter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0
        self._last = time.monotonic()
        self.rate_per_sec = 0.0

    def tick(self, n: int = 1) -> None:
        with self._lock:
            self._count += n
            now = time.monotonic()
            elapsed = now - self._last
            # update every 0.5s
            if elapsed >= 0.5:
                self.rate_per_sec = self._count / elapsed if elapsed > 0 else 0.0
                self._count = 0
                self._last = now

    def get_rate(self) -> float:
        with self._lock:
            return self.rate_per_sec


class AdaptiveSampler:
    def __init__(self, high: int, low: int, min_rate: float) -> None:
        self.high = high
        self.low = low
        self.min_rate = min_rate
        self.sample_rate = 1.0
        self.active = False
        self._lock = threading.Lock()

    def update(self, rate_per_sec: float) -> None:
        with self._lock:
            if self.active:
                if rate_per_sec <= self.low:
                    self.active = False
                    self.sample_rate = 1.0
            else:
                if rate_per_sec >= self.high:
                    self.active = True
                    # Scale sampling inversely with rate
                    # For rates much larger than high, approach min_rate
                    factor = max(rate_per_sec / max(self.high, 1), 1.0)
                    self.sample_rate = max(self.min_rate, 1.0 / factor)

    def should_sample(self) -> bool:
        with self._lock:
            return random.random() <= self.sample_rate

    def status(self) -> Tuple[bool, float]:
        with self._lock:
            return self.active, self.sample_rate


class Anonymizer:
    def __init__(self, enabled: bool, salt: str) -> None:
        self.enabled = enabled
        self.salt = salt.encode()

    def hash_str(self, s: str) -> str:
        # salted SHA256
        return hashlib.sha256(self.salt + s.encode()).hexdigest()

    def maybe(self, s: str) -> str:
        if not self.enabled:
            return s
        return self.hash_str(s)

    def maybe_list(self, lst: List[str]) -> List[str]:
        if not self.enabled:
            return lst
        return [self.hash_str(x) for x in lst]


class SimpleFernet:
    """
    Minimalist Fernet-like utility using cryptography if available.
    If not available, falls back to XOR+HMAC for testing only (NOT secure).
    """
    def __init__(self, key: Optional[str]) -> None:
        self._mode = "fallback"
        self._hmac_key = (key or DEFAULT_MODEL_SIGNING_KEY).encode()
        self._xor_key = hashlib.sha256(self._hmac_key).digest()
        try:
            # Late import to avoid hard dependency
            from cryptography.fernet import Fernet  # type: ignore
            if key and len(key) >= 32:
                # derive a 32-byte urlsafe base64 key
                b = hashlib.sha256(key.encode()).digest()
                import base64
                self._fernet = Fernet(base64.urlsafe_b64encode(b))
                self._mode = "fernet"
            else:
                # generate ephemeral key
                import base64
                self._fernet = Fernet(base64.urlsafe_b64encode(os.urandom(32)))
                self._mode = "fernet"
        except Exception:
            self._fernet = None

    def encrypt(self, data: bytes) -> bytes:
        if self._mode == "fernet":
            return self._fernet.encrypt(data)  # type: ignore
        # Fallback: XOR then append HMAC (testing only)
        xored = bytes(b ^ self._xor_key[i % len(self._xor_key)] for i, b in enumerate(data))
        mac = hmac.new(self._hmac_key, xored, hashlib.sha256).digest()
        return mac + xored

    def decrypt(self, data: bytes) -> bytes:
        if self._mode == "fernet":
            return self._fernet.decrypt(data)  # type: ignore
        mac, xored = data[:32], data[32:]
        calc = hmac.new(self._hmac_key, xored, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, calc):
            raise ValueError("ciphertext integrity check failed")
        return bytes(b ^ self._xor_key[i % len(self._xor_key)] for i, b in enumerate(xored))


class SecureModelLoader:
    def __init__(self, trusted_hmac_keys: List[str], audit_cb) -> None:
        self.trusted_hmac_keys = [k.encode() for k in trusted_hmac_keys]
        self.audit_cb = audit_cb

    @staticmethod
    def canonical_json(data: Dict[str, Any]) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def verify_and_load(self, model_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Required fields
        required = ["id", "version", "sig_alg", "signature"]
        for f in required:
            if f not in model_json:
                self.audit_cb(
                    "MODEL_VERIFICATION_FAILED",
                    {"reason": f"missing_field:{f}", "model_summary": str({k: model_json.get(k) for k in ['id','version']})},
                )
                return None
        sig_alg = model_json.get("sig_alg")
        signature = model_json.get("signature")
        content = dict(model_json)
        del content["signature"]
        if sig_alg == "HMAC-SHA256":
            content_bytes = self.canonical_json(content)
            for key in self.trusted_hmac_keys:
                expected = hmac.new(key, content_bytes, hashlib.sha256).hexdigest()
                if hmac.compare_digest(expected, signature):
                    # additional version checks can go here
                    return model_json
            self.audit_cb(
                "MODEL_VERIFICATION_FAILED",
                {"reason": "signature_mismatch", "model_id": model_json.get("id"), "version": model_json.get("version")},
            )
            return None
        else:
            self.audit_cb(
                "MODEL_VERIFICATION_FAILED",
                {"reason": f"unsupported_sig_alg:{sig_alg}", "model_id": model_json.get("id")},
            )
            return None


class RuleEngine:
    def __init__(self) -> None:
        # rules: list of dict with fields type, name, sequence, severity, description
        self.rules: List[Dict[str, Any]] = []
        self.compiled: List[Dict[str, Any]] = []

    @staticmethod
    def norm_name(n: str) -> str:
        return n.lower()

    def load_rules_from_model(self, model: Dict[str, Any]) -> None:
        rules = model.get("rules", [])
        self.rules = rules
        compiled: List[Dict[str, Any]] = []
        for r in rules:
            if r.get("type") == "sequence":
                seq = [self.norm_name(x) for x in r.get("sequence", [])]
                compiled.append({
                    "type": "sequence",
                    "name": r.get("name", "unnamed"),
                    "sequence": seq,
                    "severity": r.get("severity", "medium"),
                    "description": r.get("description", ""),
                    "id": f"{model.get('id','')}/{r.get('name','')}",
                })
        self.compiled = compiled

    def evaluate_chain(self, chain: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        norm_chain = [self.norm_name(x) for x in chain]
        for cr in self.compiled:
            if cr["type"] == "sequence":
                seq = cr["sequence"]
                # check whether seq is a subsequence of norm_chain (in order, contiguous or not)
                it = iter(norm_chain)
                if all(any(c == s for c in it) for s in seq):
                    findings.append(cr)
        return findings


class ProcessGraph:
    def __init__(self, max_depth: int = 8) -> None:
        self.max_depth = max_depth
        self.proc_by_pid: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def update_exec(self, ev: ProcessEvent) -> None:
        with self._lock:
            parent = self.proc_by_pid.get(ev.ppid)
            ancestors = []
            if parent:
                ancestors = parent.get("ancestors", [])[-(self.max_depth - 1):] + [parent.get("name", "")]
            info = {
                "pid": ev.pid,
                "ppid": ev.ppid,
                "name": ev.comm,
                "argv": ev.argv,
                "start": ev.time,
                "ancestors": ancestors,
            }
            self.proc_by_pid[ev.pid] = info

    def update_fork(self, ev: ProcessEvent) -> None:
        with self._lock:
            parent = self.proc_by_pid.get(ev.ppid)
            ancestors = []
            pname = ""
            if parent:
                ancestors = parent.get("ancestors", [])[-(self.max_depth - 1):] + [parent.get("name", "")]
            else:
                # unknown parent, we still create placeholder
                pass
            info = {
                "pid": ev.pid,
                "ppid": ev.ppid,
                "name": pname,
                "argv": [],
                "start": ev.time,
                "ancestors": ancestors,
            }
            self.proc_by_pid[ev.pid] = info

    def set_name(self, pid: int, name: str, argv: Optional[List[str]] = None) -> None:
        with self._lock:
            node = self.proc_by_pid.get(pid)
            if node:
                node["name"] = name
                if argv is not None:
                    node["argv"] = argv

    def chain_for_pid(self, pid: int, include_self: bool = True) -> List[str]:
        with self._lock:
            node = self.proc_by_pid.get(pid)
            if not node:
                return []
            chain = list(node.get("ancestors", []))
            if include_self and node.get("name"):
                chain.append(node["name"])
            return chain


class EBPFCollector(threading.Thread):
    """
    Optional eBPF collector. If BCC is not available or not permitted, remains in simulation mode.
    Produces ProcessEvent objects into an output queue.
    """
    def __init__(self, out_q: queue.Queue, config: Config, audit_cb) -> None:
        super().__init__(daemon=True)
        self.out_q = out_q
        self.config = config
        self.audit_cb = audit_cb
        self._stop = threading.Event()
        self._mode = "simulation"
        self._bpf = None

    def run(self) -> None:
        # Security: No packet injection/blocking. Read-only telemetry.
        if not self.config.use_ebpf_collector:
            self.audit_cb("EBPF_DISABLED", {"reason": "config_disabled"})
            return
        if not BCC_AVAILABLE:
            self.audit_cb("EBPF_UNAVAILABLE", {"reason": "bcc_not_installed"})
            self._mode = "simulation"
            return
        # To keep within limits, we do not actually load programs here; users can extend as needed.
        self.audit_cb("EBPF_SIMULATION_MODE", {"reason": "sample code avoids kernel hooks by default"})
        self._mode = "simulation"
        # In simulation, just idle until stopped.
        while not self._stop.is_set():
            time.sleep(0.2)

    def stop(self) -> None:
        self._stop.set()


class GraphHunter:
    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.token_bucket = TokenBucket(self.config.rate_limit_capacity, self.config.rate_limit_refill_per_sec)
        self.event_meter = EventMeter()
        self.sampler = AdaptiveSampler(self.config.sampling_high_watermark, self.config.sampling_low_watermark, self.config.sampling_min_rate)
        self.anonymizer = Anonymizer(self.config.anonymize, self.config.anonymization_salt)
        self.cipher = SimpleFernet(self.config.storage_encryption_key)
        self.graph = ProcessGraph()
        self.rule_engine = RuleEngine()
        self.audit_log: List[AuditEvent] = []
        self.alerts: List[Alert] = []
        self._in_q: "queue.Queue[ProcessEvent]" = queue.Queue(maxsize=8192)
        self._collector = EBPFCollector(self._in_q, self.config, self._audit)
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._dropped_rate_limit = 0
        self._dropped_sampling = 0
        self._last_batch_time = 0.0
        self._ethical_logged = False
        # Load default model (signed)
        self._load_default_model()

    def _audit(self, typ: str, details: Dict[str, Any]) -> None:
        self.audit_log.append(AuditEvent(time=time.time(), type=typ, details=details))

    def _load_default_model(self) -> None:
        model = {
            "id": DEFAULT_MODEL_ID,
            "version": DEFAULT_MODEL_VERSION,
            "engine_min_version": "0.0.1",
            "sig_alg": "HMAC-SHA256",
            "rules": [
                {
                    "type": "sequence",
                    "name": "word->powershell->curl",
                    "sequence": ["word", "powershell", "curl"],
                    "severity": "high",
                    "description": "LOTL pattern: Office spawning PowerShell then curl."
                }
            ],
        }
        # Sign content with default key for testing
        content = dict(model)
        # placeholder signature field will be added after content canonicalization
        content_bytes = SecureModelLoader.canonical_json(content)
        sig = hmac.new(DEFAULT_MODEL_SIGNING_KEY.encode(), content_bytes, hashlib.sha256).hexdigest()
        model["signature"] = sig
        loader = SecureModelLoader(self.config.model_hmac_keys, self._audit)
        verified = loader.verify_and_load(model)
        if verified:
            self.rule_engine.load_rules_from_model(verified)
            self._audit("MODEL_LOADED", {"id": verified.get("id"), "version": verified.get("version")})
        else:
            self._audit("MODEL_LOAD_FAILED", {"id": model.get("id"), "version": model.get("version")})

    def load_models_from_files(self, paths: List[str]) -> None:
        loader = SecureModelLoader(self.config.model_hmac_keys, self._audit)
        loaded_any = False
        for p in paths:
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                verified = loader.verify_and_load(data)
                if verified:
                    self.rule_engine.load_rules_from_model(verified)
                    self._audit("MODEL_LOADED", {"path": p, "id": verified.get("id"), "version": verified.get("version")})
                    loaded_any = True
                else:
                    self._audit("MODEL_DROP", {"path": p})
            except Exception as e:
                self._audit("MODEL_LOAD_ERROR", {"path": p, "error": str(e)})
        if not loaded_any:
            # retain existing rules (default) but note that none of provided were loaded
            pass

    def start(self) -> None:
        if not self._ethical_logged:
            print(ETHICAL_WARNING, file=sys.stderr)
            self._ethical_logged = True
        if self.config.enable_packet_injection:
            # Enforce safety: disallow overriding this at runtime
            self._audit("SECURITY_OVERRIDE_BLOCKED", {"capability": "packet_injection"})
            self.config.enable_packet_injection = False
        # start worker and optional collector
        self._worker.start()
        self._collector.start()
        self._audit("ENGINE_STARTED", {"engine_version": ENGINE_VERSION})

    def stop(self) -> None:
        self._stop.set()
        try:
            self._collector.stop()
        except Exception:
            pass

    def _worker_loop(self) -> None:
        # internal worker that processes events from queue with rate limiting and sampling
        while not self._stop.is_set():
            batch: List[ProcessEvent] = []
            start = time.monotonic()
            # prepare batch with a soft CPU budget awareness
            max_batch = self.config.batch_size
            while len(batch) < max_batch:
                try:
                    ev = self._in_q.get(timeout=0.01)
                    batch.append(ev)
                except queue.Empty:
                    break
                if (time.monotonic() - start) >= self.config.cpu_time_budget_per_batch:
                    break
            if not batch:
                # update sampling on idle based on meter
                self.sampler.update(self.event_meter.get_rate())
                continue
            # process batch
            for ev in batch:
                self.event_meter.tick(1)
                # Update adaptive sampler status by meter
                self.sampler.update(self.event_meter.get_rate())
                # rate limit check
                if not self.token_bucket.allow(1):
                    self._dropped_rate_limit += 1
                    continue
                # sampling
                if not self.sampler.should_sample():
                    self._dropped_sampling += 1
                    continue
                # process event
                self._handle_event(ev)

    def ingest_event(self, ev: ProcessEvent) -> None:
        # Public API to feed events (e.g., from tests or alternate collectors)
        try:
            self._in_q.put_nowait(ev)
        except queue.Full:
            # backpressure: drop oldest to make room
            try:
                _ = self._in_q.get_nowait()
                self._in_q.put_nowait(ev)
                self._audit("QUEUE_BACKPRESSURE", {"action": "drop_oldest"})
            except Exception:
                self._audit("QUEUE_OVERFLOW_DROP", {})

    def _handle_event(self, ev: ProcessEvent) -> None:
        # Update process graph
        if ev.type == "exec":
            self.graph.update_exec(ev)
        elif ev.type == "fork":
            self.graph.update_fork(ev)
        else:
            # ensure at least node exists
            pass

        if ev.type == "exec":
            # Set name for PID
            self.graph.set_name(ev.pid, ev.comm, ev.argv)
            # Evaluate chain on exec events as well
            chain = self.graph.chain_for_pid(ev.pid)
            self._evaluate_and_alert(chain, ev.pid, "exec")
        elif ev.type == "network":
            # Evaluate chain when network activity occurs
            chain = self.graph.chain_for_pid(ev.pid)
            self._evaluate_and_alert(chain, ev.pid, "network")

        # Optionally store encrypted telemetry at rest (anonymized if enabled)
        self._store_telemetry(ev)

    def _evaluate_and_alert(self, chain: List[str], pid: int, reason: str) -> None:
        if not chain:
            return
        findings = self.rule_engine.evaluate_chain(chain)
        for finding in findings:
            severity = finding.get("severity", "medium")
            desc = finding.get("description", "")
            self.alerts.append(Alert(
                time=time.time(),
                severity=severity,
                rule_id=finding.get("id", ""),
                description=f"{desc} (trigger: {reason})",
                chain=list(chain),
                pid=pid,
            ))
            self._audit("ALERT_RAISED", {
                "severity": severity,
                "rule": finding.get("id", ""),
                "chain": chain,
                "pid": pid,
            })

    def _store_telemetry(self, ev: ProcessEvent) -> None:
        # Store minimal event metadata encrypted in memory buffer (simulated at-rest encryption)
        try:
            data = {
                "time": ev.time,
                "type": ev.type,
                "pid": ev.pid,
                "ppid": ev.ppid,
                "comm": self.anonymizer.maybe(ev.comm),
                "argv": self.anonymizer.maybe_list(ev.argv),
                "syscall": ev.syscall,
                "dest": ev.dest,
            }
            blob = json.dumps(data, separators=(",", ":")).encode()
            _ = self.cipher.encrypt(blob)  # Encrypted blob; in real system, write to disk or secure store.
        except Exception as e:
            self._audit("TELEMETRY_STORE_ERROR", {"error": str(e)})

    # Public interfaces for monitoring and tests
    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)

    def get_audits(self) -> List[AuditEvent]:
        return list(self.audit_log)

    def get_sampling_status(self) -> Dict[str, Any]:
        active, rate = self.sampler.status()
        return {
            "active": active,
            "sample_rate": rate,
            "rate_per_sec": self.event_meter.get_rate(),
            "dropped_rate_limit": self._dropped_rate_limit,
            "dropped_sampling": self._dropped_sampling,
        }

    # Simulation helpers
    def simulate_process_chain(self, names: List[str], network_at_end: bool = True, delay: float = 0.0) -> None:
        """
        Simulates a process chain by emitting exec events with increasing PIDs and a parent-child relation.
        Optionally emits a network event for the last process to trigger LOTL detection.
        """
        now = time.time()
        base_pid = random.randint(1000, 5000)
        ppid = 1
        pid = base_pid
        # Clear any previous to avoid conflicts
        for i, name in enumerate(names):
            ev = ProcessEvent(
                time=now + i * 0.01,
                type="exec",
                pid=pid,
                ppid=ppid,
                comm=name,
                argv=[name],
            )
            self.ingest_event(ev)
            # next child
            ppid = pid
            pid += 1
            if delay > 0:
                time.sleep(delay)
        if network_at_end:
            # emit network connect from last pid (pid-1)
            nev = ProcessEvent(
                time=now + len(names) * 0.01 + 0.01,
                type="network",
                pid=pid - 1,
                ppid=ppid,
                comm=names[-1],
                argv=[names[-1]],
                syscall="connect",
                dest=("1.2.3.4", 80),
            )
            self.ingest_event(nev)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="eBPF Syscall Graph Hunter (LOTL/zero-day behavior detection)")
    parser.add_argument("--no-ebpf", action="store_true", help="Disable eBPF collector (simulation mode only).")
    parser.add_argument("--anonymize", action="store_true", help="Enable anonymization of telemetry at rest.")
    parser.add_argument("--model", action="append", help="Path to detection model JSON (signed).", default=[])
    parser.add_argument("--burst-test", type=int, default=0, help="Emit N simulated events rapidly to test adaptive sampling.")
    parser.add_argument("--simulate-chain", action="store_true", help="Simulate Word->PowerShell->curl chain (authorized testing only).")
    parser.add_argument("--run-seconds", type=int, default=5, help="Run time before exit (for demo).")
    args = parser.parse_args(argv)

    cfg = Config(
        use_ebpf_collector=not args.no_ebpf,
        anonymize=args.anonymize,
    )
    hunter = GraphHunter(cfg)
    if args.model:
        hunter.load_models_from_files(args.model)

    hunter.start()

    # Authorized testing simulation
    if args.simulate_chain:
        hunter.simulate_process_chain(["winword.exe", "powershell.exe", "curl"], network_at_end=True, delay=0.0)

    if args.burst_test > 0:
        now = time.time()
        pid = 20000
        for i in range(args.burst_test):
            ev = ProcessEvent(
                time=now + i * 0.0001,
                type="exec",
                pid=pid + i,
                ppid=1,
                comm=f"proc{i}",
                argv=[f"proc{i}"],
            )
            hunter.ingest_event(ev)

    # Run event loop for a bit
    t_end = time.time() + args.run_seconds
    try:
        while time.time() < t_end:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass

    hunter.stop()

    # Print summary
    alerts = hunter.get_alerts()
    audits = hunter.get_audits()
    sampling = hunter.get_sampling_status()

    print("=== Alerts ===")
    for a in alerts:
        print(f"[{time.strftime('%X', time.localtime(a.time))}] {a.severity.upper()} {a.rule_id}: {a.description} chain={a.chain} pid={a.pid}")
    print("=== Audit Events ===")
    for ev in audits:
        print(f"[{time.strftime('%X', time.localtime(ev.time))}] {ev.type} {ev.details}")
    print("=== Sampling Status ===")
    print(sampling)

    return 0


if __name__ == "__main__":
    sys.exit(main())