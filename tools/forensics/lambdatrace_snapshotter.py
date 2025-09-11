import os
import sys
import io
import json
import time
import socket as _socket
import threading
import hashlib
import hmac
import secrets
import stat
import errno
from collections import deque, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List


# Ethical and legal disclaimer: This tool is intended for authorized security operations,
# incident response, and controlled testing only. Do not deploy or enable in environments
# without explicit approval and a documented lawful purpose. Ensure all privacy, data
# protection, and compliance requirements are reviewed and satisfied before capture.

# -----------------------
# Redaction and utilities
# -----------------------

_SECRET_KEY_PATTERNS = [
    "PASSWORD", "PASS", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "AUTH", "PRIVATE", "CERT", "APIKEY", "SESSION",
]
_SECRET_VALUE_REGEXES = [
    # crude patterns to mask likely secrets in text
    (r"(?i)(password|pass|pwd)\s*[:=]\s*([^\s,;]+)", r"\1=<REDACTED>"),
    (r"(?i)(token|secret|key)\s*[:=]\s*([^\s,;]+)", r"\1=<REDACTED>"),
    (r"AKIA[0-9A-Z]{16}", "<REDACTED_AWS_ACCESS_KEY>"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*[0-9A-Za-z/+]{30,}", "<REDACTED_AWS_SECRET_KEY>"),
    (r"(?i)bearer\s+[0-9A-Za-z\-_\.=:+/]{16,}", "Bearer <REDACTED>"),
    (r"[0-9a-fA-F]{32,}", "<REDACTED_HEX>"),
]

try:
    import re as _re
except Exception:  # pragma: no cover
    _re = None


def _now_iso8601() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_json_dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _hash_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def redact_env(env: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for k, v in env.items():
        key_upper = k.upper()
        if any(p in key_upper for p in _SECRET_KEY_PATTERNS):
            redacted[k] = "<REDACTED>"
        else:
            # avoid including long values; cap length
            redacted[k] = v if len(v) <= 128 else v[:64] + "...<TRUNCATED>"
    return redacted


def redact_text(text: str) -> str:
    if not _re:
        return text
    red = text
    for pat, repl in _SECRET_VALUE_REGEXES:
        red = _re.sub(pat, repl, red)
    return red


# -----------------------
# Stdout/Stderr Tee
# -----------------------

class RingBufferTee(io.TextIOBase):
    def __init__(self, original, max_bytes: int = 65536):
        self._orig = original
        self._buf = deque()
        self._buf_bytes = 0
        self._max_bytes = max_bytes
        self._lock = threading.Lock()

    def write(self, s: str):
        if not isinstance(s, str):
            s = s.decode("utf-8", errors="ignore")
        with self._lock:
            self._orig.write(s)
            # capture redacted
            s_red = redact_text(s)
            self._buf.append(s_red)
            self._buf_bytes += len(s_red.encode("utf-8"))
            while self._buf and self._buf_bytes > self._max_bytes:
                old = self._buf.popleft()
                self._buf_bytes -= len(old.encode("utf-8"))
        return len(s)

    def flush(self):
        with self._lock:
            self._orig.flush()

    def snapshot(self) -> str:
        with self._lock:
            return "".join(list(self._buf)[-2000:])  # bound on number of chunks


class StdCapture:
    def __init__(self, enable: bool, max_bytes: int = 65536):
        self.enable = enable
        self._stdout_orig = None
        self._stderr_orig = None
        self._stdout_tee = None
        self._stderr_tee = None
        self._max_bytes = max_bytes

    def start(self):
        if not self.enable:
            return
        if self._stdout_tee is None:
            self._stdout_orig = sys.stdout
            self._stderr_orig = sys.stderr
            self._stdout_tee = RingBufferTee(sys.stdout, self._max_bytes)
            self._stderr_tee = RingBufferTee(sys.stderr, self._max_bytes)
            sys.stdout = self._stdout_tee  # type: ignore
            sys.stderr = self._stderr_tee  # type: ignore

    def stop(self):
        if not self.enable:
            return
        if self._stdout_tee is not None and self._stdout_orig is not None:
            sys.stdout = self._stdout_orig  # type: ignore
            self._stdout_tee = None
        if self._stderr_tee is not None and self._stderr_orig is not None:
            sys.stderr = self._stderr_orig  # type: ignore
            self._stderr_tee = None

    def snapshot(self) -> Dict[str, str]:
        if not self.enable or self._stdout_tee is None or self._stderr_tee is None:
            return {"stdout": "", "stderr": ""}
        return {"stdout": self._stdout_tee.snapshot(), "stderr": self._stderr_tee.snapshot()}


# -----------------------
# Network 5-tuple tracer (eBPF-lite)
# -----------------------

class NetTracer:
    def __init__(self, enable: bool, sample_rate: float = 1.0):
        self.enable = enable
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self._orig_socket = _socket.socket
        self._patched = False
        self._flows_lock = threading.Lock()
        self._flows: Dict[Tuple[str, str, int, int, str], Dict[str, Any]] = {}

    def _record_flow(self, sock: _socket.socket, dst: Tuple[str, int], proto: str):
        if not self.enable:
            return
        if self.sample_rate < 1.0 and secrets.randbelow(1000000) / 1000000.0 > self.sample_rate:
            return
        try:
            src_host, src_port = sock.getsockname()
            dst_host, dst_port = dst
        except Exception:
            return
        k = (src_host, dst_host, src_port, dst_port, proto)
        with self._flows_lock:
            it = self._flows.get(k)
            if it is None:
                self._flows[k] = {"count": 1, "first": _now_iso8601(), "last": _now_iso8601()}
            else:
                it["count"] += 1
                it["last"] = _now_iso8601()

    def _wrap_socket_class(self):
        outer = self

        class TracedSocket(_socket.socket):  # type: ignore
            def connect(self, address):
                res = super().connect(address)
                try:
                    proto = "tcp" if self.type == _socket.SOCK_STREAM else "udp"
                    # address may be tuple or str (unix), only record inet
                    if isinstance(address, tuple) and len(address) >= 2:
                        outer._record_flow(self, (address[0], int(address[1])), proto)
                except Exception:
                    pass
                return res

            def sendto(self, data, address):  # type: ignore
                try:
                    proto = "udp"
                    if isinstance(address, tuple) and len(address) >= 2:
                        outer._record_flow(self, (address[0], int(address[1])), proto)
                except Exception:
                    pass
                return super().sendto(data, address)  # type: ignore

        return TracedSocket

    def enable_patch(self):
        if not self.enable or self._patched:
            return
        try:
            TracedSocket = self._wrap_socket_class()
            _socket.socket = TracedSocket  # type: ignore
            self._patched = True
        except Exception:
            self._patched = False

    def disable_patch(self):
        if self._patched:
            _socket.socket = self._orig_socket  # type: ignore
            self._patched = False

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._flows_lock:
            flows = []
            for (src, dst, sp, dp, proto), meta in self._flows.items():
                flows.append(
                    {
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": sp,
                        "dst_port": dp,
                        "proto": proto,
                        "count": meta["count"],
                        "first": meta["first"],
                        "last": meta["last"],
                    }
                )
            return flows


# -----------------------
# Rate limiter and metrics
# -----------------------

class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: int):
        self.rate = max(0.0, rate_per_sec)
        self.capacity = max(1, capacity)
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0, max_wait_ms: int = 0) -> bool:
        deadline = time.monotonic() + (max_wait_ms / 1000.0)
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = max(0.0, now - self.last)
                self.last = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))


class SlidingMetrics:
    def __init__(self, maxlen: int = 500):
        self._lock = threading.Lock()
        self._items: deque = deque(maxlen=maxlen)  # each: (base_latency, overhead, success)
        self._err_count = 0
        self._total = 0

    def record(self, base_latency: float, overhead: float, success: bool):
        with self._lock:
            self._items.append((base_latency, overhead, success))
            self._total += 1
            if not success:
                self._err_count += 1

    def p95_overhead_ratio(self) -> float:
        with self._lock:
            if not self._items:
                return 0.0
            ratios = []
            for base, ov, _ in self._items:
                denom = max(1e-6, base)
                ratios.append(ov / denom)
            ratios.sort()
            idx = int(0.95 * (len(ratios) - 1))
            return ratios[idx]

    def error_rate(self) -> float:
        with self._lock:
            total = self._total if self._total > 0 else len(self._items)
            if total == 0:
                return 0.0
            # recompute err rate in window
            err = 0
            for _, _, success in self._items:
                if not success:
                    err += 1
            return err / max(1, len(self._items))


# -----------------------
# Archival with integrity log (WORM-like)
# -----------------------

class Archive:
    def __init__(self, root: str, hmac_key: bytes, key_id: str):
        self.root = root
        self.hmac_key = hmac_key
        self.key_id = key_id
        self.log_path = os.path.join(self.root, "integrity.log")
        self._log_lock = threading.Lock()
        os.makedirs(self.root, exist_ok=True)
        # restrict directory perms
        try:
            os.chmod(self.root, 0o750)
        except Exception:
            pass

    def _seal_bundle(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "schema": "lambdatrace.v1",
            "ts": _now_iso8601(),
            "evidence": evidence,
            "key_id": self.key_id,
        }
        payload_bytes = _safe_json_dumps(payload)
        content_hash = _sha256(payload_bytes)
        sig = hmac.new(self.hmac_key, (payload["ts"] + content_hash).encode("utf-8"), hashlib.sha256).hexdigest()
        return {"payload": payload, "hash": content_hash, "signature": sig, "algo": "HMAC-SHA256"}

    def _write_file_worm(self, path: str, data: bytes):
        with open(path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # best-effort set read-only to emulate WORM
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except Exception:
            pass

    def _append_integrity_log(self, entry: Dict[str, Any]):
        # append-only integrity log with hash chaining
        with self._log_lock:
            prev_hash = ""
            try:
                if os.path.exists(self.log_path):
                    with open(self.log_path, "rb") as f:
                        f.seek(0, os.SEEK_END)
                        size = f.tell()
                        # simple: compute hash of entire log as prev anchor
                        f.seek(0)
                        prev_hash = _sha256(f.read())
            except Exception:
                prev_hash = ""
            entry2 = dict(entry)
            entry2["prev_hash"] = prev_hash
            entry_bytes = (_safe_json_dumps(entry2) + b"\n")
            # sign the log entry too
            entry_sig = hmac.new(self.hmac_key, entry_bytes, hashlib.sha256).hexdigest()
            entry2["log_sig"] = entry_sig
            final_bytes = (_safe_json_dumps(entry2) + b"\n")
            # open with O_APPEND semantics
            with open(self.log_path, "ab", buffering=0) as lf:
                lf.write(final_bytes)
                try:
                    os.fsync(lf.fileno())
                except Exception:
                    pass
            # set read-only if not already; but we need to keep append; skip chmod on log

    def store_bundle(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        sealed = self._seal_bundle(evidence)
        ts = sealed["payload"]["ts"]
        bundle_id = f"{ts.replace(':', '').replace('-', '').replace('+', '')}-{sealed['hash'][:12]}"
        fname = f"bundle-{bundle_id}.json"
        fpath = os.path.join(self.root, fname)
        self._write_file_worm(fpath, _safe_json_dumps(sealed))
        # integrity log
        self._append_integrity_log({"id": bundle_id, "ts": ts, "hash": sealed["hash"], "key_id": self.key_id})
        return {"bundle_id": bundle_id, "path": fpath, "hash": sealed["hash"], "signature": sealed["signature"], "key_id": self.key_id}

    def verify_bundle(self, path: str) -> Tuple[bool, Optional[str]]:
        try:
            with open(path, "rb") as f:
                data = f.read()
            obj = json.loads(data.decode("utf-8"))
            payload = obj["payload"]
            content_hash = _sha256(_safe_json_dumps(payload))
            if content_hash != obj.get("hash"):
                return False, "hash mismatch"
            expected_sig = hmac.new(self.hmac_key, (payload["ts"] + content_hash).encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, obj.get("signature", "")):
                return False, "signature invalid"
            return True, None
        except Exception as e:
            return False, str(e)


# -----------------------
# Snapshot capture
# -----------------------

def _summarize_tmpfs(root: str = "/tmp", max_entries: int = 200) -> Dict[str, Any]:
    summary = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            # avoid deep traversal cost; limit to top 2 levels
            depth = dirpath.count(os.sep) - root.count(os.sep)
            if depth > 2:
                continue
            for name in filenames:
                try:
                    fpath = os.path.join(dirpath, name)
                    st = os.lstat(fpath)
                    size = st.st_size
                    mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
                    # avoid PII: hash file name, keep extension
                    base, ext = os.path.splitext(name)
                    safe_name = _hash_str(base) + ext[:8]
                    summary.append({"path_hash": _hash_str(dirpath), "name": safe_name, "size": size, "mtime": mtime, "mode": st.st_mode})
                    if len(summary) >= max_entries:
                        raise StopIteration
                except StopIteration:
                    raise
                except Exception:
                    continue
    except StopIteration:
        pass
    except Exception:
        pass
    return {"root": root, "entries": summary, "count": len(summary)}


def _provider_context(context: Any) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    # AWS Lambda
    if context is not None:
        try:
            req_id = getattr(context, "aws_request_id", None)
            if req_id:
                meta["aws_request_id"] = req_id
            fname = getattr(context, "function_name", None)
            if fname:
                meta["function_name"] = fname
            arn = getattr(context, "invoked_function_arn", None)
            if arn:
                meta["invoked_function_arn"] = arn
            rem_ms = getattr(context, "get_remaining_time_in_millis", None)
            if callable(rem_ms):
                meta["remaining_time_ms"] = rem_ms()
        except Exception:
            pass
    # Common cloud hints
    for k in ["AWS_REGION", "GCP_PROJECT", "FUNCTION_REGION", "WEBSITE_SITE_NAME", "K_SERVICE", "X_GOOGLE_FUNCTION_NAME", "FUNCTION_NAME"]:
        v = os.getenv(k)
        if v:
            meta[k] = v
    return meta


# -----------------------
# Main Snapshotter
# -----------------------

class LambdaTraceSnapshotter:
    def __init__(
        self,
        enabled: bool = True,
        mode: str = "sample",  # "cold-start", "every-invoke", "sample"
        sample_rate: float = 0.2,
        rate_limit_per_sec: float = 5.0,
        rate_capacity: int = 10,
        rate_wait_ms: int = 5,
        capture_stdout: bool = True,
        capture_network: bool = True,
        network_sample_rate: float = 1.0,
        overhead_threshold_p95: float = 0.05,
        error_rate_threshold: float = 0.001,
        archive_dir: Optional[str] = None,
        hmac_key: Optional[bytes] = None,
    ):
        self.enabled = enabled
        self.mode = mode
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self.dynamic_sample_rate = self.sample_rate
        self.rate_limiter = TokenBucket(rate_limit_per_sec, rate_capacity)
        self.rate_wait_ms = max(0, rate_wait_ms)
        self.metrics = SlidingMetrics()
        self._cold = True  # cold start flag per instance
        self.stdout_cap = StdCapture(capture_stdout)
        self.net_tracer = NetTracer(capture_network, network_sample_rate)
        self.overhead_threshold_p95 = max(0.0, overhead_threshold_p95)
        self.error_rate_threshold = max(0.0, error_rate_threshold)
        # HMAC key and archive
        if hmac_key is None:
            key_env = os.getenv("LAMBDATRACE_HMAC_KEY")
            if key_env:
                hmac_key = hashlib.sha256(key_env.encode("utf-8")).digest()
            else:
                # ephemeral per instance key if none provided
                hmac_key = secrets.token_bytes(32)
        self.hmac_key = hmac_key
        key_id = _sha256(self.hmac_key)[:16]
        self.archive = Archive(archive_dir or os.getenv("LAMBDATRACE_ARCHIVE_DIR", "./lambdatrace_archive"), self.hmac_key, key_id)
        # internal lock
        self._lock = threading.Lock()

    @staticmethod
    def from_env() -> "LambdaTraceSnapshotter":
        enabled = os.getenv("LAMBDATRACE_ENABLED", "1") not in ("0", "false", "False")
        mode = os.getenv("LAMBDATRACE_MODE", "sample")
        sample_rate = float(os.getenv("LAMBDATRACE_SAMPLE_RATE", "0.2"))
        rl_ps = float(os.getenv("LAMBDATRACE_RATE_PER_SEC", "5"))
        rl_cap = int(os.getenv("LAMBDATRACE_RATE_CAPACITY", "10"))
        rl_wait = int(os.getenv("LAMBDATRACE_RATE_WAIT_MS", "5"))
        capture_stdout = os.getenv("LAMBDATRACE_CAPTURE_STDOUT", "1") not in ("0", "false", "False")
        capture_network = os.getenv("LAMBDATRACE_CAPTURE_NET", "1") not in ("0", "false", "False")
        net_sr = float(os.getenv("LAMBDATRACE_NET_SAMPLE_RATE", "1.0"))
        ovr_thr = float(os.getenv("LAMBDATRACE_OVERHEAD_P95", "0.05"))
        err_thr = float(os.getenv("LAMBDATRACE_ERR_RATE", "0.001"))
        archive_dir = os.getenv("LAMBDATRACE_ARCHIVE_DIR")
        hmac_key_env = os.getenv("LAMBDATRACE_HMAC_KEY")
        hkey = hashlib.sha256(hmac_key_env.encode("utf-8")).digest() if hmac_key_env else None
        return LambdaTraceSnapshotter(
            enabled=enabled,
            mode=mode,
            sample_rate=sample_rate,
            rate_limit_per_sec=rl_ps,
            rate_capacity=rl_cap,
            rate_wait_ms=rl_wait,
            capture_stdout=capture_stdout,
            capture_network=capture_network,
            network_sample_rate=net_sr,
            overhead_threshold_p95=ovr_thr,
            error_rate_threshold=err_thr,
            archive_dir=archive_dir,
            hmac_key=hkey,
        )

    def should_capture(self, context: Any = None) -> bool:
        if not self.enabled:
            return False
        if self.mode == "cold-start":
            if self._cold:
                self._cold = False
                # do not throttle cold-start capture
                return True
            return False
        # dynamic throttling
        sr = self.dynamic_sample_rate
        if sr > 0.0:
            if secrets.randbelow(1000000) / 1000000.0 > sr:
                return False
        # rate limit
        if not self.rate_limiter.acquire(1.0, self.rate_wait_ms):
            return False
        return True

    def _auto_throttle(self):
        p95 = self.metrics.p95_overhead_ratio()
        err = self.metrics.error_rate()
        if p95 > self.overhead_threshold_p95 or err > self.error_rate_threshold:
            # Engage throttle: reduce sample rate aggressively
            new_sr = max(0.0, min(self.dynamic_sample_rate, 0.01))
            if new_sr != self.dynamic_sample_rate:
                self.dynamic_sample_rate = new_sr
                try:
                    # use stderr to avoid interfering stdout capture
                    sys.stderr.write(f"[LambdaTrace] auto-throttle engaged: p95_overhead={p95:.4f}, err_rate={err:.4f}, sample_rate={self.dynamic_sample_rate}\n")
                except Exception:
                    pass
        else:
            # relax toward configured sample_rate
            if self.dynamic_sample_rate < self.sample_rate:
                self.dynamic_sample_rate = min(self.sample_rate, self.dynamic_sample_rate + 0.01)

    def _collect_evidence(self, context: Any = None) -> Dict[str, Any]:
        env = redact_env(dict(os.environ))
        provider_meta = _provider_context(context)
        tmpfs = _summarize_tmpfs("/tmp")
        std = self.stdout_cap.snapshot()
        flows = self.net_tracer.snapshot()
        proc_meta = {
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "argv": [redact_text(a) for a in sys.argv[:20]],
            "cwd": os.getcwd(),
            "python": sys.version.split()[0],
            "time": _now_iso8601(),
        }
        # limited /proc fd summary (non-content, count only)
        fd_count = 0
        try:
            fd_count = len(os.listdir(f"/proc/{os.getpid()}/fd"))
        except Exception:
            pass
        proc_meta["open_fd_count"] = fd_count

        return {
            "env": env,
            "provider": provider_meta,
            "process": proc_meta,
            "tmpfs": tmpfs,
            "stdout": std.get("stdout", ""),
            "stderr": std.get("stderr", ""),
            "network_flows": flows,
        }

    def wrap_handler(self, handler):
        # advisory: injection only on enabled; tee and net tracer minimal overhead
        def wrapped(event, context):
            # capture decision at entry, but capture content after
            capture_now = self.should_capture(context)
            if capture_now:
                self.stdout_cap.start()
                self.net_tracer.enable_patch()
            start = time.perf_counter()
            success = True
            try:
                res = handler(event, context)
                return res
            except Exception:
                success = False
                raise
            finally:
                end = time.perf_counter()
                base_latency = end - start
                overhead = 0.0
                if capture_now:
                    o_start = time.perf_counter()
                    try:
                        evidence = self._collect_evidence(context)
                        self.stdout_cap.stop()
                        self.net_tracer.disable_patch()
                        self.archive.store_bundle(evidence)
                    except Exception as e:
                        try:
                            sys.stderr.write(f"[LambdaTrace] capture/store error: {e}\n")
                        except Exception:
                            pass
                    finally:
                        o_end = time.perf_counter()
                        overhead = o_end - o_start
                self.metrics.record(base_latency=base_latency, overhead=overhead, success=success)
                self._auto_throttle()
        return wrapped

    # Convenience API for non-decorator usage
    def capture_now(self, context: Any = None) -> Optional[Dict[str, Any]]:
        if not self.should_capture(context):
            return None
        self.stdout_cap.start()
        self.net_tracer.enable_patch()
        try:
            evidence = self._collect_evidence(context)
            return self.archive.store_bundle(evidence)
        finally:
            self.stdout_cap.stop()
            self.net_tracer.disable_patch()


# -------------
# Utilities API
# -------------

def instrument(handler):
    snap = LambdaTraceSnapshotter.from_env()
    return snap.wrap_handler(handler)


def verify_bundle(path: str) -> Tuple[bool, Optional[str]]:
    snap = LambdaTraceSnapshotter.from_env()
    return snap.archive.verify_bundle(path)


def transfer_and_verify(src_path: str, dest_dir: str) -> Tuple[str, bool, Optional[str]]:
    """
    Simulate transfer to archival storage (copy file) and verify integrity there.
    Returns (dest_path, ok, err)
    """
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.basename(src_path)
    dest_path = os.path.join(dest_dir, base)
    with open(src_path, "rb") as fsrc, open(dest_path, "wb") as fdst:
        while True:
            buf = fsrc.read(65536)
            if not buf:
                break
            fdst.write(buf)
    # verify
    ok, err = verify_bundle(dest_path)
    return dest_path, ok, err


# -------------
# Example note
# -------------
# To use in AWS Lambda (or similar):
# from tools.forensics.lambdatrace_snapshotter import instrument
# @instrument
# def handler(event, context):
#     print("Hello")
#     return {"ok": True}
#
# Or programmatic:
# snap = LambdaTraceSnapshotter.from_env()
# handler = snap.wrap_handler(handler)