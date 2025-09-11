import os
import io
import json
import time
import socket
import queue
import hashlib
import threading
import tempfile
import statistics
import contextlib
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

lt = pytest.importorskip("tools.forensics.lambdatrace_snapshotter", reason="LambdaTrace snapshotter module not available")
SnapshotterClass = getattr(lt, "LambdaTraceSnapshotter", None)
if SnapshotterClass is None:
    SnapshotterClass = getattr(lt, "Snapshotter", None)


@pytest.fixture(scope="function")
def in_memory_worm_archive(monkeypatch):
    class InMemoryWORMArchive:
        def __init__(self):
            self._store = {}
            self._integrity_logs = {}
            self._lock = threading.Lock()

        def write_once(self, bundle):
            # Expect bundle to have id and content (dict)
            if isinstance(bundle, dict):
                bundle_id = bundle.get("id") or bundle.get("bundle_id") or hashlib.sha256(
                    json.dumps(bundle, sort_keys=True, default=str).encode()
                ).hexdigest()
                bundle["id"] = bundle_id
                content = json.dumps(bundle, sort_keys=True, default=str).encode()
            elif isinstance(bundle, (bytes, bytearray)):
                content = bytes(bundle)
                bundle_id = hashlib.sha256(content).hexdigest()
            else:
                # unknown type; convert to bytes via repr
                content = repr(bundle).encode()
                bundle_id = hashlib.sha256(content).hexdigest()

            with self._lock:
                if bundle_id in self._store:
                    raise RuntimeError("WORM violation: bundle already archived")
                self._store[bundle_id] = content
                entry = {
                    "event": "archive_write",
                    "bundle_id": bundle_id,
                    "hash": hashlib.sha256(content).hexdigest(),
                    "ts": time.time(),
                }
                self._integrity_logs.setdefault(bundle_id, []).append(entry)
            return f"worm://{bundle_id}"

        def read(self, uri):
            bundle_id = uri.split("://", 1)[-1]
            with self._lock:
                content = self._store[bundle_id]
            try:
                return json.loads(content.decode())
            except Exception:
                return content

        def tamper(self, uri, mutate_fn):
            bundle_id = uri.split("://", 1)[-1]
            with self._lock:
                original = self._store[bundle_id]
                mutated = mutate_fn(original)
                self._store[bundle_id] = mutated
                self._integrity_logs.setdefault(bundle_id, []).append(
                    {
                        "event": "tamper",
                        "bundle_id": bundle_id,
                        "hash": hashlib.sha256(mutated).hexdigest(),
                        "ts": time.time(),
                    }
                )

        def integrity_log(self, bundle_id_or_uri):
            if "://" in str(bundle_id_or_uri):
                bundle_id = str(bundle_id_or_uri).split("://", 1)[-1]
            else:
                bundle_id = str(bundle_id_or_uri)
            return list(self._integrity_logs.get(bundle_id, []))

    archive = InMemoryWORMArchive()
    return archive


@pytest.fixture(scope="function")
def tsa_stub(monkeypatch):
    # If module defines external TSA, mock it to avoid network and ensure deterministic timestamp/signature
    tsa_attr_candidates = [
        "get_trusted_timestamp",
        "cryptographic_timestamp",
        "rfc3161_timestamp",
        "tsa_request",
    ]
    for name in tsa_attr_candidates:
        if hasattr(lt, name):
            def _tsa_stub(data=None):
                payload = b"" if data is None else (json.dumps(data, sort_keys=True, default=str).encode()
                                                    if not isinstance(data, (bytes, bytearray)) else bytes(data))
                ts = 1700000000.0  # fixed time for test stability
                sig = hashlib.sha256(payload + b"::" + str(ts).encode()).hexdigest()
                return {"timestamp": ts, "tsa_signature": sig}
            monkeypatch.setattr(lt, name, _tsa_stub)
    return True


@pytest.fixture(scope="function")
def local_echo_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(200)
    server_sock.settimeout(0.5)
    host, port = server_sock.getsockname()
    stop_event = threading.Event()

    def serve():
        while not stop_event.is_set():
            try:
                conn, addr = server_sock.accept()
            except socket.timeout:
                continue
            with conn:
                try:
                    _ = conn.recv(8192)
                    conn.sendall(b"ok")
                except Exception:
                    pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield host, port
    stop_event.set()
    try:
        # poke server to unblock accept
        s = socket.create_connection((host, port), timeout=0.2)
        s.close()
    except Exception:
        pass
    try:
        server_sock.close()
    except Exception:
        pass
    t.join(timeout=1.0)


def _get_snapshotter(archive_backend=None, **kwargs):
    if SnapshotterClass is None:
        pytest.skip("No Snapshotter class found in module")
    try:
        s = SnapshotterClass(archive_backend=archive_backend, **kwargs)
    except TypeError:
        # Older or different signature
        try:
            s = SnapshotterClass(**kwargs)
            if hasattr(s, "set_archive_backend"):
                s.set_archive_backend(archive_backend)
            elif hasattr(s, "archive_backend"):
                setattr(s, "archive_backend", archive_backend)
        except Exception as e:
            pytest.skip(f"Unable to instantiate snapshotter: {e}")
    return s


def _wrap_function(snapshotter, func):
    if snapshotter is None:
        return func
    if hasattr(snapshotter, "wrap") and callable(getattr(snapshotter, "wrap")):
        return snapshotter.wrap(func)
    if hasattr(snapshotter, "instrument") and callable(getattr(snapshotter, "instrument")):
        return snapshotter.instrument(func)
    # Fallback: use context-managed capture per-call if available
    def wrapper(*args, **kwargs):
        ctx = None
        if hasattr(snapshotter, "__enter__") and hasattr(snapshotter, "__exit__"):
            ctx = snapshotter.__enter__()
        try:
            return func(*args, **kwargs)
        finally:
            if ctx is not None:
                try:
                    snapshotter.__exit__(None, None, None)
                except Exception:
                    pass
    return wrapper


def _get_bundles(snapshotter):
    # Try common accessors
    for name in ("list_bundles", "get_bundles", "get_evidence_bundles"):
        if hasattr(snapshotter, name) and callable(getattr(snapshotter, name)):
            try:
                bundles = getattr(snapshotter, name)()
                if bundles is not None:
                    return bundles
            except Exception:
                pass
    if hasattr(snapshotter, "bundles"):
        return getattr(snapshotter, "bundles")
    if hasattr(snapshotter, "evidence_bundles"):
        return getattr(snapshotter, "evidence_bundles")
    return []


def _verify_bundle(snapshotter, bundle_or_uri):
    for name in ("verify_bundle", "verify", "integrity_check"):
        if hasattr(snapshotter, name) and callable(getattr(snapshotter, name)):
            return bool(getattr(snapshotter, name)(bundle_or_uri))
    # Fallback: structural check
    try:
        data = bundle_or_uri
        if isinstance(bundle_or_uri, str) and bundle_or_uri.startswith("worm://"):
            if hasattr(snapshotter, "archive_backend"):
                data = snapshotter.archive_backend.read(bundle_or_uri)
        digest = data.get("hash") or data.get("signature")
        ts = data.get("timestamp")
        return bool(digest and ts)
    except Exception:
        return False


def _tamper_detected(snapshotter, bundle_or_uri):
    for name in ("tamper_detected", "is_tampered"):
        if hasattr(snapshotter, name) and callable(getattr(snapshotter, name)):
            return bool(getattr(snapshotter, name)(bundle_or_uri))
    # Fallback: invert verify
    return not _verify_bundle(snapshotter, bundle_or_uri)


def _extract_field(bundle, *candidates):
    if bundle is None:
        return None
    if isinstance(bundle, str):
        # probably a URI
        return None
    for key in candidates:
        if isinstance(bundle, dict) and key in bundle:
            return bundle[key]
    # Nested?
    if isinstance(bundle, dict):
        meta = bundle.get("metadata") or bundle.get("meta") or {}
        if isinstance(meta, dict):
            for key in candidates:
                if key in meta:
                    return meta[key]
    return None


def _percentile(data, p):
    if not data:
        return 0.0
    data_sorted = sorted(data)
    k = int(round((p / 100.0) * (len(data_sorted) - 1)))
    return data_sorted[k]


def _run_workload(fn, total_calls, concurrency):
    latencies = []
    errors = 0
    lock = threading.Lock()

    def task(i):
        nonlocal errors
        t0 = time.perf_counter()
        try:
            fn(i)
        except Exception:
            with lock:
                errors += 1
        finally:
            t1 = time.perf_counter()
            with lock:
                latencies.append(t1 - t0)

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(task, i) for i in range(total_calls)]
        for _ in as_completed(futures):
            pass

    return latencies, errors


def _prepare_test_function(server_host, server_port, tmp_dir):
    def test_func(i):
        # Emit to stdout/stderr
        print(f"work-{i}: user_email=user{i}@example.com TOKEN=tok_{i}")
        with contextlib.redirect_stderr(io.StringIO()) as _:
            print(f"error-{i}: PASSWORD=Secr3t!", file=io.StringIO())
        # Write to tmpfs
        tmp_file = os.path.join(tmp_dir, f"tmp_{i}.txt")
        with open(tmp_file, "w") as f:
            f.write("this is temporary content that should be summarized not stored verbatim\n")
        # Network connect to localhost
        with socket.create_connection((server_host, server_port), timeout=0.5) as s:
            s.sendall(b"hello")
            _ = s.recv(32)
        # Simulate work
        time.sleep(0.01)
        return i
    return test_func


@pytest.mark.skipif(SnapshotterClass is None, reason="Snapshotter class not available")
def test_capture_under_load_and_bundle_sealing(in_memory_worm_archive, tsa_stub, local_echo_server, monkeypatch, tmp_path):
    # Configure environment with PII to test redaction
    os.environ["TEST_PASSWORD"] = "S3cr3t!"
    os.environ["TEST_SSN"] = "123-45-6789"
    os.environ["SAFE_VAR"] = "SAFE_VALUE"
    # Create snapshotter configured to capture all targets with filters/redaction
    snapshotter = _get_snapshotter(
        in_memory_worm_archive,
        sampling_rate=1.0,
        cold_start_only=False,
        rate_limit_per_sec=1000,
        backpressure_queue_size=1000,
        enable_stdout=True,
        enable_stderr=True,
        enable_env=True,
        enable_tmpfs=True,
        enable_network=True,
        pii_redaction=True,
    )

    # Ensure snapshotter started if required
    if hasattr(snapshotter, "start"):
        snapshotter.start()

    host, port = local_echo_server
    test_tmp_dir = tmp_path / "tmpfs"
    test_tmp_dir.mkdir(parents=True, exist_ok=True)
    fn = _prepare_test_function(host, port, str(test_tmp_dir))
    wrapped = _wrap_function(snapshotter, fn)

    total = 120
    conc = 50
    _run_workload(wrapped, total, conc)

    # Stop snapshotter if necessary
    if hasattr(snapshotter, "stop"):
        snapshotter.stop()

    bundles = _get_bundles(snapshotter)
    assert bundles is not None
    assert len(bundles) >= 1

    # Choose latest or last
    bundle = bundles[-1] if isinstance(bundles, (list, tuple)) else bundles

    # Validate fields exist
    # Env variables filtered
    env = _extract_field(bundle, "env", "environment", "env_vars")
    assert isinstance(env, dict)
    # secrets should be masked or removed
    for secret_key in ("TEST_PASSWORD", "TEST_SSN"):
        if secret_key in env:
            assert env[secret_key] not in ("S3cr3t!", "123-45-6789")
            assert env[secret_key] in (None, "", "***", "[REDACTED]", "[MASKED]") or "REDACT" in str(env[secret_key]).upper()

    # tmpfs summaries captured (no content)
    tmpfs = _extract_field(bundle, "tmpfs", "tmp", "tmpfs_summary")
    assert tmpfs is not None
    # Expect counts and sizes, not raw content
    if isinstance(tmpfs, dict):
        assert ("files" in tmpfs or "count" in tmpfs or "summary" in tmpfs)
    elif isinstance(tmpfs, list):
        # if list of files, ensure they are metadata only
        for entry in tmpfs:
            assert isinstance(entry, dict)
            assert "path" in entry
            assert "size" in entry or "hash" in entry
            assert "content" not in entry

    # stdout/stderr summaries
    stdout = _extract_field(bundle, "stdout", "stdout_summary")
    stderr = _extract_field(bundle, "stderr", "stderr_summary")
    assert stdout is not None
    assert stderr is not None
    # redact tokens/passwords
    for stream in (stdout, stderr):
        stream_str = json.dumps(stream, default=str) if not isinstance(stream, str) else stream
        assert "Secr3t!" not in stream_str
        assert "tok_" not in stream_str

    # network 5-tuples
    net = _extract_field(bundle, "network", "net", "connections", "flows")
    assert net is not None
    flows = net if isinstance(net, list) else net.get("flows", [])
    assert isinstance(flows, list)
    found = False
    for f in flows:
        # Accept either dict or tuple representation
        if isinstance(f, dict):
            dip = f.get("dst_ip") or f.get("destination_ip") or f.get("daddr")
            dpt = f.get("dst_port") or f.get("destination_port") or f.get("dport")
            proto = f.get("protocol") or f.get("proto")
        else:
            # assume tuple: (src_ip, src_port, dst_ip, dst_port, protocol)
            try:
                _, _, dip, dpt, proto = f
            except Exception:
                continue
        if str(dip) in ("127.0.0.1", "localhost") and int(dpt) == port and str(proto).upper() in ("TCP", "6"):
            found = True
            break
    assert found, "Expected localhost connection 5-tuple not found in evidence"

    # Sealed evidence bundle
    ts = _extract_field(bundle, "timestamp", "sealed_timestamp")
    sig = _extract_field(bundle, "signature", "sig", "seal_signature")
    assert ts is not None
    assert sig is not None
    assert _verify_bundle(snapshotter, bundle)


@pytest.mark.skipif(SnapshotterClass is None, reason="Snapshotter class not available")
def test_archive_integrity_and_tamper_detection(in_memory_worm_archive, tsa_stub, tmp_path, local_echo_server):
    snapshotter = _get_snapshotter(
        in_memory_worm_archive,
        sampling_rate=1.0,
        cold_start_only=True,
        rate_limit_per_sec=1000,
        backpressure_queue_size=1000,
        enable_env=True,
        enable_tmpfs=True,
        enable_network=False,
        pii_redaction=True,
    )

    # Create one bundle via a single call
    host, port = local_echo_server
    test_tmp_dir = tmp_path / "tmpfs2"
    test_tmp_dir.mkdir(parents=True, exist_ok=True)
    fn = _prepare_test_function(host, port, str(test_tmp_dir))
    wrapped = _wrap_function(snapshotter, fn)

    if hasattr(snapshotter, "start"):
        snapshotter.start()
    wrapped(0)
    if hasattr(snapshotter, "stop"):
        snapshotter.stop()

    bundles = _get_bundles(snapshotter)
    assert bundles and len(bundles) >= 1
    bundle = bundles[0]

    # Seal and archive
    archive_uri = None
    if hasattr(snapshotter, "seal_and_archive"):
        archive_uri = snapshotter.seal_and_archive(bundle)
    else:
        # fallback: direct write_once via archive backend
        assert hasattr(snapshotter, "archive_backend"), "snapshotter missing archive backend for archival test"
        archive_uri = snapshotter.archive_backend.write_once(bundle)

    assert archive_uri and str(archive_uri).startswith("worm://")

    # Integrity check passes after transfer
    assert _verify_bundle(snapshotter, archive_uri)

    # Tamper and detect
    def mutate(content_bytes):
        try:
            d = json.loads(content_bytes.decode())
            # Tamper env or timestamp
            if "env" in d:
                d["env"]["SAFE_VAR"] = "TAMPERED"
            else:
                d["timestamp"] = 0
            return json.dumps(d, sort_keys=True).encode()
        except Exception:
            return content_bytes + b"!tamper"

    in_memory_worm_archive.tamper(archive_uri, mutate)
    assert not _verify_bundle(snapshotter, archive_uri)
    assert _tamper_detected(snapshotter, archive_uri)

    # WORM should reject overwrite of same bundle id
    with pytest.raises(Exception):
        # Read tampered content and attempt to write again should fail due to same id
        content = in_memory_worm_archive.read(archive_uri)
        in_memory_worm_archive.write_once(content)

    # Integrity log must have entries
    bundle_id = str(archive_uri).split("://", 1)[-1]
    log = in_memory_worm_archive.integrity_log(bundle_id)
    assert isinstance(log, list)
    assert any(e.get("event") == "archive_write" for e in log)
    assert any(e.get("event") == "tamper" for e in log)


@pytest.mark.skipif(SnapshotterClass is None, reason="Snapshotter class not available")
def test_performance_overhead_and_auto_throttle(in_memory_worm_archive, tsa_stub, local_echo_server, tmp_path):
    host, port = local_echo_server
    tmp_dir = tmp_path / "tmpfs3"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    base_fn = _prepare_test_function(host, port, str(tmp_dir))

    total = 400
    conc = 50

    # Baseline
    base_latencies, base_errors = _run_workload(base_fn, total, conc)
    base_median = statistics.median(base_latencies)
    base_p95 = _percentile(base_latencies, 95)
    base_error_rate = base_errors / total

    # With capture - low sampling to minimize overhead and low rate limit to trigger auto-throttle
    snapshotter = _get_snapshotter(
        in_memory_worm_archive,
        sampling_rate=0.05,  # 5% sampling
        cold_start_only=False,
        rate_limit_per_sec=10,  # low to cause throttle at conc=50
        backpressure_queue_size=5,
        enable_env=True,
        enable_tmpfs=True,
        enable_network=False,  # skip network for perf run
        pii_redaction=True,
    )
    if hasattr(snapshotter, "start"):
        snapshotter.start()
    wrapped = _wrap_function(snapshotter, base_fn)
    cap_latencies, cap_errors = _run_workload(wrapped, total, conc)
    if hasattr(snapshotter, "stop"):
        snapshotter.stop()

    cap_median = statistics.median(cap_latencies)
    cap_p95 = _percentile(cap_latencies, 95)
    cap_error_rate = cap_errors / total

    # Overhead constraints: median and p95 increase <= 5%
    # Allow some slack for CI jitter, compare ratios
    median_increase = (cap_median - base_median) / base_median if base_median > 0 else 0.0
    p95_increase = (cap_p95 - base_p95) / base_p95 if base_p95 > 0 else 0.0
    assert median_increase <= 0.05 + 0.02  # 2% slack
    assert p95_increase <= 0.05 + 0.03  # 3% slack

    # Error rate increase <= 0.1%
    err_increase = cap_error_rate - base_error_rate
    assert err_increase <= 0.001 + 0.001  # add 0.1% slack

    # Auto-throttle engages when thresholds exceeded
    metrics = {}
    for name in ("get_metrics", "metrics", "performance_metrics"):
        if hasattr(snapshotter, name):
            m = getattr(snapshotter, name)
            metrics = m() if callable(m) else m
            break
    # Look for throttling indicators
    throttled_keys = ("auto_throttle_engaged", "throttled", "dropped_captures", "rate_limited")
    assert any(bool(metrics.get(k)) for k in throttled_keys if isinstance(metrics, dict)) or len(_get_bundles(snapshotter)) < total * 0.5


@pytest.mark.skipif(SnapshotterClass is None, reason="Snapshotter class not available")
def test_redaction_policy_applied(in_memory_worm_archive, tsa_stub, tmp_path):
    os.environ["ACCESS_TOKEN"] = "tok-secret"
    os.environ["API_KEY"] = "key-secret"
    os.environ["NON_PII"] = "ok"

    snapshotter = _get_snapshotter(
        in_memory_worm_archive,
        sampling_rate=1.0,
        pii_redaction=True,
        enable_env=True,
        enable_tmpfs=False,
        enable_network=False,
        cold_start_only=True,
    )

    def simple():
        print("emit PII ACCESS_TOKEN and API_KEY should be redacted")

    wrapped = _wrap_function(snapshotter, lambda _: simple())
    if hasattr(snapshotter, "start"):
        snapshotter.start()
    wrapped(0)
    if hasattr(snapshotter, "stop"):
        snapshotter.stop()

    bundles = _get_bundles(snapshotter)
    assert bundles
    env = _extract_field(bundles[-1] if isinstance(bundles, list) else bundles, "env", "environment", "env_vars")
    assert isinstance(env, dict)
    for k in ("ACCESS_TOKEN", "API_KEY"):
        if k in env:
            assert env[k] not in ("tok-secret", "key-secret")
            assert env[k] in (None, "", "***", "[REDACTED]", "[MASKED]") or "REDACT" in str(env[k]).upper()


@pytest.mark.skipif(SnapshotterClass is None, reason="Snapshotter class not available")
def test_cold_start_only_mode_captures_once(in_memory_worm_archive, tsa_stub):
    snapshotter = _get_snapshotter(
        in_memory_worm_archive,
        sampling_rate=1.0,
        cold_start_only=True,
        enable_env=False,
        enable_tmpfs=False,
        enable_network=False,
    )

    def work(i):
        return i

    wrapped = _wrap_function(snapshotter, work)
    if hasattr(snapshotter, "start"):
        snapshotter.start()
    for i in range(10):
        wrapped(i)
    if hasattr(snapshotter, "stop"):
        snapshotter.stop()

    bundles = _get_bundles(snapshotter)
    # Expect at most one capture in cold-start-only mode
    assert len(bundles) <= 1


@pytest.mark.skipif(SnapshotterClass is None, reason="Snapshotter class not available")
def test_backpressure_drops_and_recovery(in_memory_worm_archive, tsa_stub, tmp_path):
    snapshotter = _get_snapshotter(
        in_memory_worm_archive,
        sampling_rate=1.0,
        cold_start_only=False,
        rate_limit_per_sec=1,
        backpressure_queue_size=0,
        enable_env=False,
        enable_tmpfs=False,
        enable_network=False,
    )

    def fast_fn(i):
        # Almost no work to generate pressure
        return i

    wrapped = _wrap_function(snapshotter, fast_fn)
    if hasattr(snapshotter, "start"):
        snapshotter.start()
    lat, err = _run_workload(wrapped, 200, 50)
    if hasattr(snapshotter, "stop"):
        snapshotter.stop()
    assert err == 0

    metrics = {}
    for name in ("get_metrics", "metrics", "performance_metrics"):
        if hasattr(snapshotter, name):
            m = getattr(snapshotter, name)
            metrics = m() if callable(m) else m
            break
    # Expect drops/backpressure indicated
    drop_keys = ("dropped_captures", "backpressure_drops", "backpressure_engaged")
    assert any(bool(metrics.get(k)) for k in drop_keys if isinstance(metrics, dict)) or len(_get_bundles(snapshotter)) < 10


@pytest.mark.skipif(SnapshotterClass is None, reason="Snapshotter class not available")
def test_verify_fails_on_signature_tamper(in_memory_worm_archive, tsa_stub, tmp_path):
    snapshotter = _get_snapshotter(
        in_memory_worm_archive,
        sampling_rate=1.0,
        cold_start_only=True,
        enable_env=False,
        enable_tmpfs=False,
        enable_network=False,
    )

    def do(_):
        return None

    wrapped = _wrap_function(snapshotter, do)
    if hasattr(snapshotter, "start"):
        snapshotter.start()
    wrapped(0)
    if hasattr(snapshotter, "stop"):
        snapshotter.stop()

    bundles = _get_bundles(snapshotter)
    assert bundles
    b = bundles[0] if isinstance(bundles, list) else bundles
    # Tamper signature field
    if isinstance(b, dict):
        b2 = dict(b)
        if "signature" in b2:
            b2["signature"] = "00" * 32
        elif "sig" in b2:
            b2["sig"] = "00" * 32
        else:
            b2["hash"] = "00" * 32
        assert not _verify_bundle(snapshotter, b2)
        assert _tamper_detected(snapshotter, b2)