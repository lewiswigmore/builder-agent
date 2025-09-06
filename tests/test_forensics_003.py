import io
import json
import os
import hashlib
import base64
import time
from pathlib import Path
import pytest

import tools.forensics.container_forensic_collector as cfc_mod
from tools.forensics.container_forensic_collector import ContainerForensicCollector


class FakeRuntime:
    def __init__(self, overlay_root: Path, has_ebpf=True, mounts_with_secrets=True):
        self.overlay_root = overlay_root
        self._has_ebpf = has_ebpf
        self.mounts_with_secrets = mounts_with_secrets
        self.readonly_mount_calls = []
        self._restart_counts = {}
        self._ooms = []
        self._namespaced = []
        self._cgroup_paths = {}
        self._containers = set()
        self._process_lists = {}
        self._mounts = {}

    def register_container(self, container_id: str, cgroup_path: str = "/sys/fs/cgroup/fake.slice"):
        self._containers.add(container_id)
        self._restart_counts.setdefault(container_id, 0)
        self._cgroup_paths[container_id] = cgroup_path
        self._process_lists[container_id] = [
            {"pid": 101, "name": "init", "ns": "pid", "cgroup": cgroup_path},
            {"pid": 202, "name": "worker", "ns": "pid", "cgroup": cgroup_path},
        ]
        secrets_mounts = [
            {"source": "/run/secrets", "target": "/run/secrets", "type": "tmpfs"},
            {"source": "/var/run/secrets", "target": "/var/run/secrets", "type": "tmpfs"},
        ] if self.mounts_with_secrets else []
        self._mounts[container_id] = [
            {"source": str(self.overlay_root), "target": "/", "type": "overlay"},
            *secrets_mounts,
        ]

    def get_container_status(self, container_id: str):
        if container_id not in self._containers:
            raise cfc_mod.ContainerNotFoundError(container_id) if hasattr(cfc_mod, "ContainerNotFoundError") else FileNotFoundError(container_id)
        return {"running": True, "restart_count": self._restart_counts.get(container_id, 0)}

    def get_overlay_fs_path(self, container_id: str):
        if container_id not in self._containers:
            raise cfc_mod.ContainerNotFoundError(container_id) if hasattr(cfc_mod, "ContainerNotFoundError") else FileNotFoundError(container_id)
        return str(self.overlay_root)

    def list_processes(self, container_id: str, namespaces=True, cgroup_only=True):
        if container_id not in self._containers:
            raise cfc_mod.ContainerNotFoundError(container_id) if hasattr(cfc_mod, "ContainerNotFoundError") else FileNotFoundError(container_id)
        return list(self._process_lists[container_id])

    def list_mounts(self, container_id: str):
        if container_id not in self._containers:
            raise cfc_mod.ContainerNotFoundError(container_id) if hasattr(cfc_mod, "ContainerNotFoundError") else FileNotFoundError(container_id)
        return list(self._mounts[container_id])

    def mount_readonly_ns(self, source: str, target: str, namespace=True):
        self.readonly_mount_calls.append({"source": source, "target": target, "namespace": namespace, "flags": ["ro"]})
        self._namespaced.append(namespace)
        return True

    def has_ebpf(self):
        return self._has_ebpf

    def get_cgroup_path(self, container_id: str):
        if container_id not in self._containers:
            raise cfc_mod.ContainerNotFoundError(container_id) if hasattr(cfc_mod, "ContainerNotFoundError") else FileNotFoundError(container_id)
        return self._cgroup_paths[container_id]


class FakeSigner:
    def __init__(self):
        self.signed = []

    def sign(self, data: bytes):
        digest = hashlib.sha256(data).hexdigest().encode()
        sig = b"SIG:" + digest
        self.signed.append({"data_hash": digest.decode(), "signature": sig})
        return sig

    def verify(self, data: bytes, signature: bytes):
        return signature == self.sign(data)


class FakeEncrypter:
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
        self.calls = []

    def encrypt(self, data: bytes, key: bytes, aad: bytes = b""):
        self.calls.append({"len": len(data), "aad": aad, "key": key})
        if self.should_fail or not key:
            raise ValueError("Invalid operator key")
        payload = base64.b64encode(data)
        return b"ENC:" + base64.b64encode(key) + b":" + payload


class FakeProbe:
    def __init__(self):
        self.rate_limit = None
        self.started = False
        self.stopped = False
        self._overhead = 0.8  # percent
        self._mem_peak_mb = 32
        self._events_sampled = 0
        self._cgroup = None

    def attach(self, cgroup_path: str):
        self._cgroup = cgroup_path
        return True

    def apply_rate_limit(self, events_per_sec: int):
        self.rate_limit = events_per_sec

    def start(self):
        self.started = True
        self._events_sampled = 10000

    def stop(self):
        self.stopped = True

    def stats(self):
        return {"overhead_percent": self._overhead, "memory_peak_mb": self._mem_peak_mb, "events_sampled": self._events_sampled, "cgroup": self._cgroup}

    def set_high_cpu(self):
        # Simulate that without rate limit, overhead would be higher
        self._overhead = 1.4
        self._mem_peak_mb = 48

    def set_oomy(self):
        self._mem_peak_mb = 4096


def _get_field(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


@pytest.fixture
def setup_environment(tmp_path, monkeypatch):
    # Create deterministic overlay filesystem
    overlay_root = tmp_path / "overlay"
    (overlay_root / "etc").mkdir(parents=True)
    (overlay_root / "app").mkdir(parents=True)
    (overlay_root / "run" / "secrets").mkdir(parents=True)
    (overlay_root / "var" / "run" / "secrets").mkdir(parents=True)
    files = {
        overlay_root / "etc" / "config.yml": b"name: test\nversion: 1\n",
        overlay_root / "app" / "main.py": b"print('hello')\n",
        overlay_root / "run" / "secrets" / "token": b"super-secret-token\n",
        overlay_root / "var" / "run" / "secrets" / "db_pass": b"p@ssw0rd\n",
    }
    for p, data in files.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (1_700_000_000, 1_700_000_000))  # stable timestamp

    # Instantiate fakes
    runtime = FakeRuntime(overlay_root=overlay_root, has_ebpf=True, mounts_with_secrets=True)
    signer = FakeSigner()
    encrypter = FakeEncrypter()
    probe = FakeProbe()

    # Prepare collector and monkeypatch internals if present
    container_id = "abc123"
    runtime.register_container(container_id)

    # Monkeypatch module-level components if they exist
    if hasattr(cfc_mod, "Runtime"):
        monkeypatch.setattr(cfc_mod, "Runtime", lambda *a, **k: runtime)
    if hasattr(cfc_mod, "Signer"):
        monkeypatch.setattr(cfc_mod, "Signer", lambda *a, **k: signer)
    if hasattr(cfc_mod, "Encrypter"):
        monkeypatch.setattr(cfc_mod, "Encrypter", lambda *a, **k: encrypter)
    if hasattr(cfc_mod, "EBPFProbe"):
        monkeypatch.setattr(cfc_mod, "EBPFProbe", lambda *a, **k: probe)

    collector = ContainerForensicCollector()

    # Try to inject fakes into instance
    for name, fake in (("runtime", runtime), ("signer", signer), ("encrypter", encrypter), ("probe", probe)):
        if hasattr(collector, f"set_{name}"):
            getattr(collector, f"set_{name}")(fake)
        elif hasattr(collector, name):
            setattr(collector, name, fake)

    return {
        "collector": collector,
        "runtime": runtime,
        "signer": signer,
        "encrypter": encrypter,
        "probe": probe,
        "container_id": container_id,
        "overlay_root": overlay_root,
        "tmp_path": tmp_path,
    }


def test_acquire_overlay_and_process_list_signed_and_stable_manifest(setup_environment, tmp_path):
    env = setup_environment
    collector = env["collector"]
    runtime = env["runtime"]
    signer = env["signer"]
    container_id = env["container_id"]

    policy = {
        "scope": {"include": ["/", "/proc"], "exclude": ["/run/secrets", "/var/run/secrets"]},
        "redact": {"paths": ["/run/secrets", "/var/run/secrets"]},
    }
    operator_key = b"unit-test-operator-key"
    rate_limit = {"max_events_per_sec": 5000}

    # First collection
    result1 = collector.collect(
        container_id=container_id,
        policy=policy,
        operator_key=operator_key,
        output_dir=str(tmp_path / "out1"),
        rate_limit=rate_limit,
        overhead_threshold_percent=2.0,
    )
    # Second collection (same inputs) to test reproducible manifest
    result2 = collector.collect(
        container_id=container_id,
        policy=policy,
        operator_key=operator_key,
        output_dir=str(tmp_path / "out2"),
        rate_limit=rate_limit,
        overhead_threshold_percent=2.0,
    )

    # Ensure no restart occurred
    status = runtime.get_container_status(container_id)
    assert status["restart_count"] == 0

    # Ensure read-only namespaced mounts used at least once
    assert len(runtime.readonly_mount_calls) >= 1
    assert all("ro" in call["flags"] for call in runtime.readonly_mount_calls)
    assert any(call["namespace"] is True for call in runtime.readonly_mount_calls)

    # Evidence is signed
    bundle_bytes_1 = _get_field(result1, "bundle_bytes") or (Path(_get_field(result1, "bundle_path")).read_bytes() if _get_field(result1, "bundle_path") else None)
    signature_1 = _get_field(result1, "signature") or _get_field(result1, "metadata", {}).get("signature") if isinstance(_get_field(result1, "metadata"), dict) else None
    assert bundle_bytes_1 is not None, "Collector should return bundle bytes or path"
    assert signature_1 is not None, "Signature expected"
    assert signature_1.startswith(b"SIG:")
    # Our FakeSigner signs deterministically; verifying consistency
    assert signer.verify(bundle_bytes_1, signature_1)

    # Reproducible manifest check
    manifest1 = _get_field(result1, "manifest") or _get_field(result1, "metadata", {}).get("manifest")
    manifest2 = _get_field(result2, "manifest") or _get_field(result2, "metadata", {}).get("manifest")
    assert manifest1 is not None and manifest2 is not None, "Manifest expected in results"
    # Hash-stable manifest
    def manifest_hash(m):
        data = json.dumps(m, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(data).hexdigest()
    assert manifest_hash(manifest1) == manifest_hash(manifest2)

    # Manifest should include process list and overlay fs entries (excluding secrets)
    mf_paths = json.dumps(manifest1).lower()
    assert "process" in mf_paths or "proc" in mf_paths
    assert "/run/secrets" not in mf_paths and "/var/run/secrets" not in mf_paths


def test_probe_rate_limiting_under_high_cpu_no_oom(setup_environment, tmp_path):
    env = setup_environment
    collector = env["collector"]
    runtime = env["runtime"]
    probe = env["probe"]
    container_id = env["container_id"]

    # Simulate high-CPU workload via probe behavior
    probe.set_high_cpu()

    policy = {
        "scope": {"include": ["/"], "exclude": ["/run/secrets", "/var/run/secrets"]},
    }
    operator_key = b"unit-test-operator-key"
    rate_limit = {"max_events_per_sec": 2000}

    result = collector.collect(
        container_id=container_id,
        policy=policy,
        operator_key=operator_key,
        output_dir=str(tmp_path / "load"),
        rate_limit=rate_limit,
        overhead_threshold_percent=2.0,
    )

    # Ensure probe rate limit was applied and attached to container's cgroup
    stats = probe.stats()
    assert probe.rate_limit is not None and probe.rate_limit <= rate_limit["max_events_per_sec"]
    assert stats["cgroup"] == runtime.get_cgroup_path(container_id)

    # Ensure overhead is under threshold and no OOM
    assert stats["overhead_percent"] < 2.0
    assert stats["memory_peak_mb"] < 1024  # no OOM

    # Result should still be signed and produced
    bundle_bytes = _get_field(result, "bundle_bytes") or (Path(_get_field(result, "bundle_path")).read_bytes() if _get_field(result, "bundle_path") else None)
    signature = _get_field(result, "signature") or _get_field(result, "metadata", {}).get("signature")
    assert bundle_bytes and signature


def test_policy_based_redaction_and_sealed_index(setup_environment, tmp_path):
    env = setup_environment
    collector = env["collector"]
    encrypter = env["encrypter"]
    container_id = env["container_id"]

    policy = {
        "scope": {"include": ["/"], "exclude": ["/run/secrets", "/var/run/secrets"]},
        "redact": {"paths": ["/run/secrets", "/var/run/secrets"], "record_index": True},
    }
    operator_key = b"unit-test-operator-key"
    rate_limit = {"max_events_per_sec": 1000}

    result = collector.collect(
        container_id=container_id,
        policy=policy,
        operator_key=operator_key,
        output_dir=str(tmp_path / "redact"),
        rate_limit=rate_limit,
        overhead_threshold_percent=2.0,
    )

    # Ensure secret files are excluded from manifest
    manifest = _get_field(result, "manifest") or _get_field(result, "metadata", {}).get("manifest")
    serialized = json.dumps(manifest).lower()
    assert "/run/secrets" not in serialized
    assert "/var/run/secrets" not in serialized

    # Ensure sealed redaction index exists and was encrypted with operator key
    redaction_index = _get_field(result, "redaction_index") or _get_field(result, "metadata", {}).get("redaction_index")
    redaction_index_path = _get_field(result, "redaction_index_path")
    sealed_index = None
    if isinstance(redaction_index, (bytes, bytearray)):
        sealed_index = redaction_index
    elif redaction_index_path:
        sealed_index = Path(redaction_index_path).read_bytes()
    else:
        sealed_index = None
    assert sealed_index is not None, "Sealed redaction index expected"
    assert sealed_index.startswith(b"ENC:")
    # Our FakeEncrypter should have been called with operator key and some AAD
    assert encrypter.calls, "Encryptor should be used for sealing redaction index"
    assert encrypter.calls[-1]["key"] == operator_key
    assert isinstance(encrypter.calls[-1]["aad"], (bytes, bytearray))


def test_handles_container_not_found(setup_environment, tmp_path):
    env = setup_environment
    collector = env["collector"]

    missing_id = "does-not-exist"
    policy = {"scope": {"include": ["/"]}}
    operator_key = b"unit-test-operator-key"

    expected_exc = cfc_mod.ContainerNotFoundError if hasattr(cfc_mod, "ContainerNotFoundError") else Exception
    with pytest.raises(expected_exc):
        collector.collect(
            container_id=missing_id,
            policy=policy,
            operator_key=operator_key,
            output_dir=str(tmp_path / "missing"),
            rate_limit={"max_events_per_sec": 1000},
            overhead_threshold_percent=2.0,
        )


def test_invalid_operator_key_rejected(monkeypatch, setup_environment, tmp_path):
    env = setup_environment
    collector = env["collector"]
    container_id = env["container_id"]

    # Swap in an encrypter that fails on encrypt to simulate invalid key
    bad_encrypter = FakeEncrypter(should_fail=True)
    if hasattr(collector, "set_encrypter"):
        collector.set_encrypter(bad_encrypter)
    elif hasattr(collector, "encrypter"):
        collector.encrypter = bad_encrypter
    elif hasattr(cfc_mod, "Encrypter"):
        monkeypatch.setattr(cfc_mod, "Encrypter", lambda *a, **k: bad_encrypter)

    policy = {"scope": {"include": ["/"], "exclude": []}, "redact": {"paths": [], "record_index": True}}

    with pytest.raises(ValueError):
        collector.collect(
            container_id=container_id,
            policy=policy,
            operator_key=None,  # invalid key
            output_dir=str(tmp_path / "badkey"),
            rate_limit={"max_events_per_sec": 1000},
            overhead_threshold_percent=2.0,
        )


def test_collect_without_ebpf_fallback(tmp_path, monkeypatch):
    # Setup env where eBPF is unavailable
    overlay_root = tmp_path / "overlay_noebpf"
    (overlay_root / "etc").mkdir(parents=True)
    (overlay_root / "etc" / "config").write_text("x=1\n")
    runtime = FakeRuntime(overlay_root=overlay_root, has_ebpf=False, mounts_with_secrets=False)
    signer = FakeSigner()
    encrypter = FakeEncrypter()
    probe = FakeProbe()  # should not be used

    container_id = "noebpf-1"
    runtime.register_container(container_id)

    # Monkeypatch module-level classes if present
    if hasattr(cfc_mod, "Runtime"):
        monkeypatch.setattr(cfc_mod, "Runtime", lambda *a, **k: runtime)
    if hasattr(cfc_mod, "Signer"):
        monkeypatch.setattr(cfc_mod, "Signer", lambda *a, **k: signer)
    if hasattr(cfc_mod, "Encrypter"):
        monkeypatch.setattr(cfc_mod, "Encrypter", lambda *a, **k: encrypter)
    if hasattr(cfc_mod, "EBPFProbe"):
        monkeypatch.setattr(cfc_mod, "EBPFProbe", lambda *a, **k: probe)

    collector = ContainerForensicCollector()
    for name, fake in (("runtime", runtime), ("signer", signer), ("encrypter", encrypter)):
        if hasattr(collector, f"set_{name}"):
            getattr(collector, f"set_{name}")(fake)
        elif hasattr(collector, name):
            setattr(collector, name, fake)

    result = collector.collect(
        container_id=container_id,
        policy={"scope": {"include": ["/etc"], "exclude": []}},
        operator_key=b"k",
        output_dir=str(tmp_path / "fallback"),
        rate_limit={"max_events_per_sec": 1000},
        overhead_threshold_percent=2.0,
    )

    # Should succeed even without eBPF; probe not started
    assert _get_field(result, "bundle_bytes") or _get_field(result, "bundle_path")
    assert not probe.started and not probe.stopped, "Probe should not run when eBPF unavailable"