#!/usr/bin/env python3
"""
Container Runtime Forensic Collector

Ethical use only:
- This tool is intended for authorized, legitimate forensic acquisition of containerized workloads.
- Obtain explicit authorization, follow your organization's incident response policies, and comply with applicable laws.
- Misuse may violate privacy, policy, and law.

Capabilities (best-effort, privilege-aware):
- Live, low-impact acquisition using read-only access and optional namespaced bind-mounts.
- Cgroup-aware process enumeration to avoid affecting non-target workloads.
- Rate-limited in-memory sampling to limit CPU overhead and avoid OOM.
- Overlay filesystem snapshot with policy-based redaction of secrets.
- Network state snapshot tied to container processes when possible.
- Cryptographically signed evidence package with deterministic, reproducible manifests.
- Optional on-target encryption using operator-provided keys (via OpenSSL if available).
"""
import argparse
import base64
import errno
import fnmatch
import glob
import hashlib
import hmac
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

TOOL_VERSION = "1.0.0"

# ----------------------- Logging -----------------------

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )

# ----------------------- Utility -----------------------

def run_cmd(cmd: List[str], timeout: int = 15, check: bool = False) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False, text=True)
        if check and p.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)} rc={p.returncode} stderr={p.stderr.strip()}")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_json_atomic(obj: Any, dest: Path) -> None:
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(dest)

def normalize_tarinfo(ti: tarfile.TarInfo, fixed_mtime: int) -> tarfile.TarInfo:
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    ti.mtime = fixed_mtime
    # Normalize modes
    if ti.isdir():
        ti.mode = 0o755
    elif ti.isreg():
        ti.mode = 0o644
    elif ti.issym():
        ti.mode = 0o777
    else:
        ti.mode = 0o644
    return ti

def deterministic_tar_add(tar: tarfile.TarFile, path: Path, arcname: Path, fixed_mtime: int) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        ti = tarfile.TarInfo(str(arcname.as_posix()))
        ti = normalize_tarinfo(ti, fixed_mtime)
        ti.type = tarfile.SYMTYPE
        ti.linkname = os.readlink(str(path))
        tar.addfile(ti)
        return
    ti = tar.gettarinfo(str(path), arcname=str(arcname.as_posix()))
    ti = normalize_tarinfo(ti, fixed_mtime)
    if ti.isreg():
        with path.open("rb") as f:
            tar.addfile(ti, fileobj=f)
    else:
        tar.addfile(ti)

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

# ----------------------- Rate Limiter -----------------------

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: float):
        self.rate = max(0.1, rate_per_sec)
        self.capacity = max(self.rate, burst)
        self.tokens = self.capacity
        self.timestamp = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        with self.lock:
            now = time.time()
            delta = now - self.timestamp
            self.timestamp = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

# ----------------------- Policy -----------------------

DEFAULT_EXCLUDE_GLOBS = [
    "/run/secrets/**",
    "/var/run/secrets/**",
    "/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/**",
    "/var/lib/kubelet/pods/*/secrets/**",
    "/etc/ssl/private/**",
    "/etc/kubernetes/pki/**",
    "/root/.ssh/**",
    "/home/*/.ssh/**",
    "**/*id_rsa*",
    "**/*id_dsa*",
    "**/*id_ed25519*",
    "**/*_key",
    "**/*token*",
    "**/*.dockercfg*",
    "**/.docker/config.json",
]

class RedactionPolicy:
    def __init__(self, policy_file: Optional[Path] = None, exclude_defaults: bool = True):
        self.exclude_globs: List[str] = []
        self.redact_globs: List[str] = []
        if exclude_defaults:
            self.exclude_globs.extend(DEFAULT_EXCLUDE_GLOBS)
        if policy_file and policy_file.exists():
            try:
                data = json.loads(policy_file.read_text())
                self.exclude_globs.extend(data.get("exclude_globs", []))
                self.redact_globs.extend(data.get("redact_globs", []))
            except Exception as e:
                logging.warning(f"Failed to load policy file {policy_file}: {e}")

    def should_exclude(self, rel_path: str) -> bool:
        rel_path = rel_path.replace("//", "/")
        rel_path = rel_path if rel_path.startswith("/") else f"/{rel_path}"
        for pat in self.exclude_globs:
            if fnmatch.fnmatch(rel_path, pat):
                return True
        return False

    def should_redact(self, rel_path: str) -> bool:
        rel_path = rel_path.replace("//", "/")
        rel_path = rel_path if rel_path.startswith("/") else f"/{rel_path}"
        for pat in self.redact_globs:
            if fnmatch.fnmatch(rel_path, pat):
                return True
        return False

# ----------------------- Container Introspection -----------------------

class ContainerInfo:
    def __init__(self):
        self.runtime: str = "unknown"
        self.id: str = ""
        self.name: str = ""
        self.pid: Optional[int] = None
        self.merged_dir: Optional[str] = None
        self.cgroup_paths: List[str] = []
        self.metadata: Dict[str, Any] = {}
        self.started_at_iso: Optional[str] = None

def detect_runtime() -> Optional[str]:
    if which("docker"):
        return "docker"
    if which("crictl"):
        return "crictl"
    if which("ctr"):
        return "containerd"
    return None

def docker_inspect(container: str) -> Optional[Dict[str, Any]]:
    rc, out, err = run_cmd(["docker", "inspect", container], timeout=20)
    if rc != 0:
        logging.error(f"docker inspect failed: {err.strip()}")
        return None
    try:
        arr = json.loads(out)
        if not arr:
            return None
        return arr[0]
    except json.JSONDecodeError as e:
        logging.error(f"Invalid docker inspect output: {e}")
        return None

def crictl_inspect(container: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    # Return (container_status, process_status)
    rc, out, err = run_cmd(["crictl", "inspect", container], timeout=20)
    status = None
    if rc == 0:
        try:
            status = json.loads(out).get("status")
        except Exception:
            status = None
    rc, out, err = run_cmd(["crictl", "inspectp", container], timeout=20)
    proc = None
    if rc == 0:
        try:
            proc = json.loads(out).get("info")
        except Exception:
            proc = None
    return status, proc

def resolve_container(container: str, runtime: Optional[str]) -> ContainerInfo:
    info = ContainerInfo()
    if not runtime:
        runtime = detect_runtime()
    if not runtime:
        raise RuntimeError("No container runtime detected (docker/crictl/ctr). Install docker or crictl.")
    info.runtime = runtime
    if runtime == "docker":
        meta = docker_inspect(container)
        if not meta:
            raise RuntimeError("Failed to inspect container with docker.")
        info.metadata = meta
        info.id = meta.get("Id") or meta.get("ID") or container
        info.name = (meta.get("Name") or "").lstrip("/")
        info.started_at_iso = (meta.get("State") or {}).get("StartedAt")
        gd = meta.get("GraphDriver", {})
        merged = (gd.get("Data") or {}).get("MergedDir")
        if merged and os.path.isdir(merged):
            info.merged_dir = merged
        state = meta.get("State") or {}
        pid = state.get("Pid")
        if isinstance(pid, int) and pid > 0:
            info.pid = pid
        # cgroups from /proc/<pid>/cgroup
        if info.pid:
            cgroups = []
            try:
                with open(f"/proc/{info.pid}/cgroup", "r") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) == 3:
                            cgroups.append(parts[2])
            except Exception:
                pass
            info.cgroup_paths = cgroups
    elif runtime == "crictl":
        status, proc = crictl_inspect(container)
        if not status and not proc:
            raise RuntimeError("Failed to inspect container with crictl.")
        info.metadata = {"status": status, "process": proc}
        info.id = (status or {}).get("id") or container
        info.name = ((status or {}).get("metadata") or {}).get("name") or container
        info.started_at_iso = ((status or {}).get("state") or {}).get("started_at")
        # attempt to get pid
        info.pid = ((proc or {}).get("pid"))
        # attempt to resolve rootfs: crictl may not show merged dir; try /proc/<pid>/root
        if info.pid and os.path.isdir(f"/proc/{info.pid}/root"):
            info.merged_dir = f"/proc/{info.pid}/root"
        # cgroups
        if info.pid:
            cgroups = []
            try:
                with open(f"/proc/{info.pid}/cgroup", "r") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) == 3:
                            cgroups.append(parts[2])
            except Exception:
                pass
            info.cgroup_paths = cgroups
    elif runtime == "containerd":
        # Try ctr: merged_dir not easily available; fallback to /proc/<pid>/root if possible.
        rc, out, err = run_cmd(["ctr", "c", "info", container], timeout=20)
        if rc == 0:
            try:
                meta = json.loads(out)
                info.metadata = meta
                info.id = meta.get("ID") or container
                info.name = meta.get("ID") or container
            except Exception:
                pass
        # process pid maybe via crictl
        status, proc = crictl_inspect(container)
        if proc:
            info.pid = proc.get("pid")
        if info.pid and os.path.isdir(f"/proc/{info.pid}/root"):
            info.merged_dir = f"/proc/{info.pid}/root"
        info.cgroup_paths = []
        if info.pid:
            try:
                with open(f"/proc/{info.pid}/cgroup", "r") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) == 3:
                            info.cgroup_paths.append(parts[2])
            except Exception:
                pass
    else:
        raise RuntimeError(f"Unsupported runtime: {runtime}")
    return info

# ----------------------- Process and Network Sampling -----------------------

def pids_in_same_cgroup(target_cgroups: List[str]) -> List[int]:
    pids = []
    if not target_cgroups:
        return pids
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        pid = int(pid_str)
        try:
            with open(f"/proc/{pid}/cgroup", "r") as f:
                cg_lines = f.read().strip().splitlines()
            for line in cg_lines:
                parts = line.split(":")
                if len(parts) == 3:
                    path = parts[2]
                    if any(path == t or path.endswith(t) or t in path for t in target_cgroups):
                        pids.append(pid)
                        break
        except Exception:
            continue
    return sorted(set(pids))

def read_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            data = f.read().replace(b"\x00", b" ").strip()
            return data.decode("utf-8", errors="replace")
    except Exception:
        return ""

def read_comm(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except Exception:
        return ""

def read_exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""

def proc_uids_gids(pid: int) -> Tuple[int, int]:
    try:
        st = os.stat(f"/proc/{pid}")
        return st.st_uid, st.st_gid
    except Exception:
        return (-1, -1)

def list_threads(pid: int) -> int:
    try:
        return len([d for d in os.listdir(f"/proc/{pid}/task") if d.isdigit()])
    except Exception:
        return 0

def read_maps_paths(pid: int, max_entries: int = 100) -> List[str]:
    paths = []
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 6:
                    p = parts[-1]
                    if p.startswith("/") and p not in paths:
                        paths.append(p)
                        if len(paths) >= max_entries:
                            break
    except Exception:
        pass
    return paths

def snapshot_processes(cgroup_paths: List[str], sample_maps: bool, maps_limit: int, rate_limiter: TokenBucket, max_cpu_pct: float) -> Dict[str, Any]:
    start_wall = time.time()
    start_cpu = time.process_time()
    procs = []
    for pid in pids_in_same_cgroup(cgroup_paths):
        if not rate_limiter.consume(1.0):
            time.sleep(0.01)
        entry = {
            "pid": pid,
            "comm": read_comm(pid),
            "cmdline": read_cmdline(pid),
            "exe": read_exe(pid),
            "uid": proc_uids_gids(pid)[0],
            "gid": proc_uids_gids(pid)[1],
            "threads": list_threads(pid),
        }
        if sample_maps:
            entry["maps_sample"] = read_maps_paths(pid, maps_limit)
        procs.append(entry)
        # limit overhead
        wall = time.time() - start_wall
        cpu = time.process_time() - start_cpu
        if wall > 0 and (cpu / wall) * 100.0 > max_cpu_pct:
            # Back off
            time.sleep(0.05)
    return {"processes": sorted(procs, key=lambda x: x["pid"])}

def snapshot_network_for_pids(pids: List[int]) -> Dict[str, Any]:
    # Attempt to use ss for global snapshot and filter pids
    net = {"connections": [], "errors": []}
    rc, out, err = run_cmd(["ss", "-tupon"], timeout=10)
    if rc == 0:
        try:
            for line in out.strip().splitlines():
                # Lines may contain users:(("cmd",pid=1234,fd=5))
                if "pid=" in line:
                    for pid in pids:
                        token = f"pid={pid}"
                        if token in line:
                            net["connections"].append(line.strip())
                            break
        except Exception as e:
            net["errors"].append(f"parse_ss:{e}")
    else:
        net["errors"].append(f"ss_failed:{err.strip()}")
    # Routes and addresses
    rc, out, err = run_cmd(["ip", "-j", "addr"], timeout=5)
    if rc == 0:
        try:
            net["ip_addr"] = json.loads(out)
        except Exception as e:
            net["errors"].append(f"ip_addr_parse:{e}")
    rc, out, err = run_cmd(["ip", "-j", "route"], timeout=5)
    if rc == 0:
        try:
            net["ip_route"] = json.loads(out)
        except Exception as e:
            net["errors"].append(f"ip_route_parse:{e}")
    return net

# ----------------------- Overlay Snapshot -----------------------

def create_mount_namespace_and_bind_ro(src: str, dest: str) -> bool:
    # Best-effort: use unshare and mount if available and permitted
    if not which("unshare") or not which("mount"):
        return False
    try:
        # Create private mount namespace for this process
        rc, out, err = run_cmd(["unshare", "-m", "--propagation", "private", "true"], timeout=1)
        # Note: The above doesn't persist; instead try remount directly
    except Exception:
        pass
    # Fallback: try performing bind mount read-only in current ns (may fail without CAP_SYS_ADMIN)
    rc, out, err = run_cmd(["mount", "--bind", src, dest], timeout=5)
    if rc != 0:
        logging.debug(f"bind mount failed: {err.strip()}")
        return False
    rc, out, err = run_cmd(["mount", "-o", "remount,ro,bind", dest], timeout=5)
    if rc != 0:
        logging.debug(f"remount ro failed: {err.strip()}")
        # try to unmount to clean up
        run_cmd(["umount", dest], timeout=5)
        return False
    return True

def tar_overlay(root: Path, dest_tar: Path, policy: RedactionPolicy, fixed_mtime: int, redactions: List[Dict[str, Any]], max_files: int = 100000) -> None:
    # Deterministic tar without compression
    # Walk sorted by path
    def entries():
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            # Sort for reproducibility
            dirnames[:] = sorted(dirnames)
            filenames = sorted(filenames)
            full_dir = Path(dirpath)
            rel_dir = "/" + str(full_dir.relative_to(root)).strip(".")
            if rel_dir == "//":
                rel_dir = "/"
            # yield directories
            for d in dirnames:
                relp = os.path.join(rel_dir, d)
                if policy.should_exclude(relp):
                    redactions.append({"path": relp, "reason": "policy_exclude_dir"})
                    # Do not descend into excluded directories
                    # Remove d from traversal
                    # It's already in dirnames; modify in-place
                    # But since iterating, we will skip its content by removing from dirnames
                    # ensure we don't include directory itself either
                    continue
            # Remove excluded directories from walk
            dirnames[:] = [d for d in dirnames if not policy.should_exclude(os.path.join(rel_dir, d))]
            for d in dirnames:
                yield full_dir / d
            # files
            for f in filenames:
                relp = os.path.join(rel_dir, f)
                if policy.should_exclude(relp):
                    try:
                        st = os.lstat(full_dir / f)
                        redactions.append({
                            "path": relp,
                            "size": getattr(st, "st_size", None),
                            "mode": stat.S_IMODE(st.st_mode),
                            "reason": "policy_exclude_file"
                        })
                    except Exception:
                        redactions.append({"path": relp, "reason": "policy_exclude_file"})
                    continue
                yield full_dir / f

    count = 0
    with tarfile.open(dest_tar, mode="w", format=tarfile.PAX_FORMAT) as tf:
        # add root directory entry
        root_ti = tarfile.TarInfo(name=".")
        root_ti = normalize_tarinfo(root_ti, fixed_mtime)
        root_ti.type = tarfile.DIRTYPE
        root_ti.mode = 0o755
        tf.addfile(root_ti)
        for p in entries():
            count += 1
            if count > max_files:
                logging.warning("Max file limit reached during overlay snapshot; truncating.")
                break
            try:
                rel = p.relative_to(root)
            except Exception:
                # Shouldn't happen
                rel = Path(p.name)
            arc = Path(str(rel))
            try:
                deterministic_tar_add(tf, p, arc, fixed_mtime)
            except FileNotFoundError:
                # File disappeared during walk; skip
                continue
            except PermissionError:
                redactions.append({"path": "/" + str(arc), "reason": "permission_denied"})
                continue

# ----------------------- Signing and Encryption -----------------------

def load_hmac_key(path: Optional[Path]) -> Optional[bytes]:
    if not path:
        return None
    data = path.read_bytes()
    # Try to decode hex if plausible
    try:
        stripped = data.strip()
        if all(c in b"0123456789abcdefABCDEF" for c in stripped) and (len(stripped) % 2 == 0):
            return bytes.fromhex(stripped.decode("ascii"))
    except Exception:
        pass
    return data

def hmac_sign_file(path: Path, key: bytes) -> str:
    hm = hmac.new(key, digestmod=hashlib.sha256)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hm.update(chunk)
    return base64.b64encode(hm.digest()).decode("ascii")

def openssl_has_cipher(cipher: str) -> bool:
    rc, out, err = run_cmd(["openssl", "enc", "-ciphers"], timeout=5)
    if rc != 0:
        return False
    return cipher in out

def encrypt_file_openssl(src: Path, dst: Path, passphrase: Optional[str] = None, passfile: Optional[Path] = None, prefer_gcm: bool = True) -> Tuple[bool, str]:
    if not which("openssl"):
        return False, "openssl_not_available"
    cipher = "aes-256-gcm" if prefer_gcm and openssl_has_cipher("aes-256-gcm") else "aes-256-cbc"
    cmd = ["openssl", "enc", f"-{cipher}", "-salt", "-pbkdf2", "-in", str(src), "-out", str(dst)]
    if passphrase:
        cmd.extend(["-pass", f"pass:{passphrase}"])
    elif passfile:
        cmd.extend(["-pass", f"file:{str(passfile)}"])
    else:
        return False, "no_passphrase_or_file"
    rc, out, err = run_cmd(cmd, timeout=120)
    if rc != 0:
        return False, err.strip()
    return True, cipher

# ----------------------- Chain of Custody -----------------------

def build_chain_of_custody(operator_id: str, container: ContainerInfo, manifest: Dict[str, Any], fixed_time_iso: str) -> Dict[str, Any]:
    return {
        "tool": "Container Runtime Forensic Collector",
        "tool_version": TOOL_VERSION,
        "operator_id": operator_id,
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "kernel": platform.release(),
        },
        "container": {
            "runtime": container.runtime,
            "id": container.id,
            "name": container.name,
            "started_at": container.started_at_iso,
            "pid": container.pid,
        },
        "acquisition_time": fixed_time_iso,
        "manifest_digest": manifest.get("bundle_sha256"),
        "ethical_use_warning": "Authorized testing and collection only; improper use may violate law and policy.",
        "notes": "Evidence package created with deterministic tar entries and HMAC signature for chain-of-custody.",
    }

# ----------------------- Main Collector -----------------------

def collect_evidence(container_ref: str,
                     runtime: Optional[str],
                     output: Path,
                     operator_id: str,
                     policy: RedactionPolicy,
                     hmac_key_path: Optional[Path],
                     encrypt_passphrase: Optional[str],
                     encrypt_key_file: Optional[Path],
                     probe_rate_hz: float,
                     probe_cpu_pct: float,
                     maps_limit: int,
                     sample_maps: bool,
                     exclude_defaults: bool) -> int:
    start_time = time.time()
    try:
        info = resolve_container(container_ref, runtime)
    except Exception as e:
        logging.error(f"Failed to resolve container: {e}")
        return 2
    if not info.merged_dir or not os.path.isdir(info.merged_dir):
        logging.error("Unable to resolve container root filesystem (merged dir).")
        return 3

    # Fixed time for deterministic packaging: use container started_at if available, else epoch 0
    fixed_mtime = 0
    fixed_time_iso = "1970-01-01T00:00:00Z"
    if info.started_at_iso:
        try:
            # Normalize to seconds
            dt = datetime.fromisoformat(info.started_at_iso.replace("Z", "+00:00"))
            fixed_mtime = int(dt.timestamp())
            fixed_time_iso = dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except Exception:
            fixed_mtime = 0
            fixed_time_iso = "1970-01-01T00:00:00Z"

    # Create working dir
    work_dir = Path(tempfile.mkdtemp(prefix="forensic_collect_"))
    evidence_dir = work_dir / "evidence"
    safe_mkdir(evidence_dir)
    logging.info(f"Working directory: {work_dir}")

    # Attempt read-only bind mount in namespaced way
    ro_mount_dir = work_dir / "ro_mount"
    safe_mkdir(ro_mount_dir)
    ro_src = info.merged_dir
    used_ro_mount = False
    try:
        if create_mount_namespace_and_bind_ro(ro_src, str(ro_mount_dir)):
            used_ro_mount = True
            root_path = ro_mount_dir
        else:
            logging.warning("Read-only bind mount not available; proceeding with direct reads.")
            root_path = Path(ro_src)
    except Exception as e:
        logging.warning(f"Mount namespace/bind failed: {e}; proceeding with direct reads.")
        root_path = Path(ro_src)

    # Processes snapshot with rate limiting and CPU cap
    rate_limiter = TokenBucket(rate_per_sec=probe_rate_hz, burst=probe_rate_hz)
    procs_snapshot = snapshot_processes(info.cgroup_paths, sample_maps=sample_maps, maps_limit=maps_limit, rate_limiter=rate_limiter, max_cpu_pct=probe_cpu_pct)
    processes_json = evidence_dir / "processes.json"
    write_json_atomic(procs_snapshot, processes_json)

    # Network snapshot
    pids = [p["pid"] for p in procs_snapshot.get("processes", [])]
    net_snapshot = snapshot_network_for_pids(pids)
    network_json = evidence_dir / "network.json"
    write_json_atomic(net_snapshot, network_json)

    # Container metadata
    container_meta_json = evidence_dir / "container_metadata.json"
    write_json_atomic(info.metadata, container_meta_json)

    # Overlay snapshot
    overlay_tar = evidence_dir / "overlayfs.tar"
    redactions: List[Dict[str, Any]] = []
    try:
        tar_overlay(root_path, overlay_tar, policy, fixed_mtime=fixed_mtime, redactions=redactions)
    except Exception as e:
        logging.error(f"Overlay snapshot failed: {e}")
        return 4

    # Redaction index
    redactions_json = evidence_dir / "redactions.json"
    write_json_atomic({
        "policy": {
            "exclude_globs": policy.exclude_globs,
            "redact_globs": policy.redact_globs,
        },
        "redactions": sorted(redactions, key=lambda x: x.get("path", "")),
    }, redactions_json)

    # Manifest: compute sha256 for artifacts deterministically
    files_to_hash = [
        ("container_metadata.json", container_meta_json),
        ("processes.json", processes_json),
        ("network.json", network_json),
        ("overlayfs.tar", overlay_tar),
        ("redactions.json", redactions_json),
    ]
    manifest_entries = []
    for name, path in files_to_hash:
        if path.exists():
            digest = sha256_file(path)
            manifest_entries.append({"name": name, "sha256": digest, "size": path.stat().st_size})
    manifest = {
        "entries": sorted(manifest_entries, key=lambda x: x["name"]),
        "created_by": "Container Runtime Forensic Collector",
        "tool_version": TOOL_VERSION,
        "deterministic_mtime": fixed_time_iso,
    }
    manifest_json = evidence_dir / "manifest.json"
    write_json_atomic(manifest, manifest_json)

    # Sign redactions and manifest
    hmac_key = load_hmac_key(hmac_key_path) if hmac_key_path else None
    signatures_dir = evidence_dir / "SIGNATURES"
    if hmac_key:
        safe_mkdir(signatures_dir)
        red_sig = hmac_sign_file(redactions_json, hmac_key)
        (signatures_dir / "redactions.hmac").write_text(red_sig + "\n")
        man_sig = hmac_sign_file(manifest_json, hmac_key)
        (signatures_dir / "manifest.hmac").write_text(man_sig + "\n")
    else:
        logging.warning("No HMAC signing key provided; signatures will be omitted.")

    # Tool version file
    (evidence_dir / "TOOL_VERSION").write_text(TOOL_VERSION + "\n")

    # Bundle evidence into deterministic tar
    bundle_tar = work_dir / "evidence_bundle.tar"
    with tarfile.open(bundle_tar, mode="w", format=tarfile.PAX_FORMAT) as tf:
        # Add evidence files in sorted order to ensure determinism
        entries = sorted([p for p in evidence_dir.rglob("*")], key=lambda p: p.relative_to(evidence_dir).as_posix())
        for p in entries:
            rel = p.relative_to(evidence_dir)
            ti = tf.gettarinfo(str(p), arcname=str(rel.as_posix()))
            ti = normalize_tarinfo(ti, fixed_mtime)
            if ti.isreg():
                with p.open("rb") as f:
                    tf.addfile(ti, fileobj=f)
            else:
                tf.addfile(ti)

    # Compute bundle hash for chain of custody
    bundle_sha256 = sha256_file(bundle_tar)
    manifest["bundle_sha256"] = bundle_sha256
    write_json_atomic(manifest, manifest_json)  # update with bundle hash

    # HMAC sign the bundle tar as final signature
    bundle_sig_path = work_dir / "evidence_bundle.tar.sig"
    if hmac_key:
        sig = hmac_sign_file(bundle_tar, hmac_key)
        bundle_sig_path.write_text(sig + "\n")
    else:
        logging.warning("No HMAC key; bundle signature not created.")

    # Chain of custody
    chain = build_chain_of_custody(operator_id, info, manifest, fixed_time_iso)
    chain_json = work_dir / "chain_of_custody.json"
    write_json_atomic(chain, chain_json)
    if hmac_key:
        chain_sig = hmac_sign_file(chain_json, hmac_key)
        (work_dir / "chain_of_custody.json.sig").write_text(chain_sig + "\n")

    # Encrypt bundle if requested
    encryption_info = {}
    final_output = output
    if encrypt_passphrase or encrypt_key_file:
        enc_path = output.with_suffix(output.suffix + ".enc") if output.suffix else Path(str(output) + ".enc")
        ok, cipher_or_err = encrypt_file_openssl(bundle_tar, enc_path, passphrase=encrypt_passphrase, passfile=encrypt_key_file)
        if not ok:
            logging.error(f"Encryption failed: {cipher_or_err}")
            return 5
        encryption_info = {
            "method": "openssl_enc",
            "cipher": cipher_or_err,
            "note": "PBKDF2 used with salt; HMAC signature still applies to unencrypted bundle for integrity verification."
        }
        final_output = enc_path
    else:
        encryption_info = {"method": "none"}

    # Prepare output directory and write outputs reproducibly
    out_dir = output.parent if output.suffix else Path(str(output)).parent
    if not out_dir.exists():
        safe_mkdir(out_dir)

    # Move files
    shutil.move(str(bundle_tar), str(output if final_output == output else (work_dir / "evidence_bundle.tar")))
    if final_output != output:
        shutil.move(str(final_output), str(output))
    # Write signatures and chain-of-custody next to output with deterministic timestamps if filesystem allows
    # We do not modify mtime here

    # Write encryption info
    enc_info_path = output.with_suffix(output.suffix + ".encryption.json")
    write_json_atomic(encryption_info, enc_info_path)
    # Write signature file if exists
    if hmac_key and bundle_sig_path.exists():
        out_sig = output.with_suffix(output.suffix + ".sig")
        shutil.move(str(bundle_sig_path), str(out_sig))

    # Cleanup mount if created
    if used_ro_mount:
        run_cmd(["umount", str(ro_mount_dir)], timeout=5)

    # Copy chain-of-custody next to output
    final_chain = output.with_suffix(output.suffix + ".chain_of_custody.json")
    shutil.move(str(chain_json), str(final_chain))
    if hmac_key and (work_dir / "chain_of_custody.json.sig").exists():
        shutil.move(str(work_dir / "chain_of_custody.json.sig"), str(output.with_suffix(output.suffix + ".chain_of_custody.json.sig")))

    # Final log
    elapsed = time.time() - start_time
    logging.info(f"Evidence collected to {output} in {elapsed:.2f}s")
    return 0

# ----------------------- CLI -----------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Container Runtime Forensic Collector - Authorized use only.")
    p.add_argument("--container", "-c", required=True, help="Container ID or name.")
    p.add_argument("--runtime", choices=["docker", "crictl", "containerd"], help="Container runtime; auto-detect by default.")
    p.add_argument("--output", "-o", required=True, type=Path, help="Output evidence bundle path (tar or encrypted tar.enc).")
    p.add_argument("--operator-id", "-u", required=True, help="Operator identifier for chain-of-custody.")
    p.add_argument("--policy-file", type=Path, help="JSON policy file with exclude_globs/redact_globs.")
    p.add_argument("--no-default-secrets", action="store_true", help="Disable default secret exclusions.")
    p.add_argument("--hmac-key", type=Path, help="Path to HMAC signing key (raw bytes or hex).")
    p.add_argument("--encrypt-passphrase", help="Encrypt bundle with this passphrase using OpenSSL.")
    p.add_argument("--encrypt-key-file", type=Path, help="Path to file whose content is used as OpenSSL passphrase.")
    p.add_argument("--probe-rate-hz", type=float, default=100.0, help="Max sampling operations per second (rate limit).")
    p.add_argument("--probe-cpu-pct", type=float, default=5.0, help="Approximate max CPU overhead percent for probes.")
    p.add_argument("--maps-limit", type=int, default=64, help="Max memory map paths to sample per process.")
    p.add_argument("--no-maps", action="store_true", help="Disable sampling of process memory maps.")
    p.add_argument("-v", action="count", default=0, help="Increase verbosity (-v, -vv).")
    return p.parse_args(argv)

def main(argv: List[str]) -> int:
    args = parse_args(argv)
    setup_logging(args.v)
    # Warnings
    logging.warning("Use this tool only with authorization and in compliance with policy and law.")
    policy = RedactionPolicy(policy_file=args.policy_file, exclude_defaults=not args.no_default_secrets)
    try:
        rc = collect_evidence(
            container_ref=args.container,
            runtime=args.runtime,
            output=args.output,
            operator_id=args.operator_id,
            policy=policy,
            hmac_key_path=args.hmac_key,
            encrypt_passphrase=args.encrypt_passphrase,
            encrypt_key_file=args.encrypt_key_file,
            probe_rate_hz=args.probe_rate_hz,
            probe_cpu_pct=args.probe_cpu_pct,
            maps_limit=args.maps_limit,
            sample_maps=not args.no_maps,
            exclude_defaults=not args.no_default_secrets,
        )
        if rc != 0:
            logging.error(f"Collection failed with code {rc}")
        return rc
    except KeyboardInterrupt:
        logging.error("Interrupted by user.")
        return 130
    except Exception as e:
        logging.exception(f"Unhandled error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))