#!/usr/bin/env python3
import argparse
import base64
import datetime
import io
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from hashlib import sha256
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ETHICAL_WARNING = (
    "Ethical Notice: This toolkit is intended solely for authorized testing and incident response. "
    "Do not acquire or analyze memory from systems without explicit authorization. Misuse may violate "
    "laws and organizational policies. Ensure you have proper permissions and follow all applicable "
    "legal and ethical guidelines."
)

TOOL_VERSION = "1.0.0"

# Configure logging
logger = logging.getLogger("LiveMemoryForensicToolkit")
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

try:
    import psutil
except Exception as e:
    psutil = None
    logger.warning("psutil is not available: %s. Acquisition and analysis may be limited.", e)

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception as e:
    REPORTLAB_AVAILABLE = False
    logger.info("reportlab is not available: %s. PDF generation will fallback to plaintext-as-pdf stub.", e)


class MemoryAcquirer:
    def __init__(self):
        self.system = platform.system().lower()

    def acquire(self, output_path: Path, mode: str = "lite") -> Path:
        """
        Acquire a live memory snapshot. Mode 'lite' captures minimal volatile state (processes, connections, drivers).
        Mode 'full' attempts to acquire raw memory if feasible on current platform (best effort).
        Returns path to created archive (zip).
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        archive_path = output_path if output_path.suffix.lower() in (".zip", ".lmft", ".lmft.zip") else output_path.with_suffix(".lmft.zip")
        tmpdir = Path(tempfile.mkdtemp(prefix="lmft_acq_"))
        try:
            # metadata
            metadata = self._collect_metadata(mode)
            _write_json(tmpdir / "metadata.json", metadata)

            # processes
            processes = self._collect_processes()
            _write_json(tmpdir / "processes.json", processes)

            # network
            net = self._collect_network()
            _write_json(tmpdir / "connections.json", net)

            # drivers / modules
            drivers = self._collect_drivers()
            _write_json(tmpdir / "drivers.json", drivers)

            # code injection heuristics (live)
            heuristics = self._simple_injection_heuristics(processes)
            _write_json(tmpdir / "heuristics.json", heuristics)

            # attempt raw memory (best effort)
            raw_info = {}
            if mode == "full":
                mem_file = self._attempt_raw_memory(tmpdir)
                if mem_file:
                    raw_info["raw_memory_file"] = mem_file.name
                else:
                    raw_info["raw_memory_file"] = None
            else:
                raw_info["raw_memory_file"] = None
            _write_json(tmpdir / "raw_info.json", raw_info)

            # Include ethical notice
            (tmpdir / "ETHICS.txt").write_text(ETHICAL_WARNING, encoding="utf-8")

            # Finalize to zip
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for p in tmpdir.rglob("*"):
                    arcname = p.relative_to(tmpdir)
                    zf.write(p, arcname.as_posix())
            logger.info("Acquisition completed: %s", archive_path)
            return archive_path
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _collect_metadata(self, mode: str) -> Dict:
        return {
            "tool": "Live Memory Forensic Toolkit",
            "version": TOOL_VERSION,
            "ethical_notice": ETHICAL_WARNING,
            "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "system": {
                "os": platform.system(),
                "os_version": platform.version(),
                "platform": platform.platform(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python_version": platform.python_version(),
            },
            "mode": mode,
        }

    def _collect_processes(self) -> Dict:
        proc_list: List[Dict] = []
        if psutil is None:
            return {"error": "psutil not available", "processes": []}
        for p in psutil.process_iter(attrs=["pid", "ppid", "name", "exe", "username", "cmdline", "status", "create_time"]):
            try:
                info = p.info
                try:
                    mem = p.memory_info()
                    rss = mem.rss
                    vms = getattr(mem, "vms", None)
                except Exception:
                    rss = None
                    vms = None
                try:
                    open_files = [f.path for f in p.open_files()]
                except Exception:
                    open_files = []
                try:
                    conns = p.connections(kind="inet")
                    conn_count = len(conns)
                except Exception:
                    conn_count = None
                proc_list.append({
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "exe": info.get("exe"),
                    "username": info.get("username"),
                    "cmdline": info.get("cmdline"),
                    "status": info.get("status"),
                    "create_time": info.get("create_time"),
                    "rss": rss,
                    "vms": vms,
                    "open_files_count": len(open_files),
                    "conn_count": conn_count,
                })
            except Exception as e:
                logger.debug("Failed to collect process info: %s", e)
        return {"count": len(proc_list), "processes": proc_list}

    def _collect_network(self) -> Dict:
        if psutil is None:
            return {"error": "psutil not available", "connections": []}
        conns_list = []
        try:
            for c in psutil.net_connections(kind="inet"):
                try:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None
                except Exception:
                    try:
                        laddr = f"{c.laddr[0]}:{c.laddr[1]}" if c.laddr else None
                    except Exception:
                        laddr = None
                try:
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None
                except Exception:
                    try:
                        raddr = f"{c.raddr[0]}:{c.raddr[1]}" if c.raddr else None
                    except Exception:
                        raddr = None
                conns_list.append({
                    "fd": getattr(c, "fd", None),
                    "family": str(getattr(c, "family", None)),
                    "type": str(getattr(c, "type", None)),
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": getattr(c, "status", None),
                    "pid": getattr(c, "pid", None),
                })
        except Exception as e:
            logger.debug("Failed to enumerate connections: %s", e)
        return {"count": len(conns_list), "connections": conns_list}

    def _collect_drivers(self) -> Dict:
        sysname = platform.system().lower()
        try:
            if sysname == "linux":
                return self._drivers_linux()
            elif sysname == "windows":
                return self._drivers_windows()
            elif sysname == "darwin":
                return self._drivers_macos()
            else:
                return {"error": "unsupported os", "drivers": []}
        except Exception as e:
            logger.debug("Drivers collection failed: %s", e)
            return {"error": str(e), "drivers": []}

    def _drivers_linux(self) -> Dict:
        drivers = []
        try:
            out = subprocess.check_output(["lsmod"], text=True, stderr=subprocess.DEVNULL)
            lines = out.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    name, size, used_by = parts[0], parts[1], parts[2]
                    drivers.append({"name": name, "size": int(size), "used_by": used_by})
        except Exception:
            pass
        return {"count": len(drivers), "drivers": drivers}

    def _drivers_windows(self) -> Dict:
        drivers = []
        # Try PowerShell WMI
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-WmiObject Win32_SystemDriver | Select-Object Name,State,PathName,Description | ConvertTo-Json -Depth 2"
            ]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                drivers.append({
                    "name": d.get("Name"),
                    "state": d.get("State"),
                    "path": d.get("PathName"),
                    "description": d.get("Description"),
                })
        except Exception:
            pass
        return {"count": len(drivers), "drivers": drivers}

    def _drivers_macos(self) -> Dict:
        drivers = []
        try:
            out = subprocess.check_output(["kextstat", "-l"], text=True, stderr=subprocess.DEVNULL)
            lines = out.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    idx = parts[0]
                    refcnt = parts[2]
                    name = parts[-1]
                    drivers.append({"id": idx, "refcnt": refcnt, "name": name})
        except Exception:
            pass
        return {"count": len(drivers), "drivers": drivers}

    def _attempt_raw_memory(self, tmpdir: Path) -> Optional[Path]:
        """
        Best-effort raw memory acquisition. Requires elevated privileges; may fail.
        - Linux: try /proc/kcore (symbolic core), or /dev/mem (often restricted).
        - macOS: no easy raw RAM; skip.
        - Windows: look for winpmem.exe in PATH or current dir.
        """
        sysname = platform.system().lower()
        out_path = tmpdir / "memory.raw"
        try:
            if sysname == "linux":
                # Read a small sample to minimize footprint
                candidates = ["/proc/kcore", "/dev/crash", "/dev/mem"]
                for c in candidates:
                    p = Path(c)
                    if p.exists() and os.access(str(p), os.R_OK):
                        with open(p, "rb", buffering=0) as f, open(out_path, "wb") as w:
                            chunk = f.read(16 * 1024 * 1024)  # take 16MB sample to reduce footprint
                            w.write(chunk)
                        return out_path
            elif sysname == "windows":
                winpmem = _which(["winpmem", "winpmem.exe", "DumpIt.exe"])
                if winpmem:
                    # Use winpmem to dump to temp file (sample to minimize footprint)
                    # Some winpmem versions have --size; if not, dump fully (may be large)
                    try:
                        subprocess.check_call([winpmem, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        has_size = True
                    except Exception:
                        has_size = False
                    tmpdump = tmpdir / "memory_full.raw"
                    cmd = [winpmem, str(tmpdump)]
                    if has_size:
                        cmd = [winpmem, "--format", "raw", "--size", "16M", str(tmpdump)]
                    try:
                        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        # rename to memory.raw
                        tmpdump.rename(out_path)
                        return out_path
                    except Exception:
                        pass
            elif sysname == "darwin":
                # No straightforward lawful method programmatically without kexts. Skip.
                return None
        except Exception as e:
            logger.debug("Raw memory attempt failed: %s", e)
        return None

    def _simple_injection_heuristics(self, processes: Dict) -> Dict:
        procs = processes.get("processes", [])
        findings = []
        suspicious_keywords = [
            "powershell", "encod", "mimikatz", "rundll32", "regsvr32", "wscript", "cscript", "mshta",
            "curl", "wget", "nc ", "netcat", "ncat", "ssh", "scp", "invoke-mimikatz", "reflective"
        ]
        for p in procs:
            cmd = " ".join(p.get("cmdline") or []) if p.get("cmdline") else p.get("name") or ""
            lower = cmd.lower()
            for kw in suspicious_keywords:
                if kw in lower:
                    findings.append({
                        "pid": p.get("pid"),
                        "name": p.get("name"),
                        "cmdline": p.get("cmdline"),
                        "reason": f"keyword:{kw}"
                    })
                    break
            exe = (p.get("exe") or "").lower()
            if exe and any(tmp in exe for tmp in ["\\temp\\", "/tmp/", "/var/tmp/", "/dev/shm/"]):
                findings.append({
                    "pid": p.get("pid"),
                    "name": p.get("name"),
                    "cmdline": p.get("cmdline"),
                    "reason": "process executable in temp-like path"
                })
        return {"suspicious_processes": findings}


class VolatilityInterface:
    def __init__(self):
        self.vol_cmd = self._find_volatility()

    def available(self) -> bool:
        return self.vol_cmd is not None

    def _find_volatility(self) -> Optional[List[str]]:
        candidates = _which_all(["vol", "vol.py", "volatility", "volatility3"])
        for c in candidates:
            return [c]
        return None

    def run(self, plugin: str, image_path: str, extra: Optional[List[str]] = None) -> Tuple[int, str, str]:
        if not self.vol_cmd:
            return (127, "", "Volatility not found")
        cmd = self.vol_cmd + [
            "-f", image_path,
            plugin
        ]
        if extra:
            cmd.extend(extra)
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return (proc.returncode, proc.stdout, proc.stderr)
        except Exception as e:
            return (1, "", str(e))

    def pslist(self, image_path: str) -> Dict:
        code, out, err = self.run("windows.pslist", image_path, extra=["-r", "json"])
        if code != 0:
            # Try linux
            code, out, err = self.run("linux.pslist", image_path, extra=["-r", "json"])
        parsed = self._parse_json(out)
        return {"returncode": code, "stdout": out, "stderr": err, "data": parsed}

    def psscan(self, image_path: str) -> Dict:
        code, out, err = self.run("windows.psscan", image_path, extra=["-r", "json"])
        if code != 0:
            code, out, err = self.run("linux.psscan", image_path, extra=["-r", "json"])
        parsed = self._parse_json(out)
        return {"returncode": code, "stdout": out, "stderr": err, "data": parsed}

    def netscan(self, image_path: str) -> Dict:
        code, out, err = self.run("windows.netscan", image_path, extra=["-r", "json"])
        if code != 0:
            code, out, err = self.run("linux.netstat", image_path, extra=["-r", "json"])
        parsed = self._parse_json(out)
        return {"returncode": code, "stdout": out, "stderr": err, "data": parsed}

    def malfind(self, image_path: str) -> Dict:
        code, out, err = self.run("windows.malfind", image_path, extra=["-r", "json"])
        parsed = self._parse_json(out)
        return {"returncode": code, "stdout": out, "stderr": err, "data": parsed}

    def drivers(self, image_path: str) -> Dict:
        code, out, err = self.run("windows.driverscan", image_path, extra=["-r", "json"])
        if code != 0:
            code, out, err = self.run("linux.lsmod", image_path, extra=["-r", "json"])
        parsed = self._parse_json(out)
        return {"returncode": code, "stdout": out, "stderr": err, "data": parsed}

    def _parse_json(self, text: str) -> Optional[Dict]:
        text = (text or "").strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None


class MemoryAnalyzer:
    def __init__(self):
        self.vol = VolatilityInterface()

    def analyze(self, image_path: Path) -> Dict:
        """
        Analyze memory image or acquisition archive.
        Returns a structured analysis dictionary with processes, connections, drivers, hidden_processes, injections, and raw outputs.
        """
        analysis: Dict = {
            "ethical_notice": ETHICAL_WARNING,
            "source": str(image_path),
            "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {},
            "processes": [],
            "connections": [],
            "drivers": [],
            "hidden_processes": [],
            "injections": [],
            "raw": {}
        }
        if zipfile.is_zipfile(image_path):
            with zipfile.ZipFile(image_path, "r") as zf:
                namelist = zf.namelist()
                # Our acquisition format
                if "metadata.json" in namelist and "processes.json" in namelist:
                    metadata = json.loads(zf.read("metadata.json").decode("utf-8"))
                    procs = json.loads(zf.read("processes.json").decode("utf-8")).get("processes", [])
                    conns = json.loads(zf.read("connections.json").decode("utf-8")).get("connections", [])
                    drivers = json.loads(zf.read("drivers.json").decode("utf-8")).get("drivers", [])
                    heuristics = json.loads(zf.read("heuristics.json").decode("utf-8")).get("suspicious_processes", [])
                    analysis["summary"]["metadata"] = metadata
                    analysis["processes"] = procs
                    analysis["connections"] = conns
                    analysis["drivers"] = drivers
                    analysis["injections"] = heuristics
                    # Hidden process detection if pslist/psscan sidecars exist
                    if "pslist.json" in namelist and "psscan.json" in namelist:
                        pslist = json.loads(zf.read("pslist.json").decode("utf-8"))
                        psscan = json.loads(zf.read("psscan.json").decode("utf-8"))
                        analysis["hidden_processes"] = self._compute_hidden_from_sets(pslist, psscan)
                    else:
                        # if memory.raw exists try volatility
                        if "memory.raw" in namelist and self.vol.available():
                            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                                tmp.write(zf.read("memory.raw"))
                                tmp.flush()
                                hidden = self._hidden_with_volatility(Path(tmp.name))
                                analysis["hidden_processes"] = hidden
                                os.unlink(tmp.name)
                else:
                    # Generic ZIP (maybe with psscan/pslist)
                    candidates = {
                        "pslist": [n for n in namelist if n.endswith("pslist.json")],
                        "psscan": [n for n in namelist if n.endswith("psscan.json")],
                        "netscan": [n for n in namelist if n.endswith("netscan.json")],
                    }
                    if candidates["pslist"] and candidates["psscan"]:
                        pslist = json.loads(zf.read(candidates["pslist"][0]).decode("utf-8"))
                        psscan = json.loads(zf.read(candidates["psscan"][0]).decode("utf-8"))
                        analysis["hidden_processes"] = self._compute_hidden_from_sets(pslist, psscan)
                    # Try to parse raw for processes (not reliable)
        else:
            # Raw memory or unknown; try volatility if available
            if self.vol.available():
                try:
                    pslist = self.vol.pslist(str(image_path))
                    psscan = self.vol.psscan(str(image_path))
                    nets = self.vol.netscan(str(image_path))
                    dr = self.vol.drivers(str(image_path))
                    mal = self.vol.malfind(str(image_path))
                    analysis["raw"]["pslist"] = pslist
                    analysis["raw"]["psscan"] = psscan
                    analysis["raw"]["netscan"] = nets
                    analysis["raw"]["drivers"] = dr
                    analysis["raw"]["malfind"] = mal
                    # Flatten some info when structured data is present
                    analysis["hidden_processes"] = self._compute_hidden_from_vol(pslist, psscan)
                except Exception as e:
                    analysis["raw"]["error"] = str(e)
            else:
                analysis["raw"]["note"] = "Volatility not available; limited analysis performed"
                # As a fallback, detect scripts and known artifacts only; no process listing possible

        # Update summary
        analysis["summary"]["counts"] = {
            "processes": len(analysis.get("processes") or []),
            "connections": len(analysis.get("connections") or []),
            "drivers": len(analysis.get("drivers") or []),
            "hidden_processes": len(analysis.get("hidden_processes") or []),
            "injections": len(analysis.get("injections") or []),
        }
        return analysis

    def _compute_hidden_from_sets(self, pslist: Dict, psscan: Dict) -> List[Dict]:
        def to_set(objs):
            s = set()
            for o in objs or []:
                pid = o.get("pid") or o.get("Pid") or o.get("PID")
                if pid is not None:
                    s.add(int(pid))
            return s
        l = to_set(pslist.get("processes") or pslist.get("data") or pslist)
        s = to_set(psscan.get("processes") or psscan.get("data") or psscan)
        hidden_pids = list(s - l)
        hidden = []
        # include detail if available
        for o in (psscan.get("processes") or psscan.get("data") or []):
            pid = o.get("pid") or o.get("Pid") or o.get("PID")
            try:
                ipid = int(pid)
            except Exception:
                continue
            if ipid in hidden_pids:
                hidden.append(o)
        # Fallback to PIDs list
        if not hidden:
            hidden = [{"pid": pid} for pid in hidden_pids]
        return hidden

    def _compute_hidden_from_vol(self, pslist: Dict, psscan: Dict) -> List[Dict]:
        try:
            data_l = self._extract_vol_data(pslist)
            data_s = self._extract_vol_data(psscan)
            l = set(int(d.get("Pid") or d.get("pid")) for d in data_l if (d.get("Pid") or d.get("pid")) is not None)
            s = set(int(d.get("Pid") or d.get("pid")) for d in data_s if (d.get("Pid") or d.get("pid")) is not None)
            hidden_pids = s - l
            hidden = [d for d in data_s if int(d.get("Pid") or d.get("pid")) in hidden_pids]
            return hidden
        except Exception:
            return []

    def _extract_vol_data(self, obj: Dict) -> List[Dict]:
        data = obj.get("data")
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "rows" in data:
            return data["rows"]
        return []

    def _hidden_with_volatility(self, raw_path: Path) -> List[Dict]:
        try:
            pslist = self.vol.pslist(str(raw_path))
            psscan = self.vol.psscan(str(raw_path))
            return self._compute_hidden_from_vol(pslist, psscan)
        except Exception:
            return []


class MemoryCarver:
    def __init__(self, max_size: int = 16 * 1024 * 1024):
        self.max_size = max_size
        # Define patterns and end markers
        self.patterns = [
            ("pdf", b"%PDF-", b"%%EOF"),
            ("zip", b"PK\x03\x04", b"PK\x05\x06"),
            ("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
            ("elf", b"\x7fELF", None),
            ("pe", b"MZ", None),
            ("registry", b"regf", None),
            # script patterns: a set of bytes markers; end None -> fixed window
            ("script", b"#!/bin/bash", None),
            ("script", b"#!/usr/bin/env bash", None),
            ("script", b"#!/usr/bin/env sh", None),
            ("script", b"#!/bin/sh", None),
            ("script", b"#!/usr/bin/env python", None),
            ("script", b"powershell", None),
            ("script", b"<script", b"</script>"),
            ("script", b"function ", None),
            ("script", b"var ", None),
            ("script", b"const ", None),
            ("script", b"let ", None),
        ]

    def carve(self, image_path: Path, out_dir: Path, types: Optional[List[str]] = None) -> List[Dict]:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        carved = []

        def carve_stream(fobj, total_size: Optional[int], tag_prefix=""):
            chunk_size = 1024 * 1024
            overlap = 1024
            pos = 0
            window = b""
            while True:
                data = fobj.read(chunk_size)
                if not data:
                    break
                buf = window + data
                for name, start, end in self.patterns:
                    if types and name not in types:
                        continue
                    for m in re.finditer(re.escape(start), buf):
                        abs_off = pos - len(window) + m.start()
                        try:
                            content = self._extract_at(fobj, abs_off, start, end, total_size)
                            h = sha256(content).hexdigest()[:12]
                            ext = self._extension_for(name, content)
                            filename = f"{tag_prefix}{name}_{abs_off}_{h}.{ext}"
                            out_file = out_dir / filename
                            with open(out_file, "wb") as w:
                                w.write(content)
                            carved.append({"type": name, "offset": abs_off, "path": str(out_file), "size": len(content)})
                        except Exception as e:
                            logger.debug("Carve error at %d for %s: %s", abs_off, name, e)
                # move window
                if len(data) >= overlap:
                    window = data[-overlap:]
                else:
                    window = (window + data)[-overlap:]
                pos += len(data)

        p = Path(image_path)
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p, "r") as zf:
                # Prefer known raw memory members
                preferred = [n for n in zf.namelist() if n.lower().endswith((".raw", ".bin", ".dmp")) or n.lower() in ("memory.raw", "memory.bin", "dump.raw")]
                if preferred:
                    for name in preferred:
                        with zf.open(name, "r") as f:
                            tag = Path(name).name + "_"
                            # For zip entry, size known
                            total = zf.getinfo(name).file_size
                            carve_stream(_BufferedReader(f), total, tag_prefix=tag)
                else:
                    # Carve across all files, treating each as a stream
                    for name in zf.namelist():
                        with zf.open(name, "r") as f:
                            carve_stream(_BufferedReader(f), None, tag_prefix=Path(name).name + "_")
        else:
            with open(p, "rb") as f:
                # Get size
                try:
                    total = p.stat().st_size
                except Exception:
                    total = None
                carve_stream(f, total, tag_prefix="")

        return carved

    def _extract_at(self, fobj, offset: int, start: bytes, end: Optional[bytes], total_size: Optional[int]) -> bytes:
        # Save current pos
        current = fobj.tell()
        try:
            fobj.seek(offset)
            data = fobj.read(self.max_size)
            if not data.startswith(start):
                # Possibly because we read earlier after seek; try realignment
                if start in data:
                    idx = data.find(start)
                    data = data[idx:]
                else:
                    raise ValueError("Start signature not found at offset")
            if end:
                idx = data.find(end, len(start))
                if idx != -1:
                    return data[: idx + len(end)]
            # Fallback: fixed size window
            return data[: self.max_size]
        finally:
            try:
                fobj.seek(current)
            except Exception:
                pass

    def _extension_for(self, name: str, content: bytes) -> str:
        if name == "pdf":
            return "pdf"
        if name == "zip":
            return "zip"
        if name == "png":
            return "png"
        if name == "elf":
            return "elf"
        if name == "pe":
            return "exe"
        if name == "registry":
            return "hive"
        if name == "script":
            # try to guess
            if content.startswith(b"#!/usr/bin/env python") or b"import " in content[:500]:
                return "py"
            if content.startswith(b"#!/bin/bash") or content.startswith(b"#!/bin/sh") or b"#!/usr/bin/env bash" in content[:64]:
                return "sh"
            if b"powershell" in content[:512].lower():
                return "ps1"
            if b"<script" in content[:512].lower():
                return "html"
            return "txt"
        return "bin"


class ReportBuilder:
    def build_json(self, analysis: Dict, output_path: Path) -> Path:
        output_path = output_path if output_path.suffix.lower() == ".json" else output_path.with_suffix(".json")
        with open(output_path, "w", encoding="utf-8") as w:
            json.dump(analysis, w, indent=2)
        return output_path

    def build_html(self, analysis: Dict, output_path: Path) -> Path:
        output_path = output_path if output_path.suffix.lower() == ".html" else output_path.with_suffix(".html")
        html = self._render_html(analysis)
        with open(output_path, "w", encoding="utf-8") as w:
            w.write(html)
        return output_path

    def build_pdf(self, analysis: Dict, output_path: Path) -> Path:
        output_path = output_path if output_path.suffix.lower() == ".pdf" else output_path.with_suffix(".pdf")
        if REPORTLAB_AVAILABLE:
            c = canvas.Canvas(str(output_path), pagesize=A4)
            width, height = A4
            y = height - 40
            lines = self._render_text_lines(analysis)
            c.setFont("Helvetica", 10)
            for line in lines:
                for subline in self._wrap_text(line, 95):
                    if y < 40:
                        c.showPage()
                        c.setFont("Helvetica", 10)
                        y = height - 40
                    c.drawString(30, y, subline)
                    y -= 14
            c.showPage()
            c.save()
        else:
            # Fallback: write plaintext disguised as PDF (with warning)
            with open(output_path, "wb") as w:
                w.write(b"%PDF-FAKE\n")
                txt = "\n".join(self._render_text_lines(analysis))
                w.write(txt.encode("utf-8", errors="replace"))
        return output_path

    def _render_text_lines(self, analysis: Dict) -> List[str]:
        lines = []
        lines.append("Live Memory Forensic Toolkit Report")
        lines.append(f"Version: {TOOL_VERSION}")
        lines.append(f"Generated: {datetime.datetime.utcnow().isoformat()}Z")
        lines.append("")
        lines.append("Ethical Notice:")
        lines.append(ETHICAL_WARNING)
        lines.append("")
        lines.append(f"Source: {analysis.get('source')}")
        lines.append("Summary:")
        for k, v in (analysis.get("summary", {}).get("counts", {}) or {}).items():
            lines.append(f"  {k}: {v}")
        lines.append("")
        if analysis.get("hidden_processes"):
            lines.append("Hidden Processes Detected:")
            for hp in analysis["hidden_processes"][:50]:
                if isinstance(hp, dict):
                    pid = hp.get("pid") or hp.get("Pid") or hp.get("PID")
                    name = hp.get("name") or hp.get("Name") or ""
                    lines.append(f"  PID={pid} Name={name}")
                else:
                    lines.append(f"  {hp}")
        if analysis.get("injections"):
            lines.append("")
            lines.append("Suspicious Processes (Heuristics):")
            for sp in analysis["injections"][:50]:
                lines.append(f"  PID={sp.get('pid')} Name={sp.get('name')} Reason={sp.get('reason')}")
        lines.append("")
        lines.append("End of Report")
        return lines

    def _wrap_text(self, text: str, width: int) -> List[str]:
        words = text.split(" ")
        lines = []
        cur = ""
        for w in words:
            if len(cur) + len(w) + 1 > width:
                lines.append(cur)
                cur = w
            else:
                if cur:
                    cur += " " + w
                else:
                    cur = w
        if cur:
            lines.append(cur)
        return lines

    def _render_html(self, analysis: Dict) -> str:
        counts = analysis.get("summary", {}).get("counts", {})
        hidden = analysis.get("hidden_processes", [])
        inj = analysis.get("injections", [])
        html = []
        html.append("<!doctype html><html><head><meta charset='utf-8'><title>Live Memory Forensic Toolkit Report</title>")
        html.append("<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px;} pre{background:#f6f8fa;padding:10px;} table{border-collapse:collapse;} th,td{border:1px solid #ccc;padding:6px;} .warn{color:#b00;font-weight:bold;}</style>")
        html.append("</head><body>")
        html.append("<h1>Live Memory Forensic Toolkit Report</h1>")
        html.append(f"<p><b>Version:</b> {TOOL_VERSION}<br><b>Generated:</b> {datetime.datetime.utcnow().isoformat()}Z</p>")
        html.append(f"<p class='warn'>{ETHICAL_WARNING}</p>")
        html.append(f"<p><b>Source:</b> {analysis.get('source')}</p>")
        html.append("<h2>Summary</h2>")
        html.append("<ul>")
        for k, v in (counts or {}).items():
            html.append(f"<li>{k}: {v}</li>")
        html.append("</ul>")

        if hidden:
            html.append("<h2>Hidden Processes</h2>")
            html.append("<table><tr><th>PID</th><th>Name</th></tr>")
            for hp in hidden[:200]:
                if isinstance(hp, dict):
                    pid = hp.get("pid") or hp.get("Pid") or hp.get("PID") or ""
                    name = hp.get("name") or hp.get("Name") or ""
                else:
                    pid = str(hp)
                    name = ""
                html.append(f"<tr><td>{pid}</td><td>{_html_escape(name)}</td></tr>")
            html.append("</table>")

        if inj:
            html.append("<h2>Suspicious Processes (Heuristics)</h2>")
            html.append("<table><tr><th>PID</th><th>Name</th><th>Reason</th></tr>")
            for sp in inj[:200]:
                html.append(f"<tr><td>{_html_escape(str(sp.get('pid')))}</td><td>{_html_escape(str(sp.get('name')))}</td><td>{_html_escape(str(sp.get('reason')))}</td></tr>")
            html.append("</table>")

        html.append("<h2>Raw</h2>")
        html.append("<pre>")
        raw = analysis.get("raw") or {}
        snippet = _truncate_string(json.dumps(raw, indent=2), 20000)
        html.append(_html_escape(snippet))
        html.append("</pre>")

        html.append("</body></html>")
        return "".join(html)


class LiveMemoryForensicToolkit:
    def __init__(self):
        self.acquirer = MemoryAcquirer()
        self.analyzer = MemoryAnalyzer()
        self.carver = MemoryCarver()
        self.report_builder = ReportBuilder()

    def acquire(self, output_path: Path, mode: str = "lite") -> Path:
        logger.info(ETHICAL_WARNING)
        return self.acquirer.acquire(output_path=output_path, mode=mode)

    def analyze(self, image_path: Path) -> Dict:
        logger.info("Analyzing memory image: %s", image_path)
        analysis = self.analyzer.analyze(image_path)
        logger.info("Analysis complete.")
        return analysis

    def carve(self, image_path: Path, out_dir: Path, types: Optional[List[str]] = None) -> List[Dict]:
        logger.info("Carving artifacts from: %s", image_path)
        carved = self.carver.carve(image_path, out_dir, types=types)
        logger.info("Carving complete. Extracted %d artifacts.", len(carved))
        return carved

    def report(self, analysis: Dict, output_basename: Path, formats: List[str]) -> List[Path]:
        outfiles: List[Path] = []
        if "json" in formats:
            outfiles.append(self.report_builder.build_json(analysis, output_basename.with_suffix(".json")))
        if "html" in formats:
            outfiles.append(self.report_builder.build_html(analysis, output_basename.with_suffix(".html")))
        if "pdf" in formats:
            outfiles.append(self.report_builder.build_pdf(analysis, output_basename.with_suffix(".pdf")))
        logger.info("Report generated: %s", ", ".join(str(p) for p in outfiles))
        return outfiles


def _write_json(path: Path, data: Dict):
    with open(path, "w", encoding="utf-8") as w:
        json.dump(data, w, indent=2)


def _which(names: List[str]) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _which_all(names: List[str]) -> List[str]:
    found = []
    for n in names:
        p = shutil.which(n)
        if p:
            found.append(p)
    return found


def _truncate_string(s: str, maxlen: int) -> str:
    if len(s) <= maxlen:
        return s
    return s[: maxlen - 20] + "\n...[truncated]..."


def _html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class _BufferedReader(io.RawIOBase):
    """
    Wrap a file-like object that may not support tell/seek reliably (e.g., ZipExtFile) to provide a minimal
    interface for carving with seek and read. We buffer content to a temporary file if needed.
    """
    def __init__(self, f):
        self._tmp = tempfile.NamedTemporaryFile(delete=False)
        self._path = Path(self._tmp.name)
        # Copy in chunks
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            self._tmp.write(chunk)
        self._tmp.flush()
        self._tmp.close()
        self._fh = open(self._path, "rb")

    def read(self, size=-1):
        return self._fh.read(size)

    def seek(self, offset, whence=io.SEEK_SET):
        return self._fh.seek(offset, whence)

    def tell(self):
        return self._fh.tell()

    def close(self):
        try:
            self._fh.close()
        finally:
            try:
                os.unlink(self._path)
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def main():
    parser = argparse.ArgumentParser(description="Live Memory Forensic Toolkit - Acquire and analyze live memory (authorized use only)")
    sub = parser.add_subparsers(dest="cmd")

    p_acq = sub.add_parser("acquire", help="Acquire memory snapshot")
    p_acq.add_argument("-o", "--output", required=True, help="Output archive path (.lmft.zip)")
    p_acq.add_argument("--mode", choices=["lite", "full"], default="lite", help="Acquisition mode (default: lite)")

    p_an = sub.add_parser("analyze", help="Analyze memory image or acquisition archive")
    p_an.add_argument("-i", "--image", required=True, help="Path to memory image (raw/zip)")
    p_an.add_argument("-o", "--out", help="Write analysis JSON to this path")

    p_carve = sub.add_parser("carve", help="Carve artifacts from memory image")
    p_carve.add_argument("-i", "--image", required=True, help="Path to memory image (raw/zip)")
    p_carve.add_argument("-o", "--outdir", required=True, help="Directory to store carved artifacts")
    p_carve.add_argument("-t", "--types", nargs="*", help="Types to carve (pdf zip png elf pe registry script)")

    p_rep = sub.add_parser("report", help="Generate report from analysis JSON (or run analysis and report)")
    p_rep.add_argument("-i", "--image", help="Optional: if provided, will run analysis on this image first")
    p_rep.add_argument("-a", "--analysis", help="Path to existing analysis JSON to render")
    p_rep.add_argument("-o", "--outbase", required=True, help="Output base path (without extension)")
    p_rep.add_argument("-f", "--formats", nargs="*", default=["json", "html", "pdf"], help="Report formats")

    p_full = sub.add_parser("full", help="End-to-end: acquire -> analyze -> carve -> report")
    p_full.add_argument("-o", "--outdir", required=True, help="Output directory for results")
    p_full.add_argument("--mode", choices=["lite", "full"], default="lite", help="Acquisition mode")
    p_full.add_argument("--carve-types", nargs="*", default=["script", "pdf", "zip", "png", "pe", "elf", "registry"], help="Types to carve")
    p_full.add_argument("--image", help="Skip acquire and use existing image")

    args = parser.parse_args()
    toolkit = LiveMemoryForensicToolkit()

    try:
        if args.cmd == "acquire":
            archive = toolkit.acquire(Path(args.output), mode=args.mode)
            print(str(archive))
        elif args.cmd == "analyze":
            analysis = toolkit.analyze(Path(args.image))
            if args.out:
                with open(args.out, "w", encoding="utf-8") as w:
                    json.dump(analysis, w, indent=2)
                print(args.out)
            else:
                print(json.dumps(analysis, indent=2))
        elif args.cmd == "carve":
            carved = toolkit.carve(Path(args.image), Path(args.outdir), types=args.types)
            print(json.dumps(carved, indent=2))
        elif args.cmd == "report":
            if args.image:
                analysis = toolkit.analyze(Path(args.image))
            else:
                if not args.analysis:
                    raise ValueError("Either --image or --analysis must be provided")
                with open(args.analysis, "r", encoding="utf-8") as r:
                    analysis = json.load(r)
            outbase = Path(args.outbase)
            outputs = toolkit.report(analysis, outbase, formats=args.formats)
            for p in outputs:
                print(str(p))
        elif args.cmd == "full":
            outdir = Path(args.outdir)
            outdir.mkdir(parents=True, exist_ok=True)
            if args.image:
                image_path = Path(args.image)
            else:
                image_path = toolkit.acquire(outdir / "acquisition.lmft.zip", mode=args.mode)
            analysis = toolkit.analyze(image_path)
            with open(outdir / "analysis.json", "w", encoding="utf-8") as w:
                json.dump(analysis, w, indent=2)
            carved_dir = outdir / "carved"
            toolkit.carve(image_path, carved_dir, types=args.carve_types)
            toolkit.report(analysis, outdir / "report", formats=["json", "html", "pdf"])
            print(str(outdir))
        else:
            parser.print_help()
    except Exception as e:
        logger.error("Error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()