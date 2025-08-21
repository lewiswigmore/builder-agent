#!/usr/bin/env python3
"""
Security Log Analyzer - Advanced log analysis tool for detecting security events and anomalies

Guidelines:
- Authorized testing and use only. Use responsibly and ethically. Ensure you have explicit permission
  to analyze any logs and systems. Unauthorized access or analysis may be illegal and unethical.
- This tool performs best-effort detection and correlation and may produce false positives/negatives.
- Proper error handling is included, but always validate findings before acting.

Features:
- Parse multiple log formats: syslog (RFC3164-ish), JSON (one object per line), CSV (header-based), Apache access logs (common/combined).
- Pattern matching for known attack signatures (e.g., SQL injection, XSS, path traversal, command injection).
- Anomaly detection using simple statistical analysis.
- IOC (Indicators of Compromise) correlation for IPs (from a provided file).
- Timeline analysis and event correlation by IP.

Usage:
  python -m tools.threat_hunt.log_analyzer --input path/to/logfile.log [--format auto|apache|syslog|json|csv]
                                           [--ioc-ips ioc_ips.txt] [--output report.json]
                                           [--timeline timeline.json] [--json]

Notes:
- The analyzer attempts to auto-detect log format by sampling lines unless explicitly specified.
- CSV is expected to have a header row.
- JSON logs should be one JSON object per line.
- Apache access logs in Common or Combined format are supported for parsing and signature detection.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# --------- Utility and Data Structures ----------

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return default

def parse_iso8601(s: str) -> Optional[datetime]:
    try:
        # Try standard fromisoformat
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass
    # Try a few common formats
    for fmt in ("%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(s, fmt)
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    # Epoch seconds?
    try:
        if "." in s:
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
        return datetime.fromtimestamp(int(s), tz=timezone.utc)
    except Exception:
        return None

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

@dataclass
class Event:
    timestamp: datetime
    source_type: str
    message: str
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    status: Optional[int] = None
    bytes_sent: Optional[int] = None
    user_agent: Optional[str] = None
    host: Optional[str] = None
    process: Optional[str] = None
    severity: str = "INFO"
    tags: List[str] = field(default_factory=list)
    matched_signatures: List[str] = field(default_factory=list)
    ioc_hits: List[str] = field(default_factory=list)
    raw: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

# --------- Signature Engine ----------

DEFAULT_SIGNATURES = [
    {"name": "SQL Injection - Union Select", "pattern": r"(?i)union\s+(?:all\s+)?select\b"},
    {"name": "SQL Injection - Boolean", "pattern": r"(?i)(?:\bor\b|\band\b)\s+\d+\s*=\s*\d+"},
    {"name": "SQL Injection - tautology 1=1", "pattern": r"(?i)1\s*=\s*1"},
    {"name": "SQL Injection - Comment", "pattern": r"(?i)(?:--|#|/\*)\s*$"},
    {"name": "SQL Injection - Sleep/Benchmark", "pattern": r"(?i)\b(?:sleep|benchmark)\s*\("},
    {"name": "Path Traversal", "pattern": r"(?i)(?:\.\./|%2e%2e%2f)"},
    {"name": "XSS - Script Tag", "pattern": r"(?i)<\s*script\b"},
    {"name": "Command Injection", "pattern": r"(?i)[;&|]\s*(?:sh|bash|nc|curl|wget|python|perl|php|cat|ls|whoami)\b"},
]

class SignatureEngine:
    def __init__(self, signature_file: Optional[str] = None):
        self.rules: List[Tuple[str, re.Pattern]] = []
        self.load(signature_file)

    def load(self, signature_file: Optional[str]):
        rules: List[Dict[str, str]] = []
        if signature_file and os.path.isfile(signature_file):
            try:
                with open(signature_file, "r", encoding="utf-8") as f:
                    rules = json.load(f)
            except Exception as e:
                eprint(f"[!] Failed to load signatures from {signature_file}: {e}")
        if not rules:
            # Try default location relative to this file
            here = os.path.dirname(os.path.abspath(__file__))
            default_path = os.path.join(here, "signatures", "attack_signatures.json")
            if os.path.isfile(default_path):
                try:
                    with open(default_path, "r", encoding="utf-8") as f:
                        rules = json.load(f)
                except Exception as e:
                    eprint(f"[!] Failed to load built-in signatures: {e}")
        if not rules:
            rules = DEFAULT_SIGNATURES
        compiled: List[Tuple[str, re.Pattern]] = []
        for r in rules:
            name = r.get("name") or "Unnamed"
            pat = r.get("pattern")
            if not pat:
                continue
            try:
                compiled.append((name, re.compile(pat)))
            except re.error as e:
                eprint(f"[!] Invalid regex in signature '{name}': {e}")
        self.rules = compiled

    def match_text(self, text: str) -> List[str]:
        hits = []
        for name, pat in self.rules:
            try:
                if pat.search(text):
                    hits.append(name)
            except Exception:
                continue
        return hits

    def evaluate_event(self, ev: Event) -> List[str]:
        fields_to_check = []
        if ev.message:
            fields_to_check.append(ev.message)
        if ev.url:
            fields_to_check.append(ev.url)
        # Also include the raw request line if present in extra
        raw_req = ev.extra.get("request_line")
        if raw_req:
            fields_to_check.append(str(raw_req))
        combined = "\n".join(fields_to_check)
        if not combined:
            return []
        return self.match_text(combined)

# --------- IOC Engine ----------

class IOCEngine:
    def __init__(self, ip_iocs_path: Optional[str] = None):
        self.ip_set: set[str] = set()
        if ip_iocs_path:
            self.load_ips(ip_iocs_path)

    def load_ips(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    self.ip_set.add(s)
        except FileNotFoundError:
            eprint(f"[!] IOC IP file not found: {path}")
        except Exception as e:
            eprint(f"[!] Failed to load IOC IPs: {e}")

    def check_ip(self, ip: Optional[str]) -> Optional[str]:
        if ip and ip in self.ip_set:
            return ip
        return None

# --------- Parsers ----------

class BaseParser:
    def source_type(self) -> str:
        raise NotImplementedError

    def can_parse_sample(self, lines: List[str]) -> float:
        # Return ratio of lines likely parsed successfully
        successes = 0
        tested = 0
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            tested += 1
            try:
                if self.try_parse_line(ln) is not None:
                    successes += 1
            except Exception:
                continue
            if tested >= 25:
                break
        if tested == 0:
            return 0.0
        return successes / tested

    def parse(self, data: Union[str, Iterable[str]]) -> List[Event]:
        raise NotImplementedError

    def try_parse_line(self, line: str) -> Optional[Event]:
        raise NotImplementedError

class ApacheAccessLogParser(BaseParser):
    # Common and Combined log format regexes
    # Common: ip ident authuser [date] "request" status bytes
    COMMON = re.compile(
        r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\S+)'
    )
    # Combined: common + "referer" "user-agent"
    COMBINED = re.compile(
        r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
    )

    def source_type(self) -> str:
        return "apache_access"

    def try_parse_line(self, line: str) -> Optional[Event]:
        m = self.COMBINED.match(line) or self.COMMON.match(line)
        if not m:
            return None
        ts = self._parse_apache_time(m.group("ts"))
        if not ts:
            ts = now_utc()
        request = m.group("request") or ""
        method = None
        url = None
        if request:
            parts = request.split()
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]
        status = safe_int(m.group("status")) if m.group("status") and m.group("status") != "-" else None
        bytes_sent = None if m.group("bytes") in (None, "-",) else safe_int(m.group("bytes"))
        ua = m.groupdict().get("ua") or None
        ev = Event(
            timestamp=ts,
            source_type=self.source_type(),
            message=request,
            src_ip=m.group("ip"),
            method=method,
            url=url,
            status=status,
            bytes_sent=bytes_sent,
            user_agent=ua,
            raw=line,
            extra={"ident": m.group("ident"), "authuser": m.group("authuser"), "request_line": request}
        )
        return ev

    def parse(self, data: Union[str, Iterable[str]]) -> List[Event]:
        if isinstance(data, str):
            lines = data.splitlines()
        else:
            lines = list(data)
        events: List[Event] = []
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                ev = self.try_parse_line(line)
                if ev:
                    events.append(ev)
            except Exception:
                continue
        return events

    @staticmethod
    def _parse_apache_time(s: str) -> Optional[datetime]:
        # Example: 10/Oct/2000:13:55:36 -0700
        try:
            return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            try:
                dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                return parse_iso8601(s)

class SyslogParser(BaseParser):
    # Simplified RFC3164-like
    # <PRI>MMM dd HH:MM:SS host process[pid]: message
    SYSLOG = re.compile(
        r'^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)$'
    )

    def source_type(self) -> str:
        return "syslog"

    def try_parse_line(self, line: str) -> Optional[Event]:
        m = self.SYSLOG.match(line)
        if not m:
            return None
        ts = self._parse_syslog_time(m.group("ts"))
        if not ts:
            ts = now_utc()
        ev = Event(
            timestamp=ts,
            source_type=self.source_type(),
            message=m.group("msg"),
            host=m.group("host"),
            process=m.group("proc"),
            raw=line,
        )
        # Try to extract IP and URL from message
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", m.group("msg"))
        if ip_match:
            ev.src_ip = ip_match.group(1)
        url_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^"]+)"', m.group("msg"))
        if url_match:
            ev.method = url_match.group(1)
            ev.url = url_match.group(2)
        return ev

    def parse(self, data: Union[str, Iterable[str]]) -> List[Event]:
        if isinstance(data, str):
            lines = data.splitlines()
        else:
            lines = list(data)
        events: List[Event] = []
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                ev = self.try_parse_line(line)
                if ev:
                    events.append(ev)
            except Exception:
                continue
        return events

    @staticmethod
    def _parse_syslog_time(s: str) -> Optional[datetime]:
        # Syslog timestamps are without year and tz; assume current year, local timezone then convert to UTC
        try:
            dt = datetime.strptime(s, "%b %d %H:%M:%S")
        except ValueError:
            # Handle single-digit day with leading space (already handled by %d) or different formats
            return None
        # Assume current year
        now = datetime.now()
        dt = dt.replace(year=now.year)
        # Assume local time; convert to UTC
        try:
            import time as time_mod
            import datetime as dt_mod
            local_tz = dt_mod.timezone(timedelta(seconds=-time_mod.timezone))
            dt_local = dt.replace(tzinfo=local_tz)
            return dt_local.astimezone(timezone.utc)
        except Exception:
            return dt.replace(tzinfo=timezone.utc)

class JSONLogParser(BaseParser):
    def source_type(self) -> str:
        return "json"

    def try_parse_line(self, line: str) -> Optional[Event]:
        line = line.strip()
        if not line:
            return None
        if not (line.startswith("{") and line.endswith("}")):
            return None
        try:
            obj = json.loads(line)
        except Exception:
            return None
        return self._event_from_obj(obj, raw=line)

    def _event_from_obj(self, obj: Dict[str, Any], raw: Optional[str] = None) -> Event:
        # Map common keys
        ts = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp") or obj.get("ts")
        ts_dt = parse_iso8601(str(ts)) if ts is not None else now_utc()
        msg = obj.get("message") or obj.get("msg") or obj.get("log") or ""
        src_ip = obj.get("src_ip") or obj.get("ip") or obj.get("client_ip") or obj.get("remote_addr")
        dest_ip = obj.get("dest_ip") or obj.get("dst_ip")
        method = obj.get("method") or obj.get("http_method")
        url = obj.get("url") or obj.get("uri") or obj.get("path") or obj.get("request")
        status = obj.get("status") or obj.get("status_code") or obj.get("code")
        status_int = safe_int(status) if status is not None else None
        bytes_sent = safe_int(obj.get("bytes") or obj.get("bytes_sent")) if obj.get("bytes") or obj.get("bytes_sent") else None
        ua = obj.get("user_agent") or obj.get("ua")
        host = obj.get("host") or obj.get("hostname")
        process = obj.get("process") or obj.get("app") or obj.get("program")
        ev = Event(
            timestamp=ts_dt if ts_dt else now_utc(),
            source_type=self.source_type(),
            message=str(msg),
            src_ip=src_ip,
            dest_ip=dest_ip,
            method=method,
            url=url,
            status=status_int,
            bytes_sent=bytes_sent,
            user_agent=ua,
            host=host,
            process=process,
            raw=raw if raw else json.dumps(obj, ensure_ascii=False),
            extra={k: v for k, v in obj.items() if k not in {"timestamp","time","@timestamp","ts","message","msg","log","src_ip","ip","client_ip","remote_addr","dest_ip","dst_ip","method","http_method","url","uri","path","request","status","status_code","code","bytes","bytes_sent","user_agent","ua","host","hostname","process","app","program"}}
        )
        return ev

    def parse(self, data: Union[str, Iterable[str]]) -> List[Event]:
        lines = data.splitlines() if isinstance(data, str) else list(data)
        events: List[Event] = []
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                ev = self.try_parse_line(line)
                if ev:
                    events.append(ev)
            except Exception:
                continue
        return events

class CSVLogParser(BaseParser):
    def __init__(self):
        self._header: Optional[List[str]] = None

    def source_type(self) -> str:
        return "csv"

    def _row_to_event(self, row: Dict[str, str]) -> Event:
        # Normalize keys to lower
        lower = {k.lower().strip(): v for k, v in row.items()}
        ts = lower.get("timestamp") or lower.get("time") or lower.get("@timestamp") or lower.get("ts")
        ts_dt = parse_iso8601(str(ts)) if ts is not None else now_utc()
        msg = lower.get("message") or lower.get("msg") or lower.get("log") or ""
        src_ip = lower.get("src_ip") or lower.get("ip") or lower.get("client_ip") or lower.get("remote_addr")
        dest_ip = lower.get("dest_ip") or lower.get("dst_ip")
        method = lower.get("method") or lower.get("http_method")
        url = lower.get("url") or lower.get("uri") or lower.get("path") or lower.get("request")
        status = lower.get("status") or lower.get("status_code") or lower.get("code")
        status_int = safe_int(status) if status is not None else None
        bytes_sent = safe_int(lower.get("bytes") or lower.get("bytes_sent")) if (lower.get("bytes") or lower.get("bytes_sent")) else None
        ua = lower.get("user_agent") or lower.get("ua")
        host = lower.get("host") or lower.get("hostname")
        process = lower.get("process") or lower.get("app") or lower.get("program")
        ev = Event(
            timestamp=ts_dt if ts_dt else now_utc(),
            source_type=self.source_type(),
            message=str(msg),
            src_ip=src_ip,
            dest_ip=dest_ip,
            method=method,
            url=url,
            status=status_int,
            bytes_sent=bytes_sent,
            user_agent=ua,
            host=host,
            process=process,
            raw=json.dumps(row, ensure_ascii=False),
            extra={k: v for k, v in row.items()}
        )
        return ev

    def try_parse_line(self, line: str) -> Optional[Event]:
        # This parser relies on header; for sampling, do a best effort:
        # Consider it's CSV if it has at least two commas and no unbalanced quotes
        if line.count(",") < 1:
            return None
        # Just attempt to create a dummy DictReader with header guessed from first line; not robust but sufficient for sampling
        try:
            # naive check for quotes balance
            if line.count('"') % 2 != 0:
                return None
        except Exception:
            return None
        # Cannot parse a single line without headers into an Event sensibly
        return None

    def parse(self, data: Union[str, Iterable[str]]) -> List[Event]:
        if isinstance(data, str):
            lines = data.splitlines()
        else:
            lines = list(data)
        events: List[Event] = []
        if not lines:
            return events
        try:
            reader = csv.DictReader(lines)
        except Exception:
            return events
        for row in reader:
            try:
                ev = self._row_to_event(row)
                if ev:
                    events.append(ev)
            except Exception:
                continue
        return events

# --------- Analyzer and Correlation ----------

class AnomalyDetector:
    def __init__(self):
        pass

    def detect(self, events: List[Event]) -> Dict[str, Dict[str, Any]]:
        # Returns a mapping of ip -> anomaly info
        per_ip = defaultdict(list)
        for ev in events:
            if ev.src_ip:
                per_ip[ev.src_ip].append(ev)

        counts = {ip: len(lst) for ip, lst in per_ip.items()}
        anomalies: Dict[str, Dict[str, Any]] = {}
        if counts:
            mean = sum(counts.values()) / len(counts)
            var = sum((c - mean) ** 2 for c in counts.values()) / len(counts)
            std = math.sqrt(var)
            threshold = mean + 3 * std if std > 0 else (mean * 2 + 10)
            for ip, c in counts.items():
                if c >= max(threshold, mean + 5) and c > 10:
                    anomalies.setdefault(ip, {"reasons": [], "metrics": {}})
                    anomalies[ip]["reasons"].append("High request volume")
                    anomalies[ip]["metrics"]["count"] = c
                    anomalies[ip]["metrics"]["mean"] = mean
                    anomalies[ip]["metrics"]["std"] = std

        # Look for high 404/500 error ratios per IP
        for ip, lst in per_ip.items():
            if not lst:
                continue
            status_codes = [ev.status for ev in lst if ev.status is not None]
            if not status_codes:
                continue
            err = sum(1 for s in status_codes if s >= 400)
            ratio = err / len(status_codes)
            if ratio >= 0.6 and err >= 5:
                anomalies.setdefault(ip, {"reasons": [], "metrics": {}})
                anomalies[ip]["reasons"].append("High error ratio")
                anomalies[ip]["metrics"]["error_ratio"] = round(ratio, 3)
                anomalies[ip]["metrics"]["errors"] = err
                anomalies[ip]["metrics"]["total"] = len(status_codes)

        # Rare user-agent anomalies
        ua_counter = Counter(ev.user_agent for ev in events if ev.user_agent)
        rare_uas = {ua for ua, cnt in ua_counter.items() if cnt == 1 and len(ua_counter) > 5}
        for ev in events:
            if ev.user_agent and ev.user_agent in rare_uas and ev.src_ip:
                anomalies.setdefault(ev.src_ip, {"reasons": [], "metrics": {}})
                if "Rare user-agent" not in anomalies[ev.src_ip]["reasons"]:
                    anomalies[ev.src_ip]["reasons"].append("Rare user-agent")

        return anomalies

class Correlator:
    def build_timeline(self, events: List[Event]) -> List[Dict[str, Any]]:
        # Return sorted events as dictionaries
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        return [e.to_dict() for e in sorted_events]

    def correlate_by_ip(self, events: List[Event]) -> Dict[str, List[Dict[str, Any]]]:
        by_ip: Dict[str, List[Event]] = defaultdict(list)
        for e in events:
            if e.src_ip:
                by_ip[e.src_ip].append(e)
        # Sort each list by time
        correlated: Dict[str, List[Dict[str, Any]]] = {}
        for ip, evs in by_ip.items():
            evs_sorted = sorted(evs, key=lambda e: e.timestamp)
            correlated[ip] = [e.to_dict() for e in evs_sorted]
        return correlated

# --------- Format Auto-Detection ----------

class ParserSelector:
    def __init__(self):
        self.parsers = [
            JSONLogParser(),
            ApacheAccessLogParser(),
            SyslogParser(),
            CSVLogParser(),
        ]

    def select(self, sample_lines: List[str], forced: Optional[str] = None) -> BaseParser:
        forced = (forced or "").lower()
        if forced in ("apache", "apache_access"):
            return ApacheAccessLogParser()
        if forced in ("syslog",):
            return SyslogParser()
        if forced in ("json", "jsonl"):
            return JSONLogParser()
        if forced in ("csv",):
            return CSVLogParser()

        # Heuristics by file content
        # If most lines start with { and end with }, it's JSONL
        json_like = sum(1 for l in sample_lines if l.strip().startswith("{") and l.strip().endswith("}"))
        if json_like >= max(1, len([l for l in sample_lines if l.strip()]) // 2):
            return JSONLogParser()

        # Evaluate parsers by success ratio
        best_parser: Optional[BaseParser] = None
        best_score = -1.0
        for p in self.parsers:
            try:
                score = p.can_parse_sample(sample_lines)
            except Exception:
                score = 0.0
            if score > best_score:
                best_score = score
                best_parser = p

        # Fallback
        return best_parser or ApacheAccessLogParser()

# --------- Main Analyzer ----------

class SecurityLogAnalyzer:
    def __init__(self, signature_file: Optional[str] = None, ioc_ips: Optional[str] = None):
        self.signature_engine = SignatureEngine(signature_file=signature_file)
        self.ioc_engine = IOCEngine(ip_iocs_path=ioc_ips)
        self.anomaly_detector = AnomalyDetector()
        self.correlator = Correlator()
        self.selector = ParserSelector()

    def analyze(self, input_paths: List[str], forced_format: Optional[str] = None) -> Dict[str, Any]:
        all_events: List[Event] = []
        for path in input_paths:
            # Read content
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except FileNotFoundError:
                eprint(f"[!] Input file not found: {path}")
                continue
            except Exception as e:
                eprint(f"[!] Failed to read {path}: {e}")
                continue

            # Select parser
            parser = self.selector.select(lines[:100], forced=forced_format)

            # Parse
            try:
                events = parser.parse(lines)
            except Exception as e:
                eprint(f"[!] Failed to parse {path} with {parser.source_type()}: {e}")
                events = []

            # Enhance events with signatures and IOCs
            for ev in events:
                try:
                    hits = self.signature_engine.evaluate_event(ev)
                    if hits:
                        ev.matched_signatures.extend(hits)
                        ev.severity = "HIGH"
                        ev.tags.append("signature")
                except Exception as e:
                    eprint(f"[!] Signature evaluation error: {e}")
                try:
                    ioc_hit = self.ioc_engine.check_ip(ev.src_ip)
                    if ioc_hit:
                        ev.ioc_hits.append(ioc_hit)
                        ev.severity = "CRITICAL"
                        ev.tags.append("ioc")
                except Exception as e:
                    eprint(f"[!] IOC check error: {e}")
            all_events.extend(events)

        # Anomaly detection
        anomalies = self.anomaly_detector.detect(all_events)
        for ev in all_events:
            if ev.src_ip and ev.src_ip in anomalies:
                if "anomaly" not in ev.tags:
                    ev.tags.append("anomaly")
                if ev.severity == "INFO":
                    ev.severity = "MEDIUM"

        # Identify suspicious IP addresses
        suspicious_ips: Dict[str, Dict[str, Any]] = {}
        for ev in all_events:
            if not ev.src_ip:
                continue
            ip_info = suspicious_ips.setdefault(ev.src_ip, {"signature_hits": 0, "ioc_hits": 0, "anomaly": False, "events": 0})
            ip_info["events"] += 1
            if ev.matched_signatures:
                ip_info["signature_hits"] += 1
            if ev.ioc_hits:
                ip_info["ioc_hits"] += 1
            if ev.src_ip in anomalies:
                ip_info["anomaly"] = True

        # Build results
        timeline = self.correlator.build_timeline(all_events)
        correlated = self.correlator.correlate_by_ip(all_events)

        return {
            "events": [e.to_dict() for e in all_events],
            "suspicious_ips": suspicious_ips,
            "anomalies": anomalies,
            "timeline": timeline,
            "correlated_by_ip": correlated,
            "stats": {
                "total_events": len(all_events),
                "signature_hits": sum(1 for e in all_events if e.matched_signatures),
                "ioc_events": sum(1 for e in all_events if e.ioc_hits),
                "anomalous_events": sum(1 for e in all_events if "anomaly" in e.tags),
                "sources": Counter(e.source_type for e in all_events),
            }
        }

def print_summary(report: Dict[str, Any], as_json: bool = False):
    if as_json:
        try:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        except Exception as e:
            eprint(f"[!] Failed to render JSON report: {e}")
        return
    # Text summary
    stats = report.get("stats", {})
    print("=== Security Log Analyzer Report ===")
    print(f"Total events: {stats.get('total_events', 0)}")
    print(f"Signature hits: {stats.get('signature_hits', 0)}")
    print(f"IOC-correlated events: {stats.get('ioc_events', 0)}")
    print(f"Anomalous events: {stats.get('anomalous_events', 0)}")
    sources = stats.get("sources", {})
    if sources:
        print("Sources:")
        for src, cnt in (sources.items() if isinstance(sources, dict) else sources.most_common()):
            print(f"  - {src}: {cnt}")

    # Suspicious IPs
    susp = report.get("suspicious_ips", {})
    if susp:
        print("Suspicious IP addresses:")
        for ip, info in susp.items():
            if info.get("signature_hits") or info.get("ioc_hits") or info.get("anomaly"):
                flags = []
                if info.get("signature_hits"):
                    flags.append(f"signatures={info['signature_hits']}")
                if info.get("ioc_hits"):
                    flags.append(f"ioc={info['ioc_hits']}")
                if info.get("anomaly"):
                    flags.append("anomaly")
                print(f"  - {ip} ({', '.join(flags)})")

    print("\nNote: Use responsibly and ethically. Authorized testing only.")

def save_json(path: str, obj: Any):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
    except Exception as e:
        eprint(f"[!] Failed to write JSON to {path}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Advanced threat hunting log analysis tool",
        epilog="Ethical use only. Ensure you are authorized to analyze the given logs."
    )
    parser.add_argument("--input", "-i", nargs="+", required=True, help="Path(s) to input log file(s)")
    parser.add_argument("--format", "-f", default="auto", help="Log format: auto|apache|syslog|json|csv")
    parser.add_argument("--signatures", "-s", default=None, help="Path to signature JSON file (optional)")
    parser.add_argument("--ioc-ips", default=None, help="Path to a text file with IOC IPs (one per line)")
    parser.add_argument("--output", "-o", default=None, help="Path to write full JSON report")
    parser.add_argument("--timeline", "-t", default=None, help="Path to write event timeline JSON")
    parser.add_argument("--json", action="store_true", help="Print JSON summary to stdout")
    parser.add_argument("--no-banner", action="store_true", help="Do not print ethical warning banner")
    args = parser.parse_args()

    if not args.no_banner:
        eprint("Security Log Analyzer - For authorized security testing and incident response only.")
        eprint("Ensure you have explicit permission to collect and analyze logs. Misuse may be illegal.")

    analyzer = SecurityLogAnalyzer(signature_file=args.signatures, ioc_ips=args.ioc_ips)
    report = analyzer.analyze(args.input, forced_format=args.format)

    # Save outputs
    if args.output:
        save_json(args.output, report)
    if args.timeline:
        save_json(args.timeline, report.get("timeline", []))

    # Print summary
    print_summary(report, as_json=args.json)

if __name__ == "__main__":
    main()