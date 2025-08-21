import io
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, List, Optional

import pytest

# Import the analyzer module
import importlib

analyzer_module = importlib.import_module("tools.threat_hunt.log_analyzer")


def get_attr(obj: Any, names: Iterable[str]) -> Optional[Any]:
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


@pytest.fixture(scope="session")
def analyzer():
    # Try to construct a class-based analyzer if available; else return module as the "analyzer"
    cls = get_attr(analyzer_module, ["SecurityLogAnalyzer", "LogAnalyzer", "Analyzer"])
    if cls is not None:
        try:
            return cls()
        except TypeError:
            # If class requires config, try default None
            return cls(config=None)
    # Fallback to module-level functions
    return analyzer_module


@pytest.fixture
def apache_access_logs() -> str:
    # Sample Apache Combined Log Format lines, including an SQL injection attempt
    return "\n".join(
        [
            '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"',
            '192.0.2.1 - - [10/Oct/2023:13:56:01 +0000] "GET /search.php?q=%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 512 "-" "curl/7.68.0"',
            '198.51.100.23 - - [10/Oct/2023:13:56:05 +0000] "GET /items?id=1%20UNION%20SELECT%201,username,password%20FROM%20users HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
        ]
    )


@pytest.fixture
def syslog_lines() -> str:
    # Classic syslog lines with embedded IP patterns
    return "\n".join(
        [
            "Oct 11 22:14:15 testhost sshd[12345]: Failed password for invalid user admin from 192.0.2.1 port 4242 ssh2",
            "Oct 11 22:14:16 testhost sshd[12345]: Accepted password for user from 127.0.0.1 port 4243 ssh2",
            "Oct 11 22:14:20 testhost app[3456]: Connection from 203.0.113.5 to /admin attempted",
        ]
    )


@pytest.fixture
def json_lines() -> str:
    entries = [
        {
            "timestamp": "2023-10-10T13:56:01+00:00",
            "ip": "203.0.113.5",
            "event": "login_failed",
            "message": "User admin failed login",
        },
        {
            "timestamp": "2023-10-10T13:56:05+00:00",
            "ip": "198.51.100.23",
            "event": "file_access",
            "message": "Access to sensitive file",
        },
        {
            "timestamp": "2023-10-10T13:56:10+00:00",
            "ip": "127.0.0.1",
            "event": "heartbeat",
            "message": "Service check",
        },
    ]
    return "\n".join(json.dumps(e) for e in entries)


@pytest.fixture
def csv_lines() -> str:
    # CSV with header
    return "\n".join(
        [
            "timestamp,ip,message,status",
            "2023-10-10T13:56:01+00:00,192.0.2.1,GET /index.html,200",
            "2023-10-10T13:56:05+00:00,127.0.0.1,POST /login,401",
            "2023-10-10T13:56:10+00:00,198.51.100.23,GET /admin,403",
        ]
    )


def call_parse(parse_callable: Callable, data: Any, fmt: str, tmp_path) -> List[dict]:
    # Try common calling conventions for parse APIs
    # 1) parse(data, format=fmt)
    try:
        result = parse_callable(data, format=fmt)
        if result is not None:
            return list(result)
    except TypeError:
        pass
    # 2) parse(data, fmt)
    try:
        result = parse_callable(data, fmt)
        if result is not None:
            return list(result)
    except TypeError:
        pass
    # 3) parse(format=fmt, data=data)
    try:
        result = parse_callable(format=fmt, data=data)
        if result is not None:
            return list(result)
    except TypeError:
        pass
    # 4) If parser expects a file path, write to temp file and pass path
    file_path = tmp_path / f"logs_{fmt}.log"
    mode = "w"
    if isinstance(data, (bytes, bytearray)):
        mode = "wb"
    with open(file_path, mode) as f:
        if "b" in mode:
            f.write(data)
        else:
            f.write(str(data))
    try:
        result = parse_callable(str(file_path), format=fmt)
        if result is not None:
            return list(result)
    except TypeError:
        pass
    try:
        result = parse_callable(str(file_path), fmt)
        if result is not None:
            return list(result)
    except TypeError:
        pass
    raise AssertionError("parse_logs function did not accept provided arguments")


def ensure_parse_fn(analyzer) -> Callable:
    parse_fn = get_attr(analyzer, ["parse_logs", "parse", "load", "ingest"])
    assert callable(parse_fn), "parse function not found in analyzer"
    return parse_fn


def ensure_sig_fn(analyzer) -> Callable:
    sig_fn = get_attr(
        analyzer,
        [
            "detect_attack_signatures",
            "detect_signatures",
            "pattern_match",
            "match_signatures",
        ],
    )
    assert callable(sig_fn), "signature detection function not found in analyzer"
    return sig_fn


def ensure_anomaly_fn(analyzer) -> Callable:
    anomaly_fn = get_attr(
        analyzer,
        [
            "detect_anomalies",
            "anomaly_detection",
            "find_anomalies",
            "detect_statistical_anomalies",
        ],
    )
    assert callable(anomaly_fn), "anomaly detection function not found in analyzer"
    return anomaly_fn


def ensure_ioc_fn(analyzer) -> Callable:
    ioc_fn = get_attr(
        analyzer,
        ["correlate_iocs", "ioc_correlation", "match_iocs", "correlate_indicators"],
    )
    assert callable(ioc_fn), "IOC correlation function not found in analyzer"
    return ioc_fn


def ensure_timeline_fn(analyzer) -> Callable:
    timeline_fn = get_attr(
        analyzer, ["generate_timeline", "timeline_analysis", "build_timeline"]
    )
    assert callable(timeline_fn), "timeline generation function not found in analyzer"
    return timeline_fn


def item_get(item: Any, keys: List[str]) -> Optional[Any]:
    if isinstance(item, dict):
        for k in keys:
            if k in item:
                return item[k]
    for k in keys:
        if hasattr(item, k):
            return getattr(item, k)
    return None


def parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        # Try common formats
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        # Try fromisoformat (handles +00:00)
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None
    return None


def has_sql_injection_flag(detection: Any) -> bool:
    # Determine if a detection entry indicates SQL injection
    text = ""
    for key in ("type", "signature", "name", "rule"):
        v = item_get(detection, [key])
        if isinstance(v, str):
            text += v.lower() + " "
    # Also inspect message/context
    for key in ("message", "context", "pattern"):
        v = item_get(detection, [key])
        if isinstance(v, str):
            text += v.lower() + " "
    return "sql" in text and "inject" in text


def get_event_ip(event: Any) -> Optional[str]:
    return item_get(event, ["ip", "source_ip", "src_ip", "client_ip", "remote_addr"])


def get_event_status(event: Any) -> Optional[int]:
    status = item_get(event, ["status", "status_code", "http_status"])
    if isinstance(status, int):
        return status
    if isinstance(status, str) and status.isdigit():
        return int(status)
    return None


def get_event_request_path(event: Any) -> Optional[str]:
    return item_get(
        event,
        ["path", "url", "request_path", "uri", "request", "http_request", "resource"],
    )


def get_event_method(event: Any) -> Optional[str]:
    return item_get(event, ["method", "http_method", "request_method"])


def get_detection_ip(detection: Any) -> Optional[str]:
    for key in ("ip", "source_ip", "ioc", "indicator", "value", "match"):
        val = item_get(detection, [key])
        if isinstance(val, str):
            return val
    # If detection refers to an event
    ev = item_get(detection, ["event"])
    if ev:
        return get_event_ip(ev)
    return None


def ensure_list_events(obj: Any) -> List[dict]:
    # Ensure we get a list of events as dict-like objects
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    if hasattr(obj, "__iter__"):
        return list(obj)
    return [obj]


def test_parse_apache_access_logs_success(analyzer, apache_access_logs, tmp_path):
    parse_fn = ensure_parse_fn(analyzer)
    events = call_parse(parse_fn, apache_access_logs, "apache", tmp_path)
    events = ensure_list_events(events)
    assert len(events) >= 3, "Should parse all Apache access log lines"

    # Validate that IP, method, path, and status are extracted
    ips = [get_event_ip(e) for e in events]
    assert "127.0.0.1" in ips
    assert "192.0.2.1" in ips
    assert "198.51.100.23" in ips

    methods = [get_event_method(e) for e in events]
    assert any(m and m.upper() == "GET" for m in methods)

    paths = [get_event_request_path(e) for e in events]
    assert any(p and "/index.html" in p for p in paths)
    assert any(p and "/search.php" in p for p in paths)
    assert any(p and "/items" in p for p in paths)

    statuses = [get_event_status(e) for e in events]
    assert 200 in statuses
    assert 500 in statuses


def test_detect_sql_injection_attempts(analyzer, apache_access_logs, tmp_path):
    parse_fn = ensure_parse_fn(analyzer)
    sig_fn = ensure_sig_fn(analyzer)
    events = call_parse(parse_fn, apache_access_logs, "apache", tmp_path)
    detections = sig_fn(events)
    detections = ensure_list_events(detections)
    assert len(detections) >= 1, "Expected at least one detection for SQL injection patterns"
    assert any(has_sql_injection_flag(d) for d in detections), "SQL injection should be detected"


def test_identify_suspicious_ip_addresses(analyzer, json_lines, tmp_path):
    parse_fn = ensure_parse_fn(analyzer)
    ioc_fn = ensure_ioc_fn(analyzer)
    events = call_parse(parse_fn, json_lines, "json", tmp_path)
    iocs = ["203.0.113.5", "198.51.100.23"]  # Suspicious IPs to correlate
    correlations = ioc_fn(events, iocs)
    correlations = ensure_list_events(correlations)
    matched_ips = {get_detection_ip(c) for c in correlations}
    assert "203.0.113.5" in matched_ips
    assert "198.51.100.23" in matched_ips


def test_generate_security_event_timeline(analyzer):
    timeline_fn = ensure_timeline_fn(analyzer)
    # Create out-of-order events with ISO timestamps
    base = datetime(2023, 10, 10, 13, 56, tzinfo=timezone.utc)
    events = [
        {"timestamp": (base + timedelta(seconds=30)).isoformat(), "ip": "127.0.0.1", "message": "A"},
        {"timestamp": (base + timedelta(seconds=10)).isoformat(), "ip": "192.0.2.1", "message": "B"},
        {"timestamp": (base + timedelta(seconds=20)).isoformat(), "ip": "203.0.113.5", "message": "C"},
    ]
    timeline = timeline_fn(events)
    timeline = ensure_list_events(timeline)
    assert len(timeline) == 3
    parsed = [parse_timestamp(item_get(e, ["timestamp"])) for e in timeline]
    assert all(p is not None for p in parsed)
    assert parsed == sorted(parsed), "Timeline should be sorted chronologically"


def test_parse_multiple_formats_syslog_json_csv(analyzer, syslog_lines, json_lines, csv_lines, tmp_path):
    parse_fn = ensure_parse_fn(analyzer)

    syslog_events = call_parse(parse_fn, syslog_lines, "syslog", tmp_path)
    assert len(syslog_events) >= 3
    assert any(get_event_ip(e) == "192.0.2.1" for e in syslog_events) or any(
        "192.0.2.1" in (item_get(e, ["message"]) or "") for e in syslog_events
    )

    json_events = call_parse(parse_fn, json_lines, "json", tmp_path)
    assert len(json_events) >= 3
    assert any(get_event_ip(e) == "203.0.113.5" for e in json_events)

    csv_events = call_parse(parse_fn, csv_lines, "csv", tmp_path)
    assert len(csv_events) >= 3
    assert any(get_event_status(e) == 401 for e in csv_events)
    assert any((get_event_request_path(e) or "").startswith("/login") for e in csv_events) or any(
        "login" in (item_get(e, ["message"]) or "") for e in csv_events
    )


def test_error_handling_unknown_format_raises(analyzer, tmp_path):
    parse_fn = ensure_parse_fn(analyzer)
    with pytest.raises((ValueError, NotImplementedError, KeyError, TypeError)):
        _ = call_parse(parse_fn, "foo", "unknown_format_xyz", tmp_path)


def test_error_handling_malformed_log_line(analyzer, tmp_path):
    parse_fn = ensure_parse_fn(analyzer)
    data = "\n".join(
        [
            '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"',
            "THIS IS NOT A VALID LOG LINE",
        ]
    )
    events = call_parse(parse_fn, data, "apache", tmp_path)
    # Should parse at least one valid event and not crash
    assert isinstance(events, list)
    assert len(events) >= 1
    # The malformed line should either be skipped or marked as error
    if len(events) == 2:
        # If both returned, ensure one contains an error flag or minimal fields missing
        malformed = [e for e in events if not get_event_method(e) or not get_event_request_path(e)]
        assert malformed, "Malformed line should be identified or handled distinctly"


def test_anomaly_detection_spike(analyzer):
    anomaly_fn = ensure_anomaly_fn(analyzer)
    # Generate events: baseline low rate, then a spike
    base = datetime(2023, 10, 10, 13, 0, tzinfo=timezone.utc)
    events = []
    # Baseline: 1 event per minute for 20 minutes
    for i in range(20):
        events.append({"timestamp": (base + timedelta(minutes=i)).isoformat(), "ip": "127.0.0.1", "message": "ok"})
    # Spike: 30 events within the 21st minute
    spike_minute = base + timedelta(minutes=21)
    for i in range(30):
        events.append({"timestamp": (spike_minute + timedelta(seconds=i)).isoformat(), "ip": "192.0.2.1", "message": "req"})
    anomalies = anomaly_fn(events)
    anomalies = ensure_list_events(anomalies)
    assert len(anomalies) >= 1, "Expected at least one anomaly for traffic spike"


def test_mock_external_ioc_feed_fetch_if_available(monkeypatch):
    # If the analyzer supports fetching IOC feeds over HTTP, ensure we can mock requests
    fetch_fn = get_attr(analyzer_module, ["fetch_ioc_feed", "load_ioc_feed", "get_ioc_feed"])
    if fetch_fn is None:
        # Try instance method
        cls = get_attr(analyzer_module, ["SecurityLogAnalyzer", "LogAnalyzer", "Analyzer"])
        if cls is None:
            pytest.skip("No IOC feed fetch function available to test mocking")
        try:
            instance = cls()
        except TypeError:
            instance = cls(config=None)
        fetch_fn = get_attr(instance, ["fetch_ioc_feed", "load_ioc_feed", "get_ioc_feed"])
        if fetch_fn is None:
            pytest.skip("No IOC feed fetch method available to test mocking")

    class DummyResp:
        def __init__(self, body: str, code: int = 200):
            self._body = body
            self.status_code = code

        def json(self):
            return json.loads(self._body)

        @property
        def text(self):
            return self._body

        def raise_for_status(self):
            if not (200 <= self.status_code < 300):
                raise RuntimeError("HTTP error")

    requests_mod = importlib.import_module("requests")

    def fake_get(url, timeout=None):
        assert url.startswith("http://localhost") or url.startswith("https://localhost")
        data = {"iocs": ["203.0.113.5", "198.51.100.23", "127.0.0.1"]}
        return DummyResp(json.dumps(data), 200)

    monkeypatch.setattr(requests_mod, "get", fake_get, raising=True)

    # Call with localhost URL to adhere to rules
    url = "http://localhost/iocs.json"
    try:
        result = fetch_fn(url)  # function form
    except TypeError:
        # maybe method needs self param already bound; skip if not callable
        pytest.skip("IOC fetch function signature unexpected")
    # Accept either dict with 'iocs' or flat list
    if isinstance(result, dict) and "iocs" in result:
        iocs = result["iocs"]
    else:
        iocs = result
    assert isinstance(iocs, (list, tuple))
    assert "203.0.113.5" in iocs and "198.51.100.23" in iocs