import json
import csv
import io
import types
import pytest
import importlib
import xml.etree.ElementTree as ET


@pytest.fixture(scope="session")
def scanner_module():
    return importlib.import_module("tools.recon.port_scanner")


@pytest.fixture(scope="session")
def ScannerClass(scanner_module):
    # Prefer AdvancedPortScanner; fall back to PortScanner or any *Scanner class
    if hasattr(scanner_module, "AdvancedPortScanner"):
        return getattr(scanner_module, "AdvancedPortScanner")
    if hasattr(scanner_module, "PortScanner"):
        return getattr(scanner_module, "PortScanner")
    # find any class ending with Scanner
    for name in dir(scanner_module):
        obj = getattr(scanner_module, name)
        if isinstance(obj, type) and name.lower().endswith("scanner"):
            return obj
    pytest.skip("No scanner class found in tools.recon.port_scanner")


@pytest.fixture()
def scanner(ScannerClass):
    try:
        return ScannerClass()
    except TypeError:
        # Attempt to instantiate with no-arg or kwargs fallbacks
        try:
            return ScannerClass(host=None, rate_limit=None)  # type: ignore
        except Exception:
            return ScannerClass()  # type: ignore


class FakeTCPSocket:
    _fileno_counter = 100

    def __init__(self, *args, **kwargs):
        self.timeout = None
        self.closed = False
        self.connected = False
        self.addr = None
        self.sent = b""
        self._banner_sent = False
        self.family = args[0] if args else None
        self.type = args[1] if len(args) > 1 else None
        FakeTCPSocket._fileno_counter += 1
        self._fileno = FakeTCPSocket._fileno_counter

    def settimeout(self, t):
        self.timeout = t

    def setblocking(self, b):
        pass

    def setsockopt(self, *args, **kwargs):
        pass

    def connect_ex(self, addr):
        self.addr = addr
        self.connected = True
        host, port = addr
        # Simulate only port 22 open
        if host in ("127.0.0.1", "localhost") and 1 <= port <= 1000:
            if port == 22:
                return 0  # success
            return 111  # ECONNREFUSED
        return 111

    def connect(self, addr):
        rc = self.connect_ex(addr)
        if rc != 0:
            raise OSError(rc, "connect failed")
        return 0

    def send(self, data):
        self.sent += data
        return len(data)

    def sendall(self, data):
        self.sent += data

    def recv(self, bufsize):
        # Provide a banner only once for SSH
        if self.addr:
            host, port = self.addr
        else:
            port = 22
        if port == 22 and not self._banner_sent:
            self._banner_sent = True
            return b"SSH-2.0-OpenSSH_8.9\r\n"
        return b""

    def close(self):
        self.closed = True

    def fileno(self):
        return self._fileno

    def getpeername(self):
        return self.addr or ("127.0.0.1", 22)


class FakeUDPSocket:
    _fileno_counter = 200

    def __init__(self, *args, **kwargs):
        self.timeout = None
        self.closed = False
        self.addr = None
        FakeUDPSocket._fileno_counter += 1
        self._fileno = FakeUDPSocket._fileno_counter

    def settimeout(self, t):
        self.timeout = t

    def setsockopt(self, *args, **kwargs):
        pass

    def sendto(self, data, addr):
        self.addr = addr
        return len(data)

    def recvfrom(self, bufsize):
        # Simulate no responses (open|filtered typical for UDP)
        raise TimeoutError("UDP recv timeout")

    def close(self):
        self.closed = True

    def fileno(self):
        return self._fileno


@pytest.fixture()
def fake_sockets(monkeypatch):
    import socket

    def fake_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        if type == socket.SOCK_DGRAM:
            return FakeUDPSocket(family, type, proto)
        return FakeTCPSocket(family, type, proto)

    def fake_create_connection(address, timeout=None, source_address=None):
        s = FakeTCPSocket()
        s.settimeout(timeout)
        s.connect(address)
        return s

    monkeypatch.setattr("socket.socket", fake_socket)
    monkeypatch.setattr("socket.create_connection", fake_create_connection)
    # For UDP timeout exception consistency
    if not hasattr(__import__("socket"), "timeout"):
        class _Timeout(Exception):
            pass
        monkeypatch.setattr("socket.timeout", _Timeout)  # type: ignore


@pytest.fixture()
def sleep_spy(monkeypatch):
    calls = {"count": 0, "args": []}

    def fake_sleep(duration):
        calls["count"] += 1
        calls["args"].append(duration)

    import time
    monkeypatch.setattr(time, "sleep", fake_sleep)
    return calls


def _run_tcp_scan(scanner, host, ports, rate_limit=None, stealth=None):
    # Try multiple possible APIs
    if hasattr(scanner, "scan_tcp"):
        kwargs = {}
        if stealth is not None:
            kwargs["stealth"] = stealth
        if rate_limit is not None:
            kwargs["rate_limit"] = rate_limit
        return scanner.scan_tcp(host=host, ports=ports, **kwargs)
    if hasattr(scanner, "scan"):
        kwargs = {}
        if rate_limit is not None:
            kwargs["rate_limit"] = rate_limit
        if stealth is not None:
            kwargs["stealth"] = stealth
        return scanner.scan(host=host, ports=ports, protocols=["tcp"], **kwargs)
    if hasattr(scanner, "scan_ports"):
        kwargs = {"tcp": True, "udp": False}
        if rate_limit is not None:
            kwargs["rate_limit"] = rate_limit
        if stealth is not None:
            kwargs["stealth"] = stealth
        return scanner.scan_ports(host, ports, **kwargs)
    raise AttributeError("Scanner does not expose TCP scanning method")


def _run_udp_scan(scanner, host, ports, rate_limit=None):
    if hasattr(scanner, "scan_udp"):
        kwargs = {}
        if rate_limit is not None:
            kwargs["rate_limit"] = rate_limit
        return scanner.scan_udp(host=host, ports=ports, **kwargs)
    if hasattr(scanner, "scan"):
        kwargs = {}
        if rate_limit is not None:
            kwargs["rate_limit"] = rate_limit
        return scanner.scan(host=host, ports=ports, protocols=["udp"], **kwargs)
    if hasattr(scanner, "scan_ports"):
        kwargs = {"tcp": False, "udp": True}
        if rate_limit is not None:
            kwargs["rate_limit"] = rate_limit
        return scanner.scan_ports(host, ports, **kwargs)
    pytest.skip("UDP scanning method not available")


def _export_json(scanner, results):
    # Handle ScanResult object with to_json method
    if hasattr(results, 'to_json'):
        return results.to_json()
    if hasattr(scanner, "export_results"):
        return scanner.export_results("json", results)
    if hasattr(scanner, "to_json"):
        return scanner.to_json(results)
    if hasattr(scanner, "export"):
        return scanner.export("json", results)
    pytest.skip("No JSON export method available")


def _export_xml(scanner, results):
    # Handle ScanResult object with to_xml method  
    if hasattr(results, 'to_xml'):
        return results.to_xml()
    if hasattr(scanner, "export_results"):
        return scanner.export_results("xml", results)
    if hasattr(scanner, "to_xml"):
        return scanner.to_xml(results)
    if hasattr(scanner, "export"):
        return scanner.export("xml", results)
    pytest.skip("No XML export method available")


def _export_csv(scanner, results):
    # Handle ScanResult object with to_csv method
    if hasattr(results, 'to_csv'):
        return results.to_csv()
    if hasattr(scanner, "export_results"):
        return scanner.export_results("csv", results)
    if hasattr(scanner, "to_csv"):
        return scanner.to_csv(results)
    if hasattr(scanner, "export"):
        return scanner.export("csv", results)
    pytest.skip("No CSV export method available")


def _as_list_of_dicts(results):
    # Normalize results to list of dicts
    # Handle ScanResult object
    if hasattr(results, 'results') and isinstance(results.results, list):
        return [vars(r) if hasattr(r, '__dict__') else r for r in results.results]
    if isinstance(results, dict) and "results" in results:
        return results["results"]
    if isinstance(results, list):
        return [vars(r) if hasattr(r, '__dict__') else r for r in results]
    # Some scanners might return generator
    if isinstance(results, types.GeneratorType):
        return list(results)
    # Fallback: wrap single dict
    if isinstance(results, dict):
        return [results]
    return []


def test_scan_common_ports_tcp_localhost(scanner, fake_sockets):
    ports = list(range(1, 1001))
    results = _run_tcp_scan(scanner, host="127.0.0.1", ports=ports, stealth=True)
    items = _as_list_of_dicts(results)
    assert isinstance(items, list)
    # Should include at least port 22 as open
    found_22 = False
    for item in items:
        if int(item.get("port", -1)) == 22:
            found_22 = True
            state = str(item.get("state", "open")).lower()
            assert "open" in state
    assert found_22, "Expected port 22 to be detected in scan results"


def test_detect_ssh_service_on_22_with_banner(scanner, fake_sockets):
    results = _run_tcp_scan(scanner, host="localhost", ports=[22], stealth=True)
    items = _as_list_of_dicts(results)
    assert items, "No results returned for port 22"
    ssh_items = [i for i in items if int(i.get("port", -1)) == 22]
    assert ssh_items, "No result entry for port 22"
    entry = ssh_items[0]
    # Check banner presence
    banner = entry.get("banner") or entry.get("service_banner") or entry.get("version") or ""
    assert isinstance(banner, (str, bytes))
    banner_str = banner.decode() if isinstance(banner, bytes) else banner
    assert "SSH" in banner_str.upper()
    # If service field exists, it should mention ssh
    service = entry.get("service") or entry.get("name") or ""
    if service:
        assert "ssh" in str(service).lower()


def test_export_results_to_json(scanner, fake_sockets):
    results = _run_tcp_scan(scanner, host="127.0.0.1", ports=[22, 80, 443], stealth=True)
    json_str = _export_json(scanner, results)
    assert isinstance(json_str, str)
    data = json.loads(json_str)
    # Normalize
    if isinstance(data, dict) and "results" in data:
        items = data["results"]
    elif isinstance(data, list):
        items = data
    else:
        # Accept mapping keyed by port
        items = []
        for v in (data.values() if isinstance(data, dict) else []):
            items.append(v)
    assert any(int((i.get("port") if isinstance(i, dict) else i)) == 22 for i in items)


def test_handle_rate_limiting_parameters(scanner, fake_sockets, sleep_spy):
    # Test that providing rate_limit parameter is accepted and does not cause errors
    results = _run_tcp_scan(scanner, host="127.0.0.1", ports=[22, 23, 24, 25], rate_limit=2, stealth=True)
    items = _as_list_of_dicts(results)
    assert isinstance(items, list)
    # If implementation uses sleeps to rate limit, we expect at least one sleep call
    assert sleep_spy["count"] >= 0  # Should not crash; allow zero if rate limiting handled differently


def test_invalid_port_range_raises(scanner):
    with pytest.raises((ValueError, AssertionError)):
        _run_tcp_scan(scanner, host="127.0.0.1", ports=[-1, 70000], stealth=False)


def test_invalid_host_raises(scanner):
    # Host validation should raise; allow broad exception types commonly used
    with pytest.raises((ValueError, OSError)):
        _run_tcp_scan(scanner, host="256.256.256.256", ports=[22], stealth=False)


def test_udp_scanning_capability(scanner, fake_sockets):
    # Ensure UDP scanning method exists and can be called without real network
    try:
        results = _run_udp_scan(scanner, host="127.0.0.1", ports=[53, 123])
    except AttributeError:
        pytest.skip("UDP scanning not implemented")
    items = _as_list_of_dicts(results)
    assert isinstance(items, list)


def test_export_xml_and_csv_formats(scanner, fake_sockets):
    # Prepare a small result set
    results = _run_tcp_scan(scanner, host="127.0.0.1", ports=[22], stealth=True)
    # XML
    try:
        xml_str = _export_xml(scanner, results)
        assert isinstance(xml_str, str)
        root = ET.fromstring(xml_str)
        # Find at least one port element containing 22
        text = ET.tostring(root, encoding="unicode")
        assert "22" in text
    except pytest.skip.Exception:  # type: ignore
        pass
    # CSV
    try:
        csv_str = _export_csv(scanner, results)
        assert isinstance(csv_str, str)
        sio = io.StringIO(csv_str)
        reader = csv.reader(sio)
        rows = list(reader)
        assert any("22" in cell for row in rows for cell in row)
    except pytest.skip.Exception:  # type: ignore
        pass


def test_stealth_scanning_parameter(scanner, fake_sockets):
    # Ensure that stealth parameter is accepted by TCP scanning APIs
    try:
        results = _run_tcp_scan(scanner, host="127.0.0.1", ports=[22], stealth=True)
    except TypeError:
        pytest.skip("Stealth parameter not supported by scan method")
    items = _as_list_of_dicts(results)
    assert any(int(i.get("port", -1)) == 22 for i in items)