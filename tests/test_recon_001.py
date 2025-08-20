import json
import pytest

from tools.recon import port_scanner as port_scanner


class FakeSocket:
    # Class-level configuration for open ports and banners
    open_tcp_ports = {22}
    open_udp_ports = {53}
    banners = {22: b"SSH-2.0-OpenSSH_8.2\r\n"}

    def __init__(self, family=None, type=None, proto=0, fileno=None):
        self.family = family
        self.type = type
        self.proto = proto
        self.timeout = None
        self.connected = False
        self.remote = None
        self._closed = False
        self._last_udp_addr = None
        self._recv_used = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def settimeout(self, t):
        self.timeout = t

    def gettimeout(self):
        return self.timeout

    # TCP connect
    def connect(self, addr):
        host, port = addr
        self.remote = (host, port)
        if self.type is not None and self.type != getattr(port_scanner.socket, "SOCK_STREAM", object()):
            raise OSError("connect called on non-stream socket")
        if host in ("127.0.0.1", "localhost") and port in self.open_tcp_ports:
            self.connected = True
            return
        raise ConnectionRefusedError(f"Connection refused to {addr}")

    # Non-throwing connect
    def connect_ex(self, addr):
        try:
            self.connect(addr)
            return 0
        except ConnectionRefusedError:
            import errno
            return errno.ECONNREFUSED

    def sendall(self, data):
        # Simulate sending data; no-op
        return len(data)

    def recv(self, bufsize):
        # Simulate banner grabbing on open TCP ports
        if not self.remote:
            return b""
        port = self.remote[1]
        if port in self.banners and not self._recv_used:
            self._recv_used = True
            return self.banners[port][:bufsize]
        # subsequent reads return empty to simulate end
        return b""

    def sendto(self, data, addr):
        self._last_udp_addr = addr
        return len(data)

    def recvfrom(self, bufsize):
        if not self._last_udp_addr:
            raise port_scanner.socket.timeout("No UDP addr set")
        host, port = self._last_udp_addr
        if host in ("127.0.0.1", "localhost") and port in self.open_udp_ports:
            # Simulate a minimal UDP response
            return (b"\x00" * min(1, bufsize), (host, port))
        raise port_scanner.socket.timeout("UDP port filtered/closed")

    def fileno(self):
        return 0

    def close(self):
        self._closed = True


class SleepRecorder:
    def __init__(self):
        self.calls = []

    def __call__(self, t):
        self.calls.append(t)


@pytest.fixture(autouse=True)
def patch_local_network(monkeypatch):
    # Patch socket.socket in the module to our FakeSocket
    monkeypatch.setattr(port_scanner.socket, "socket", FakeSocket)
    # Patch gethostbyname to resolve localhost only
    def fake_gethostbyname(host):
        if host in ("localhost", "127.0.0.1"):
            return "127.0.0.1"
        # allow raw IP passthrough
        if isinstance(host, str):
            parts = host.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return host
        # unresolved hosts raise
        raise port_scanner.socket.gaierror(f"Name or service not known: {host}")
    monkeypatch.setattr(port_scanner.socket, "gethostbyname", fake_gethostbyname)
    # Some implementations may use getaddrinfo
    def fake_getaddrinfo(host, port, *args, **kwargs):
        ip = fake_gethostbyname(host)
        # return a tuple similar to real getaddrinfo: (family, type, proto, canonname, sockaddr)
        return [
            (port_scanner.socket.AF_INET, port_scanner.socket.SOCK_STREAM, 6, "", (ip, port)),
            (port_scanner.socket.AF_INET, port_scanner.socket.SOCK_DGRAM, 17, "", (ip, port)),
        ]
    if hasattr(port_scanner.socket, "AF_INET"):
        monkeypatch.setattr(port_scanner.socket, "getaddrinfo", fake_getaddrinfo)


def find_port_entry(results, port, protocol="tcp"):
    ports = results.get("ports") or results.get("results") or []
    for entry in ports:
        if entry.get("port") == port and entry.get("protocol", "tcp") == protocol:
            return entry
    return None


def ensure_scanner(rate_limit=None):
    try:
        if rate_limit is None:
            return port_scanner.PortScanner()
        return port_scanner.PortScanner(rate_limit=rate_limit)
    except TypeError:
        # Fallback if constructor doesn't accept rate_limit; set attribute directly
        s = port_scanner.PortScanner()
        if rate_limit is not None:
            setattr(s, "rate_limit", rate_limit)
        return s


def perform_scan(scanner, host, ports, tcp=True, udp=False, stealth=False, rate_limit=None):
    # Attempt to call scan with supported signature
    try:
        return scanner.scan(host=host, ports=ports, tcp=tcp, udp=udp, stealth=stealth, rate_limit=rate_limit)
    except TypeError:
        # Try without rate_limit parameter
        return scanner.scan(host=host, ports=ports, tcp=tcp, udp=udp, stealth=stealth)


def export_results(results, fmt):
    # Try module-level export_results first
    if hasattr(port_scanner, "export_results"):
        return port_scanner.export_results(results, fmt)
    # Try scanner method export
    scanner = ensure_scanner()
    if hasattr(scanner, "export"):
        return scanner.export(results, fmt)
    # Try dedicated format methods
    method = {
        "json": "to_json",
        "xml": "to_xml",
        "csv": "to_csv",
    }.get(fmt.lower())
    if method and hasattr(scanner, method):
        return getattr(scanner, method)(results)
    raise AttributeError("No export function available")


def test_scan_common_ports_localhost_successfully():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="127.0.0.1", ports=range(1, 1001), tcp=True, udp=False)
    assert isinstance(results, dict)
    # Assert results include ports list
    ports = results.get("ports") or results.get("results")
    assert isinstance(ports, list)
    # Ensure port 22 is reported as open (from our fake)
    p22 = find_port_entry(results, 22, protocol="tcp")
    assert p22 is not None
    assert p22.get("state", "").lower().startswith("open")
    # Ensure some closed or filtered ports are present as well
    states = {p.get("state", "").lower() for p in ports}
    assert any(s in states for s in ("closed", "filtered", "closed|filtered", "open|filtered"))


def test_detect_ssh_service_on_port_22_with_banner():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="localhost", ports=[22], tcp=True, udp=False)
    p22 = find_port_entry(results, 22, protocol="tcp")
    assert p22 is not None
    # service detection
    assert "service" in p22
    assert p22["service"].lower() in ("ssh", "ssh2")
    # banner grabbing
    assert "banner" in p22
    assert b"ssh-2.0" in (p22["banner"].encode() if isinstance(p22["banner"], str) else p22["banner"]).lower()


def test_export_results_to_json_format():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="127.0.0.1", ports=[22], tcp=True, udp=False)
    out = export_results(results, "json")
    # Validate JSON string
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    # Ensure port 22 entry appears in exported JSON
    ports = parsed.get("ports") or parsed.get("results") or []
    assert any(p.get("port") == 22 for p in ports)


def test_handle_rate_limiting_parameters(monkeypatch):
    sleep_recorder = SleepRecorder()
    # Patch time.sleep used inside the module
    monkeypatch.setattr(port_scanner.time, "sleep", sleep_recorder)
    scanner = ensure_scanner(rate_limit=0.01)
    # Small port set to count sleeps
    results = perform_scan(scanner, host="127.0.0.1", ports=[22, 23, 24], tcp=True, udp=False)
    assert isinstance(results, dict)
    # Expect at least number of probes - 1 sleeps (implementation dependent)
    assert len(sleep_recorder.calls) >= 2


def test_udp_scan_detects_dns_like_service():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="127.0.0.1", ports=[53], tcp=False, udp=True)
    p53 = find_port_entry(results, 53, protocol="udp")
    assert p53 is not None
    assert p53.get("state", "").lower() in ("open", "open|filtered")
    # Heuristic service name
    assert p53.get("service", "").lower() in ("dns", "domain", "udp")


def test_export_xml_and_csv_formats():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="127.0.0.1", ports=[22, 53], tcp=True, udp=True)
    xml_out = export_results(results, "xml")
    assert isinstance(xml_out, str)
    assert "<" in xml_out and ">" in xml_out
    # Basic structure checks
    assert "22" in xml_out
    csv_out = export_results(results, "csv")
    assert isinstance(csv_out, str)
    # CSV should have header and at least one data line
    lines = [ln for ln in csv_out.strip().splitlines() if ln.strip()]
    assert len(lines) >= 2
    header = lines[0].lower()
    assert "port" in header and "protocol" in header and "state" in header


def test_invalid_host_error():
    scanner = ensure_scanner()
    with pytest.raises(Exception):
        perform_scan(scanner, host="256.256.256.256", ports=[22], tcp=True, udp=False)


def test_empty_ports_list_returns_no_results():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="127.0.0.1", ports=[], tcp=True, udp=False)
    assert isinstance(results, dict)
    ports = results.get("ports") or results.get("results")
    assert ports == [] or ports is None or len(ports) == 0


def test_unknown_export_format_raises():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="127.0.0.1", ports=[22], tcp=True, udp=False)
    with pytest.raises(Exception):
        export_results(results, "yaml")


def test_stealth_scan_flag_supported():
    scanner = ensure_scanner()
    results = perform_scan(scanner, host="127.0.0.1", ports=[22, 80], tcp=True, udp=False, stealth=True)
    assert isinstance(results, dict)
    ports = results.get("ports") or results.get("results") or []
    assert any(p.get("port") == 22 for p in ports)
    # If technique is reported, ensure it indicates stealth
    technique = results.get("technique") or results.get("scan_type") or results.get("type")
    if isinstance(technique, str):
        assert any(k in technique.lower() for k in ("stealth", "syn"))