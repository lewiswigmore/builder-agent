"""
Advanced Port Scanner - Multi-threaded TCP/UDP scanner with service detection, banner grabbing, and export.

ETHICAL WARNING:
- Use this tool only on systems and networks you own or are explicitly authorized to test.
- Unauthorized scanning may be illegal and can disrupt services.
- Respect rate limits and applicable laws and policies.

This scanner provides:
- TCP and UDP port scanning
- Service version detection and banner grabbing
- Rate limiting and randomized probing for stealth
- Multiple output formats: JSON, XML, CSV
- Best-effort "stealth" techniques (randomization, jitter, RST close). SYN scan requires root and is not implemented.

Note: UDP scanning is inherently unreliable; lack of response often means "open|filtered".
"""
from __future__ import annotations

import csv
import json
import random
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET
import io


def _now() -> float:
    return time.monotonic()


@dataclass
class PortResult:
    port: int
    protocol: str  # 'tcp' or 'udp'
    state: str  # 'open', 'closed', 'filtered', 'open|filtered', 'error'
    service: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    reason: Optional[str] = None
    duration_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    started_at: float
    ended_at: float
    results: List[PortResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_sec": round(self.ended_at - self.started_at, 3),
            "results": [vars(r) for r in self.results],
            "notes": self.notes,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_xml(self) -> str:
        root = ET.Element("scan")
        ET.SubElement(root, "target").text = self.target
        ET.SubElement(root, "started_at").text = str(self.started_at)
        ET.SubElement(root, "ended_at").text = str(self.ended_at)
        ET.SubElement(root, "duration_sec").text = str(round(self.ended_at - self.started_at, 3))
        notes = ET.SubElement(root, "notes")
        for n in self.notes:
            ET.SubElement(notes, "note").text = n
        ports_el = ET.SubElement(root, "ports")
        for r in self.results:
            pe = ET.SubElement(ports_el, "port", attrib={"number": str(r.port), "protocol": r.protocol})
            ET.SubElement(pe, "state").text = r.state
            if r.service:
                ET.SubElement(pe, "service").text = r.service
            if r.banner:
                ET.SubElement(pe, "banner").text = r.banner
            if r.product:
                ET.SubElement(pe, "product").text = r.product
            if r.reason:
                ET.SubElement(pe, "reason").text = r.reason
            ET.SubElement(pe, "duration_ms").text = str(round(r.duration_ms, 2))
            if r.error:
                ET.SubElement(pe, "error").text = r.error
        return ET.tostring(root, encoding="unicode")

    def to_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["target", "port", "protocol", "state", "service", "product", "banner", "reason", "duration_ms", "error"]
        )
        for r in self.results:
            writer.writerow(
                [
                    self.target,
                    r.port,
                    r.protocol,
                    r.state,
                    r.service or "",
                    r.product or "",
                    (r.banner or "").replace("\n", "\\n"),
                    r.reason or "",
                    round(r.duration_ms, 2),
                    r.error or "",
                ]
            )
        return output.getvalue()

    def export(self, path: str, fmt: str = "json") -> None:
        fmt = fmt.lower()
        if fmt == "json":
            data = self.to_json()
        elif fmt == "xml":
            data = self.to_xml()
        elif fmt == "csv":
            data = self.to_csv()
        else:
            raise ValueError(f"Unsupported format: {fmt}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)


class TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: Optional[int] = None):
        self.rate = max(0.01, float(rate_per_sec))
        self.capacity = int(capacity if capacity is not None else max(1.0, rate_per_sec))
        self._tokens = self.capacity
        self._last = _now()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = _now()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                # Need to wait for next token
                needed = 1 - self._tokens
                sleep_time = max(0.001, needed / self.rate)
            time.sleep(sleep_time)


def _default_service_for_port(port: int, proto: str) -> Optional[str]:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        # simple common mapping fallbacks
        if proto == "tcp":
            return {
                22: "ssh",
                21: "ftp",
                23: "telnet",
                25: "smtp",
                80: "http",
                110: "pop3",
                143: "imap",
                443: "https",
                3306: "mysql",
                5432: "postgresql",
                6379: "redis",
                8080: "http-proxy",
            }.get(port)
        if proto == "udp":
            return {
                53: "domain",
                67: "dhcps",
                68: "dhcpc",
                69: "tftp",
                123: "ntp",
                161: "snmp",
                162: "snmptrap",
            }.get(port)
    return None


def _parse_banner(port: int, proto: str, data: Optional[bytes]) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (service_hint, product)
    """
    if not data:
        return None, None
    text = ""
    try:
        text = data.decode(errors="ignore")
    except Exception:
        pass
    text_l = text.lower()
    product = None
    service = None
    if "ssh-" in text_l:
        service = "ssh"
        # e.g., SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
        product = text.strip().split()[0] if text else None
    elif "smtp" in text_l or text_l.startswith("220"):
        service = "smtp"
    elif "http" in text_l or "server:" in text_l:
        service = "http"
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                product = line.split(":", 1)[1].strip()
                break
    elif "redis" in text_l or "+pong" in text_l:
        service = "redis"
        product = "redis"
    elif "ftp" in text_l:
        service = "ftp"
    elif "imap" in text_l:
        service = "imap"
    elif "pop3" in text_l:
        service = "pop3"
    elif "mysql" in text_l:
        service = "mysql"
    elif "postgresql" in text_l or "postgres" in text_l:
        service = "postgresql"
    if not service:
        service = _default_service_for_port(port, proto)
    return service, product


class PortScanner:
    def __init__(
        self,
        target: Optional[str] = None,
        ports: Optional[Iterable[int]] = None,
        tcp: bool = True,
        udp: bool = False,
        threads: int = 100,
        rate_limit: Optional[float] = None,
        timeout: float = 2.0,
        jitter: Tuple[float, float] = (0.0, 0.05),
        randomize: bool = True,
        stealth_mode: str = "connect",  # connect | rst_close | syn (fallback to connect)
        host: Optional[str] = None,  # alias for target
    ):
        """
        Create a PortScanner.

        - target: hostname or IP to scan. Defaults to 127.0.0.1 if not provided.
        - ports: iterable of port numbers. Defaults to common ports 1-1000.
        - tcp/udp: enable protocols.
        - threads: number of worker threads.
        - rate_limit: max probes per second (global). Defaults to 200/sec.
        - timeout: per-connection timeout in seconds.
        - jitter: tuple(min,max) random sleep before each probe.
        - randomize: randomize port order.
        - stealth_mode:
            - connect: normal TCP connect scan.
            - rst_close: attempt to close with RST (reduced footprint).
            - syn: SYN scan (requires root) - not implemented; falls back to 'connect'.
        """
        # Resolve target with alias support
        if target is None and host:
            target = host
        if target is None:
            target = "127.0.0.1"
        self._validate_host(target)
        self.target = target

        # Ports default and validation
        if ports is None:
            ports_list = common_ports(1, 1000)
        else:
            ports_list = list(set(int(p) for p in ports if isinstance(p, (int, str))))
            ports_list = [int(p) for p in ports_list if 0 < int(p) <= 65535]
            if not ports_list:
                raise ValueError("No valid ports provided (must be 1-65535).")
        self.ports = ports_list

        self.tcp = bool(tcp)
        self.udp = bool(udp)
        self.threads = max(1, int(threads))
        self.timeout = float(timeout)
        self.jitter = jitter
        self.randomize = bool(randomize)
        self.stealth_mode = stealth_mode

        # Rate limit handling
        self._rate_limit = float(rate_limit) if rate_limit is not None else 200.0
        self._bucket = TokenBucket(rate_per_sec=self._rate_limit, capacity=int(max(1, self._rate_limit)))
        self._results_lock = threading.Lock()

    @staticmethod
    def _validate_host(host: str) -> None:
        # Prefer IPv4 for compatibility; raise ValueError if cannot resolve
        try:
            socket.getaddrinfo(host, None, family=socket.AF_INET)
        except socket.gaierror as e:
            raise ValueError(f"Invalid target host: {host}") from e

    @property
    def rate_limit(self) -> float:
        return self._rate_limit

    @rate_limit.setter
    def rate_limit(self, value: Optional[float]) -> None:
        new_val = float(value) if value is not None else 200.0
        new_val = max(0.01, new_val)
        self._rate_limit = new_val
        # Update token bucket if already created
        if hasattr(self, "_bucket") and isinstance(self._bucket, TokenBucket):
            self._bucket.rate = new_val
            self._bucket.capacity = int(max(1, new_val))

    def scan(self) -> ScanResult:
        started = _now()
        if self.randomize:
            random.shuffle(self.ports)

        futures = []
        results: List[PortResult] = []
        notes: List[str] = [
            "Ethical use only: scan with permission.",
            f"Stealth mode: {self.stealth_mode}",
            f"Rate limit: {self._bucket.rate} per second",
        ]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for p in self.ports:
                if self.tcp:
                    futures.append(executor.submit(self._scan_tcp, p))
                if self.udp:
                    futures.append(executor.submit(self._scan_udp, p))

            for fut in as_completed(futures):
                r = fut.result()
                if isinstance(r, list):
                    items = r
                else:
                    items = [r]
                with self._results_lock:
                    results.extend(items)

        ended = _now()
        sr = ScanResult(self.target, started, ended, results, notes)
        return sr

    def _apply_jitter(self):
        if self.jitter and (self.jitter[1] > 0):
            low, high = self.jitter
            if high < low:
                low, high = high, low
            d = random.uniform(low, high)
            if d > 0:
                time.sleep(d)

    def _rst_close(self, sock: socket.socket):
        # Try to force RST by setting SO_LINGER with 0 timeout.
        try:
            linger = struct.pack("ii", 1, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    def _scan_tcp(self, port: int) -> PortResult:
        self._bucket.acquire()
        self._apply_jitter()
        start = _now()
        service_guess = _default_service_for_port(port, "tcp")
        banner_data: Optional[bytes] = None
        state = "closed"
        reason = None
        product = None
        error = None

        # Only 'connect' and 'rst_close' implemented; 'syn' falls back.
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            # Set TCP_NODELAY for snappier behavior
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            s.connect((self.target, port))
            state = "open"
            reason = "tcp-connect"
            # Try banner grabbing based on common ports
            banner_data = self._grab_tcp_banner(s, port, service_guess)
            if not banner_data:
                # Passive read if server sends first (e.g., SSH/FTP/SMTP)
                try:
                    s.settimeout(0.8)
                    data = s.recv(4096)
                    if data:
                        banner_data = data
                except Exception:
                    pass
            # Close socket considering stealth mode
            if self.stealth_mode == "rst_close":
                self._rst_close(s)
                s = None
        except (ConnectionRefusedError, OSError) as e:
            state = "closed"
            reason = getattr(e, "strerror", str(e))
            error = str(e)
        except socket.timeout as e:
            state = "filtered"
            reason = "timeout"
            error = str(e)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

        svc, prod = _parse_banner(port, "tcp", banner_data)
        service = svc or service_guess
        product = prod or product
        banner_text = None
        if banner_data:
            try:
                banner_text = banner_data.decode(errors="ignore")
            except Exception:
                banner_text = repr(banner_data[:64])
        duration_ms = (_now() - start) * 1000.0
        return PortResult(
            port=port,
            protocol="tcp",
            state=state,
            service=service,
            banner=banner_text,
            product=product,
            reason=reason,
            duration_ms=duration_ms,
            error=error,
        )

    def _grab_tcp_banner(self, s: socket.socket, port: int, service_guess: Optional[str]) -> Optional[bytes]:
        """
        Attempt active banner grabbing for known services.
        """
        try:
            if port in (80, 8080, 8000, 8888) or (service_guess and "http" in service_guess and port != 443):
                req = f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\nUser-Agent: AdvancedPortScanner/1.0\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                s.settimeout(1.2)
                data = s.recv(4096)
                return data
            if port == 443 or (service_guess == "https"):
                ctx = ssl.create_default_context()
                try:
                    s_ssl = ctx.wrap_socket(s, server_hostname=self.target)
                except Exception:
                    return None
                req = f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\nUser-Agent: AdvancedPortScanner/1.0\r\nConnection: close\r\n\r\n"
                s_ssl.sendall(req.encode())
                s_ssl.settimeout(1.5)
                data = s_ssl.recv(4096)
                return data
            if port in (25, 587) or (service_guess == "smtp"):
                s.settimeout(1.0)
                try:
                    greet = s.recv(4096)
                except Exception:
                    greet = b""
                try:
                    s.sendall(b"EHLO scanner.local\r\n")
                    data = greet + s.recv(4096)
                    return data
                except Exception:
                    return greet or None
            if port in (21,) or (service_guess == "ftp"):
                s.settimeout(1.0)
                try:
                    data = s.recv(4096)
                    return data
                except Exception:
                    return None
            if port in (22,) or (service_guess == "ssh"):
                s.settimeout(1.0)
                try:
                    data = s.recv(256)
                    return data
                except Exception:
                    return None
            if port in (6379,) or (service_guess == "redis"):
                s.settimeout(0.8)
                try:
                    s.sendall(b"PING\r\n")
                    data = s.recv(256)
                    return data
                except Exception:
                    return None
        except Exception:
            return None
        return None

    def _scan_udp(self, port: int) -> PortResult:
        self._bucket.acquire()
        self._apply_jitter()
        start = _now()
        state = "open|filtered"
        reason = "no-response"
        banner_text = None
        error = None
        service = _default_service_for_port(port, "udp")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            try:
                s.connect((self.target, port))
            except Exception:
                pass
            payload = self._udp_payload_for_port(port, service)
            try:
                s.send(payload)
            except Exception as e:
                error = str(e)
            try:
                data = s.recv(4096)
                if data:
                    state = "open"
                    reason = "response"
                    if data:
                        try:
                            banner_text = data.decode(errors="ignore")
                        except Exception:
                            banner_text = repr(data[:64])
            except socket.timeout:
                # no response
                pass
            except ConnectionRefusedError as e:
                state = "closed"
                reason = "icmp-port-unreachable"
                error = str(e)
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        except Exception as e:
            state = "error"
            reason = "exception"
            error = str(e)

        duration_ms = (_now() - start) * 1000.0
        return PortResult(
            port=port,
            protocol="udp",
            state=state,
            service=service,
            banner=banner_text,
            product=None,
            reason=reason,
            duration_ms=duration_ms,
            error=error,
        )

    def _udp_payload_for_port(self, port: int, service: Optional[str]) -> bytes:
        # Very minimal payloads to elicit responses
        if port == 53 or service == "domain":
            # Minimal DNS query (transaction id 0x1337)
            try:
                # Header: id, flags, qdcount, ancount, nscount, arcount
                header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
                qname = b"\x01a\x01i\x01o\x00"  # a.i.o
                question = qname + struct.pack(">HH", 1, 1)  # A IN
                return header + question
            except Exception:
                return b"\x00" * 12
        if port == 123 or service == "ntp":
            # Minimal NTP request
            return b"\x1b" + b"\0" * 47
        if port in (161,) or service == "snmp":
            # Simple SNMP get (community 'public') to 1.3.6.1.2.1.1.1.0
            return bytes.fromhex(
                "30819f020103301002010004067075626c6963a2818b020100020100300f300d06092b060102010101000500301d301b06092b06010201010100020101300e0400000400a003020100a10f020100020100300a300806062b06010201010500"
            )
        # Default: empty or single null byte
        return b"\x00"


def common_ports(start: int = 1, end: int = 1000) -> List[int]:
    if start < 1 or end > 65535 or start > end:
        raise ValueError("Invalid port range")
    return list(range(start, end + 1))


__all__ = [
    "PortScanner",
    "ScanResult",
    "PortResult",
    "common_ports",
]