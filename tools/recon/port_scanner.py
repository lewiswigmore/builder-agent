import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host, port):
    """
    Scans a single port on a given host.
    Returns True if the port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def scan_ports(host, start_port, end_port, max_workers=100):
    """
    Scans a range of ports on a given host.
    Returns a list of open ports.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in range(start_port, end_port + 1)}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
    return open_ports
