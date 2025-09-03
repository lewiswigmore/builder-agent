import pytest
import socket
from unittest.mock import patch, MagicMock
from tools.recon.port_scanner import scan_port, scan_ports

@patch('socket.socket')
def test_scan_port_open(mock_socket):
    """
    Tests that scan_port returns True for an open port.
    """
    mock_sock_instance = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    
    host = "localhost"
    port = 80
    
    result = scan_port(host, port)
    
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    mock_sock_instance.settimeout.assert_called_once_with(1)
    mock_sock_instance.connect.assert_called_once_with((host, port))
    assert result is True

@patch('socket.socket')
def test_scan_port_closed_timeout(mock_socket):
    """
    Tests that scan_port returns False when a timeout occurs.
    """
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect.side_effect = socket.timeout
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    
    host = "localhost"
    port = 81
    
    result = scan_port(host, port)
    
    assert result is False

@patch('socket.socket')
def test_scan_port_closed_refused(mock_socket):
    """
    Tests that scan_port returns False when the connection is refused.
    """
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect.side_effect = ConnectionRefusedError
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    
    host = "localhost"
    port = 82
    
    result = scan_port(host, port)
    
    assert result is False

@patch('tools.recon.port_scanner.scan_port')
def test_scan_ports(mock_scan_port):
    """
    Tests that scan_ports correctly identifies open ports.
    """
    def side_effect(host, port):
        if port in [80, 443]:
            return True
        return False
        
    mock_scan_port.side_effect = side_effect
    
    host = "example.com"
    start_port = 1
    end_port = 1024
    
    open_ports = scan_ports(host, start_port, end_port)
    
    assert 80 in open_ports
    assert 443 in open_ports
    assert len(open_ports) == 2
