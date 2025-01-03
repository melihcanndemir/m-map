import pytest
from m_map.m_map import get_service, get_service_banner, detect_os
from unittest.mock import patch, MagicMock

def test_service_detection():
    # Test well-known ports
    common_services = {
        '21': 'FTP',
        '22': 'SSH',
        '80': 'HTTP',
        '443': 'HTTPS'
    }
    
    for port, expected in common_services.items():
        assert get_service(port) == expected

@patch('socket.socket')
def test_service_banner(mock_socket):
    # Mock socket for banner grabbing
    mock_sock = MagicMock()
    mock_socket.return_value = mock_sock
    mock_sock.recv.return_value = b'SSH-2.0-OpenSSH_8.2p1'
    
    banner = get_service_banner('127.0.0.1', 22)
    assert 'SSH' in banner

@patch('nmap.PortScanner')
def test_os_detection(mock_scanner):
    # Mock nmap scanner
    mock_nm = MagicMock()
    mock_scanner.return_value = mock_nm
    
    mock_nm.scan.return_value = {
        'scan': {
            '127.0.0.1': {
                'osmatch': [{'name': 'Linux 5.x'}]
            }
        }
    }
    
    os_info = detect_os('127.0.0.1')
    assert 'Linux' in os_info 