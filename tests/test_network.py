import pytest
from unittest.mock import patch, MagicMock
from m_map.m_map import scan_port, network_scan, udp_scan
from queue import Queue

def test_scan_port():
    from m_map.m_map import scan_port
    
    # Test local ports
    assert scan_port("127.0.0.1", 80) is False  # Port muhtemelen kapalı
    
    # Test invalid port
    assert scan_port("127.0.0.1", 99999) is False  # Geçersiz port
    
    # Test invalid host
    assert scan_port("invalid.host", 80) is False  # Geçersiz host
    
    # Test timeout - özel bir test IP'si kullanıyoruz
    assert scan_port("192.0.2.1", 80, timeout=0.1) is False  # Timeout test

@patch('socket.socket')
def test_udp_scan(mock_socket):
    # Mock socket behavior
    mock_sock = MagicMock()
    mock_socket.return_value = mock_sock
    mock_sock.recvfrom.return_value = (b'', ('127.0.0.1', 53))
    
    target = "127.0.0.1"
    ports = [53, 161]  # Common UDP ports
    queue = Queue()
    progress_queue = Queue()
    
    udp_scan(target, ports, queue, progress_queue)
    
    # Check results
    results = []
    while not queue.empty():
        results.append(queue.get())
    
    assert len(results) > 0
    assert all(isinstance(port, int) for port, _ in results)
    assert all(status in ["UDP OPEN", "UDP OPEN|FILTERED"] for _, status in results)

@patch('m_map.m_map.ping_scan')
def test_network_scan(mock_ping):
    # Mock ping responses
    mock_ping.side_effect = lambda ip: ip.endswith('.1') or ip.endswith('.2')
    
    subnet = "192.168.1.0/24"
    active_hosts = network_scan(subnet)
    
    assert len(active_hosts) == 2
    assert "192.168.1.1" in active_hosts
    assert "192.168.1.2" in active_hosts 

@pytest.mark.parametrize("ip_address,expected", [
    ("192.168.1.1", True),
    ("256.256.256.256", False),
    ("abc.def.ghi.jkl", False),
    ("127.0.0.1", True)
])
def test_validate_ip(ip_address, expected):
    from m_map.m_map import validate_ip
    assert validate_ip(ip_address) == expected

@pytest.mark.parametrize("subnet,expected", [
    ("192.168.1.0/24", True),
    ("192.168.1.0/33", False),
    ("192.168.1/24", False),
    ("invalid/24", False)
])
def test_validate_subnet(subnet, expected):
    from m_map.m_map import validate_subnet
    assert validate_subnet(subnet) == expected

def test_get_service_name():
    from m_map.m_map import get_service_name
    assert get_service_name(80) == "http"
    assert get_service_name(443) == "https"
    assert get_service_name(99999) == "unknown" 

def test_port_range_parser():
    from m_map.m_map import parse_port_range
    
    assert parse_port_range("80") == [80]
    assert parse_port_range("80-83") == [80, 81, 82, 83]
    assert parse_port_range("80,443") == [80, 443]
    assert parse_port_range("22-25,80") == [22, 23, 24, 25, 80]
    with pytest.raises(ValueError):
        parse_port_range("invalid")

def test_scan_timeout():
    from m_map.m_map import scan_port
    
    # Var olmayan bir IP'ye tarama yaparak timeout testi
    result = scan_port("192.0.2.1", 80, timeout=1)
    assert result is False

@pytest.mark.parametrize("target,expected", [
    ("localhost", True),
    ("127.0.0.1", True),
    ("example.com", True),
    ("invalid.invalid", False)
])
def test_resolve_host(target, expected):
    from m_map.m_map import resolve_host
    assert bool(resolve_host(target)) == expected 