import pytest
from unittest.mock import patch, MagicMock
from m_map import scan_port, network_scan, udp_scan
from queue import Queue

def test_scan_port():
    target = "127.0.0.1"
    ports = [80, 443]
    queue = Queue()
    progress_queue = Queue()
    
    # Test port scanning
    scan_port(target, ports, queue, progress_queue)
    
    # Check progress queue
    assert progress_queue.qsize() == len(ports)
    
    # Get results
    results = []
    while not queue.empty():
        results.append(queue.get())
    
    # Results should be sorted and valid
    if results:
        assert all(isinstance(port, int) for port, _ in results)
        assert all(isinstance(service, str) for _, service in results)

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

@patch('m_map.ping_scan')
def test_network_scan(mock_ping):
    # Mock ping responses
    mock_ping.side_effect = lambda ip: ip.endswith('.1') or ip.endswith('.2')
    
    subnet = "192.168.1.0/24"
    active_hosts = network_scan(subnet)
    
    assert len(active_hosts) == 2
    assert "192.168.1.1" in active_hosts
    assert "192.168.1.2" in active_hosts 