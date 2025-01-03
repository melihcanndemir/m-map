import pytest
from unittest.mock import patch, MagicMock
import socket

def test_get_banner_simple():
    from m_map.m_map import get_banner
    
    # Test verisi
    test_data = b"SSH-2.0-OpenSSH_8.2p1\r\n"
    
    # Context manager mock'u düzelt
    mock_context = MagicMock()
    mock_context.__enter__.return_value.recv.return_value = test_data
    
    with patch('socket.socket', return_value=mock_context):
        banner = get_banner("127.0.0.1", 22)
        assert "SSH-2.0-OpenSSH" in banner

def test_get_banner_timeout():
    from m_map.m_map import get_banner
    
    # Context manager mock'u düzelt
    mock_context = MagicMock()
    mock_context.__enter__.return_value.recv.side_effect = socket.timeout()
    
    with patch('socket.socket', return_value=mock_context):
        banner = get_banner("127.0.0.1", 80)
        assert banner == ""

def test_detect_service_http():
    from m_map.m_map import detect_service
    
    with patch('m_map.m_map.get_banner') as mock_get_banner:
        # HTTP banner simülasyonu
        mock_get_banner.return_value = "HTTP/1.1 200 OK\r\nServer: nginx"
        
        service = detect_service("127.0.0.1", 80)
        assert "HTTP" in service  # Sadece HTTP içerdiğini kontrol et
        assert "nginx" in service  # nginx içerdiğini kontrol et

def test_detect_service_ssh():
    from m_map.m_map import detect_service
    
    with patch('m_map.m_map.get_banner') as mock_get_banner:
        # SSH banner simülasyonu
        mock_get_banner.return_value = "SSH-2.0-OpenSSH_8.2p1"
        
        service = detect_service("127.0.0.1", 22)
        assert "SSH" in service  # Sadece SSH içerdiğini kontrol et
        assert "OpenSSH" in service  # OpenSSH içerdiğini kontrol et

def test_detect_service_unknown():
    from m_map.m_map import detect_service
    
    with patch('m_map.m_map.get_banner') as mock_get_banner:
        # Bilinmeyen servis simülasyonu
        mock_get_banner.return_value = "UNKNOWN SERVICE"
        
        service = detect_service("127.0.0.1", 12345)
        assert service == "Unknown" 