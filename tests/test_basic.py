import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from m_map import get_service, ping_scan, get_optimal_thread_count

def test_get_service():
    # Test known ports
    assert get_service('80') == 'HTTP'
    assert get_service('443') == 'HTTPS'
    assert get_service('22') == 'SSH'
    
    # Test unknown port
    assert get_service('12345') == 0

def test_get_optimal_thread_count():
    thread_count = get_optimal_thread_count()
    assert thread_count <= 200
    assert thread_count > 0

def test_ping_scan():
    # Test localhost
    assert ping_scan('127.0.0.1') == True
    
    # Test invalid IP
    assert ping_scan('256.256.256.256') == False 