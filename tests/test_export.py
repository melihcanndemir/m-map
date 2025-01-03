import os
import json
import pytest
from datetime import datetime

def test_save_results(tmp_path):
    from m_map.m_map import save_results
    
    # Test verileri
    target = "192.168.1.1"
    results = [(80, "HTTP"), (443, "HTTPS")]
    scan_time = datetime.now()
    
    # Geçici dizinde dosya oluştur
    filename = save_results(target, results, scan_time)
    
    # Dosyanın oluşturulduğunu kontrol et
    assert os.path.exists(filename)
    
    # Dosya içeriğini kontrol et
    with open(filename, 'r') as f:
        content = f.read()
        assert "M-MAP Port Scan Report" in content
        assert target in content
        assert "80" in content
        assert "443" in content

def test_export_results_json(tmp_path):
    from m_map.m_map import export_results
    
    # Test verileri
    target = "192.168.1.1"
    results = [(80, "HTTP"), (443, "HTTPS")]
    
    # JSON formatında dışa aktar
    filename = export_results(results, 'json', target)
    
    # Dosyanın oluşturulduğunu kontrol et
    assert os.path.exists(filename)
    assert filename.endswith('.json')
    
    # JSON içeriğini kontrol et
    with open(filename, 'r') as f:
        data = json.load(f)
        assert data['target'] == target
        assert len(data['open_ports']) == 2
        assert data['open_ports'][0]['port'] == 80

def test_export_results_empty():
    from m_map.m_map import export_results
    
    # Boş sonuç listesi ile test
    result = export_results([], 'txt', "192.168.1.1")
    assert result is None

def test_export_html_report(tmp_path):
    from m_map.m_map import export_html_report
    
    # Test verileri
    target = "192.168.1.1"
    results = [(80, "HTTP"), (443, "HTTPS")]
    scan_time = datetime.now()
    
    # HTML raporu oluştur
    filename = export_html_report(results, target, scan_time)
    
    # Dosyanın oluşturulduğunu kontrol et
    assert os.path.exists(filename)
    assert filename.endswith('.html')
    
    # HTML içeriğini kontrol et
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
        assert "<title>M-MAP Scan Report</title>" in content
        assert target in content
        assert "80" in content
        assert "443" in content 