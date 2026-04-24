import pytest
import toml
from fastapi.testclient import TestClient
from src.api.submission import app
import os
from pathlib import Path
import subprocess

client = TestClient(app)

def test_metrics_endpoint_exists():
    """Verify /metrics endpoint is exposed and returns Prometheus format"""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "http_requests_total" in response.text
    assert "http_request_duration_seconds" in response.text

def test_custom_security_metrics():
    """Verify business-logic metrics are instrumented"""
    from src.api.submission import record_malware_detection
    
    # Trigger a malware detection metric update
    record_malware_detection("high", "T1059.001")
    
    # Scrape metrics
    response = client.get("/metrics")
    assert "sandbox_malware_detected_total" in response.text
    assert 'severity="high"' in response.text
    assert 'technique="T1059.001"' in response.text

def test_enarx_config_valid():
    """Verify Enarx.toml is syntactically valid and contains required fields"""
    config_path = Path("src/confidential/Enarx.toml")
    assert config_path.exists()
    
    config = toml.load(config_path)
    
    assert "enarx" in config
    assert "id" in config["enarx"]
    assert "deploy" in config
    assert "target" in config["deploy"]
    assert config["deploy"]["target"] in ["sgx", "sev", "none"]
    
    assert "wasm" in config
    assert "path" in config["wasm"]
    assert config["wasm"]["path"].endswith(".wasm")
