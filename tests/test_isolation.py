import pytest
import asyncio
from src.isolation.schemas import RBISessionRequest, SanitizationRequest
from src.isolation.kasm_client import get_kasm_client, SimulatedKasmClient, RealKasmClient
from src.isolation.dangerzone import get_dangerzone_manager, SimulatedDangerzoneManager

@pytest.mark.asyncio
async def test_simulated_kasm_client():
    client = get_kasm_client(mode="simulated")
    assert isinstance(client, SimulatedKasmClient)
    
    req = RBISessionRequest(
        url="http://malicious.com",
        browser_type="chrome"
    )
    
    result = await client.create_session(req)
    assert result.status == "active"
    assert result.session_id is not None
    assert "example.com" in result.cast_url
    assert "malicious.com" in result.cast_url

@pytest.mark.asyncio
async def test_real_kasm_client_unimplemented():
    client = get_kasm_client(mode="live", api_url="http", api_key="k", api_secret="s")
    assert isinstance(client, RealKasmClient)
    
    req = RBISessionRequest(url="http://malicious.com")
    result = await client.create_session(req)
    
    # Real client without real backend just falls back to error safely
    assert result.status == "error"
    assert result.cast_url == "about:blank"

@pytest.mark.asyncio
async def test_simulated_dangerzone_manager():
    manager = get_dangerzone_manager(mode="simulated")
    assert isinstance(manager, SimulatedDangerzoneManager)
    
    file_content = b"fake pdf content with macro"
    req = SanitizationRequest(file_name="invoice.pdf", file_size=len(file_content))
    
    result = await manager.sanitize_document(file_content, req)
    
    assert result.status == "safe"
    assert result.task_id is not None
    assert result.original_sha256 is not None
    assert result.safe_sha256 is not None
    assert result.original_sha256 != result.safe_sha256
    assert "/api/v1/isolation/download" in result.safe_file_url
