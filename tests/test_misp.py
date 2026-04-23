"""
Tests for the MISP Threat Intelligence Client.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.ti.misp_client import MISPClient, IOC_TYPE_MAP


class TestMISPClientInit:
    """Test MISP client initialization."""

    def test_default_config(self):
        client = MISPClient()
        assert client.url == "http://localhost:8081"

    def test_custom_url(self):
        client = MISPClient(url="https://misp.example.com")
        assert client.url == "https://misp.example.com"

    def test_trailing_slash_stripped(self):
        client = MISPClient(url="https://misp.example.com/")
        assert client.url == "https://misp.example.com"


class TestIOCMapping:
    """Test IOC type mapping from internal to MISP types."""

    def test_ip_mapping(self):
        assert IOC_TYPE_MAP["ip"] == "ip-dst"

    def test_domain_mapping(self):
        assert IOC_TYPE_MAP["domain"] == "domain"

    def test_url_mapping(self):
        assert IOC_TYPE_MAP["url"] == "url"

    def test_hash_mapping(self):
        assert IOC_TYPE_MAP["file_hash"] == "sha256"

    def test_registry_mapping(self):
        assert IOC_TYPE_MAP["registry_key"] == "regkey"


def _make_mock_response(json_data):
    """Create a mock httpx response."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


@pytest.mark.asyncio
class TestMISPEnrichment:
    """Test MISP enrichment methods."""

    async def test_enrich_hash_not_found(self):
        client = MISPClient(api_key="test-key")
        mock_http = AsyncMock()
        mock_http.is_closed = False
        mock_http.request = AsyncMock(return_value=_make_mock_response(
            {"response": {"Attribute": []}}
        ))
        client._client = mock_http

        result = await client.enrich_hash("abc123" * 10)
        assert result["found"] is False
        assert result["events"] == []

    async def test_enrich_hash_found(self):
        client = MISPClient(api_key="test-key")
        mock_http = AsyncMock()
        mock_http.is_closed = False
        mock_http.request = AsyncMock(return_value=_make_mock_response({
            "response": {
                "Attribute": [{
                    "Event": {
                        "id": "42",
                        "info": "Test malware campaign",
                        "threat_level_id": "1",
                    },
                    "Tag": [
                        {"name": "tlp:amber"},
                        {"name": "mitre-attack:T1055"},
                    ],
                }]
            }
        }))
        client._client = mock_http

        result = await client.enrich_hash("abc123" * 10)
        assert result["found"] is True
        assert len(result["events"]) == 1
        assert result["threat_level"] == 1
        assert "tlp:amber" in result["tags"]

    async def test_no_api_key_skips_request(self):
        client = MISPClient(api_key="")
        result = await client.enrich_hash("abc123" * 10)
        assert result["found"] is False

    async def test_enrich_ioc_not_found(self):
        client = MISPClient(api_key="test-key")
        mock_http = AsyncMock()
        mock_http.is_closed = False
        mock_http.request = AsyncMock(return_value=_make_mock_response(
            {"response": {"Attribute": []}}
        ))
        client._client = mock_http

        result = await client.enrich_ioc("domain", "safe.example.com")
        assert result["found"] is False


@pytest.mark.asyncio
class TestMISPEventCreation:
    """Test MISP event creation from analysis results."""

    async def test_create_event_success(self):
        client = MISPClient(api_key="test-key")
        mock_http = AsyncMock()
        mock_http.is_closed = False
        mock_http.request = AsyncMock(return_value=_make_mock_response(
            {"Event": {"id": "100", "uuid": "test-uuid-123"}}
        ))
        client._client = mock_http

        uuid = await client.create_event_from_analysis(
            sample_sha256="a" * 64,
            sample_name="malware.exe",
            verdict="malicious",
            confidence=0.95,
            iocs=[
                {"ioc_type": "domain", "value": "evil.com", "confidence": "high"},
                {"ioc_type": "ip", "value": "10.0.0.1", "confidence": "medium"},
            ],
            behaviors=[],
            mitre_tactics=["T1055", "T1547"],
        )

        assert uuid == "test-uuid-123"
        mock_http.request.assert_called()

    async def test_create_event_benign_uses_green_tlp(self):
        client = MISPClient(api_key="test-key")
        mock_http = AsyncMock()
        mock_http.is_closed = False
        mock_http.request = AsyncMock(return_value=_make_mock_response(
            {"Event": {"id": "101", "uuid": "uuid-benign"}}
        ))
        client._client = mock_http

        uuid = await client.create_event_from_analysis(
            sample_sha256="b" * 64,
            sample_name="clean.exe",
            verdict="benign",
            confidence=0.8,
            iocs=[],
            behaviors=[],
        )
        assert uuid == "uuid-benign"


@pytest.mark.asyncio
class TestMISPCorrelation:
    """Test sample correlation."""

    async def test_correlate_no_match(self):
        client = MISPClient(api_key="test-key")
        mock_http = AsyncMock()
        mock_http.is_closed = False
        mock_http.request = AsyncMock(return_value=_make_mock_response(
            {"response": {"Attribute": []}}
        ))
        client._client = mock_http

        result = await client.correlate_sample("c" * 64)
        assert result["direct_match"] is False
        assert result["priority_boost"] == 0
