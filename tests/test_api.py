"""
Tests for the Submission API endpoints.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Test the health check endpoint (no auth required)."""

    def test_health_check(self):
        from src.api.submission import app
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["version"] == "1.0.0"


class TestPydanticModels:
    """Test Pydantic model validation."""

    def test_sample_submission_response(self):
        from src.api.submission import SampleSubmissionResponse
        from datetime import datetime, timezone
        resp = SampleSubmissionResponse(
            sample_id="test-id",
            sha256="a" * 64,
            status="queued",
            message="Test",
            queued_at=datetime.now(timezone.utc),
        )
        assert resp.sample_id == "test-id"
        assert resp.status == "queued"

    def test_queue_status_response(self):
        from src.api.submission import QueueStatusResponse
        resp = QueueStatusResponse(
            pending_count=5,
            processing_count=2,
            estimated_wait_seconds=1500,
        )
        assert resp.pending_count == 5
        assert resp.estimated_wait_seconds == 1500

    def test_analysis_result_model(self):
        from src.api.submission import AnalysisResult
        result = AnalysisResult(
            sample_id="test-id",
            verdict="malicious",
            confidence_score=0.95,
            summary="Test analysis",
            behaviors=[],
            iocs=[],
            mitre_attack=[],
            sigma_matches=[],
        )
        assert result.verdict == "malicious"
        assert result.confidence_score == 0.95


class TestHashCalculation:
    """Test hash calculation utility."""

    def test_calculate_hashes(self):
        from src.api.submission import calculate_hashes
        content = b"test file content"
        hashes = calculate_hashes(content)
        assert "sha256" in hashes
        assert "sha1" in hashes
        assert "md5" in hashes
        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha1"]) == 40
        assert len(hashes["md5"]) == 32

    def test_consistent_hashes(self):
        from src.api.submission import calculate_hashes
        content = b"deterministic content"
        h1 = calculate_hashes(content)
        h2 = calculate_hashes(content)
        assert h1 == h2, "Same content should produce same hashes"

    def test_different_content_different_hashes(self):
        from src.api.submission import calculate_hashes
        h1 = calculate_hashes(b"content A")
        h2 = calculate_hashes(b"content B")
        assert h1["sha256"] != h2["sha256"]


class TestStoragePath:
    """Test storage path generation."""

    def test_get_storage_path_uses_shard(self):
        from src.api.submission import get_storage_path
        path = get_storage_path("ab" + "c" * 62)
        assert "ab" in str(path), "Path should use first 2 chars as shard directory"

    def test_different_hashes_different_paths(self):
        from src.api.submission import get_storage_path
        p1 = get_storage_path("aa" + "1" * 62)
        p2 = get_storage_path("bb" + "2" * 62)
        assert p1 != p2
