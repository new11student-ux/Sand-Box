"""
Tests for the worker's CAPEv2 report processing and Sigma integration.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch
from src.worker.main import (
    run_sigma_matching,
    _transform_capev2_to_behavior,
)


class TestCAPEv2ReportTransformation:
    """Test transformation of CAPEv2 reports to behavior data."""

    def test_api_calls_extracted(self, sample_capev2_report):
        behavior = _transform_capev2_to_behavior(sample_capev2_report)
        assert "VirtualAllocEx" in behavior["api_calls"]
        assert "WriteProcessMemory" in behavior["api_calls"]
        assert "CreateRemoteThread" in behavior["api_calls"]

    def test_registry_ops_extracted(self, sample_capev2_report):
        behavior = _transform_capev2_to_behavior(sample_capev2_report)
        paths = [op["path"] for op in behavior["registry_operations"]]
        assert any("CurrentVersion\\Run" in p for p in paths)

    def test_file_ops_extracted(self, sample_capev2_report):
        behavior = _transform_capev2_to_behavior(sample_capev2_report)
        paths = [op["path"] for op in behavior["file_operations"]]
        assert any("payload.exe" in p for p in paths)

    def test_network_extracted(self, sample_capev2_report):
        behavior = _transform_capev2_to_behavior(sample_capev2_report)
        connections = behavior["network"]["connections"]
        assert len(connections) == 3
        assert connections[0]["port"] == 4444

    def test_dns_extracted(self, sample_capev2_report):
        behavior = _transform_capev2_to_behavior(sample_capev2_report)
        dns = behavior["network"]["dns"]
        queries = [d["query"] for d in dns]
        assert "evil-c2.example.com" in queries

    def test_empty_report(self):
        behavior = _transform_capev2_to_behavior({})
        assert behavior["api_calls"] == []
        assert behavior["registry_operations"] == []
        assert behavior["file_operations"] == []


class TestSigmaIntegration:
    """Test Sigma rule matching on CAPEv2 reports."""

    def test_malicious_report_triggers_sigma(self, sample_capev2_report):
        matches = run_sigma_matching(sample_capev2_report)
        assert len(matches) > 0, "Malicious report should trigger at least one Sigma rule"

    def test_injection_detected_from_report(self, sample_capev2_report):
        matches = run_sigma_matching(sample_capev2_report)
        rule_ids = [m.rule_id for m in matches]
        assert "sandbox-001" in rule_ids, "Process injection should be detected"

    def test_persistence_detected_from_report(self, sample_capev2_report):
        matches = run_sigma_matching(sample_capev2_report)
        rule_ids = [m.rule_id for m in matches]
        assert "sandbox-002" in rule_ids, "Registry persistence should be detected"

    def test_empty_report_no_matches(self):
        matches = run_sigma_matching({})
        high_matches = [m for m in matches if m.level in ("high", "critical")]
        assert len(high_matches) == 0, "Empty report should not trigger high-severity rules"

    def test_match_levels_are_valid(self, sample_capev2_report):
        matches = run_sigma_matching(sample_capev2_report)
        valid_levels = {"informational", "info", "low", "medium", "high", "critical"}
        for m in matches:
            assert m.level in valid_levels, f"Invalid level: {m.level}"
