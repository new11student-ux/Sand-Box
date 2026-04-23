"""
Tests for ML integration: training data generation, model training, and worker integration.
"""

import pytest
import numpy as np
from src.ml.training_data_generator import (
    generate_training_data, FEATURE_NAMES,
    _generate_malicious_sample, _generate_benign_sample,
)


class TestFeatureSchema:
    """Test the 15-feature schema."""

    def test_feature_count(self):
        assert len(FEATURE_NAMES) == 15

    def test_feature_names(self):
        assert "api_call_entropy" in FEATURE_NAMES
        assert "injection_indicator" in FEATURE_NAMES
        assert "c2_beaconing_indicator" in FEATURE_NAMES
        assert "defense_evasion_indicator" in FEATURE_NAMES


class TestMaliciousSampleGeneration:
    """Test malicious sample generation for each subtype."""

    def test_generic_malicious(self):
        sample = _generate_malicious_sample("generic")
        assert len(sample) == 15
        assert all(isinstance(v, (int, float)) for v in sample)

    def test_injection_subtype(self):
        sample = _generate_malicious_sample("injection")
        assert len(sample) == 15
        # injection_indicator (index 11) should be high
        assert sample[11] >= 0.6

    def test_c2_subtype(self):
        sample = _generate_malicious_sample("c2")
        assert len(sample) == 15
        # c2_beaconing_indicator (index 12) should be high
        assert sample[12] >= 0.6

    def test_dropper_subtype(self):
        sample = _generate_malicious_sample("dropper")
        assert len(sample) == 15
        # dropper_indicator (index 10) should be high
        assert sample[10] >= 0.6

    def test_evasion_subtype(self):
        sample = _generate_malicious_sample("evasion")
        assert len(sample) == 15
        # defense_evasion_indicator (index 14) should be high
        assert sample[14] >= 0.6


class TestBenignSampleGeneration:
    """Test benign sample generation."""

    def test_benign_sample(self):
        sample = _generate_benign_sample()
        assert len(sample) == 15

    def test_benign_low_indicators(self):
        sample = _generate_benign_sample()
        # All malicious indicators should be low
        assert sample[10] <= 0.1  # dropper
        assert sample[11] <= 0.1  # injection
        assert sample[12] <= 0.1  # c2
        assert sample[13] <= 0.1  # privesc
        assert sample[14] <= 0.1  # evasion

    def test_benign_low_suspicious_apis(self):
        sample = _generate_benign_sample()
        assert sample[5] <= 2  # suspicious_api_count


class TestTrainingDataGeneration:
    """Test the full training data generation pipeline."""

    def test_generate_default(self):
        X, y = generate_training_data(n_samples=100, seed=42)
        assert X.shape == (100, 15)
        assert y.shape == (100,)

    def test_label_distribution(self):
        X, y = generate_training_data(n_samples=1000, malicious_ratio=0.4, seed=42)
        malicious_count = np.sum(y == 1)
        benign_count = np.sum(y == 0)
        assert malicious_count == 400
        assert benign_count == 600

    def test_reproducibility(self):
        X1, y1 = generate_training_data(n_samples=50, seed=123)
        X2, y2 = generate_training_data(n_samples=50, seed=123)
        np.testing.assert_array_equal(X1, X2)
        np.testing.assert_array_equal(y1, y2)

    def test_different_seeds(self):
        X1, _ = generate_training_data(n_samples=50, seed=1)
        X2, _ = generate_training_data(n_samples=50, seed=2)
        assert not np.array_equal(X1, X2)

    def test_custom_ratio(self):
        X, y = generate_training_data(n_samples=200, malicious_ratio=0.7, seed=42)
        assert np.sum(y == 1) == 140
        assert np.sum(y == 0) == 60

    def test_values_in_range(self):
        X, y = generate_training_data(n_samples=500, seed=42)
        # All values should be non-negative
        assert np.all(X >= 0)
        # Labels should be binary
        assert set(np.unique(y)) == {0, 1}


class TestMLWorkerIntegration:
    """Test ML classifier integration with worker pipeline."""

    def test_run_ml_prediction_untrained(self):
        """When classifier is untrained, should return ml_available=False."""
        from src.worker.main import run_ml_prediction
        result = run_ml_prediction({"api_calls": []})
        assert result["ml_available"] is False
        assert result["ml_score"] is None

    def test_transform_capev2_to_behavior(self):
        """Test CAPEv2 report transformation."""
        from src.worker.main import _transform_capev2_to_behavior
        report = {
            "behavior": {
                "processes": [
                    {"calls": [{"api": "VirtualAllocEx"}, {"api": "WriteProcessMemory"}]}
                ],
                "regkey_written": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"],
                "file_written": ["C:\\Windows\\Temp\\payload.exe"],
            },
            "network": {
                "tcp": [{"dst": "10.0.0.1", "dport": 4444}],
                "dns": [{"request": "evil.example.com"}],
            },
        }
        behavior = _transform_capev2_to_behavior(report)
        assert "api_calls" in behavior
        assert len(behavior["api_calls"]) == 2
        assert "registry_operations" in behavior
        assert len(behavior["registry_operations"]) == 1
        assert "file_operations" in behavior
        assert len(behavior["file_operations"]) == 1

    def test_ebpf_telemetry_function(self):
        """Test the eBPF telemetry wrapper in worker."""
        from src.worker.main import run_ebpf_telemetry
        result = run_ebpf_telemetry("test-sample-ebpf", "malicious")
        assert "event_count" in result
        assert result["event_count"] > 0
        assert "suspicious_count" in result
        assert "output_path" in result

    def test_falco_monitoring_function(self):
        """Test the Falco monitoring wrapper in worker."""
        from src.worker.main import run_falco_monitoring
        result = run_falco_monitoring("test-sample-falco", "malicious")
        assert "total_alerts" in result
        assert result["total_alerts"] > 0
        assert "risk_score" in result
        assert result["risk_score"] > 0

    def test_falco_benign_monitoring(self):
        """Benign samples should get minimal alerts."""
        from src.worker.main import run_falco_monitoring
        result = run_falco_monitoring("test-benign", "benign")
        assert result["total_alerts"] == 1
        assert result["critical_alerts"] == 0
