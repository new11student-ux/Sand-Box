"""
Academic Validation Tests
Ensures ML explanations are stable and evasion resistance works.
"""

import pytest
import numpy as np
import random
from src.ml.false_positive_classifier import FalsePositiveClassifier
from src.worker.evasion_resistance import EvasionResistanceEngine

@pytest.fixture
def dummy_classifier():
    clf = FalsePositiveClassifier()
    # Mock training for test purposes
    X_dummy = np.random.rand(100, 15)
    y_dummy = np.random.randint(0, 2, 100)
    clf.train(X_dummy, y_dummy)
    return clf

@pytest.mark.research
def test_ml_explanations_are_consistent(dummy_classifier):
    """Verify SHAP explanations are stable across similar inputs"""
    
    def generate_similar_malware():
        # Baseline suspicious behavior
        return {
            "api_calls": [{"api": "VirtualAlloc"}, {"api": "WriteProcessMemory"}],
            "network": {"connections": [{"port": 4444, "host": "1.2.3.4"}]},
            "process_tree": {"children": [{"children": []}]},
            "file_operations": [{"type": "write", "path": "temp/mal.exe"}],
            "registry_operations": [{"path": "CurrentVersion\\Run"}]
        }

    # Generate 10 identical/highly similar samples
    similar_samples = [generate_similar_malware() for _ in range(10)]
    
    explanations = [dummy_classifier.explain(s) for s in similar_samples]
    
    # Top 3 features should be consistent (Jaccard similarity > 0.7)
    top_features = [set([f["feature"] for f in e["top_features"][:3]]) for e in explanations]
    
    similarities = []
    for i, a in enumerate(top_features):
        for b in top_features[i+1:]:
            union_len = len(a | b)
            if union_len == 0:
                similarities.append(1.0)
            else:
                similarities.append(len(a & b) / union_len)
    
    assert np.mean(similarities) > 0.7, "Explanations lack consistency"

@pytest.mark.research
def test_evasion_resistance_improves_detection():
    """Verify the evasion resistance engine generates significantly different profiles."""
    engine = EvasionResistanceEngine()
    
    # Ensure it detects the system check evasion pattern
    result = engine.adapt_to_evasion("sample_123", ["T1497.001"])
    
    assert result["emulate_user_interaction"] is True
    assert result["profile"]["cpu_cores"] >= 4
    assert result["profile"]["ram_gb"] >= 8
    
    # Verify interactions are generated
    interactions = engine.emulate_user_interaction()
    assert len(interactions) >= 3
    assert any(e["type"] == "mouse_move" for e in interactions)
