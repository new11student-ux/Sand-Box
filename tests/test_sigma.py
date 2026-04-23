"""
Tests for the Sigma Rule Detection Engine.
"""

import pytest
from src.sigma.engine import SigmaEngine, SigmaRule


class TestSigmaEngineLoading:
    """Test Sigma rule loading."""

    def test_load_builtin_rules(self):
        engine = SigmaEngine()
        count = engine.load_rules()
        assert count >= 7, f"Expected at least 7 built-in rules, got {count}"

    def test_rules_have_required_fields(self):
        engine = SigmaEngine()
        engine.load_rules()
        for rule in engine.rules:
            assert rule.id, "Rule must have an ID"
            assert rule.title, "Rule must have a title"
            assert rule.level in ("informational", "info", "low", "medium", "high", "critical")
            assert rule.detection, "Rule must have detection logic"


class TestSigmaMatching:
    """Test Sigma rule matching against behavior data."""

    def setup_method(self):
        self.engine = SigmaEngine()
        self.engine.load_rules()

    def test_process_injection_detected(self, sample_behavior_data):
        matches = self.engine.match(sample_behavior_data)
        rule_ids = [m.rule_id for m in matches]
        assert "sandbox-001" in rule_ids, "Process injection rule should fire"

    def test_registry_persistence_detected(self, sample_behavior_data):
        matches = self.engine.match(sample_behavior_data)
        rule_ids = [m.rule_id for m in matches]
        assert "sandbox-002" in rule_ids, "Registry persistence rule should fire"

    def test_sandbox_evasion_detected(self, sample_behavior_data):
        matches = self.engine.match(sample_behavior_data)
        rule_ids = [m.rule_id for m in matches]
        assert "sandbox-004" in rule_ids, "Evasion detection rule should fire"

    def test_temp_file_drop_detected(self, sample_behavior_data):
        matches = self.engine.match(sample_behavior_data)
        rule_ids = [m.rule_id for m in matches]
        assert "sandbox-006" in rule_ids, "Temp file drop rule should fire"

    def test_benign_no_high_severity(self, benign_behavior_data):
        matches = self.engine.match(benign_behavior_data)
        high_matches = [m for m in matches if m.level in ("high", "critical")]
        assert len(high_matches) == 0, (
            f"Benign data should not trigger high-severity rules, "
            f"but got: {[m.rule_title for m in high_matches]}"
        )

    def test_match_has_mitre_info(self, sample_behavior_data):
        matches = self.engine.match(sample_behavior_data)
        injection_match = next((m for m in matches if m.rule_id == "sandbox-001"), None)
        assert injection_match is not None
        assert "T1055" in injection_match.mitre_attack_ids
        assert "defense_evasion" in injection_match.mitre_tactics

    def test_matches_to_behaviors_format(self, sample_behavior_data):
        matches = self.engine.match(sample_behavior_data)
        behaviors = self.engine.matches_to_behaviors(matches, "test-sample-uuid")
        assert len(behaviors) == len(matches)
        for b in behaviors:
            assert "sample_id" in b
            assert "behavior_type" in b
            assert "severity" in b
            assert "sigma_rule_id" in b
            assert b["sample_id"] == "test-sample-uuid"


class TestSigmaConditions:
    """Test Sigma condition evaluation edge cases."""

    def setup_method(self):
        self.engine = SigmaEngine()

    def test_and_condition(self):
        result = self.engine._evaluate_condition(
            "sel1 and sel2",
            {"sel1": True, "sel2": True}
        )
        assert result is True

    def test_and_condition_fails(self):
        result = self.engine._evaluate_condition(
            "sel1 and sel2",
            {"sel1": True, "sel2": False}
        )
        assert result is False

    def test_or_condition(self):
        result = self.engine._evaluate_condition(
            "sel1 or sel2",
            {"sel1": False, "sel2": True}
        )
        assert result is True

    def test_not_condition(self):
        result = self.engine._evaluate_condition(
            "not sel1",
            {"sel1": False}
        )
        assert result is True

    def test_1_of_pattern(self):
        result = self.engine._evaluate_condition(
            "1 of selection*",
            {"selection_a": False, "selection_b": True, "other": False}
        )
        assert result is True

    def test_all_of_pattern(self):
        result = self.engine._evaluate_condition(
            "all of selection*",
            {"selection_a": True, "selection_b": True}
        )
        assert result is True
