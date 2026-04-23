"""
Tests for the Falco Runtime Security Monitor.
"""

import pytest
from src.observability.falco_monitor import (
    FalcoMonitor, FalcoAlert, SecuritySummary,
    SANDBOX_RULES, FalcoRuleDefinition,
)


class TestFalcoRuleDefinitions:
    """Test built-in Falco rule definitions."""

    def test_rules_exist(self):
        assert len(SANDBOX_RULES) >= 5

    def test_rule_fields(self):
        for rule in SANDBOX_RULES:
            assert isinstance(rule, FalcoRuleDefinition)
            assert rule.name
            assert rule.description
            assert rule.condition
            assert rule.output
            assert rule.priority in (
                "EMERGENCY", "ALERT", "CRITICAL", "ERROR",
                "WARNING", "NOTICE", "INFO", "DEBUG"
            )

    def test_mitre_tags(self):
        """All sandbox rules should have MITRE ATT&CK mapping."""
        for rule in SANDBOX_RULES:
            assert rule.mitre_attack_id is not None
            assert rule.mitre_attack_id.startswith("T")

    def test_rule_names_unique(self):
        names = [r.name for r in SANDBOX_RULES]
        assert len(names) == len(set(names))


class TestFalcoAlert:
    """Test FalcoAlert data model."""

    def test_create_alert(self):
        alert = FalcoAlert(
            timestamp=1000.0,
            rule="Test Rule",
            priority="WARNING",
            output="Test alert message",
            source="syscall",
            sample_id="sample-123",
        )
        assert alert.rule == "Test Rule"
        assert alert.priority == "WARNING"
        assert alert.sample_id == "sample-123"

    def test_to_dict(self):
        alert = FalcoAlert(
            timestamp=1000.0,
            rule="Test Rule",
            priority="CRITICAL",
            output="Test output",
            source="syscall",
            container_id="abc123",
        )
        d = alert.to_dict()
        assert d["rule"] == "Test Rule"
        assert d["priority"] == "CRITICAL"
        assert "@timestamp" in d


class TestFalcoMonitor:
    """Test Falco monitor functionality."""

    def setup_method(self):
        self.monitor = FalcoMonitor(mode="simulated")

    def test_generate_malicious_alerts(self):
        alerts = self.monitor.generate_alerts(
            sample_id="mal-001",
            behavior_profile="malicious",
        )
        assert len(alerts) > 0
        # Malicious should trigger high-priority alerts
        priorities = {a.priority for a in alerts}
        assert "CRITICAL" in priorities or "ALERT" in priorities or "WARNING" in priorities

    def test_generate_benign_alerts(self):
        alerts = self.monitor.generate_alerts(
            sample_id="benign-001",
            behavior_profile="benign",
        )
        assert len(alerts) == 1  # Only INFO-level "started" alert
        assert alerts[0].priority == "INFO"

    def test_generate_evasive_alerts(self):
        alerts = self.monitor.generate_alerts(
            sample_id="evasive-001",
            behavior_profile="evasive",
        )
        assert len(alerts) > 0
        # Evasive triggers all rules
        assert len(alerts) >= len(SANDBOX_RULES)

    def test_alerts_sorted_by_timestamp(self):
        alerts = self.monitor.generate_alerts("sort-test", behavior_profile="malicious")
        timestamps = [a.timestamp for a in alerts]
        assert timestamps == sorted(timestamps)

    def test_alert_sample_correlation(self):
        alerts = self.monitor.generate_alerts("corr-test", behavior_profile="malicious")
        for alert in alerts:
            assert alert.sample_id == "corr-test"

    def test_custom_alert_count(self):
        alerts = self.monitor.generate_alerts("count-test", behavior_profile="malicious", count=3)
        assert len(alerts) == 3


class TestSecuritySummary:
    """Test security summary computation."""

    def setup_method(self):
        self.monitor = FalcoMonitor(mode="simulated")

    def test_compute_summary_malicious(self):
        alerts = self.monitor.generate_alerts("sum-mal", behavior_profile="malicious")
        summary = self.monitor.compute_summary(alerts)

        assert isinstance(summary, SecuritySummary)
        assert summary.total_alerts > 0
        assert summary.risk_score > 0

    def test_compute_summary_benign(self):
        alerts = self.monitor.generate_alerts("sum-benign", behavior_profile="benign")
        summary = self.monitor.compute_summary(alerts)

        assert summary.total_alerts == 1
        assert summary.critical_alerts == 0
        assert summary.escape_attempts == 0

    def test_empty_summary(self):
        summary = self.monitor.compute_summary([])
        assert summary.total_alerts == 0
        assert summary.risk_score == 0.0

    def test_alert_by_rule(self):
        alerts = self.monitor.generate_alerts("rule-test", behavior_profile="malicious")
        summary = self.monitor.compute_summary(alerts)
        assert len(summary.alert_by_rule) > 0

    def test_risk_score_range(self):
        alerts = self.monitor.generate_alerts("risk-test", behavior_profile="evasive", count=20)
        summary = self.monitor.compute_summary(alerts)
        assert 0 <= summary.risk_score <= 10


class TestAlertCorrelation:
    """Test alert correlation and filtering."""

    def setup_method(self):
        self.monitor = FalcoMonitor(mode="simulated")

    def test_correlate_with_analysis(self):
        alerts_a = self.monitor.generate_alerts("sample-a", behavior_profile="malicious")
        alerts_b = self.monitor.generate_alerts("sample-b", behavior_profile="malicious")
        all_alerts = alerts_a + alerts_b

        correlated = self.monitor.correlate_with_analysis(all_alerts, "sample-a")
        assert len(correlated) == len(alerts_a)
        assert all(a.sample_id == "sample-a" for a in correlated)

    def test_mitre_coverage(self):
        alerts = self.monitor.generate_alerts("mitre-test", behavior_profile="malicious")
        coverage = self.monitor.get_mitre_coverage(alerts)
        assert len(coverage) > 0
        for technique_id in coverage.keys():
            assert technique_id.startswith("T")
