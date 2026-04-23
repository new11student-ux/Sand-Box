"""
Advanced Cybersecurity Sandbox Platform
Falco Runtime Security Monitor

Integrates with Falco for real-time runtime security monitoring
of sandbox containers. Detects escape attempts, privilege escalation,
and policy violations.

Modes:
  - Simulated: generates realistic alerts for demo/testing
  - Live: connects to Falco gRPC/HTTP output (requires Falco running)
"""

import asyncio
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any
from collections import Counter

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FALCO_URL = os.getenv("FALCO_URL", "http://localhost:8765")
FALCO_RULES_DIR = Path(os.getenv("FALCO_RULES_DIR", "./vendor/falco/rules"))


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class FalcoAlert:
    """A single Falco security alert."""
    timestamp: float
    rule: str
    priority: str           # EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG
    output: str             # Human-readable alert message
    source: str             # syscall, k8s_audit, etc.
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    fields: Dict[str, Any] = field(default_factory=dict)
    sample_id: Optional[str] = None
    mitre_attack_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["@timestamp"] = datetime.fromtimestamp(
            self.timestamp, tz=timezone.utc
        ).isoformat()
        return d


@dataclass
class FalcoRuleDefinition:
    """Custom Falco rule definition."""
    name: str
    description: str
    condition: str
    output: str
    priority: str
    tags: List[str] = field(default_factory=list)
    mitre_attack_id: Optional[str] = None


@dataclass
class SecuritySummary:
    """Summary of security alerts for an analysis session."""
    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    alert_by_rule: Dict[str, int] = field(default_factory=dict)
    escape_attempts: int = 0
    privilege_escalations: int = 0
    network_violations: int = 0
    risk_score: float = 0.0


# ============================================================================
# Built-in Sandbox Rules
# ============================================================================

SANDBOX_RULES: List[FalcoRuleDefinition] = [
    FalcoRuleDefinition(
        name="Sandbox Container Escape Attempt",
        description="Detects attempts to escape sandbox container via namespace manipulation",
        condition="container.id != host and (evt.type in (setns, unshare, pivot_root, chroot))",
        output="Container escape attempt detected (user=%user.name command=%proc.cmdline container=%container.name)",
        priority="CRITICAL",
        tags=["sandbox", "container_escape"],
        mitre_attack_id="T1611",
    ),
    FalcoRuleDefinition(
        name="Sandbox Unauthorized Network Egress",
        description="Detects outbound network connections from sandbox containers to non-whitelisted IPs",
        condition="container.name startswith 'sandbox-' and evt.type = connect and fd.sip != 127.0.0.1",
        output="Unauthorized network egress from sandbox (container=%container.name dest=%fd.sip:%fd.sport)",
        priority="WARNING",
        tags=["sandbox", "network_egress"],
        mitre_attack_id="T1048",
    ),
    FalcoRuleDefinition(
        name="Sandbox Privilege Escalation",
        description="Detects privilege escalation attempts within sandbox containers",
        condition="container.name startswith 'sandbox-' and evt.type in (setuid, setgid, setreuid, setregid)",
        output="Privilege escalation in sandbox (user=%user.name command=%proc.cmdline container=%container.name)",
        priority="CRITICAL",
        tags=["sandbox", "privilege_escalation"],
        mitre_attack_id="T1068",
    ),
    FalcoRuleDefinition(
        name="Sandbox Sensitive File Access",
        description="Detects reads of sensitive host paths from sandbox containers",
        condition="container.name startswith 'sandbox-' and fd.name in (/etc/shadow, /etc/passwd, /proc/1/ns/)",
        output="Sensitive file access from sandbox (file=%fd.name container=%container.name proc=%proc.name)",
        priority="ALERT",
        tags=["sandbox", "sensitive_file"],
        mitre_attack_id="T1005",
    ),
    FalcoRuleDefinition(
        name="Sandbox Process Injection via ptrace",
        description="Detects ptrace attach from sandbox containers indicating process injection",
        condition="container.name startswith 'sandbox-' and evt.type = ptrace and evt.arg.request = PTRACE_ATTACH",
        output="Process injection via ptrace in sandbox (container=%container.name target_pid=%evt.arg.pid)",
        priority="CRITICAL",
        tags=["sandbox", "process_injection"],
        mitre_attack_id="T1055",
    ),
]


# ============================================================================
# Falco Monitor
# ============================================================================

class FalcoMonitor:
    """
    Falco runtime security monitor.

    In simulated mode, generates realistic security alerts.
    In live mode (future), connects to Falco's HTTP/gRPC output.
    """

    def __init__(self, mode: str = "simulated", falco_url: Optional[str] = None):
        self.mode = mode
        self.falco_url = falco_url or FALCO_URL
        self.rules = list(SANDBOX_RULES)
        self._alerts: List[FalcoAlert] = []

    def generate_alerts(
        self,
        sample_id: str,
        behavior_profile: str = "malicious",
        count: Optional[int] = None,
    ) -> List[FalcoAlert]:
        """
        Generate simulated Falco alerts for an analysis session.

        Args:
            sample_id: Sample being analyzed
            behavior_profile: 'malicious', 'evasive', or 'benign'
            count: Number of alerts (auto-determined if None)
        """
        if count is None:
            count = {"malicious": 8, "evasive": 12, "benign": 1}.get(behavior_profile, 3)

        alerts = []
        container_id = f"sandbox-{sample_id[:8]}"
        container_name = f"sandbox-analysis-{sample_id[:12]}"
        base_time = time.time()

        if behavior_profile == "benign":
            # Benign: only INFO-level alerts
            alerts.append(FalcoAlert(
                timestamp=base_time,
                rule="Sandbox Analysis Started",
                priority="INFO",
                output=f"Analysis session started (container={container_name} sample={sample_id[:16]})",
                source="syscall",
                container_id=container_id,
                container_name=container_name,
                sample_id=sample_id,
            ))
            self._alerts = alerts
            return alerts

        # Select rules based on profile
        if behavior_profile == "evasive":
            active_rules = self.rules  # All rules fire for evasive
        else:
            active_rules = random.sample(self.rules, min(count, len(self.rules)))

        for i, rule in enumerate(active_rules):
            if i >= count:
                break
            t = base_time + i * random.uniform(0.5, 3.0)

            fields = self._generate_alert_fields(rule, behavior_profile)

            alerts.append(FalcoAlert(
                timestamp=t,
                rule=rule.name,
                priority=rule.priority,
                output=self._format_output(rule, container_name, fields),
                source="syscall",
                container_id=container_id,
                container_name=container_name,
                fields=fields,
                sample_id=sample_id,
                mitre_attack_id=rule.mitre_attack_id,
            ))

        alerts.sort(key=lambda a: a.timestamp)
        self._alerts = alerts
        return alerts

    def _generate_alert_fields(self, rule: FalcoRuleDefinition, profile: str) -> Dict[str, Any]:
        """Generate realistic alert fields for a rule."""
        base_fields = {
            "user.name": random.choice(["root", "sandbox", "www-data"]),
            "proc.name": random.choice(["malware.exe", "sh", "bash", "python3", "curl"]),
            "proc.pid": random.randint(1000, 9999),
        }

        if "network" in rule.name.lower() or "egress" in rule.name.lower():
            base_fields["fd.sip"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            base_fields["fd.sport"] = random.choice([4444, 8080, 443, 80, 5555])

        if "file" in rule.name.lower():
            base_fields["fd.name"] = random.choice([
                "/etc/shadow", "/etc/passwd", "/proc/1/ns/mnt", "/proc/self/maps",
            ])

        if "ptrace" in rule.name.lower() or "injection" in rule.name.lower():
            base_fields["evt.arg.pid"] = random.randint(1, 999)
            base_fields["evt.arg.request"] = "PTRACE_ATTACH"

        return base_fields

    def _format_output(self, rule: FalcoRuleDefinition, container: str, fields: Dict) -> str:
        """Format human-readable alert output."""
        proc = fields.get("proc.name", "unknown")
        user = fields.get("user.name", "unknown")
        return f"{rule.description} (user={user} proc={proc} container={container})"

    def compute_summary(self, alerts: Optional[List[FalcoAlert]] = None) -> SecuritySummary:
        """Compute security summary from alerts."""
        alerts = alerts or self._alerts
        if not alerts:
            return SecuritySummary()

        rule_counter = Counter(a.rule for a in alerts)
        priority_map = {"EMERGENCY": 5, "ALERT": 4, "CRITICAL": 4, "ERROR": 3, "WARNING": 2, "NOTICE": 1, "INFO": 0}

        critical = sum(1 for a in alerts if a.priority in ("CRITICAL", "EMERGENCY", "ALERT"))
        high = sum(1 for a in alerts if a.priority in ("ERROR", "WARNING"))
        escapes = sum(1 for a in alerts if "escape" in a.rule.lower())
        privesc = sum(1 for a in alerts if "privilege" in a.rule.lower() or "escalation" in a.rule.lower())
        network = sum(1 for a in alerts if "network" in a.rule.lower() or "egress" in a.rule.lower())

        # Risk score: 0-10 scale
        risk = min(10.0, sum(priority_map.get(a.priority, 0) for a in alerts) / max(len(alerts), 1) * 2.5)

        return SecuritySummary(
            total_alerts=len(alerts),
            critical_alerts=critical,
            high_alerts=high,
            alert_by_rule=dict(rule_counter),
            escape_attempts=escapes,
            privilege_escalations=privesc,
            network_violations=network,
            risk_score=round(risk, 2),
        )

    def correlate_with_analysis(
        self, alerts: List[FalcoAlert], sample_id: str
    ) -> List[FalcoAlert]:
        """Correlate Falco alerts with a specific analysis session."""
        return [a for a in alerts if a.sample_id == sample_id]

    def get_mitre_coverage(self, alerts: Optional[List[FalcoAlert]] = None) -> Dict[str, int]:
        """Get MITRE ATT&CK technique coverage from alerts."""
        alerts = alerts or self._alerts
        mitre_counter = Counter(
            a.mitre_attack_id for a in alerts
            if a.mitre_attack_id
        )
        return dict(mitre_counter)
