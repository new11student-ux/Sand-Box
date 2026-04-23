"""
Advanced Cybersecurity Sandbox Platform
Sigma Rule Detection Engine

Loads Sigma rules from YAML files and matches them against
behavioral logs from sandbox analysis (CAPEv2 output).
"""

import os
import re
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

import yaml
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SIGMA_RULES_DIR = os.getenv("SIGMA_RULES_DIR", "./vendor/sigma/rules")

# MITRE ATT&CK tag → tactic/technique mapping
MITRE_TAG_PATTERN = re.compile(r"attack\.([a-z_]+)")
MITRE_TECHNIQUE_PATTERN = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


@dataclass
class SigmaRule:
    """Parsed Sigma rule."""
    id: str
    title: str
    status: str              # stable, test, experimental
    level: str               # informational, low, medium, high, critical
    description: str
    author: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    mitre_attack_ids: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    file_path: str = ""


@dataclass
class SigmaMatch:
    """Result of a Sigma rule match."""
    rule_id: str
    rule_title: str
    level: str
    description: str
    matched_fields: Dict[str, Any]
    mitre_attack_ids: List[str]
    mitre_tactics: List[str]
    tags: List[str]


class SigmaEngine:
    """
    Sigma rule loader and matching engine.

    Supports a subset of Sigma detection logic:
    - Selection with field matching (exact, contains, startswith, endswith)
    - Logical conditions (and, or, not, 1 of selection*)
    - Logsource filtering (category, product)
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = Path(rules_dir or SIGMA_RULES_DIR)
        self.rules: List[SigmaRule] = []
        self._loaded = False

    def load_rules(self, categories: Optional[List[str]] = None) -> int:
        """
        Load Sigma rules from YAML files.

        Args:
            categories: Optional list of logsource categories to load
                        (e.g., ['process_creation', 'network_connection'])

        Returns:
            Number of rules loaded
        """
        self.rules = []

        if not self.rules_dir.exists():
            logger.warning("Sigma rules dir not found: %s", self.rules_dir)
            # Load built-in rules as fallback
            self._load_builtin_rules()
            self._loaded = True
            return len(self.rules)

        rule_files = list(self.rules_dir.rglob("*.yml")) + list(
            self.rules_dir.rglob("*.yaml")
        )
        logger.info("Found %d Sigma rule files in %s", len(rule_files), self.rules_dir)

        for path in rule_files:
            try:
                rule = self._parse_rule_file(path)
                if rule is None:
                    continue
                if categories and rule.logsource.get("category") not in categories:
                    continue
                self.rules.append(rule)
            except Exception as exc:
                logger.debug("Skipping %s: %s", path.name, exc)

        # Always add built-in rules
        self._load_builtin_rules()

        self._loaded = True
        logger.info("Loaded %d Sigma rules", len(self.rules))
        return len(self.rules)

    def _parse_rule_file(self, path: Path) -> Optional[SigmaRule]:
        """Parse a single Sigma YAML rule file."""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return None

        if "detection" not in data:
            return None

        tags = data.get("tags", [])
        mitre_ids = []
        mitre_tactics = []
        for tag in tags:
            tech_match = MITRE_TECHNIQUE_PATTERN.match(tag)
            if tech_match:
                mitre_ids.append(tech_match.group(1).upper())
            tactic_match = MITRE_TAG_PATTERN.match(tag)
            if tactic_match:
                tactic = tactic_match.group(1)
                if not tactic.startswith("t"):
                    mitre_tactics.append(tactic)

        return SigmaRule(
            id=data.get("id", ""),
            title=data.get("title", path.stem),
            status=data.get("status", "experimental"),
            level=data.get("level", "medium"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {}),
            tags=tags,
            mitre_attack_ids=mitre_ids,
            mitre_tactics=mitre_tactics,
            falsepositives=data.get("falsepositives", []),
            file_path=str(path),
        )

    def _load_builtin_rules(self):
        """Load built-in Sigma rules for common malware behaviors."""
        builtins = [
            SigmaRule(
                id="sandbox-001", title="Suspicious Process Injection",
                status="stable", level="high",
                description="Detects process injection via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
                author="Sandbox Platform",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection": {"api_calls|contains": [
                        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"
                    ]},
                    "condition": "selection",
                },
                tags=["attack.defense_evasion", "attack.t1055"],
                mitre_attack_ids=["T1055"], mitre_tactics=["defense_evasion"],
            ),
            SigmaRule(
                id="sandbox-002", title="Registry Run Key Persistence",
                status="stable", level="high",
                description="Detects creation of Run/RunOnce registry keys for persistence",
                author="Sandbox Platform",
                logsource={"category": "registry_event", "product": "windows"},
                detection={
                    "selection": {"registry_path|contains": [
                        "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
                    ]},
                    "condition": "selection",
                },
                tags=["attack.persistence", "attack.t1547.001"],
                mitre_attack_ids=["T1547.001"], mitre_tactics=["persistence"],
            ),
            SigmaRule(
                id="sandbox-003", title="Suspicious Network Beaconing",
                status="stable", level="medium",
                description="Detects periodic outbound connections indicative of C2 beaconing",
                author="Sandbox Platform",
                logsource={"category": "network_connection"},
                detection={
                    "selection": {"beaconing_score|gte": 0.7},
                    "condition": "selection",
                },
                tags=["attack.command_and_control", "attack.t1071"],
                mitre_attack_ids=["T1071"], mitre_tactics=["command_and_control"],
            ),
            SigmaRule(
                id="sandbox-004", title="Sandbox Evasion Detected",
                status="stable", level="high",
                description="Detects anti-analysis / VM detection techniques",
                author="Sandbox Platform",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection": {"api_calls|contains": [
                        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    ]},
                    "condition": "selection",
                },
                tags=["attack.defense_evasion", "attack.t1497"],
                mitre_attack_ids=["T1497"], mitre_tactics=["defense_evasion"],
            ),
            SigmaRule(
                id="sandbox-005", title="Privilege Escalation Attempt",
                status="stable", level="high",
                description="Detects token manipulation for privilege escalation",
                author="Sandbox Platform",
                logsource={"category": "process_creation", "product": "windows"},
                detection={
                    "selection": {"api_calls|contains": [
                        "AdjustTokenPrivileges", "ImpersonateLoggedOnUser",
                    ]},
                    "condition": "selection",
                },
                tags=["attack.privilege_escalation", "attack.t1134"],
                mitre_attack_ids=["T1134"], mitre_tactics=["privilege_escalation"],
            ),
            SigmaRule(
                id="sandbox-006", title="File Dropped in Temp Directory",
                status="stable", level="medium",
                description="Detects executable files written to temp directories",
                author="Sandbox Platform",
                logsource={"category": "file_event", "product": "windows"},
                detection={
                    "selection_path": {"file_path|contains": ["\\Temp\\", "\\tmp\\"]},
                    "selection_ext": {"file_path|endswith": [".exe", ".dll", ".scr", ".bat", ".ps1"]},
                    "condition": "selection_path and selection_ext",
                },
                tags=["attack.execution", "attack.t1204"],
                mitre_attack_ids=["T1204"], mitre_tactics=["execution"],
            ),
            SigmaRule(
                id="sandbox-007", title="DNS Query to DGA Domain",
                status="stable", level="high",
                description="Detects DNS queries to domains with high entropy (DGA indicator)",
                author="Sandbox Platform",
                logsource={"category": "dns_query"},
                detection={
                    "selection": {"domain_entropy|gte": 3.5, "domain_length|gte": 20},
                    "condition": "selection",
                },
                tags=["attack.command_and_control", "attack.t1568.002"],
                mitre_attack_ids=["T1568.002"], mitre_tactics=["command_and_control"],
            ),
        ]
        for rule in builtins:
            if rule.id not in {r.id for r in self.rules}:
                self.rules.append(rule)

    # ------------------------------------------------------------------
    # Matching engine
    # ------------------------------------------------------------------

    def match(self, behavior_data: Dict[str, Any]) -> List[SigmaMatch]:
        """
        Match behavior data against all loaded Sigma rules.

        Args:
            behavior_data: Dict containing behavioral observations:
                - api_calls: List[str]
                - registry_operations: List[Dict]
                - file_operations: List[Dict]
                - network: Dict with connections, dns
                - process_tree: Dict
                - beaconing_score: float (if pre-computed)
                - domain_entropy / domain_length (if pre-computed)

        Returns:
            List of SigmaMatch objects for all matching rules
        """
        if not self._loaded:
            self.load_rules()

        matches = []
        for rule in self.rules:
            try:
                result = self._evaluate_rule(rule, behavior_data)
                if result:
                    matches.append(SigmaMatch(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        description=rule.description,
                        matched_fields=result,
                        mitre_attack_ids=rule.mitre_attack_ids,
                        mitre_tactics=rule.mitre_tactics,
                        tags=rule.tags,
                    ))
            except Exception as exc:
                logger.debug("Error evaluating rule %s: %s", rule.title, exc)

        if matches:
            logger.info(
                "Sigma: %d rules matched out of %d", len(matches), len(self.rules)
            )

        return matches

    def _evaluate_rule(
        self, rule: SigmaRule, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a single Sigma rule against behavior data."""
        detection = rule.detection
        condition = detection.get("condition", "")

        # Gather named selections
        selections = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            selections[key] = self._evaluate_selection(value, data)

        # Evaluate condition
        if not condition:
            return None

        result = self._evaluate_condition(condition, selections)
        if result:
            # Collect which fields matched
            matched = {}
            for sel_name, sel_result in selections.items():
                if sel_result:
                    matched[sel_name] = True
            return matched

        return None

    def _evaluate_selection(
        self, selection: Any, data: Dict[str, Any]
    ) -> bool:
        """Evaluate a single detection selection block."""
        if not isinstance(selection, dict):
            return False

        for field_expr, expected in selection.items():
            # Parse field name and modifier
            parts = field_expr.split("|")
            field_name = parts[0]
            modifiers = parts[1:] if len(parts) > 1 else []

            # Get actual value from behavior data
            actual = self._resolve_field(field_name, data)

            if not self._match_value(actual, expected, modifiers):
                return False

        return True

    def _resolve_field(self, field_name: str, data: Dict[str, Any]) -> Any:
        """Resolve a Sigma field name to a value in behavior data."""
        # Direct field lookup
        if field_name in data:
            return data[field_name]

        # Flatten common structures
        if field_name == "api_calls":
            calls = data.get("api_calls", [])
            if calls and isinstance(calls[0], dict):
                return [c.get("api", "") for c in calls]
            return calls

        if field_name == "registry_path":
            ops = data.get("registry_operations", [])
            return [op.get("path", "") for op in ops]

        if field_name == "file_path":
            ops = data.get("file_operations", [])
            return [op.get("path", "") for op in ops]

        if field_name == "domain_entropy":
            dns = data.get("network", {}).get("dns", [])
            if dns:
                import numpy as np
                entropies = []
                for q in dns:
                    d = q.get("query", "")
                    if d:
                        _, counts = np.unique(list(d), return_counts=True)
                        probs = counts / len(d)
                        entropies.append(-np.sum(probs * np.log2(probs + 1e-10)))
                return max(entropies) if entropies else 0
            return 0

        if field_name == "domain_length":
            dns = data.get("network", {}).get("dns", [])
            if dns:
                return max(len(q.get("query", "")) for q in dns)
            return 0

        return None

    def _match_value(
        self, actual: Any, expected: Any, modifiers: List[str]
    ) -> bool:
        """Match actual value against expected with Sigma modifiers."""
        if actual is None:
            return False

        # Handle list of expected values (OR logic within a field)
        if isinstance(expected, list):
            if "contains" in modifiers:
                return self._match_contains_list(actual, expected)
            if "endswith" in modifiers:
                return self._match_endswith_list(actual, expected)
            if "startswith" in modifiers:
                return self._match_startswith_list(actual, expected)
            # Exact match for any in list
            if isinstance(actual, list):
                return any(e in actual for e in expected)
            return actual in expected

        # Numeric comparisons
        if "gte" in modifiers:
            try:
                return float(actual) >= float(expected)
            except (ValueError, TypeError):
                return False
        if "lte" in modifiers:
            try:
                return float(actual) <= float(expected)
            except (ValueError, TypeError):
                return False

        # String modifiers
        if isinstance(actual, list):
            actual_str = " ".join(str(a) for a in actual)
        else:
            actual_str = str(actual)

        if "contains" in modifiers:
            return str(expected).lower() in actual_str.lower()
        if "startswith" in modifiers:
            return actual_str.lower().startswith(str(expected).lower())
        if "endswith" in modifiers:
            return actual_str.lower().endswith(str(expected).lower())

        # Exact match
        return str(actual) == str(expected)

    def _match_contains_list(self, actual: Any, expected_list: List) -> bool:
        """Check if actual contains ANY item from expected list (Sigma OR semantics)."""
        if isinstance(actual, list):
            # For list of actual values: any actual item contains any expected item
            return any(
                str(e).lower() in str(a).lower()
                for a in actual for e in expected_list
            )
        actual_lower = str(actual).lower()
        return any(str(e).lower() in actual_lower for e in expected_list)

    def _match_endswith_list(self, actual: Any, expected_list: List) -> bool:
        """Check if any actual item ends with any expected value."""
        if isinstance(actual, list):
            return any(
                str(a).lower().endswith(str(e).lower())
                for a in actual for e in expected_list
            )
        return any(str(actual).lower().endswith(str(e).lower()) for e in expected_list)

    def _match_startswith_list(self, actual: Any, expected_list: List) -> bool:
        """Check if any actual item starts with any expected value."""
        if isinstance(actual, list):
            return any(
                str(a).lower().startswith(str(e).lower())
                for a in actual for e in expected_list
            )
        return any(str(actual).lower().startswith(str(e).lower()) for e in expected_list)

    def _evaluate_condition(
        self, condition: str, selections: Dict[str, bool]
    ) -> bool:
        """Evaluate a Sigma condition expression."""
        condition = condition.strip()

        # Handle "1 of selection*" pattern
        of_match = re.match(r"(\d+|all)\s+of\s+(\S+)", condition)
        if of_match:
            count_str, pattern = of_match.groups()
            pattern_re = pattern.replace("*", ".*")
            matching = [
                v for k, v in selections.items()
                if re.match(pattern_re, k)
            ]
            if count_str == "all":
                return all(matching)
            return sum(1 for m in matching if m) >= int(count_str)

        # Handle "sel1 and sel2"
        if " and " in condition:
            parts = condition.split(" and ")
            return all(
                self._evaluate_condition(p.strip(), selections)
                for p in parts
            )

        # Handle "sel1 or sel2"
        if " or " in condition:
            parts = condition.split(" or ")
            return any(
                self._evaluate_condition(p.strip(), selections)
                for p in parts
            )

        # Handle "not sel"
        if condition.startswith("not "):
            inner = condition[4:].strip()
            return not self._evaluate_condition(inner, selections)

        # Direct selection name
        return selections.get(condition, False)

    # ------------------------------------------------------------------
    # Utility: convert matches to DB-ready dicts
    # ------------------------------------------------------------------

    def matches_to_behaviors(
        self, matches: List[SigmaMatch], sample_id: str
    ) -> List[Dict[str, Any]]:
        """Convert SigmaMatch list to behavior records ready for DB insert."""
        behaviors = []
        for m in matches:
            behaviors.append({
                "sample_id": sample_id,
                "behavior_type": self._infer_behavior_type(m),
                "severity": m.level,
                "description": f"[Sigma] {m.rule_title}: {m.description}",
                "sigma_rule_id": m.rule_id,
                "sigma_rule_name": m.rule_title,
                "mitre_attack_id": m.mitre_attack_ids[0] if m.mitre_attack_ids else None,
                "mitre_attack_tactic": m.mitre_tactics[0] if m.mitre_tactics else None,
                "mitre_attack_technique": m.rule_title,
                "raw_data": {
                    "matched_fields": m.matched_fields,
                    "tags": m.tags,
                },
            })
        return behaviors

    def _infer_behavior_type(self, match: SigmaMatch) -> str:
        """Infer behavior_type from Sigma tags."""
        for tactic in match.mitre_tactics:
            mapping = {
                "persistence": "persistence",
                "defense_evasion": "evasion",
                "privilege_escalation": "injection",
                "command_and_control": "c2",
                "exfiltration": "exfiltration",
                "execution": "process",
                "discovery": "process",
            }
            if tactic in mapping:
                return mapping[tactic]
        return "process"
