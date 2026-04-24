import yaml
import re
import logging
from typing import List, Dict, Any
from pathlib import Path
from .schemas import MitreTagResult

logger = logging.getLogger(__name__)

class MitreTagger:
    """Heuristic engine that maps raw behavioral telemetry to MITRE ATT&CK techniques."""
    
    def __init__(self, rules_path: str = "src/config/mitre_rules.yaml"):
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str) -> List[Dict[str, Any]]:
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or []
        except Exception as e:
            logger.error(f"Failed to load MITRE rules from {path}: {e}")
            return []

    def analyze(self, behaviors: List[Dict[str, Any]]) -> List[MitreTagResult]:
        """Analyze a list of behavioral events and return matching MITRE tags."""
        tags = []
        
        for rule in self.rules:
            # Simple heuristic matching simulation
            # In a real engine, this would evaluate complex logic (state machines, windows)
            matched_conditions = []
            
            for condition in rule.get("conditions", []):
                field = condition.get("field")
                pattern = condition.get("pattern")
                
                # Check if any behavior matches this condition
                for behavior in behaviors:
                    val = behavior.get(field, "")
                    if pattern and val and re.search(pattern, str(val), re.IGNORECASE):
                        matched_conditions.append(f"Matched {field} ~ {pattern}")
                        break
            
            # If all conditions for a rule matched, we trigger the tag
            if matched_conditions and len(matched_conditions) == len(rule.get("conditions", [])):
                tags.append(MitreTagResult(
                    technique_id=rule["technique_id"],
                    technique_name=rule["name"],
                    confidence=rule["confidence"],
                    matched_conditions=matched_conditions,
                    evidence={"triggering_behaviors": len(matched_conditions)}
                ))
                
        return tags
