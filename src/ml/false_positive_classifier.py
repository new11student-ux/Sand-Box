"""
Advanced Cybersecurity Sandbox Platform
ML-based False Positive Reduction Classifier

Uses XGBoost with SHAP explainability for analyst transparency
"""

import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import numpy as np
from datetime import datetime

# ML imports
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import xgboost as xgb
import shap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FalsePositiveClassifier:
    """
    ML classifier for reducing false positives in malware analysis.

    Features:
    - API call n-grams
    - Process tree embeddings
    - Network beaconing scores
    - File operation ratios
    - Registry persistence indicators

    Outputs:
    - Malicious probability score
    - SHAP values for explainability
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        n_estimators: int = 100,
        max_depth: int = 6,
        learning_rate: float = 0.1
    ):
        self.model_path = Path(model_path) if model_path else Path("./models")
        self.model_path.mkdir(parents=True, exist_ok=True)

        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            objective="binary:logistic",
            eval_metric="auc",
            use_label_encoder=False,
            random_state=42
        )

        self.feature_names = [
            "api_call_entropy",
            "process_tree_depth",
            "network_beaconing_score",
            "file_write_ratio",
            "registry_persistence_count",
            "suspicious_api_count",
            "network_connection_count",
            "file_entropy_avg",
            "api_call_ngram_score",
            "mutex_count",
            "dropper_indicator",
            "injection_indicator",
            "c2_beaconing_indicator",
            "privilege_escalation_indicator",
            "defense_evasion_indicator"
        ]

        self.is_trained = False

    def extract_features(self, behavior_data: Dict) -> np.ndarray:
        """
        Extract features from sandbox behavior data.

        Args:
            behavior_data: Dictionary containing behavioral observations

        Returns:
            Feature vector as numpy array
        """
        features = []

        # API call entropy (randomness in API sequence)
        api_calls = behavior_data.get("api_calls", [])
        api_entropy = self._calculate_entropy(api_calls)
        features.append(api_entropy)

        # Process tree depth
        process_tree = behavior_data.get("process_tree", {})
        tree_depth = self._calculate_tree_depth(process_tree)
        features.append(tree_depth)

        # Network beaconing score (periodic connections)
        network = behavior_data.get("network", {})
        beacon_score = self._detect_beaconing(network.get("connections", []))
        features.append(beacon_score)

        # File operation ratio
        file_ops = behavior_data.get("file_operations", [])
        writes = sum(1 for op in file_ops if op.get("type") == "write")
        reads = sum(1 for op in file_ops if op.get("type") == "read")
        write_ratio = writes / (writes + reads + 1)
        features.append(write_ratio)

        # Registry persistence indicators
        registry_ops = behavior_data.get("registry_operations", [])
        persistence_keys = [
            "CurrentVersion\\Run",
            "CurrentVersion\\RunOnce",
            "Winlogon\\Shell",
            "Services"
        ]
        persistence_count = sum(
            1 for op in registry_ops
            if any(key in op.get("path", "") for key in persistence_keys)
        )
        features.append(persistence_count)

        # Suspicious API count
        suspicious_apis = {
            "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
            "CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookEx"
        }
        suspicious_count = sum(
            1 for call in api_calls
            if call.get("api", "") in suspicious_apis
        )
        features.append(suspicious_count)

        # Network connection count
        conn_count = len(network.get("connections", []))
        features.append(conn_count)

        # Average file entropy
        file_entropies = [
            op.get("entropy", 0) for op in file_ops
            if op.get("type") == "write"
        ]
        avg_entropy = np.mean(file_entropies) if file_entropies else 0
        features.append(avg_entropy)

        # API call n-gram score (simplified)
        ngram_score = self._calculate_ngram_score(api_calls)
        features.append(ngram_score)

        # Mutex count
        mutex_count = len(behavior_data.get("mutexes", []))
        features.append(mutex_count)

        # Dropper indicator
        dropper_score = self._detect_dropper(behavior_data)
        features.append(dropper_score)

        # Injection indicator
        injection_score = self._detect_injection(behavior_data)
        features.append(injection_score)

        # C2 beaconing indicator
        c2_score = self._detect_c2(network)
        features.append(c2_score)

        # Privilege escalation indicator
        priv_score = self._detect_privilege_escalation(behavior_data)
        features.append(priv_score)

        # Defense evasion indicator
        evasion_score = self._detect_evasion(behavior_data)
        features.append(evasion_score)

        return np.array(features).reshape(1, -1)

    def _calculate_entropy(self, items: List) -> float:
        """Calculate Shannon entropy of a sequence."""
        if not items:
            return 0.0

        _, counts = np.unique(items, return_counts=True)
        probabilities = counts / len(items)
        return -np.sum(probabilities * np.log2(probabilities + 1e-10))

    def _calculate_tree_depth(self, tree: Dict, depth: int = 0) -> int:
        """Calculate maximum depth of process tree."""
        if not tree:
            return depth

        children = tree.get("children", [])
        if not children:
            return depth

        return max(self._calculate_tree_depth(child, depth + 1) for child in children)

    def _detect_beaconing(self, connections: List[Dict]) -> float:
        """Detect periodic network beaconing (C2 pattern)."""
        if len(connections) < 3:
            return 0.0

        # Extract timestamps and calculate intervals
        timestamps = sorted([
            c.get("timestamp", 0) for c in connections
            if c.get("timestamp")
        ])

        if len(timestamps) < 3:
            return 0.0

        intervals = np.diff(timestamps)
        if len(intervals) < 2:
            return 0.0

        # Low variance in intervals suggests beaconing
        variance = np.var(intervals)
        mean_interval = np.mean(intervals)

        if mean_interval == 0:
            return 0.0

        # Coefficient of variation (lower = more periodic)
        cv = np.sqrt(variance) / mean_interval
        beacon_score = max(0, 1 - cv)  # Higher score = more beaconing-like

        return beacon_score

    def _calculate_ngram_score(self, api_calls: List[Dict], n: int = 3) -> float:
        """Calculate suspicious n-gram score from API call sequence."""
        if len(api_calls) < n:
            return 0.0

        # Define suspicious n-grams (simplified)
        suspicious_sequences = [
            ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
            ["InternetOpen", "InternetConnect", "HttpSendRequest"],
            ["RegOpenKey", "RegSetValue", "CreateProcess"],
        ]

        api_sequence = [call.get("api", "") for call in api_calls]

        score = 0.0
        for i in range(len(api_sequence) - n + 1):
            ngram = api_sequence[i:i + n]
            for suspicious in suspicious_sequences:
                if ngram == suspicious:
                    score += 1.0

        return min(score / 10, 1.0)  # Normalize to 0-1

    def _detect_dropper(self, behavior_data: Dict) -> float:
        """Detect dropper behavior (download + execute pattern)."""
        score = 0.0

        network = behavior_data.get("network", {})
        file_ops = behavior_data.get("file_operations", [])
        process_ops = behavior_data.get("process_operations", [])

        # Check for download
        has_download = any(
            "http" in str(conn.get("url", ""))
            for conn in network.get("connections", [])
        )

        # Check for file write in temp directory
        has_temp_write = any(
            "temp" in op.get("path", "").lower() and op.get("type") == "write"
            for op in file_ops
        )

        # Check for process creation after download
        has_execute = len(process_ops) > 0

        if has_download and has_temp_write and has_execute:
            score += 0.5

        # Check for PE file write
        pe_extensions = [".exe", ".dll", ".scr"]
        has_pe_write = any(
            any(op.get("path", "").lower().endswith(ext) for ext in pe_extensions)
            and op.get("type") == "write"
            for op in file_ops
        )

        if has_pe_write:
            score += 0.5

        return score

    def _detect_injection(self, behavior_data: Dict) -> float:
        """Detect code injection patterns."""
        score = 0.0

        api_calls = behavior_data.get("api_calls", [])
        suspicious_injection_apis = {
            "VirtualAllocEx": 0.2,
            "WriteProcessMemory": 0.2,
            "CreateRemoteThread": 0.3,
            "NtMapViewOfSection": 0.2,
            "SetWindowsHookExA": 0.1,
            "QueueUserAPC": 0.2,
        }

        for call in api_calls:
            api_name = call.get("api", "")
            if api_name in suspicious_injection_apis:
                score += suspicious_injection_apis[api_name]

        return min(score, 1.0)

    def _detect_c2(self, network: Dict) -> float:
        """Detect command and control communication patterns."""
        score = 0.0

        connections = network.get("connections", [])
        dns_queries = network.get("dns", [])

        # Check for DGA-like domains
        for query in dns_queries:
            domain = query.get("query", "")
            if domain:
                # Long random-looking domains
                if len(domain) > 20 and self._calculate_entropy(list(domain)) > 3.5:
                    score += 0.3

        # Check for unusual ports
        unusual_ports = {4444, 5555, 6666, 8080, 8443, 9999}
        for conn in connections:
            port = conn.get("port", 0)
            if port in unusual_ports:
                score += 0.2

        # Check for HTTPS to IP (no domain)
        for conn in connections:
            if conn.get("port") == 443:
                host = conn.get("host", "")
                if self._is_ip_address(host):
                    score += 0.3

        return min(score, 1.0)

    def _detect_privilege_escalation(self, behavior_data: Dict) -> float:
        """Detect privilege escalation attempts."""
        score = 0.0

        api_calls = behavior_data.get("api_calls", [])
        priv_apis = {
            "OpenProcessToken": 0.1,
            "LookupPrivilegeValue": 0.2,
            "AdjustTokenPrivileges": 0.3,
            "ImpersonateLoggedOnUser": 0.2,
            "DuplicateToken": 0.2,
        }

        for call in api_calls:
            api_name = call.get("api", "")
            if api_name in priv_apis:
                score += priv_apis[api_name]

        return min(score, 1.0)

    def _detect_evasion(self, behavior_data: Dict) -> float:
        """Detect sandbox/VM evasion techniques."""
        score = 0.0

        api_calls = behavior_data.get("api_calls", [])
        evasion_patterns = {
            "IsDebuggerPresent": 0.2,
            "CheckRemoteDebuggerPresent": 0.2,
            "NtQueryInformationProcess": 0.1,
            "GetTickCount": 0.1,  # Timing check
            "QueryPerformanceCounter": 0.1,  # Timing check
        }

        for call in api_calls:
            api_name = call.get("api", "")
            if api_name in evasion_patterns:
                score += evasion_patterns[api_name]

        # Check for sleep/skip behavior
        process_ops = behavior_data.get("process_operations", [])
        has_long_sleep = any(
            op.get("sleep_duration", 0) > 60000  # > 1 minute
            for op in process_ops
        )
        if has_long_sleep:
            score += 0.3

        return min(score, 1.0)

    def _is_ip_address(self, host: str) -> bool:
        """Check if string is an IP address."""
        parts = host.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        eval_set: Optional[Tuple[np.ndarray, np.ndarray]] = None
    ):
        """
        Train the classifier.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (0 = benign, 1 = malicious)
            eval_set: Optional evaluation set for early stopping
        """
        if eval_set:
            eval_metric = [(X, y), eval_set]
        else:
            eval_metric = None

        self.model.fit(
            X, y,
            eval_set=eval_metric,
            verbose=True,
            early_stopping_rounds=10 if eval_set else None
        )

        self.is_trained = True
        self.save()

        logger.info("Model training completed")

    def predict(self, behavior_data: Dict) -> Tuple[bool, float, Dict]:
        """
        Predict whether sample is malicious.

        Args:
            behavior_data: Behavioral observations

        Returns:
            Tuple of (is_malicious, confidence, explanation)
        """
        if not self.is_trained:
            self.load()

        features = self.extract_features(behavior_data)

        # Get prediction and probability
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0, 1]

        # Get SHAP values for explainability
        explainer = shap.TreeExplainer(self.model)
        shap_values = explainer.shap_values(features)

        explanation = {
            "malicious_probability": float(probability),
            "feature_contributions": {},
            "top_features": []
        }

        # Get top contributing features
        feature_importance = list(zip(
            self.feature_names,
            shap_values[0] if len(shap_values.shape) > 1 else shap_values
        ))
        feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)

        for name, value in feature_importance[:5]:
            explanation["feature_contributions"][name] = float(value)
            explanation["top_features"].append({
                "feature": name,
                "contribution": float(value)
            })

        return bool(prediction), float(probability), explanation

    def save(self):
        """Save model to disk."""
        model_file = self.model_path / "false_positive_classifier.json"
        self.model.save_model(str(model_file))
        logger.info(f"Model saved to {model_file}")

    def load(self):
        """Load model from disk."""
        model_file = self.model_path / "false_positive_classifier.json"
        if model_file.exists():
            self.model.load_model(str(model_file))
            self.is_trained = True
            logger.info(f"Model loaded from {model_file}")
        else:
            logger.warning("No saved model found, model needs training")


def train_from_dataset(dataset_path: str):
    """
    Train classifier from dataset.

    Expected dataset format (CSV):
    - api_call_entropy, process_tree_depth, network_beaconing_score, ...
    - label (0 = benign, 1 = malicious)
    """
    logger.info(f"Loading training data from {dataset_path}")

    df = pd.read_csv(dataset_path)

    # Separate features and labels
    feature_cols = [
        "api_call_entropy", "process_tree_depth", "network_beaconing_score",
        "file_write_ratio", "registry_persistence_count", "suspicious_api_count",
        "network_connection_count", "file_entropy_avg", "api_call_ngram_score",
        "mutex_count", "dropper_indicator", "injection_indicator",
        "c2_beaconing_indicator", "privilege_escalation_indicator",
        "defense_evasion_indicator"
    ]

    X = df[feature_cols].values
    y = df["label"].values

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Create and train model
    classifier = FalsePositiveClassifier()
    classifier.train(X_train, y_train, eval_set=(X_test, y_test))

    # Evaluate
    y_pred = classifier.model.predict(X_test)
    y_proba = classifier.model.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 50)
    print("MODEL EVALUATION")
    print("=" * 50)
    print(f"\nClassification Report:\n{classification_report(y_test, y_pred)}")
    print(f"\nConfusion Matrix:\n{confusion_matrix(y_test, y_pred)}")
    print(f"\nROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}")

    return classifier


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # Train from dataset
        dataset_path = sys.argv[1]
        train_from_dataset(dataset_path)
    else:
        # Demo with sample data
        print("Usage: python false_positive_classifier.py <dataset.csv>")
        print("\nNo dataset provided. Run with EMBER dataset or CAPEv2 logs.")
