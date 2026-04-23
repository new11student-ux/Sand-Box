"""
Advanced Cybersecurity Sandbox Platform
ML Training Data Generator

Generates synthetic training data for the FalsePositiveClassifier.
Produces labeled feature vectors matching the classifier's 15-feature schema.

Features:
  1. api_call_entropy         8. file_entropy_avg
  2. process_tree_depth       9. api_call_ngram_score
  3. network_beaconing_score  10. mutex_count
  4. file_write_ratio         11. dropper_indicator
  5. registry_persistence_count 12. injection_indicator
  6. suspicious_api_count     13. c2_beaconing_indicator
  7. network_connection_count 14. privilege_escalation_indicator
                              15. defense_evasion_indicator
"""

import csv
import logging
import random
from pathlib import Path
from typing import List, Tuple, Optional

import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FEATURE_NAMES = [
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
    "defense_evasion_indicator",
]


def _generate_malicious_sample(subtype: str = "generic") -> List[float]:
    """Generate a single malicious feature vector."""
    if subtype == "injection":
        return [
            round(random.uniform(3.0, 5.5), 3),     # api_call_entropy (high)
            random.randint(3, 8),                     # process_tree_depth (deep)
            round(random.uniform(0.0, 0.4), 3),       # beaconing (low-mid)
            round(random.uniform(0.1, 0.4), 3),       # file_write_ratio
            random.randint(0, 2),                      # registry_persistence
            random.randint(5, 20),                     # suspicious_api_count (high)
            random.randint(2, 15),                     # network_connections
            round(random.uniform(4.0, 7.5), 3),       # file_entropy_avg
            round(random.uniform(0.3, 1.0), 3),       # ngram_score (high)
            random.randint(1, 5),                      # mutex_count
            round(random.uniform(0.0, 0.3), 3),       # dropper
            round(random.uniform(0.6, 1.0), 3),       # injection (HIGH)
            round(random.uniform(0.0, 0.3), 3),       # c2
            round(random.uniform(0.0, 0.4), 3),       # privesc
            round(random.uniform(0.0, 0.3), 3),       # evasion
        ]
    elif subtype == "c2":
        return [
            round(random.uniform(2.5, 4.5), 3),
            random.randint(2, 5),
            round(random.uniform(0.6, 1.0), 3),       # beaconing (HIGH)
            round(random.uniform(0.1, 0.3), 3),
            random.randint(0, 1),
            random.randint(2, 10),
            random.randint(10, 50),                    # many connections
            round(random.uniform(3.0, 6.0), 3),
            round(random.uniform(0.1, 0.5), 3),
            random.randint(1, 3),
            round(random.uniform(0.0, 0.2), 3),
            round(random.uniform(0.0, 0.3), 3),
            round(random.uniform(0.6, 1.0), 3),       # c2 (HIGH)
            round(random.uniform(0.0, 0.2), 3),
            round(random.uniform(0.1, 0.5), 3),
        ]
    elif subtype == "dropper":
        return [
            round(random.uniform(2.0, 4.0), 3),
            random.randint(2, 6),
            round(random.uniform(0.1, 0.5), 3),
            round(random.uniform(0.5, 0.9), 3),       # high write ratio
            random.randint(1, 5),                      # persistence
            random.randint(3, 12),
            random.randint(3, 20),
            round(random.uniform(5.0, 7.8), 3),       # high entropy files
            round(random.uniform(0.2, 0.7), 3),
            random.randint(0, 3),
            round(random.uniform(0.6, 1.0), 3),       # dropper (HIGH)
            round(random.uniform(0.0, 0.3), 3),
            round(random.uniform(0.1, 0.5), 3),
            round(random.uniform(0.0, 0.2), 3),
            round(random.uniform(0.0, 0.3), 3),
        ]
    elif subtype == "evasion":
        return [
            round(random.uniform(1.5, 3.5), 3),
            random.randint(1, 4),
            round(random.uniform(0.0, 0.3), 3),
            round(random.uniform(0.0, 0.2), 3),
            random.randint(0, 1),
            random.randint(4, 15),
            random.randint(0, 5),
            round(random.uniform(2.0, 5.0), 3),
            round(random.uniform(0.0, 0.3), 3),
            random.randint(0, 2),
            round(random.uniform(0.0, 0.2), 3),
            round(random.uniform(0.0, 0.2), 3),
            round(random.uniform(0.0, 0.2), 3),
            round(random.uniform(0.0, 0.3), 3),
            round(random.uniform(0.6, 1.0), 3),       # evasion (HIGH)
        ]
    else:  # generic malicious
        return [
            round(random.uniform(2.5, 5.0), 3),
            random.randint(2, 7),
            round(random.uniform(0.2, 0.8), 3),
            round(random.uniform(0.2, 0.7), 3),
            random.randint(1, 4),
            random.randint(4, 18),
            random.randint(5, 30),
            round(random.uniform(3.5, 7.0), 3),
            round(random.uniform(0.2, 0.8), 3),
            random.randint(1, 5),
            round(random.uniform(0.2, 0.7), 3),
            round(random.uniform(0.2, 0.7), 3),
            round(random.uniform(0.2, 0.7), 3),
            round(random.uniform(0.1, 0.5), 3),
            round(random.uniform(0.1, 0.5), 3),
        ]


def _generate_benign_sample() -> List[float]:
    """Generate a single benign feature vector."""
    return [
        round(random.uniform(0.5, 2.5), 3),       # low entropy
        random.randint(1, 3),                       # shallow tree
        round(random.uniform(0.0, 0.15), 3),       # no beaconing
        round(random.uniform(0.0, 0.15), 3),       # low write ratio
        0,                                          # no persistence
        random.randint(0, 2),                       # few suspicious APIs
        random.randint(0, 5),                       # few connections
        round(random.uniform(0.0, 3.0), 3),         # low file entropy
        round(random.uniform(0.0, 0.1), 3),         # no suspicious ngrams
        random.randint(0, 1),                       # few mutexes
        round(random.uniform(0.0, 0.1), 3),         # no dropper
        round(random.uniform(0.0, 0.1), 3),         # no injection
        round(random.uniform(0.0, 0.1), 3),         # no c2
        round(random.uniform(0.0, 0.1), 3),         # no privesc
        round(random.uniform(0.0, 0.1), 3),         # no evasion
    ]


def generate_training_data(
    n_samples: int = 5000,
    malicious_ratio: float = 0.4,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data.

    Args:
        n_samples: Total number of samples
        malicious_ratio: Fraction that are malicious (0.0-1.0)
        seed: Random seed for reproducibility

    Returns:
        (X, y) where X is feature matrix and y is label vector
    """
    random.seed(seed)
    np.random.seed(seed)

    n_malicious = int(n_samples * malicious_ratio)
    n_benign = n_samples - n_malicious

    subtypes = ["injection", "c2", "dropper", "evasion", "generic"]
    per_subtype = n_malicious // len(subtypes)
    remainder = n_malicious - per_subtype * len(subtypes)

    features = []
    labels = []

    # Generate malicious samples
    for i, subtype in enumerate(subtypes):
        count = per_subtype + (1 if i < remainder else 0)
        for _ in range(count):
            features.append(_generate_malicious_sample(subtype))
            labels.append(1)

    # Generate benign samples
    for _ in range(n_benign):
        features.append(_generate_benign_sample())
        labels.append(0)

    X = np.array(features)
    y = np.array(labels)

    # Shuffle
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]

    logger.info(
        "Generated %d samples: %d malicious (%.1f%%), %d benign (%.1f%%)",
        n_samples, n_malicious, malicious_ratio * 100,
        n_benign, (1 - malicious_ratio) * 100,
    )

    return X, y


def save_to_csv(
    X: np.ndarray, y: np.ndarray, output_path: str = "./storage/training_data.csv"
) -> Path:
    """Save training data to CSV file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["label"])
        for i in range(len(X)):
            writer.writerow(list(X[i]) + [int(y[i])])

    logger.info("Saved training data to %s (%d rows)", path, len(X))
    return path


if __name__ == "__main__":
    X, y = generate_training_data(n_samples=5000)
    save_to_csv(X, y)
    print(f"Generated {len(X)} samples. Malicious: {sum(y)}, Benign: {len(y) - sum(y)}")
