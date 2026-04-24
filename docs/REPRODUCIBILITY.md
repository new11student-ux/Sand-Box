# Reproducibility Guide

## Academic Rigor & Verification

To reproduce the Phase 2 Machine Learning results for the graduation thesis, follow these steps:

### 1. Environment Setup
```bash
git checkout phase-2-final
pip install -r requirements.txt
pip install pytest pandas scikit-learn shap xgboost
```

### 2. Dataset Provenance
- **Malware Samples**: MalwareBazaar (2024-Q4), filtered by tags: `rat`, `trojan`, `ransomware`.
- **Benign Samples**: Compiled binaries from GitHub repositories with >1000 stars (e.g., portable tools, developer utilities).
- The raw dataset is expected to be located in `data/raw_samples.csv`.

### 3. Running the Benchmark
```bash
# This will train the model and output the classification report, confusion matrix, and ROC AUC
python src/ml/false_positive_classifier.py data/benchmark_dataset.csv
```

### 4. Running Academic Validity Tests
```bash
# This tests SHAP explanation consistency and evasion resistance impact
pytest tests/test_research_validity.py -v
```

### 5. Expected Output Metrics
When run against the `benchmark_dataset.csv` (10,000 samples, 50% split), the expected metrics are:
- `evasion_detection_rate`: > 0.85
- `false_positive_rate`: < 0.05
- `shap_explanation_consistency` (Jaccard similarity): > 0.70
