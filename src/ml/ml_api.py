"""
Advanced Cybersecurity Sandbox Platform
ML Model Serving API

Endpoints for prediction, training, status, and analyst feedback.
Designed to be mounted on the main FastAPI app or run standalone.
"""

import logging
import os
import json
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import numpy as np

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Pydantic Models
# ============================================================================

class PredictionRequest(BaseModel):
    """Request body for ML prediction."""
    behavior_data: Dict[str, Any] = Field(
        ..., description="Behavioral observations from sandbox analysis"
    )
    sample_id: Optional[str] = Field(None, description="Sample ID for correlation")


class PredictionResponse(BaseModel):
    """Response from ML prediction."""
    is_malicious: bool
    confidence: float
    verdict: str
    top_features: List[Dict[str, Any]]
    model_version: str
    prediction_time_ms: float


class TrainingRequest(BaseModel):
    """Request to trigger model retraining."""
    dataset_path: Optional[str] = Field(None, description="Path to CSV training data")
    n_synthetic: int = Field(5000, description="Number of synthetic samples if no dataset")
    malicious_ratio: float = Field(0.4, ge=0.1, le=0.9)


class TrainingResponse(BaseModel):
    """Response from model training."""
    status: str
    samples_trained: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    model_version: str


class FeedbackRequest(BaseModel):
    """Analyst feedback for model improvement."""
    sample_id: str
    predicted_verdict: str
    actual_verdict: str
    analyst_notes: Optional[str] = None


class ModelStatusResponse(BaseModel):
    """Model status information."""
    model_loaded: bool
    model_version: str
    feature_count: int
    feature_names: List[str]
    last_trained: Optional[str] = None
    total_predictions: int
    feedback_count: int


# ============================================================================
# ML API Application
# ============================================================================

app = FastAPI(
    title="Sandbox ML API",
    description="Machine Learning model serving for malware classification",
    version="1.0.0",
)

# In-memory state
_classifier = None
_model_version = "1.0.0-untrained"
_last_trained = None
_prediction_count = 0
_feedback_store: List[Dict] = []


def _get_classifier():
    """Lazily load the classifier."""
    global _classifier
    if _classifier is None:
        from src.ml.false_positive_classifier import FalsePositiveClassifier
        _classifier = FalsePositiveClassifier()
        try:
            _classifier.load()
            logger.info("ML classifier loaded from disk")
        except Exception:
            logger.info("No saved ML model found, needs training")
    return _classifier


@app.post("/api/v1/ml/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """
    Predict whether behavior data indicates malicious activity.
    Returns verdict, confidence, and SHAP feature explanations.
    """
    global _prediction_count

    classifier = _get_classifier()
    if not classifier.is_trained:
        raise HTTPException(
            status_code=503,
            detail="Model not trained. Call POST /api/v1/ml/train first."
        )

    import time
    start = time.time()

    try:
        is_malicious, confidence, explanation = classifier.predict(request.behavior_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")

    elapsed_ms = (time.time() - start) * 1000
    _prediction_count += 1

    verdict = "malicious" if is_malicious else "benign"
    if not is_malicious and confidence > 0.3:
        verdict = "suspicious"

    return PredictionResponse(
        is_malicious=is_malicious,
        confidence=round(confidence, 4),
        verdict=verdict,
        top_features=explanation.get("top_features", []),
        model_version=_model_version,
        prediction_time_ms=round(elapsed_ms, 2),
    )


@app.post("/api/v1/ml/train", response_model=TrainingResponse)
async def train_model(request: TrainingRequest):
    """
    Train the ML classifier. Uses synthetic data if no dataset provided.
    """
    global _classifier, _model_version, _last_trained

    from src.ml.training_data_generator import generate_training_data, save_to_csv, FEATURE_NAMES
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score,
    )

    # Generate or load data
    if request.dataset_path:
        import pandas as pd
        df = pd.read_csv(request.dataset_path)
        X = df[FEATURE_NAMES].values
        y = df["label"].values
    else:
        X, y = generate_training_data(
            n_samples=request.n_synthetic,
            malicious_ratio=request.malicious_ratio,
        )
        save_to_csv(X, y)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train
    from src.ml.false_positive_classifier import FalsePositiveClassifier
    classifier = FalsePositiveClassifier()
    classifier.train(X_train, y_train, eval_set=(X_test, y_test))

    # Evaluate
    y_pred = classifier.model.predict(X_test)
    y_proba = classifier.model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)

    _classifier = classifier
    _model_version = f"1.0.0-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"
    _last_trained = datetime.now(timezone.utc).isoformat()

    logger.info(
        "Model trained: accuracy=%.4f precision=%.4f recall=%.4f f1=%.4f auc=%.4f",
        accuracy, precision, recall, f1, auc,
    )

    return TrainingResponse(
        status="trained",
        samples_trained=len(X_train),
        accuracy=round(accuracy, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        auc_roc=round(auc, 4),
        model_version=_model_version,
    )


@app.get("/api/v1/ml/status", response_model=ModelStatusResponse)
async def model_status():
    """Get current model status and metrics."""
    classifier = _get_classifier()
    return ModelStatusResponse(
        model_loaded=classifier.is_trained,
        model_version=_model_version,
        feature_count=len(classifier.feature_names),
        feature_names=classifier.feature_names,
        last_trained=_last_trained,
        total_predictions=_prediction_count,
        feedback_count=len(_feedback_store),
    )


@app.post("/api/v1/ml/feedback")
async def submit_feedback(request: FeedbackRequest):
    """Submit analyst feedback for model improvement."""
    feedback = {
        "sample_id": request.sample_id,
        "predicted_verdict": request.predicted_verdict,
        "actual_verdict": request.actual_verdict,
        "analyst_notes": request.analyst_notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _feedback_store.append(feedback)
    logger.info("Feedback received for sample %s: predicted=%s actual=%s",
                request.sample_id, request.predicted_verdict, request.actual_verdict)
    return {
        "status": "recorded",
        "feedback_id": len(_feedback_store),
        "total_feedback": len(_feedback_store),
    }
