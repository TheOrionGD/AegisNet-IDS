import logging
import numpy as np
import pandas as pd
import datetime
from datetime import timezone
from pathlib import Path
from typing import Dict, Any, Optional
from ml_services.model import AnomalyModel
from ml_services.feature_engineering import FeatureEngineer
from config_loader import load_config

logger = logging.getLogger(__name__)

_MODELS_PATH = Path(__file__).resolve().parents[2] / "models"


class MLEngine:
    """
    ML Anomaly Detection Engine for CNS.
    Wraps Isolation Forest to provide real-time anomaly scores for incoming events.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = load_config(config_path)
        self.model = AnomalyModel()
        scaler_path = str(_MODELS_PATH / "scaler.joblib")
        self.engineer = FeatureEngineer(window_size="1min", scaler_path=scaler_path)
        self.initialized = False
        self._load_model()

    def _load_model(self):
        try:
            model_path = (
                Path(__file__).resolve().parents[2]
                / "models"
                / "isolation_forest.joblib"
            )
            self.model.load_model(str(model_path))
            self.initialized = True
            logger.info(
                f"ML Engine successfully initialized with pre-trained model: {model_path}"
            )
        except Exception as e:
            logger.warning(
                f"ML Engine could not load pre-trained model: {e}. Running in zero-shot/disabled mode."
            )

    def run_inference(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from a single event and return an anomaly score.
        If the model isn't initialized, returns a default neutral score.
        """
        if not self.initialized:
            return {"anomaly_score": 0.0, "is_anomaly": False}

        try:
            # Prepare minimal dataframe for feature engineering
            df = pd.DataFrame([event])
            if "timestamp" not in df.columns:
                df["timestamp"] = datetime.datetime.now(timezone.utc)
            else:
                df["timestamp"] = pd.to_datetime(df["timestamp"])

            # Heuristic feature extraction for single event (simplified for real-time)
            # In a full impl, we'd use a rolling buffer of 60s
            features = self.engineer.extract_features(df)
            if features.empty:
                # Fallback to direct mapping if window aggregation fails on single row
                return {"anomaly_score": 0.1, "is_anomaly": False}

            normalized, _ = self.engineer.normalize_features(features, fit=False)
            scores, labels = self.model.predict(normalized)

            # Normalize Isolation Forest decision_function (lower is more anomalous)
            # decision_function output is roughly in [-0.5, 0.5]
            raw_score = float(scores[0])
            # Scale to [0, 1] where 1 is HIGH anomaly
            normalized_score = 1.0 - (raw_score + 0.5)
            normalized_score = max(0.0, min(1.0, normalized_score))

            return {
                "anomaly_score": round(normalized_score, 3),
                "is_anomaly": labels[0] == -1,
            }
        except Exception as e:
            logger.error(f"Inference error: {e}")
            return {"anomaly_score": 0.0, "is_anomaly": False}


# Global instance
ml_engine = MLEngine()
