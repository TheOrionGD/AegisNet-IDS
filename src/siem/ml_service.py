import logging
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..model import AnomalyModel
from ..feature_engineering import FeatureEngineer
from ..config_loader import load_config

logger = logging.getLogger(__name__)

class MLService:
    """Service for real-time anomaly detection integration into the SIEM."""
    
    def __init__(self, config_path: str = 'config/config.yaml'):
        self.config = load_config(config_path)
        self.model = AnomalyModel()
        self.engineer = FeatureEngineer(window_size=self.config['feature']['window_size'])
        self.initialized = False
        self._load_resources()

    def _load_resources(self):
        try:
            model_path = self.config['paths']['model_path']
            scaler_path = self.config['paths']['scaler_path']
            
            if Path(model_path).exists() and Path(scaler_path).exists():
                self.model.load_model(model_path)
                self.engineer.scaler = joblib.load(scaler_path)
                self.initialized = True
                logger.info("ML Service initialized with pre-trained model and scaler.")
            else:
                logger.warning(f"ML resources not found at {model_path} or {scaler_path}. ML detection will be disabled.")
        except Exception as e:
            logger.error(f"Failed to initialize ML Service: {e}")

    def detect_anomaly(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check a single log entry for anomalies.
        Note: Isolation Forest works best on batches or windows. 
        For true real-time, we might need to maintain a small buffer.
        """
        if not self.initialized:
            return None
            
        try:
            # Create a temporary DataFrame for feature extraction
            # In a production setting, this would manage a rolling window
            df = pd.DataFrame([log_entry])
            if 'timestamp' not in df.columns:
                df['timestamp'] = datetime.utcnow()
            else:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
            # If payload is present, flatten it for feature extraction compatibility
            if 'raw_payload' in log_entry and isinstance(log_entry['raw_payload'], dict):
                for k, v in log_entry['raw_payload'].items():
                    df[k] = v

            # We need at least one full window for standard extract_features to work correctly
            # As a shortcut for this implementation, we simulate a feature vector if window isn't full
            # or handle it gracefully.
            features = self.engineer.extract_features(df)
            if features.empty:
                return None
                
            normalized, _ = self.engineer.normalize_features(features, fit=False)
            scores, labels = self.model.predict(normalized)
            
            is_anomaly = labels[0] == -1
            score = float(scores[0])
            
            if is_anomaly or score < self.config['threshold']['anomaly_score']:
                return {
                    "is_anomaly": True,
                    "score": score,
                    "type": "ML_ANOMALY",
                    "confidence": abs(score) * 10, # Heuristic confidence
                    "timestamp": datetime.utcnow().isoformat()
                }
        except Exception as e:
            logger.error(f"Real-time ML detection error: {e}")
            
        return None

# Singleton instance
_ml_service = None

def get_ml_service():
    global _ml_service
    if _ml_service is None:
        _ml_service = MLService()
    return _ml_service
