import joblib
import logging
from pathlib import Path
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class AnomalyModel:
    """Isolation Forest model wrapper for anomaly detection."""

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None

    def train(self, X):
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state
        )
        self.model.fit(X)
        logger.info('Anomaly detection model trained.')

    def predict(self, X):
        if self.model is None:
            raise ValueError('Model has not been loaded or trained.')
        scores = self.model.decision_function(X)
        labels = self.model.predict(X)
        return scores, labels

    def save_model(self, path: str):
        if self.model is None:
            raise ValueError('Model has not been trained.')
        path_obj = Path(path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path_obj)
        logger.info(f'Model saved to {path_obj}')

    def load_model(self, path: str):
        path_obj = Path(path)
        if not path_obj.exists():
            raise FileNotFoundError(f'Model file does not exist: {path_obj}')
        self.model = joblib.load(path_obj)
        logger.info(f'Model loaded from {path_obj}')