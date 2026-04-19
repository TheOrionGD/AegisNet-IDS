import logging
import numpy as np
import pandas as pd
import joblib
import datetime
from datetime import timezone
from typing import Dict, Any, List, Optional
from collections import deque
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_MODELS_DIR = _PROJECT_ROOT / "models"


class RealtimeMLEngine:
    """
    Real-time ML inference engine for anomaly detection.
    Uses pre-trained Isolation Forest model with sliding window features.
    """

    FEATURE_COLUMNS = [
        "pkt_len_count",
        "pkt_len_mean",
        "pkt_len_max",
        "pkt_len_min",
        "pkt_len_std",
        "src_port_nunique",
        "dst_port_nunique",
        "src_ip_nunique",
        "dst_ip_nunique",
        "protocol_TCP_count",
        "protocol_UDP_count",
        "protocol_ICMP_count",
        "packet_rate",
        "mean_time_diff",
        "internal_packets",
        "internal_ratio",
        "dst_ip_entropy",
        "packet_rate_lag_1",
        "packet_rate_change",
    ]

    def __init__(
        self,
        model_path: str = str(_MODELS_DIR / "isolation_forest.joblib"),
        scaler_path: str = str(_MODELS_DIR / "scaler.joblib"),
        threshold: float = 0.5,
        window_size: int = 60,
    ):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.threshold = threshold
        self.window_size = window_size
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._event_buffer: deque = deque(maxlen=window_size)
        self._initialized = False

    def load_models(self) -> bool:
        """Load the trained model and scaler."""
        try:
            self.model = joblib.load(self.model_path)
            logger.info(f"Model loaded: {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = None

        try:
            self.scaler = joblib.load(self.scaler_path)
            logger.info(f"Scaler loaded: {self.scaler_path}")
        except Exception as e:
            logger.warning(f"Scaler not found, using fitted scaler: {e}")
            self.scaler = StandardScaler()

        self._initialized = self.model is not None
        return self._initialized

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal."""
        if not ip:
            return False
        return (
            ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.")
            and len(ip.split(".")) == 4
            and 16 <= int(ip.split(".")[1]) <= 31
        )

    def _extract_features_from_buffer(self) -> pd.DataFrame:
        """Extract features from the sliding window buffer."""
        if not self._event_buffer:
            return pd.DataFrame()

        events = list(self._event_buffer)
        df = pd.DataFrame(events)

        if "timestamp" not in df.columns:
            df["timestamp"] = datetime.datetime.now(timezone.utc)
        else:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        if df["timestamp"].isna().all():
            df["timestamp"] = datetime.datetime.now(timezone.utc)

        df = df.sort_values("timestamp")
        df["protocol"] = df.get("protocol", "TCP").fillna("TCP").str.upper()
        df["pkt_len"] = df.get("pkt_len", 0).fillna(0).astype(int)
        df["src_port"] = df.get("src_port", 0).fillna(0).astype(int)
        df["dst_port"] = df.get("dst_port", 0).fillna(0).astype(int)
        df["src_ip"] = df.get("src_ip", "0.0.0.0").fillna("0.0.0.0").astype(str)
        df["dst_ip"] = df.get("dst_ip", "0.0.0.0").fillna("0.0.0.0").astype(str)

        features = {}
        features["pkt_len_count"] = len(df)
        features["pkt_len_mean"] = df["pkt_len"].mean()
        features["pkt_len_max"] = df["pkt_len"].max()
        features["pkt_len_min"] = df["pkt_len"].min()
        features["pkt_len_std"] = df["pkt_len"].std() if len(df) > 1 else 0

        features["src_port_nunique"] = df["src_port"].nunique()
        features["dst_port_nunique"] = df["dst_port"].nunique()
        features["src_ip_nunique"] = df["src_ip"].nunique()
        features["dst_ip_nunique"] = df["dst_ip"].nunique()

        protocol_counts = df["protocol"].value_counts()
        features["protocol_TCP_count"] = protocol_counts.get("TCP", 0)
        features["protocol_UDP_count"] = protocol_counts.get("UDP", 0)
        features["protocol_ICMP_count"] = protocol_counts.get("ICMP", 0)

        time_range = (
            (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
            if len(df) > 1
            else 1
        )
        features["packet_rate"] = len(df) / max(time_range, 1)

        if len(df) > 1:
            time_diffs = df["timestamp"].diff().dt.total_seconds().dropna()
            features["mean_time_diff"] = time_diffs.mean() if len(time_diffs) > 0 else 0
        else:
            features["mean_time_diff"] = 0

        internal_count = df["src_ip"].apply(self._is_internal_ip).sum()
        features["internal_packets"] = internal_count
        features["internal_ratio"] = internal_count / max(len(df), 1)

        dst_ip_counts = df["dst_ip"].value_counts()
        if len(dst_ip_counts) > 1:
            probs = dst_ip_counts / dst_ip_counts.sum()
            features["dst_ip_entropy"] = -np.sum(probs * np.log(probs + 1e-10))
        else:
            features["dst_ip_entropy"] = 0

        features["packet_rate_lag_1"] = features["packet_rate"]
        features["packet_rate_change"] = 0

        feature_df = pd.DataFrame([features])
        for col in self.FEATURE_COLUMNS:
            if col not in feature_df.columns:
                feature_df[col] = 0

        feature_df = feature_df[self.FEATURE_COLUMNS].fillna(0)
        return feature_df

    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the sliding window buffer."""
        self._event_buffer.append(event)

    def predict(self, event: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run inference on the current buffer or a single event.
        Returns anomaly score and classification.
        """
        if not self._initialized:
            if not self.load_models():
                return {
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "risk_level": "UNKNOWN",
                    "error": "Model not loaded",
                }

        if event:
            self.add_event(event)

        if len(self._event_buffer) < 1:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "risk_level": "LOW",
            }

        try:
            features = self._extract_features_from_buffer()
            if features.empty:
                return {
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "risk_level": "LOW",
                }

            if self.scaler and hasattr(self.scaler, "mean_"):
                try:
                    features_scaled = self.scaler.transform(features)
                except Exception:
                    features_scaled = features.values
            else:
                features_scaled = features.values

            decision = self.model.decision_function(features_scaled)[0]
            raw_score = float(decision)

            normalized_score = 1.0 - (raw_score + 0.5)
            normalized_score = max(0.0, min(1.0, normalized_score))

            is_anomaly = normalized_score >= self.threshold

            risk_level = "LOW"
            if normalized_score >= 0.8:
                risk_level = "CRITICAL"
            elif normalized_score >= 0.7:
                risk_level = "HIGH"
            elif normalized_score >= 0.5:
                risk_level = "MEDIUM"

            return {
                "anomaly_score": round(normalized_score, 3),
                "is_anomaly": is_anomaly,
                "risk_level": risk_level,
                "raw_decision": round(raw_score, 3),
                "events_in_window": len(self._event_buffer),
            }

        except Exception as e:
            logger.error(f"Inference error: {e}")
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "risk_level": "ERROR",
                "error": str(e),
            }

    def predict_single(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference on a single event using heuristic features.
        Optimized for <1 second latency.
        """
        if not self._initialized:
            if not self.load_models():
                return {
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "risk_level": "UNKNOWN",
                }

        try:
            features = self._extract_realtime_features(event)
            if features.empty:
                return {
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "risk_level": "LOW",
                }

            if self.scaler and hasattr(self.scaler, "mean_"):
                try:
                    features_scaled = self.scaler.transform(features)
                except Exception:
                    features_scaled = features.values
            else:
                features_scaled = features.values

            decision = self.model.decision_function(features_scaled)[0]
            raw_score = float(decision)

            normalized_score = 1.0 - (raw_score + 0.5)
            normalized_score = max(0.0, min(1.0, normalized_score))

            is_anomaly = normalized_score >= self.threshold

            risk_level = "LOW"
            if normalized_score >= 0.8:
                risk_level = "CRITICAL"
            elif normalized_score >= 0.7:
                risk_level = "HIGH"
            elif normalized_score >= 0.5:
                risk_level = "MEDIUM"

            return {
                "anomaly_score": round(normalized_score, 3),
                "is_anomaly": is_anomaly,
                "risk_level": risk_level,
                "raw_decision": round(raw_score, 3),
            }

        except Exception as e:
            logger.error(f"Single event inference error: {e}")
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "error": str(e),
            }

    def _extract_realtime_features(self, event: Dict[str, Any]) -> pd.DataFrame:
        """Extract features for single event with defaults."""
        features_dict = {
            "pkt_len_count": 1,
            "pkt_len_mean": event.get("pkt_len", 0),
            "pkt_len_max": event.get("pkt_len", 0),
            "pkt_len_min": event.get("pkt_len", 0),
            "pkt_len_std": 0,
            "src_port_nunique": 1,
            "dst_port_nunique": 1,
            "src_ip_nunique": 1,
            "dst_ip_nunique": 1,
            "protocol_TCP_count": 1 if event.get("protocol") == "TCP" else 0,
            "protocol_UDP_count": 1 if event.get("protocol") == "UDP" else 0,
            "protocol_ICMP_count": 1 if event.get("protocol") == "ICMP" else 0,
            "packet_rate": 1.0,
            "mean_time_diff": 0,
            "internal_packets": 1
            if self._is_internal_ip(event.get("src_ip", ""))
            else 0,
            "internal_ratio": 1.0,
            "dst_ip_entropy": 0,
            "packet_rate_lag_1": 1.0,
            "packet_rate_change": 0,
        }

        feature_df = pd.DataFrame([features_dict])
        feature_df = feature_df[self.FEATURE_COLUMNS].fillna(0)
        return feature_df

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "initialized": self._initialized,
            "buffer_size": len(self._event_buffer),
            "window_size": self.window_size,
            "threshold": self.threshold,
            "model_path": self.model_path,
        }


_global_engine: Optional[RealtimeMLEngine] = None


def get_realtime_engine(
    model_path: str = str(_MODELS_DIR / "isolation_forest.joblib"),
    scaler_path: str = str(_MODELS_DIR / "scaler.joblib"),
    threshold: float = 0.5,
) -> RealtimeMLEngine:
    """Get or create the global realtime ML engine instance."""
    global _global_engine
    if _global_engine is None:
        _global_engine = RealtimeMLEngine(
            model_path=model_path,
            scaler_path=scaler_path,
            threshold=threshold,
        )
        _global_engine.load_models()
    return _global_engine
