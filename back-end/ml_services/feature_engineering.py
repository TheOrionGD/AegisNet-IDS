import logging
from typing import Tuple, Optional

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import NotFittedError
from scipy.stats import entropy

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Extract features from Snort alert data and normalize them for ML."""

    def __init__(self, window_size: str = "1min", scaler_path: Optional[str] = None):
        self.window_size = window_size
        self.scaler = StandardScaler()
        if scaler_path:
            self._load_scaler(scaler_path)

    def _load_scaler(self, scaler_path: str) -> None:
        path_obj = Path(scaler_path)
        if path_obj.exists():
            self.scaler = joblib.load(path_obj)
            logger.info(f"Scaler loaded from {path_obj}")
        else:
            logger.warning(
                f"Scaler file not found: {path_obj}, will fit during training"
            )
        self.columns = [
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

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()

        df = df.copy()

        # 1. Map common aliases (robustness for varying ingestion formats)
        alias_map = {
            "proto": "protocol",
            "src_addr": "src_ip",
            "dest_addr": "dst_ip",
            "dst_addr": "dst_ip",
            "pkt_num": "pkt_len",
        }
        for alias, target in alias_map.items():
            if alias in df.columns and target not in df.columns:
                df[target] = df[alias]

        # 2. Ensure all required columns exist with safe defaults before aggregation
        required_cols = {
            "protocol": "UNKNOWN",
            "pkt_len": 0,
            "src_port": 0,
            "dst_port": 0,
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
        }
        for col, default in required_cols.items():
            if col not in df.columns:
                df[col] = default
            else:
                df[col] = df[col].fillna(default)

        # 3. Clean and prepare
        df["protocol"] = df["protocol"].astype(str).str.upper()
        df = df.set_index("timestamp").sort_index()

        agg = {
            "pkt_len": ["count", "mean", "max", "min", "std"],
            "src_port": "nunique",
            "dst_port": "nunique",
            "src_ip": "nunique",
            "dst_ip": "nunique",
        }
        features = df.resample(self.window_size).agg(agg)
        features.columns = ["_".join(col).strip() for col in features.columns.values]
        features = features.fillna(0)

        protocol_counts = (
            df.groupby(pd.Grouper(freq=self.window_size))["protocol"]
            .value_counts()
            .unstack(fill_value=0)
        )
        protocol_counts.columns = [
            f"protocol_{col}_count" for col in protocol_counts.columns
        ]
        features = features.join(protocol_counts, how="left").fillna(0)

        window_seconds = pd.to_timedelta(self.window_size).total_seconds()
        features["packet_rate"] = features["pkt_len_count"] / window_seconds

        time_diffs = df.groupby(pd.Grouper(freq=self.window_size)).apply(
            lambda group: (
                group.index.to_series().diff().dt.total_seconds().mean()
                if len(group) > 1
                else 0
            )
        )
        features["mean_time_diff"] = time_diffs

        internal_mask = (
            df["src_ip"]
            .astype(str)
            .str.match(r"^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")
        )
        internal_counts = (
            df[internal_mask].groupby(pd.Grouper(freq=self.window_size)).size()
        )
        features["internal_packets"] = internal_counts
        features["internal_packets"] = features["internal_packets"].fillna(0)
        features["internal_ratio"] = np.where(
            features["pkt_len_count"] > 0,
            features["internal_packets"] / features["pkt_len_count"],
            0,
        )

        features["internal_ratio"] = (
            features["internal_ratio"].replace([np.inf, -np.inf], 0).fillna(0)
        )

        # New Feature: Shannon Entropy of Destination IPs (to detect scans and spreading)
        def calc_entropy(x):
            value_counts = x.value_counts()
            if len(value_counts) <= 1:
                return 0.0
            return float(entropy(value_counts))

        entropy_series = df.groupby(pd.Grouper(freq=self.window_size))["dst_ip"].apply(
            calc_entropy
        )
        features["dst_ip_entropy"] = entropy_series.fillna(0)

        # New Feature: Lagged Packet Rate (Rate of Change)
        features["packet_rate_lag_1"] = features["packet_rate"].shift(1).fillna(0)
        features["packet_rate_change"] = (
            features["packet_rate"] - features["packet_rate_lag_1"]
        )

        # 7. Ensure consistent feature set and order
        for col in self.columns:
            if col not in features.columns:
                features[col] = 0

        features = features[self.columns]
        features.fillna(0, inplace=True)

        logger.info(f"Extracted features with shape {features.shape}")
        return features

    def normalize_features(
        self, features: pd.DataFrame, fit: bool = True
    ) -> Tuple[pd.DataFrame, StandardScaler]:
        if features.empty:
            return features, self.scaler

        if fit:
            self.scaler.fit(features)
        else:
            # Check if scaler is fitted
            if not hasattr(self.scaler, "mean_") or self.scaler.mean_ is None:
                logger.warning(
                    "StandardScaler not fitted and fit=False. Returning raw features."
                )
                return features, self.scaler

        try:
            normalized = pd.DataFrame(
                self.scaler.transform(features),
                index=features.index,
                columns=features.columns,
            )
            return normalized, self.scaler
        except Exception as e:
            logger.warning(f"Normalization failed ({e}). Returning raw features.")
            return features, self.scaler
