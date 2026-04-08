import logging
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from scipy.stats import entropy

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Extract features from Snort alert data and normalize them for ML."""

    def __init__(self, window_size: str = '1min'):
        self.window_size = window_size
        self.scaler = StandardScaler()

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()

        df = df.copy()
        df['protocol'] = df['protocol'].fillna('UNKNOWN').astype(str).str.upper()
        df = df.set_index('timestamp').sort_index()

        agg = {
            'pkt_len': ['count', 'mean', 'max', 'min', 'std'],
            'src_port': 'nunique',
            'dst_port': 'nunique',
            'src_ip': 'nunique',
            'dst_ip': 'nunique'
        }
        features = df.resample(self.window_size).agg(agg)
        features.columns = ['_'.join(col).strip() for col in features.columns.values]
        features = features.fillna(0)

        protocol_counts = df.groupby(pd.Grouper(freq=self.window_size))['protocol'].value_counts().unstack(fill_value=0)
        protocol_counts.columns = [f'protocol_{col}_count' for col in protocol_counts.columns]
        features = features.join(protocol_counts, how='left').fillna(0)

        window_seconds = pd.to_timedelta(self.window_size).total_seconds()
        features['packet_rate'] = features['pkt_len_count'] / window_seconds

        time_diffs = df.groupby(pd.Grouper(freq=self.window_size)).apply(
            lambda group: group.index.to_series().diff().dt.total_seconds().mean() if len(group) > 1 else 0
        )
        features['mean_time_diff'] = time_diffs

        internal_mask = df['src_ip'].astype(str).str.match(r'^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')
        internal_counts = df[internal_mask].groupby(pd.Grouper(freq=self.window_size)).size()
        features['internal_packets'] = internal_counts
        features['internal_packets'] = features['internal_packets'].fillna(0)
        features['internal_ratio'] = np.where(
            features['pkt_len_count'] > 0,
            features['internal_packets'] / features['pkt_len_count'],
            0
        )

        features['internal_ratio'] = features['internal_ratio'].replace([np.inf, -np.inf], 0).fillna(0)
        
        # New Feature: Shannon Entropy of Destination IPs (to detect scans and spreading)
        def calc_entropy(x):
            value_counts = x.value_counts()
            if len(value_counts) <= 1:
                return 0.0
            return float(entropy(value_counts))
            
        entropy_series = df.groupby(pd.Grouper(freq=self.window_size))['dst_ip'].apply(calc_entropy)
        features['dst_ip_entropy'] = entropy_series.fillna(0)

        # New Feature: Lagged Packet Rate (Rate of Change)
        features['packet_rate_lag_1'] = features['packet_rate'].shift(1).fillna(0)
        features['packet_rate_change'] = features['packet_rate'] - features['packet_rate_lag_1']

        features.fillna(0, inplace=True)

        logger.info(f'Extracted features with shape {features.shape}')
        return features

    def normalize_features(self, features: pd.DataFrame, fit: bool = True) -> Tuple[pd.DataFrame, StandardScaler]:
        if features.empty:
            return features, self.scaler

        if fit:
            self.scaler.fit(features)

        normalized = pd.DataFrame(
            self.scaler.transform(features),
            index=features.index,
            columns=features.columns
        )
        return normalized, self.scaler