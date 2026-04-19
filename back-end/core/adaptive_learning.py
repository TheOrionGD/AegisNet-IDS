#!/usr/bin/env python3
"""
Phase 4 – Adaptive Learning Engine
====================================
Continuously retrains the IsolationForest model using confirmed SIEM incidents.

Key capabilities:
 - Maintains a rolling window (last N incidents) of labeled training samples
 - Distinguishes confirmed_true_positive / false_positive / unknown labels
 - Simulates incremental learning by retraining on the rolling window
 - Tracks model versions: model_v1, model_v2, … persisted to disk + DB
 - Computes performance metrics: precision, recall, drift_score
 - Adjusts IsolationForest contamination dynamically based on feedback ratios
"""

import logging
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import uuid
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from siem.storage import get_storage
from api.models.database import MONGODB_URL, DATABASE_NAME

logger = logging.getLogger(__name__)


class ModelVersion:
    """Metadata container for a single model version."""

    def __init__(
        self,
        version: str,
        contamination: float,
        training_samples: int,
        precision: float = 0.0,
        recall: float = 0.0,
        drift_score: float = 0.0,
    ):
        self.version = version
        self.contamination = contamination
        self.training_samples = training_samples
        self.precision = precision
        self.recall = recall
        self.drift_score = drift_score
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.is_active = False

    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "contamination": self.contamination,
            "training_samples": self.training_samples,
            "precision": self.precision,
            "recall": self.recall,
            "drift_score": self.drift_score,
            "is_active": self.is_active,
        }


class AdaptiveLearningEngine:
    """
    Self-learning engine that retrains the IsolationForest model
    using feedback from the SIEM and analyst annotations.

    Label semantics
    ---------------
    confirmed_true_positive : event IS an attack  → train as anomaly
    false_positive          : event is benign     → train as normal
    unknown                 : no feedback yet     → excluded from ml_services.training
    """

    LABELS = {"confirmed_true_positive", "false_positive", "unknown"}

    def __init__(
        self,
        models_dir: str = "models",
        mongo_url: str = None,
        db_name: str = None,
        rolling_window: int = 500,
        min_samples_to_retrain: int = 20,
        base_contamination: float = 0.1,
    ):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.mongo_url = mongo_url or MONGODB_URL
        self.db_name = db_name or DATABASE_NAME
        self.storage = get_storage()
        self.rolling_window = rolling_window
        self.min_samples_to_retrain = min_samples_to_retrain
        self.base_contamination = base_contamination

        self._sample_buffer: List[Tuple[Dict, str]] = []
        self._lock = threading.Lock()

        # Version counter – loaded from existing model files
        self._version_counter = self._detect_latest_version()
        self._active_version: Optional[ModelVersion] = None

        logger.info(
            f"AdaptiveLearningEngine initialized. "
            f"Next version will be model_v{self._version_counter + 1}"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def ingest_sample(
        self,
        features: Dict[str, float],
        label: str,
        incident_id: Optional[str] = None,
    ) -> None:
        """
        Add a labeled feature vector to the rolling training buffer.

        Args:
            features   : flat dict of numeric feature values (same columns as
                         feature_engineering output)
            label      : one of 'confirmed_true_positive', 'false_positive',
                         'unknown'
            incident_id: optional SIEM incident ID for traceability
        """
        if label not in self.LABELS:
            raise ValueError(f"Invalid label '{label}'. Must be one of {self.LABELS}")

        entry = {"features": features, "label": label, "incident_id": incident_id}
        with self._lock:
            self._sample_buffer.append(entry)
            # Trim to rolling window
            if len(self._sample_buffer) > self.rolling_window:
                self._sample_buffer = self._sample_buffer[-self.rolling_window :]

        logger.debug(
            f"Ingested sample (label={label}, buffer_size={len(self._sample_buffer)})"
        )

    def maybe_retrain(self) -> Optional[ModelVersion]:
        """
        Trigger retraining if buffer has enough labeled samples and sufficient
        True-Positive examples.  Returns the new ModelVersion or None.
        """
        with self._lock:
            labeled = [s for s in self._sample_buffer if s["label"] != "unknown"]

        if len(labeled) < self.min_samples_to_retrain:
            logger.info(
                f"Skipping retrain: only {len(labeled)} labeled samples "
                f"(need {self.min_samples_to_retrain})"
            )
            return None

        return self._retrain(labeled)

    def force_retrain(self) -> ModelVersion:
        """Force retraining regardless of buffer size (uses all available data)."""
        with self._lock:
            labeled = [s for s in self._sample_buffer if s["label"] != "unknown"]
        if not labeled:
            # Retrain on the full buffer treating everything as normal
            with self._lock:
                labeled = [
                    {"features": s["features"], "label": "false_positive"}
                    for s in self._sample_buffer
                ]
        if not labeled:
            raise RuntimeError("No samples in buffer – cannot retrain")
        return self._retrain(labeled)

    def get_current_version(self) -> Optional[ModelVersion]:
        """Return the currently active model version metadata."""
        return self._active_version

    def get_version_history(self) -> List[Dict]:
        """Return all model version metadata from MongoDB."""
        try:
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                cursor = (
                    self.storage.db["model_versions"]
                    .find()
                    .sort("created_at", -1)
                    .limit(20)
                )
                rows = loop.run_until_complete(cursor.to_list(length=20))
            finally:
                loop.close()
            for r in rows:
                r.pop("_id", None)
            return rows
        except Exception as exc:
            logger.warning(f"Could not load version history: {exc}")
            return []

    def compute_drift_score(
        self,
        reference_model_path: str,
        current_features: np.ndarray,
    ) -> float:
        """
        Compute a simple drift score as the mean absolute difference in
        anomaly scores between the reference model and the current model
        on the same feature matrix.

        Returns value in [0, 1]:  0 = no drift, 1 = maximum drift.
        """
        current_model_path = self._active_model_path()
        if (
            not Path(current_model_path).exists()
            or not Path(reference_model_path).exists()
        ):
            return 0.0

        try:
            ref_model = joblib.load(reference_model_path)
            cur_model = joblib.load(current_model_path)

            ref_scores = ref_model.decision_function(current_features)
            cur_scores = cur_model.decision_function(current_features)

            drift = float(np.mean(np.abs(ref_scores - cur_scores)))
            # Normalise: typical decision_function range is roughly [-0.5, 0.5]
            drift_score = min(1.0, drift / 0.5)
            logger.info(f"Drift score computed: {drift_score:.4f}")
            return drift_score
        except Exception as exc:
            logger.warning(f"Drift score computation failed: {exc}")
            return 0.0

    def adjust_contamination(self, fp_rate: float, fn_rate: float) -> float:
        """
        Dynamically adjust IsolationForest contamination based on observed
        false-positive and false-negative rates.

        Rules:
          - High FP rate  → increase contamination (fewer anomalies expected)
          - High FN rate  → decrease contamination (more anomalies expected)
          - Clamp to [0.01, 0.40]
        """
        delta = (fn_rate - fp_rate) * 0.05
        new_contamination = float(np.clip(self.base_contamination + delta, 0.01, 0.40))
        logger.info(
            f"Contamination adjusted: {self.base_contamination:.3f} → "
            f"{new_contamination:.3f}  (fp_rate={fp_rate:.3f}, fn_rate={fn_rate:.3f})"
        )
        self.base_contamination = new_contamination
        return new_contamination

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _retrain(self, labeled_samples: List[Dict]) -> ModelVersion:
        """Core retraining logic."""
        logger.info(f"Starting retrain on {len(labeled_samples)} labeled samples …")

        # Build feature matrix and binary labels
        # true_positive → anomaly (label=−1 in sklearn)
        # false_positive (benign) → normal (label=+1)
        X_rows = []
        y_true = []
        for sample in labeled_samples:
            feat_vals = list(sample["features"].values())
            if not feat_vals:
                continue
            X_rows.append(feat_vals)
            y_true.append(-1 if sample["label"] == "confirmed_true_positive" else 1)

        if not X_rows:
            raise RuntimeError("All samples have empty feature dicts")

        X = np.array(X_rows, dtype=float)
        y_true_arr = np.array(y_true)

        # Replace NaN / Inf
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        # Compute new contamination based on TP ratio
        tp_ratio = float(np.mean(y_true_arr == -1))
        contamination = float(np.clip(tp_ratio if tp_ratio > 0 else 0.05, 0.01, 0.40))

        # Scaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Train IsolationForest
        model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
        )
        model.fit(X_scaled)

        # Evaluate on training data (self-assessment)
        y_pred = model.predict(X_scaled)  # -1 anomaly, +1 normal
        # Map to binary: anomaly=1, normal=0 for metrics
        y_true_bin = (y_true_arr == -1).astype(int)
        y_pred_bin = (y_pred == -1).astype(int)

        precision = float(precision_score(y_true_bin, y_pred_bin, zero_division=0))
        recall = float(recall_score(y_true_bin, y_pred_bin, zero_division=0))

        # Bump version
        self._version_counter += 1
        version_name = f"model_v{self._version_counter}"

        # Persist model
        model_path = self.models_dir / f"{version_name}.joblib"
        scaler_path = self.models_dir / f"{version_name}_scaler.joblib"
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)

        # Compute drift against previous version if available
        prev_path = self.models_dir / f"model_v{self._version_counter - 1}.joblib"
        drift_score = 0.0
        if prev_path.exists() and len(X_scaled) > 0:
            try:
                prev_model = joblib.load(prev_path)
                prev_scores = prev_model.decision_function(X_scaled)
                cur_scores = model.decision_function(X_scaled)
                drift_score = float(
                    min(1.0, np.mean(np.abs(prev_scores - cur_scores)) / 0.5)
                )
            except Exception:
                drift_score = 0.0

        mv = ModelVersion(
            version=version_name,
            contamination=contamination,
            training_samples=len(X_rows),
            precision=precision,
            recall=recall,
            drift_score=drift_score,
        )
        mv.is_active = True

        # Deactivate previous
        if self._active_version:
            self._active_version.is_active = False

        self._active_version = mv
        self._persist_version(mv)

        logger.info(
            f"✅ Retrain complete → {version_name} | "
            f"precision={precision:.3f} recall={recall:.3f} "
            f"drift={drift_score:.3f} contamination={contamination:.3f}"
        )
        return mv

    def _persist_version(self, mv: ModelVersion) -> None:
        """Persist model version metadata to MongoDB."""
        import asyncio

        async def _save():
            collection = self.storage.db["model_versions"]
            await collection.update_many({}, {"$set": {"is_active": False}})
            doc = mv.to_dict()
            await collection.replace_one({"version": mv.version}, doc, upsert=True)

        try:
            asyncio.run(_save())
        except Exception as exc:
            logger.warning(f"Failed to persist model version to DB: {exc}")

    def _active_model_path(self) -> str:
        if self._active_version:
            return str(self.models_dir / f"{self._active_version.version}.joblib")
        return str(self.models_dir / f"model_v{self._version_counter}.joblib")

    def _detect_latest_version(self) -> int:
        """Scan models dir to find the highest existing version number."""
        if not self.models_dir.exists():
            return 0
        versions = []
        for f in self.models_dir.glob("model_v*.joblib"):
            try:
                num = int(f.stem.replace("model_v", "").split("_")[0])
                versions.append(num)
            except ValueError:
                continue
        return max(versions) if versions else 0
