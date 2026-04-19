#!/usr/bin/env python3
"""
Phase 4 – Feedback Loop System (Human-in-the-Loop)
===================================================
Accepts analyst labels (TRUE_POSITIVE / FALSE_POSITIVE / UNKNOWN) for
SIEM incidents and feeds them back into:

  1. The Adaptive Learning Engine's training buffer
  2. The Rule Generator's effectiveness scoring
  3. Dynamic threshold adjustment:
       - Excess FP  → raise anomaly_score threshold (reduce sensitivity)
       - Excess FN  → lower anomaly_score threshold (raise sensitivity)

All feedback is persisted to MongoDB Atlas.
Threshold adjustments are persisted to a JSON config overlay file so
the pipeline can read them on restart.
"""

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from siem.storage import get_storage
from api.models.database import MONGODB_URL, DATABASE_NAME

logger = logging.getLogger(__name__)

LABEL_TP = "TRUE_POSITIVE"
LABEL_FP = "FALSE_POSITIVE"
LABEL_UNKNOWN = "UNKNOWN"
VALID_LABELS = {LABEL_TP, LABEL_FP, LABEL_UNKNOWN}

ADJUSTMENT_BATCH_SIZE = 5
THRESHOLD_STEP = 0.05
THRESHOLD_MIN = -0.8
THRESHOLD_MAX = -0.1


class FeedbackLoop:
    """Human-in-the-Loop feedback processor. Thread-safe."""

    def __init__(
        self,
        mongo_url: str = None,
        db_name: str = None,
        threshold_config_path: str = "data/adaptive_thresholds.json",
        initial_threshold: float = -0.3,
    ):
        self.mongo_url = mongo_url or MONGODB_URL
        self.db_name = db_name or DATABASE_NAME
        self.storage = get_storage()
        self.threshold_config_path = Path(threshold_config_path)
        self.threshold_config_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

        self.current_threshold = self._load_threshold(initial_threshold)

        self._tp_since_adjust = 0
        self._fp_since_adjust = 0

        self._learning_engine = None

        logger.info(
            f"FeedbackLoop initialized. Current threshold={self.current_threshold:.3f}"
        )

    def attach_learning_engine(self, engine) -> None:
        self._learning_engine = engine
        logger.info("[Feedback] Learning engine attached")

    def submit_feedback(
        self,
        incident_id: str,
        label: str,
        features: Optional[Dict] = None,
        analyst: str = "analyst",
        notes: str = "",
    ) -> Dict:
        if label not in VALID_LABELS:
            raise ValueError(f"Invalid label: {label}. Must be one of {VALID_LABELS}")

        with self._lock:
            record = {
                "id": str(uuid.uuid4()),
                "incident_id": incident_id,
                "label": label,
                "analyst": analyst,
                "notes": notes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "features": features or {},
            }

            import asyncio

            asyncio.run(self._save_feedback_async(record))

            if label == LABEL_TP:
                self._tp_since_adjust += 1
            elif label == LABEL_FP:
                self._fp_since_adjust += 1

            self._maybe_adjust_threshold()

            logger.info(
                f"[Feedback] incident={incident_id} label={label} analyst={analyst}"
            )
            return record

    async def _save_feedback_async(self, record: Dict) -> None:
        try:
            await self.storage.db["feedback"].replace_one(
                {"id": record["id"]}, record, upsert=True
            )
        except Exception as exc:
            logger.warning(f"Failed to save feedback: {exc}")

    def get_current_threshold(self) -> float:
        return self.current_threshold

    def get_feedback_stats(self) -> Dict:
        try:
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                pipeline = [{"$group": {"_id": "$label", "count": {"$sum": 1}}}]
                cursor = self.storage.db["feedback"].aggregate(pipeline)
                rows = loop.run_until_complete(cursor.to_list(length=10))
            finally:
                loop.close()

            stats = {label: 0 for label in VALID_LABELS}
            for row in rows:
                stats[row["_id"]] = row["count"]
            total = sum(stats.values())
            fp_rate = stats[LABEL_FP] / total if total > 0 else 0.0
            tp_rate = stats[LABEL_TP] / total if total > 0 else 0.0
            return {
                "total_feedback": total,
                "true_positives": stats[LABEL_TP],
                "false_positives": stats[LABEL_FP],
                "unknown": stats[LABEL_UNKNOWN],
                "fp_rate": round(fp_rate, 4),
                "tp_rate": round(tp_rate, 4),
                "current_threshold": self.current_threshold,
            }
        except Exception as exc:
            logger.warning(f"Could not load feedback stats: {exc}")
            return {"current_threshold": self.current_threshold}

    def get_recent_feedback(self, limit: int = 50) -> List[Dict]:
        try:
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                cursor = (
                    self.storage.db["feedback"]
                    .find()
                    .sort("timestamp", -1)
                    .limit(limit)
                )
                rows = loop.run_until_complete(cursor.to_list(length=limit))
            finally:
                loop.close()
            for r in rows:
                r.pop("_id", None)
            return rows
        except Exception as exc:
            logger.warning(f"Could not load recent feedback: {exc}")
            return []

    def bulk_process_feedback(self, feedback_list: List[Dict]) -> int:
        count = 0
        for fb in feedback_list:
            try:
                self.submit_feedback(
                    incident_id=fb["incident_id"],
                    label=fb["label"],
                    features=fb.get("features"),
                    analyst=fb.get("analyst", "bulk"),
                    notes=fb.get("notes", ""),
                )
                count += 1
            except Exception as exc:
                logger.warning(f"Skipping feedback entry due to error: {exc}")
        return count

    def _adjust_threshold(self) -> None:
        tp = self._tp_since_adjust
        fp = self._fp_since_adjust
        total = tp + fp

        if total == 0:
            return

        fp_ratio = fp / total

        if fp_ratio > 0.6 and self.current_threshold < THRESHOLD_MAX:
            self.current_threshold = min(
                THRESHOLD_MAX, self.current_threshold + THRESHOLD_STEP
            )
            self._save_threshold()
            logger.info(
                f"[Feedback] FP-heavy ({fp_ratio:.1%}), raised threshold to {self.current_threshold:.3f}"
            )

        elif fp_ratio < 0.3 and self.current_threshold > THRESHOLD_MIN:
            self.current_threshold = max(
                THRESHOLD_MIN, self.current_threshold - THRESHOLD_STEP
            )
            self._save_threshold()
            logger.info(
                f"[Feedback] TP-heavy ({fp_ratio:.1%}), lowered threshold to {self.current_threshold:.3f}"
            )

        self._tp_since_adjust = 0
        self._fp_since_adjust = 0

    def _maybe_adjust_threshold(self) -> None:
        if (self._tp_since_adjust + self._fp_since_adjust) >= ADJUSTMENT_BATCH_SIZE:
            self._adjust_threshold()

    def _load_threshold(self, default: float) -> float:
        if self.threshold_config_path.exists():
            try:
                with open(self.threshold_config_path, "r") as f:
                    data = json.load(f)
                    return data.get("anomaly_score_threshold", default)
            except Exception as exc:
                logger.warning(f"Could not load threshold config: {exc}")
        return default

    def _save_threshold(self) -> None:
        try:
            self.threshold_config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.threshold_config_path, "w") as f:
                json.dump({"anomaly_score_threshold": self.current_threshold}, f)
        except Exception as exc:
            logger.warning(f"Could not persist threshold: {exc}")

    def _audit_log(self, message: str, event_type: str = "INFO") -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "message": message,
        }
        self.audit_log.append(entry)
        logger.info(f"[AUDIT] {event_type}: {message}")


def get_feedback_loop() -> FeedbackLoop:
    return FeedbackLoop()
