#!/usr/bin/env python3
"""
Phase 4 – Feedback Loop System (Human-in-the-Loop)
====================================================
Accepts analyst labels (TRUE_POSITIVE / FALSE_POSITIVE / UNKNOWN) for
SIEM incidents and feeds them back into:

  1. The Adaptive Learning Engine's training buffer
  2. The Rule Generator's effectiveness scoring
  3. Dynamic threshold adjustment:
       - Excess FP  → raise anomaly_score threshold (reduce sensitivity)
       - Excess FN  → lower anomaly_score threshold (raise sensitivity)

All feedback is persisted to the `feedback` table in SQLite.
Threshold adjustments are persisted to a JSON config overlay file so
the pipeline can read them on restart.
"""

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Valid analyst labels
LABEL_TP = "TRUE_POSITIVE"
LABEL_FP = "FALSE_POSITIVE"
LABEL_UNKNOWN = "UNKNOWN"
VALID_LABELS = {LABEL_TP, LABEL_FP, LABEL_UNKNOWN}

# Minimum batch size before a threshold adjustment is computed
ADJUSTMENT_BATCH_SIZE = 5
# Step size for threshold nudging
THRESHOLD_STEP = 0.05
# Bounds for anomaly_score threshold
THRESHOLD_MIN = -0.8
THRESHOLD_MAX = -0.1


class FeedbackLoop:
    """
    Human-in-the-Loop feedback processor.
    Thread-safe: safe to call from concurrent pipeline threads.
    """

    def __init__(
        self,
        db_path: str = "data/siem.db",
        threshold_config_path: str = "data/adaptive_thresholds.json",
        initial_threshold: float = -0.3,
    ):
        self.db_path = Path(db_path)
        self.threshold_config_path = Path(threshold_config_path)
        self.threshold_config_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

        # Load persisted threshold or use initial
        self.current_threshold = self._load_threshold(initial_threshold)

        # Counters since last adjustment
        self._tp_since_adjust = 0
        self._fp_since_adjust = 0

        # Reference to the adaptive learning engine (injected lazily)
        self._learning_engine = None

        logger.info(
            f"FeedbackLoop initialized. "
            f"Current threshold={self.current_threshold:.3f}"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def attach_learning_engine(self, engine) -> None:
        """Inject the AdaptiveLearningEngine reference."""
        self._learning_engine = engine

    def submit_feedback(
        self,
        incident_id: str,
        label: str,
        features: Optional[Dict] = None,
        analyst: str = "system",
        notes: str = "",
    ) -> Dict:
        """
        Record analyst feedback for an incident.

        Args:
            incident_id : SIEM incident_id
            label       : TRUE_POSITIVE | FALSE_POSITIVE | UNKNOWN
            features    : optional dict of numeric features for ML retraining
            analyst     : identifier of the analyst (default 'system')
            notes       : free-text notes

        Returns:
            feedback record dict
        """
        label = label.upper()
        if label not in VALID_LABELS:
            raise ValueError(
                f"Invalid label '{label}'. Must be one of {VALID_LABELS}"
            )

        record = {
            "id": str(uuid.uuid4()),
            "incident_id": incident_id,
            "label": label,
            "analyst": analyst,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notes": notes,
        }
        self._persist_feedback(record)

        with self._lock:
            if label == LABEL_TP:
                self._tp_since_adjust += 1
            elif label == LABEL_FP:
                self._fp_since_adjust += 1

            # Feed into ML retraining queue
            if self._learning_engine and features:
                ml_label = (
                    "confirmed_true_positive"
                    if label == LABEL_TP
                    else "false_positive"
                    if label == LABEL_FP
                    else "unknown"
                )
                self._learning_engine.ingest_sample(features, ml_label, incident_id)

            # Maybe adjust threshold based on accumulated feedback
            total = self._tp_since_adjust + self._fp_since_adjust
            if total >= ADJUSTMENT_BATCH_SIZE:
                self._adjust_threshold()

        logger.info(
            f"[Feedback] incident={incident_id} label={label} analyst={analyst}"
        )
        return record

    def get_current_threshold(self) -> float:
        """Return the current dynamically adjusted anomaly score threshold."""
        return self.current_threshold

    def get_feedback_stats(self) -> Dict:
        """Return aggregate feedback statistics from the DB."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """
                SELECT label, COUNT(*) as count
                FROM feedback
                GROUP BY label
                """
            )
            rows = cur.fetchall()
            conn.close()
            stats = {label: 0 for label in VALID_LABELS}
            for row in rows:
                stats[row[0]] = row[1]
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
        """Retrieve recent feedback entries from the DB."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM feedback ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            logger.warning(f"Could not load recent feedback: {exc}")
            return []

    def bulk_process_feedback(self, feedback_list: List[Dict]) -> int:
        """
        Process a batch of feedback dicts at once.
        Each dict must have keys: incident_id, label.
        Optionally: features, analyst, notes.

        Returns count of processed entries.
        """
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

    # ──────────────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────────────

    def _adjust_threshold(self) -> None:
        """
        Nudge anomaly_score threshold based on recent TP/FP ratio.

        Logic:
          - FP-heavy batch  → raise threshold (less sensitive → fewer FPs)
          - TP-heavy batch  → lower threshold (more sensitive → catch more TPs)
        """
        tp = self._tp_since_adjust
        fp = self._fp_since_adjust
        total = tp + fp

        if total == 0:
            return

        fp_rate = fp / total
        tp_rate = tp / total

        if fp_rate > 0.5:
            # Too many false positives – raise threshold
            delta = THRESHOLD_STEP * min(fp_rate, 1.0)
            new_threshold = min(THRESHOLD_MAX, self.current_threshold + delta)
            direction = "↑ (reducing sensitivity)"
        elif tp_rate > 0.7 and fp_rate < 0.2:
            # Model is catching real attacks well but might miss some – lower slightly
            delta = THRESHOLD_STEP * 0.5
            new_threshold = max(THRESHOLD_MIN, self.current_threshold - delta)
            direction = "↓ (increasing sensitivity)"
        else:
            # Balanced – no adjustment
            self._tp_since_adjust = 0
            self._fp_since_adjust = 0
            return

        old = self.current_threshold
        self.current_threshold = new_threshold
        self._tp_since_adjust = 0
        self._fp_since_adjust = 0

        self._save_threshold()

        logger.info(
            f"[FeedbackLoop] Threshold adjusted {old:.3f} → "
            f"{new_threshold:.3f} {direction} "
            f"(batch: tp={tp}, fp={fp})"
        )

        # Notify the learning engine to also update contamination
        if self._learning_engine:
            fn_rate = max(0.0, 1.0 - tp_rate)
            self._learning_engine.adjust_contamination(fp_rate, fn_rate)

    def _persist_feedback(self, record: Dict) -> None:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO feedback
                (id, incident_id, label, analyst, timestamp, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["incident_id"],
                    record["label"],
                    record["analyst"],
                    record["timestamp"],
                    record["notes"],
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning(f"Failed to persist feedback: {exc}")

    def _load_threshold(self, default: float) -> float:
        if self.threshold_config_path.exists():
            try:
                with self.threshold_config_path.open("r") as f:
                    data = json.load(f)
                    return float(data.get("anomaly_score_threshold", default))
            except Exception:
                pass
        return default

    def _save_threshold(self) -> None:
        try:
            existing = {}
            if self.threshold_config_path.exists():
                with self.threshold_config_path.open("r") as f:
                    existing = json.load(f)
            existing["anomaly_score_threshold"] = self.current_threshold
            existing["last_updated"] = datetime.now(timezone.utc).isoformat()
            with self.threshold_config_path.open("w") as f:
                json.dump(existing, f, indent=2)
        except Exception as exc:
            logger.warning(f"Failed to save threshold: {exc}")
