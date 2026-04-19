#!/usr/bin/env python3
"""
Phase 4 – Global Security Posture Engine
=========================================
Computes a real-time system risk score (0–100) and network threat level
(LOW / MEDIUM / HIGH / CRITICAL) based on:

  1. Active SIEM incidents (count, severity distribution, recency)
  2. ML anomaly frequency (how often ML fires per time window)
  3. Active attack patterns from threat hunting (lateral movement, beaconing…)
  4. Automated response actions taken (BLOCK events increase posture score)
  5. Feedback loop health (high FP rate reduces score confidence)

The posture is recomputed on-demand and cached (TTL = 60 seconds).
Historical posture snapshots are stored in the `security_posture` SQLite table.
"""

import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Threat level thresholds
_LEVEL_CRITICAL = 75
_LEVEL_HIGH = 50
_LEVEL_MEDIUM = 25


class ThreatLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityPostureEngine:
    """
    Computes and tracks a global security risk score.

    Score contributors (all normalized to 0–100):
      incidents_score   : 40% weight  – based on recent incident count + severity
      anomaly_score     : 25% weight  – ML anomaly firing rate
      hunt_score        : 20% weight  – active threat hunt findings
      response_score    : 15% weight  – BLOCK/RATE_LIMIT actions taken recently
    """

    POSTURE_CACHE_TTL = 60  # seconds

    WEIGHTS = {
        "incidents": 0.40,
        "anomaly": 0.25,
        "hunt": 0.20,
        "response": 0.15,
    }

    def __init__(
        self,
        db_path: str = "data/cns.db",
        lookback_hours: int = 24,
    ):
        self.db_path = Path(db_path)
        self.lookback_hours = lookback_hours
        self._lock = threading.Lock()
        self._cache: Optional[Dict] = None
        self._cache_ts: float = 0.0

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def compute_posture(self, force: bool = False) -> Dict:
        """
        Compute (or return cached) the current security posture.

        Args:
            force : if True, bypass cache and recompute

        Returns:
            dict with keys:
              risk_score    (int, 0-100)
              threat_level  (str)
              components    (dict of sub-scores)
              computed_at   (ISO timestamp)
              insights      (list of human-readable strings)
        """
        with self._lock:
            if (
                not force
                and self._cache is not None
                and (time.monotonic() - self._cache_ts) < self.POSTURE_CACHE_TTL
            ):
                return self._cache

            posture = self._recompute()
            self._cache = posture
            self._cache_ts = time.monotonic()
            self._persist_snapshot(posture)
            return posture

    def get_threat_level(self) -> str:
        """Return current threat level without full posture object."""
        return self.compute_posture().get("threat_level", ThreatLevel.LOW)

    def get_posture_history(self, limit: int = 48) -> List[Dict]:
        """
        Return historical posture snapshots (most recent first).
        Useful for trending charts.
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM security_posture ORDER BY computed_at DESC LIMIT ?",
                (limit,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            logger.warning(f"Failed to load posture history: {exc}")
            return []

    # ──────────────────────────────────────────────────────────────────────────
    # Core computation
    # ──────────────────────────────────────────────────────────────────────────

    def _recompute(self) -> Dict:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        ).isoformat()

        incidents_score = self._score_incidents(cutoff)
        anomaly_score = self._score_anomaly_frequency(cutoff)
        hunt_score = self._score_hunt_findings(cutoff)
        response_score = self._score_response_actions(cutoff)

        raw = (
            incidents_score * self.WEIGHTS["incidents"]
            + anomaly_score * self.WEIGHTS["anomaly"]
            + hunt_score * self.WEIGHTS["hunt"]
            + response_score * self.WEIGHTS["response"]
        )
        risk_score = int(min(100, max(0, round(raw))))

        threat_level = self._classify_threat(risk_score)
        insights = self._build_insights(
            incidents_score, anomaly_score, hunt_score, response_score, risk_score
        )

        posture = {
            "id": str(uuid.uuid4()),
            "risk_score": risk_score,
            "threat_level": threat_level,
            "components": {
                "incidents_score": round(incidents_score, 2),
                "anomaly_score": round(anomaly_score, 2),
                "hunt_score": round(hunt_score, 2),
                "response_score": round(response_score, 2),
            },
            "weights": self.WEIGHTS,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "lookback_hours": self.lookback_hours,
            "insights": insights,
        }
        logger.info(
            f"[Posture] risk={risk_score} level={threat_level} "
            f"(inc={incidents_score:.1f} "
            f"anom={anomaly_score:.1f} "
            f"hunt={hunt_score:.1f} "
            f"resp={response_score:.1f})"
        )
        return posture

    def _score_incidents(self, cutoff: str) -> float:
        """
        0–100 score based on:
          - Count of recent incidents (scaled at 20 = max)
          - Severity weighting: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
        """
        if not self.db_path.exists():
            return 0.0
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                "SELECT severity, COUNT(*) as cnt FROM incidents "
                "WHERE start_time >= ? GROUP BY severity",
                (cutoff,),
            )
            rows = cur.fetchall()
            conn.close()
        except Exception:
            return 0.0

        severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        weighted_sum = sum(
            severity_weights.get(row[0].upper(), 1) * row[1] for row in rows
        )
        # Scale: 100 weighted-incidents = max score
        return min(100.0, weighted_sum)

    def _score_anomaly_frequency(self, cutoff: str) -> float:
        """
        0–100 score: count of ML_ANOMALY events in the lookback window.
        Scaled: 50 anomalies = max score.
        """
        if not self.db_path.exists():
            return 0.0
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM raw_logs "
                "WHERE alert_type = 'ML_ANOMALY' AND timestamp >= ?",
                (cutoff,),
            )
            count = cur.fetchone()[0]
            conn.close()
            return min(100.0, count * 2.0)
        except Exception:
            return 0.0

    def _score_hunt_findings(self, cutoff: str) -> float:
        """
        0–100 score: weighted count of threat hunt findings.
        Lateral movement and beaconing are high-weight.
        """
        weight_map = {
            "lateral_movement": 20,
            "beaconing": 15,
            "low_and_slow": 10,
            "stealth_scan": 8,
        }
        if not self.db_path.exists():
            return 0.0
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                "SELECT hunt_type, COUNT(*) as cnt FROM hunt_results "
                "WHERE detected_at >= ? GROUP BY hunt_type",
                (cutoff,),
            )
            rows = cur.fetchall()
            conn.close()
        except Exception:
            return 0.0

        weighted = sum(weight_map.get(r[0], 5) * r[1] for r in rows)
        return min(100.0, float(weighted))

    def _score_response_actions(self, cutoff: str) -> float:
        """
        0–100 score: heavier actions = higher score.
        BLOCK=10, RATE_LIMIT=5, ALERT=2, LOG=0.5
        """
        action_weights = {"BLOCK": 10, "RATE_LIMIT": 5, "ALERT": 2, "LOG": 0.5}
        if not self.db_path.exists():
            return 0.0
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                "SELECT action_type, COUNT(*) FROM response_actions "
                "WHERE executed_at >= ? GROUP BY action_type",
                (cutoff,),
            )
            rows = cur.fetchall()
            conn.close()
        except Exception:
            return 0.0

        weighted = sum(action_weights.get(r[0], 1) * r[1] for r in rows)
        return min(100.0, float(weighted))

    def _classify_threat(self, score: int) -> str:
        if score >= _LEVEL_CRITICAL:
            return ThreatLevel.CRITICAL
        if score >= _LEVEL_HIGH:
            return ThreatLevel.HIGH
        if score >= _LEVEL_MEDIUM:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def _build_insights(
        self,
        inc: float,
        anom: float,
        hunt: float,
        resp: float,
        total: int,
    ) -> List[str]:
        insights = []
        if total >= _LEVEL_CRITICAL:
            insights.append(
                "🔴 CRITICAL: Network under active multi-vector attack. "
                "Immediate SOC intervention required."
            )
        elif total >= _LEVEL_HIGH:
            insights.append(
                "🟠 HIGH: Significant threat activity detected. "
                "Review incidents and validate automated blocks."
            )
        elif total >= _LEVEL_MEDIUM:
            insights.append(
                "🟡 MEDIUM: Elevated threat indicators present. "
                "Analyst review recommended."
            )
        else:
            insights.append("🟢 LOW: System operating within normal parameters.")

        if inc >= 60:
            insights.append(
                f"Incident subscore {inc:.0f}/100: High volume of correlated incidents."
            )
        if anom >= 50:
            insights.append(
                f"Anomaly subscore {anom:.0f}/100: ML model detecting frequent anomalies."
            )
        if hunt >= 40:
            insights.append(
                f"Hunt subscore {hunt:.0f}/100: Threat hunting found active attack patterns."
            )
        if resp >= 30:
            insights.append(
                f"Response subscore {resp:.0f}/100: Multiple automated blocks active."
            )
        return insights

    def _persist_snapshot(self, posture: Dict) -> None:
        if not self.db_path.exists():
            return
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO security_posture
                (id, risk_score, threat_level, components_json, computed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    posture["id"],
                    posture["risk_score"],
                    posture["threat_level"],
                    json.dumps(posture["components"]),
                    posture["computed_at"],
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning(f"Failed to persist posture snapshot: {exc}")
