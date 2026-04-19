#!/usr/bin/env python3
"""
Phase 4 – Global Security Posture Engine
========================================
Computes a real-time system risk score (0–100) and network threat level
(LOW / MEDIUM / HIGH / CRITICAL) based on:

  1. Active SIEM incidents (count, severity distribution, recency)
  2. ML anomaly frequency (how often ML fires per time window)
  3. Active attack patterns from threat hunting (lateral movement, beaconing…)
  4. Automated response actions taken (BLOCK events increase posture score)
  5. Feedback loop health (high FP rate reduces score confidence)

The posture is recomputed on-demand and cached (TTL = 60 seconds).
Historical posture snapshots are stored in MongoDB Atlas.
"""

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from siem.storage import get_storage
from api.models.database import MONGODB_URL, DATABASE_NAME

logger = logging.getLogger(__name__)

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

    POSTURE_CACHE_TTL = 60

    WEIGHTS = {
        "incidents": 0.40,
        "anomaly": 0.25,
        "hunt": 0.20,
        "response": 0.15,
    }

    def __init__(
        self,
        mongo_url: str = None,
        db_name: str = None,
        lookback_hours: int = 24,
    ):
        self.mongo_url = mongo_url or MONGODB_URL
        self.db_name = db_name or DATABASE_NAME
        self.storage = get_storage()
        self.lookback_hours = lookback_hours
        self._lock = threading.Lock()
        self._cache: Optional[Dict] = None
        self._cache_ts: float = 0.0

    def compute_posture(self, force: bool = False) -> Dict:
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
        return self.compute_posture().get("threat_level", ThreatLevel.LOW)

    async def get_posture_history_async(self, limit: int = 48) -> List[Dict]:
        try:
            collection = self.storage.db["security_posture"]
            cursor = collection.find().sort("computed_at", -1).limit(limit)
            results = await cursor.to_list(length=limit)
            return [r.pop("_id", None) or r for r in results]
        except Exception as exc:
            logger.warning(f"Failed to load posture history: {exc}")
            return []

    def get_posture_history(self, limit: int = 48) -> List[Dict]:
        import asyncio

        return asyncio.run(self.get_posture_history_async(limit))

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
        severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        try:
            collection = self.storage.db["incidents"]
            pipeline = [
                {"$match": {"start_time": {"$gte": cutoff}}},
                {"$group": {"_id": "$severity", "cnt": {"$sum": 1}}},
            ]
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                cursor = collection.aggregate(pipeline)
                rows = loop.run_until_complete(cursor.to_list(length=100))
            finally:
                loop.close()

            weighted_sum = sum(
                severity_weights.get(str(row["_id"]).upper(), 1) * row["cnt"]
                for row in rows
            )
            return min(100.0, weighted_sum)
        except Exception:
            return 0.0

    def _score_anomaly_frequency(self, cutoff: str) -> float:
        try:
            collection = self.storage.db["ids_events"]
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                count = loop.run_until_complete(
                    collection.count_documents(
                        {"is_anomaly": True, "timestamp": {"$gte": cutoff}}
                    )
                )
            finally:
                loop.close()
            return min(100.0, count * 2.0)
        except Exception:
            return 0.0

    def _score_hunt_findings(self, cutoff: str) -> float:
        weight_map = {
            "lateral_movement": 20,
            "beaconing": 15,
            "low_and_slow": 10,
            "stealth_scan": 8,
        }
        try:
            collection = self.storage.db["hunt_results"]
            pipeline = [
                {"$match": {"detected_at": {"$gte": cutoff}}},
                {"$group": {"_id": "$hunt_type", "cnt": {"$sum": 1}}},
            ]
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                cursor = collection.aggregate(pipeline)
                rows = loop.run_until_complete(cursor.to_list(length=100))
            finally:
                loop.close()

            weighted = sum(
                weight_map.get(str(row["_id"]), 5) * row["cnt"] for row in rows
            )
            return min(100.0, float(weighted))
        except Exception:
            return 0.0

    def _score_response_actions(self, cutoff: str) -> float:
        action_weights = {"BLOCK": 10, "RATE_LIMIT": 5, "ALERT": 2, "LOG": 0.5}
        try:
            collection = self.storage.db["response_actions"]
            pipeline = [
                {"$match": {"executed_at": {"$gte": cutoff}}},
                {"$group": {"_id": "$action_type", "cnt": {"$sum": 1}}},
            ]
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                cursor = collection.aggregate(pipeline)
                rows = loop.run_until_complete(cursor.to_list(length=100))
            finally:
                loop.close()

            weighted = sum(
                action_weights.get(str(row["_id"]), 1) * row["cnt"] for row in rows
            )
            return min(100.0, float(weighted))
        except Exception:
            return 0.0

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
                "CRITICAL: Network under active multi-vector attack. "
                "Immediate SOC intervention required."
            )
        elif total >= _LEVEL_HIGH:
            insights.append(
                "HIGH: Significant threat activity detected. "
                "Review incidents and validate automated blocks."
            )
        elif total >= _LEVEL_MEDIUM:
            insights.append(
                "MEDIUM: Elevated threat indicators present. "
                "Analyst review recommended."
            )
        else:
            insights.append("LOW: System operating within normal parameters.")

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

    async def _persist_snapshot_async(self, posture: Dict) -> None:
        try:
            collection = self.storage.db["security_posture"]
            await collection.replace_one(
                {"id": posture["id"]},
                posture,
                upsert=True,
            )
        except Exception as exc:
            logger.warning(f"Failed to persist posture snapshot: {exc}")

    def _persist_snapshot(self, posture: Dict) -> None:
        try:
            import asyncio

            asyncio.run(self._persist_snapshot_async(posture))
        except Exception as exc:
            logger.warning(f"Failed to persist posture snapshot: {exc}")


def get_security_posture_engine() -> SecurityPostureEngine:
    return SecurityPostureEngine()
