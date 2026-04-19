from typing import List, Dict, Any, Optional
from ..models.security_event import SecurityEvent
from ..repositories.mongo_repo import MongoRepository
import json
import asyncio


class AlertService:
    def __init__(self, repository: MongoRepository):
        self.repository = repository

    async def get_normalized_alerts(self, limit: int = 100) -> List[SecurityEvent]:
        try:
            raw_alerts = await self.repository.get_alerts(limit=limit)
        except Exception as e:
            import logging

            logging.getLogger(__name__).error(f"Error fetching alerts from repo: {e}")
            return []

        normalized = []
        for alert in raw_alerts:
            # Map raw_logs to SecurityEvent
            # alert keys: id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, alert_type, severity, signature_id, raw_payload

            ml_score = 0.0
            raw_payload = {}
            if alert.get("alert_type") == "ML_ANOMALY" and alert.get("raw_payload"):
                try:
                    p = json.loads(alert.get("raw_payload"))
                    ml_score = float(p.get("anomaly_score", 0.0))
                    raw_payload = p
                except Exception:
                    pass

            normalized.append(
                SecurityEvent(
                    id=alert.get("id", ""),
                    timestamp=alert.get("timestamp", ""),
                    source="IDS"
                    if alert.get("alert_type") != "ML_ANOMALY"
                    else "ML_ENGINE",
                    type=alert.get("alert_type", "UNKNOWN"),
                    severity=alert.get("severity", "LOW"),
                    src_ip=alert.get("src_ip"),
                    dst_ip=alert.get("dst_ip"),
                    protocol=alert.get("protocol"),
                    message=f"Alert {alert.get('alert_type')} from {alert.get('src_ip')}",
                    ml_score=ml_score,
                    correlation_score=0.0,
                    raw_payload=raw_payload,
                )
            )
        return normalized

    async def get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        try:
            return await self.repository.get_top_ips(limit=limit)
        except Exception as e:
            import logging

            logging.getLogger(__name__).error(f"Error fetching top IPs: {e}")
            return []

    async def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        try:
            return await self.repository.get_timeline(hours=hours)
        except Exception as e:
            import logging

            logging.getLogger(__name__).error(f"Error fetching timeline: {e}")
            return []

    def ingest_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Manually ingest an alert (used by internal services).
        The active detection pipeline is now handled via the Event Bus + AnalysisWorker.
        """
        return self.repository.ingest_log(alert_data)
