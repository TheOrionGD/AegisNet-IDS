from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from ..models.database import get_database
from .base_repo import BaseRepository


class MongoRepository(BaseRepository):
    def __init__(self):
        self.db: AsyncIOMotorDatabase = get_database()

    async def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        collection = self.db.security_events
        cursor = collection.find().sort("timestamp", -1).limit(limit)
        alerts = []
        async for event in cursor:
            alerts.append(self._map_alert(event))
        return alerts

    async def get_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        collection = self.db.incidents
        cursor = collection.find().sort("created_at", -1).limit(limit)
        incidents = []
        async for incident in cursor:
            incidents.append(self._map_incident(incident))
        return incidents

    async def get_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        collection = self.db.anomalies
        cursor = collection.find().sort("timestamp", -1).limit(limit)
        anomalies = []
        async for anomaly in cursor:
            anomalies.append(
                {
                    "id": str(anomaly["_id"]),
                    "timestamp": anomaly["timestamp"].isoformat(),
                    "source": "ML_ENGINE",
                    "anomaly_score": anomaly.get("score", 0.0),
                    "model_type": "Isolation Forest",
                    "message": f"Anomaly detected with score {anomaly.get('score', 0.0)}",
                    "features": anomaly.get("features", {}),
                    "src_ip": anomaly.get("src_ip", "0.0.0.0"),
                    "dst_ip": anomaly.get("dst_ip", "0.0.0.0"),
                }
            )
        return anomalies

    async def get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        collection = self.db.security_events
        pipeline = [
            {"$match": {"raw_data.src_ip": {"$exists": True}}},
            {"$group": {"_id": "$raw_data.src_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
        ]
        result = await collection.aggregate(pipeline).to_list(length=limit)
        return [{"ip": str(doc["_id"]), "count": doc["count"]} for doc in result]

    async def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        collection = self.db.security_events
        since = datetime.utcnow() - timedelta(hours=hours)
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}}},
            {
                "$group": {
                    "_id": {"$dateTrunc": {"date": "$timestamp", "unit": "hour"}},
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        result = await collection.aggregate(pipeline).to_list(length=None)
        return [
            {
                "timestamp": doc["_id"].isoformat(),
                "count": doc["count"],
                "id": str(doc["_id"]),
            }
            for doc in result
        ]

    def _severity_to_string(self, severity: int) -> str:
        mapping = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        return mapping.get(severity, "unknown")

    def _map_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(event["_id"]),
            "timestamp": event["timestamp"].isoformat(),
            "source": event.get("source", ""),
            "type": event.get("event_type", ""),
            "severity": self._severity_to_string(event.get("severity", 1)),
            "message": event.get("message", ""),
            "raw_payload": event.get("raw_data", {}),
        }

    def _map_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "incident_id": str(incident["_id"]),
            "incident_type": "GENERIC",
            "alert_count": 1,
            "severity": self._severity_to_string(incident.get("severity", 1)),
            "confidence": 0.8,
            "attack_pattern": [],
            "start_time": incident["created_at"].isoformat(),
            "end_time": incident.get("resolved_at", incident["created_at"]).isoformat(),
            "title": incident.get("title", ""),
            "description": incident.get("description", ""),
            "status": incident.get("status", "open"),
        }
