import json
import logging
import datetime
from datetime import timezone
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure

import os
from dotenv import load_dotenv

from api.models.database import (
    Feedback,
    ModelVersion,
    ResponseAction,
    RuleScore,
    get_database,
    db_instance,
    MONGODB_URL,
    DATABASE_NAME,
)
from config_loader import load_config

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(dotenv_path=_PROJECT_ROOT / ".env", override=False)


class SIEMStorage:
    """
    Production-grade SIEM Storage abstraction using MongoDB Atlas.
    Uses motor async client for logs/feedback and MongoDB collections for incidents.
    """

    def __init__(self, mongo_url: str = None, db_name: str = None):
        self.config = load_config()
        self.mongo_url = mongo_url or MONGODB_URL
        self.db_name = db_name or "aegisnet"
        self.client: AsyncIOMotorClient = AsyncIOMotorClient(self.mongo_url)
        self.db = self.client["aegisnet"]
        self._connected = True

    def _connect(self):
        """Establish MongoDB connection."""
        try:
            self.client = AsyncIOMotorClient(self.mongo_url)
            self.db = self.client[self.db_name]
            self._connected = True
            logger.info(f"[STORAGE] Connected to MongoDB: {self.db_name}")
        except Exception as e:
            logger.error(f"[STORAGE] MongoDB connection failed: {e}")
            self._connected = False

    @property
    def logs_collection(self):
        """Get logs collection."""
        return self.db["logs"]

    @property
    def incidents_collection(self):
        """Get incidents collection."""
        return self.db["incidents"]

    @property
    def feedback_collection(self):
        """Get feedback collection."""
        return self.db["feedback"]

    @property
    def model_versions_collection(self):
        """Get model versions collection."""
        return self.db["model_versions"]

    @property
    def response_actions_collection(self):
        """Get response actions collection."""
        return self.db["response_actions"]

    @property
    def rule_scores_collection(self):
        """Get rule scores collection."""
        return self.db["rule_scores"]

    @property
    def ids_events_collection(self):
        """Get IDS events collection."""
        return self.db["ids_events"]

    async def _ensure_indices(self):
        """Ensure MongoDB indices exist."""
        try:
            await self.logs_collection.create_index("timestamp")
            await self.logs_collection.create_index("src_ip")
            await self.logs_collection.create_index("alert_type")
            await self.incidents_collection.create_index("incident_id")
            await self.incidents_collection.create_index("start_time")
            await self.feedback_collection.create_index("incident_id")
            await self.ids_events_collection.create_index("timestamp")
            await self.ids_events_collection.create_index("src_ip")
            await self.ids_events_collection.create_index("ml_score")
            logger.info("[STORAGE] MongoDB indices ensured")
        except Exception as e:
            logger.warning(f"[STORAGE] Failed to create indices: {e}")

    async def ingest_log(self, log_entry: Dict[str, Any]) -> str:
        """Store a log entry in MongoDB logs collection."""
        if not self._connected:
            logger.warning("[STORAGE] MongoDB not connected, skipping log ingest")
            return None

        log_id = str(uuid.uuid4())
        log_entry["id"] = log_id

        now_ts = datetime.datetime.now(timezone.utc).isoformat()
        log_entry.setdefault("timestamp", now_ts)
        log_entry.setdefault("src_ip", "0.0.0.0")
        log_entry.setdefault("dst_ip", "0.0.0.0")
        log_entry.setdefault("protocol", "UNKNOWN")
        log_entry.setdefault("severity", "LOW")
        log_entry.setdefault("alert_type", "GENERIC_ALERT")

        try:
            await self.logs_collection.insert_one(log_entry)
            logger.debug(f"[STORAGE] Stored log: {log_id}")
        except Exception as e:
            logger.error(f"[STORAGE] Failed to store log: {e}")

        return log_id

    async def ingest_ids_event(self, event: Dict[str, Any]) -> str:
        """Fast-path ingestion for IDS/Snort events with ML scoring."""
        if not self._connected:
            logger.warning("[STORAGE] MongoDB not connected, skipping IDS event")
            return None

        event_id = str(uuid.uuid4())
        event["id"] = event_id

        now_ts = datetime.datetime.now(timezone.utc).isoformat()
        event.setdefault("timestamp", now_ts)
        event.setdefault("src_ip", "0.0.0.0")
        event.setdefault("dst_ip", "0.0.0.0")
        event.setdefault("src_port", 0)
        event.setdefault("dst_port", 0)
        event.setdefault("protocol", "TCP")
        event.setdefault("alert_type", "SNORT_ALERT")
        event.setdefault("severity", "MEDIUM")
        event.setdefault("ml_score", 0.0)
        event.setdefault("ml_risk_level", "LOW")
        event.setdefault("is_anomaly", False)
        event.setdefault("threat_level", "NORMAL")

        try:
            await self.ids_events_collection.insert_one(event)
            logger.debug(
                f"[STORAGE] Stored IDS event: {event.get('src_ip')} -> {event.get('dst_ip')}"
            )
        except Exception as e:
            logger.error(f"[STORAGE] Failed to store IDS event: {e}")

        return event_id

    async def get_ids_events(
        self, hours_back: int = 24, min_score: float = 0.0
    ) -> List[Dict[str, Any]]:
        """Query IDS events with optional ML score filtering."""
        if not self._connected:
            return []

        try:
            cutoff = datetime.datetime.now(timezone.utc) - datetime.timedelta(
                hours=hours_back
            )
            query = {
                "timestamp": {"$gte": cutoff.isoformat()},
            }
            if min_score > 0:
                query["ml_score"] = {"$gte": min_score}

            cursor = (
                self.ids_events_collection.find(query).sort("timestamp", -1).limit(1000)
            )
            events = await cursor.to_list(length=1000)
            return [event.pop("_id", None) or event for event in events]
        except Exception as e:
            logger.error(f"[STORAGE] Failed to query IDS events: {e}")
            return []

    async def get_anomalous_ips(
        self, hours_back: int = 24, min_score: float = 0.7
    ) -> List[Dict[str, Any]]:
        """Get IPs with high anomaly scores."""
        if not self._connected:
            return []

        try:
            cutoff = datetime.datetime.now(timezone.utc) - datetime.timedelta(
                hours=hours_back
            )
            pipeline = [
                {
                    "$match": {
                        "timestamp": {"$gte": cutoff.isoformat()},
                        "ml_score": {"$gte": min_score},
                    }
                },
                {
                    "$group": {
                        "_id": "$src_ip",
                        "count": {"$sum": 1},
                        "avg_score": {"$avg": "$ml_score"},
                    }
                },
                {"$sort": {"count": -1}},
                {"$limit": 20},
            ]

            cursor = self.ids_events_collection.aggregate(pipeline)
            results = await cursor.to_list(length=20)
            return [
                {
                    "ip": r["_id"],
                    "count": r["count"],
                    "avg_score": r["avg_score"],
                }
                for r in results
            ]
        except Exception as e:
            logger.error(f"[STORAGE] Failed to get anomalous IPs: {e}")
            return []

    async def get_recent_logs(
        self, src_ip: str, minutes_back: int
    ) -> List[Dict[str, Any]]:
        """Retrieve recent logs from MongoDB."""
        if not self._connected:
            return []

        try:
            cutoff = datetime.datetime.now(timezone.utc) - datetime.timedelta(
                minutes=minutes_back
            )
            query = {
                "src_ip": src_ip,
                "timestamp": {"$gte": cutoff.isoformat()},
            }
            cursor = self.logs_collection.find(query).sort("timestamp", -1).limit(1000)
            logs = await cursor.to_list(length=1000)
            return [log.pop("_id", None) or log for log in logs]
        except Exception as e:
            logger.error(f"[STORAGE] Failed to get recent logs: {e}")
            return []

    async def get_raw_logs_window(self, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Retrieve logs from MongoDB for a time window."""
        if not self._connected:
            return []

        try:
            cutoff = datetime.datetime.now(timezone.utc) - datetime.timedelta(
                hours=hours_back
            )
            query = {"timestamp": {"$gte": cutoff.isoformat()}}
            cursor = self.logs_collection.find(query).sort("timestamp", -1).limit(5000)
            logs = await cursor.to_list(length=5000)
            return [log.pop("_id", None) or log for log in logs]
        except Exception as e:
            logger.error(f"[STORAGE] Failed to get logs window: {e}")
            return []

    async def store_incident(self, incident: Dict[str, Any]):
        """Store a correlated incident in MongoDB."""
        if not self._connected:
            logger.warning("[STORAGE] MongoDB not connected, skipping incident store")
            return

        try:
            await self.incidents_collection.replace_one(
                {"incident_id": incident["incident_id"]},
                incident,
                upsert=True,
            )
            logger.info(f"[STORAGE] Stored incident: {incident['incident_id']}")
        except Exception as e:
            logger.error(f"[STORAGE] Failed to store incident: {e}")

    async def get_all_incidents(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Retrieve incidents from MongoDB."""
        if not self._connected:
            return []

        try:
            cursor = (
                self.incidents_collection.find().sort("start_time", -1).limit(limit)
            )
            incidents = await cursor.to_list(length=limit)
            return [incident.pop("_id", None) or incident for incident in incidents]
        except Exception as e:
            logger.error(f"[STORAGE] Failed to get incidents: {e}")
            return []

    async def store_response_action(self, action: Dict[str, Any]):
        """Persist SOAR response action to MongoDB."""
        if not self._connected:
            logger.warning("[STORAGE] MongoDB not connected, skipping response action")
            return

        try:
            await self.response_actions_collection.replace_one(
                {"id": action["id"]},
                action,
                upsert=True,
            )
            logger.info(f"[STORAGE] Stored response action: {action['id']}")
        except Exception as e:
            logger.error(f"[STORAGE] Failed to store response action: {e}")

    async def submit_feedback(
        self, incident_id: str, label: str, analyst: str = "system", notes: str = ""
    ):
        """Store analyst feedback in MongoDB."""
        if not self._connected:
            logger.warning("[STORAGE] MongoDB not connected, skipping feedback")
            return

        try:
            fb = Feedback(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                label=label,
                analyst=analyst,
                notes=notes,
            )
            await self.feedback_collection.insert_one(fb.model_dump())
            logger.info(f"[STORAGE] Stored feedback for incident: {incident_id}")
        except Exception as e:
            logger.error(f"[STORAGE] Failed to store feedback: {e}")

    async def update_model_version(self, version_data: Dict[str, Any]):
        """Store model training metadata in MongoDB."""
        if not self._connected:
            logger.warning("[STORAGE] MongoDB not connected, skipping model version")
            return

        try:
            await self.model_versions_collection.replace_one(
                {"version": version_data["version"]},
                version_data,
                upsert=True,
            )
            logger.info(f"[STORAGE] Stored model version: {version_data['version']}")
        except Exception as e:
            logger.error(f"[STORAGE] Failed to store model version: {e}")

    async def get_rule_score(self, sid: int) -> Optional[Dict[str, Any]]:
        if not self._connected:
            return None

        try:
            rule = await self.rule_scores_collection.find_one({"sid": sid})
            if rule:
                rule.pop("_id", None)
                return rule
            return None
        except Exception as e:
            logger.error(f"[STORAGE] Failed to get rule score: {e}")
            return None

    async def update_rule_hit(self, sid: int):
        if not self._connected:
            return

        try:
            result = await self.rule_scores_collection.find_one_and_update(
                {"sid": sid},
                {
                    "$inc": {"hit_count": 1},
                    "$set": {
                        "last_hit_at": datetime.datetime.now(timezone.utc).isoformat()
                    },
                },
                upsert=True,
            )
        except Exception as e:
            logger.error(f"[STORAGE] Failed to update rule hit: {e}")


_storage_instance: Optional[SIEMStorage] = None


def get_storage() -> SIEMStorage:
    """Get or create SIEM storage singleton."""
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = SIEMStorage()
    return _storage_instance
