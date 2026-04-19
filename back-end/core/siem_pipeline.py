"""
Real-time SIEM Pipeline: Unified Event Processing
Snort → API → PostgreSQL → Elasticsearch → ML → WebSocket → Frontend
"""

import json
import logging
import uuid
import asyncio
import datetime
from datetime import timezone
from typing import Dict, Any, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class EventSource(Enum):
    SNORT = "snort"
    ML = "ml"
    SYSTEM = "system"
    EXTERNAL = "external"


class EventSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SIEMEvent:
    """
    Unified SIEM event schema for all event types.
    Provides normalization across Snort, ML, and system events.
    """

    def __init__(self, event_data: Dict[str, Any] = None):
        self.event_id = event_data.get("event_id") or str(uuid.uuid4())
        self.timestamp = (
            event_data.get("timestamp")
            or datetime.datetime.now(timezone.utc).isoformat()
        )

        # Network fields
        self.src_ip = event_data.get("src_ip", "0.0.0.0")
        self.dst_ip = event_data.get("dst_ip", "0.0.0.0")
        self.src_port = event_data.get("src_port", 0)
        self.dst_port = event_data.get("dst_port", 0)
        self.protocol = event_data.get("protocol", "TCP").upper()

        # Alert fields
        self.alert_type = event_data.get("alert_type", "GENERIC_ALERT")
        self.signature_id = event_data.get("signature_id", "0:0")
        self.severity = event_data.get("severity", "MEDIUM")

        # ML fields (optional)
        self.ml_score = event_data.get("ml_score", 0.0)
        self.ml_risk_level = event_data.get("ml_risk_level", "LOW")
        self.ml_is_anomaly = event_data.get("ml_is_anomaly", False)

        # Source
        self.source = event_data.get("source", "system")

        # Raw payload
        self.raw = event_data.get("raw", {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "alert_type": self.alert_type,
            "signature_id": self.signature_id,
            "severity": self.severity,
            "ml_score": self.ml_score,
            "ml_risk_level": self.ml_risk_level,
            "ml_is_anomaly": self.ml_is_anomaly,
            "source": self.source,
            "raw": self.raw,
        }

    def to_elasticsearch(self) -> Dict[str, Any]:
        """Convert for Elasticsearch indexing."""
        return self.to_dict()

    def to_frontend(self) -> Dict[str, Any]:
        """Convert for frontend WebSocket display."""
        return {
            "incident_id": self.event_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "incident_type": self.alert_type,
            "confidence": self.ml_score,
            "severity": self.severity,
            "ml_contributed": self.ml_is_anomaly,
            "start_time": self.timestamp,
            "end_time": None,
            "ml_score": self.ml_score,
            "risk_level": self.ml_risk_level,
            "source": self.source,
        }


class SIEMPipeline:
    """
    Main SIEM pipeline that processes events through all stages:
    1. Ingestion (Snort, ML, System)
    2. ML Anomaly Scoring
    3. PostgreSQL Storage
    4. Elasticsearch Indexing
    5. WebSocket Broadcast
    """

    def __init__(self):
        self._ml_engine = None
        self._storage = None
        self._ws_manager = None
        self._initialized = False
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    def initialize(self):
        """Initialize pipeline components."""
        try:
            from core.realtime_ml import get_realtime_engine

            self._ml_engine = get_realtime_engine()
            logger.info("[PIPELINE] ML Engine initialized")
        except Exception as e:
            logger.warning(f"[PIPELINE] ML Engine init failed: {e}")

        try:
            from siem.storage import SIEMStorage

            self._storage = SIEMStorage()
            logger.info(f"[PIPELINE] Storage initialized ({self._storage._es_mode})")
        except Exception as e:
            logger.warning(f"[PIPELINE] Storage init failed: {e}")

        try:
            from api.ws_manager import manager as ws_mgr

            self._ws_manager = ws_mgr
            logger.info("[PIPELINE] WebSocket manager initialized")
        except Exception as e:
            logger.warning(f"[PIPELINE] WS Manager init failed: {e}")

        self._initialized = True

    async def process_event(self, event: Dict[str, Any]) -> SIEMEvent:
        """
        Process event through full SIEM pipeline:
        1. Normalize to SIEMEvent
        2. Run ML scoring
        3. Store to PostgreSQL
        4. Index to Elasticsearch
        5. Broadcast to WebSocket
        """
        if not self._initialized:
            self.initialize()

        siem_event = SIEMEvent(event)

        # Run ML anomaly scoring
        if self._ml_engine and self._ml_engine._initialized:
            try:
                ml_result = self._ml_engine.predict_single(event)
                siem_event.ml_score = ml_result.get("anomaly_score", 0.0)
                siem_event.ml_risk_level = ml_result.get("risk_level", "LOW")
                siem_event.ml_is_anomaly = ml_result.get("is_anomaly", False)

                # Elevate severity if ML detects anomaly
                if siem_event.ml_is_anomaly and siem_event.severity in [
                    "LOW",
                    "MEDIUM",
                ]:
                    siem_event.severity = "HIGH"
            except Exception as e:
                logger.error(f"[PIPELINE] ML scoring error: {e}")

        # Store to PostgreSQL/SQLite
        if self._storage and self._storage._pg_mode in ["live", "stub"]:
            try:
                self._store_to_postgres(siem_event)
            except Exception as e:
                logger.error(f"[PIPELINE] PostgreSQL store error: {e}")

        # Index to Elasticsearch
        if self._storage and self._storage._es_mode == "live":
            try:
                self._storage.ingest_ids_event(siem_event.to_elasticsearch())
            except Exception as e:
                logger.error(f"[PIPELINE] ES index error: {e}")

        # Broadcast to WebSocket for frontend
        if self._ws_manager and (
            siem_event.ml_is_anomaly or siem_event.severity in ["HIGH", "CRITICAL"]
        ):
            try:
                await self._ws_manager.broadcast(
                    siem_event.to_frontend(), event_type="incident"
                )
                logger.info(
                    f"[PIPELINE] Broadcast: {siem_event.src_ip} -> {siem_event.dst_ip} [{siem_event.severity}]"
                )
            except Exception as e:
                logger.error(f"[PIPELINE] WS broadcast error: {e}")

        return siem_event

    def _store_to_postgres(self, event: SIEMEvent):
        """Store event to PostgreSQL/SQLite."""
        if not self._storage or not self._storage.SessionLocal:
            return

        try:
            with self._storage.engine.begin() as conn:
                from sqlalchemy import text

                conn.execute(
                    text("""
                    INSERT OR REPLACE INTO technical_incidents 
                    (incident_id, data, start_time) 
                    VALUES (:id, :data, :ts)
                """),
                    {
                        "id": event.event_id,
                        "data": json.dumps(event.to_dict()),
                        "ts": event.timestamp,
                    },
                )
        except Exception as e:
            logger.debug(f"[PIPELINE] Postgres store skipped: {e}")

    async def process_batch(self, events: List[Dict[str, Any]]) -> List[SIEMEvent]:
        """Process a batch of events."""
        results = []
        for event in events:
            result = await self.process_event(event)
            results.append(result)
        return results

    async def start_processor(self):
        """Start async event processor."""
        self._running = True
        self.initialize()
        logger.info("[PIPELINE] Event processor started")

        while self._running:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                await self.process_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"[PIPELINE] Processor error: {e}")

    def enqueue_event(self, event: Dict[str, Any]):
        """Enqueue event for async processing."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self._event_queue.put(event))
        except RuntimeError:
            pass

    def stop(self):
        """Stop the pipeline."""
        self._running = False
        logger.info("[PIPELINE] Pipeline stopped")


# Global pipeline instance
_pipeline: Optional[SIEMPipeline] = None


def get_siem_pipeline() -> SIEMPipeline:
    """Get or create the global SIEM pipeline."""
    global _pipeline
    if _pipeline is None:
        _pipeline = SIEMPipeline()
    return _pipeline


async def process_siem_event(event: Dict[str, Any]) -> SIEMEvent:
    """Process a single event through the pipeline."""
    pipeline = get_siem_pipeline()
    return await pipeline.process_event(event)


async def process_siem_batch(events: List[Dict[str, Any]]) -> List[SIEMEvent]:
    """Process a batch of events through the pipeline."""
    pipeline = get_siem_pipeline()
    return await pipeline.process_batch(events)
