from fastapi import APIRouter, Depends, Query
from typing import List, Dict, Any
from ..dependencies import get_alert_service
from ..services.alert_service import AlertService
from ..models.security_event import SecurityEvent
from ..ws_manager import manager

from core.event_bus import bus
from core.siem_pipeline import get_siem_pipeline, process_siem_event, process_siem_batch
import datetime
from datetime import timezone

router = APIRouter()

# Simple In-Memory Rate Limiter (Stub for Production)
RATE_LIMIT_STORE = {}


async def check_rate_limit(client_id: str = "default"):
    """
    Basic Rate Limiter.
    In production, this should use Redis or a distributed counter.
    """
    now = datetime.datetime.now(timezone.utc).timestamp()
    if client_id not in RATE_LIMIT_STORE:
        RATE_LIMIT_STORE[client_id] = []

    # Keep only last 60 seconds
    RATE_LIMIT_STORE[client_id] = [
        t for t in RATE_LIMIT_STORE[client_id] if now - t < 60
    ]

    if len(RATE_LIMIT_STORE[client_id]) > 1000:  # 1000 events per minute
        return False

    RATE_LIMIT_STORE[client_id].append(now)
    return True


@router.get("/alerts", response_model=List[SecurityEvent])
async def get_alerts(
    limit: int = 50, service: AlertService = Depends(get_alert_service)
):
    """Retrieve normalized alerts (raw IDS + ML + system)"""
    try:
        return service.get_normalized_alerts(limit=limit)
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Error fetching alerts: {e}")
        return []


@router.get("/timeline")
async def get_timeline(
    hours: int = 24, service: AlertService = Depends(get_alert_service)
):
    """Retrieve time-series attack flow"""
    try:
        return {"status": "success", "data": service.get_timeline(hours=hours)}
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Error fetching timeline: {e}")
        return {"status": "success", "data": []}


@router.get("/ips/top")
async def get_top_ips(
    limit: int = 10, service: AlertService = Depends(get_alert_service)
):
    """Retrieve top attacker IPs"""
    try:
        return {"status": "success", "data": service.get_top_ips(limit=limit)}
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Error fetching top IPs: {e}")
        return {"status": "success", "data": []}


@router.post("/ingest")
async def ingest_alert(alert: Dict[str, Any]):
    """
    Production-grade Ingestion Endpoint with full SIEM pipeline processing.
    Snort → API → PostgreSQL → Elasticsearch → ML → WebSocket
    """
    if not await check_rate_limit():
        return {"status": "dropped", "reason": "rate_limit_exceeded"}

    if "timestamp" not in alert:
        alert["timestamp"] = datetime.datetime.now(timezone.utc).isoformat()

    alert["source"] = "snort"

    try:
        processed = await process_siem_event(alert)
        return {
            "status": "processed",
            "event_id": processed.event_id,
            "ml_score": processed.ml_score,
            "ml_risk_level": processed.ml_risk_level,
            "is_anomaly": processed.ml_is_anomaly,
            "timestamp": processed.timestamp,
        }
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Pipeline error: {e}")
        await bus.publish("raw_alert", alert)
        return {
            "status": "published",
            "id": alert.get("pkt_num", "N/A"),
            "timestamp": alert["timestamp"],
        }


@router.post("/ingest/batch")
async def ingest_batch(alerts: List[Dict[str, Any]]):
    """Batch ingestion with full SIEM pipeline processing."""
    processed = 0
    processed_events = []

    for alert in alerts:
        if not await check_rate_limit():
            break
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.datetime.now(timezone.utc).isoformat()
        alert["source"] = "snort"

        try:
            processed = await process_siem_event(alert)
            processed_events.append(processed)
        except Exception as e:
            import logging

            logging.getLogger(__name__).error(f"Batch pipeline error: {e}")
            await bus.publish("raw_alert", alert)
        processed += 1

    return {
        "status": "processed",
        "count": processed,
        "anomalies": sum(1 for e in processed_events if e.ml_is_anomaly),
    }
