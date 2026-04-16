from fastapi import APIRouter, Depends, Query
from typing import List, Dict, Any
from ..dependencies import get_alert_service
from ..services.alert_service import AlertService
from ..models.security_event import SecurityEvent
from ..ws_manager import manager

from core.event_bus import bus
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
    RATE_LIMIT_STORE[client_id] = [t for t in RATE_LIMIT_STORE[client_id] if now - t < 60]
    
    if len(RATE_LIMIT_STORE[client_id]) > 1000: # 1000 events per minute
        return False
    
    RATE_LIMIT_STORE[client_id].append(now)
    return True

@router.get("/alerts", response_model=List[SecurityEvent])
async def get_alerts(limit: int = 50, service: AlertService = Depends(get_alert_service)):
    """Retrieve normalized alerts (raw IDS + ML + system)"""
    return service.get_normalized_alerts(limit=limit)

@router.get("/timeline")
async def get_timeline(hours: int = 24, service: AlertService = Depends(get_alert_service)):
    """Retrieve time-series attack flow"""
    return {"status": "success", "data": service.get_timeline(hours=hours)}

@router.get("/ips/top")
async def get_top_ips(limit: int = 10, service: AlertService = Depends(get_alert_service)):
    """Retrieve top attacker IPs"""
    return {"status": "success", "data": service.get_top_ips(limit=limit)}


@router.post("/ingest")
async def ingest_alert(alert: Dict[str, Any]):
    """
    Production-grade Ingestion Endpoint.
    Includes rate-limiting (Issue 5), timestamp normalization, and async bus publishing.
    """
    # 1. Backpressure Check
    if not await check_rate_limit():
        return {"status": "dropped", "reason": "rate_limit_exceeded"}

    # 2. Normalization
    if 'timestamp' not in alert:
        alert['timestamp'] = datetime.datetime.now(timezone.utc).isoformat()
    
    # 3. Distributed Pub/Sub
    await bus.publish("raw_alert", alert)
    
    return {
        "status": "published",
        "id": alert.get('pkt_num', 'N/A'), # Snort 3 pkt_num
        "timestamp": alert['timestamp']
    }

@router.post("/ingest/batch")
async def ingest_batch(alerts: List[Dict[str, Any]]):
    """Batch ingestion for high-throughput collectors."""
    processed = 0
    for alert in alerts:
        if not await check_rate_limit():
            break
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.datetime.now(timezone.utc).isoformat()
        await bus.publish("raw_alert", alert)
        processed += 1
    
    return {"status": "published", "count": processed}
