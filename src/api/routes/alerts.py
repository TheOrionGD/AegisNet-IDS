from fastapi import APIRouter, Depends, Query
from typing import List, Dict, Any
from ..dependencies import get_alert_service
from ..services.alert_service import AlertService
from ..models.security_event import SecurityEvent
from ..ws_manager import manager

router = APIRouter()

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
async def ingest_alert(alert: Dict[str, Any], service: AlertService = Depends(get_alert_service)):
    """Endpoint for Snort or other IDS to push raw logs"""
    log_id = service.ingest_alert(alert)
    
    # Broadcast to all connected SOC dashboards
    # In a production app, we'd fetch the normalized event first
    # For now, we broadcast the raw data with and added id
    alert['id'] = log_id
    await manager.broadcast(alert, event_type="alert")
    
    return {"status": "ingested", "id": log_id}
