from fastapi import APIRouter, Depends
from typing import List
from ..dependencies import get_anomaly_service
from ..services.anomaly_service import AnomalyService
from ..models.security_event import Anomaly

router = APIRouter()

@router.get("/anomalies", response_model=List[Anomaly])
async def get_anomalies(limit: int = 50, service: AnomalyService = Depends(get_anomaly_service)):
    """Retrieve ML-only outputs (Isolation Forest + LSTM)"""
    return service.get_anomalies(limit=limit)
