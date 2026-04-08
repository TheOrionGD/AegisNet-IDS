from fastapi import APIRouter, Depends
from typing import List
from ..dependencies import get_ml_service
from ..services.ml_service import MLService
from ..models.security_event import Anomaly

router = APIRouter()

@router.get("/anomalies", response_model=List[Anomaly])
async def get_anomalies(limit: int = 50, service: MLService = Depends(get_ml_service)):
    """Retrieve ML-only outputs (Isolation Forest + LSTM)"""
    return service.get_anomalies(limit=limit)
