from fastapi import APIRouter
from ..models.security_event import HealthStatus
from datetime import datetime

router = APIRouter()


@router.get("/health", response_model=HealthStatus)
async def get_health():
    """Retrieve system status"""
    return HealthStatus(
        status="OK",
        version="5.0.0",
        components={
            "ids": "ENABLED",
            "ml_engine": "ENABLED",
            "correlation_engine": "ENABLED",
            "storage": "MongoDB",
        },
    )
