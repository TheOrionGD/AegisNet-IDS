from fastapi import APIRouter, Depends
from typing import List
from ..dependencies import get_incident_service
from ..services.incident_service import IncidentService
from ..models.security_event import Incident

router = APIRouter()


@router.get("/incidents", response_model=List[Incident])
async def get_incidents(
    limit: int = 50, service: IncidentService = Depends(get_incident_service)
):
    """Retrieve correlated security events"""
    try:
        return service.get_incidents(limit=limit)
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Error fetching incidents: {e}")
        return []
