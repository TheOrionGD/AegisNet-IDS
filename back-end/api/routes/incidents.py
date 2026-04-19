from fastapi import APIRouter, Depends, HTTPException
from typing import List
import logging
from ..dependencies import get_incident_service
from ..services.incident_service import IncidentService
from ..models.security_event import Incident
from ..auth_guards import allow_analyst, allow_admin, allow_incident_management

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/incidents", response_model=List[Incident], dependencies=[Depends(allow_analyst)])
async def get_incidents(
    limit: int = 50, service: IncidentService = Depends(get_incident_service)
):
    """Retrieve correlated security incidents.
    
    **Access Control:** Analyst, Admin
    """
    try:
        return await service.get_incidents(limit=limit)
    except Exception as e:
        logger.error(f"Error fetching incidents: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch incidents. Please try again.")
