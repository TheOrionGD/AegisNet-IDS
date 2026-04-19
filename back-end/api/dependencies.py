from fastapi import HTTPException
from .repositories.mongo_repo import MongoRepository
from .services.alert_service import AlertService
from .services.incident_service import IncidentService
from .services.anomaly_service import AnomalyService
from .models.database import get_database, connect_to_mongo
from config_loader import load_config
import logging

logger = logging.getLogger(__name__)


async def get_repository() -> MongoRepository:
    """Get MongoDB repository, connecting if necessary."""
    db = get_database()
    if db is None:
        logger.warning("[deps] DB not connected — attempting reconnect...")
        await connect_to_mongo()
        db = get_database()
        if db is None:
            logger.error("[deps] Database connection unavailable after retry")
            raise HTTPException(
                status_code=503, detail="Database connection unavailable"
            )
    return MongoRepository()


async def get_alert_service() -> AlertService:
    """Dependency: AlertService backed by MongoDB."""
    repo = await get_repository()
    return AlertService(repo)


async def get_incident_service() -> IncidentService:
    """Dependency: IncidentService backed by MongoDB."""
    repo = await get_repository()
    return IncidentService(repo)


async def get_anomaly_service() -> AnomalyService:
    """Dependency: AnomalyService backed by MongoDB."""
    repo = await get_repository()
    return AnomalyService(repo)
