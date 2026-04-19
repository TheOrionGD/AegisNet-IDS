from .repositories.mongo_repo import MongoRepository
from .services.alert_service import AlertService
from .services.incident_service import IncidentService
from .services.anomaly_service import AnomalyService
from ..models.database import get_database
from config_loader import load_config


async def get_repository():
    """Get MongoDB repository."""
    # Ensure database is connected
    db = get_database()
    if db is None:
        from ..models.database import connect_to_mongo
        await connect_to_mongo()
    return MongoRepository()


def get_alert_service():
    # For sync services, but since repo is async, might need to adjust
    # For now, assuming services are updated to async
    pass  # Will update services later


def get_incident_service():
    pass  # Will update services later


def get_incident_service():
    repo = get_repository()
    return IncidentService(repo)


def get_anomaly_service():
    repo = get_repository()
    return AnomalyService(repo)
