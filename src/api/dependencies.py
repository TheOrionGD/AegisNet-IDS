from .repositories.sqlite_repo import SQLiteRepository
from .services.alert_service import AlertService
from .services.incident_service import IncidentService
from .services.ml_service import MLService
from config_loader import load_config
from pathlib import Path

def get_repository():
    config = load_config()
    db_path = config.get('siem', {}).get('db_path', 'data/siem.db')
    # If running from src/api, we might need to adjust relative path if it's not absolute
    return SQLiteRepository(db_path=db_path)

def get_alert_service():
    repo = get_repository()
    return AlertService(repo)

def get_incident_service():
    repo = get_repository()
    return IncidentService(repo)

def get_ml_service():
    repo = get_repository()
    return MLService(repo)
