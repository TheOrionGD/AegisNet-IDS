from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from .repositories.sqlite_repo import SQLiteRepository
from .repositories.postgres_repo import PostgresRepository
from .services.alert_service import AlertService
from .services.incident_service import IncidentService
from .services.anomaly_service import AnomalyService
from config_loader import load_config
from pathlib import Path
from .models.base import Base

def get_database_url():
    """Get database URL from config."""
    config = load_config()
    return config.get('database', {}).get('url', 'sqlite:///data/siem.db')

def get_engine():
    """Get SQLAlchemy engine."""
    database_url = get_database_url()
    return create_engine(database_url)

def get_session_local():
    """Get session local factory."""
    engine = get_engine()
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

SessionLocal = None

def get_db():
    """Get database session."""
    session_local = get_session_local()
    db = session_local()
    try:
        yield db
    finally:
        db.close()

def get_repository():
    """Get appropriate repository based on database URL."""
    database_url = get_database_url()
    if database_url.startswith('postgresql'):
        return PostgresRepository(database_url)
    else:
        config = load_config()
        db_path = config.get('siem', {}).get('db_path', 'data/siem.db')
        return SQLiteRepository(db_path=db_path)

def get_alert_service():
    repo = get_repository()
    return AlertService(repo)

def get_incident_service():
    repo = get_repository()
    return IncidentService(repo)

def get_anomaly_service():
    repo = get_repository()
    return AnomalyService(repo)
