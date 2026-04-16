from sqlalchemy import create_engine, func, desc, text
from sqlalchemy.orm import sessionmaker, Session
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, UTC
from ..models.database import SecurityEvent, Incident, Anomaly, User
from .base_repo import BaseRepository

class PostgresRepository(BaseRepository):
    def __init__(self, database_url: str):
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            events = session.query(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit).all()
            return [
                {
                    "id": str(event.id),
                    "timestamp": event.timestamp.isoformat(),
                    "source": event.source,
                    "type": event.event_type,
                    "severity": self._severity_to_string(event.severity),
                    "message": event.message,
                    "raw_payload": event.raw_data
                }
                for event in events
            ]

    def get_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            incidents = session.query(Incident).order_by(desc(Incident.created_at)).limit(limit).all()
            return [
                {
                    "incident_id": str(incident.id),
                    "incident_type": "GENERIC",
                    "alert_count": 1,  # Simplified
                    "severity": self._severity_to_string(incident.severity),
                    "confidence": 0.8,  # Simplified
                    "attack_pattern": [],
                    "start_time": incident.created_at.isoformat(),
                    "end_time": incident.updated_at.isoformat() if incident.resolved_at else incident.created_at.isoformat(),
                    "title": incident.title,
                    "description": incident.description,
                    "status": incident.status
                }
                for incident in incidents
            ]

    def get_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            anomalies = session.query(Anomaly).order_by(desc(Anomaly.timestamp)).limit(limit).all()
            return [
                {
                    "timestamp": anomaly.timestamp.isoformat(),
                    "source": "ML_ENGINE",
                    "anomaly_score": anomaly.score,
                    "model_type": "Isolation Forest",
                    "message": f"Anomaly detected with score {anomaly.score}",
                    "features": anomaly.features
                }
                for anomaly in anomalies
            ]

    def get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            # Extract IPs from raw_data JSON and count occurrences
            result = session.execute(text("""
                SELECT 
                    (raw_data->>'src_ip') as ip,
                    COUNT(*) as count
                FROM security_events 
                WHERE raw_data->>'src_ip' IS NOT NULL
                GROUP BY raw_data->>'src_ip'
                ORDER BY count DESC
                LIMIT :limit
            """), {"limit": limit})
            
            return [
                {"ip": row[0], "count": row[1]}
                for row in result
            ]

    def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        with self.get_session() as session:
            since = datetime.now(UTC) - timedelta(hours=hours)
            result = session.execute(text("""
                SELECT 
                    DATE_TRUNC('hour', timestamp) as hour,
                    COUNT(*) as count
                FROM security_events 
                WHERE timestamp >= :since
                GROUP BY DATE_TRUNC('hour', timestamp)
                ORDER BY hour
            """), {"since": since})
            
            return [
                {"timestamp": row[0].isoformat(), "count": row[1]}
                for row in result
            ]

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user."""
        with self.get_session() as session:
            user = session.query(User).filter(User.username == username).first()
            if user and self._verify_password(password, user.password_hash):
                return user
        return None

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password (simplified - use proper hashing in production)."""
        # In production, use passlib or similar
        return plain_password == hashed_password  # Placeholder

    @staticmethod
    def _severity_to_string(severity: int) -> str:
        """Convert severity number to string."""
        mapping = {1: "LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
        return mapping.get(severity, "UNKNOWN")