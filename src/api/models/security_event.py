from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class SecurityEvent(BaseModel):
    id: str
    timestamp: str
    source: str  # IDS, ML, SYSTEM, etc.
    type: str    # Alert type
    severity: str # LOW, MEDIUM, HIGH, CRITICAL
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    message: str
    ml_score: float = 0.0
    correlation_score: float = 0.0
    raw_payload: Optional[Dict[str, Any]] = None

class Incident(BaseModel):
    incident_id: str
    src_ip: str
    alert_count: int
    severity: str
    attack_pattern: List[str]
    start_time: str
    end_time: str
    cve_match: Optional[str] = ""
    known_exploit: bool = False

class Anomaly(BaseModel):
    timestamp: str
    source: str = "ML_ENGINE"
    src_ip: str
    anomaly_score: float
    model_type: str  # Isolation Forest, LSTM, etc.
    message: str

class HealthStatus(BaseModel):
    status: str
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    components: Dict[str, str]
