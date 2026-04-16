import uuid
from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="analyst")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    source = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    severity = Column(Integer, nullable=False)
    message = Column(Text)
    raw_data = Column(JSON)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(Integer, nullable=False)
    status = Column(String, default="open")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    assignee = Column(String)

class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    event_id = Column(String(36), ForeignKey("security_events.id"), nullable=False)
    added_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    incident = relationship("Incident")
    event = relationship("SecurityEvent")

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    score = Column(Float, nullable=False)
    features = Column(JSON)
    prediction = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), nullable=False, index=True)
    label = Column(String, nullable=False)
    analyst = Column(String, default="system")
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(Text, default="")

class ModelVersion(Base):
    __tablename__ = "model_versions"
    version = Column(String(50), primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    contamination = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    drift_score = Column(Float)
    training_samples = Column(Integer)
    is_active = Column(Boolean, default=False)

class ResponseAction(Base):
    __tablename__ = "response_actions"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), nullable=False, index=True)
    severity_score = Column(Integer)
    action_type = Column(String)
    action_detail = Column(Text)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    state = Column(String, default="OPEN")
    output = Column(Text, default="")

class RuleScore(Base):
    __tablename__ = "rule_scores"
    sid = Column(Integer, primary_key=True)
    rule_text = Column(Text)
    hit_count = Column(Integer, default=0)
    effectiveness_score = Column(Float, default=0.5)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_hit_at = Column(DateTime(timezone=True))
    is_retired = Column(Boolean, default=False)