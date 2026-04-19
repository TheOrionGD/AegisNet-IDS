import logging
from typing import Dict, Any, List, Optional
from datetime import timezone
import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.realtime_ml import get_realtime_engine
from core.ip_reputation import get_reputation_tracker
from siem.storage import SIEMStorage

logger = logging.getLogger(__name__)

router = APIRouter()


class EventInput(BaseModel):
    """Input model for single event analysis."""

    timestamp: Optional[str] = None
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = 0
    dst_port: Optional[int] = 0
    protocol: Optional[str] = "TCP"
    pkt_len: Optional[int] = 0
    alert_msg: Optional[str] = ""


class BatchInput(BaseModel):
    """Input model for batch event analysis."""

    events: List[EventInput]


class AnalysisResult(BaseModel):
    """Analysis result model."""

    timestamp: str
    src_ip: str
    dst_ip: str
    anomaly_score: float
    is_anomaly: bool
    risk_level: str


def _get_storage() -> Optional[SIEMStorage]:
    """Get SIEM storage instance."""
    try:
        return SIEMStorage()
    except Exception as e:
        logger.warning(f"Storage not available: {e}")
        return None


@router.post("/analyze", response_model=AnalysisResult)
async def analyze_event(event: EventInput):
    """
    Analyze a single network event for anomalies.
    Returns anomaly score and risk level.
    """
    engine = get_realtime_engine()
    tracker = get_reputation_tracker()

    event_dict = {
        "timestamp": event.timestamp or datetime.datetime.now(timezone.utc).isoformat(),
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port or 0,
        "dst_port": event.dst_port or 0,
        "protocol": event.protocol or "TCP",
        "pkt_len": event.pkt_len or 0,
    }

    result = engine.predict_single(event_dict)

    tracker.track_event(
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port or 0,
        dst_port=event.dst_port or 0,
        protocol=event.protocol or "TCP",
        anomaly_score=result.get("anomaly_score", 0.0),
        is_anomaly=result.get("is_anomaly", False),
    )

    storage = _get_storage()
    if storage and result.get("is_anomaly"):
        try:
            log_entry = {
                **event_dict,
                "alert_type": "ML_ANOMALY",
                "severity": result.get("risk_level", "LOW"),
                "anomaly_score": result.get("anomaly_score", 0.0),
            }
            storage.ingest_log(log_entry)
        except Exception as e:
            logger.warning(f"Storage write failed: {e}")

    return AnalysisResult(
        timestamp=event_dict["timestamp"],
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        anomaly_score=result.get("anomaly_score", 0.0),
        is_anomaly=result.get("is_anomaly", False),
        risk_level=result.get("risk_level", "LOW"),
    )


@router.post("/analyze-batch")
async def analyze_batch(batch: BatchInput):
    """
    Analyze a batch of network events.
    Processes up to 100 events per request.
    """
    engine = get_realtime_engine()
    tracker = get_reputation_tracker()
    storage = _get_storage()

    results = []
    anomalies = []

    for event in batch.events[:100]:
        event_dict = {
            "timestamp": event.timestamp
            or datetime.datetime.now(timezone.utc).isoformat(),
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port or 0,
            "dst_port": event.dst_port or 0,
            "protocol": event.protocol or "TCP",
            "pkt_len": event.pkt_len or 0,
        }

        result = engine.predict_single(event_dict)

        tracker.track_event(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            src_port=event.src_port or 0,
            dst_port=event.dst_port or 0,
            protocol=event.protocol or "TCP",
            anomaly_score=result.get("anomaly_score", 0.0),
            is_anomaly=result.get("is_anomaly", False),
        )

        analysis = AnalysisResult(
            timestamp=event_dict["timestamp"],
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            anomaly_score=result.get("anomaly_score", 0.0),
            is_anomaly=result.get("is_anomaly", False),
            risk_level=result.get("risk_level", "LOW"),
        )
        results.append(analysis)

        if result.get("is_anomaly"):
            anomalies.append(analysis)
            if storage:
                try:
                    log_entry = {
                        **event_dict,
                        "alert_type": "ML_ANOMALY",
                        "severity": result.get("risk_level", "LOW"),
                        "anomaly_score": result.get("anomaly_score", 0.0),
                    }
                    storage.ingest_log(log_entry)
                except Exception as e:
                    logger.warning(f"Storage write failed: {e}")

    return {
        "processed": len(results),
        "anomalies_detected": len(anomalies),
        "results": results,
    }


@router.get("/health")
async def health_check():
    """Health check for the analysis pipeline."""
    engine = get_realtime_engine()
    tracker = get_reputation_tracker()

    return {
        "status": "healthy",
        "ml_engine": engine.get_stats(),
        "reputation_tracker": tracker.get_stats(),
        "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
    }


@router.get("/stats")
async def get_pipeline_stats():
    """Get full pipeline statistics."""
    engine = get_realtime_engine()
    tracker = get_reputation_tracker()

    return {
        "ml_engine": engine.get_stats(),
        "reputation_tracker": tracker.get_stats(),
    }


@router.post("/reset")
async def reset_pipeline():
    """Reset the pipeline state."""
    engine = get_realtime_engine()
    if hasattr(engine, "_event_buffer"):
        engine._event_buffer.clear()

    tracker = get_reputation_tracker()
    tracker.clear()

    return {
        "status": "reset",
        "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
    }
