from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from ..dependencies import get_anomaly_service
from ..services.anomaly_service import AnomalyService
from ..models.security_event import Anomaly
from core.realtime_ml import get_realtime_engine
from ..ws_manager import manager

router = APIRouter()


@router.get("/anomalies", response_model=List[Anomaly])
async def get_anomalies(
    limit: int = 50, service: AnomalyService = Depends(get_anomaly_service)
):
    """Retrieve ML-only outputs (Isolation Forest + LSTM)"""
    try:
        return service.get_anomalies(limit=limit)
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Error fetching anomalies: {e}")
        return []


@router.post("/infer")
async def infer_anomaly(event: Dict[str, Any]):
    """
    Real-time ML inference endpoint for anomaly detection.
    Returns anomaly score and risk level with WebSocket broadcast for high-confidence detections.
    """
    try:
        ml_engine = get_realtime_engine()
        result = ml_engine.predict_single(event)

        if result.get("is_anomaly") or result.get("anomaly_score", 0) >= 0.7:
            alert_payload = {
                "type": "anomaly_detection",
                "event": event,
                "ml_result": result,
            }
            await manager.broadcast(alert_payload, event_type="ml_alert")

        return {"status": "success", "result": result}
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Inference error: {e}")
        return {"status": "error", "message": str(e)}


@router.post("/infer/batch")
async def infer_batch(events: List[Dict[str, Any]]):
    """
    Batch ML inference for multiple events.
    Returns list of anomaly scores and risk levels.
    """
    results = []
    try:
        ml_engine = get_realtime_engine()
        for event in events:
            result = ml_engine.predict_single(event)
            results.append({"event": event, "result": result})

        return {"status": "success", "count": len(results), "results": results}
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Batch inference error: {e}")
        return {"status": "error", "message": str(e)}


@router.get("/model/status")
async def model_status():
    """Get ML model status and statistics."""
    try:
        ml_engine = get_realtime_engine()
        stats = ml_engine.get_stats()
        return {"status": "success", "model": stats}
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Model status error: {e}")
        return {"status": "error", "message": str(e)}
