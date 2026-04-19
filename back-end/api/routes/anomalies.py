from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any
from ..dependencies import get_anomaly_service
from ..services.anomaly_service import AnomalyService
from ..models.security_event import Anomaly
from core.realtime_ml import get_realtime_engine
from ..ws_manager import manager
from ..auth_guards import allow_analyst, allow_admin
import logging

router = APIRouter()

logger = logging.getLogger(__name__)


@router.get("/anomalies", response_model=list, dependencies=[Depends(allow_analyst)])
async def get_anomalies(
    limit: int = 50, service: AnomalyService = Depends(get_anomaly_service)
):
    """Retrieve ML-only outputs (Isolation Forest + LSTM)

    **Access Control:** Analyst, Admin
    """
    try:
        result = await service.get_anomalies(limit=limit)
        if result is None:
            logger.info("[anomalies] Result is None, returning []")
            return []
        logger.info(f"[anomalies] Returning {len(result)} anomalies")
        return result
    except Exception as e:
        logger.error(f"[anomalies] Error: {e}", exc_info=True)
        return []


@router.post("/infer", dependencies=[Depends(allow_analyst)])
async def infer_anomaly(event: Dict[str, Any]):
    """
    Real-time ML inference endpoint for anomaly detection.
    Returns anomaly score and risk level with WebSocket broadcast for high-confidence detections.

    **Access Control:** Analyst, Admin
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


@router.post("/infer/batch", dependencies=[Depends(allow_analyst)])
async def infer_batch(events: List[Dict[str, Any]]):
    """
    Batch ML inference for multiple events.
    Returns list of anomaly scores and risk levels.

    **Access Control:** Analyst, Admin
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


@router.get("/model/status", dependencies=[Depends(allow_analyst)])
async def model_status():
    """Get ML model status and statistics.

    **Access Control:** Analyst, Admin
    """
    try:
        ml_engine = get_realtime_engine()
        stats = ml_engine.get_stats()
        return {"status": "success", "model": stats}
    except Exception as e:
        import logging

        logging.getLogger(__name__).error(f"Model status error: {e}")
        return {"status": "error", "message": str(e)}
