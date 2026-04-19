import json
import logging
import asyncio
from typing import Dict, Any, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import timezone
import datetime

from core.realtime_ml import get_realtime_engine
from core.ip_reputation import get_reputation_tracker
from core.stream_processor import StreamEvent

logger = logging.getLogger(__name__)

router = APIRouter()


class AnalysisConnectionManager:
    """Manages WebSocket connections for real-time analysis."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(
            f"Analysis WebSocket connected. Active: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)
        logger.info(
            f"Analysis WebSocket disconnected. Active: {len(self.active_connections)}"
        )

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast analysis result to all connected clients."""
        payload = {
            "type": "analysis",
            "data": message,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        }
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
                self.disconnect(connection)


analysis_manager = AnalysisConnectionManager()


async def process_stream_event(event: StreamEvent) -> Dict[str, Any]:
    """Process a stream event through ML engine and reputation tracker."""
    engine = get_realtime_engine()
    tracker = get_reputation_tracker()

    event_dict = event.to_dict()
    result = engine.predict_single(event_dict)

    event_dict["anomaly_score"] = result.get("anomaly_score", 0.0)
    event_dict["is_anomaly"] = result.get("is_anomaly", False)
    event_dict["risk_level"] = result.get("risk_level", "LOW")

    tracker.track_event(
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        anomaly_score=result.get("anomaly_score", 0.0),
        is_anomaly=result.get("is_anomaly", False),
    )

    return {
        "timestamp": event.timestamp,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "pkt_len": event.pkt_len,
        "alert_msg": event.alert_msg,
        "anomaly_score": result.get("anomaly_score", 0.0),
        "is_anomaly": result.get("is_anomaly", False),
        "risk_level": result.get("risk_level", "LOW"),
    }


@router.websocket("/ws/analyze")
async def websocket_analyze(websocket: WebSocket):
    """WebSocket endpoint for real-time analysis streaming."""
    await analysis_manager.connect(websocket)

    engine = get_realtime_engine()
    tracker = get_reputation_tracker()

    try:
        while True:
            data = await websocket.receive_text()

            if data == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            try:
                event_data = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json(
                    {
                        "type": "error",
                        "data": {"error": "Invalid JSON"},
                    }
                )
                continue

            try:
                result = engine.predict_single(event_data)

                tracker.track_event(
                    src_ip=event_data.get("src_ip", ""),
                    dst_ip=event_data.get("dst_ip", ""),
                    src_port=event_data.get("src_port", 0),
                    dst_port=event_data.get("dst_port", 0),
                    protocol=event_data.get("protocol", "TCP"),
                    anomaly_score=result.get("anomaly_score", 0.0),
                    is_anomaly=result.get("is_anomaly", False),
                )

                response = {
                    "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
                    "src_ip": event_data.get("src_ip", ""),
                    "dst_ip": event_data.get("dst_ip", ""),
                    "anomaly_score": result.get("anomaly_score", 0.0),
                    "is_anomaly": result.get("is_anomaly", False),
                    "risk_level": result.get("risk_level", "LOW"),
                }

                await websocket.send_json(
                    {
                        "type": "analysis",
                        "data": response,
                    }
                )

                if result.get("is_anomaly"):
                    await analysis_manager.broadcast(response)

            except Exception as e:
                logger.error(f"Processing error: {e}")
                await websocket.send_json(
                    {
                        "type": "error",
                        "data": {"error": str(e)},
                    }
                )

    except WebSocketDisconnect:
        analysis_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        analysis_manager.disconnect(websocket)


@router.get("/stats")
async def get_stats():
    """Get streaming pipeline statistics."""
    engine = get_realtime_engine()
    tracker = get_reputation_tracker()
    return {
        "ml_engine": engine.get_stats(),
        "reputation_tracker": tracker.get_stats(),
        "websocket_connections": len(analysis_manager.active_connections),
    }


@router.get("/suspicious-ips")
async def get_suspicious_ips(limit: int = 10):
    """Get top suspicious IPs."""
    tracker = get_reputation_tracker()
    return {"ips": tracker.get_top_suspicious(limit=limit)}


@router.get("/anomalous-ips")
async def get_anomalous_ips(min_score: float = 0.5):
    """Get IPs with anomaly score above threshold."""
    tracker = get_reputation_tracker()
    return {"ips": tracker.get_anomalous_ips(min_score=min_score)}
