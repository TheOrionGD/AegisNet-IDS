import datetime
import logging
from datetime import timezone
from typing import Dict, List
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    WebSocket connection manager for real-time event streaming.
    Supports multiple event types: alerts, incidents, ML detections, and IDS events.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"[WS] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"[WS] Client disconnected. Total: {len(self.active_connections)}"
            )

    async def send_to(
        self, websocket: WebSocket, message: dict, event_type: str = "alert"
    ):
        """Send message to a specific WebSocket client."""
        payload = {
            "type": event_type,
            "data": message,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        }
        try:
            await websocket.send_json(payload)
        except Exception as e:
            logger.error(f"[WS] Send error: {e}")

    async def broadcast(self, message: dict, event_type: str = "alert"):
        """
        Broadcast message to all connected clients.
        Supports event types: 'alert', 'incident', 'ml_alert', 'ids_alert', 'anomaly'.
        """
        payload = {
            "type": event_type,
            "data": message,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        }
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

    async def broadcast_ids_alert(self, alert: dict):
        """Broadcast IDS alert with priority handling."""
        await self.broadcast(alert, event_type="ids_alert")

    async def broadcast_anomaly(self, anomaly: dict):
        """Broadcast ML anomaly detection."""
        await self.broadcast(anomaly, event_type="anomaly")

    def get_connection_count(self) -> int:
        """Get number of active connections."""
        return len(self.active_connections)


manager = ConnectionManager()


class AnalysisConnectionManager:
    """Dedicated WebSocket manager for analysis streaming."""

    def __init__(self):
        self.analysis_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.analysis_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.analysis_connections:
            self.analysis_connections.remove(websocket)

    async def broadcast_analysis(self, message: dict):
        payload = {
            "type": "analysis",
            "data": message,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        }
        for conn in self.analysis_connections:
            try:
                await conn.send_json(payload)
            except Exception:
                pass


analysis_manager = AnalysisConnectionManager()
