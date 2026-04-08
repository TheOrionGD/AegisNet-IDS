from fastapi import WebSocket
from datetime import datetime

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict, event_type: str = "alert"):
        payload = {
            "type": event_type,
            "data": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                pass

manager = ConnectionManager()
