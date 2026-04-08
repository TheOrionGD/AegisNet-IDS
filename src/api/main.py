from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
from datetime import datetime
from .routes import alerts, incidents, anomalies, health
from .dependencies import get_alert_service, get_incident_service
from .ws_manager import manager
import sys
from pathlib import Path

app = FastAPI(
    title="CNS SIEM API",
    description="SIEM-grade Security Information and Event Management API",
    version="5.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(alerts.router, tags=["Alerts"])
app.include_router(incidents.router, tags=["Incidents"])
app.include_router(anomalies.router, tags=["Anomalies"])
app.include_router(health.router, tags=["Health"])

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.on_event("startup")
async def startup_event():
    # In a full implementation, this could initialize connections or pre-load models
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
