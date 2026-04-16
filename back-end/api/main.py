from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import datetime
import os
from datetime import timezone
from pathlib import Path
from .routes import alerts, incidents, anomalies, health, auth
from .dependencies import get_alert_service, get_incident_service, get_engine
from .models.database import Base
from .ws_manager import manager
from core.event_bus import bus
from core.worker import worker
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()

import logging
logger = logging.getLogger(__name__)

# Initialize Infrastructure on Startup with Retry Logic
def verify_infrastructure(max_retries=15, delay=3):
    """Ensures all backend services (Postgres, Redis, ES) are reachable."""
    engine = get_engine()
    db_ready = False
    
    # 1. Database (PostgreSQL or fallback SQLite)
    for i in range(max_retries):
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("[STARTUP] Database connected and schema verified.")
            db_ready = True
            break
        except Exception as e:
            if i < max_retries - 1:
                logger.warning(f"[STARTUP] Database not ready ({i+1}/{max_retries}), retrying in {delay}s...")
                time.sleep(delay)
            else:
                logger.error("[STARTUP] Could not connect to database.")
                database_url = get_engine().url
                if database_url.drivername.startswith('postgresql'):
                    fallback_path = Path(__file__).resolve().parents[1] / 'data' / 'siem.db'
                    fallback_url = f"sqlite:///{fallback_path.as_posix()}"
                    os.environ['DATABASE_URL'] = fallback_url
                    logger.warning(f"[STARTUP] Falling back to local SQLite database at {fallback_path}.")
                    engine = get_engine()
                    Base.metadata.create_all(bind=engine)
                    logger.info("[STARTUP] Local SQLite database initialized.")
                    db_ready = True
                else:
                    raise e

    # 2. Redis & Elasticsearch check will happen inside services on instantiation
    # but we can do a quick check here to log status
    from siem.storage import SIEMStorage
    try:
        storage = SIEMStorage()
        logger.info(f"[STARTUP] Storage System initialized in {storage._es_mode} mode.")
    except Exception as e:
        logger.error(f"[STARTUP] Storage System failure: {e}")

    return engine

engine = verify_infrastructure()

app = FastAPI(
    title="CNS SIEM API",
    description="Event-Driven SOC-grade SIEM + SOAR Platform",
    version="6.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global task tracker
background_tasks = set()

async def broadcast_incident(incident: dict):
    """Reliably broadcasts incidents to the React dashboard."""
    try:
        await manager.broadcast(incident, event_type="incident")
    except Exception:
        pass

@app.on_event("startup")
async def startup_event():
    # 1. Initialize Persistent Event Bus
    await bus.initialize()

    # 2. Start Event Bus Consumer (Dashboard Group)
    bus.subscribe("incident", broadcast_incident)
    bus_task = asyncio.create_task(bus.consume(group="dashboard_group"))
    background_tasks.add(bus_task)
    bus_task.add_done_callback(background_tasks.discard)

    logger.info("CNS SIEM API: Persistence layer ready.")



@app.on_event("shutdown")
async def shutdown_event():
    bus.stop()
    for task in background_tasks:
        task.cancel()
    logger.info("CNS SIEM Backend: Stopped background workers.")

# Root info
@app.get("/")
async def root():
    return {
        "message": "CNS AegisNet SIEM API is ONLINE",
        "docs": "/docs",
        "status": "active",
        "timestamp": datetime.datetime.now(timezone.utc).isoformat()
    }

# Include Routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
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

if __name__ == "__main__":
    import uvicorn
    import logging
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get('API_PORT', 2345))
    uvicorn.run(app, host="0.0.0.0", port=port)

