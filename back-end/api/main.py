from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import asyncio
import json
import datetime
import os
from datetime import timezone
from pathlib import Path
from .routes import (
    alerts,
    incidents,
    anomalies,
    health,
    auth,
    analysis,
    websocket as ws_routes,
)
from .dependencies import get_alert_service, get_incident_service
from .models.database import connect_to_mongo
from .ws_manager import manager
from core.event_bus import bus
from core.worker import worker
from core.realtime_ml import get_realtime_engine
from core.siem_pipeline import get_siem_pipeline
from dotenv import load_dotenv
import time

# ── Root .env resolution ───────────────────────────────────────────────────────
# This file lives at  <project-root>/back-end/api/main.py
#   parents[0] = back-end/api/
#   parents[1] = back-end/
#   parents[2] = project root  (E:\PROJECTS\CNS)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(dotenv_path=_PROJECT_ROOT / ".env", override=False)
# ──────────────────────────────────────────────────────────────────────────────

import logging

logger = logging.getLogger(__name__)


# Initialize Infrastructure on Startup with Retry Logic
async def verify_infrastructure(max_retries=3, delay=1):
    """Ensures MongoDB Atlas is reachable."""
    db_ready = False

    # 1. Database (MongoDB Atlas)
    for i in range(max_retries):
        try:
            await connect_to_mongo()
            logger.info("[STARTUP] MongoDB Atlas connected.")
            db_ready = True
            break
        except Exception as e:
            if i < max_retries - 1:
                logger.warning(
                    f"[STARTUP] MongoDB not ready ({i + 1}/3), retrying in 1s... {e}"
                )
                await asyncio.sleep(delay)
            else:
                logger.error(f"[STARTUP] Could not connect to MongoDB Atlas: {e}")
                raise e

    # 2. Redis & Elasticsearch check will happen inside services on instantiation
    # but we can do a quick check here to log status
    from siem.storage import SIEMStorage

    try:
        storage = SIEMStorage()
        logger.info(f"[STARTUP] Storage System initialized.")
    except Exception as e:
        logger.error(f"[STARTUP] Storage System failure: {e}")

    return db_ready


engine = None  # Placeholder, will be set in startup

app = FastAPI(
    title="CNS SIEM API",
    description="Event-Driven SOC-grade SIEM + SOAR Platform",
    version="6.0.0",
)

# CORS — allow dev server and backend-host-accessed frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:1234",
        "http://localhost:3000",
        "http://127.0.0.1:1234",
        "http://10.169.17.117:1234",  # Frontend accessed via backend host IP
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


class EnsureCORSHeadersMiddleware(BaseHTTPMiddleware):
    """
    Fallback middleware that ensures CORS headers are present on all responses,
    including error responses from exception handlers.
    """

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        origin = request.headers.get("origin")
        allowed_origins = [
            "http://localhost:1234",
            "http://localhost:3000",
            "http://127.0.0.1:1234",
            "http://10.169.17.117:1234",
        ]
        # If the request origin is in our allowed list and the header is missing, add it
        if (
            origin in allowed_origins
            and "access-control-allow-origin" not in response.headers
        ):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response


app.add_middleware(EnsureCORSHeadersMiddleware)


# Global exception handler — ensures CORS headers are always present on 500 responses
from fastapi import Request
from fastapi.responses import JSONResponse


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
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
    # 0. Verify Infrastructure (DB, Storage, etc.)
    await verify_infrastructure()

    # 1. Initialize Persistent Event Bus
    await bus.initialize()

    # 2. Start Event Bus Consumer (Dashboard Group)
    bus.subscribe("incident", broadcast_incident)
    bus_task = asyncio.create_task(bus.consume(group="dashboard_group"))
    background_tasks.add(bus_task)
    bus_task.add_done_callback(background_tasks.discard)

    # 3. Initialize heavy components (ML Engine, SIEM Pipeline) in background
    async def init_ml_engine():
        try:
            engine = get_realtime_engine()
            engine.load_models()
            logger.info("Realtime ML Engine initialized")
        except Exception as e:
            logger.error(f"ML Engine initialization failed: {e}", exc_info=True)

    async def init_siem_pipeline():
        try:
            pipeline = get_siem_pipeline()
            pipeline.initialize()
            logger.info("SIEM Pipeline initialized")
        except Exception as e:
            logger.error(f"SIEM Pipeline initialization failed: {e}", exc_info=True)

    ml_task = asyncio.create_task(init_ml_engine())
    pipeline_task = asyncio.create_task(init_siem_pipeline())
    background_tasks.add(ml_task)
    background_tasks.add(pipeline_task)
    ml_task.add_done_callback(background_tasks.discard)
    pipeline_task.add_done_callback(background_tasks.discard)

    logger.info("CNS SIEM API: Persistence layer ready. Background services starting.")


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
        "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
    }


# Include Routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(alerts.router, tags=["Alerts"])
app.include_router(incidents.router, tags=["Incidents"])
app.include_router(anomalies.router, tags=["Anomalies"])
app.include_router(health.router, tags=["Health"])
app.include_router(analysis.router, prefix="/detect", tags=["Detection"])
app.include_router(ws_routes.router, tags=["Streaming"])


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
    port = int(os.environ.get("API_PORT", 2346))
    uvicorn.run(app, host="0.0.0.0", port=port)
