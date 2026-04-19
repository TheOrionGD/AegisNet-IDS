from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import json
import asyncio
from pathlib import Path
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional

sys.path.append(str(Path(__file__).parent.parent))
from config_loader import load_config
from siem.storage import get_storage
from api.models.database import MONGODB_URL, DATABASE_NAME

app = FastAPI(
    title="CNS SIEM Dashboard API",
    description="Phase 3+4 SOC Dashboard: incidents, threat intel, posture, hunts",
    version="4.0.0",
)

_storage = None


def get_storage_instance():
    global _storage
    if _storage is None:
        _storage = get_storage()
    return _storage


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


async def poll_new_events():
    last_log_time = None
    last_incident_time = None

    try:
        storage = get_storage_instance()
        collection = storage.db["ids_events"]
        cursor = collection.find().sort("timestamp", -1).limit(1)
        events = await cursor.to_list(length=1)
        if events:
            last_log_time = events[0].get("timestamp")

        inc_collection = storage.db["incidents"]
        cursor = inc_collection.find().sort("start_time", -1).limit(1)
        incidents = await cursor.to_list(length=1)
        if incidents:
            last_incident_time = incidents[0].get("start_time")
    except Exception as e:
        print(f"Error initializing event times: {e}")
        last_log_time = "1970-01-01"
        last_incident_time = "1970-01-01"

    while True:
        await asyncio.sleep(2)
        if not manager.active_connections:
            continue

        events_to_broadcast = []
        try:
            storage = get_storage_instance()

            if last_log_time:
                cursor = (
                    storage.db["ids_events"]
                    .find({"timestamp": {"$gt": last_log_time}})
                    .sort("timestamp", 1)
                )
            else:
                cursor = storage.db["ids_events"].find().sort("timestamp", 1).limit(50)

            logs = await cursor.to_list(length=100)
            for row in logs:
                last_log_time = max(last_log_time or "", row.get("timestamp", ""))

                evt_type = "ML" if row.get("is_anomaly", False) else "IDS"
                score = row.get("ml_score", 0.0)

                events_to_broadcast.append(
                    {
                        "timestamp": row.get("timestamp"),
                        "type": evt_type,
                        "severity": row.get("severity", "LOW"),
                        "source_ip": row.get("src_ip"),
                        "message": row.get("alert_type", "EVENT"),
                        "score": score,
                    }
                )

            if last_incident_time:
                cursor = (
                    storage.db["incidents"]
                    .find({"start_time": {"$gt": last_incident_time}})
                    .sort("start_time", 1)
                )
            else:
                cursor = storage.db["incidents"].find().sort("start_time", 1).limit(10)

            incidents = await cursor.to_list(length=50)
            for row in incidents:
                last_incident_time = max(
                    last_incident_time or "", row.get("start_time", "")
                )

                events_to_broadcast.append(
                    {
                        "timestamp": row.get("start_time"),
                        "type": "CORRELATION",
                        "severity": row.get("severity", "LOW"),
                        "source_ip": row.get("src_ip", ""),
                        "message": f"Incident {row.get('incident_id', 'unknown')} matched.",
                        "score": float(row.get("alert_count", 1)),
                    }
                )

            for evt in events_to_broadcast:
                await manager.broadcast(evt)

        except Exception as e:
            print(f"Error in background task: {e}")


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(poll_new_events())


@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/dashboard/incidents")
async def get_incidents(limit: int = 50):
    try:
        storage = get_storage_instance()
        cursor = storage.db["incidents"].find().sort("start_time", -1).limit(limit)
        results = await cursor.to_list(length=limit)
        for r in results:
            r.pop("_id", None)
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/ips")
async def get_top_ips(limit: int = 10):
    try:
        storage = get_storage_instance()
        pipeline = [
            {"$match": {"src_ip": {"$exists": True, "$ne": ""}}},
            {"$group": {"_id": "$src_ip", "alert_count": {"$sum": 1}}},
            {"$sort": {"alert_count": -1}},
            {"$limit": limit},
        ]
        cursor = storage.db["ids_events"].aggregate(pipeline)
        results = await cursor.to_list(length=limit)
        results = [
            {"src_ip": r["_id"], "alert_count": r["alert_count"]} for r in results
        ]
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/timeline")
async def get_timeline():
    try:
        storage = get_storage_instance()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff}}},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d %H:00:00",
                            "date": {"$toDate": "$timestamp"},
                        }
                    },
                    "volume": {"$sum": 1},
                }
            },
            {"$sort": {"_id": -1}},
            {"$limit": 24},
        ]
        cursor = storage.db["ids_events"].aggregate(pipeline)
        results = await cursor.to_list(length=24)
        results = [{"time_bucket": r["_id"], "volume": r["volume"]} for r in results]
        return {"status": "success", "data": results[::-1]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/posture")
async def get_security_posture():
    try:
        from siem.security_posture import SecurityPostureEngine

        engine = SecurityPostureEngine()
        posture = engine.compute_posture()
        return {"status": "success", "data": posture}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/posture/history")
async def get_posture_history(limit: int = 48):
    try:
        storage = get_storage_instance()
        cursor = (
            storage.db["security_posture"].find().sort("computed_at", -1).limit(limit)
        )
        results = await cursor.to_list(length=limit)
        for r in results:
            r.pop("_id", None)
        return {"status": "success", "count": len(results), "data": results[::-1]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/hunts")
async def get_hunt_results(limit: int = 50, hunt_type: Optional[str] = None):
    try:
        storage = get_storage_instance()
        query = {}
        if hunt_type:
            query["hunt_type"] = hunt_type
        cursor = (
            storage.db["hunt_results"].find(query).sort("detected_at", -1).limit(limit)
        )
        results = await cursor.to_list(length=limit)
        for r in results:
            r.pop("_id", None)
            if isinstance(r.get("details"), str):
                try:
                    r["details"] = json.loads(r["details"])
                except:
                    pass
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class FeedbackRequest(BaseModel):
    incident_id: str
    label: str
    analyst: str = "analyst"
    notes: str = ""


@app.post("/phase4/feedback")
async def submit_feedback(req: FeedbackRequest):
    try:
        storage = get_storage_instance()
        from datetime import datetime

        feedback_doc = {
            "id": str(datetime.now(timezone.utc).timestamp()),
            "incident_id": req.incident_id,
            "label": req.label,
            "analyst": req.analyst,
            "notes": req.notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await storage.db["feedback"].insert_one(feedback_doc)
        return {"status": "success", "feedback_id": feedback_doc["id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/feedback")
async def get_feedback(limit: int = 50):
    try:
        storage = get_storage_instance()
        cursor = storage.db["feedback"].find().sort("timestamp", -1).limit(limit)
        results = await cursor.to_list(length=limit)
        for r in results:
            r.pop("_id", None)
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/responses")
async def get_response_actions(limit: int = 50):
    try:
        storage = get_storage_instance()
        cursor = (
            storage.db["response_actions"].find().sort("executed_at", -1).limit(limit)
        )
        results = await cursor.to_list(length=limit)
        for r in results:
            r.pop("_id", None)
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/model-versions")
async def get_model_versions():
    try:
        storage = get_storage_instance()
        cursor = storage.db["model_versions"].find().sort("trained_at", -1).limit(20)
        results = await cursor.to_list(length=20)
        for r in results:
            r.pop("_id", None)
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/rule-scores")
async def get_rule_scores(retired: bool = False):
    try:
        storage = get_storage_instance()
        query = {} if retired else {"is_retired": False}
        cursor = storage.db["rule_scores"].find(query).sort("effectiveness_score", -1)
        results = await cursor.to_list(length=100)
        for r in results:
            r.pop("_id", None)
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
