from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import sqlite3
import json
import asyncio
from pathlib import Path
import sys

# Hack to allow running directly from src/siem/
sys.path.append(str(Path(__file__).parent.parent))
from config_loader import load_config

app = FastAPI(
    title="CNS SIEM Dashboard API",
    description="Phase 3+4 SOC Dashboard: incidents, threat intel, posture, hunts",
    version="4.0.0",
)


def get_db_connection():
    config = load_config()
    db_path = config.get('siem', {}).get('db_path', 'data/siem.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# ── WebSocket Manager ────────────────────────────────────────────────────────

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
    """Background task to poll SQLite for new events and broadcast them via WebSockets."""
    last_log_time = None
    last_incident_time = None
    
    # Initialize from current DB state
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(timestamp) as m from raw_logs")
        row = cursor.fetchone()
        if row and row['m']:
            last_log_time = row['m']
            
        cursor.execute("SELECT MAX(start_time) as m from incidents")
        row = cursor.fetchone()
        if row and row['m']:
            last_incident_time = row['m']
        conn.close()
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
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Fetch new logs
            if last_log_time:
                cursor.execute("SELECT * from raw_logs WHERE timestamp > ? ORDER BY timestamp ASC", (last_log_time,))
            else:
                cursor.execute("SELECT * from raw_logs ORDER BY timestamp ASC LIMIT 50")
            
            logs = cursor.fetchall()
            for row in logs:
                r = dict(row)
                last_log_time = max(last_log_time or "", r['timestamp'])
                
                evt_type = "ML" if r['alert_type'] == "ML_ANOMALY" else "IDS"
                score = 0.0
                if evt_type == "ML" and r['raw_payload']:
                    try:
                        p = json.loads(r['raw_payload'])
                        score = float(p.get("anomaly_score", 0.0))
                    except:
                        pass
                
                events_to_broadcast.append({
                    "timestamp": r['timestamp'],
                    "type": evt_type,
                    "severity": r['severity'],
                    "source_ip": r['src_ip'],
                    "message": r['alert_type'],
                    "score": score
                })
                
            # Fetch new incidents
            if last_incident_time:
                cursor.execute("SELECT * from incidents WHERE start_time > ? ORDER BY start_time ASC", (last_incident_time,))
            else:
                cursor.execute("SELECT * from incidents ORDER BY start_time ASC LIMIT 10")
                
            incidents = cursor.fetchall()
            for row in incidents:
                r = dict(row)
                last_incident_time = max(last_incident_time or "", r['start_time'])
                
                events_to_broadcast.append({
                    "timestamp": r['start_time'],
                    "type": "CORRELATION",
                    "severity": r['severity'],
                    "source_ip": r['src_ip'],
                    "message": f"Incident {r['incident_id']} matched. {r['alert_count']} alerts.",
                    "score": float(r['alert_count'])
                })
                
            conn.close()
            
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
    # Give the client some initial context immediately if wanted, or just wait for live
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── Phase 3 endpoints (unchanged) ────────────────────────────────────────────

@app.get("/dashboard/incidents")
def get_incidents(limit: int = 50):
    """Retrieve top incidents (correlated events)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY start_time DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            record = dict(row)
            try:
                record['attack_pattern'] = json.loads(record['attack_pattern'])
            except:
                record['attack_pattern'] = []
            results.append(record)
            
        conn.close()
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/ips")
def get_top_ips(limit: int = 10):
    """Retrieve top attacker IPs based on raw logs"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT src_ip, COUNT(*) as alert_count 
            FROM raw_logs 
            GROUP BY src_ip 
            ORDER BY alert_count DESC 
            LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        
        results = [dict(row) for row in rows]
        conn.close()
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/timeline")
def get_timeline():
    """Retrieve alert volume aggregated by hour"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket, COUNT(*) as volume
            FROM raw_logs
            GROUP BY time_bucket
            ORDER BY time_bucket DESC
            LIMIT 24
        ''')
        rows = cursor.fetchall()
        
        results = [dict(row) for row in rows]
        conn.close()
        return {"status": "success", "data": results[::-1]}  # Return chronological
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Phase 4 endpoints ─────────────────────────────────────────────────────────

@app.get("/phase4/posture")
def get_security_posture():
    """
    Real-time Global Security Posture:
    Returns risk_score (0-100), threat_level, and component breakdown.
    """
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from phase4.security_posture import SecurityPostureEngine
        config = load_config()
        db_path = config.get('siem', {}).get('db_path', 'data/siem.db')
        engine = SecurityPostureEngine(db_path=db_path)
        posture = engine.compute_posture()
        return {"status": "success", "data": posture}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/posture/history")
def get_posture_history(limit: int = 48):
    """Historical security posture snapshots for trend charts."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM security_posture ORDER BY computed_at DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            record = dict(row)
            try:
                record['components'] = json.loads(record.get('components_json', '{}'))
            except Exception:
                record['components'] = {}
            results.append(record)
        conn.close()
        return {"status": "success", "count": len(results), "data": results[::-1]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/hunts")
def get_hunt_results(limit: int = 50, hunt_type: str = None):
    """Retrieve recent threat hunting findings, optionally filtered by type."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if hunt_type:
            cursor.execute(
                "SELECT * FROM hunt_results WHERE hunt_type = ? "
                "ORDER BY detected_at DESC LIMIT ?",
                (hunt_type, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM hunt_results ORDER BY detected_at DESC LIMIT ?",
                (limit,)
            )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            record = dict(row)
            try:
                record['details'] = json.loads(record.get('details', '{}'))
            except Exception:
                record['details'] = {}
            results.append(record)
        conn.close()
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class FeedbackRequest(BaseModel):
    incident_id: str
    label: str  # TRUE_POSITIVE | FALSE_POSITIVE | UNKNOWN
    analyst: str = "analyst"
    notes: str = ""


@app.post("/phase4/feedback")
def submit_feedback(req: FeedbackRequest):
    """
    Submit analyst feedback for an incident (human-in-the-loop).
    Triggers threshold adjustment when enough feedback accumulates.
    """
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from phase4.feedback_loop import FeedbackLoop
        config = load_config()
        db_path = config.get('siem', {}).get('db_path', 'data/siem.db')
        fb = FeedbackLoop(db_path=db_path)
        record = fb.submit_feedback(
            incident_id=req.incident_id,
            label=req.label,
            analyst=req.analyst,
            notes=req.notes,
        )
        stats = fb.get_feedback_stats()
        return {
            "status": "success",
            "feedback_id": record["id"],
            "current_stats": stats,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/feedback")
def get_feedback(limit: int = 50):
    """Retrieve recent analyst feedback entries."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM feedback ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return {"status": "success", "count": len(rows), "data": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/responses")
def get_response_actions(limit: int = 50):
    """Retrieve recent automated SOAR-Lite response actions."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM response_actions ORDER BY executed_at DESC LIMIT ?",
            (limit,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return {"status": "success", "count": len(rows), "data": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/model-versions")
def get_model_versions():
    """Retrieve ML model version history."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM model_versions ORDER BY created_at DESC LIMIT 20"
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return {"status": "success", "count": len(rows), "data": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/phase4/rule-scores")
def get_rule_scores(retired: bool = False):
    """Retrieve rule effectiveness scores and hit rates."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if retired:
            cursor.execute(
                "SELECT * FROM rule_scores ORDER BY effectiveness_score DESC"
            )
        else:
            cursor.execute(
                "SELECT * FROM rule_scores WHERE is_retired = 0 "
                "ORDER BY effectiveness_score DESC"
            )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return {"status": "success", "count": len(rows), "data": rows}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
