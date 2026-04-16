import sqlite3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Ensure we can import from src
base_path = Path(__file__).parent.parent.parent
if str(base_path) not in sys.path:
    sys.path.append(str(base_path))

from siem.storage import SIEMStorage
from .base_repo import BaseRepository

class SQLiteRepository(BaseRepository):
    def __init__(self, db_path: str):
        # Resolve relative paths against the back-end root
        p = Path(db_path)
        if not p.is_absolute():
            p = (Path(__file__).parent.parent / db_path).resolve()
        self.db_path = str(p)
        p.parent.mkdir(parents=True, exist_ok=True)

        # SIEMStorage handles its own config — no db_path arg needed here
        self.storage = SIEMStorage()
        self._ensure_table()

    def _ensure_table(self):
        """Create raw_logs table if it doesn't exist yet."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS raw_logs (
                    id TEXT PRIMARY KEY,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    severity TEXT,
                    label TEXT,
                    alert_type TEXT DEFAULT 'IDS',
                    timestamp TEXT,
                    raw_data TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS technical_incidents (
                    incident_id TEXT PRIMARY KEY,
                    data TEXT,
                    start_time TEXT
                )
            """)
            conn.commit()

    def get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM raw_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def get_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.storage.get_all_incidents(limit=limit)

    def get_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM raw_logs 
            WHERE alert_type = 'ML_ANOMALY' 
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT src_ip, COUNT(*) as alert_count 
            FROM raw_logs 
            GROUP BY src_ip 
            ORDER BY alert_count DESC 
            LIMIT ?
        ''', (limit,))
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        conn = self.get_conn()
        cursor = conn.cursor()
        # Aggregating by hour
        cursor.execute('''
            SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket, COUNT(*) as volume
            FROM raw_logs
            WHERE timestamp >= datetime('now', ?)
            GROUP BY time_bucket
            ORDER BY time_bucket DESC
        ''', (f'-{hours} hours',))
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows[::-1] # Return chronological

    def ingest_log(self, data: Dict[str, Any]) -> str:
        import uuid
        log_id = data.get('id') or str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO raw_logs
                    (id, src_ip, dst_ip, protocol, severity, label, alert_type, timestamp, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                log_id,
                data.get('src_ip', ''),
                data.get('dst_ip', ''),
                data.get('protocol', ''),
                data.get('severity', ''),
                data.get('label', ''),
                data.get('alert_type', 'IDS'),
                data.get('timestamp', ''),
                json.dumps(data),
            ))
            conn.commit()
        return log_id
