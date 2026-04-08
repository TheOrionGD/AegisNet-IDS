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
        self.storage = SIEMStorage(db_path=db_path)
        self.db_path = db_path

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
        return self.storage.ingest_log(data)
