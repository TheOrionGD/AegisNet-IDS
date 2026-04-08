import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import uuid
import datetime

logger = logging.getLogger(__name__)

class SIEMStorage:
    """SIEM Elastic-like storage abstraction using SQLite as fallback."""
    def __init__(self, db_path: str = "data/siem.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Raw Logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS raw_logs (
            id           TEXT PRIMARY KEY,
            timestamp    TEXT,
            src_ip       TEXT,
            dst_ip       TEXT,
            src_port     INTEGER DEFAULT 0,
            dst_port     INTEGER DEFAULT 0,
            protocol     TEXT,
            alert_type   TEXT,
            severity     TEXT,
            signature_id INTEGER,
            raw_payload  TEXT
        )
        ''')

        # Migration: add src_port / dst_port to existing databases that pre-date Phase 4
        for col, default in [('src_port', 0), ('dst_port', 0)]:
            try:
                cursor.execute(f'ALTER TABLE raw_logs ADD COLUMN {col} INTEGER DEFAULT {default}')
            except sqlite3.OperationalError:
                pass  # column already exists
        
        # Correlated Incidents table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            src_ip TEXT,
            alert_count INTEGER,
            severity TEXT,
            attack_pattern TEXT, 
            start_time TEXT,
            end_time TEXT,
            cve_match TEXT,
            known_exploit BOOLEAN
        )
        ''')
        
        # ── Phase 4 tables ────────────────────────────────────────────────

        # Analyst feedback
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id          TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            label       TEXT NOT NULL,
            analyst     TEXT DEFAULT 'system',
            timestamp   TEXT,
            notes       TEXT DEFAULT ''
        )
        ''')

        # Model version tracking
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_versions (
            version          TEXT PRIMARY KEY,
            created_at       TEXT,
            contamination    REAL,
            precision        REAL,
            recall           REAL,
            drift_score      REAL,
            training_samples INTEGER,
            is_active        INTEGER DEFAULT 0
        )
        ''')

        # Automated response actions
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS response_actions (
            id            TEXT PRIMARY KEY,
            incident_id   TEXT,
            severity_score INTEGER,
            action_type   TEXT,
            action_detail TEXT,
            executed_at   TEXT,
            state         TEXT DEFAULT 'OPEN'
        )
        ''')

        # Threat hunting results
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS hunt_results (
            id          TEXT PRIMARY KEY,
            hunt_type   TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            details     TEXT,
            detected_at TEXT,
            confidence  REAL
        )
        ''')

        # Rule effectiveness scoring
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rule_scores (
            sid                 INTEGER PRIMARY KEY,
            rule_text           TEXT,
            hit_count           INTEGER DEFAULT 0,
            effectiveness_score REAL    DEFAULT 0.5,
            created_at          TEXT,
            last_hit_at         TEXT,
            is_retired          INTEGER DEFAULT 0
        )
        ''')

        # Security posture snapshots
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_posture (
            id              TEXT PRIMARY KEY,
            risk_score      INTEGER,
            threat_level    TEXT,
            components_json TEXT,
            computed_at     TEXT
        )
        ''')

        # Indices for correlation
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON raw_logs(src_ip, timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON raw_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_feedback_incident ON feedback(incident_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_response_incident ON response_actions(incident_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_hunt_type ON hunt_results(hunt_type, detected_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posture_time ON security_posture(computed_at)')

        conn.commit()
        conn.close()
        logger.info(f"SIEM Storage initialized at {self.db_path}")

    def ingest_log(self, log_entry: Dict[str, Any]) -> str:
        """Stores a raw parsed log entry."""
        log_id = str(uuid.uuid4())
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO raw_logs
        (id, timestamp, src_ip, dst_ip, src_port, dst_port,
         protocol, alert_type, severity, signature_id, raw_payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_id,
            log_entry.get('timestamp'),
            log_entry.get('src_ip', ''),
            log_entry.get('dst_ip', ''),
            int(log_entry.get('src_port', 0) or 0),
            int(log_entry.get('dst_port', 0) or 0),
            log_entry.get('protocol', ''),
            log_entry.get('alert_type', ''),
            log_entry.get('severity', 'LOW'),
            log_entry.get('signature_id', 0),
            json.dumps(log_entry.get('raw_payload', {}))
        ))
        conn.commit()
        conn.close()
        return log_id

    def store_incident(self, incident: Dict[str, Any]):
        """Stores a correlated incident."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Convert attack_pattern list to JSON string for SQLite
        attack_pattern = json.dumps(incident.get('attack_pattern', []))
        
        cursor.execute('''
        INSERT OR REPLACE INTO incidents (incident_id, src_ip, alert_count, severity, attack_pattern, start_time, end_time, cve_match, known_exploit)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident.get('incident_id'),
            incident.get('src_ip'),
            incident.get('alert_count', 0),
            incident.get('severity', 'LOW'),
            attack_pattern,
            incident.get('start_time'),
            incident.get('end_time'),
            incident.get('cve_match', ''),
            incident.get('known_exploit', False)
        ))
        conn.commit()
        conn.close()
        logger.info(f"Stored Incident: {incident.get('incident_id')} with severity {incident.get('severity')}")

    def get_recent_logs(self, src_ip: str, minutes_back: int) -> List[Dict[str, Any]]:
        """Retrieve recent logs for a specific source IP (used by correlation engine)."""
        time_threshold = (datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes_back)).isoformat()
        
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM raw_logs WHERE src_ip = ? AND timestamp >= ?
        ''', (src_ip, time_threshold))
        
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_all_incidents(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Retrieve recent incidents for Phase 4 engines."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM incidents ORDER BY start_time DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        results = []
        for row in rows:
            record = dict(row)
            try:
                record['attack_pattern'] = json.loads(record.get('attack_pattern', '[]'))
            except Exception:
                record['attack_pattern'] = []
            results.append(record)
        return results

    def get_incidents_by_severity(self, severity: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve incidents filtered by severity."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            'SELECT * FROM incidents WHERE severity = ? ORDER BY start_time DESC LIMIT ?',
            (severity.upper(), limit)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_incident_severity(self, incident_id: str, new_severity: str) -> bool:
        """Update incident severity (used by Phase 4 response engine)."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE incidents SET severity = ? WHERE incident_id = ?',
                (new_severity.upper(), incident_id)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as exc:
            logger.error(f'Failed to update incident severity: {exc}')
            return False

    def get_raw_logs_window(self, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Retrieve raw logs from the last N hours (for threat hunting)."""
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours_back)).isoformat()
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM raw_logs WHERE timestamp >= ? ORDER BY timestamp', (cutoff,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
