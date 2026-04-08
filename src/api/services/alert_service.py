from typing import List, Dict, Any, Optional
from ..models.security_event import SecurityEvent
from ..repositories.base_repo import BaseRepository
import json
from siem.ml_service import get_ml_service

class AlertService:
    def __init__(self, repository: BaseRepository):
        self.repository = repository

    def get_normalized_alerts(self, limit: int = 100) -> List[SecurityEvent]:
        raw_alerts = self.repository.get_alerts(limit=limit)
        normalized = []
        for alert in raw_alerts:
            # Map raw_logs to SecurityEvent
            # alert keys: id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, alert_type, severity, signature_id, raw_payload
            
            ml_score = 0.0
            if alert.get('alert_type') == 'ML_ANOMALY' and alert.get('raw_payload'):
                try:
                    p = json.loads(alert.get('raw_payload'))
                    ml_score = float(p.get("anomaly_score", 0.0))
                except:
                    pass

            normalized.append(SecurityEvent(
                id=alert.get('id', ''),
                timestamp=alert.get('timestamp', ''),
                source="IDS" if alert.get('alert_type') != 'ML_ANOMALY' else "ML_ENGINE",
                type=alert.get('alert_type', 'UNKNOWN'),
                severity=alert.get('severity', 'LOW'),
                src_ip=alert.get('src_ip'),
                dst_ip=alert.get('dst_ip'),
                protocol=alert.get('protocol'),
                message=f"Alert {alert.get('alert_type')} from {alert.get('src_ip')}",
                ml_score=ml_score,
                correlation_score=0.0, # Placeholder
                raw_payload=json.loads(alert.get('raw_payload', '{}')) if alert.get('raw_payload') else {}
            ))
        return normalized

    def get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.repository.get_top_ips(limit=limit)

    def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        return self.repository.get_timeline(hours=hours)

    def ingest_alert(self, alert_data: Dict[str, Any]) -> str:
        # 1. Ingest the raw log
        log_id = self.repository.ingest_log(alert_data)
        
        # 2. Run ML detection if it's a raw IDS alert
        if alert_data.get('alert_type') != 'ML_ANOMALY':
            ml_service = get_ml_service()
            anomaly = ml_service.detect_anomaly(alert_data)
            if anomaly:
                # Store the anomaly log
                anomaly_log = {
                    "timestamp": anomaly['timestamp'],
                    "src_ip": alert_data.get('src_ip'),
                    "dst_ip": alert_data.get('dst_ip'),
                    "src_port": alert_data.get('src_port'),
                    "dst_port": alert_data.get('dst_port'),
                    "protocol": alert_data.get('protocol'),
                    "alert_type": "ML_ANOMALY",
                    "severity": "HIGH" if anomaly['score'] < -0.2 else "MEDIUM",
                    "raw_payload": {"anomaly_score": anomaly['score'], "confidence": anomaly['confidence']}
                }
                self.repository.ingest_log(anomaly_log)

        return log_id
