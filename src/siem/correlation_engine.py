import uuid
import datetime
import logging
from typing import Dict, Any, List, Optional
from .storage import SIEMStorage

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """Groups Snort alerts and ML anomalies into actionable incidents."""
    
    def __init__(self, config: dict, storage: SIEMStorage):
        self.config = config
        self.storage = storage
        self.window_minutes = int(self.config.get('siem', {}).get('correlation', {}).get('window_minutes', 2))
        self.high_threshold = int(self.config.get('siem', {}).get('correlation', {}).get('high_severity_threshold', 5))
        self.med_threshold = int(self.config.get('siem', {}).get('correlation', {}).get('medium_severity_threshold', 3))

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Takes a new event, stores it, fetches windowed context, and generates an Incident
        if it hits correlation rules.
        """
        # Store incoming event
        self.storage.ingest_log(event)
        
        src_ip = event.get('src_ip')
        if not src_ip:
             return None
             
        # Fetch windowed context
        recent_logs = self.storage.get_recent_logs(src_ip, self.window_minutes)
        if not recent_logs:
            return None
            
        alert_count = len(recent_logs)
        types = list(set([log['alert_type'] for log in recent_logs if log.get('alert_type')]))
        
        # Calculate Severity Rule
        severity = 'LOW'
        if alert_count >= self.high_threshold or len(types) >= 3:
            severity = 'HIGH'
        elif alert_count >= self.med_threshold:
            severity = 'MEDIUM'
            
        # We only generate an incident struct if something is noteworthy
        # For this prototype we will group anything > 1 alert or ANY anomaly event 
        # Even a single 'anomaly' is treated as an incident
        is_anomaly = event.get('alert_type') == 'ML_ANOMALY'
        
        if alert_count > 1 or is_anomaly:
            start_time = min([log['timestamp'] for log in recent_logs if log.get('timestamp')])
            end_time = max([log['timestamp'] for log in recent_logs if log.get('timestamp')])
            
            incident = {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "src_ip": src_ip,
                "alert_count": alert_count,
                "severity": "HIGH" if is_anomaly else severity,
                "attack_pattern": types,
                "start_time": start_time,
                "end_time": end_time,
                "cve_match": "",
                "known_exploit": False
            }
            return incident
            
        return None
