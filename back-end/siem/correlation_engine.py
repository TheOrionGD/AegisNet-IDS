import uuid
import datetime
from datetime import timezone
import logging
import networkx as nx
from typing import Dict, Any, List, Optional
from .storage import SIEMStorage
from collections import deque

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Production-grade Stateful Correlation Engine.
    Uses Graph Theory (NetworkX) to track attack progression and entity relationships.
    """
    def __init__(self, config: dict, storage: SIEMStorage):
        self.config = config
        self.storage = storage
        self.window_seconds = 300  # 5 minute tactical window for correlation
        
        # Entity State Store: { src_ip: { 'graph': nx.DiGraph, 'last_update': timestamp } }
        self.entity_states: Dict[str, Dict[str, Any]] = {}

    def _get_entity_state(self, ip: str) -> Dict[str, Any]:
        """Lazy-init or retrieve the state for a specific IP."""
        now = datetime.datetime.now(timezone.utc)
        if ip not in self.entity_states:
            self.entity_states[ip] = {
                'graph': nx.DiGraph(),
                'last_update': now,
                'alert_sequence': deque(maxlen=50)
            }
        
        # Cleanup stale state
        state = self.entity_states[ip]
        if (now - state['last_update']).total_seconds() > self.window_seconds:
             state['graph'].clear()
        
        state['last_update'] = now
        return state

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Stateful evaluation of an event using Graph-based analysis.
        """
        src_ip = event.get('src_ip')
        if not src_ip: return None

        state = self._get_entity_state(src_ip)
        g = state['graph']
        
        # 1. Add node for current alert
        event_id = event.get('id', str(uuid.uuid4()))
        # Fallback to 'label' which is common in IDS ingest
        alert_type = event.get('alert_type', event.get('label', 'UNKNOWN')).upper()
        
        g.add_node(event_id, 
                   type=alert_type, 
                   severity=event.get('severity', 'LOW'),
                   time=datetime.datetime.now(timezone.utc))
        
        # 2. Link to previous alerts in the window (Temporal Edges)
        now = datetime.datetime.now(timezone.utc)
        for node, data in g.nodes(data=True):
            if node == event_id: continue
            # Link if within 120 seconds of each other
            if abs((now - data['time']).total_seconds()) < 120:
                g.add_edge(node, event_id)

        # 3. Analyze Graph for Attack Chains (Issue 3)
        incident = self._analyze_graph(src_ip, g, event)
        if incident:
            self.storage.store_incident(incident)
            logger.info(f"CORRELATION: Found chain for {src_ip} | Score: {incident['confidence']}")
            return incident

        return None

    def _analyze_graph(self, ip: str, g: nx.DiGraph, current_event: dict) -> Optional[dict]:
        """
        Performs path analysis and pattern matching on the entity graph.
        """
        nodes_data = dict(g.nodes(data=True))
        types = [d['type'] for d in nodes_data.values()]
        
        # Pattern Definition: (Type Keyword, Weight)
        patterns = {
            "RECON": (["SCAN", "ENUM", "PORT", "PROBE"], 0.2),
            "DELIVERY": (["EXPLOIT", "HTTP", "SHELL", "DOWNLOAD", "SQL"], 0.4),
            "ANOMALY": (["ML_ANOMALY", "DNS", "WEIRD"], 0.3),
            "ACTION": (["CNC", "DATA_EXFIL", "LOGIN", "INJECTION", "XSS", "BRUTE"], 0.5)
        }
        
        # Calculate Probabilistic Score
        stages_hit = set()
        confidence = 0.0
        for stage, (keywords, weight) in patterns.items():
            if any(any(k in t for k in keywords) for t in types):
                stages_hit.add(stage)
                confidence += weight

        # Severity Boost: High/Critical alerts raise confidence (Issue 4)
        current_severity = current_event.get('severity', 'LOW').upper()
        if current_severity == 'CRITICAL':
            confidence += 0.2
        elif current_severity == 'HIGH':
            confidence += 0.1

        # Cap confidence at 0.99
        confidence = min(0.99, confidence)

        # Trigger Incident if at least 2 distinct stages or confidence > 0.6
        if len(stages_hit) >= 2 or confidence > 0.6:
            # Deterministic naming
            incident_type = "MULTI-STAGE ATTACK" if len(stages_hit) >= 3 else "SUSPICIOUS CHAIN"
            severity = "CRITICAL" if confidence > 0.8 else "HIGH" if confidence > 0.5 else "MEDIUM"
            
            return {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "incident_type": incident_type,
                "src_ip": ip,
                "alert_count": g.number_of_nodes(),
                "severity": severity,
                "confidence": round(confidence, 2),
                "attack_pattern": list(set(types)),
                "stages": list(stages_hit),
                "start_time": min([d['time'] for d in nodes_data.values()]).isoformat(),
                "end_time": datetime.datetime.now(timezone.utc).isoformat(),
                "ml_contributed": any("ML" in t for t in types)
            }
        
        return None


