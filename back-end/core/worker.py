import asyncio
import logging
from core.event_bus import bus
from core.ml_engine import ml_engine
from core.response_engine import ResponseEngine
from siem.correlation_engine import CorrelationEngine
from siem.storage import SIEMStorage
from api.ws_manager import manager
from config_loader import load_config

logger = logging.getLogger(__name__)

class EventWorker:
    """
    Background worker that orchestrates the flow of security events.
    Flow: Alert -> ML Scoring -> Correlation -> Incident -> SOAR -> WebSocket
    """
    def __init__(self, config_path: str = 'config/config.yaml'):
        self.config = load_config(config_path)
        self.storage = SIEMStorage()
        self.correlation_engine = CorrelationEngine(self.config, self.storage)
        # Issue 4: SOAR engine now loads internal config
        self.response_engine = ResponseEngine(self.storage)

    async def start(self):
        """Initialize subscriptions and start the event loop."""
        # Note: bus.initialize() must be called before this by the main app
        bus.subscribe("raw_alert", self.handle_alert)
        logger.info("Production Event Worker initialized.")


    async def handle_alert(self, alert_data: dict):
        """Processes a single incoming alert through the pipeline."""
        try:
            # 1. Ingest/Store Raw Alert
            log_id = self.storage.ingest_log(alert_data)
            alert_data['id'] = log_id
            
            # 2. ML Inference (Isolation Forest)
            ml_result = ml_engine.run_inference(alert_data)
            alert_data['ml_score'] = ml_result['anomaly_score']
            alert_data['is_anomaly'] = ml_result['is_anomaly']
            
            # If it's a significant anomaly, inject the ML_ANOMALY tag for correlation
            if alert_data['is_anomaly']:
                alert_data['alert_type'] = f"ML_ANOMALY: {alert_data.get('alert_type', 'GENERIC')}"
                logger.info(f"ML Anomaly Detected! Score: {alert_data['ml_score']} | Data: {alert_data.get('src_ip')}")
            
            # 3. Correlation Check
            incident = self.correlation_engine.evaluate_event(alert_data)
            
            if incident:
                # 4. Incident Generation & Persistence
                # (Already stored inside correlation_engine.evaluate_event)
                
                # 5. Distributed Notification (True SIEM Scaling)
                # Publish to the persistent stream for SOAR and WebSocket workers
                await bus.publish("incident", incident)
                logger.debug(f"Published Incident {incident['incident_id']} to event bus.")

        except Exception as e:
            logger.error(f"Error in EventWorker pipeline: {e}", exc_info=True)


# Global Instance
worker = EventWorker()
