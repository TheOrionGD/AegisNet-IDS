import asyncio
import logging
from core.event_bus import bus
from core.response_engine import ResponseEngine
from siem.storage import SIEMStorage

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("SOARWorker")

class SOARHandler:
    def __init__(self):
        self.storage = SIEMStorage()
        self.response_engine = ResponseEngine(self.storage)

    async def handle_incident(self, incident: dict):
        """Processes a correlated incident and triggers SOAR playbooks."""
        logger.info(f"SOAR [INCOMING]: Processing incident {incident.get('incident_id')}")
        response = await self.response_engine.execute_response(incident)
        
        if response:
            logger.info(f"SOAR [ACTION]: {response['state']} - {response['action_detail']}")
            # In a true distributed system, we could publish 'action_completed' event
            await bus.publish("response_action", response)

async def main():
    logger.info("Starting CNS SOAR Worker (Response Orchestration)...")
    
    # 1. Initialize Persistent Stream Bus
    await bus.initialize()
    
    # 2. Initialize SOAR Handler
    handler = SOARHandler()
    
    # 3. Subscribe to Incidents Stream
    # Note: Using a separate consumer group 'soar_group' allows 
    # both Analysis (for internal state) and SOAR (for action) to see the same incidents if needed,
    # or just SOAR to handle the logic.
    bus.subscribe("incident", handler.handle_incident)
    
    # 4. Start Persistent Consumer (Kafka-style)
    await bus.consume(group="soar_group")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("SOAR Worker stopped.")
