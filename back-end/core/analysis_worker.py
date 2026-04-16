import asyncio
import logging
from core.event_bus import bus
from core.worker import EventWorker
from config_loader import load_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("AnalysisWorker")

async def main():
    logger.info("Starting CNS Analysis Worker (ML + Correlation)...")
    
    # 1. Initialize Persistent Stream Bus
    await bus.initialize()
    
    # 2. Initialize Logic Worker
    worker = EventWorker()
    
    # 3. Subscribe to Ingestion Stream
    bus.subscribe("raw_alert", worker.handle_alert)
    
    # 4. Start Persistent Consumer (Kafka-style)
    # Using a dedicated consumer group for Analysis
    await bus.consume(group="analysis_group")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Analysis Worker stopped.")
