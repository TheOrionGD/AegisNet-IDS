import asyncio
import logging
import json
import datetime
from datetime import timezone
import uuid
from typing import Dict, Any, Callable, List, DefaultDict, Optional
from collections import defaultdict

import redis
import redis.asyncio as async_redis
from config_loader import load_config

try:
    from core.siem_pipeline import get_siem_pipeline

    SIEM_PIPELINE_AVAILABLE = True
except ImportError:
    SIEM_PIPELINE_AVAILABLE = False

try:
    # Test if we can at least find the redis module
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class EventBus:
    """
    True SIEM Persistent Event Bus (Kafka-like).
    Uses Redis Streams for durability and Consumer Groups for scaling.
    """

    def __init__(self, redis_url: Optional[str] = None):
        if not redis_url:
            try:
                config = load_config()
                redis_url = config.get("bus", {}).get(
                    "redis_url", "redis://localhost:6379"
                )
            except Exception:
                redis_url = "redis://localhost:6379"

        self.redis_url = redis_url
        self.redis_client: Optional[async_redis.Redis] = None
        self.stream_key = "cns_events"
        self.local_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.subscribers: DefaultDict[str, List[Callable]] = defaultdict(list)
        self.mode = "LOCAL"
        self.running = False
        self.group_name = "cns_worker_group"
        self.consumer_name = f"consumer-{uuid.uuid4().hex[:4]}"

    async def initialize(self):
        """Connect to Redis and ensure Stream / Consumer Group exist."""
        # Disabled Redis to avoid hanging on startup
        self.mode = "LOCAL"

    async def publish(self, event_type: str, data: Dict[str, Any]):
        """Publish a persistent event to the Stream."""
        event = {
            "type": event_type,
            "data": json.dumps(data),
            "ts": datetime.datetime.now(timezone.utc).isoformat(),
        }

        if self.mode == "STREAM" and self.redis_client:
            # XADD: Kafka-like append
            await self.redis_client.xadd(self.stream_key, event)
        else:
            if self.local_queue.full():
                try:
                    self.local_queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await self.local_queue.put({"type": event_type, "data": data})

        logger.debug(f"Event Published ({self.mode}): {event_type}")

    async def consume(self, group: Optional[str] = None):
        """Persistent consumer using XREADGROUP."""
        self.running = True
        self.group_name = group or self.group_name

        if self.mode == "STREAM" and self.redis_client:
            # Ensure this specific group exists
            try:
                await self.redis_client.xgroup_create(
                    self.stream_key, self.group_name, id="0", mkstream=True
                )
            except Exception:
                pass  # Already exists or stream created

            logger.info(
                f"Event Bus [STREAM]: Consumer {self.consumer_name} started in group {self.group_name}"
            )
            while self.running:
                try:
                    # BLOCKing read from Stream
                    streams = await self.redis_client.xreadgroup(
                        self.group_name,
                        self.consumer_name,
                        {self.stream_key: ">"},
                        count=10,
                        block=2000,
                    )

                    for stream, messages in streams:
                        for entry_id, message_data in messages:
                            # Parse and dispatch
                            event = {
                                "type": message_data["type"],
                                "data": json.loads(message_data["data"]),
                            }
                            await self._dispatch(event)
                            # XACK: Acknowledge successful processing
                            await self.redis_client.xack(
                                self.stream_key, self.group_name, entry_id
                            )
                except Exception as e:
                    logger.error(f"Stream consume error: {e}")
                    await asyncio.sleep(1)
        else:
            logger.info("Event Bus [LOCAL]: Consumer started.")
            while self.running:
                try:
                    event = await self.local_queue.get()
                    await self._dispatch(event)
                    self.local_queue.task_done()
                except Exception as e:
                    logger.error(f"Local consume error: {e}")
                    await asyncio.sleep(0.1)

    async def _dispatch(self, event: dict):
        event_type = event.get("type")
        data = event.get("data")

        # Process through SIEM Pipeline for anomaly scoring
        if SIEM_PIPELINE_AVAILABLE and event_type == "raw_alert":
            try:
                pipeline = get_siem_pipeline()
                if pipeline._initialized or pipeline.initialize():
                    await pipeline.process_event(data)
            except Exception as e:
                logger.debug(f"SIEM pipeline processing skipped: {e}")

        if event_type in self.subscribers:
            tasks = [callback(data) for callback in self.subscribers[event_type]]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    def subscribe(self, event_type: str, callback: Callable):
        self.subscribers[event_type].append(callback)
        logger.info(f"Subscribed to {event_type}")

    def stop(self):
        self.running = False


# Global instance
bus = EventBus()
