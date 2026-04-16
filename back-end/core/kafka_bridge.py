import json
import asyncio
import os
import logging
from aiokafka import AIOKafkaProducer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("KafkaBridge")

class KafkaAlertHandler(FileSystemEventHandler):
    """
    Asynchronous file tailer for Snort alerts.
    Produces alerts to a Kafka topic for industrial-grade processing.
    """
    def __init__(self, bootstrap_servers, topic, log_file):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.log_file = os.path.abspath(log_file)
        self.pointer_file = f"{self.log_file}.pointer"
        self.producer = None
        self.loop = asyncio.get_event_loop()
        self.file_handle = None

    async def start(self):
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        await self.producer.start()
        logger.info(f"Kafka Producer started. Target topic: {self.topic}")
        self._resume_from_pointer()

    async def stop(self):
        if self.producer:
            await self.producer.stop()
        if self.file_handle:
            self.file_handle.close()

    def _resume_from_pointer(self):
        offset = 0
        if os.path.exists(self.pointer_file):
            try:
                with open(self.pointer_file, 'r') as f:
                    offset = int(f.read().strip())
            except:
                offset = 0

        if os.path.exists(self.log_file):
            self.file_handle = open(self.log_file, 'r')
            if offset <= os.path.getsize(self.log_file):
                self.file_handle.seek(offset)
            else:
                logger.warning("Log file rotated or shrunk. Starting from 0.")

    def _save_pointer(self):
        if self.file_handle:
            with open(self.pointer_file, 'w') as f:
                f.write(str(self.file_handle.tell()))

    def on_modified(self, event):
        if event.src_path == self.log_file:
            asyncio.run_coroutine_threadsafe(self._process_new_lines(), self.loop)

    async def _process_new_lines(self):
        if not self.file_handle:
            self._resume_from_pointer()
            if not self.file_handle: return

        # Rotation check
        try:
            if os.path.getsize(self.log_file) < self.file_handle.tell():
                logger.info("Log rotation detected.")
                self.file_handle.close()
                self._resume_from_pointer()
        except FileNotFoundError:
            return

        lines = self.file_handle.readlines()
        for line in lines:
            if not line.strip(): continue
            try:
                alert = json.loads(line.strip())
                await self.producer.send_and_wait(self.topic, alert)
            except Exception as e:
                logger.error(f"Error producing to Kafka: {e}")

        self._save_pointer()

async def run_bridge(log_file, bootstrap_servers="kafka:29092", topic="cns-alerts"):
    handler = KafkaAlertHandler(bootstrap_servers, topic, log_file)
    await handler.start()

    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(os.path.abspath(log_file)), recursive=False)
    observer.start()

    logger.info(f"Watching {log_file} for Snort alerts...")
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        observer.stop()
        await handler.stop()
    observer.join()

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/alert.json"
    servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    try:
        asyncio.run(run_bridge(path, servers))
    except KeyboardInterrupt:
        pass
