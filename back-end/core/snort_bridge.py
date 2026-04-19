import json
import time
import asyncio
import requests
import logging
import os
import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("SnortBridge")


class IDSAlertBroadcaster:
    """
    Real-time IDS alert broadcaster that streams to ML engine and WebSocket clients.
    Implements instant anomaly scoring with WebSocket push notifications.
    """

    def __init__(self, api_url=None):
        self.api_url = api_url or os.environ.get("API_URL", "http://localhost:2346")
        self._ml_engine = None
        self._ws_manager = None
        self._event_queue = asyncio.Queue()
        self._running = False
        self._initialize_components()

    def _initialize_components(self):
        """Initialize ML engine and WebSocket manager."""
        try:
            from core.realtime_ml import get_realtime_engine

            self._ml_engine = get_realtime_engine()
            logger.info("[IDS-BROADCAST] ML Engine initialized")
        except Exception as e:
            logger.warning(f"[IDS-BROADCAST] ML Engine init failed: {e}")

        try:
            from api.ws_manager import manager as ws_mgr

            self._ws_manager = ws_mgr
            logger.info("[IDS-BROADCAST] WebSocket manager connected")
        except Exception as e:
            logger.warning(f"[IDS-BROADCAST] WS Manager init failed: {e}")

    async def process_alert(self, alert: dict) -> dict:
        """
        Process a single alert through ML model and broadcast via WebSocket.
        Returns enriched alert with anomaly scoring.
        """
        enriched = alert.copy()
        enriched["processed_at"] = datetime.datetime.now().isoformat()

        ml_result = {"anomaly_score": 0.0, "risk_level": "LOW", "is_anomaly": False}

        if self._ml_engine:
            try:
                ml_result = self._ml_engine.predict_single(alert)
            except Exception as e:
                logger.error(f"[IDS-BROADCAST] ML inference error: {e}")

        enriched["ml_score"] = ml_result.get("anomaly_score", 0.0)
        enriched["ml_risk_level"] = ml_result.get("risk_level", "LOW")
        enriched["ml_is_anomaly"] = ml_result.get("is_anomaly", False)

        if enriched.get("severity") in ["HIGH", "CRITICAL"] or ml_result.get(
            "is_anomaly"
        ):
            enriched["threat_level"] = "ELEVATED"
            await self._broadcast_alert(enriched)

        return enriched

    async def _broadcast_alert(self, alert: dict):
        """Broadcast alert to WebSocket clients in real-time."""
        if self._ws_manager:
            try:
                await self._ws_manager.broadcast(alert, event_type="ids_alert")
                logger.info(
                    f"[IDS-BROADCAST] Real-time alert sent: {alert.get('src_ip')} -> {alert.get('dst_ip')}"
                )
            except Exception as e:
                logger.error(f"[IDS-BROADCAST] Broadcast error: {e}")

    async def start_processor(self):
        """Start async alert processor."""
        self._running = True
        logger.info("[IDS-BROADCAST] Alert processor started")

        while self._running:
            try:
                alert = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                await self.process_alert(alert)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"[IDS-BROADCAST] Processor error: {e}")

    def enqueue_alert(self, alert: dict):
        """Enqueue alert for async processing."""
        try:
            asyncio.create_task(self._event_queue.put(alert))
        except RuntimeError:
            asyncio.get_event_loop().run_until_complete(self._event_queue.put(alert))


_ids_broadcaster = None


def get_ids_broadcaster(api_url=None) -> IDSAlertBroadcaster:
    """Get or create the global IDS broadcaster."""
    global _ids_broadcaster
    if _ids_broadcaster is None:
        _ids_broadcaster = IDSAlertBroadcaster(api_url)
    return _ids_broadcaster


class SnortAlertHandler(FileSystemEventHandler):
    """
    Tails the Snort alert.json file and forwards alerts to the CNS API.
    Uses a pointer file to ensure persistent tracking across restarts.
    Integrated with ML streaming and WebSocket alerts.
    """

    def __init__(self, api_url, log_file):
        self.api_url = api_url
        self.log_file = log_file
        self.pointer_file = f"{log_file}.pointer"
        self.file_handle = None
        self._ids_broadcaster = get_ids_broadcaster(api_url)
        self._resume_from_pointer()

    def _resume_from_pointer(self):
        """Read the last saved offset and seek to it."""
        offset = 0
        if os.path.exists(self.pointer_file):
            try:
                with open(self.pointer_file, "r") as f:
                    offset = int(f.read().strip())
                logger.info(f"Resuming Snort bridge from offset {offset}")
            except Exception:
                offset = 0

        if os.path.exists(self.log_file):
            self.file_handle = open(self.log_file, "r")
            file_size = os.path.getsize(self.log_file)

            if offset > file_size:
                logger.warning(
                    "Log file smaller than pointer. Possibly rotated. Starting from 0."
                )
                offset = 0

            self.file_handle.seek(offset)
            logger.info(f"Snort bridge initialized at offset {offset}")

    def _save_pointer(self):
        """Save the current file position to the pointer file."""
        if self.file_handle:
            try:
                with open(self.pointer_file, "w") as f:
                    f.write(str(self.file_handle.tell()))
            except Exception as e:
                logger.error(f"Failed to save pointer: {e}")

    def on_modified(self, event):
        if event.src_path == os.path.abspath(self.log_file):
            self._process_new_lines()

    def _process_new_lines(self):
        if not self.file_handle:
            self._resume_from_pointer()
            if not self.file_handle:
                return

        # Handle file rotation
        current_pos = self.file_handle.tell()
        try:
            if os.path.getsize(self.log_file) < current_pos:
                logger.info("Snort log rotated. Resetting pointer.")
                self.file_handle.close()
                self._resume_from_pointer()
        except FileNotFoundError:
            return

        lines = self.file_handle.readlines()
        if lines:
            batch = []
            for line in lines:
                if not line.strip():
                    continue
                try:
                    alert = json.loads(line)
                    if isinstance(alert, str):  # This is the "Double Encoding" fix
                        alert = json.loads(alert)
                except Exception as e:
                    logger.error(f"Failed to parse line: {e}")
                    continue

            if batch:
                if self._forward_batch(batch):
                    self._save_pointer()

    def _normalize_alert(self, alert):
        """
        Translates Snort 3 JSON into the CNS Unified Schema.
        Handles variations in field naming and types.
        """
        rule = alert.get("rule", {})

        # Priority mapping: Snort Priority (1=High, 2=Med, 3=Low)
        pri = rule.get("priority", 3)
        severity = "HIGH" if pri == 1 else "MEDIUM" if pri == 2 else "LOW"

        return {
            "timestamp": alert.get("timestamp", datetime.datetime.now().isoformat()),
            "pkt_num": alert.get("pkt_num", 0),
            "src_ip": alert.get("src_addr", alert.get("src_ip", "0.0.0.0")),
            "dst_ip": alert.get("dst_addr", alert.get("dst_ip", "0.0.0.0")),
            "src_port": alert.get("src_port", 0),
            "dst_port": alert.get("dst_port", 0),
            "protocol": alert.get("proto", "TCP").upper(),
            "alert_type": rule.get("msg", "SNORT_GENERIC_ALERT"),
            "severity": severity,
            "signature_id": f"{rule.get('gid', 1)}:{rule.get('sid', 0)}",
            "raw_payload": alert,
        }

    def _forward_batch(self, batch):
        """Forward batch to API with ML-based real-time anomaly scoring."""
        for alert in batch:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._ids_broadcaster.process_alert(alert))
                else:
                    loop.run_until_complete(self._ids_broadcaster.process_alert(alert))
            except RuntimeError:
                pass

        try:
            endpoint = f"{self.api_url}/ingest/batch"
            response = requests.post(endpoint, json=batch, timeout=5)
            if response.status_code == 200:
                logger.info(
                    f"Successfully processed batch of {len(batch)} alerts with ML scoring."
                )
                return True
            logger.error(f"API Error: {response.status_code}")
        except Exception as e:
            logger.error(f"Network error: {e}")
        return False


def run_bridge(api_url="http://localhost:8000", log_file="alert_fast.txt"):
    # Ensure log directory exists
    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    if not os.path.exists(log_file):
        with open(log_file, "w") as f:
            f.write("")

    event_handler = SnortAlertHandler(api_url, log_file)
    observer = Observer()
    observer.schedule(
        event_handler, path=os.path.dirname(os.path.abspath(log_file)), recursive=False
    )
    observer.start()

    logger.info("Snort 3 Bridge Daemon started. Listening for alerts...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    import sys

    # Change 2345 to 2346
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:2346"
    # Ensure this matches your actual Snort log location
    path = sys.argv[2] if len(sys.argv) > 2 else "/var/log/snort/alert_json.txt"
    run_bridge(url, path)
