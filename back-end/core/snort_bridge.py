import json
import time
import requests
import logging
import os
import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("SnortBridge")

class SnortAlertHandler(FileSystemEventHandler):
    """
    Tails the Snort alert.json file and forwards alerts to the CNS API.
    Uses a pointer file to ensure persistent tracking across restarts.
    """
    def __init__(self, api_url, log_file):
        self.api_url = api_url
        self.log_file = log_file
        self.pointer_file = f"{log_file}.pointer"
        self.file_handle = None
        self._resume_from_pointer()

    def _resume_from_pointer(self):
        """Read the last saved offset and seek to it."""
        offset = 0
        if os.path.exists(self.pointer_file):
            try:
                with open(self.pointer_file, 'r') as f:
                    offset = int(f.read().strip())
                logger.info(f"Resuming Snort bridge from offset {offset}")
            except Exception:
                offset = 0

        if os.path.exists(self.log_file):
            self.file_handle = open(self.log_file, 'r')
            file_size = os.path.getsize(self.log_file)
            
            if offset > file_size:
                logger.warning("Log file smaller than pointer. Possibly rotated. Starting from 0.")
                offset = 0
            
            self.file_handle.seek(offset)
            logger.info(f"Snort bridge initialized at offset {offset}")

    def _save_pointer(self):
        """Save the current file position to the pointer file."""
        if self.file_handle:
            try:
                with open(self.pointer_file, 'w') as f:
                    f.write(str(self.file_handle.tell()))
            except Exception as e:
                logger.error(f"Failed to save pointer: {e}")

    def on_modified(self, event):
        if event.src_path == os.path.abspath(self.log_file):
            self._process_new_lines()

    def _process_new_lines(self):
        if not self.file_handle:
            self._resume_from_pointer()
            if not self.file_handle: return

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
                if not line.strip(): continue
                try:
                    alert = json.loads(line.strip())
                    normalized = self._normalize_alert(alert)
                    batch.append(normalized)
                except Exception as e:
                    logger.error(f"Error parsing Snort JSON: {e}")

            if batch:
                if self._forward_batch(batch):
                    self._save_pointer()

    def _normalize_alert(self, alert):
        """
        Translates Snort 3 JSON into the CNS Unified Schema.
        Handles variations in field naming and types.
        """
        rule = alert.get('rule', {})
        
        # Priority mapping: Snort Priority (1=High, 2=Med, 3=Low)
        pri = rule.get('priority', 3)
        severity = "HIGH" if pri == 1 else "MEDIUM" if pri == 2 else "LOW"

        return {
            "timestamp": alert.get('timestamp', datetime.datetime.now().isoformat()),
            "pkt_num": alert.get('pkt_num', 0),
            "src_ip": alert.get('src_addr', alert.get('src_ip', '0.0.0.0')),
            "dst_ip": alert.get('dst_addr', alert.get('dst_ip', '0.0.0.0')),
            "src_port": alert.get('src_port', 0),
            "dst_port": alert.get('dst_port', 0),
            "protocol": alert.get('proto', 'TCP').upper(),
            "alert_type": rule.get('msg', 'SNORT_GENERIC_ALERT'),
            "severity": severity,
            "signature_id": f"{rule.get('gid', 1)}:{rule.get('sid', 0)}",
            "raw_payload": alert
        }

    def _forward_batch(self, batch):
        try:
            endpoint = f"{self.api_url}/ingest/batch"
            response = requests.post(endpoint, json=batch, timeout=5)
            if response.status_code == 200:
                logger.info(f"Successfully processed batch of {len(batch)} alerts.")
                return True
            logger.error(f"API Error: {response.status_code}")
        except Exception as e:
            logger.error(f"Network error: {e}")
        return False


def run_bridge(api_url="http://localhost:8000", log_file="alert_fast.txt"):
    # Ensure log directory exists
    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f: f.write("")

    event_handler = SnortAlertHandler(api_url, log_file)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(os.path.abspath(log_file)), recursive=False)
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
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:2345"
    path = sys.argv[2] if len(sys.argv) > 2 else "logs/alert.json"
    run_bridge(url, path)
