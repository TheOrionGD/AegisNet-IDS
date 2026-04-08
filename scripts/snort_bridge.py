import time
import json
import requests
import os
from pathlib import Path

# Configuration
SNORT_LOG_PATH = "logs/alert_json.txt" # Typical Snort 3 JSON output path
SIEM_API_URL = "http://localhost:8000/alerts/ingest"

def tail_file(filename):
    """Generator that yields new lines in a file."""
    try:
        with open(filename, "r") as f:
            # Go to the end of file
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except FileNotFoundError:
        print(f"Waiting for {filename} to be created...")
        while not os.path.exists(filename):
            time.sleep(1)
        yield from tail_file(filename)

def process_snort_alert(raw_line):
    """Parse Snort 3 JSON alert and map to SIEM schema."""
    try:
        alert = json.loads(raw_line)
        # Mapping Snort 3 JSON fields to SIEM schema
        # Snort 3 sample: {"seconds": 167..., "src_addr": "...", "dst_addr": "...", "action": "allow", "msg": "...", "sid": 123...}
        
        siem_log = {
            "timestamp": alert.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%S"),
            "src_ip": alert.get("src_addr") or alert.get("source_ip", "0.0.0.0"),
            "dst_ip": alert.get("dst_addr") or alert.get("dest_ip", "0.0.0.0"),
            "src_port": alert.get("src_port") or 0,
            "dst_port": alert.get("dst_port") or 0,
            "protocol": alert.get("proto") or "TCP",
            "alert_type": "IDS_ALERT",
            "severity": "CRITICAL" if alert.get("priority") == 1 else "HIGH" if alert.get("priority") == 2 else "MEDIUM",
            "signature_id": alert.get("sid") or 0,
            "raw_payload": alert
        }
        return siem_log
    except Exception as e:
        print(f"Error parsing snort alert: {e}")
        return None

def run_bridge():
    print(f"Starting Snort -> SIEM Bridge...")
    print(f"Monitoring: {SNORT_LOG_PATH}")
    print(f"Forwarding to: {SIEM_API_URL}")
    
    # Ensure log dir exists
    Path(SNORT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    if not os.path.exists(SNORT_LOG_PATH):
        with open(SNORT_LOG_PATH, "w") as f:
            pass

    for line in tail_file(SNORT_LOG_PATH):
        siem_log = process_snort_alert(line)
        if siem_log:
            try:
                response = requests.post(SIEM_API_URL, json=siem_log, timeout=5)
                if response.status_code == 200:
                    print(f"[OK] Forwarded alert: {siem_log['src_ip']} -> {siem_log['alert_type']}")
                else:
                    print(f"[ERR] API returned {response.status_code}: {response.text}")
            except Exception as e:
                print(f"[ERR] Failed to connect to SIEM API: {e}")

if __name__ == "__main__":
    run_bridge()
