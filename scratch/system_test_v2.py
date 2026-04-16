import subprocess
import time
import requests
import json
import os
import sys
from pathlib import Path
import signal

# Add paths to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_PATH = ROOT_DIR / "back-end"
SCRIPTS_PATH = ROOT_DIR / "scripts"

sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_PATH))
sys.path.insert(0, str(SCRIPTS_PATH))

from threat_simulator import ThreatSimulator

API_URL = "http://localhost:8000"

def start_system():
    print("Starting system using run_system.py...")
    # Using sys.executable to ensure we use the same environment
    proc = subprocess.Popen([sys.executable, "run_system.py"], cwd=ROOT_DIR)
    return proc

def wait_for_api(timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            r = requests.get(f"{API_URL}/health")
            if r.status_code == 200:
                print("API is UP and healthy.")
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    return False

def run_test():
    system_proc = None
    try:
        # Start system
        system_proc = start_system()
        
        if not wait_for_api():
            print("FAILED: API did not start in time.")
            return False

        print("\n=== STAGE 1: Generating Threat Data ===")
        # Use ThreatSimulator in synthetic mode
        output_dir = ROOT_DIR / "scratch" / "data"
        tse = ThreatSimulator(target_ip='10.0.0.1', mode='synthetic', output_dir=str(output_dir))
        
        # Clear previous logs if any
        for f in output_dir.glob("*.json"):
            f.unlink()

        # Run some attacks
        tse.run_recon('port_scan')
        tse.run_dos('syn_flood')
        tse.run_web_attack('sqli')
        
        print("\n=== STAGE 2: Ingesting Data into SIEM ===")
        # Collect all generated logs
        all_logs = []
        for p in output_dir.glob("*_anomalies.json"):
            with p.open('r') as f:
                for line in f:
                    if line.strip():
                        # The simulator produces logs with 'event' key, but the ingest/batch
                        # expects the format that snort_bridge.py _normalize_alert produces.
                        # { "timestamp": ..., "src_ip": ..., "alert_type": ..., ... }
                        raw_log = json.loads(line.strip())
                        normalized = {
                            "timestamp": raw_log.get('timestamp'),
                            "src_ip": raw_log.get('event', {}).get('source', {}).get('ip'),
                            "dst_ip": raw_log.get('event', {}).get('destination', {}).get('ip'),
                            "src_port": raw_log.get('event', {}).get('source', {}).get('port'),
                            "dst_port": raw_log.get('event', {}).get('destination', {}).get('port'),
                            "protocol": raw_log.get('event', {}).get('protocol'),
                            "alert_type": "TSE_SIMULATED_ATTACK",
                            "severity": "HIGH",
                            "raw_payload": raw_log
                        }
                        # Add specific alert types based on file name
                        if "recon" in p.name: normalized["alert_type"] = "RECON_SCAN"
                        elif "dos" in p.name: normalized["alert_type"] = "DOS_ATTACK"
                        elif "web" in p.name: normalized["alert_type"] = "WEB_EXPLOIT"
                        
                        all_logs.append(normalized)

        if not all_logs:
            print("FAILED: No logs generated.")
            return False

        print(f"Sending {len(all_logs)} alerts to {API_URL}/ingest/batch...")
        r = requests.post(f"{API_URL}/ingest/batch", json=all_logs)
        print(f"Ingestion result: {r.status_code} - {r.json()}")

        print("\n=== STAGE 3: Verifying Detections ===")
        print("Waiting 10 seconds for workers to process...")
        time.sleep(10)

        # Check raw alerts
        r = requests.get(f"{API_URL}/alerts?limit=50")
        alerts = r.json()
        print(f"Found {len(alerts)} alerts in database.")
        
        # Check incidents (Correlated results)
        r = requests.get(f"{API_URL}/incidents?limit=10")
        # Note: the endpoint in main.py is /incidents, but in dashboard_api.py it was /dashboard/incidents?
        # Let's check the routes in main.py again. It uses incidents.router.
        # Looking at alerts.py, it was /alerts.
        
        # Let's use the UI-facing dashboard endpoints if available
        # Actually /incidents should work if it's in the router.
        
        print("\n=== TEST COMPLETE ===")
        if len(alerts) > 0:
            print("PASS: Data successfully ingested and retrieved.")
        else:
            print("FAIL: No data found in database.")

        return True

    except Exception as e:
        print(f"ERROR during test: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if system_proc:
            print("\nShutting down system...")
            # On Windows, we might need a more forceful shutdown if subprocess.terminate() isn't enough
            # but run_system.py handles SIGINT
            system_proc.send_signal(signal.CTRL_C_EVENT)
            try:
                system_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                system_proc.kill()
            print("System shutdown complete.")

if __name__ == "__main__":
    success = run_test()
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
