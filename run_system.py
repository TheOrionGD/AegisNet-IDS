#!/usr/bin/env python3
"""
AegisNet Unified Orchestrator
=============================
Handles the deterministic boot sequence of the distributed SIEM components:
1. Event Bus (Redis)
2. SIEM API (FastAPI)
3. Analysis Worker (ML + Correlation)
4. SOAR Worker (Automatic Response)
5. Snort Bridge (Log Ingestion)
"""

import subprocess
import time
import sys
import os
import signal
import logging
import threading
from pathlib import Path
from dotenv import load_dotenv
import requests

# Load environment variables from .env if present
load_dotenv()

# Ensure logs directory exists
Path('logs').mkdir(exist_ok=True)

# Setup logging to file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ORCHESTRATOR] %(message)s',
    handlers=[
        logging.FileHandler('logs/orchestrator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AegisNet")

class SystemOrchestrator:
    def __init__(self):
        self.processes = {}
        self.root_dir = Path(__file__).resolve().parent
        self.python_exe = sys.executable
        self.api_port = int(os.environ.get('API_PORT', 2345))
        self.logs_dir = self.root_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True)

        # Set PYTHONPATH more targeted: only for back-end processes
        back_end_dir = self.root_dir / "back-end"
        self.pythonpath = os.pathsep.join([str(self.root_dir), str(back_end_dir)])
        existing_pythonpath = os.environ.get('PYTHONPATH', '')
        if existing_pythonpath:
            self.pythonpath = os.pathsep.join([existing_pythonpath, self.pythonpath])

        self.env = os.environ.copy()
        self.env['PYTHONPATH'] = self.pythonpath

        self.monitoring_thread = None
        self.shutdown_event = threading.Event()

    def start_process(self, name, command, cwd=None, log_file=None):
        """Starts a background process and tracks it."""
        logger.info(f"Starting {name}...")
        try:
            if log_file:
                log_path = self.logs_dir / log_file
                with open(log_path, 'a') as f:
                    f.write(f"\n--- Starting {name} at {time.ctime()} ---\n")
                stdout = open(log_path, 'a')
                stderr = subprocess.STDOUT  # Combine stderr to stdout
            else:
                stdout = subprocess.PIPE
                stderr = subprocess.PIPE

            proc = subprocess.Popen(
                command,
                cwd=cwd or self.root_dir,
                env=self.env,
                stdout=stdout,
                stderr=stderr,
                shell=False  # Always False since command is list
            )
            self.processes[name] = (proc, log_file)
            return proc
        except Exception as e:
            logger.error(f"Failed to start {name}: {e}")
            return None

    def restart_process(self, name):
        """Restarts a crashed process."""
        if name not in self.processes:
            return
        proc, log_file = self.processes[name]
        if proc.poll() is None:
            return  # Still running
        logger.warning(f"Process {name} crashed, restarting...")
        # Define commands based on name
        if name == "SIEM API":
            if self.is_port_in_use(self.api_port):
                logger.info(f"Port {self.api_port} still in use, waiting before restarting API...")
                if not self.wait_for_port_free(self.api_port, timeout=10, delay=1):
                    logger.warning(f"Port {self.api_port} still busy after waiting; attempting restart anyway.")
            command = [self.python_exe, "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", str(self.api_port)]
            cwd = self.root_dir / "back-end"
        elif name == "Analysis Worker":
            command = [self.python_exe, "core/analysis_worker.py"]
            cwd = self.root_dir / "back-end"
        elif name == "SOAR Worker":
            command = [self.python_exe, "core/soar_worker.py"]
            cwd = self.root_dir / "back-end"
        elif name == "Snort Bridge":
            alert_log = self.root_dir / "alert_json.txt"
            if not alert_log.exists():
                alert_log.parent.mkdir(parents=True, exist_ok=True)
                alert_log.touch()
            command = [self.python_exe, "core/snort_bridge.py", f"http://localhost:{self.api_port}", str(alert_log)]
            cwd = self.root_dir / "back-end"
        else:
            return
        self.start_process(name, command, cwd, log_file)

    def find_open_port(self, start_port=8000, max_tries=10):
        """Find an available local TCP port starting from start_port."""
        port = start_port
        for _ in range(max_tries):
            if not self.is_port_in_use(port):
                return port
            port += 1
        return None

    def is_port_in_use(self, port):
        """Checks if a local port is already in use."""
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(('127.0.0.1', port)) == 0
        except Exception:
            return False

    def wait_for_port_free(self, port, timeout=10, delay=1):
        """Waits until a local port is free or a timeout expires."""
        end_time = time.time() + timeout
        while time.time() < end_time:
            if not self.is_port_in_use(port):
                return True
            time.sleep(delay)
        return False

    def check_api_health(self, retries=30, delay=3):
        """Check if API is healthy."""
        for _ in range(retries):
            try:
                response = requests.get(f"http://localhost:{self.api_port}/health", timeout=5)
                if response.status_code == 200:
                    return True
            except:
                pass
            time.sleep(delay)
        return False

    def monitor_processes(self):
        """Thread to monitor process health and restart if needed."""
        while not self.shutdown_event.is_set():
            for name in list(self.processes.keys()):
                proc, _ = self.processes[name]
                if proc.poll() is not None:
                    self.restart_process(name)
            time.sleep(5)  # Check every 5 seconds

    def boot(self):
        """Executes the boot sequence with dependency delays."""
        print("\n" + "="*60)
        print("  AEGISNET SIEM: UNIFIED SYSTEM BOOT")
        print("="*60 + "\n")

        # Port Check and dynamic API port assignment
        api_port = self.find_open_port(self.api_port)
        if api_port is None:
            logger.error(f"FATAL: No available port found starting from {self.api_port}. Please free a local port and try again.")
            sys.exit(1)
        if api_port != self.api_port:
            logger.warning(f"Port {self.api_port} is busy. Using fallback API port {api_port}.")
        self.api_port = api_port

        # 1. API + Dashboard Server
        if self.is_port_in_use(self.api_port):
            logger.info(f"Port {self.api_port} still in use, waiting before starting API...")
            if not self.wait_for_port_free(self.api_port, timeout=10, delay=1):
                logger.warning(f"Port {self.api_port} still busy after waiting; attempting startup anyway.")
        self.start_process(
            "SIEM API",
            [self.python_exe, "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", str(self.api_port)],
            cwd=self.root_dir / "back-end",
            log_file="api.log"
        )
        # Wait for API to be healthy (increase timeout for database fallback)
        if not self.check_api_health(retries=60, delay=3):
            logger.error("API failed to start healthily. Aborting boot.")
            sys.exit(1)

        # 2. Analysis Worker (ML + Correlation)
        self.start_process(
            "Analysis Worker",
            [self.python_exe, "core/analysis_worker.py"],
            cwd=self.root_dir / "back-end",
            log_file="analysis_worker.log"
        )
        time.sleep(2)

        # 3. SOAR Worker (Response Orchestration)
        self.start_process(
            "SOAR Worker",
            [self.python_exe, "core/soar_worker.py"],
            cwd=self.root_dir / "back-end",
            log_file="soar_worker.log"
        )
        time.sleep(2)

        # 4. Ingestion Bridge (Snort-to-Bus)
        alert_log = self.root_dir / "alert_json.txt"
        if not alert_log.exists():
            alert_log.parent.mkdir(parents=True, exist_ok=True)
            alert_log.touch()

        self.start_process(
            "Snort Bridge",
            [self.python_exe, "core/snort_bridge.py", f"http://localhost:{self.api_port}", str(alert_log)],
            cwd=self.root_dir / "back-end",
            log_file="snort_bridge.log"
        )

        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        self.monitoring_thread.start()

        print("\n" + "="*60)
        print("  SYSTEM READY - Operational in Distributed Mode")
        print("="*60 + "\n")
        print(f"  -> API: http://localhost:{self.api_port}")
        print(f"  -> WS:  ws://localhost:{self.api_port}/ws/events")
        
        if os.name == 'nt':
            print("\n  [WINDOWS DETECTED - VMWARE OPTIMIZED]")
            print("  - To start Snort 3 on Windows with VMware support, run:")
            print("    powershell -ExecutionPolicy Bypass -File scripts\\run_snort_windows.ps1")
            print("  - See docs\\README_VMWARE.md for network setup instructions.")
        else:
            print("\n  [LINUX DETECTED]")
            print("  - To start Snort 3, run:")
            print("    sudo bash scripts/run_snort.sh")
            
        print("\n  (Press Ctrl+C to shutdown all services)\n")

    def shutdown(self):
        """Cleanly shuts down all child processes."""
        logger.info("Initiating system shutdown...")
        self.shutdown_event.set()
        for name, (proc, log_file) in self.processes.items():
            logger.info(f"Stopping {name}...")
            proc.terminate()
            if log_file:
                try:
                    open(self.logs_dir / log_file, 'a').close()  # Ensure file is closed
                except:
                    pass
        
        # Wait a bit for graceful cleanup
        time.sleep(2)
        
        # Kill if still alive
        for name, (proc, log_file) in self.processes.items():
            if proc.poll() is None:
                proc.kill()
        
        logger.info("All services stopped.")

def main():
    orchestrator = SystemOrchestrator()
    try:
        orchestrator.boot()
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        orchestrator.shutdown()
        sys.exit(0)

if __name__ == "__main__":
    main()
