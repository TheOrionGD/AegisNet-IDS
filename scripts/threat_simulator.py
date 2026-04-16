#!/usr/bin/env python3
"""
CNS Threat Simulation Engine (TSE)
A comprehensive tool to simulate cyber threats for SIEM/IDS testing.
Supports both live network traffic (Scapy) and synthetic log generation.
"""

import os
import sys
import json
import random
import time
import argparse
import logging
from datetime import datetime, timedelta
from pathlib import Path

# Scapy is optional for synthetic mode
try:
    from scapy.all import IP, TCP, UDP, ICMP, send, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Add project root to sys.path for internal imports
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_PATH = ROOT_DIR / "back-end"
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from siem.threat_defs import RECONNAISSANCE, DOS, EXFILTRATION, C2_BEACONING, WEB_ATTACK, SIGNATURES, THRESHOLDS, TARGET_PORTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class ThreatSimulator:
    def __init__(self, target_ip='127.0.0.1', mode='synthetic', output_dir='data/raw_logs'):
        self.target_ip = target_ip
        self.mode = mode
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if mode == 'live' and not SCAPY_AVAILABLE:
            logger.error("Scapy not found. Live mode unavailable. Install scapy or use 'synthetic' mode.")
            sys.exit(1)
        
        logger.info(f"Initialized TSE in {mode} mode targeting {target_ip}")

    def _generate_log(self, src_ip, dst_ip, src_port, dst_port, protocol, length=64, timestamp=None, payload=None):
        if not timestamp:
            timestamp = datetime.now().isoformat() + '+0000'
        
        log = {
            "timestamp": timestamp,
            "event": {
                "source": {"ip": src_ip, "port": src_port},
                "destination": {"ip": dst_ip, "port": dst_port},
                "protocol": protocol,
                "packet": {"length": length}
            }
        }
        if payload:
            log["event"]["payload"] = payload
        return log

    def _save_logs(self, logs, filename):
        path = self.output_dir / filename
        with open(path, 'a', encoding='utf-8') as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
        logger.info(f"Saved {len(logs)} logs to {path}")

    def _send_packets(self, packets, verbose=False):
        if self.mode == 'live' and SCAPY_AVAILABLE:
            send(packets, verbose=verbose)
        else:
            logger.warning("Packet sending ignored in synthetic mode.")

    def run_recon(self, scan_type='port_scan'):
        """Simulate reconnaissance attacks."""
        logger.info(f"Running reconnaissance: {scan_type}")
        src_ip = "192.168.1.100"
        logs = []
        packets = []
        
        if scan_type == 'port_scan':
            ports = range(20, 20 + THRESHOLDS['port_scan_min_ports'] + 10)
            for port in ports:
                if self.mode == 'synthetic':
                    logs.append(self._generate_log(src_ip, self.target_ip, random.randint(1024, 65535), port, "TCP"))
                else:
                    packets.append(IP(dst=self.target_ip) / TCP(dport=port, flags='S'))
        
        elif scan_type == 'icmp_sweep':
            for i in range(1, 255):
                dst = f"10.0.0.{i}"
                if self.mode == 'synthetic':
                    logs.append(self._generate_log(src_ip, dst, 0, 0, "ICMP"))
                else:
                    packets.append(IP(dst=dst) / ICMP())

        if self.mode == 'synthetic':
            self._save_logs(logs, "recon_anomalies.json")
        else:
            self._send_packets(packets)

    def run_dos(self, attack_type='syn_flood'):
        """Simulate DoS attacks."""
        logger.info(f"Running DoS: {attack_type}")
        src_ip = "192.168.1.50"
        logs = []
        packets = []
        count = THRESHOLDS['dos_min_packets'] + 50
        
        if attack_type == 'syn_flood':
            for _ in range(count):
                if self.mode == 'synthetic':
                    logs.append(self._generate_log(src_ip, self.target_ip, random.randint(1024, 65535), 80, "TCP"))
                else:
                    packets.append(IP(dst=self.target_ip) / TCP(dport=80, flags='S'))
        
        elif attack_type == 'log_burst':
            for i in range(1000):
                # Simulated high frequency logs
                logs.append(self._generate_log(f"192.168.1.{random.randint(1,255)}", self.target_ip, random.randint(1024, 65535), 80, "TCP"))

        if self.mode == 'synthetic' or attack_type == 'log_burst':
            self._save_logs(logs, "dos_anomalies.json")
        else:
            self._send_packets(packets)

    def run_exfiltration(self, num_packets=50):
        """Simulate data exfiltration."""
        logger.info("Running exfiltration simulation")
        src_ip = "10.0.0.5" # Internal host
        dst_ip = "1.2.3.4"   # External malicious IP
        logs = []
        packets = []
        
        for _ in range(num_packets):
            length = random.randint(1100, 1500)
            if self.mode == 'synthetic':
                logs.append(self._generate_log(src_ip, dst_ip, 4444, 443, "TCP", length=length))
            else:
                packets.append(IP(dst=dst_ip) / TCP(dport=443) / Raw(load="A" * length))

        if self.mode == 'synthetic':
            self._save_logs(logs, "exfil_anomalies.json")
        else:
            self._send_packets(packets)

    def run_c2_beaconing(self, duration_mins=5, interval_secs=30):
        """Simulate command and control beaconing."""
        logger.info(f"Running C2 beaconing simulation (Duration: {duration_mins}m, Interval: {interval_secs}s)")
        src_ip = "10.0.0.10"
        dst_ip = "99.88.77.66"
        logs = []
        
        base_time = datetime.now()
        num_beacons = (duration_mins * 60) // interval_secs
        
        for i in range(num_beacons):
            timestamp = (base_time + timedelta(seconds=i * interval_secs)).isoformat() + '+0000'
            ua = random.choice(SIGNATURES[C2_BEACONING]['user_agents'])
            if self.mode == 'synthetic':
                logs.append(self._generate_log(src_ip, dst_ip, random.randint(1024, 65535), 443, "TCP", timestamp=timestamp, payload=ua))
            else:
                # In live mode we just sleep and send
                pkt = IP(dst=dst_ip) / TCP(dport=443) / Raw(load=f"GET /beacon HTTP/1.1\r\nUser-Agent: {ua}\r\n\r\n")
                send(pkt, verbose=False)
                time.sleep(interval_secs)

        if self.mode == 'synthetic':
            self._save_logs(logs, "c2_anomalies.json")

    def run_web_attack(self, attack_type='sqli'):
        """Simulate web attacks with signatures in payloads."""
        logger.info(f"Running web attack: {attack_type}")
        src_ip = "192.168.1.75"
        logs = []
        
        patterns = SIGNATURES[WEB_ATTACK].get(attack_type, [])
        for pattern in patterns:
            # Simulated HTTP GET/POST with malicious payload
            payload = f"GET /search?q={pattern} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
            if self.mode == 'synthetic':
                logs.append(self._generate_log(src_ip, self.target_ip, random.randint(1024, 65535), 80, "TCP", payload=payload))
            else:
                pkt = IP(dst=self.target_ip) / TCP(dport=80) / Raw(load=payload)
                self._send_packets([pkt])

        if self.mode == 'synthetic':
            self._save_logs(logs, f"web_{attack_type}_anomalies.json")

def main():
    parser = argparse.ArgumentParser(description="CNS Threat Simulation Engine")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--mode", choices=["synthetic", "live"], default="synthetic", help="Simulation mode")
    parser.add_argument("--attack", choices=["recon", "dos", "exfil", "c2", "web", "all"], default="all", help="Attack type to simulate")
    parser.add_argument("--output", default="data/raw_logs", help="Output directory for logs")
    
    args = parser.parse_args()
    
    tse = ThreatSimulator(target_ip=args.target, mode=args.mode, output_dir=args.output)
    
    if args.attack == "recon" or args.attack == "all":
        tse.run_recon('port_scan')
        tse.run_recon('icmp_sweep')
        
    if args.attack == "dos" or args.attack == "all":
        tse.run_dos('syn_flood')
        tse.run_dos('log_burst')
        
    if args.attack == "exfil" or args.attack == "all":
        tse.run_exfiltration()
        
    if args.attack == "c2" or args.attack == "all":
        tse.run_c2_beaconing()
        
    if args.attack == "web" or args.attack == "all":
        tse.run_web_attack('sqli')
        tse.run_web_attack('xss')
        tse.run_web_attack('path_traversal')

if __name__ == "__main__":
    main()
