import json
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

def generate_normal_logs(num=100):
    logs = []
    base_time = datetime.now()
    for i in range(num):
        timestamp = (base_time + timedelta(seconds=i)).isoformat() + '+0000'
        log = {
            "timestamp": timestamp,
            "event": {
                "source": {"ip": f"192.168.1.{random.randint(1,255)}", "port": random.randint(1024,65535)},
                "destination": {"ip": f"10.0.0.{random.randint(1,255)}", "port": 80},
                "protocol": random.choice(["TCP", "UDP"]),
                "packet": {"length": random.randint(64,1500)}
            }
        }
        logs.append(log)
    return logs

def generate_dos_burst(num=500):
    logs = []
    base_time = datetime.now()
    dst_ip = "10.0.0.1"
    for i in range(num):
        timestamp = (base_time + timedelta(milliseconds=i*10)).isoformat() + '+0000'
        log = {
            "timestamp": timestamp,
            "event": {
                "source": {"ip": f"192.168.1.{random.randint(1,255)}", "port": random.randint(1024,65535)},
                "destination": {"ip": dst_ip, "port": 80},
                "protocol": "TCP",
                "packet": {"length": 100}
            }
        }
        logs.append(log)
    return logs

def generate_port_scan(num=100):
    logs = []
    base_time = datetime.now()
    dst_ip = "10.0.0.1"
    for i in range(num):
        timestamp = (base_time + timedelta(seconds=i)).isoformat() + '+0000'
        log = {
            "timestamp": timestamp,
            "event": {
                "source": {"ip": "192.168.1.100", "port": random.randint(1024,65535)},
                "destination": {"ip": dst_ip, "port": random.randint(1,1023)},
                "protocol": "TCP",
                "packet": {"length": 64}
            }
        }
        logs.append(log)
    return logs

def generate_unusual_protocol(num=50):
    logs = []
    base_time = datetime.now()
    for i in range(num):
        timestamp = (base_time + timedelta(seconds=i)).isoformat() + '+0000'
        log = {
            "timestamp": timestamp,
            "event": {
                "source": {"ip": f"192.168.1.{random.randint(1,255)}", "port": 0},
                "destination": {"ip": f"10.0.0.{random.randint(1,255)}", "port": 0},
                "protocol": "ICMP",
                "packet": {"length": 64}
            }
        }
        logs.append(log)
    return logs

def save_logs(logs, filename):
    path = Path("data/raw_logs") / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        for log in logs:
            f.write(json.dumps(log) + '\n')
    print(f"Saved {len(logs)} logs to {path}")

if __name__ == "__main__":
    # Normal traffic
    normal = generate_normal_logs(100)
    save_logs(normal, "normal.json")

    # Anomalies
    dos = generate_dos_burst(500)
    save_logs(dos, "dos_burst.json")

    port_scan = generate_port_scan(100)
    save_logs(port_scan, "port_scan.json")

    unusual = generate_unusual_protocol(50)
    save_logs(unusual, "unusual_protocol.json")

    print("Simulation logs generated.")