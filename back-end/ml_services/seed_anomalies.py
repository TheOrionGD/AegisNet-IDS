import sqlite3
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "siem.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

MODEL_TYPES = [
    "Isolation Forest",
    "LSTM Autoencoder",
    "Random Forest",
    "One-Class SVM",
    "Deep Autoencoder",
]
ANOMALY_MESSAGES = [
    "Unusual packet length distribution detected from source",
    "Behavioral pattern deviation exceeds threshold",
    "Sequential port scan activity detected",
    "Abrupt change in network traffic entropy",
    "Anomalous protocol sequence identified",
    "Statistical outlier in packet timing patterns",
    "Deviation from learned baseline behavior",
    "Cluster of suspicious network beacons detected",
    "Multi-vector attack signature matched",
    "Unusual data exfiltration pattern identified",
]
IP_SEGMENTS = ["192.168.1", "10.0.0", "172.16.0", "192.168.2", "10.10.10"]


def seed_anomalies(count=50):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_logs (
            id TEXT PRIMARY KEY,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            severity TEXT,
            label TEXT,
            alert_type TEXT DEFAULT 'IDS',
            timestamp TEXT,
            raw_data TEXT
        )
    """)
    conn.commit()

    base_time = datetime.now() - timedelta(hours=24)

    for i in range(count):
        timestamp = base_time + timedelta(
            minutes=random.randint(0, 1440), seconds=random.randint(0, 59)
        )

        src_ip = f"{random.choice(IP_SEGMENTS)}.{random.randint(1, 254)}"
        dst_ip = f"{random.choice(IP_SEGMENTS)}.{random.randint(1, 254)}"

        protocol = random.choice(["TCP", "UDP", "ICMP"])
        model_type = random.choice(MODEL_TYPES)
        message = random.choice(ANOMALY_MESSAGES)
        anomaly_score = round(random.uniform(0.5, 1.0), 3)

        raw_payload = json.dumps(
            {
                "anomaly_score": anomaly_score,
                "model_type": model_type,
                "message": message,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
            }
        )

        log_id = str(uuid.uuid4())

        cursor.execute(
            """
            INSERT OR REPLACE INTO raw_logs
            (id, src_ip, dst_ip, protocol, severity, alert_type, timestamp, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                log_id,
                src_ip,
                dst_ip,
                protocol,
                "HIGH",
                "ML_ANOMALY",
                timestamp.isoformat(),
                raw_payload,
            ),
        )

    conn.commit()
    conn.close()
    print(f"Successfully seeded {count} ML anomalies to {DB_PATH}")


if __name__ == "__main__":
    seed_anomalies(50)
