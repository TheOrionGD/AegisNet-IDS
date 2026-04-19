import asyncio
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from siem.storage import get_storage
from api.models.database import MONGODB_URL, DATABASE_NAME

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


async def seed_anomalies_async(count=50):
    storage = get_storage()
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

        event = {
            "id": str(uuid.uuid4()),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "severity": "HIGH",
            "alert_type": "ML_ANOMALY",
            "timestamp": timestamp.isoformat(),
            "is_anomaly": True,
            "ml_score": anomaly_score,
            "ml_risk_level": "HIGH" if anomaly_score > 0.7 else "MEDIUM",
            "raw_data": {
                "anomaly_score": anomaly_score,
                "model_type": model_type,
                "message": message,
            },
        }

        await storage.db["ids_events"].insert_one(event)

    print(f"Successfully seeded {count} ML anomalies to MongoDB Atlas")


def seed_anomalies(count=50):
    asyncio.run(seed_anomalies_async(count))


if __name__ == "__main__":
    seed_anomalies(50)
