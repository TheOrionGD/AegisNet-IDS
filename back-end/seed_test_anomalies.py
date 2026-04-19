#!/usr/bin/env python3
"""
Seed test anomalies data into MongoDB Atlas 'anomalies' collection.
This creates realistic test data for the dashboard.
"""

import asyncio
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

# Set up path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent))

from api.models.database import connect_to_mongo, get_database

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
    """Seed test anomalies to MongoDB Atlas."""
    await connect_to_mongo()
    db = get_database()
    
    if db is None:
        print("❌ Failed to connect to MongoDB Atlas")
        return
    
    collection = db.anomalies
    
    # Clear existing data
    await collection.delete_many({})
    print(f"Cleared existing anomalies")
    
    base_time = datetime.utcnow() - timedelta(hours=24)
    anomalies = []

    for i in range(count):
        timestamp = base_time + timedelta(
            minutes=random.randint(0, 1440), 
            seconds=random.randint(0, 59)
        )

        src_ip = f"{random.choice(IP_SEGMENTS)}.{random.randint(1, 254)}"
        dst_ip = f"{random.choice(IP_SEGMENTS)}.{random.randint(1, 254)}"

        score = round(random.uniform(0.5, 1.0), 3)
        model_type = random.choice(MODEL_TYPES)
        message = random.choice(ANOMALY_MESSAGES)

        anomaly = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "score": score,
            "model_type": model_type,
            "message": message,
            "features": {
                "packet_count": random.randint(10, 1000),
                "avg_packet_size": random.randint(50, 1500),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            },
        }
        anomalies.append(anomaly)

    # Bulk insert
    result = await collection.insert_many(anomalies)
    print(f"✅ Successfully seeded {len(result.inserted_ids)} anomalies to MongoDB Atlas")
    print(f"   Collection: {collection.name}")
    print(f"   Database: {db.name}")


def main():
    """Run the seed operation."""
    try:
        asyncio.run(seed_anomalies_async(50))
        print("\n✅ Seeding completed successfully!")
        print("   You can now fetch anomalies from: GET /anomalies")
    except Exception as e:
        print(f"\n❌ Seeding failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
