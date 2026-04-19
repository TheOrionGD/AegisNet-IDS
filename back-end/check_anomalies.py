import asyncio
from siem.storage import get_storage


async def check_anomalies():
    storage = get_storage()
    count = await storage.db["ids_events"].count_documents({"is_anomaly": True})
    print(f"ML Anomalies: {count}")


if __name__ == "__main__":
    asyncio.run(check_anomalies())
