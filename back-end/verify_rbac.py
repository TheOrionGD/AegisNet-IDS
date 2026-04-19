#!/usr/bin/env python3
import asyncio
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from api.models.database import connect_to_mongo, get_database

async def verify_rbac():
    await connect_to_mongo()
    db = get_database()
    users = await db.users.find().to_list(length=100)
    print(f'\n✅ Found {len(users)} RBAC users in MongoDB:')
    for user in users:
        print(f'   • {user["username"]} ({user["email"]}) - Role: {user["role"]}')
    
    anomalies = await db.anomalies.find().to_list(length=1)
    anomaly_count = await db.anomalies.count_documents({})
    print(f'\n✅ Found {anomaly_count} anomalies in MongoDB collection')
    print(f'   Sample anomaly timestamp: {anomalies[0].get("timestamp") if anomalies else "N/A"}')

asyncio.run(verify_rbac())
