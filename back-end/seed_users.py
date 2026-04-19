#!/usr/bin/env python3
"""
Seed MongoDB with RBAC-enabled users.
Creates two users:
  - oriongd (admin): Full system access
  - grish (analyst): Read-only access, can view dashboards and logs
"""

import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from api.auth import get_password_hash
from api.models.database import connect_to_mongo, get_database


async def seed_users_async():
    """Initialize users with roles in MongoDB."""
    await connect_to_mongo()
    db = get_database()
    
    if db is None:
        print("❌ Failed to connect to MongoDB Atlas")
        return
    
    collection = db.users
    
    # Seed users with proper structure
    users = [
        {
            "username": "oriongd",
            "email": "oriongd@aegis.net",
            "password_hash": get_password_hash("oriongd"),
            "role": "admin",
            "is_active": True,
            "created_at": "2026-04-20T00:00:00Z",
            "permissions": [
                "view:dashboard",
                "view:alerts",
                "view:anomalies",
                "view:incidents",
                "manage:rules",
                "manage:users",
                "system:reset",
                "manage:ml_models"
            ]
        },
        {
            "username": "grish",
            "email": "grish@aegis.net",
            "password_hash": get_password_hash("grish"),
            "role": "analyst",
            "is_active": True,
            "created_at": "2026-04-20T00:00:00Z",
            "permissions": [
                "view:dashboard",
                "view:alerts",
                "view:anomalies",
                "view:incidents",
                "view:logs"
            ]
        }
    ]
    
    # Delete existing users and insert new ones
    await collection.delete_many({})
    result = await collection.insert_many(users)
    
    print(f"✅ Successfully created {len(result.inserted_ids)} users in MongoDB Atlas")
    print(f"\n   Users:")
    print(f"   ├─ oriongd@aegis.net (admin)")
    print(f"   │  └─ Password: oriongd")
    print(f"   └─ grish@aegis.net (analyst)")
    print(f"      └─ Password: grish")
    print(f"\n   Collection: {collection.name}")
    print(f"   Database: {db.name}")


def main():
    """Run the seed operation."""
    try:
        asyncio.run(seed_users_async())
        print("\n✅ User seeding completed successfully!")
    except Exception as e:
        print(f"\n❌ User seeding failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
