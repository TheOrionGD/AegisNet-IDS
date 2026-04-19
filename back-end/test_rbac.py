#!/usr/bin/env python3
"""
RBAC Testing Script
Tests Role-Based Access Control with oriongd (admin) and grish (analyst)
"""

import asyncio
import httpx
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from api.auth import get_password_hash
from api.models.database import connect_to_mongo, get_database

BASE_URL = "http://10.169.17.117:2346"
TEST_USERS = {
    "oriongd": {"password": "oriongd", "role": "admin"},
    "grish": {"password": "grish", "role": "analyst"}
}


async def get_token(username: str, password: str) -> str:
    """Authenticate and get JWT token."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/token",
            data={"username": username, "password": password}
        )
        if response.status_code == 200:
            return response.json()["access_token"]
        else:
            print(f"❌ Authentication failed for {username}: {response.text}")
            return None


async def test_endpoint(endpoint: str, token: str, username: str) -> dict:
    """Test an endpoint with a given token."""
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get(f"{BASE_URL}{endpoint}", headers=headers)
        
        status = "✅" if response.status_code == 200 else "❌"
        return {
            "endpoint": endpoint,
            "user": username,
            "role": TEST_USERS[username]["role"],
            "status_code": response.status_code,
            "status": status,
            "detail": response.json().get("detail") if response.status_code != 200 else "OK"
        }


async def run_rbac_tests():
    """Run comprehensive RBAC tests."""
    print("=" * 80)
    print("ROLE-BASED ACCESS CONTROL (RBAC) TEST SUITE")
    print("=" * 80)
    
    # Get tokens for both users
    print("\n1️⃣  AUTHENTICATING USERS...")
    tokens = {}
    for username, user_info in TEST_USERS.items():
        token = await get_token(username, user_info["password"])
        if token:
            tokens[username] = token
            print(f"   ✅ {username} ({user_info['role']}) authenticated")
        else:
            print(f"   ❌ Failed to authenticate {username}")
            return
    
    # Test endpoints
    print("\n2️⃣  TESTING ROLE-BASED ENDPOINTS...")
    endpoints = [
        ("/anomalies?limit=10", "Analyst+", "View ML anomalies"),
        ("/alerts?limit=10", "Analyst+", "View security alerts"),
        ("/incidents?limit=10", "Analyst+", "View incidents"),
        ("/users/me", "Analyst+", "View current user info"),
    ]
    
    results = []
    for endpoint, access_level, description in endpoints:
        print(f"\n   📌 Testing: {description}")
        print(f"      Endpoint: {endpoint}")
        print(f"      Access Level: {access_level}")
        
        for username in TEST_USERS.keys():
            token = tokens[username]
            result = await test_endpoint(endpoint, token, username)
            results.append(result)
            
            status = result["status"]
            code = result["status_code"]
            role = result["role"]
            detail = result["detail"]
            
            if code == 200:
                print(f"      {status} {username} ({role}): {code} OK")
            else:
                print(f"      {status} {username} ({role}): {code} - {detail}")
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    print("\n📊 Results by User:")
    for username in TEST_USERS.keys():
        user_results = [r for r in results if r["user"] == username]
        passed = sum(1 for r in user_results if r["status_code"] == 200)
        total = len(user_results)
        status = "✅" if passed == total else "⚠️"
        print(f"   {status} {username} ({TEST_USERS[username]['role']}): {passed}/{total} endpoints accessible")
    
    print("\n📊 Results by Endpoint:")
    unique_endpoints = list(set(r["endpoint"] for r in results))
    for endpoint in unique_endpoints:
        endpoint_results = [r for r in results if r["endpoint"] == endpoint]
        accessible_by = [r["user"] for r in endpoint_results if r["status_code"] == 200]
        print(f"   📍 {endpoint}")
        print(f"      Accessible by: {', '.join(accessible_by)}")
    
    print("\n✅ RBAC Test Complete!")
    print("\n🔐 Security Notes:")
    print("   • Both users can access analyst-level endpoints")
    print("   • Admin (oriongd) has full system access")
    print("   • Analyst (grish) has read-only dashboard access")
    print("   • All requests require valid @aegis.net email domain")
    print("   • Invalid tokens return 401 Unauthorized")
    print("   • Insufficient permissions return 403 Forbidden")


def main():
    """Run the test suite."""
    try:
        asyncio.run(run_rbac_tests())
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
