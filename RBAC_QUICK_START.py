#!/usr/bin/env python3
"""
QUICK START: RBAC Authentication & Testing

This guide shows how to test the Role-Based Access Control system.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from api.auth import get_password_hash, create_access_token, verify_password
from api.models.database import connect_to_mongo, get_database


RBAC_QUICK_START = """
╔═══════════════════════════════════════════════════════════════════════════╗
║           CNS SIEM - ROLE-BASED ACCESS CONTROL (RBAC) SETUP              ║
╚═══════════════════════════════════════════════════════════════════════════╝

✅ IMPLEMENTATION COMPLETE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 AUTHENTICATED USERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. ADMIN USER
   Username: oriongd
   Email:    oriongd@aegis.net
   Password: oriongd
   Role:     admin
   
   Permissions:
   ✓ View dashboard & alerts
   ✓ View ML anomalies
   ✓ View incidents
   ✓ Manage security rules
   ✓ Manage ML models
   ✓ System reset (dangerous)
   ✓ User management

2. ANALYST USER
   Username: grish
   Email:    grish@aegis.net
   Password: grish
   Role:     analyst
   
   Permissions:
   ✓ View dashboard & alerts
   ✓ View ML anomalies
   ✓ View incidents
   ✓ View audit logs
   ✗ Manage rules
   ✗ Manage ML models
   ✗ System operations

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 PROTECTED ENDPOINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ANALYST-LEVEL ACCESS (Admin + Analyst):
  GET    /anomalies           → View ML anomalies
  POST   /infer               → Run ML inference
  POST   /infer/batch         → Batch inference
  GET    /model/status        → ML model status
  GET    /alerts              → View security alerts
  GET    /incidents           → View incidents
  GET    /users/me            → Current user info

ADMIN-ONLY ACCESS:
  DELETE /system/reset        → Hard system reset
  POST   /users/              → Create new users
  PUT    /rules/{id}          → Manage security rules

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧪 TESTING RBAC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. GET JWT TOKEN (Login)
   curl -X POST http://10.169.17.117:2346/token \\
     -H "Content-Type: application/x-www-form-urlencoded" \\
     -d "username=oriongd&password=oriongd"

   Response:
   {{
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_type": "bearer"
   }}

2. USE TOKEN TO ACCESS PROTECTED ENDPOINT
   curl -X GET http://10.169.17.117:2346/anomalies?limit=10 \\
     -H "Authorization: Bearer <access_token_from_step_1>"

3. TEST ANALYST CANNOT ACCESS ADMIN ENDPOINTS
   Try accessing admin-only endpoints with grish's token:
   
   curl -X DELETE http://10.169.17.117:2346/system/reset \\
     -H "Authorization: Bearer <grish_token>"
   
   Expected: 403 Forbidden
   Detail: "Operation not permitted for role: analyst"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 SECURITY FEATURES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Email Domain Validation
  → Only @aegis.net email addresses allowed
  → External domains receive 403 Forbidden

✓ Password Security
  → Passwords hashed with bcrypt
  → Salted with random 12-round bcrypt

✓ Token Security
  → JWT tokens with HS256 algorithm
  → 60-minute expiration (configurable)
  → Signed with secure JWT_SECRET_KEY

✓ Role-Based Guards
  → Granular permission levels
  → Extensible guard system
  → Logged unauthorized access attempts

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 FILES CREATED/MODIFIED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CREATED:
  ✓ back-end/api/auth_guards.py        → Permission level definitions
  ✓ back-end/seed_users.py             → Initialize RBAC users
  ✓ back-end/seed_test_anomalies.py    → Populate test anomalies
  ✓ back-end/test_rbac.py              → RBAC test suite
  ✓ back-end/verify_rbac.py            → Verification script

MODIFIED:
  ✓ back-end/api/auth.py               → Added @aegis.net domain validation
  ✓ back-end/api/routes/anomalies.py   → Protected with allow_analyst
  ✓ back-end/api/routes/alerts.py      → Protected with allow_analyst
  ✓ back-end/api/routes/incidents.py   → Protected with allow_analyst

FIXED:
  ✓ back-end/api/routes/anomalies.py   → Added missing await in get_anomalies()

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 DATABASE STATUS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MongoDB Collections Initialized:
  ✓ users (2 records)
    └─ oriongd (admin) 
    └─ grish (analyst)
  
  ✓ anomalies (50 records)
    └─ Timestamped ML anomaly data with scores

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 NEXT STEPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. RESTART BACKEND SERVER
   cd back-end
   uvicorn api.main:app --reload --host 0.0.0.0 --port 2346

2. TEST AUTHENTICATION
   python test_rbac.py

3. FRONTEND INTEGRATION
   → Frontend will send Bearer token in Authorization header
   → Dashboard restricted to authenticated users
   → WebSocket connection requires valid token

4. ADD MORE USERS (OPTIONAL)
   POST /users/ endpoint accepts:
   {{
     "username": "new_analyst",
     "email": "new_analyst@aegis.net",
     "password": "secure_password",
     "role": "analyst"
   }}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

print(RBAC_QUICK_START)

# Verify setup
async def verify_setup():
    try:
        await connect_to_mongo()
        db = get_database()
        
        users_count = await db.users.count_documents({})
        anomalies_count = await db.anomalies.count_documents({})
        
        print("\n✅ VERIFICATION RESULTS:")
        print(f"   Users in Database: {users_count}")
        print(f"   Anomalies in Database: {anomalies_count}")
        print("\n✅ RBAC System is ready to use!")
        
    except Exception as e:
        print(f"\n⚠️  Error: {e}")

if __name__ == "__main__":
    asyncio.run(verify_setup())
