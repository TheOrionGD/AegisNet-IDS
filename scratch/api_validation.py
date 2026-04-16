import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_siem_workflow():
    print("--- CNS SIEM API VALIDATION ---")
    
    # 1. Register User
    print("\n[1/4] Registering new Tactical Operator...")
    reg_payload = {
        "username": f"operator_{int(time.time())}",
        "email": f"test_{int(time.time())}@cns.io",
        "password": "securepassword123"
    }

    
    try:
        reg_res = requests.post(f"{BASE_URL}/auth/users/", json=reg_payload)
        reg_res.raise_for_status()
        print(f"SUCCESS: Operator {reg_payload['username']} registered.")
    except Exception as e:
        print(f"FAILED: Registration error - {e}")
        if hasattr(e, 'response'): print(f"Response: {e.response.text}")
        return

    # 2. Login (Get Token)
    print("\n[2/4] Initializing Tactical Link (Login)...")
    login_data = {
        "username": reg_payload['username'],
        "password": reg_payload['password']
    }
    
    try:
        # OAuth2PasswordRequestForm expects form-encoded data
        login_res = requests.post(f"{BASE_URL}/auth/token", data=login_data)
        login_res.raise_for_status()
        token = login_res.json()["access_token"]
        print("SUCCESS: JWT Authorization acquired.")
    except Exception as e:
        print(f"FAILED: Login error - {e}")
        return

    headers = {"Authorization": f"Bearer {token}"}

    # 3. Fetch Alerts
    print("\n[3/4] Pulling Tactical Alerts...")
    try:
        alerts_res = requests.get(f"{BASE_URL}/alerts", headers=headers)
        alerts_res.raise_for_status()
        alerts = alerts_res.json()
        print(f"SUCCESS: Retrieved {len(alerts)} alerts from the buffer.")
        if alerts:
            print(f"Sample: {alerts[0].get('message', 'No message')}")
    except Exception as e:
        print(f"FAILED: Alerts retrieval error - {e}")

    # 4. Fetch Incidents
    print("\n[4/4] Retrieving High-Priority Incidents...")
    try:
        inc_res = requests.get(f"{BASE_URL}/incidents", headers=headers)
        inc_res.raise_for_status()
        incidents = inc_res.json()
        print(f"SUCCESS: Retrieved {len(incidents)} incidents.")
        if incidents:
            print(f"Active Incident: {incidents[0].get('title', 'Untitled')}")
    except Exception as e:
        print(f"FAILED: Incidents retrieval error - {e}")

    print("\n--- VALIDATION COMPLETE ---")

if __name__ == "__main__":
    test_siem_workflow()
