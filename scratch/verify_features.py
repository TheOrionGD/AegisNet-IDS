from fastapi.testclient import TestClient
import sys
import os

# Add paths to sys.path
sys.path.append(os.getcwd())
sys.path.append(os.path.join(os.getcwd(), "back-end"))

from api.main import app

client = TestClient(app)

def test_auth_flow():
    print("Testing Auth Flow...")
    # 1. Create User
    user_data = {
        "username": "admin_test",
        "email": "admin@example.com",
        "password": "strongpassword123"
    }
    response = client.post("/auth/users/", json=user_data)
    if response.status_code == 400 and "already registered" in response.text:
        print("User already exists, proceeding to token...")
    else:
        assert response.status_code == 200
        print("User created successfully.")

    # 2. Get Token
    token_data = {
        "username": "admin_test",
        "password": "strongpassword123"
    }
    response = client.post("/auth/token", data=token_data)
    assert response.status_code == 200
    token = response.json()["access_token"]
    print("Token retrieved successfully.")
    return token

def test_ingestion(token):
    print("Testing Ingestion...")
    # Ingest Alert
    alert = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "protocol": "TCP",
        "alert_type": "UA_ACCESS",
        "severity": "CRITICAL",
        "raw_payload": {"msg": "SQL Injection Attempt"}
    }
    response = client.post("/ingest", json=alert)
    assert response.status_code == 200
    print("Alert ingestion successful.")

    # Ingest Batch
    batch = [
        {"src_ip": "1.1.1.1", "alert_type": "DNS_SCAN"},
        {"src_ip": "2.2.2.2", "alert_type": "PORT_SCAN"}
    ]
    response = client.post("/ingest/batch", json=batch)
    assert response.status_code == 200
    assert response.json()["count"] == 2
    print("Batch ingestion successful.")

if __name__ == "__main__":
    try:
        token = test_auth_flow()
        test_ingestion(token)
        print("\nAll feature verifications passed!")
    except Exception as e:
        print(f"\nVerification failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
