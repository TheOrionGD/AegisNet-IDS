from fastapi.testclient import TestClient
from src.api.main import app
import json

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "OK"
    print("Health check passed.")

def test_alerts():
    response = client.get("/alerts?limit=1")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    print(f"Alerts check passed. Found {len(data)} alerts.")

def test_incidents():
    response = client.get("/incidents?limit=1")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    print(f"Incidents check passed. Found {len(data)} incidents.")

def test_anomalies():
    response = client.get("/anomalies?limit=1")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    print(f"Anomalies check passed. Found {len(data)} anomalies.")

if __name__ == "__main__":
    try:
        test_health()
        test_alerts()
        test_incidents()
        test_anomalies()
        print("All API tests passed!")
    except Exception as e:
        print(f"API tests failed: {e}")
