import requests
import json
import time

BASE_URL = "http://localhost:8000"
TEST_USER = {
    "username": f"testuser_{int(time.time())}",
    "email": f"test_{int(time.time())}@example.com",
    "password": "testpassword123"
}

def test_endpoint(method, path, data=None, token=None):
    url = f"{BASE_URL}{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    print(f"Testing {method} {path}...", end=" ", flush=True)
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            # For /auth/token, it's form data
            if path == "/auth/token":
                response = requests.post(url, data=data, timeout=10)
            else:
                response = requests.post(url, json=data, headers=headers, timeout=10)
        
        if response.status_code in [200, 201]:
            print("[\033[92mSUCCESS\033[00m]")
            return response.json()
        else:
            print(f"[\033[91mFAILED\033[00m] (Status: {response.status_code})")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"[\033[91mERROR\033[00m] ({str(e)})")
        return None

def main():
    print("="*60)
    print("CNS SIEM API ENDPOINT VERIFICATION")
    print("="*60)

    # 1. Public Endpoints
    test_endpoint("GET", "/")
    test_endpoint("GET", "/health")

    # 2. Authentication Flow
    print("\nRegistering Test User...")
    reg_res = test_endpoint("POST", "/auth/users/", data=TEST_USER)
    
    token = None
    if reg_res:
        print("Logging in...")
        token_res = test_endpoint("POST", "/auth/token", data={
            "username": TEST_USER["username"],
            "password": TEST_USER["password"]
        })
        if token_res:
            token = token_res.get("access_token")

    if token:
        test_endpoint("GET", "/auth/users/me", token=token)
    else:
        print("Skipping protected endpoints due to auth failure.")

    # 3. Data Retrieval
    test_endpoint("GET", "/alerts")
    test_endpoint("GET", "/timeline")
    test_endpoint("GET", "/ips/top")
    test_endpoint("GET", "/incidents")
    test_endpoint("GET", "/anomalies")

    # 4. Ingestion
    sample_alert = {
        "source": "Snort",
        "event_type": "alert",
        "severity": 1,
        "message": "Verification Test Alert",
        "pkt_num": 99999,
        "src_addr": "192.168.1.100",
        "dest_addr": "10.0.0.5",
        "src_port": 1234,
        "dest_port": 80,
        "proto": "TCP"
    }
    test_endpoint("POST", "/ingest", data=sample_alert)
    test_endpoint("POST", "/ingest/batch", data=[sample_alert, sample_alert])

    print("\nVerification Complete.")
    print("="*60)

if __name__ == "__main__":
    main()
