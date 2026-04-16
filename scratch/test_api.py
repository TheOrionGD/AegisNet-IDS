import requests
import sys

def test_root():
    try:
        r = requests.get("http://localhost:8000/")
        print(f"Status: {r.status_code}")
        print(f"Content: {r.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_root()
