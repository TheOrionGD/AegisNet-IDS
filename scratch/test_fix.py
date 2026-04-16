import pandas as pd
import datetime
import sys
import os

# Add relevant paths
sys.path.append(os.path.abspath("."))
sys.path.append(os.path.abspath("back-end"))

from ml_services.feature_engineering import FeatureEngineer

def test_robustness():
    engineer = FeatureEngineer(window_size='1min')
    
    # Case 1: Alert with 'proto' instead of 'protocol'
    raw_alert = {
        "timestamp": datetime.datetime.utcnow(),
        "proto": "TCP",
        "src_addr": "192.168.1.100",
        "dst_addr": "10.0.0.5",
        "src_port": 1234,
        "dest_port": 80,
        "pkt_num": 100
    }
    
    df = pd.DataFrame([raw_alert])
    print("Testing alert with 'proto' and 'src_addr'...")
    try:
        features = engineer.extract_features(df)
        print("SUCCESS: Features extracted.")
        print(f"Columns: {features.columns.tolist()}")
        if 'protocol_TCP_count' in features.columns:
            print("SUCCESS: 'proto' mapped to 'protocol' results.")
    except Exception as e:
        print(f"FAILED: {e}")

    # Case 2: Alert with MISSING protocol
    missing_alert = {
        "timestamp": datetime.datetime.utcnow(),
        "src_ip": "192.168.1.100",
        # no protocol
    }
    df_missing = pd.DataFrame([missing_alert])
    print("\nTesting alert with MISSING protocol...")
    try:
        features = engineer.extract_features(df_missing)
        print("SUCCESS: Features extracted despite missing protocol.")
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    test_robustness()
