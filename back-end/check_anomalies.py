import sqlite3

conn = sqlite3.connect("data/cns.db")
cursor = conn.execute("SELECT COUNT(*) FROM raw_logs WHERE alert_type = 'ML_ANOMALY'")
print("ML Anomalies:", cursor.fetchone()[0])
conn.close()
