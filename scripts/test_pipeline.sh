#!/bin/bash
set -e

python3 src/train.py
python3 src/detect.py

echo "Pipeline complete."
echo "Processed data saved to: $(python3 -c 'import yaml; c=__import__("yaml").safe_load(open("config/config.yaml")); print(c["paths"]["processed_data"])')"
echo "Model saved to: $(python3 -c 'import yaml; c=__import__("yaml").safe_load(open("config/config.yaml")); print(c["paths"]["model_path"])')"
echo "Anomalies written to: $(python3 -c 'import yaml; c=__import__("yaml").safe_load(open("config/config.yaml")); print(c["paths"]["anomalies_output"])')"
