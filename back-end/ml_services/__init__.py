# ml_services package initializer
#
# Loads the single root .env file so that standalone scripts (train.py,
# evaluate.py, simulate_anomalies.py, etc.) always find MONGODB_URL and
# other credentials regardless of the working directory they're launched from.
#
# This file lives at:  <project-root>/back-end/ml_services/__init__.py
#   parents[0] = back-end/ml_services/
#   parents[1] = back-end/
#   parents[2] = project root  (E:\PROJECTS\CNS)

from pathlib import Path
from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(dotenv_path=_PROJECT_ROOT / ".env", override=False)
