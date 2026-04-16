import sys
from pathlib import Path

# Add back-end to path
sys.path.append(str(Path("back-end").resolve()))

from config_loader import load_config

try:
    config = load_config()
    db_url = config.get('database', {}).get('url')
    print(f"DATABASE_URL: {db_url}")
except Exception as e:
    print(f"Error loading config: {e}")
