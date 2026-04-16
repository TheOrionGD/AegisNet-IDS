import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent
back_end_path = repo_root / "back-end"
ml_services_path = repo_root / "ml_services"

for p in [str(repo_root), str(back_end_path), str(ml_services_path)]:
    if p not in sys.path:
        sys.path.insert(0, p)
