from typing import List, Dict, Any, Optional
from ..models.security_event import Anomaly
from ..repositories.base_repo import BaseRepository
import json


class AnomalyService:
    def __init__(self, repository: BaseRepository):
        self.repository = repository

    def get_anomalies(self, limit: int = 50) -> List[Anomaly]:
        raw_anomalies = self.repository.get_anomalies(limit=limit)
        results = []
        for ra in raw_anomalies:
            score = 0.0
            model_type = "Isolation Forest"
            message = f"ML Anomaly detected from {ra.get('src_ip', '0.0.0.0')}"

            if ra.get("raw_payload"):
                try:
                    p = json.loads(ra["raw_payload"])
                    score = float(p.get("anomaly_score", 0.0))
                    if p.get("model_type"):
                        model_type = p["model_type"]
                    if p.get("message"):
                        message = p["message"]
                except:
                    pass

            results.append(
                Anomaly(
                    timestamp=ra.get("timestamp", ""),
                    src_ip=ra.get("src_ip", "0.0.0.0"),
                    anomaly_score=score,
                    model_type=model_type,
                    message=message,
                )
            )
        return results
