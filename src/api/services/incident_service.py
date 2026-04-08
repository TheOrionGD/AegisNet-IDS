from typing import List, Dict, Any, Optional
from ..models.security_event import Incident
from ..repositories.base_repo import BaseRepository

class IncidentService:
    def __init__(self, repository: BaseRepository):
        self.repository = repository

    def get_incidents(self, limit: int = 50) -> List[Incident]:
        raw_incidents = self.repository.get_incidents(limit=limit)
        results = []
        for ri in raw_incidents:
            results.append(Incident(
                incident_id=ri.get('incident_id'),
                src_ip=ri.get('src_ip'),
                alert_count=ri.get('alert_count', 0),
                severity=ri.get('severity', 'LOW'),
                attack_pattern=ri.get('attack_pattern', []),
                start_time=ri.get('start_time'),
                end_time=ri.get('end_time'),
                cve_match=ri.get('cve_match', ""),
                known_exploit=ri.get('known_exploit', False)
            ))
        return results
