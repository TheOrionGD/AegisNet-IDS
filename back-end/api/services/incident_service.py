from typing import List, Dict, Any, Optional
from ..models.security_event import Incident
from ..repositories.base_repo import BaseRepository
import logging

logger = logging.getLogger(__name__)


class IncidentService:
    def __init__(self, repository: BaseRepository):
        self.repository = repository

    async def get_incidents(self, limit: int = 50) -> List[Incident]:
        """Fetch and normalize incidents from the repository."""
        try:
            raw_incidents = await self.repository.get_incidents(limit=limit)
        except Exception as e:
            logger.error(f"Error fetching incidents from repo: {e}", exc_info=True)
            return []

        results = []
        for ri in raw_incidents:
            try:
                results.append(
                    Incident(
                        incident_id=ri.get("incident_id", ""),
                        incident_type=ri.get("incident_type", "GENERIC"),
                        src_ip=ri.get("src_ip", ri.get("source_ip", "0.0.0.0")),
                        alert_count=ri.get("alert_count", 1),
                        severity=ri.get("severity", "LOW"),
                        confidence=ri.get("confidence", 0.5),
                        attack_pattern=ri.get("attack_pattern", []),
                        start_time=ri.get("start_time", ri.get("timestamp", "")),
                        end_time=ri.get("end_time", ri.get("start_time", "")),
                        cve_match=ri.get("cve_match", ""),
                        known_exploit=ri.get("known_exploit", False),
                    )
                )
            except Exception as e:
                logger.warning(f"Error parsing incident {ri.get('incident_id')}: {e}")
                continue
        return results
