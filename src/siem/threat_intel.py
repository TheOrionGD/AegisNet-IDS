import requests
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ThreatIntelEngine:
    """Enriches incidents with CVE matches and Threat Intel feeds."""
    def __init__(self, config: dict):
        self.config = config
        self.enable_api = config.get('threat_intel', {}).get('enable_api', False)
        
        # In a real environment, we would fetch from MISP or NVD feeds
        # Here we mock a basic known port mapping to CVEs typical in Snort alerts
        self.known_cves = {
            22: {"cve_match": "CVE-2024-XXXX (SSH Brute Force)", "known_exploit": True, "attack_class": "Authentication Bypass"},
            80: {"cve_match": "CVE-2023-XXXX (HTTP Anomaly)", "known_exploit": True, "attack_class": "Web Application Attack"},
            3389: {"cve_match": "CVE-2019-0708 (BlueKeep)", "known_exploit": True, "attack_class": "Remote Code Execution"},
            445: {"cve_match": "CVE-2017-0144 (EternalBlue)", "known_exploit": True, "attack_class": "Remote Code Execution"}
        }

    def enrich_incident(self, incident: Dict[str, Any], raw_logs_sample: list) -> Dict[str, Any]:
        """
        Enriches an incident based on the ports commonly attacked in its raw logs.
        """
        if not raw_logs_sample:
            return incident

        # Try to find a target port from the payload if it exists
        target_ports = set()
        for log in raw_logs_sample:
            try:
                # Basic parsing assuming we might have port info in payload in the real system
                payload_str = str(log.get('raw_payload', ''))
                # We expect the IDS phase parsed src/dst port usually, but we fallback
                # to string mapping for the prototype to simulate enrichment.
                for port in self.known_cves.keys():
                    if f"port: {port}" in payload_str or f"dst_port': {port}" in payload_str:
                        target_ports.add(port)
            except Exception:
                continue

        # If we found a known port attack surface in the logs, enrich the incident
        for port in target_ports:
            if port in self.known_cves:
                cve_info = self.known_cves[port]
                incident['cve_match'] = cve_info['cve_match']
                incident['known_exploit'] = cve_info['known_exploit']
                # Optional: escalate severity if it's a known exploit
                if incident.get('severity') not in ['HIGH', 'CRITICAL']:
                    incident['severity'] = 'HIGH'
                logger.info(f"Threat Intel Hit: Enriched {incident.get('incident_id')} with {cve_info['cve_match']}")
                break  # Just apply the first matched CVE for this MVP
                
        return incident
