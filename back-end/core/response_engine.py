import logging
import datetime
from datetime import timezone
import uuid
import subprocess
import threading
import ipaddress
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List, Protocol
from abc import ABC, abstractmethod

from siem.storage import SIEMStorage
from config_loader import load_config

logger = logging.getLogger(__name__)

class ActionType:
    LOG = "LOG"
    ALERT = "ALERT"
    RATE_LIMIT = "RATE_LIMIT"
    BLOCK = "BLOCK"

class FirewallDriver(ABC):
    """Abstract interface for firewall response actions."""
    @abstractmethod
    def block_ip(self, ip: str) -> List[str]:
        pass

    @abstractmethod
    def rate_limit_ip(self, ip: str) -> List[str]:
        pass

class IPTablesDriver(FirewallDriver):
    """Linux IPTables driver implementation."""
    def block_ip(self, ip: str) -> List[str]:
        return [f"iptables -I INPUT 1 -s {ip} -j DROP"]

    def rate_limit_ip(self, ip: str) -> List[str]:
        return [f"iptables -I INPUT 1 -s {ip} -m limit --limit 10/min -j ACCEPT"]

class ResponseEngine:
    """
    Hardened SOAR (Security Orchestration, Automation, and Response) Engine.
    Implements driver-based execution and strict input sanitization.
    """
    def __init__(self, storage: SIEMStorage, driver: Optional[FirewallDriver] = None):
        self.storage = storage
        self.config = load_config('config/config.yaml')
        self.driver = driver or IPTablesDriver()
        
        # Operational Guards
        self.safe_mode = self.config.get('soar', {}).get('safe_mode', True)
        self.execute_enabled = self.config.get('soar', {}).get('execute', False)
        self.confidence_threshold = self.config.get('soar', {}).get('confidence_threshold', 0.8)
        
        self._lock = threading.Lock()
        self._rule_sid_counter = 3000000 
        self.snort_dynamic_rules_path = Path(self.config['paths'].get('dynamic_rules', "generated_rules.rules"))
        self.firewall_rules_path = Path(self.config['paths'].get('firewall_rules', "data/firewall_rules.sh"))

    def _sanitize_ip(self, ip: str) -> str:
        """Validate IP address to prevent command injection."""
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError:
            logger.error(f"Security Alert: Attempted SOAR action on invalid IP: {ip}")
            raise ValueError(f"Invalid IP address: {ip}")

    async def execute_response(self, incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluate an incident and execute a tiered response action."""
        confidence = float(incident.get("confidence", 0.0))
        raw_ip = incident.get("src_ip")
        
        if not raw_ip:
            return None

        # 1. Strict Sanitization
        try:
            src_ip = self._sanitize_ip(raw_ip)
        except ValueError:
            return None

        if src_ip in ["0.0.0.0", "127.0.0.1", "::1"]:
            return None

        incident_id = incident.get("incident_id", str(uuid.uuid4()))
        severity_str = str(incident.get("severity", "LOW")).upper()

        # 2. Tiered Logic
        severity_score = self._severity_to_score(severity_str)
        action_type, action_detail, commands = self._determine_action(severity_score, src_ip, incident_id)

        # 3. Confidence Gate
        if confidence < self.confidence_threshold:
            logger.info(f"SOAR: Confidence {confidence:.2f} below threshold {self.confidence_threshold}. Switching to LOG_ONLY.")
            action_type = ActionType.LOG
            commands = []

        response_action = {
            "id": str(uuid.uuid4()),
            "incident_id": incident_id,
            "severity_score": severity_score,
            "action_type": action_type,
            "action_detail": action_detail,
            "executed_at": datetime.datetime.now(timezone.utc),
            "state": "PENDING",
            "output": ""
        }

        # 4. Execution Phase
        if action_type != ActionType.LOG:
            if not self.safe_mode and self.execute_enabled:
                results_output = []
                final_state = "SUCCESS"
                
                for cmd in commands:
                    try:
                        logger.warning(f"SOAR [ACTIVE]: Executing: {cmd}")
                        # Use shell=False for safety even with split()
                        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5, shell=False)
                        if result.returncode != 0:
                            final_state = "PARTIAL_FAILURE"
                        results_output.append(f"[{cmd}] -> {result.stdout} {result.stderr}")
                    except Exception as e:
                        final_state = "ERROR"
                        results_output.append(f"Execution Error ({cmd}): {str(e)}")
                
                response_action['state'] = final_state
                response_action['output'] = "\n".join(results_output)
            else:
                response_action['state'] = "LOGGED_SAFE_MODE"
                logger.info(f"SOAR [SAFE]: Mock execution for {action_type} on {src_ip}")

        else:
            response_action['state'] = "LOGGED"

        # 5. Side effects: Rule File Generation
        if action_type in [ActionType.BLOCK, ActionType.RATE_LIMIT]:
            self._generate_rule_files(action_type, src_ip, incident_id)

        # 6. Store in storage (Relational PG handles this now)
        self.storage.store_response_action(response_action)
        return response_action

    def _severity_to_score(self, severity_str: str) -> int:
        mapping = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 50, "LOW": 15}
        return mapping.get(severity_str.upper(), 15)

    def _determine_action(self, score: int, src_ip: str, incident_id: str) -> Tuple[str, str, List[str]]:
        if score >= 80: 
            return ActionType.BLOCK, f"BLOCK src_ip={src_ip}", self.driver.block_ip(src_ip)
        
        if score >= 60: 
            return ActionType.RATE_LIMIT, f"RATE_LIMIT src_ip={src_ip}", self.driver.rate_limit_ip(src_ip)
            
        if score >= 30: 
            return ActionType.ALERT, f"ALERT_ESCALATION src_ip={src_ip}", []

        return ActionType.LOG, f"LOG_ONLY src_ip={src_ip}", []

    def _generate_rule_files(self, action_type: str, src_ip: str, incident_id: str):
        try:
            timestamp = datetime.datetime.now(timezone.utc).isoformat()
            if action_type == ActionType.BLOCK:
                rule = self._build_snort_block_rule(src_ip, incident_id)
                self._append_to_file(self.snort_dynamic_rules_path, f"\n# AegisNet Auto-Block {timestamp}\n{rule}\n")
            
            fw_commands = self.driver.block_ip(src_ip) if action_type == ActionType.BLOCK else self.driver.rate_limit_ip(src_ip)
            for cmd in fw_commands:
                self._append_to_file(self.firewall_rules_path, f"{cmd} # {timestamp}\n")
        except Exception as e:
            logger.error(f"Failed to generate rule files: {e}")

    def _build_snort_block_rule(self, src_ip: str, incident_id: str) -> str:
        with self._lock:
            self._rule_sid_counter += 1
            sid = self._rule_sid_counter
        return f'drop ip {src_ip} any -> any any (msg:"AEGISNET-AUTO-BLOCK incident={incident_id}"; sid:{sid}; rev:1;)'

    def _append_to_file(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(content)
            
    # Legacy support for tests (proxies to execute_response)
    def evaluate_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        import asyncio
        return asyncio.run(self.execute_response(incident))

    def get_recent_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        # This would normally query PG
        return []

    def advance_state(self, incident_id: str, new_state: str) -> bool:
        # This would update PG
        return True
