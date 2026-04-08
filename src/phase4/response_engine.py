#!/usr/bin/env python3
"""
Phase 4 – Automated Response Engine (SOAR-Lite)
================================================
Triggers tiered automated defensive actions based on SIEM incident severity.

Severity tiers
--------------
 0–30   LOG ONLY         – record to DB, no action
31–60   ALERT ESCALATION – tag incident for SOC review
61–80   RATE LIMITING    – generate iptables rate-limit rule (mock)
81–100  BLOCK / SNORT    – generate Snort block rule + iptables DROP rule

Incident state machine
----------------------
  OPEN → INVESTIGATING → CONTAINED

All actions are persisted to `response_actions` table in SQLite.
Firewall / Snort rules are written to text files (cross-platform safe).
"""

import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import sqlite3
import json

logger = logging.getLogger(__name__)

# Severity thresholds
_T_LOG = 30
_T_ALERT = 60
_T_RATELIMIT = 80

# Incident state machine
STATES = ["OPEN", "INVESTIGATING", "CONTAINED"]


class ActionType:
    LOG = "LOG"
    ALERT = "ALERT"
    RATE_LIMIT = "RATE_LIMIT"
    BLOCK = "BLOCK"


class ResponseEngine:
    """
    SOAR-Lite: evaluates SIEM incidents and fires appropriate automated
    defensive actions without requiring human intervention.
    """

    def __init__(
        self,
        db_path: str = "data/siem.db",
        actions_dir: str = "data/response_actions",
        snort_dynamic_rules_path: str = "generated_rules.rules",
        firewall_rules_path: str = "data/firewall_rules.sh",
    ):
        self.db_path = Path(db_path)
        self.actions_dir = Path(actions_dir)
        self.actions_dir.mkdir(parents=True, exist_ok=True)
        self.snort_dynamic_rules_path = Path(snort_dynamic_rules_path)
        self.firewall_rules_path = Path(firewall_rules_path)
        self._lock = threading.Lock()
        self._rule_sid_counter = 3000000  # Phase 4 SID namespace

        logger.info("ResponseEngine initialized (SOAR-Lite)")

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def evaluate_incident(self, incident: Dict) -> Dict:
        """
        Main entry point.  Reads incident severity, determines action tier,
        executes action, persists result, returns action record.

        Args:
            incident: incident dict from CorrelationEngine / SIEM storage
                      must have keys: incident_id, severity, src_ip

        Returns:
            action_record dict with keys:
              id, incident_id, severity_score, action_type,
              action_detail, executed_at, state
        """
        severity_str = str(incident.get("severity", "LOW")).upper()
        severity_score = self._severity_to_score(severity_str)
        src_ip = incident.get("src_ip", "0.0.0.0")
        incident_id = incident.get("incident_id", str(uuid.uuid4()))

        action_type, action_detail = self._determine_action(
            severity_score, src_ip, incident_id
        )
        state = self._severity_to_initial_state(severity_score)

        action_record = {
            "id": str(uuid.uuid4()),
            "incident_id": incident_id,
            "severity_score": severity_score,
            "action_type": action_type,
            "action_detail": action_detail,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "state": state,
        }

        self._execute_action(action_type, action_detail, src_ip, incident_id)
        self._persist_action(action_record)

        logger.info(
            f"[SOAR] Incident {incident_id} | score={severity_score} | "
            f"action={action_type} | state={state}"
        )
        return action_record

    def advance_state(self, incident_id: str, new_state: str) -> bool:
        """
        Advance the incident state machine.
        Valid transitions: OPEN→INVESTIGATING, INVESTIGATING→CONTAINED
        """
        if new_state not in STATES:
            raise ValueError(f"Invalid state '{new_state}'")
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                "UPDATE response_actions SET state = ? WHERE incident_id = ?",
                (new_state, incident_id),
            )
            conn.commit()
            conn.close()
            logger.info(f"Incident {incident_id} state → {new_state}")
            return True
        except Exception as exc:
            logger.error(f"State transition failed: {exc}")
            return False

    def get_recent_actions(self, limit: int = 50) -> List[Dict]:
        """Retrieve recent response actions from the DB."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM response_actions ORDER BY executed_at DESC LIMIT ?",
                (limit,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            logger.warning(f"Failed to retrieve actions: {exc}")
            return []

    def get_blocked_ips(self) -> List[str]:
        """Return IPs that have BLOCK actions associated."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                "SELECT DISTINCT action_detail FROM response_actions "
                "WHERE action_type = 'BLOCK'"
            )
            rows = cur.fetchall()
            conn.close()
            ips = []
            for r in rows:
                detail = r[0] or ""
                # Extract IP from detail string like "Block src_ip=1.2.3.4"
                for part in detail.split():
                    if part.startswith("src_ip="):
                        ips.append(part.split("=", 1)[1])
            return list(set(ips))
        except Exception:
            return []

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _severity_to_score(self, severity_str: str) -> int:
        """Convert textual severity label to numeric score."""
        mapping = {
            "CRITICAL": 95,
            "HIGH": 80,
            "MEDIUM": 50,
            "LOW": 15,
        }
        return mapping.get(severity_str, 15)

    def _severity_to_initial_state(self, score: int) -> str:
        if score > _T_RATELIMIT:
            return "INVESTIGATING"
        if score > _T_ALERT:
            return "OPEN"
        return "OPEN"

    def _determine_action(
        self, score: int, src_ip: str, incident_id: str
    ) -> Tuple[str, str]:
        """Return (action_type, action_detail_string)."""
        if score > _T_RATELIMIT:
            # BLOCK tier
            snort_rule = self._build_snort_block_rule(src_ip, incident_id)
            iptables_rule = self._build_iptables_drop(src_ip)
            detail = (
                f"BLOCK src_ip={src_ip} | "
                f"snort_sid={self._rule_sid_counter} | "
                f"iptables={iptables_rule}"
            )
            return ActionType.BLOCK, detail

        if score > _T_ALERT:
            # RATE LIMIT tier
            iptables_rule = self._build_iptables_ratelimit(src_ip)
            detail = (
                f"RATE_LIMIT src_ip={src_ip} | iptables={iptables_rule}"
            )
            return ActionType.RATE_LIMIT, detail

        if score > _T_LOG:
            # ALERT ESCALATION tier
            detail = (
                f"ALERT_ESCALATION incident={incident_id} | "
                f"src_ip={src_ip} | requires_soc_review=True"
            )
            return ActionType.ALERT, detail

        # LOG ONLY
        detail = f"LOG_ONLY incident={incident_id} | src_ip={src_ip} | score={score}"
        return ActionType.LOG, detail

    def _execute_action(
        self, action_type: str, detail: str, src_ip: str, incident_id: str
    ) -> None:
        """Execute the side-effects for each action type."""
        if action_type == ActionType.LOG:
            logger.info(f"[LOG-ONLY] {detail}")

        elif action_type == ActionType.ALERT:
            # Tag in DB (update incident if it exists; store alert flag)
            try:
                conn = sqlite3.connect(str(self.db_path))
                cur = conn.cursor()
                cur.execute(
                    "UPDATE incidents SET severity = 'CRITICAL' WHERE incident_id = ?",
                    (incident_id,),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
            logger.warning(f"[ALERT-ESCALATION] {detail}")

        elif action_type == ActionType.RATE_LIMIT:
            self._append_to_file(
                self.firewall_rules_path,
                self._build_iptables_ratelimit(src_ip) + "\n",
            )
            logger.warning(f"[RATE-LIMIT] Applied to {src_ip}")

        elif action_type == ActionType.BLOCK:
            snort_rule = self._build_snort_block_rule(src_ip, incident_id)
            iptables_rule = self._build_iptables_drop(src_ip)
            self._append_to_file(
                self.snort_dynamic_rules_path,
                f"\n# Phase4 auto-block {datetime.now(timezone.utc).isoformat()}\n"
                + snort_rule + "\n",
            )
            self._append_to_file(
                self.firewall_rules_path,
                iptables_rule + "\n",
            )
            logger.critical(f"[BLOCK] Snort+iptables rules generated for {src_ip}")

    def _build_snort_block_rule(self, src_ip: str, incident_id: str) -> str:
        self._rule_sid_counter += 1
        sid = self._rule_sid_counter
        return (
            f'drop ip {src_ip} any -> any any '
            f'(msg:"AUTO-BLOCK Phase4 incident={incident_id}"; '
            f'sid:{sid}; rev:1; classtype:policy-violation;)'
        )

    def _build_iptables_drop(self, src_ip: str) -> str:
        return (
            f"iptables -I INPUT 1 -s {src_ip} -j DROP "
            f"# Phase4 auto-block {datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        )

    def _build_iptables_ratelimit(self, src_ip: str) -> str:
        return (
            f"iptables -I INPUT 1 -s {src_ip} -m limit --limit 10/min "
            f"--limit-burst 20 -j ACCEPT "
            f"# Phase4 rate-limit {datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        )

    def _append_to_file(self, path: Path, content: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(content)
        except IOError as exc:
            logger.error(f"Failed to write action file {path}: {exc}")

    def _persist_action(self, record: Dict) -> None:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO response_actions
                (id, incident_id, severity_score, action_type,
                 action_detail, executed_at, state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["incident_id"],
                    record["severity_score"],
                    record["action_type"],
                    record["action_detail"],
                    record["executed_at"],
                    record["state"],
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning(f"Failed to persist response action: {exc}")
