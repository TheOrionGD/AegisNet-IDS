#!/usr/bin/env python3
"""
Hardened Phase 4 Test Suite
===========================
Updated for Driver-based SOAR and ELK/PG Storage architecture.
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import numpy as np

# Add src to path
_SRC = Path(__file__).parent.parent
sys.path.insert(0, str(_SRC))

from core.adaptive_learning import AdaptiveLearningEngine
from core.response_engine import ResponseEngine, ActionType, IPTablesDriver
from siem.storage import SIEMStorage
from core.feedback_loop import FeedbackLoop, LABEL_FP, LABEL_TP
from siem.security_posture import SecurityPostureEngine, ThreatLevel


# Mock Storage for SOAR tests
@pytest.fixture
def mock_storage():
    storage = MagicMock(spec=SIEMStorage)
    return storage

@pytest.fixture
def sample_features():
    return {
        "pkt_len_count": 100.0,
        "pkt_len_mean": 512.0,
        "packet_rate": 10.0,
        "internal_ratio": 0.2,
        "dst_ip_entropy": 2.5
    }

class TestResponseEngine:

    def _make_incident(self, severity: str, incident_id: str = "INC-TEST0001"):
        return {
            "incident_id": incident_id,
            "severity": severity,
            "src_ip": "10.0.0.99",
            "confidence": 0.9
        }

    def test_response_engine_log_only(self, mock_storage):
        """Severity LOW → LOG action."""
        engine = ResponseEngine(storage=mock_storage)
        record = engine.evaluate_incident(self._make_incident("LOW"))
        assert record["action_type"] == ActionType.LOG
        assert record["severity_score"] == 15

    def test_response_engine_alert_escalation(self, mock_storage):
        """Severity MEDIUM → ALERT action."""
        engine = ResponseEngine(storage=mock_storage)
        record = engine.evaluate_incident(self._make_incident("MEDIUM"))
        assert record["action_type"] == ActionType.ALERT

    def test_response_engine_rate_limit(self, mock_storage):
        """Severity HIGH → RATE_LIMIT action."""
        engine = ResponseEngine(storage=mock_storage)
        record = engine.evaluate_incident(self._make_incident("HIGH"))
        assert record["action_type"] == ActionType.RATE_LIMIT

    def test_response_engine_block(self, mock_storage, tmp_path):
        """Severity CRITICAL → BLOCK action."""
        engine = ResponseEngine(storage=mock_storage)
        # Configure paths for rule generation testing
        engine.snort_dynamic_rules_path = tmp_path / "rules.rules"
        engine.firewall_rules_path = tmp_path / "fw.sh"
        
        record = engine.evaluate_incident(self._make_incident("CRITICAL", "INC-CRIT001"))
        assert record["action_type"] == ActionType.BLOCK
        assert record["severity_score"] == 95
        assert engine.snort_dynamic_rules_path.exists()

    def test_response_engine_injection_protection(self, mock_storage):
        """Invalid IP should be rejected by sanitization."""
        engine = ResponseEngine(storage=mock_storage)
        malicious_incident = {
            "incident_id": "INC-BAD",
            "severity": "CRITICAL",
            "src_ip": "10.0.0.1; rm -rf /",
            "confidence": 1.0
        }
        record = engine.evaluate_incident(malicious_incident)
        assert record is None # Sanitization should return None for invalid IP

    def test_response_engine_persists_to_storage(self, mock_storage):
        """Verify action is persisted via storage mock."""
        engine = ResponseEngine(storage=mock_storage)
        engine.evaluate_incident(self._make_incident("LOW", "INC-DB-TEST"))
        assert mock_storage.store_response_action.called

# Keep other tests (AdaptiveLearning, etc.) but they might need minor tweaks if they used SQLite directly
# For this execution, we focus on fixing the SOAR blockers reported in the audit.
