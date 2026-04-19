#!/usr/bin/env python3
"""
Phase 4 Core Pipeline
======================
Extends the Phase 3 pipeline with full Phase 4 orchestration:
  Network → Snort → ML → SIEM → Phase 4 Engines → Feedback → Rule Evolution

Phase 4 adds:
  - ResponseEngine   : SOAR-Lite automated action on every created incident
  - SecurityPosture  : recomputed after each incident
  - ThreatHunting    : runs in a background thread every `hunt_interval_seconds`
  - AdaptiveLearning : retrain trigger evaluated on every N incidents
  - FeedbackLoop     : shared singleton, accepting external labels via DB polling
"""

import json
import logging
import threading
import time
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import joblib
import pandas as pd
import sys

sys.path.append(str(Path(__file__).parent.parent))

from config_loader import load_config
from ml_services.data_loader import DataLoader
from ml_services.feature_engineering import FeatureEngineer
from ml_services.model import AnomalyModel
from siem.storage import SIEMStorage
from siem.correlation_engine import CorrelationEngine
from siem.threat_intel import ThreatIntelEngine
from rule_generator import RuleGenerator

# Consolidated Logic Imports
try:
    from core.adaptive_learning import AdaptiveLearningEngine
    from core.response_engine import ResponseEngine
    from siem.threat_hunting import ThreatHuntingEngine
    from core.feedback_loop import FeedbackLoop
    from siem.security_posture import SecurityPostureEngine

    _PHASE4_AVAILABLE = True
except ImportError as _ex:
    _PHASE4_AVAILABLE = False
    logging.warning(
        f"Production modules not available ({_ex}). Running in limited mode."
    )

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


class Phase4Orchestrator:
    """
    Manages all Phase 4 engines as a single injectable component.
    Thread-safe.  Safe to call from the pipeline event handler which
    runs in a watchdog worker thread.
    """

    def __init__(self, config: dict, storage: SIEMStorage):
        self.config = config
        self.storage = storage
        db_path = config.get("siem", {}).get("db_path", "data/cns.db")
        models_dir = config.get("paths", {}).get("models_dir", "models")

        self.learning_engine = AdaptiveLearningEngine(
            models_dir=models_dir,
            db_path=db_path,
            rolling_window=config.get("phase4", {}).get("rolling_window", 500),
            min_samples_to_retrain=config.get("phase4", {}).get(
                "min_samples_to_retrain", 20
            ),
        )
        self.response_engine = ResponseEngine(
            db_path=db_path,
            actions_dir=config.get("phase4", {}).get(
                "actions_dir", "data/response_actions"
            ),
            snort_dynamic_rules_path=config.get("paths", {}).get(
                "generated_rules", "generated_rules.rules"
            ),
            firewall_rules_path=config.get("phase4", {}).get(
                "firewall_rules_path", "data/firewall_rules.sh"
            ),
        )
        self.hunt_engine = ThreatHuntingEngine(db_path=db_path)
        self.feedback_loop = FeedbackLoop(
            db_path=db_path,
            threshold_config_path=config.get("phase4", {}).get(
                "threshold_config", "data/adaptive_thresholds.json"
            ),
        )
        self.posture_engine = SecurityPostureEngine(
            db_path=db_path,
            lookback_hours=config.get("phase4", {}).get("posture_lookback_hours", 24),
        )

        # Wire feedback → learning
        self.feedback_loop.attach_learning_engine(self.learning_engine)

        # Counters
        self._incident_count = 0
        self._retrain_interval = config.get("phase4", {}).get(
            "retrain_every_n_incidents", 50
        )
        self._lock = threading.Lock()

        # Start background threat hunting thread
        hunt_interval = config.get("phase4", {}).get("hunt_interval_seconds", 300)
        self._start_hunt_thread(hunt_interval)

        logger.info(
            "✅ Phase 4 Orchestrator initialized (SOAR-Lite + AdaptiveLearning + ThreatHunting)"
        )

    def handle_incident(self, incident: dict, features_dict: dict = None) -> dict:
        """
        Called for every SIEM incident. Executes:
          1. Automated response action
          2. Ingest features into learning buffer
          3. Maybe trigger retrain
          4. Refresh posture (with cache TTL so not every call is expensive)
        """
        # 1. Automated response
        action = self.response_engine.evaluate_incident(incident)

        # 2. Feed into learning buffer if we have features
        if features_dict:
            # Use 'unknown' because incident hasn't been analyst-labeled yet
            self.learning_engine.ingest_sample(
                features_dict, "unknown", incident.get("incident_id")
            )

        with self._lock:
            self._incident_count += 1
            should_retrain = self._incident_count % self._retrain_interval == 0

        # 3. Periodic retrain
        if should_retrain:
            logger.info(f"[Phase4] Retrain trigger at incident #{self._incident_count}")
            try:
                mv = self.learning_engine.maybe_retrain()
                if mv:
                    logger.info(
                        f"[Phase4] New model: {mv.version} precision={mv.precision:.3f}"
                    )
            except Exception as exc:
                logger.warning(f"[Phase4] Retrain failed: {exc}")

        # 4. Posture refresh (cached)
        try:
            posture = self.posture_engine.compute_posture()
            logger.info(
                f"[Phase4] Posture: {posture['threat_level']} score={posture['risk_score']}"
            )
        except Exception as exc:
            logger.warning(f"[Phase4] Posture refresh failed: {exc}")

        return action

    def _start_hunt_thread(self, interval_seconds: int) -> None:
        """Start a background thread that runs threat hunting periodically."""

        def hunt_loop():
            while True:
                time.sleep(interval_seconds)
                try:
                    results = self.hunt_engine.run_all_hunts(lookback_hours=24)
                    if results:
                        logger.info(f"[Phase4] Threat hunt: {len(results)} findings")
                except Exception as exc:
                    logger.warning(f"[Phase4] Hunt cycle failed: {exc}")

        t = threading.Thread(target=hunt_loop, daemon=True, name="ThreatHuntThread")
        t.start()
        logger.info(
            f"[Phase4] Threat hunting thread started (interval={interval_seconds}s)"
        )


class PipelineEventHandler(FileSystemEventHandler):
    def __init__(self, config: dict):
        self.config = config
        self.alert_file = Path(config["paths"]["alert_file"])
        self.log_dir = Path(config["paths"]["log_dir"])
        self.state_file = Path(
            config["paths"].get("monitor_state", "logs/monitor_state.json")
        )
        self.offsets = self._load_state()

        # Phase 2: ML Model & Feature Engineer
        self.model = AnomalyModel(
            contamination=config["model"]["contamination"],
            random_state=config["model"]["random_state"],
        )
        self.model.load_model(config["paths"]["model_path"])

        self.engineer = FeatureEngineer(window_size=config["feature"]["window_size"])
        self.engineer.scaler = joblib.load(config["paths"]["scaler_path"])

        # Phase 3: SIEM Components
        self.storage = SIEMStorage(config.get("siem", {}).get("db_path", "data/cns.db"))
        self.correlation = CorrelationEngine(config, self.storage)
        self.threat_intel = ThreatIntelEngine(config)

        # Phase 3: Rule Generator
        self.rule_generator = RuleGenerator(
            "generated_rules.rules",
            db_path=config.get("siem", {}).get("db_path", "data/cns.db"),
        )

        # Phase 4: Orchestrator (optional)
        self.phase4: Phase4Orchestrator = None
        if _PHASE4_AVAILABLE:
            try:
                self.phase4 = Phase4Orchestrator(config, self.storage)
            except Exception as exc:
                logger.warning(f"Phase 4 init failed – running in Phase 3 mode: {exc}")

    def _load_state(self) -> dict:
        if self.state_file.exists():
            try:
                with self.state_file.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                pass
        return {}

    def _save_state(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with self.state_file.open("w", encoding="utf-8") as f:
            json.dump(self.offsets, f, indent=2)

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        self.process_file(Path(event.src_path))

    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        self.process_file(Path(event.src_path))

    def process_file(self, path: Path) -> None:
        if not path.exists():
            return

        offset = self.offsets.get(str(path), 0)
        new_entries = []
        raw_payloads = []
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                f.seek(offset)
                for line in f:
                    payload = line.strip()
                    if not payload:
                        continue
                    try:
                        entry = json.loads(payload)
                        loader = DataLoader()
                        parsed = loader._extract_fields(entry)
                        if parsed:
                            new_entries.append(parsed)
                            raw_payloads.append(entry)
                    except json.JSONDecodeError:
                        continue
                self.offsets[str(path)] = f.tell()
                self._save_state()
        except Exception as exc:
            logger.error(f"Failed to read incremental entries from {path}: {exc}")
            return

        if not new_entries:
            return

        df = pd.DataFrame(new_entries)
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df.dropna(subset=["timestamp"], inplace=True)
            df.sort_values(by="timestamp", inplace=True)

        # Push to ML Engine
        features = self.engineer.extract_features(df)
        is_anomaly_detected = False
        anomalies_for_rules = []
        last_features_dict = {}

        if not features.empty:
            normalized_features, _ = self.engineer.normalize_features(
                features, fit=False
            )
            scores, labels = self.model.predict(normalized_features)

            for window, score, label in zip(features.index, scores, labels):
                if label == -1 or score < self.config["threshold"]["anomaly_score"]:
                    is_anomaly_detected = True
                    anomalies_for_rules.append(
                        {
                            "window_start": window.isoformat(),
                            "anomaly_score": float(score),
                            "label": "anomaly",
                            "source_file": str(path),
                        }
                    )
                    # Keep last features dict for Phase 4 learning feed
                    last_features_dict = {
                        col: float(val)
                        for col, val in zip(features.columns, features.loc[window])
                    }

        # Process each raw event for SIEM Correlation
        for parsed_event, raw_entry in zip(new_entries, raw_payloads):
            parsed_event["raw_payload"] = raw_entry
            parsed_event["alert_type"] = parsed_event.get("alert_msg", "UNKNOWN_ALERT")

            if is_anomaly_detected:
                parsed_event["alert_type"] = "ML_ANOMALY"
                parsed_event["severity"] = "HIGH"

            # Feed to Correlation Engine
            incident = self.correlation.evaluate_event(parsed_event)

            if incident:
                # Enrich with Threat Intel
                incident = self.threat_intel.enrich_incident(incident, [parsed_event])
                self.storage.store_incident(incident)

                # Rule Generation
                if is_anomaly_detected or incident.get("severity") in [
                    "HIGH",
                    "CRITICAL",
                ]:
                    self._generate_rules(df, anomalies_for_rules, incident)

                # ── Phase 4 ──────────────────────────────────────────────
                if self.phase4:
                    try:
                        self.phase4.handle_incident(
                            incident,
                            features_dict=last_features_dict
                            if last_features_dict
                            else None,
                        )
                    except Exception as exc:
                        logger.warning(f"Phase 4 incident handling failed: {exc}")

    def _generate_rules(self, df, anomalies, incident):
        try:
            generated_rules = self.rule_generator.analyze_anomalies(df, anomalies)
            if generated_rules:
                augmented_rules = []
                for rule in generated_rules:
                    incident_meta = f"incident_id {incident['incident_id']}; "
                    cve_meta = (
                        f"reference:cve,{incident['cve_match']}; "
                        if incident.get("cve_match")
                        else ""
                    )
                    new_rule = (
                        rule[:-1] + " metadata: " + incident_meta + cve_meta + rule[-1]
                    )
                    augmented_rules.append(new_rule)

                self.rule_generator.save_rules(augmented_rules, append=True)
                self.rule_generator.save_rules_metadata(
                    "generated_rules_metadata.json", augmented_rules, anomalies
                )
                logger.info(
                    f"Generated {len(augmented_rules)} auto-rules for incident {incident['incident_id']}"
                )
        except Exception as e:
            logger.warning(f"Rule generation failed during pipeline: {e}")


def start_pipeline():
    config = load_config()

    # Ensure log directory exists
    Path(config["paths"]["log_dir"]).mkdir(parents=True, exist_ok=True)

    event_handler = PipelineEventHandler(config)
    observer = Observer()
    observer.schedule(event_handler, path=config["paths"]["log_dir"], recursive=False)
    observer.start()

    phase = "4" if _PHASE4_AVAILABLE and event_handler.phase4 else "3"
    logger.info(f"🚀 Phase {phase} Real-time Pipeline Started")
    logger.info("Monitoring Snort alerts → ML inference → SIEM → Phase 4 Engines")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_pipeline()
