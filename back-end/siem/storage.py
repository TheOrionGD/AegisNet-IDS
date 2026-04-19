import json
import logging
import datetime
from datetime import timezone
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# ── Optional Elasticsearch (graceful degradation to in-memory in dev) ──────────
try:
    from elasticsearch import Elasticsearch, NotFoundError

    _ES_AVAILABLE = True
except ImportError:
    _ES_AVAILABLE = False
    logger_pre = logging.getLogger(__name__)
    logger_pre.warning("elasticsearch package not found — ES storage disabled.")

from api.models.database import (
    Feedback,
    ModelVersion,
    ResponseAction,
    RuleScore,
    Incident as PGIncident,
    SecurityEvent as PGEvent,
)
from config_loader import load_config

logger = logging.getLogger(__name__)


class _ESStub:
    """In-memory stub that mimics just enough of the ES client to keep the pipeline running."""

    def __init__(self):
        self._store: Dict[str, Dict] = {}  # index:id → doc
        self._lists: Dict[str, list] = {}  # index → list of docs

    def _key(self, index, doc_id):
        return f"{index}:{doc_id}"

    class _Indices:
        def exists(self, index):
            return True

        def create(self, **kw):
            pass

    indices = _Indices()

    def index(self, index, document, id=None, **kw):
        doc_id = id or str(uuid.uuid4())
        self._lists.setdefault(index, []).append(document)
        self._store[self._key(index, doc_id)] = document
        return {"result": "created", "_id": doc_id}

    def search(self, index="*", query=None, size=100, sort=None, **kw):
        # Flatten all indices matching the pattern
        hits = []
        for k, docs in self._lists.items():
            pat = index.replace("*", "")
            if pat in k or index == "*":
                hits.extend(docs)
        hits = hits[-size:]
        return {
            "hits": {
                "hits": [{"_source": d} for d in reversed(hits)],
                "total": {"value": len(hits)},
            }
        }


class SIEMStorage:
    """
    Production-grade SIEM Storage abstraction.
    Uses Elasticsearch for high-volume telemetry and PostgreSQL for relational state.
    Falls back to in-memory stub + SQLite when services are unavailable (dev mode).
    """

    def __init__(self, es_url: str = None, pg_url: str = None):
        self.config = load_config()

        # ── Elasticsearch / Stub ──────────────────────────────────────────────
        es_url = es_url or self.config.get("elasticsearch", {}).get(
            "url", "http://localhost:9200"
        )
        self.log_index = "cns-alerts"
        self.incident_index = "cns-incidents"

        if _ES_AVAILABLE:
            try:
                # First, do a light-weight ping with a very short timeout
                test_es = Elasticsearch([es_url], request_timeout=1, max_retries=0)
                if not test_es.ping():
                    raise ConnectionError("ES ping failed")

                # If ping succeeds, create the real client
                self.es = Elasticsearch(
                    [es_url],
                    request_timeout=2,
                    retry_on_timeout=True,
                    max_retries=3,
                    verify_certs=False,
                )
                self._es_mode = "live"
                logger.info(f"[STORAGE] Elasticsearch connected at {es_url}")
            except Exception as e:
                logger.warning(
                    f"[STORAGE] Elasticsearch unreachable at {es_url} ({type(e).__name__}: {e}). Using in-memory stub."
                )
                self.es = _ESStub()
                self._es_mode = "stub"
        else:
            self.es = _ESStub()
            self._es_mode = "stub"

        # ── PostgreSQL / SQLite ───────────────────────────────────────────────
        pg_url = pg_url or self.config.get("database", {}).get(
            "url", "sqlite:///data/cns.db"
        )
        self._fallback_sqlite = False
        self.pg_url = pg_url
        try:
            self.engine = create_engine(pg_url)
            self.SessionLocal = sessionmaker(
                autocommit=False, autoflush=False, bind=self.engine
            )
            self._pg_mode = "live"
            logger.info(f"[STORAGE] Database connected: {pg_url[:40]}...")
        except Exception as e:
            logger.error(f"[STORAGE] DB engine creation failed: {e}")
            self.engine = None
            self.SessionLocal = None
            self._pg_mode = "unavailable"

        self._ensure_indices()

    def _fallback_to_sqlite(self, fallback_path: str = None):
        if fallback_path is None:
            fallback_path = Path(__file__).resolve().parents[1] / "data" / "cns.db"
        sqlite_url = f"sqlite:///{fallback_path.as_posix()}"
        try:
            self.engine = create_engine(sqlite_url)
            self.SessionLocal = sessionmaker(
                autocommit=False, autoflush=False, bind=self.engine
            )
            self._pg_mode = "stub"
            self._fallback_sqlite = True
            logger.warning(f"[STORAGE] Falling back to local SQLite DB at {sqlite_url}")
            with self.engine.begin() as conn:
                conn.execute(
                    text("""
                    CREATE TABLE IF NOT EXISTS technical_incidents (
                        incident_id TEXT PRIMARY KEY,
                        data TEXT,
                        start_time TEXT
                    )
                """)
                )
            logger.info("[STORAGE] Local SQLite fallback storage initialized.")
        except Exception as e:
            logger.error(f"[STORAGE] SQLite fallback failed: {e}")
            self.engine = None
            self.SessionLocal = None
            self._pg_mode = "unavailable"

    def _ensure_indices(self):
        """Ensure ES indices exist with proper mappings."""
        try:
            if not self.es.indices.exists(index=self.incident_index):
                self.es.indices.create(
                    index=self.incident_index,
                    body={
                        "mappings": {
                            "properties": {
                                "incident_id": {"type": "keyword"},
                                "src_ip": {"type": "ip"},
                                "dst_ip": {"type": "ip"},
                                "severity": {"type": "keyword"},
                                "start_time": {"type": "date"},
                                "end_time": {"type": "date"},
                                "attack_pattern": {"type": "keyword"},
                                "confidence": {"type": "float"},
                                "ml_score": {"type": "float"},
                                "ml_risk_level": {"type": "keyword"},
                                "is_anomaly": {"type": "boolean"},
                            }
                        }
                    },
                )
                logger.info(f"Created ES index: {self.incident_index}")
        except Exception as e:
            logger.error(f"Failed to ensure ES indices: {e}")

        try:
            ids_index = "cns-ids-events"
            if not self.es.indices.exists(index=ids_index):
                self.es.indices.create(
                    index=ids_index,
                    body={
                        "mappings": {
                            "properties": {
                                "timestamp": {"type": "date"},
                                "src_ip": {"type": "ip"},
                                "dst_ip": {"type": "ip"},
                                "src_port": {"type": "integer"},
                                "dst_port": {"type": "integer"},
                                "protocol": {"type": "keyword"},
                                "alert_type": {"type": "keyword"},
                                "severity": {"type": "keyword"},
                                "signature_id": {"type": "keyword"},
                                "ml_score": {"type": "float"},
                                "ml_risk_level": {"type": "keyword"},
                                "is_anomaly": {"type": "boolean"},
                                "threat_level": {"type": "keyword"},
                            }
                        }
                    },
                )
                logger.info(f"Created ES index: {ids_index}")
        except Exception as e:
            logger.warning(f"Failed to create IDS events index: {e}")

        # Ensure SQLite technical_incidents table exists if DB is connected
        if self._pg_mode == "live":
            try:
                with self.engine.begin() as conn:
                    # technical_incidents for dev/stub shared state
                    conn.execute(
                        text("""
                        CREATE TABLE IF NOT EXISTS technical_incidents (
                            incident_id TEXT PRIMARY KEY,
                            data TEXT,
                            start_time TEXT
                        )
                    """)
                    )
                    logger.info("Ensured technical_incidents table in SQLite/PG")
            except Exception as e:
                logger.error(f"Failed to ensure technical_incidents table: {e}")
                if self.pg_url.startswith("postgresql"):
                    logger.warning(
                        "[STORAGE] PostgreSQL unavailable. Falling back to local SQLite."
                    )
                    self._fallback_to_sqlite()
        elif self._pg_mode == "unavailable":
            self._fallback_to_sqlite()

    # --- Telemetry (Elasticsearch) ---

    def ingest_log(self, log_entry: Dict[str, Any]) -> str:
        """Proxied log ingestion with schema safety for downstream ML and dashboard."""
        log_id = str(uuid.uuid4())
        log_entry["id"] = log_id

        now_ts = datetime.datetime.now(timezone.utc).isoformat()
        log_entry.setdefault("timestamp", now_ts)
        log_entry.setdefault("src_ip", "0.0.0.0")
        log_entry.setdefault("dst_ip", "0.0.0.0")
        log_entry.setdefault("protocol", "UNKNOWN")
        log_entry.setdefault("severity", "LOW")
        log_entry.setdefault("alert_type", "GENERIC_ALERT")

        index_name = (
            f"cns-alerts-{datetime.datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
        )
        try:
            self.es.index(index=index_name, document=log_entry)
        except Exception as e:
            logger.error(f"[STORAGE] Failed to index log in ES: {e}")

        return log_id

    def ingest_ids_event(self, event: Dict[str, Any]) -> str:
        """Fast-path ingestion for IDS/Snort events with ML scoring."""
        event_id = str(uuid.uuid4())
        event["id"] = event_id

        now_ts = datetime.datetime.now(timezone.utc).isoformat()
        event.setdefault("timestamp", now_ts)
        event.setdefault("src_ip", "0.0.0.0")
        event.setdefault("dst_ip", "0.0.0.0")
        event.setdefault("src_port", 0)
        event.setdefault("dst_port", 0)
        event.setdefault("protocol", "TCP")
        event.setdefault("alert_type", "SNORT_ALERT")
        event.setdefault("severity", "MEDIUM")
        event.setdefault("ml_score", 0.0)
        event.setdefault("ml_risk_level", "LOW")
        event.setdefault("is_anomaly", False)
        event.setdefault("threat_level", "NORMAL")

        index_name = "cns-ids-events"
        try:
            self.es.index(index=index_name, document=event)
            logger.debug(
                f"[STORAGE] Indexed IDS event: {event.get('src_ip')} -> {event.get('dst_ip')}"
            )
        except Exception as e:
            logger.error(f"[STORAGE] Failed to index IDS event: {e}")

        return event_id

    def get_ids_events(
        self, hours_back: int = 24, min_score: float = 0.0
    ) -> List[Dict[str, Any]]:
        """Query IDS events with optional ML score filtering."""
        query = {
            "bool": {"must": [{"range": {"timestamp": {"gte": f"now-{hours_back}h"}}}]}
        }

        if min_score > 0:
            query["bool"]["must"].append({"range": {"ml_score": {"gte": min_score}}})

        try:
            res = self.es.search(index="cns-ids-events", query=query, size=1000)
            return [hit["_source"] for hit in res["hits"]["hits"]]
        except Exception as e:
            logger.error(f"[STORAGE] Failed to query IDS events: {e}")
            return []

    def get_anomalous_ips(
        self, hours_back: int = 24, min_score: float = 0.7
    ) -> List[Dict[str, Any]]:
        """Get IPs with high anomaly scores."""
        query = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": f"now-{hours_back}h"}}},
                    {"range": {"ml_score": {"gte": min_score}}},
                ]
            }
        }

        try:
            res = self.es.search(
                index="cns-ids-events",
                query=query,
                size=100,
                aggs={
                    "top_ips": {
                        "terms": {"field": "src_ip", "size": 20},
                        "aggs": {"avg_score": {"avg": {"field": "ml_score"}}},
                    }
                },
            )

            buckets = res.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
            return [
                {
                    "ip": b["key"],
                    "count": b["doc_count"],
                    "avg_score": b["avg_score"]["value"],
                }
                for b in buckets
            ]
        except Exception as e:
            logger.error(f"[STORAGE] Failed to get anomalous IPs: {e}")
            return []

    def get_recent_logs(self, src_ip: str, minutes_back: int) -> List[Dict[str, Any]]:
        """Retrieve recent logs from Elasticsearch."""
        query = {
            "bool": {
                "must": [
                    {"term": {"src_ip": src_ip}},
                    {"range": {"timestamp": {"gte": f"now-{minutes_back}m"}}},
                ]
            }
        }
        res = self.es.search(
            index=f"{self.log_index}-*",
            query={"bool": {"must": query["bool"]["must"]}},
            size=1000,
        )
        return [hit["_source"] for hit in res["hits"]["hits"]]

    def get_raw_logs_window(self, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Retrieve logs from ES for a time window."""
        query = {"range": {"timestamp": {"gte": f"now-{hours_back}h"}}}
        res = self.es.search(index=self.log_index, query=query, size=5000)
        return [hit["_source"] for hit in res["hits"]["hits"]]

    # --- Incidents (Elasticsearch + Postgres Metadata) ---

    def store_incident(self, incident: Dict[str, Any]):
        """Store a correlated incident in ES for searchability."""
        self.es.index(
            index=self.incident_index, id=incident["incident_id"], document=incident
        )
        logger.info(f"Indexed Incident in ES: {incident['incident_id']}")

        # Fallback to SQLite technical_incidents if ES is in stub mode
        if self._es_mode == "stub" and self._pg_mode == "live":
            try:
                with self.engine.begin() as conn:
                    conn.execute(
                        text(
                            "INSERT OR REPLACE INTO technical_incidents (incident_id, data, start_time) VALUES (:id, :data, :ts)"
                        ),
                        {
                            "id": incident["incident_id"],
                            "data": json.dumps(incident),
                            "ts": incident.get("start_time"),
                        },
                    )
                logger.info(f"Buffered incident in SQLite: {incident['incident_id']}")
            except Exception as e:
                logger.error(f"Failed to buffer incident in SQLite: {e}")

    def get_all_incidents(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Retrieve incidents from ES."""
        if self._es_mode == "live":
            res = self.es.search(
                index=self.incident_index,
                query={"match_all": {}},
                size=limit,
                sort=[{"start_time": "desc"}],
            )
            return [hit["_source"] for hit in res["hits"]["hits"]]
        elif self._pg_mode == "live":
            # Fallback to technical_incidents table
            try:
                with self.engine.connect() as conn:
                    res = conn.execute(
                        text(
                            "SELECT data FROM technical_incidents ORDER BY start_time DESC LIMIT :limit"
                        ),
                        {"limit": limit},
                    )
                    return [json.loads(row[0]) for row in res.fetchall()]
            except Exception as e:
                logger.error(f"Failed to fetch incidents from SQLite: {e}")

        # Fallback to ES search (which will use stub memory)
        res = self.es.search(
            index=self.incident_index, query={"match_all": {}}, size=limit
        )
        return [hit["_source"] for hit in res["hits"]["hits"]]

    # --- Relational State (PostgreSQL) ---

    def store_response_action(self, action: Dict[str, Any]):
        """Persist SOAR response action to PostgreSQL."""
        if not self.SessionLocal:
            logger.warning("[STORAGE] store_response_action skipped — DB unavailable.")
            return
        with self.SessionLocal() as session:
            db_action = ResponseAction(**action)
            session.add(db_action)
            session.commit()
            logger.info(f"Stored Response Action in PG: {action['id']}")

    def submit_feedback(
        self, incident_id: str, label: str, analyst: str = "system", notes: str = ""
    ):
        """Store analyst feedback in PostgreSQL."""
        if not self.SessionLocal:
            logger.warning("[STORAGE] submit_feedback skipped — DB unavailable.")
            return
        with self.SessionLocal() as session:
            fb = Feedback(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                label=label,
                analyst=analyst,
                notes=notes,
            )
            session.add(fb)
            session.commit()

    def update_model_version(self, version_data: Dict[str, Any]):
        """Store model training metadata in PostgreSQL."""
        if not self.SessionLocal:
            logger.warning("[STORAGE] update_model_version skipped — DB unavailable.")
            return
        with self.SessionLocal() as session:
            mv = (
                session.query(ModelVersion)
                .filter_by(version=version_data["version"])
                .first()
            )
            if mv:
                for k, v in version_data.items():
                    setattr(mv, k, v)
            else:
                mv = ModelVersion(**version_data)
                session.add(mv)
            session.commit()

    def get_rule_score(self, sid: int) -> Optional[Dict[str, Any]]:
        if not self.SessionLocal:
            return None
        with self.SessionLocal() as session:
            rule = session.query(RuleScore).filter_by(sid=sid).first()
            if rule:
                return {
                    "sid": rule.sid,
                    "hit_count": rule.hit_count,
                    "effectiveness_score": rule.effectiveness_score,
                    "is_retired": int(rule.is_retired),
                }
            return None

    def update_rule_hit(self, sid: int):
        with self.SessionLocal() as session:
            rule = session.query(RuleScore).filter_by(sid=sid).first()
            if rule:
                rule.hit_count += 1
                rule.last_hit_at = datetime.datetime.now(timezone.utc)
                session.commit()
