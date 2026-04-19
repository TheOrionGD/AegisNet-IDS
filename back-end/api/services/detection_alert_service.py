import logging
import uuid
import datetime
from datetime import timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    logger.warning("Elasticsearch not available")


class AlertStorageService:
    """
    Alert storage service for AegisNet.
    Stores detection alerts to Elasticsearch index 'aegisnet-alerts'.
    """

    INDEX_NAME = "aegisnet-alerts"

    def __init__(self, es_url: str = "http://localhost:9200"):
        self.es_url = es_url
        self.es: Optional[Elasticsearch] = None
        self._connected = False
        self._connect()

    def _connect(self) -> None:
        """Connect to Elasticsearch."""
        if not ES_AVAILABLE:
            logger.warning("Elasticsearch not installed, alerts will not be stored")
            return

        try:
            self.es = Elasticsearch([self.es_url], request_timeout=5)
            if self.es.ping():
                self._connected = True
                self._ensure_index()
                logger.info(f"Alert storage connected to {self.es_url}")
            else:
                logger.warning(f"Cannot connect to Elasticsearch at {self.es_url}")
        except Exception as e:
            logger.warning(f"Elasticsearch connection failed: {e}")

    def _ensure_index(self) -> None:
        """Ensure the alerts index exists."""
        if not self._connected or not self.es:
            return

        try:
            if not self.es.indices.exists(index=self.INDEX_NAME):
                self.es.indices.create(
                    index=self.INDEX_NAME,
                    body={
                        "mappings": {
                            "properties": {
                                "alert_id": {"type": "keyword"},
                                "timestamp": {"type": "date"},
                                "src_ip": {"type": "ip"},
                                "dst_ip": {"type": "ip"},
                                "src_port": {"type": "integer"},
                                "dst_port": {"type": "integer"},
                                "protocol": {"type": "keyword"},
                                "anomaly_score": {"type": "float"},
                                "is_anomaly": {"type": "boolean"},
                                "risk_level": {"type": "keyword"},
                                "alert_type": {"type": "keyword"},
                                "ml_model": {"type": "keyword"},
                            }
                        }
                    }
                )
                logger.info(f"Created index: {self.INDEX_NAME}")
        except Exception as e:
            logger.error(f"Index creation failed: {e}")

    def store_alert(self, alert: Dict[str, Any]) -> str:
        """
        Store an alert to Elasticsearch.
        Returns the alert ID.
        """
        alert_id = str(uuid.uuid4())

        alert_doc = {
            "alert_id": alert_id,
            "timestamp": alert.get("timestamp", datetime.datetime.now(timezone.utc).isoformat()),
            "src_ip": alert.get("src_ip", "0.0.0.0"),
            "dst_ip": alert.get("dst_ip", "0.0.0.0"),
            "src_port": alert.get("src_port", 0),
            "dst_port": alert.get("dst_port", 0),
            "protocol": alert.get("protocol", "UNKNOWN"),
            "anomaly_score": alert.get("anomaly_score", 0.0),
            "is_anomaly": alert.get("is_anomaly", False),
            "risk_level": alert.get("risk_level", "LOW"),
            "alert_type": alert.get("alert_type", "ML_ANOMALY"),
            "ml_model": "IsolationForest",
        }

        if self._connected and self.es:
            try:
                self.es.index(index=self.INDEX_NAME, id=alert_id, body=alert_doc)
                logger.debug(f"Alert stored: {alert_id}")
            except Exception as e:
                logger.error(f"Alert storage failed: {e}")

        return alert_id

    def get_recent_alerts(
        self,
        limit: int = 100,
        min_score: float = 0.0,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get recent alerts from storage."""
        if not self._connected or not self.es:
            return []

        query: Dict[str, Any] = {"bool": {"must": []}}

        if min_score > 0:
            query["bool"]["must"].append({
                "range": {"anomaly_score": {"gte": min_score}}
            })

        if risk_level:
            query["bool"]["must"].append({
                "term": {"risk_level": risk_level.upper()}
            })

        if not query["bool"]["must"]:
            query = {"match_all": {}}

        try:
            results = self.es.search(
                index=self.INDEX_NAME,
                body={
                    "query": query,
                    "sort": [{"timestamp": "desc"}],
                    "size": limit,
                },
            )
            return [hit["_source"] for hit in results["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Alert retrieval failed: {e}")
            return []

    def get_alerts_by_ip(
        self,
        ip: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get alerts for a specific IP."""
        if not self._connected or not self.es:
            return []

        query = {
            "bool": {
                "should": [
                    {"term": {"src_ip": ip}},
                    {"term": {"dst_ip": ip}},
                ]
            }
        }

        try:
            results = self.es.search(
                index=self.INDEX_NAME,
                body={
                    "query": query,
                    "sort": [{"timestamp": "desc"}],
                    "size": limit,
                },
            )
            return [hit["_source"] for hit in results["hits"]["hits"]]
        except Exception as e:
            logger.error(f"IP alert retrieval failed: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get alert storage statistics."""
        if not self._connected or not self.es:
            return {"connected": False}

        try:
            stats = self.es.search(
                index=self.INDEX_NAME,
                body={"query": {"match_all": {}}, "size": 0,
            )
            total = stats["hits"]["total"]["value"]

            risk_counts = self.es.search(
                index=self.INDEX_NAME,
                body={
                    "aggs": {
                        "risk": {"terms": {"field": "risk_level"}}
                    },
                    "size": 0,
                }
            )

            return {
                "connected": True,
                "total_alerts": total,
                "risk_distribution": {
                    bucket["key"]: bucket["doc_count"]
                    for bucket in risk_counts["aggregations"]["risk"]["buckets"]
                },
            }
        except Exception as e:
            logger.error(f"Stats retrieval failed: {e}")
            return {"connected": False, "error": str(e)}


_alert_service: Optional[AlertStorageService] = None


def get_alert_service() -> AlertStorageService:
    """Get or create the global alert service."""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertStorageService()
    return _alert_service