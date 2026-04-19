#!/usr/bin/env python3
"""
Phase 4 – Threat Hunting Engine
===============================
Proactively searches SIEM history for:
  • Lateral movement   – multi-hop src→dst IP chains
  • Low-and-slow       – few events spread over long time windows
  • Beaconing          – regular interval connections to a fixed destination
  • Stealth scans      – small port-counts spread over hours

Uses NetworkX DiGraph to build attack graphs:
  Nodes  = IP addresses
  Edges  = (src_ip, dst_ip) annotated with {ports, timestamps, alert_types}

Results are stored in MongoDB Atlas and returned as dicts.
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

import networkx as nx
import numpy as np
import pandas as pd

from siem.storage import get_storage
from api.models.database import MONGODB_URL, DATABASE_NAME

logger = logging.getLogger(__name__)


class ThreatHuntingEngine:
    """
    Offline / periodic threat hunting against the SIEM MongoDB Atlas database.
    Call `run_all_hunts()` to execute the full sweep.
    """

    BEACON_JITTER_THRESHOLD_SECONDS = 30.0
    BEACON_MIN_HITS = 5
    LOW_SLOW_MIN_SPREAD_MINUTES = 30
    LOW_SLOW_MAX_EVENTS_PER_HOUR = 3
    STEALTH_PORT_THRESHOLD = 10
    STEALTH_SPREAD_MINUTES = 45

    def __init__(self, mongo_url: str = None, db_name: str = None):
        self.mongo_url = mongo_url or MONGODB_URL
        self.db_name = db_name or DATABASE_NAME
        self.storage = get_storage()

    def run_all_hunts(self, lookback_hours: int = 24) -> List[Dict]:
        logs_df = self._load_raw_logs(lookback_hours)
        if logs_df.empty:
            logger.info("No logs available for threat hunting")
            return []

        results: List[Dict] = []

        attack_graph = self.build_attack_graph(logs_df)

        results += self._hunt_lateral_movement(logs_df, attack_graph)
        results += self._hunt_beaconing(logs_df)
        results += self._hunt_low_and_slow(logs_df)
        results += self._hunt_stealth_scans(logs_df)

        for r in results:
            self._persist_hunt_result(r)

        logger.info(f"Threat hunting complete: {len(results)} findings")
        return results

    def build_attack_graph(self, logs_df: pd.DataFrame) -> nx.DiGraph:
        G = nx.DiGraph()

        if logs_df.empty:
            return G

        for _, row in logs_df.iterrows():
            src = str(row.get("src_ip", ""))
            dst = str(row.get("dst_ip", ""))
            port = row.get("dst_port", 0)
            ts = str(row.get("timestamp", ""))
            proto = str(row.get("protocol", "UNKNOWN"))

            if not src or not dst or src == dst:
                continue

            if G.has_edge(src, dst):
                G[src][dst]["ports"].add(int(port) if port else 0)
                G[src][dst]["timestamps"].append(ts)
                G[src][dst]["protocols"].add(proto)
                G[src][dst]["count"] += 1
            else:
                G.add_edge(
                    src,
                    dst,
                    ports={int(port) if port else 0},
                    timestamps=[ts],
                    protocols={proto},
                    count=1,
                )

        logger.info(
            f"Attack graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges"
        )
        return G

    def get_graph_json(self, G: nx.DiGraph) -> Dict:
        data = nx.node_link_data(G)
        for link in data.get("links", []):
            if "ports" in link:
                link["ports"] = list(link["ports"])
            if "protocols" in link:
                link["protocols"] = list(link["protocols"])
        return data

    async def get_recent_hunt_results(self, limit: int = 50) -> List[Dict]:
        try:
            collection = self.storage.db["hunt_results"]
            cursor = collection.find().sort("detected_at", -1).limit(limit)
            results = await cursor.to_list(length=limit)
            return [r.pop("_id", None) or r for r in results]
        except Exception as exc:
            logger.warning(f"Failed to load hunt results: {exc}")
            return []

    def _hunt_lateral_movement(
        self, logs_df: pd.DataFrame, G: nx.DiGraph
    ) -> List[Dict]:
        results = []
        if G.number_of_nodes() == 0:
            return results

        for node in G.nodes():
            in_deg = G.in_degree(node)
            out_deg = G.out_degree(node)
            if in_deg >= 1 and out_deg >= 1:
                predecessors = list(G.predecessors(node))
                successors = list(G.successors(node))
                confidence = min(1.0, (in_deg + out_deg) / 10.0)
                detail = {
                    "pivot_ip": node,
                    "attacked_from": predecessors[:5],
                    "attacked_to": successors[:5],
                    "in_degree": in_deg,
                    "out_degree": out_deg,
                }
                results.append(
                    self._make_result(
                        hunt_type="lateral_movement",
                        src_ip=predecessors[0] if predecessors else node,
                        dst_ip=successors[0] if successors else node,
                        details=detail,
                        confidence=confidence,
                    )
                )

        logger.info(f"Lateral movement hunt: {len(results)} findings")
        return results

    def _hunt_beaconing(self, logs_df: pd.DataFrame) -> List[Dict]:
        results = []
        if logs_df.empty or "timestamp" not in logs_df.columns:
            return results

        df = logs_df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.dropna(subset=["timestamp"])

        grouped = df.groupby(["src_ip", "dst_ip"])
        for (src, dst), grp in grouped:
            if len(grp) < self.BEACON_MIN_HITS:
                continue
            times = grp["timestamp"].sort_values()
            diffs = times.diff().dt.total_seconds().dropna()
            if diffs.empty:
                continue
            jitter = float(diffs.std())
            mean_interval = float(diffs.mean())
            if jitter < self.BEACON_JITTER_THRESHOLD_SECONDS and mean_interval > 0:
                confidence = min(
                    1.0,
                    (1.0 - jitter / self.BEACON_JITTER_THRESHOLD_SECONDS)
                    * min(1.0, len(grp) / 20.0),
                )
                results.append(
                    self._make_result(
                        hunt_type="beaconing",
                        src_ip=str(src),
                        dst_ip=str(dst),
                        details={
                            "hit_count": len(grp),
                            "mean_interval_seconds": round(mean_interval, 2),
                            "jitter_seconds": round(jitter, 2),
                        },
                        confidence=confidence,
                    )
                )

        logger.info(f"Beaconing hunt: {len(results)} findings")
        return results

    def _hunt_low_and_slow(self, logs_df: pd.DataFrame) -> List[Dict]:
        results = []
        if logs_df.empty or "timestamp" not in logs_df.columns:
            return results

        df = logs_df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.dropna(subset=["timestamp"])

        for src_ip, grp in df.groupby("src_ip"):
            if len(grp) < 2:
                continue
            total_span = (
                grp["timestamp"].max() - grp["timestamp"].min()
            ).total_seconds() / 60.0

            if total_span < self.LOW_SLOW_MIN_SPREAD_MINUTES:
                continue

            events_per_hour = len(grp) / (total_span / 60.0)
            if events_per_hour <= self.LOW_SLOW_MAX_EVENTS_PER_HOUR:
                confidence = min(
                    1.0,
                    0.3
                    + 0.4 * min(1.0, total_span / 120.0)
                    + 0.3 * min(1.0, len(grp) / 10.0),
                )
                dst_ips = grp["dst_ip"].dropna().unique().tolist()[:5]
                results.append(
                    self._make_result(
                        hunt_type="low_and_slow",
                        src_ip=str(src_ip),
                        dst_ip=dst_ips[0] if dst_ips else "",
                        details={
                            "total_events": len(grp),
                            "span_minutes": round(total_span, 1),
                            "events_per_hour": round(events_per_hour, 2),
                            "dst_ips_sampled": dst_ips,
                        },
                        confidence=confidence,
                    )
                )

        logger.info(f"Low-and-slow hunt: {len(results)} findings")
        return results

    def _hunt_stealth_scans(self, logs_df: pd.DataFrame) -> List[Dict]:
        results = []
        if logs_df.empty or "timestamp" not in logs_df.columns:
            return results

        df = logs_df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df = df.dropna(subset=["timestamp"])

        for src_ip, grp in df.groupby("src_ip"):
            unique_ports = grp["dst_port"].nunique()
            if unique_ports == 0 or unique_ports >= self.STEALTH_PORT_THRESHOLD:
                continue

            span_minutes = (
                grp["timestamp"].max() - grp["timestamp"].min()
            ).total_seconds() / 60.0

            if span_minutes >= self.STEALTH_SPREAD_MINUTES and unique_ports >= 2:
                confidence = min(
                    1.0,
                    0.4 * min(1.0, span_minutes / 120.0)
                    + 0.3 * min(1.0, unique_ports / self.STEALTH_PORT_THRESHOLD)
                    + 0.3,
                )
                ports_seen = sorted(
                    grp["dst_port"].dropna().astype(int).unique().tolist()
                )
                results.append(
                    self._make_result(
                        hunt_type="stealth_scan",
                        src_ip=str(src_ip),
                        dst_ip=str(grp["dst_ip"].iloc[0]),
                        details={
                            "unique_ports": unique_ports,
                            "span_minutes": round(span_minutes, 1),
                            "ports_sampled": ports_seen[:20],
                        },
                        confidence=confidence,
                    )
                )

        logger.info(f"Stealth scan hunt: {len(results)} findings")
        return results

    def _make_result(
        self,
        hunt_type: str,
        src_ip: str,
        dst_ip: str,
        details: Dict,
        confidence: float,
    ) -> Dict:
        return {
            "id": str(uuid.uuid4()),
            "hunt_type": hunt_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "details": json.dumps(details),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "confidence": round(confidence, 4),
        }

    def _load_raw_logs(self, lookback_hours: int) -> pd.DataFrame:
        import asyncio

        async def _fetch():
            cutoff = (
                datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
            ).isoformat()
            try:
                collection = self.storage.db["ids_events"]
                query = {"timestamp": {"$gte": cutoff}}
                cursor = collection.find(query).sort("timestamp", -1).limit(10000)
                events = await cursor.to_list(length=10000)
                return pd.DataFrame(events)
            except Exception as exc:
                logger.warning(f"Failed to load raw logs for hunting: {exc}")
                return pd.DataFrame()

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, _fetch())
                    return future.result()
            else:
                return asyncio.run(_fetch())
        except Exception as exc:
            logger.warning(f"Failed to load raw logs for hunting: {exc}")
            return pd.DataFrame()

    async def _persist_hunt_result_async(self, result: Dict) -> None:
        try:
            collection = self.storage.db["hunt_results"]
            await collection.replace_one(
                {"id": result["id"]},
                result,
                upsert=True,
            )
        except Exception as exc:
            logger.warning(f"Failed to persist hunt result: {exc}")

    def _persist_hunt_result(self, result: Dict) -> None:
        try:
            import asyncio

            asyncio.run(self._persist_hunt_result_async(result))
        except Exception as exc:
            logger.warning(f"Failed to persist hunt result: {exc}")


def get_threat_hunting_engine() -> ThreatHuntingEngine:
    return ThreatHuntingEngine()
