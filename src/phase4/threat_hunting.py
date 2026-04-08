#!/usr/bin/env python3
"""
Phase 4 – Threat Hunting Engine
================================
Proactively searches SIEM history for:
  • Lateral movement   – multi-hop src→dst IP chains
  • Low-and-slow       – few events spread over long time windows
  • Beaconing          – regular interval connections to a fixed destination
  • Stealth scans      – small port-counts spread over hours

Uses NetworkX DiGraph to build attack graphs:
  Nodes  = IP addresses
  Edges  = (src_ip, dst_ip) annotated with {ports, timestamps, alert_types}

Results are stored in the `hunt_results` table and returned as dicts.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class ThreatHuntingEngine:
    """
    Offline / periodic threat hunting against the SIEM SQLite database.
    Call `run_all_hunts()` to execute the full sweep.
    """

    # Beaconing: standard deviation of inter-arrival seconds must be < this threshold
    BEACON_JITTER_THRESHOLD_SECONDS = 30.0
    # Minimum occurrences to call something a beacon
    BEACON_MIN_HITS = 5
    # Low-and-slow: events spread > this many minutes qualify
    LOW_SLOW_MIN_SPREAD_MINUTES = 30
    LOW_SLOW_MAX_EVENTS_PER_HOUR = 3
    # Stealth scan: unique ports < threshold but spread over many minutes
    STEALTH_PORT_THRESHOLD = 10
    STEALTH_SPREAD_MINUTES = 45

    def __init__(self, db_path: str = "data/siem.db"):
        self.db_path = Path(db_path)

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def run_all_hunts(self, lookback_hours: int = 24) -> List[Dict]:
        """
        Execute all hunt scenarios against the last `lookback_hours` of logs.
        Persists results and returns list of hunt_result dicts.
        """
        logs_df = self._load_raw_logs(lookback_hours)
        if logs_df.empty:
            logger.info("No logs available for threat hunting")
            return []

        results: List[Dict] = []

        # Build attack graph first – used by multiple hunts
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
        """
        Construct a directed attack graph from raw log rows.

        Nodes : IP addresses (prefixed src_ / dst_ to distinguish roles)
        Edges : (src_ip, dst_ip) with edge attributes:
                  ports      – set of destination ports seen
                  timestamps – list of ISO timestamps
                  protocols  – set of protocols
        """
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
        """Serialize the attack graph for storage / API response."""
        data = nx.node_link_data(G)
        # Convert sets to lists for JSON serialisation
        for link in data.get("links", []):
            if "ports" in link:
                link["ports"] = list(link["ports"])
            if "protocols" in link:
                link["protocols"] = list(link["protocols"])
        return data

    def get_recent_hunt_results(self, limit: int = 50) -> List[Dict]:
        """Retrieve recent hunt results from the DB."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM hunt_results ORDER BY detected_at DESC LIMIT ?",
                (limit,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            logger.warning(f"Failed to load hunt results: {exc}")
            return []

    # ──────────────────────────────────────────────────────────────────────────
    # Hunt scenarios
    # ──────────────────────────────────────────────────────────────────────────

    def _hunt_lateral_movement(
        self, logs_df: pd.DataFrame, G: nx.DiGraph
    ) -> List[Dict]:
        """
        Detect lateral movement: an IP that is both a source AND a destination
        in the attack graph (multi-hop pivoting).

        A node that appears as both source and destination with high in-degree
        AND out-degree is a candidate pivot host.
        """
        results = []
        if G.number_of_nodes() == 0:
            return results

        for node in G.nodes():
            in_deg = G.in_degree(node)
            out_deg = G.out_degree(node)
            if in_deg >= 1 and out_deg >= 1:
                # Build path: predecessors → node → successors
                predecessors = list(G.predecessors(node))
                successors = list(G.successors(node))
                confidence = min(
                    1.0, (in_deg + out_deg) / 10.0
                )
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
        """
        Detect beaconing: regular-interval connections from a src_ip to a
        fixed dst_ip.  Uses inter-arrival time standard deviation as jitter.
        Low jitter = automated beacon.
        """
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
                    1.0, (1.0 - jitter / self.BEACON_JITTER_THRESHOLD_SECONDS)
                    * min(1.0, len(grp) / 20.0)
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
        """
        Detect low-and-slow attacks: src_ip with very few events/hour but
        spread over a long total time window.
        """
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
            ).total_seconds() / 60.0  # minutes

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
        """
        Detect stealth scans: source probing a small number of unique ports
        (< threshold) spread over a long time window (signature of slow scan).
        """
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

    # ──────────────────────────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────────────────────────

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
        """Load raw_logs from SIEM DB for the last N hours."""
        if not self.db_path.exists():
            return pd.DataFrame()
        try:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
            ).isoformat()
            conn = sqlite3.connect(str(self.db_path))
            df = pd.read_sql_query(
                "SELECT * FROM raw_logs WHERE timestamp >= ?",
                conn,
                params=(cutoff,),
            )
            conn.close()
            return df
        except Exception as exc:
            logger.warning(f"Failed to load raw logs for hunting: {exc}")
            return pd.DataFrame()

    def _persist_hunt_result(self, result: Dict) -> None:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO hunt_results
                (id, hunt_type, src_ip, dst_ip, details, detected_at, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result["id"],
                    result["hunt_type"],
                    result["src_ip"],
                    result["dst_ip"],
                    result["details"],
                    result["detected_at"],
                    result["confidence"],
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning(f"Failed to persist hunt result: {exc}")
