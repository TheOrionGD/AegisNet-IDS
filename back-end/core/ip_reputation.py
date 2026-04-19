import logging
import datetime
from datetime import timezone
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field
import threading

logger = logging.getLogger(__name__)


@dataclass
class IPProfile:
    """Profile for tracked IP address."""

    ip: str
    first_seen: str
    last_seen: str
    event_count: int = 0
    anomaly_count: int = 0
    avg_anomaly_score: float = 0.0
    ports: set = field(default_factory=set)
    protocols: set = field(default_factory=set)
    targets: set = field(default_factory=set)
    risk_level: str = "LOW"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "anomaly_count": self.anomaly_count,
            "avg_anomaly_score": round(self.avg_anomaly_score, 3),
            "ports": list(self.ports),
            "protocols": list(self.protocols),
            "targets": list(self.targets),
            "risk_level": self.risk_level,
            "tags": self.tags,
        }

    def update_risk_level(self) -> None:
        """Update risk level based on profile."""
        if self.anomaly_count >= 10 or self.avg_anomaly_score >= 0.8:
            self.risk_level = "CRITICAL"
        elif self.anomaly_count >= 5 or self.avg_anomaly_score >= 0.6:
            self.risk_level = "HIGH"
        elif self.anomaly_count >= 2 or self.avg_anomaly_score >= 0.4:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"

        if self.event_count > 100:
            if "HIGH_VOLUME" not in self.tags:
                self.tags.append("HIGH_VOLUME")
        if len(self.targets) > 20:
            if "SCANNER" not in self.tags:
                self.tags.append("SCANNER")
        if len(self.ports) > 10:
            if "PORT_SCAN" not in self.tags:
                self.tags.append("PORT_SCAN")


class IPReputationTracker:
    """
    Live IP reputation tracking service.
    Tracks source IPs, calculates risk scores, maintains profiles.
    """

    def __init__(
        self,
        max_ips: int = 10000,
        window_minutes: int = 60,
        prune_threshold: float = 0.3,
    ):
        self.max_ips = max_ips
        self.window_minutes = window_minutes
        self.prune_threshold = prune_threshold
        self._profiles: Dict[str, IPProfile] = {}
        self._lock = threading.Lock()

    def track_event(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "TCP",
        anomaly_score: float = 0.0,
        is_anomaly: bool = False,
    ) -> IPProfile:
        """Track a network event from an IP."""
        if not src_ip or src_ip == "0.0.0.0":
            return None

        now = datetime.datetime.now(timezone.utc).isoformat()

        with self._lock:
            if src_ip not in self._profiles:
                self._profiles[src_ip] = IPProfile(
                    ip=src_ip,
                    first_seen=now,
                    last_seen=now,
                )
                if len(self._profiles) > self.max_ips:
                    self._prune_profiles()

            profile = self._profiles[src_ip]
            profile.event_count += 1
            profile.last_seen = now

            if is_anomaly:
                profile.anomaly_count += 1
                profile.avg_anomaly_score = (
                    profile.avg_anomaly_score * (profile.anomaly_count - 1)
                    + anomaly_score
                ) / profile.anomaly_count

            if src_port > 0:
                profile.ports.add(src_port)
            if dst_port > 0:
                profile.targets.add(f"{dst_ip}:{dst_port}")
            if protocol:
                profile.protocols.add(protocol)

            profile.update_risk_level()
            return profile

    def _prune_profiles(self) -> None:
        """Remove old/low-value profiles when limit reached."""
        if not self._profiles:
            return

        sorted_profiles = sorted(
            self._profiles.items(),
            key=lambda x: (
                x[1].event_count,
                x[1].avg_anomaly_score,
            ),
            reverse=True,
        )

        to_keep = sorted_profiles[: self.max_ips]
        self._profiles = {ip: profile for ip, profile in to_keep}
        logger.info(f"Pruned IP profiles, keeping {len(self._profiles)}")

    def get_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get profile for a specific IP."""
        with self._lock:
            profile = self._profiles.get(ip)
            return profile.to_dict() if profile else None

    def get_top_suspicious(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top N suspicious IPs sorted by anomaly score."""
        with self._lock:
            sorted_ips = sorted(
                self._profiles.values(),
                key=lambda x: (
                    x.avg_anomaly_score,
                    x.anomaly_count,
                ),
                reverse=True,
            )
            return [p.to_dict() for p in sorted_ips[:limit]]

    def get_anomalous_ips(self, min_score: float = 0.5) -> List[Dict[str, Any]]:
        """Get all IPs with anomaly score above threshold."""
        with self._lock:
            return [
                p.to_dict()
                for p in self._profiles.values()
                if p.avg_anomaly_score >= min_score
            ]

    def get_stats(self) -> Dict[str, Any]:
        """Get tracker statistics."""
        with self._lock:
            total_events = sum(p.event_count for p in self._profiles.values())
            total_anomalies = sum(p.anomaly_count for p in self._profiles.values())
            risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for p in self._profiles.values():
                risk_counts[p.risk_level] = risk_counts.get(p.risk_level, 0) + 1

            return {
                "tracked_ips": len(self._profiles),
                "total_events": total_events,
                "total_anomalies": total_anomalies,
                "risk_distribution": risk_counts,
            }

    def clear(self) -> None:
        """Clear all profiles."""
        with self._lock:
            self._profiles.clear()


_global_tracker: Optional[IPReputationTracker] = None


def get_reputation_tracker() -> IPReputationTracker:
    """Get or create global IP reputation tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = IPReputationTracker()
    return _global_tracker
