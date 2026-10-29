"""DDoS shield interface for traffic analysis and mitigation.

This package exposes placeholders for traffic ingestion, feature extraction,
and mitigation hooks. The goal is to keep the interfaces explicit so the
network detection and the API layer can be built in parallel.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from time import monotonic
from typing import Deque, Dict, List


@dataclass
class TrafficEvent:
    """Represents a traffic observation for analysis."""

    source_ip: str
    protocol: str
    packet_size: int
    tcp_flags: str
    http_entropy: float


class DDoSShield:
    """Rate-based traffic shield with a sliding window per source IP."""

    def __init__(self, rate_limit: int = 10, window_seconds: float = 60.0) -> None:
        if rate_limit < 1:
            raise ValueError("rate_limit must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.events: List[TrafficEvent] = []
        self.blocked_ips: set[str] = set()
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self._recent_events: Dict[str, Deque[float]] = defaultdict(deque)

    def ingest_event(self, event: TrafficEvent) -> Dict[str, object]:
        """Record an event and return a rate-based allow/block decision."""
        self.events.append(event)
        now = monotonic()
        timestamps = self._recent_events[event.source_ip]
        cutoff = now - self.window_seconds
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        timestamps.append(now)
        if len(timestamps) > self.rate_limit:
            self.blocked_ips.add(event.source_ip)

        allowed = event.source_ip not in self.blocked_ips
        decision = {
            "allowed": allowed,
            "reason": "allow" if allowed else "rate_limit_exceeded",
            "event_count": len(self.events),
            "source_event_count": len(timestamps),
            "rate_limit": self.rate_limit,
            "window_seconds": self.window_seconds,
        }
        return decision

    def block_ip(self, source_ip: str) -> None:
        """Block a source IP address."""
        self.blocked_ips.add(source_ip)
