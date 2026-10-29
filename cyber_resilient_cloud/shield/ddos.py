"""DDoS shield interface for traffic analysis and mitigation.

This package exposes placeholders for traffic ingestion, feature extraction,
and mitigation hooks. The goal is to keep the interfaces explicit so the
network detection and the API layer can be built in parallel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class TrafficEvent:
    """Represents a traffic observation for analysis."""

    source_ip: str
    protocol: str
    packet_size: int
    tcp_flags: str
    http_entropy: float


class DDoSShield:
    """Simple shield placeholder implementing a traffic decision interface."""

    def __init__(self) -> None:
        self.events: List[TrafficEvent] = []
        self.blocked_ips: set[str] = set()

    def ingest_event(self, event: TrafficEvent) -> Dict[str, object]:
        """Record an event and return a basic decision payload."""
        self.events.append(event)
        decision = {
            "allowed": event.source_ip not in self.blocked_ips,
            "reason": "allow" if event.source_ip not in self.blocked_ips else "blocked",
            "event_count": len(self.events),
        }
        return decision

    def block_ip(self, source_ip: str) -> None:
        """Block a source IP address."""
        self.blocked_ips.add(source_ip)
