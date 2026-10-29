"""Flask API entrypoint for the cyber-resilient cloud scaffold."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

from flask import Flask, jsonify, redirect, request, send_file

from cyber_resilient_cloud.blockchain.chain import append_block, create_chain
from cyber_resilient_cloud.shield.ddos import DDoSShield, TrafficEvent

app = Flask(__name__, static_folder="../dashboard/static", static_url_path="/static")
shield = DDoSShield(
    rate_limit=int(os.getenv("SHIELD_RATE_LIMIT", "10")),
    window_seconds=float(os.getenv("SHIELD_WINDOW_SECONDS", "60")),
)
chain = create_chain()


@app.get("/")
def index() -> object:
    """Redirect the root URL to the dashboard."""
    return redirect("/dashboard")


@app.get("/health")
def health() -> tuple[dict, int]:
    """Simple health endpoint for the service."""
    return jsonify({"status": "ok", "shield_events": len(shield.events), "chain_length": len(chain["blocks"])}), 200


@app.post("/shield/ingest")
def ingest() -> tuple[dict, int]:
    """Validate and ingest a client traffic event through the shield."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    source_ip = request.remote_addr or payload.get("source_ip")
    try:
        source_ip = str(ipaddress.ip_address(source_ip))
    except (ValueError, TypeError):
        return jsonify({"error": "source_ip must be a valid IP address"}), 400

    try:
        event = TrafficEvent(
            source_ip=source_ip,
            protocol=_required_string(payload, "protocol", 16),
            packet_size=_bounded_int(payload, "packet_size", 1, 10_000_000),
            tcp_flags=_required_string(payload, "tcp_flags", 32),
            http_entropy=_bounded_float(payload, "http_entropy", 0.0, 1.0),
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    decision = shield.ingest_event(event)
    append_block(chain, "traffic", {
        "source_ip": event.source_ip,
        "protocol": event.protocol,
        "packet_size": event.packet_size,
        "allowed": decision["allowed"],
        "reason": decision["reason"],
    })
    return jsonify({"decision": decision, "chain_length": len(chain["blocks"])}), 200


def _required_string(payload: dict, field: str, max_length: int) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValueError(f"{field} must be a non-empty string of at most {max_length} characters")
    return value.strip()


def _bounded_int(payload: dict, field: str, minimum: int, maximum: int) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _bounded_float(payload: dict, field: str, minimum: float, maximum: float) -> float:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be a number between {minimum} and {maximum}")
    return float(value)


@app.get("/dashboard")
def dashboard() -> object:
    """Serve the monitoring dashboard HTML page."""
    dashboard_path = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
    return send_file(dashboard_path, mimetype="text/html")


@app.get("/dashboard/data")
def dashboard_data() -> tuple[dict, int]:
    """Return the current shield and blockchain state to the dashboard."""
    return jsonify({
        "shield_events": len(shield.events),
        "chain_blocks": chain["blocks"],
        "blocked_ips": list(shield.blocked_ips),
    }), 200
