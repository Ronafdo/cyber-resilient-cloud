"""Flask API entrypoint for the cyber-resilient cloud scaffold."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, redirect, send_file

from cyber_resilient_cloud.blockchain.chain import append_block, create_chain
from cyber_resilient_cloud.shield.ddos import DDoSShield, TrafficEvent

app = Flask(__name__, static_folder="../dashboard/static", static_url_path="/static")
shield = DDoSShield()
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
    """Ingest a traffic event through the shield and record it in the chain."""
    event = TrafficEvent(source_ip="10.0.0.1", protocol="tcp", packet_size=1500, tcp_flags="SYN", http_entropy=0.7)
    decision = shield.ingest_event(event)
    append_block(chain, "traffic", {"source_ip": event.source_ip, "allowed": decision["allowed"]})
    return jsonify({"decision": decision, "chain_length": len(chain["blocks"])}), 200


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
