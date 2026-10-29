"""Flask API entrypoint for the cyber-resilient cloud scaffold."""

from __future__ import annotations

import ipaddress
import base64
import hashlib
import os
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, request, send_file

from cyber_resilient_cloud.blockchain.chain import append_block, create_chain
from cyber_resilient_cloud.shield.ddos import DDoSShield, TrafficEvent
from cyber_resilient_cloud.storage import Storage

app = Flask(__name__, static_folder="../dashboard/static", static_url_path="/static")
shield = DDoSShield(
    rate_limit=int(os.getenv("SHIELD_RATE_LIMIT", "10")),
    window_seconds=float(os.getenv("SHIELD_WINDOW_SECONDS", "60")),
)
chain = create_chain()
storage = Storage(os.getenv("CLOUD_DATA_DIR", Path(__file__).resolve().parents[2] / "data"))


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
    decision["source_ip"] = event.source_ip
    append_block(chain, "traffic", {
        "source_ip": event.source_ip,
        "protocol": event.protocol,
        "packet_size": event.packet_size,
        "allowed": decision["allowed"],
        "reason": decision["reason"],
    })
    return jsonify({"decision": decision, "chain_length": len(chain["blocks"])}), 200


@app.post("/files")
def upload_file() -> tuple[dict, int]:
    """Persist an encrypted browser payload without receiving the password or plaintext."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400
    try:
        filename = _required_string(payload, "filename", 255)
        mime_type = _required_string(payload, "mime_type", 127)
        plaintext_size = _bounded_int(payload, "plaintext_size", 0, 25 * 1024 * 1024)
        plaintext_hash = _required_string(payload, "plaintext_hash", 64)
        salt = _required_string(payload, "salt", 64)
        nonce = _required_string(payload, "nonce", 64)
        ciphertext = base64.b64decode(_required_string(payload, "ciphertext", 40 * 1024 * 1024), validate=True)
    except (ValueError, KeyError, base64.binascii.Error) as error:
        return jsonify({"error": f"invalid encrypted file payload: {error}"}), 400
    if not filename or "/" in filename or "\\" in filename:
        return jsonify({"error": "filename must be a plain file name"}), 400
    if len(ciphertext) > 30 * 1024 * 1024:
        return jsonify({"error": "encrypted file exceeds the 30 MB limit"}), 413
    record = storage.save_file({
        "filename": filename, "mime_type": mime_type, "plaintext_size": plaintext_size,
        "plaintext_hash": plaintext_hash, "ciphertext_hash": hashlib.sha256(ciphertext).hexdigest(),
        "salt": salt, "nonce": nonce,
    }, ciphertext)
    return jsonify({"id": record["id"], "filename": filename, "size": plaintext_size}), 201


@app.get("/files")
def list_files() -> tuple[list[dict], int]:
    return jsonify(storage.list_files()), 200


@app.get("/files/<file_id>/metadata")
def file_metadata(file_id: str) -> tuple[dict, int]:
    record = storage.get_file(file_id)
    if record is None:
        return jsonify({"error": "file not found"}), 404
    return jsonify({key: record[key] for key in (
        "id", "filename", "mime_type", "plaintext_size", "plaintext_hash",
        "ciphertext_hash", "salt", "nonce", "created_at",
    )}), 200


@app.get("/files/<file_id>/download")
def download_file(file_id: str) -> Response | tuple[dict, int]:
    record = storage.get_file(file_id)
    if record is None:
        return jsonify({"error": "file not found"}), 404
    response = Response(storage.read_blob(record), mimetype="application/octet-stream")
    response.headers["X-File-Name"] = record["filename"]
    response.headers["X-Mime-Type"] = record["mime_type"]
    response.headers["X-Salt"] = record["salt"]
    response.headers["X-Nonce"] = record["nonce"]
    response.headers["X-Plaintext-Hash"] = record["plaintext_hash"]
    return response


@app.post("/files/<file_id>/verify")
def verify_file(file_id: str) -> tuple[dict, int]:
    try:
        result = storage.verify_file(file_id)
    except FileNotFoundError:
        return jsonify({"error": "file not found"}), 404
    return jsonify(result), 200


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
        "chain_blocks": chain["blocks"] + storage.audit_blocks(),
        "blocked_ips": list(shield.blocked_ips),
        "files": storage.list_files(),
    }), 200
