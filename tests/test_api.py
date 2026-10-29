from cyber_resilient_cloud.api.app import app


def test_root_redirects_to_dashboard():
    client = app.test_client()
    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"] == "/dashboard"


def test_dashboard_data_endpoint_returns_chain_payload():
    client = app.test_client()
    response = client.get("/dashboard/data")

    assert response.status_code == 200
    data = response.get_json()
    assert "chain_blocks" in data
    assert isinstance(data["chain_blocks"], list)


def test_dashboard_static_asset_is_served():
    client = app.test_client()
    response = client.get("/static/app.js")

    assert response.status_code == 200
    assert b"simulate-traffic" in response.data


def test_ingest_accepts_validated_client_event():
    client = app.test_client()
    response = client.post("/shield/ingest", json={
        "protocol": "tcp",
        "packet_size": 1500,
        "tcp_flags": "SYN",
        "http_entropy": 0.7,
    }, environ_base={"REMOTE_ADDR": "192.0.2.10"})

    assert response.status_code == 200
    data = response.get_json()
    assert data["decision"]["allowed"] is True
    assert data["decision"]["source_event_count"] >= 1


def test_ingest_rejects_invalid_event():
    client = app.test_client()
    response = client.post("/shield/ingest", json={
        "protocol": "tcp",
        "packet_size": -1,
        "tcp_flags": "SYN",
        "http_entropy": 0.7,
    })

    assert response.status_code == 400
    assert "packet_size" in response.get_json()["error"]


def test_shield_blocks_source_after_rate_limit():
    from cyber_resilient_cloud.shield.ddos import DDoSShield, TrafficEvent

    shield = DDoSShield(rate_limit=2, window_seconds=60)
    event = TrafficEvent("192.0.2.20", "tcp", 1500, "SYN", 0.7)
    assert shield.ingest_event(event)["allowed"] is True
    assert shield.ingest_event(event)["allowed"] is True
    decision = shield.ingest_event(event)

    assert decision["allowed"] is False
    assert decision["reason"] == "rate_limit_exceeded"
