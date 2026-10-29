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
