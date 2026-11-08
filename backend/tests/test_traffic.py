def test_get_traffic_status(client):
    """Tests the GET /api/traffic/status endpoint."""
    response = client.get("/api/traffic/status")
    assert response.status_code == 200

    payload = response.json()
    assert payload["success"] is True
    assert "data" in payload

    data = payload["data"]
    assert "available" in data
    assert "supported_protocols" in data
    assert isinstance(data["supported_protocols"], list)
    assert "TCP" in data["supported_protocols"]
    assert "UDP" in data["supported_protocols"]
    assert "engine_version" in data

