def test_get_health(client):
    """Tests the GET /api/health endpoint returns required system and status fields."""
    response = client.get("/api/health")
    assert response.status_code == 200

    payload = response.json()
    assert payload["success"] is True
    assert "data" in payload

    data = payload["data"]
    assert data["application_name"] == "Ashlynx Network Inspector"
    assert data["version"] == "1.0.0"
    assert data["backend_status"] == "operational"
    assert "operating_system" in data and len(data["operating_system"]) > 0
    assert "python_version" in data and len(data["python_version"]) > 0

