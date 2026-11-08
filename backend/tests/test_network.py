def test_get_network_interfaces(client):
    """Tests the GET /api/network/interfaces endpoint."""
    response = client.get("/api/network/interfaces")
    assert response.status_code == 200

    payload = response.json()
    assert payload["success"] is True
    assert "data" in payload

    data = payload["data"]
    assert "total_interfaces" in data
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)
    assert data["total_interfaces"] == len(data["interfaces"])

    # If the system has interfaces, verify schema keys
    if data["interfaces"]:
        iface = data["interfaces"][0]
        assert "name" in iface
        assert "ipv4_address" in iface
        assert "mac_address" in iface
        assert "is_up" in iface


def test_get_network_summary(client):
    """Tests the GET /api/network/summary endpoint."""
    response = client.get("/api/network/summary")
    assert response.status_code == 200

    payload = response.json()
    assert payload["success"] is True
    assert "data" in payload

    data = payload["data"]
    assert "bytes_sent" in data
    assert "bytes_recv" in data
    assert "packets_sent" in data
    assert "packets_recv" in data
    assert isinstance(data["bytes_sent"], int)
    assert isinstance(data["bytes_recv"], int)
    assert isinstance(data["packets_sent"], int)
    assert isinstance(data["packets_recv"], int)
    assert data["bytes_sent"] >= 0
    assert data["bytes_recv"] >= 0

