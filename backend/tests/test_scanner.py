import socket
import threading
import time
import pytest
from backend.app.scanner.tcp import (
    COMMON_PORTS_PRESET,
    resolve_inferred_service,
    scan_single_tcp_port,
)
from backend.app.schemas.scanner import (
    PortScanRequest,
    ScanExecutionResponse,
    ScanValidationRequest,
)
from backend.app.services.scanner_service import ScannerService


@pytest.fixture(scope="session")
def ephemeral_tcp_server():
    """Starts a local TCP listening server on an ephemeral loopback port for open-port tests."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(10)
    port = server.getsockname()[1]
    running = True

    def accept_loop():
        while running:
            try:
                server.settimeout(0.5)
                conn, _ = server.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    yield port
    running = False
    server.close()
    thread.join(timeout=1.0)


# 1. TCP port open detection
def test_tcp_open_port_detection(ephemeral_tcp_server):
    res = scan_single_tcp_port("127.0.0.1", ephemeral_tcp_server, timeout=1.5)
    assert res.state == "OPEN"
    assert res.port == ephemeral_tcp_server
    assert res.protocol == "TCP"
    assert res.service_confidence == "inferred"
    assert res.response_time_ms >= 0.0


# 2. TCP closed port detection
def test_tcp_closed_port_detection():
    # Find an unbound port and use 2.5s timeout so Windows returns RST/10061
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()

    res = scan_single_tcp_port("127.0.0.1", closed_port, timeout=2.5)
    assert res.state == "CLOSED"
    assert res.port == closed_port
    assert res.protocol == "TCP"


# 3. Connection timeout classification (NO_RESPONSE / UNKNOWN)
def test_tcp_timeout_classification():
    # Use an extremely small timeout (0.01s) against an unbound port to force timeout
    res = scan_single_tcp_port("127.0.0.1", 59876, timeout=0.01)
    # Must be classified as NO_RESPONSE, UNKNOWN, or FILTERED, and NOT falsely classified as CLOSED
    assert res.state in ("NO_RESPONSE", "FILTERED", "UNKNOWN")
    assert res.state != "CLOSED"


# 4. Invalid IP rejection
def test_invalid_ip_rejection():
    with pytest.raises(ValueError):
        ScannerService.resolve_target_ip("999.999.999.999")

    with pytest.raises(ValueError):
        ScannerService.resolve_target_ip("not-a-valid-hostname-or-ip-12345678.invalid")


# 5. Invalid port rejection
def test_invalid_port_rejection():
    with pytest.raises(ValueError):
        ScannerService.resolve_ports(ports=[0])

    with pytest.raises(ValueError):
        ScannerService.resolve_ports(ports=[65536])

    with pytest.raises(ValueError):
        ScannerService.resolve_ports(port_range="0-100")


# 6. Duplicate port handling
def test_duplicate_port_handling():
    ports = ScannerService.resolve_ports(ports=[80, 443, 80, 8080, 443])
    assert ports == [80, 443, 8080]


# 7. Port range validation
def test_port_range_validation():
    ports = ScannerService.resolve_ports(port_range="80-83")
    assert ports == [80, 81, 82, 83]

    with pytest.raises(ValueError):
        ScannerService.resolve_ports(port_range="100-50")  # inverted bounds


# 8. Maximum concurrency enforcement
def test_concurrency_validation(client):
    # Concurrency > 100 should be rejected by Pydantic validation
    response = client.post(
        "/api/scanner/scan",
        json={"target": "127.0.0.1", "ports": [80], "concurrency": 150},
    )
    assert response.status_code == 422


# 9. Empty port list rejection
def test_empty_port_list_rejection():
    with pytest.raises(ValueError):
        ScannerService.resolve_ports(ports=[], port_range=None, preset=None)


# 10. Scan result schema validation
def test_scan_result_schema_validation(ephemeral_tcp_server):
    req = PortScanRequest(
        target="127.0.0.1",
        ports=[ephemeral_tcp_server],
        timeout=1.0,
        concurrency=10,
    )
    import asyncio
    res = asyncio.run(ScannerService.execute_scan(req))
    assert isinstance(res, ScanExecutionResponse)
    assert res.scan_type == "TCP_CONNECT"
    assert res.total_ports == 1
    assert res.open_ports == 1
    assert len(res.results) == 1
    assert res.results[0].service_confidence == "inferred"


# 11. Scan ID generation
def test_scan_id_generation(ephemeral_tcp_server):
    req = PortScanRequest(target="127.0.0.1", ports=[ephemeral_tcp_server])
    import asyncio
    res = asyncio.run(ScannerService.execute_scan(req))
    assert res.scan_id.startswith("scan-")
    assert len(res.scan_id) == 13  # 'scan-' + 8 hex chars


# 12. Scan history retrieval
def test_scan_history_retrieval(client, ephemeral_tcp_server):
    # Trigger a scan
    client.post(
        "/api/scanner/scan",
        json={"target": "127.0.0.1", "ports": [ephemeral_tcp_server]},
    )
    hist_resp = client.get("/api/scanner/history")
    assert hist_resp.status_code == 200
    data = hist_resp.json()["data"]
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "scan_id" in data[0]
    assert data[0]["target"] == "127.0.0.1"


# 13. Target authorization enforcement
def test_target_authorization_enforcement(client):
    # Public IP outside authorized CIDRs (8.8.8.8) must be rejected
    response = client.post(
        "/api/scanner/scan",
        json={"target": "8.8.8.8", "ports": [53]},
    )
    assert response.status_code == 400
    assert "authorized" in response.json()["detail"].lower()


# 14. API integration tests
def test_api_scanner_endpoints(client, ephemeral_tcp_server):
    # GET /api/scanner/status
    st_resp = client.get("/api/scanner/status")
    assert st_resp.status_code == 200
    assert st_resp.json()["data"]["available"] is True
    assert "TCP_CONNECT" in st_resp.json()["data"]["supported_methods"]

    # POST /api/scanner/validate (valid)
    v_resp = client.post(
        "/api/scanner/validate",
        json={"target": "127.0.0.1", "ports": [80, 443]},
    )
    assert v_resp.status_code == 200
    assert v_resp.json()["data"]["valid"] is True
    assert v_resp.json()["data"]["target_authorized"] is True

    # POST /api/scanner/validate (unauthorized target)
    v_bad = client.post(
        "/api/scanner/validate",
        json={"target": "1.1.1.1", "ports": [80]},
    )
    assert v_bad.status_code == 200
    assert v_bad.json()["data"]["valid"] is False
    assert v_bad.json()["data"]["target_authorized"] is False

    # POST /api/scanner/scan
    scan_resp = client.post(
        "/api/scanner/scan",
        json={
            "target": "127.0.0.1",
            "ports": [ephemeral_tcp_server],
            "timeout": 1.0,
            "concurrency": 10,
        },
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()["data"]
    scan_id = scan_data["scan_id"]
    assert scan_data["open_ports"] >= 1

    # GET /api/scanner/scans/{scan_id}
    fetch_resp = client.get(f"/api/scanner/scans/{scan_id}")
    assert fetch_resp.status_code == 200
    assert fetch_resp.json()["data"]["scan_id"] == scan_id

    # GET /api/scanner/latest
    latest_resp = client.get("/api/scanner/latest")
    assert latest_resp.status_code == 200
    assert latest_resp.json()["data"]["scan_id"] == scan_id
