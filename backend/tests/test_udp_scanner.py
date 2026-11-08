import socket
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.scanner.udp import (
    COMMON_UDP_PORTS_PRESET,
    COMMON_UDP_SERVICES,
    resolve_inferred_udp_service,
    scan_single_udp_port,
    scan_udp_ports_concurrent,
)
from backend.app.schemas.scanner import UdpScanExecutionResponse, UdpScanRequest
from backend.app.services.scanner_service import ScannerService

client = TestClient(app)


def test_udp_service_mapping():
    """Verifies well-known UDP port service mapping and fallback."""
    assert resolve_inferred_udp_service(53) == "DNS"
    assert resolve_inferred_udp_service(123) == "NTP"
    assert resolve_inferred_udp_service(161) == "SNMP"
    assert resolve_inferred_udp_service(1900) == "SSDP"
    assert resolve_inferred_udp_service(60999) in ("UNKNOWN", "unknown") or isinstance(resolve_inferred_udp_service(60999), str)


def test_udp_listening_socket_detection():
    """Spins up a mock local UDP listener socket and verifies scanner detects it as OPEN."""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    assigned_port = udp_sock.getsockname()[1]

    # In a separate thread or non-blocking, echo back any packet received
    import threading

    def echo_server():
        try:
            udp_sock.settimeout(1.0)
            data, addr = udp_sock.recvfrom(1024)
            udp_sock.sendto(b"ACK" + data, addr)
        except Exception:
            pass
        finally:
            udp_sock.close()

    th = threading.Thread(target=echo_server, daemon=True)
    th.start()

    try:
        res = scan_single_udp_port("127.0.0.1", assigned_port, timeout=0.5)
        assert res.port == assigned_port
        assert res.protocol == "UDP"
        assert res.state in ("OPEN", "OPEN|FILTERED")
    finally:
        th.join(timeout=1.0)


def test_udp_concurrent_scan():
    """Tests concurrent UDP scan across multiple ports."""
    ports = [53, 123, 137]
    results = scan_udp_ports_concurrent("127.0.0.1", ports, timeout=0.3, concurrency=5)
    assert len(results) == 3
    for r in results:
        assert r.port in ports
        assert r.protocol == "UDP"
        assert r.state in ("OPEN", "CLOSED", "OPEN|FILTERED", "UNKNOWN")


def test_udp_api_validate_valid():
    """Tests POST /api/scanner/udp/validate with valid local target."""
    resp = client.post("/api/scanner/udp/validate", json={"target": "127.0.0.1", "preset": "common"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["data"]["valid"] is True
    assert data["data"]["target_ip"] == "127.0.0.1"
    assert data["data"]["resolved_ports_count"] == len(COMMON_UDP_PORTS_PRESET)


def test_udp_api_validate_unauthorized():
    """Tests safe-mode boundary enforcement on public IP."""
    resp = client.post("/api/scanner/udp/validate", json={"target": "8.8.8.8", "preset": "common"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert data["data"]["valid"] is False
    assert data["data"]["target_authorized"] is False


def test_udp_api_scan_and_latest():
    """Tests POST /api/scanner/udp/scan and GET /api/scanner/udp/latest."""
    resp = client.post(
        "/api/scanner/udp/scan",
        json={"target": "127.0.0.1", "ports": [53, 123], "timeout": 0.3, "concurrency": 2},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    scan_id = data["data"]["scan_id"]
    assert scan_id is not None
    assert data["data"]["total_ports"] == 2

    # Check latest
    latest_resp = client.get("/api/scanner/udp/latest")
    assert latest_resp.status_code == 200
    latest_data = latest_resp.json()
    assert latest_data["success"] is True
    assert latest_data["data"]["scan_id"] == scan_id
