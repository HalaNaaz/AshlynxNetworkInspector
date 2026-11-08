import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.reports.report_manager import ReportManager


def test_e2e_full_system_workflow():
    """End-to-End integration test across Port Scanner, UDP Scanner, Discovery, and Reports."""
    client = TestClient(app)

    # 1. Health check
    h_resp = client.get("/api/health")
    assert h_resp.status_code == 200
    assert h_resp.json()["data"]["backend_status"] == "operational"

    # 2. Network interfaces
    if_resp = client.get("/api/network/interfaces")
    assert if_resp.status_code == 200
    assert len(if_resp.json()["data"]["interfaces"]) > 0

    # 3. TCP Port Scan on localhost (ports 135, 445, 80)
    tcp_resp = client.post(
        "/api/scanner/scan",
        json={
            "target": "127.0.0.1",
            "ports": [135, 445, 80],
            "timeout": 0.5,
            "concurrency": 10,
        },
    )
    assert tcp_resp.status_code == 200
    tcp_data = tcp_resp.json()["data"]
    tcp_scan_id = tcp_data["scan_id"]
    assert tcp_data["total_ports"] == 3
    assert tcp_data["status"] == "completed"

    # 4. UDP Port Scan on localhost (port 53, 123)
    udp_resp = client.post(
        "/api/scanner/udp/scan",
        json={
            "target": "127.0.0.1",
            "ports": [53, 123],
            "timeout": 0.3,
            "concurrency": 5,
        },
    )
    assert udp_resp.status_code == 200
    udp_data = udp_resp.json()["data"]
    udp_scan_id = udp_data["scan_id"]
    assert udp_data["total_ports"] == 2

    # 5. Host Discovery on loopback (127.0.0.1/32)
    disc_resp = client.post(
        "/api/discovery/scan",
        json={
            "cidr": "127.0.0.1/32",
            "method": "AUTO",
            "timeout": 0.5,
            "concurrency": 5,
        },
    )
    assert disc_resp.status_code == 200
    disc_data = disc_resp.json()["data"]
    disc_id = disc_data["discovery_id"]
    assert disc_data["online_hosts_count"] >= 1
    # Verify loopback MAC is not all-zeros
    loopback_host = disc_data["hosts"][0]
    assert loopback_host["mac_address"] is None or loopback_host["mac_address"] != "00:00:00:00:00:00"

    # 6. Generate PDF report from TCP Scan
    pdf_gen_resp = client.post(
        "/api/reports/generate",
        json={
            "report_type": "tcp_scan",
            "report_format": "pdf",
            "source_id": tcp_scan_id,
            "title": "E2E Localhost TCP Security Audit",
        },
    )
    assert pdf_gen_resp.status_code == 201
    pdf_meta = pdf_gen_resp.json()["data"]
    pdf_id = pdf_meta["report_id"]

    # Download PDF and verify
    pdf_dl = client.get(f"/api/reports/{pdf_id}/download")
    assert pdf_dl.status_code == 200
    assert pdf_dl.content.startswith(b"%PDF")
    assert len(pdf_dl.content) > 2000

    # 7. Generate CSV report from UDP Scan
    csv_gen_resp = client.post(
        "/api/reports/generate",
        json={
            "report_type": "udp_scan",
            "report_format": "csv",
            "source_id": udp_scan_id,
            "title": "E2E Localhost UDP Reconnaissance",
        },
    )
    assert csv_gen_resp.status_code == 201
    csv_meta = csv_gen_resp.json()["data"]
    csv_id = csv_meta["report_id"]

    # Download CSV and verify
    csv_dl = client.get(f"/api/reports/{csv_id}/download")
    assert csv_dl.status_code == 200
    assert "Port" in csv_dl.text
    assert "53" in csv_dl.text
    assert "CLOSED" in csv_dl.text

    # 8. Generate JSON report from Host Discovery
    json_gen_resp = client.post(
        "/api/reports/generate",
        json={
            "report_type": "host_discovery",
            "report_format": "json",
            "source_id": disc_id,
            "title": "E2E Host Discovery Compliance Record",
        },
    )
    assert json_gen_resp.status_code == 201
    json_meta = json_gen_resp.json()["data"]
    json_id = json_meta["report_id"]

    # Download JSON and verify
    json_dl = client.get(f"/api/reports/{json_id}/download")
    assert json_dl.status_code == 200
    json_data = json_dl.json()
    assert json_data["metadata"]["product"] == "Ashlynx Network Inspector"
    assert json_data["scope_and_target"]["Target Subnet"] == "127.0.0.1/32"

    # Cleanup generated test reports
    ReportManager.delete_report(pdf_id)
    ReportManager.delete_report(csv_id)
    ReportManager.delete_report(json_id)
