import io
import json
import csv
import base64
import zlib
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.reports import (
    ReportFormat,
    ReportGenerateRequest,
    ReportType,
)
from backend.app.reports.report_manager import ReportManager
from backend.app.reports.data_collector import DataCollector, ReportPayload
from backend.app.reports.pdf_generator import PdfReportGenerator
from backend.app.reports.csv_generator import CsvReportGenerator
from backend.app.reports.json_generator import JsonReportGenerator
from backend.app.services.scanner_service import ScannerService
from backend.app.services.discovery_service import DiscoveryService
from backend.app.capture.capture_manager import CaptureManager
from backend.app.capture.capture_engine import LiveCaptureEngine
from backend.app.schemas.scanner import ScanExecutionResponse, PortScanResultItem, UdpScanExecutionResponse, UdpScanResultItem
from backend.app.schemas.discovery import HostDiscoveryResponse, DiscoveredHostItem
from backend.app.schemas.capture import PacketMetadataItem


@pytest.fixture(autouse=True)
def setup_test_telemetry():
    """Seeds test data into services for report generation."""
    # Seed TCP Scan
    tcp_scan = ScanExecutionResponse(
        scan_id="tcp-test-01",
        target="127.0.0.1",
        scan_type="TCP_CONNECT",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        duration_seconds=0.45,
        total_ports=3,
        open_ports=1,
        closed_ports=1,
        filtered_ports=1,
        no_response_ports=0,
        filtered_or_unknown_ports=1,
        results=[
            PortScanResultItem(port=80, state="OPEN", service="http", service_confidence="inferred", response_time_ms=1.2),
            PortScanResultItem(port=443, state="CLOSED", service="https", service_confidence="inferred", response_time_ms=0.8),
            PortScanResultItem(port=8080, state="FILTERED", service="http-proxy", service_confidence="inferred", response_time_ms=1000.0),
        ],
    )
    ScannerService._scans["tcp-test-01"] = tcp_scan
    ScannerService._latest_scan = tcp_scan

    # Seed TCP Scan scan-183d6624 (127.0.0.1, 21 ports, 2 open, 0 closed, 19 no response)
    scan_183 = ScanExecutionResponse(
        scan_id="scan-183d6624",
        target="127.0.0.1",
        scan_type="TCP_CONNECT",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        duration_seconds=1.01,
        total_ports=21,
        open_ports=2,
        closed_ports=0,
        filtered_ports=0,
        no_response_ports=19,
        filtered_or_unknown_ports=19,
        results=[
            PortScanResultItem(port=135, state="OPEN", service="MS-RPC", service_confidence="inferred", response_time_ms=0.6),
            PortScanResultItem(port=445, state="OPEN", service="SMB", service_confidence="inferred", response_time_ms=0.7),
        ] + [
            PortScanResultItem(port=p, state="NO_RESPONSE", service="unknown", service_confidence="inferred", response_time_ms=1002.0)
            for p in [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        ],
    )
    ScannerService._scans["scan-183d6624"] = scan_183

    # Seed UDP Scan
    udp_scan = UdpScanExecutionResponse(
        scan_id="udp-test-01",
        target="127.0.0.1",
        scan_type="UDP_DGRAM",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        duration_seconds=0.30,
        total_ports=2,
        open_ports=1,
        closed_ports=1,
        open_or_filtered_ports=0,
        unknown_ports=0,
        results=[
            UdpScanResultItem(port=53, state="OPEN", service="dns", response_time_ms=2.1),
            UdpScanResultItem(port=123, state="CLOSED", service="ntp", response_time_ms=0.9),
        ],
    )
    ScannerService._udp_scans["udp-test-01"] = udp_scan
    ScannerService._latest_udp_scan = udp_scan

    # Seed Host Discovery
    discovery = HostDiscoveryResponse(
        discovery_id="disc-test-01",
        cidr="192.168.1.0/24",
        method="AUTO",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        duration_seconds=1.1,
        total_probed=2,
        online_hosts_count=2,
        hosts=[
            DiscoveredHostItem(ip_address="192.168.1.1", hostname="gateway.local", status="online", mac_address="AA:BB:CC:DD:EE:01", response_time_ms=1.5, discovery_method="ARP"),
            DiscoveredHostItem(ip_address="192.168.1.50", hostname="workstation", status="online", mac_address="AA:BB:CC:DD:EE:02", response_time_ms=0.6, discovery_method="ARP"),
        ],
    )
    DiscoveryService._discoveries["disc-test-01"] = discovery
    DiscoveryService._latest_discovery = discovery

    # Seed Capture Engine with session
    test_engine = LiveCaptureEngine(
        session_id="sess-test-01",
        interface_id="wifi0",
        interface_name="Wi-Fi Test Interface",
        filter_bpf="ip",
        buffer_limit=100,
    )
    test_engine._total_captured = 50
    test_engine._bytes_captured = 15400
    test_engine.status = "CAPTURING"

    # Push a test frame to populate analytics & buffer
    test_frame = PacketMetadataItem(
        packet_id=1,
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        protocol="TCP",
        src_port=54321,
        dst_port=443,
        length=74,
        tcp_flags="SYN",
        interface="wifi0",
        session_id="sess-test-01",
    )
    test_engine._packets.append(test_frame)
    test_engine.analytics_engine.process_packet(test_frame)
    test_engine.security_engine.process_packet(test_frame)

    CaptureManager.register_test_engine(test_engine)


def test_data_collector_all_sources():
    """Verifies data extraction across all supported report sources including system baseline."""
    for rtype in [
        ReportType.SYSTEM_BASELINE,
        ReportType.TCP_SCAN,
        ReportType.UDP_SCAN,
        ReportType.HOST_DISCOVERY,
        ReportType.CAPTURE_SESSION,
        ReportType.TRAFFIC_ANALYTICS,
        ReportType.SECURITY_EVENTS,
    ]:
        req = ReportGenerateRequest(
            report_type=rtype,
            report_format=ReportFormat.JSON,
            title=f"Test {rtype.value}",
        )
        payload = DataCollector.collect_data(req)
        assert payload.report_type == rtype
        assert payload.source_id is not None
        assert len(payload.table_headers) > 0
        assert isinstance(payload.table_rows, list)
        assert len(payload.summary_metrics) > 0
        assert payload.engines_status is not None
        assert len(payload.limitations) > 0


def test_generators_pdf_csv_json():
    """Tests that PDF, CSV, and JSON generators produce valid, parseable outputs."""
    req = ReportGenerateRequest(
        report_type=ReportType.TCP_SCAN,
        report_format=ReportFormat.PDF,
        source_id="tcp-test-01",
    )
    payload = DataCollector.collect_data(req)

    # 1. PDF Generation
    pdf_bytes = PdfReportGenerator.generate(payload)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000

    # 2. CSV Generation
    csv_bytes = CsvReportGenerator.generate(payload)
    assert isinstance(csv_bytes, bytes)
    csv_text = csv_bytes.decode("utf-8")
    assert "Port" in csv_text
    assert "State" in csv_text
    # Parse with csv reader: exactly 1 header + 3 data rows = 4 rows
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 4
    assert rows[0] == ["Port", "State", "Service", "Confidence", "Latency (ms)"]

    # 3. JSON Generation
    json_bytes = JsonReportGenerator.generate(payload)
    assert isinstance(json_bytes, bytes)
    parsed = json.loads(json_bytes.decode("utf-8"))
    assert parsed["report_type"] == "tcp_scan"
    assert parsed["product"] == "Ashlynx Network Inspector"
    assert parsed["application_version"] == "1.0.0"
    assert "findings" in parsed
    assert len(parsed["findings"]) == 3


def test_path_traversal_protection():
    """Ensures directory traversal attempts are strictly blocked."""
    with pytest.raises(PermissionError):
        ReportManager.get_safe_filepath("../../etc/passwd")

    with pytest.raises(ValueError):
        ReportManager.sanitize_id("../bad_id")


def test_report_manager_lifecycle():
    """Tests generating, listing, previewing, and deleting reports."""
    req = ReportGenerateRequest(
        report_type=ReportType.HOST_DISCOVERY,
        report_format=ReportFormat.CSV,
        source_id="disc-test-01",
        title="Test Subnet Audit",
    )
    meta = ReportManager.generate_report(req)
    assert meta.report_id.startswith("rpt-")
    assert meta.report_format == ReportFormat.CSV

    # Preview
    preview = ReportManager.get_preview(meta.report_id)
    assert preview.report_id == meta.report_id
    assert preview.total_rows == 2

    # History
    history = ReportManager.list_history()
    assert any(h.report_id == meta.report_id for h in history)

    # File retrieval
    fpath, mime, fname = ReportManager.get_report_file(meta.report_id)
    assert fpath.exists()
    assert mime == "text/csv; charset=utf-8"

    # Delete
    deleted = ReportManager.delete_report(meta.report_id)
    assert deleted is True
    assert not fpath.exists()


def test_api_reports_endpoints():
    """Tests the full HTTP API workflow for reports."""
    client = TestClient(app)

    # 1. Sources listing
    resp = client.get("/api/reports/sources")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert len(data["data"]["sources"]) > 0

    # 2. Generate PDF Report
    gen_resp = client.post(
        "/api/reports/generate",
        json={
            "report_type": "tcp_scan",
            "report_format": "pdf",
            "source_id": "tcp-test-01",
            "title": "API Verification Scan Report",
        },
    )
    assert gen_resp.status_code == 201
    meta = gen_resp.json()["data"]
    report_id = meta["report_id"]

    # 3. Preview Report
    prev_resp = client.get(f"/api/reports/{report_id}/preview")
    assert prev_resp.status_code == 200
    prev_data = prev_resp.json()["data"]
    assert prev_data["report_id"] == report_id
    assert "Summary" in prev_data["summary"]

    # 4. Download Report
    dl_resp = client.get(f"/api/reports/{report_id}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/pdf"
    assert "attachment" in dl_resp.headers["content-disposition"]
    assert dl_resp.content.startswith(b"%PDF")

    # 5. History
    hist_resp = client.get("/api/reports/history")
    assert hist_resp.status_code == 200
    items = hist_resp.json()["data"]
    assert any(item["report_id"] == report_id for item in items)

    # 6. Delete
    del_resp = client.delete(f"/api/reports/{report_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["data"] is True

    # 7. Download deleted report returns 404
    dl_404 = client.get(f"/api/reports/{report_id}/download")
    assert dl_404.status_code == 404


def test_system_baseline_report_integrity_and_authoritative_metadata():
    """Validates that reports never contain hardcoded '0.1.0' or 'Phase 1 Initialized',

    and adhere strictly to the 11-field standardized JSON schema.
    """
    from backend.app.core.config import settings

    req = ReportGenerateRequest(
        report_type=ReportType.SYSTEM_BASELINE,
        report_format=ReportFormat.JSON,
        source_id="system",
        title="Authoritative Baseline Audit",
    )
    payload = DataCollector.collect_data(req)
    json_bytes = JsonReportGenerator.generate(payload, report_id="rpt-baseline-test")
    raw_text = json_bytes.decode("utf-8")
    parsed = json.loads(raw_text)

    # 1. Authoritative version checks - NO hardcoded 0.1.0
    assert parsed["version"] == settings.app_version
    assert parsed["version"] == "1.0.0"
    assert "0.1.0" not in raw_text
    assert "Phase 1 Initialized" not in raw_text

    # 2. Top-level Schema Key Verification (Requested ANI Standard Schema)
    expected_top_keys = [
        "report_id",
        "product",
        "version",
        "report_type",
        "export_date",
        "source_session_id",
        "engines",
        "summary",
        "metrics",
        "findings",
        "limitations",
    ]
    for key in expected_top_keys:
        assert key in parsed, f"Missing required top-level key: {key}"

    assert parsed["product"] == "Ashlynx Network Inspector"
    assert parsed["report_type"] == "system_baseline"
    assert parsed["source_session_id"] is None  # System baseline has no single session ID

    # 3. Engines Runtime Status Verification (Live subsystems)
    engines = parsed["engines"]
    assert "engine_a_port_scanner" in engines
    assert "engine_b_traffic_analyzer" in engines
    assert "engine_c_host_discovery" in engines
    assert "engine_d_security_intelligence" in engines

    # Port scanner engine verification
    assert engines["engine_a_port_scanner"]["name"] == "Port Scanner (TCP Connect & UDP Datagram)"
    assert engines["engine_a_port_scanner"]["status"] in ("operational", "ready")
    assert engines["engine_a_port_scanner"]["safe_mode_enforced"] is True

    # Traffic analyzer engine verification
    assert engines["engine_b_traffic_analyzer"]["name"] == "Live Packet Capture & Traffic Analytics"
    assert "capability_status" in engines["engine_b_traffic_analyzer"]
    assert "npcap_installed" in engines["engine_b_traffic_analyzer"]
    assert "scapy_installed" in engines["engine_b_traffic_analyzer"]

    # Security intelligence engine verification
    assert engines["engine_d_security_intelligence"]["name"] == "Security Intelligence & Anomaly Detection"
    assert engines["engine_d_security_intelligence"]["runtime_state"] in ("active", "idle")

    # 4. Limitations Verification
    assert isinstance(parsed["limitations"], list)
    assert len(parsed["limitations"]) >= 3
    assert any("privileges" in lim.lower() for lim in parsed["limitations"])


def test_system_baseline_format_consistency_json_csv_pdf():
    """Verifies that JSON, CSV, and PDF all generate consistently for SYSTEM_BASELINE."""
    req_json = ReportGenerateRequest(
        report_type=ReportType.SYSTEM_BASELINE,
        report_format=ReportFormat.JSON,
        source_id="system",
        title="Multi-Format Baseline Audit",
    )
    payload = DataCollector.collect_data(req_json)

    # 1. JSON
    json_bytes = JsonReportGenerator.generate(payload)
    parsed = json.loads(json_bytes.decode("utf-8"))
    assert parsed["report_type"] == "system_baseline"
    assert parsed["version"] == "1.0.0"

    # 2. CSV
    csv_bytes = CsvReportGenerator.generate(payload)
    csv_text = csv_bytes.decode("utf-8")
    assert "Subsystem / Engine" in csv_text or "Version" in csv_text
    reader = csv.reader(io.StringIO(csv_text))
    csv_rows = list(reader)
    assert len(csv_rows) == 5  # 1 header + 4 engine rows
    assert csv_rows[0] == ["Subsystem / Engine", "Version", "Operational Status", "Active Target / Session", "Runtime State"]

    # 3. PDF
    pdf_bytes = PdfReportGenerator.generate(payload)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000


def test_inactive_engines_and_null_integrity():
    """Verifies that when engines are not active, they are not marked active,

    and absent scan targets/sessions are represented as null/None, never fabricated.
    """
    # Create empty request without prior session
    req = ReportGenerateRequest(
        report_type=ReportType.SYSTEM_BASELINE,
        report_format=ReportFormat.JSON,
        source_id="system",
    )
    payload = DataCollector.collect_data(req)
    engines = payload.engines_status

    # Check Engine A
    assert engines["engine_a_port_scanner"]["runtime_state"] == "idle"
    # Scanner is not currently running an active scan, so runtime_state is idle
    assert engines["engine_c_host_discovery"]["runtime_state"] == "idle"


def test_tcp_scan_183d6624_independent_three_formats():
    """Validates complete end-to-end format routing, data integrity, and serializer isolation

    for TCP scan 'scan-183d6624' across PDF, CSV, and JSON formats.
    """
    client = TestClient(app)

    # -------------------------------------------------------------
    # 1. JSON Schema Export Verification
    # -------------------------------------------------------------
    json_gen = client.post(
        "/api/reports/generate",
        json={
            "report_type": "tcp_scan",
            "report_format": "json",
            "source_id": "scan-183d6624",
            "title": "TCP Scan 183d6624 JSON Schema Audit",
        },
    )
    assert json_gen.status_code == 201
    json_meta = json_gen.json()["data"]
    json_rep_id = json_meta["report_id"]
    assert json_meta["report_format"] == "json"
    assert json_meta["filename"] == f"ani_tcp_scan_{json_rep_id}.json"

    # Download JSON
    json_dl = client.get(f"/api/reports/{json_rep_id}/download")
    assert json_dl.status_code == 200
    assert json_dl.headers["content-type"] == "application/json"
    assert f'filename="ani_tcp_scan_{json_rep_id}.json"' in json_dl.headers["content-disposition"]
    raw_json_str = json_dl.content.decode("utf-8")
    assert not raw_json_str.startswith("```")  # No markdown code fences
    assert not raw_json_str.startswith("Port,State")  # Not CSV!

    # Parse with Python standard json.loads()
    json_data = json.loads(raw_json_str)
    assert json_data["report_id"] == json_rep_id
    assert json_data["product"] == "Ashlynx Network Inspector"
    assert json_data["application_version"] == "1.0.0"
    assert json_data["report_type"] == "tcp_scan"
    assert "generated_at" in json_data

    # Verify source block
    assert json_data["source"]["target"] == "127.0.0.1"
    assert json_data["source"]["scan_id"] == "scan-183d6624"

    # Verify summary metrics
    assert json_data["summary"]["total_ports"] == 21
    assert json_data["summary"]["open"] == 2
    assert json_data["summary"]["closed"] == 0
    assert json_data["summary"]["no_response"] == 19

    # Verify findings array
    findings = json_data["findings"]
    assert isinstance(findings, list)
    assert len(findings) == 21
    # Check open ports
    open_findings = [f for f in findings if f["state"] == "OPEN"]
    assert len(open_findings) == 2
    open_ports = {f["port"] for f in open_findings}
    assert open_ports == {135, 445}

    # Verify localhost exposure assessment
    scope = json_data["scope_and_target"]
    assert "Localhost loopback" in scope["Network Exposure Scope"]
    assert "NOT ASSESSED" in scope["Network Exposure Scope"]

    # Verify JSON preview endpoint returns structured json_preview
    prev_json = client.get(f"/api/reports/{json_rep_id}/preview")
    assert prev_json.status_code == 200
    prev_json_data = prev_json.json()["data"]
    assert prev_json_data["report_format"] == "json"
    assert prev_json_data["json_preview"] is not None
    assert prev_json_data["json_preview"]["report_id"] == json_rep_id
    assert prev_json_data["raw_content"] is not None

    # -------------------------------------------------------------
    # 2. CSV Export Verification
    # -------------------------------------------------------------
    csv_gen = client.post(
        "/api/reports/generate",
        json={
            "report_type": "tcp_scan",
            "report_format": "csv",
            "source_id": "scan-183d6624",
            "title": "TCP Scan 183d6624 CSV Export",
        },
    )
    assert csv_gen.status_code == 201
    csv_meta = csv_gen.json()["data"]
    csv_rep_id = csv_meta["report_id"]
    assert csv_meta["report_format"] == "csv"
    assert csv_meta["filename"] == f"ani_tcp_scan_{csv_rep_id}.csv"

    # Download CSV
    csv_dl = client.get(f"/api/reports/{csv_rep_id}/download")
    assert csv_dl.status_code == 200
    assert "text/csv" in csv_dl.headers["content-type"]
    assert f'filename="ani_tcp_scan_{csv_rep_id}.csv"' in csv_dl.headers["content-disposition"]
    csv_text = csv_dl.content.decode("utf-8")
    assert not csv_text.startswith("#")  # No metadata comment lines

    # Parse with standard csv.reader
    reader = csv.reader(io.StringIO(csv_text))
    csv_lines = list(reader)
    # Exactly 1 header row + 21 data rows = 22 lines
    assert len(csv_lines) == 22
    assert csv_lines[0] == ["Port", "State", "Service", "Confidence", "Latency (ms)"]
    for row in csv_lines:
        assert len(row) == 5  # Consistent column count!

    # Verify with pandas if available
    try:
        import pandas as pd
        df = pd.read_csv(io.StringIO(csv_text))
        assert len(df) == 21
        assert list(df.columns) == ["Port", "State", "Service", "Confidence", "Latency (ms)"]
        assert len(df[df["State"] == "OPEN"]) == 2
    except ImportError:
        pass  # pandas is optional

    # -------------------------------------------------------------
    # 3. PDF Audit Verification
    # -------------------------------------------------------------
    pdf_gen = client.post(
        "/api/reports/generate",
        json={
            "report_type": "tcp_scan",
            "report_format": "pdf",
            "source_id": "scan-183d6624",
            "title": "TCP Scan 183d6624 Executive PDF Audit",
        },
    )
    assert pdf_gen.status_code == 201
    pdf_meta = pdf_gen.json()["data"]
    pdf_rep_id = pdf_meta["report_id"]
    assert pdf_meta["report_format"] == "pdf"
    assert pdf_meta["filename"] == f"ani_tcp_scan_{pdf_rep_id}.pdf"

    # Download PDF
    pdf_dl = client.get(f"/api/reports/{pdf_rep_id}/download")
    assert pdf_dl.status_code == 200
    assert pdf_dl.headers["content-type"] == "application/pdf"
    assert f'filename="ani_tcp_scan_{pdf_rep_id}.pdf"' in pdf_dl.headers["content-disposition"]
    assert pdf_dl.content.startswith(b"%PDF")
    assert len(pdf_dl.content) > 1000

    # -------------------------------------------------------------
    # 4. Cross-Format Consistency Verification
    # -------------------------------------------------------------
    # All three formats reflect the same underlying scan record
    assert json_meta["source_id"] == "scan-183d6624"
    assert csv_meta["source_id"] == "scan-183d6624"
    assert pdf_meta["source_id"] == "scan-183d6624"
    assert json_meta["item_count"] == 21
    assert csv_meta["item_count"] == 21
    assert pdf_meta["item_count"] == 21


def test_csv_formula_injection_protection():
    """Ensures formula injection characters (=, +, -, @, tab, CR) are sanitized in CSV cells."""
    sanitized_eq = CsvReportGenerator._sanitize_cell("=1+1")
    assert sanitized_eq == "'=1+1"

    sanitized_at = CsvReportGenerator._sanitize_cell("@SUM(A1:A10)")
    assert sanitized_at == "'@SUM(A1:A10)"

    sanitized_minus = CsvReportGenerator._sanitize_cell("-cmd")
    assert sanitized_minus == "'-cmd"

    sanitized_normal = CsvReportGenerator._sanitize_cell("OPEN")
    assert sanitized_normal == "OPEN"


def test_unsupported_format_returns_safe_validation_error():
    """Verifies that requesting an unsupported format returns HTTP 422 validation error."""
    client = TestClient(app)
    resp = client.post(
        "/api/reports/generate",
        json={
            "report_type": "tcp_scan",
            "report_format": "xml",  # Unsupported
            "source_id": "scan-183d6624",
        },
    )
    assert resp.status_code == 422


def test_cross_format_regression_scan_ede9b462():
    """Validates cross-format consistency, pandas compatibility, and localhost exposure accuracy using scan-ede9b462."""
    import base64
    import zlib
    import pandas as pd

    # 1. Retrieve the authentic scan record
    scan = ScannerService.get_scan("scan-ede9b462")
    assert scan is not None, "scan-ede9b462 must be present in ScannerService archive"
    assert scan.scan_id == "scan-ede9b462"
    assert scan.target == "127.0.0.1"
    assert scan.total_ports == 21
    assert scan.open_ports == 2
    assert scan.closed_ports == 0
    assert scan.filtered_ports == 0
    assert scan.no_response_ports == 19
    assert len(scan.results) == 21

    # 2. Collect Report Payload
    req = ReportGenerateRequest(
        report_type=ReportType.TCP_SCAN,
        report_format=ReportFormat.CSV,
        source_id="scan-ede9b462",
        title="TCP Connect Port Reconnaissance Audit — 127.0.0.1",
    )
    payload = DataCollector.collect_data(req)

    # 3. Verify CSV Generation & pandas compatibility
    csv_bytes = CsvReportGenerator.generate(payload)
    csv_text = csv_bytes.decode("utf-8")
    assert not csv_text.startswith("#"), "CSV must not have comment lines or metadata preamble"

    # Standard csv.reader check
    reader = csv.reader(io.StringIO(csv_text))
    csv_lines = list(reader)
    assert len(csv_lines) == 22, "Expected 1 header + 21 data rows = 22 total lines"
    assert csv_lines[0] == ["Port", "State", "Service", "Confidence", "Latency (ms)"]
    for row in csv_lines:
        assert len(row) == 5, "Every row must have exactly 5 columns"

    # pandas.read_csv() compatibility without any special options
    df = pd.read_csv(io.BytesIO(csv_bytes))
    assert len(df) == 21
    assert list(df.columns) == ["Port", "State", "Service", "Confidence", "Latency (ms)"]
    csv_open_count = int((df["State"] == "OPEN").sum())
    csv_closed_count = int((df["State"] == "CLOSED").sum())
    csv_filtered_count = int((df["State"] == "FILTERED").sum())
    csv_no_response_count = int((df["State"] == "NO_RESPONSE").sum())

    assert csv_open_count == 2
    assert csv_closed_count == 0
    assert csv_filtered_count == 0
    assert csv_no_response_count == 19

    # 4. Verify JSON Generation & Schema
    json_bytes = JsonReportGenerator.generate(payload, report_id="rpt-ede9b462")
    jdata = json.loads(json_bytes.decode("utf-8"))

    assert jdata["report_id"] == "rpt-ede9b462"
    assert jdata["source"]["target"] == "127.0.0.1"
    assert jdata["source"]["scan_id"] == "scan-ede9b462"

    # Summary metrics in JSON
    json_summary = jdata["summary"]
    assert json_summary["total_ports"] == 21
    assert json_summary["open"] == 2
    assert json_summary["closed"] == 0
    assert json_summary["filtered"] == 0
    assert json_summary["no_response"] == 19

    # Detailed findings counts
    findings = jdata["findings"]
    assert len(findings) == 21
    json_open_count = sum(1 for f in findings if f["state"] == "OPEN")
    json_closed_count = sum(1 for f in findings if f["state"] == "CLOSED")
    json_filtered_count = sum(1 for f in findings if f["state"] == "FILTERED")
    json_no_response_count = sum(1 for f in findings if f["state"] == "NO_RESPONSE")

    assert json_open_count == 2
    assert json_closed_count == 0
    assert json_filtered_count == 0
    assert json_no_response_count == 19

    # Localhost Exposure Assessment in JSON
    sec_posture = jdata["security_posture"]
    scope_target = jdata["scope_and_target"]

    assert sec_posture.get("Assessment Scope") == "LOCALHOST ONLY"
    assert sec_posture.get("Remote Network Exposure") == "NOT ASSESSED"
    assert sec_posture.get("Local Administrative-Service-Associated Ports Detected") == "Yes"
    assert "Administrative Services Exposed" not in sec_posture, "Must not claim Administrative Services Exposed for localhost"

    assert scope_target.get("Assessment Scope") == "LOCALHOST ONLY"
    assert scope_target.get("Remote Network Exposure") == "NOT ASSESSED"

    # 5. Verify PDF Generation & Wording
    pdf_bytes = PdfReportGenerator.generate(payload)
    assert pdf_bytes.startswith(b"%PDF"), "PDF must have standard %PDF signature"
    assert len(pdf_bytes) > 2000

    # Decompress streams to inspect text
    pdf_text_chunks = []
    parts = pdf_bytes.split(b"stream\n")
    for p in parts[1:]:
        idx = p.find(b"~>")
        if idx != -1:
            s = p[: idx + 2].strip()
            if not s.startswith(b"<~"):
                s = b"<~" + s
            try:
                decomp = zlib.decompress(base64.a85decode(s, adobe=True)).decode("latin1", errors="ignore")
                pdf_text_chunks.append(decomp)
            except Exception:
                pass

    full_pdf_text = " ".join(pdf_text_chunks)
    assert "127.0.0.1" in full_pdf_text
    assert "scan-ede9b462" in full_pdf_text
    assert "LOCALHOST ONLY" in full_pdf_text
    assert "NOT ASSESSED" in full_pdf_text
    assert "NO_RESPONSE" in full_pdf_text
    assert "Administrative Services Exposed: True" not in full_pdf_text

    # 6. Cross-Format Consistency Verification
    assert csv_open_count == json_open_count == scan.open_ports == 2
    assert csv_closed_count == json_closed_count == scan.closed_ports == 0
    assert csv_filtered_count == json_filtered_count == scan.filtered_ports == 0
    assert csv_no_response_count == json_no_response_count == scan.no_response_ports == 19
    assert len(df) == len(findings) == scan.total_ports == 21


def test_host_discovery_semantics_no_response_never_offline():
    """Verifies that non-responsive discovery targets are classified as NO_RESPONSE and never converted to OFFLINE."""
    disc = DiscoveryService.get_discovery_by_id("4da8dc89-cf98-4df6-b5a5-d49ecf5f447c")
    assert disc is not None
    assert disc.cidr == "192.168.29.0/24"
    assert disc.total_probed == 254
    assert disc.online_hosts_count == 6

    req = ReportGenerateRequest(
        report_type=ReportType.HOST_DISCOVERY,
        report_format=ReportFormat.JSON,
        source_id=disc.discovery_id,
    )
    payload = DataCollector.collect_data(req)

    # 1. Metric values
    metrics = payload.summary_metrics
    assert metrics["Total Probed"] == 254
    assert metrics["Online Hosts"] == 6
    assert metrics["No Response"] == 248
    assert metrics["Unreachable"] == 0
    assert "Offline Hosts" not in metrics
    assert "Offline" not in metrics

    # 2. Executive summary narrative
    exec_summary = payload.executive_summary
    assert "6 confirmed ONLINE (responsive)" in exec_summary
    assert "248 NO_RESPONSE (timed out)" in exec_summary
    assert "OFFLINE" not in exec_summary

    # 3. JSON serialization
    json_bytes = JsonReportGenerator.generate(payload)
    parsed = json.loads(json_bytes.decode("utf-8"))
    summary = parsed["summary"]
    assert summary["total_probed"] == 254
    assert summary["online"] == 6
    assert summary["no_response"] == 248
    assert summary["unreachable"] == 0
    assert "offline" not in summary

    # Ensure no finding has status 'OFFLINE'
    for item in parsed["findings"]:
        assert item["status"] in ("ONLINE", "NO_RESPONSE", "UNREACHABLE", "UNKNOWN")
        assert item["status"] != "OFFLINE"


def test_host_discovery_inventory_and_all_254_records_preservation():
    """Verifies that the PDF inventory truncation bug is resolved and all 254 records are preserved across PDF, CSV, and JSON."""
    disc = DiscoveryService.get_discovery_by_id("4da8dc89-cf98-4df6-b5a5-d49ecf5f447c")
    req = ReportGenerateRequest(
        report_type=ReportType.HOST_DISCOVERY,
        report_format=ReportFormat.PDF,
        source_id=disc.discovery_id,
    )
    payload = DataCollector.collect_data(req)

    # 1. Table rows preservation in payload
    assert len(payload.table_rows) == 254

    # 2. CSV generation & pandas parse
    csv_bytes = CsvReportGenerator.generate(payload)
    csv_text = csv_bytes.decode("utf-8")
    lines = [l for l in csv_text.splitlines() if l.strip()]
    assert len(lines) == 255  # 1 header + 254 rows
    reader = list(csv.reader(io.StringIO(csv_text)))
    assert len(reader) == 255
    assert reader[0] == ["IP Address", "Hostname", "Status", "MAC Address", "Latency (ms)", "Method"]

    try:
        import pandas as pd
        df = pd.read_csv(io.StringIO(csv_text))
        assert df.shape == (254, 6)
        csv_online_count = sum(df["Status"] == "ONLINE")
        csv_no_resp_count = sum(df["Status"] == "NO_RESPONSE")
        assert csv_online_count == 6
        assert csv_no_resp_count == 248
    except ImportError:
        pass

    # 3. JSON generation
    json_bytes = JsonReportGenerator.generate(payload)
    parsed = json.loads(json_bytes.decode("utf-8"))
    assert len(parsed["findings"]) == 254

    # 4. PDF generation and full stream decompression
    pdf_bytes = PdfReportGenerator.generate(payload)
    assert pdf_bytes.startswith(b"%PDF")

    # Decompress streams
    pdf_text_chunks = []
    pos = 0
    while True:
        s_idx = pdf_bytes.find(b"stream\n", pos)
        if s_idx == -1:
            s_idx = pdf_bytes.find(b"stream\r\n", pos)
            if s_idx == -1:
                break
            s_idx += 8
        else:
            s_idx += 7
        e_idx = pdf_bytes.find(b"endstream", s_idx)
        if e_idx == -1:
            break
        data = pdf_bytes[s_idx:e_idx].strip()
        if not data.startswith(b"<~"):
            data = b"<~" + data
        if not data.endswith(b"~>"):
            data = data + b"~>"
        try:
            decomp = zlib.decompress(base64.a85decode(data, adobe=True)).decode("latin1", errors="ignore")
            pdf_text_chunks.append(decomp)
        except Exception:
            pass
        pos = e_idx + 9

    full_pdf_text = " ".join(pdf_text_chunks)

    # Verify Section 4 responsive hosts present (including previously truncated .86, .156, .180)
    assert "192.168.29.1" in full_pdf_text
    assert "192.168.29.3" in full_pdf_text
    assert "192.168.29.59" in full_pdf_text
    assert "192.168.29.86" in full_pdf_text
    assert "192.168.29.156" in full_pdf_text
    assert "192.168.29.180" in full_pdf_text

    # Verify Status Definitions Callout Box
    assert "HOST STATUS DEFINITIONS & EVIDENCE CLASSIFICATION" in full_pdf_text
    assert "NO_RESPONSE" in full_pdf_text
    assert "UNREACHABLE" in full_pdf_text
    assert "assumed offline" in full_pdf_text

    # Verify Complete Subnet Inventory Appendix header and end of subnet
    assert "COMPLETE SUBNET ADDRESS INVENTORY" in full_pdf_text
    assert "192.168.29.254" in full_pdf_text

    # Verify OFFLINE is not present
    assert "OFFLINE" not in full_pdf_text


def test_host_discovery_context_aware_recommendations():
    """Verifies that discovery recommendations are context-aware (SOHO Wi-Fi vs Enterprise vs Loopback)."""
    # 1. SOHO / Home Wi-Fi (192.168.29.0/24)
    recs_soho = DataCollector._generate_discovery_recommendations(
        cidr="192.168.29.0/24",
        total_probed=254,
        online_count=6,
        no_response_count=248,
        unreachable_count=0,
        method="AUTO",
    )
    soho_text = " ".join(recs_soho)
    assert "[Confirmed Finding]" in soho_text
    assert "[General Hardening]" in soho_text
    assert "WPA3-Personal or WPA2-AES" in soho_text
    assert "Guest Network" in soho_text
    assert "DHCP clients" in soho_text
    assert "802.1X" not in soho_text, "Enterprise 802.1X must not be recommended on SOHO Wi-Fi"
    assert "VLAN" not in soho_text, "Enterprise VLAN switching must not be recommended on SOHO Wi-Fi"

    # 2. Enterprise Network (10.0.0.0/24)
    recs_ent = DataCollector._generate_discovery_recommendations(
        cidr="10.0.0.0/24",
        total_probed=254,
        online_count=12,
        no_response_count=242,
        unreachable_count=0,
        method="AUTO",
    )
    ent_text = " ".join(recs_ent)
    assert "802.1X" in ent_text
    assert "VLAN" in ent_text
    assert "CMDB" in ent_text

    # 3. Loopback (127.0.0.1/32)
    recs_loop = DataCollector._generate_discovery_recommendations(
        cidr="127.0.0.1/32",
        total_probed=1,
        online_count=1,
        no_response_count=0,
        unreachable_count=0,
        method="AUTO",
    )
    loop_text = " ".join(recs_loop)
    assert "Loopback subnet" in loop_text
    assert "127.0.0.1" in loop_text


def test_host_discovery_session_digest_integrity():
    """Verifies deterministic SHA-256 session digest computation and integrity sign-off."""
    disc = DiscoveryService.get_discovery_by_id("4da8dc89-cf98-4df6-b5a5-d49ecf5f447c")
    req = ReportGenerateRequest(
        report_type=ReportType.HOST_DISCOVERY,
        report_format=ReportFormat.JSON,
        source_id=disc.discovery_id,
    )
    payload = DataCollector.collect_data(req)

    # 1. Deterministic computation
    digest1 = DataCollector.compute_session_digest(payload)
    digest2 = DataCollector.compute_session_digest(payload)
    assert digest1 == digest2
    assert len(digest1) == 64  # Hex SHA-256

    # 2. Tamper sensitivity
    modified_payload = ReportPayload(
        title=payload.title,
        report_type=payload.report_type,
        source_id=payload.source_id,
        generated_at=payload.generated_at,
        executive_summary=payload.executive_summary,
        scope_info=payload.scope_info,
        summary_metrics={**payload.summary_metrics, "Online Hosts": 99},
        table_headers=payload.table_headers,
        table_rows=payload.table_rows,
        recommendations=payload.recommendations,
    )
    digest_tampered = DataCollector.compute_session_digest(modified_payload)
    assert digest_tampered != digest1

    # 3. Included in JSON export
    json_bytes = JsonReportGenerator.generate(payload)
    parsed = json.loads(json_bytes.decode("utf-8"))
    assert "integrity" in parsed
    assert parsed["integrity"]["algorithm"] == "SHA-256"
    assert parsed["integrity"]["session_digest"] == f"sha256:{digest1}"
    assert parsed["integrity"]["verified"] is True
    assert parsed["integrity"]["status"] == "PASSED"
    assert "scope_of_protection" in parsed["integrity"]

    # 4. JSON Report verification & tampering detection
    is_valid, comp, exp = DataCollector.verify_json_report(parsed)
    assert is_valid is True
    assert comp == exp == digest1

    # Tamper with JSON metric
    parsed_tampered = json.loads(json_bytes.decode("utf-8"))
    parsed_tampered["metrics"]["Online Hosts"] = 999
    is_valid_tampered, comp_t, _ = DataCollector.verify_json_report(parsed_tampered)
    assert is_valid_tampered is False
    assert comp_t != digest1


def test_stopped_session_immutable_duration():
    """Verifies that once a capture session is stopped, observation duration is permanently immutable."""
    engine = LiveCaptureEngine(session_id="cap-duration-test", interface_name="Wi-Fi", interface_id="test-iface")
    engine.status = "CAPTURING"
    engine.started_at = datetime.now(timezone.utc)
    engine.analytics_engine.created_at = engine.started_at
    CaptureManager.register_test_engine(engine)

    # Stop session with fixed timestamp
    stop_time = datetime.now(timezone.utc)
    engine.status = "STOPPED"
    engine.stopped_at = stop_time
    engine.analytics_engine.set_status("STOPPED", stopped_at=stop_time)

    overview1 = engine.analytics_engine.get_overview()
    stats1 = engine.get_statistics()
    assert overview1.duration_seconds == stats1.capture_duration_seconds

    # Simulate passage of time and ensure duration does not tick up
    import time
    time.sleep(0.05)

    overview2 = engine.analytics_engine.get_overview()
    stats2 = engine.get_statistics()
    assert overview2.duration_seconds == overview1.duration_seconds
    assert stats2.capture_duration_seconds == stats1.capture_duration_seconds


def test_cross_format_session_digest_and_duration_consistency():
    """Verifies that PDF, CSV, and JSON exports for the same stopped session produce identical digests and durations."""
    engine = LiveCaptureEngine(session_id="cap-1b027bdbe612", interface_name="Wi-Fi", interface_id="test-iface")
    engine.session_id = "cap-1b027bdbe612"
    engine.status = "STOPPED"
    t0 = datetime(2026, 11, 9, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 9, 10, 3, 24, 430000, tzinfo=timezone.utc)  # 204.43s
    engine.started_at = t0
    engine.stopped_at = t1
    engine.analytics_engine.created_at = t0
    engine.analytics_engine.set_status("STOPPED", stopped_at=t1)
    CaptureManager.register_test_engine(engine)

    req_pdf = ReportGenerateRequest(
        report_type=ReportType.TRAFFIC_ANALYTICS,
        report_format=ReportFormat.PDF,
        source_id="cap-1b027bdbe612",
    )
    req_json = ReportGenerateRequest(
        report_type=ReportType.TRAFFIC_ANALYTICS,
        report_format=ReportFormat.JSON,
        source_id="cap-1b027bdbe612",
    )
    req_csv = ReportGenerateRequest(
        report_type=ReportType.TRAFFIC_ANALYTICS,
        report_format=ReportFormat.CSV,
        source_id="cap-1b027bdbe612",
    )

    payload_pdf = DataCollector.collect_data(req_pdf)
    payload_json = DataCollector.collect_data(req_json)
    payload_csv = DataCollector.collect_data(req_csv)

    # 1. Observation duration is identical across all three formats
    assert payload_pdf.scope_info["Observation Duration"] == "204.43 seconds"
    assert payload_json.scope_info["Observation Duration"] == "204.43 seconds"
    assert payload_csv.scope_info["Observation Duration"] == "204.43 seconds"

    # 2. Session digest is 100% identical and deterministic across formats
    assert payload_pdf.session_digest == payload_json.session_digest == payload_csv.session_digest
    assert len(payload_pdf.session_digest) == 64

    # 3. Dynamic verification succeeds for all payloads
    assert DataCollector.verify_session_integrity(payload_pdf)[0] is True
    assert DataCollector.verify_session_integrity(payload_json)[0] is True
    assert DataCollector.verify_session_integrity(payload_csv)[0] is True


def test_dns_metric_consistency_across_overview_and_dns():
    """Verifies that DNS query counts and packet counts are consistent and explicitly labeled."""
    engine = LiveCaptureEngine(session_id="cap-dns-test", interface_name="Wi-Fi", interface_id="test-iface")
    engine.session_id = "cap-dns-test"
    engine.status = "CAPTURING"
    engine.started_at = datetime.now(timezone.utc)
    engine.analytics_engine.created_at = engine.started_at
    CaptureManager.register_test_engine(engine)

    # Feed 3 queries and 2 responses
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    for i in range(3):
        pkt = IP(src="192.168.29.59", dst="192.168.29.1")/UDP(sport=50000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=f"test{i}.com"))
        meta = PacketMetadataItem(
            packet_id=i+1,
            timestamp=datetime.now(timezone.utc),
            src_ip="192.168.29.59",
            dst_ip="192.168.29.1",
            src_port=50000+i,
            dst_port=53,
            protocol="DNS",
            length=len(pkt),
            dns_summary=f"Query: test{i}.com",
            interface="Wi-Fi",
            session_id="cap-dns-test",
        )
        engine.analytics_engine.process_packet(meta, raw_packet=pkt)

    for i in range(2):
        pkt = IP(src="192.168.29.1", dst="192.168.29.59")/UDP(sport=53, dport=50000+i)/DNS(qr=1, rcode=0, qd=DNSQR(qname=f"test{i}.com"), an=DNSRR(rrname=f"test{i}.com", rdata="1.2.3.4"))
        meta = PacketMetadataItem(
            packet_id=i+4,
            timestamp=datetime.now(timezone.utc),
            src_ip="192.168.29.1",
            dst_ip="192.168.29.59",
            src_port=53,
            dst_port=50000+i,
            protocol="DNS",
            length=len(pkt),
            dns_summary="Response (rcode=0)",
            interface="Wi-Fi",
            session_id="cap-dns-test",
        )
        engine.analytics_engine.process_packet(meta, raw_packet=pkt)

    overview = engine.analytics_engine.get_overview()
    dns_analytics = engine.analytics_engine.get_dns()

    # Exact semantic consistency
    assert overview.dns_queries_count == 3
    assert dns_analytics.total_queries == 3
    assert dns_analytics.total_responses == 2
    assert dns_analytics.total_dns_packets == 5

    # Report collection consistency
    req = ReportGenerateRequest(
        report_type=ReportType.TRAFFIC_ANALYTICS,
        report_format=ReportFormat.JSON,
        source_id="cap-dns-test",
    )
    payload = DataCollector.collect_data(req)
    assert payload.summary_metrics["DNS Queries"] == 3
    assert payload.summary_metrics["DNS Responses"] == 2
    assert payload.summary_metrics["Total DNS Frames"] == 5


