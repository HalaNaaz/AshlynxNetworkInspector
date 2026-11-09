import os
from datetime import datetime, timezone
from pathlib import Path
import pytest

from backend.app.db.migrations import init_db
from backend.app.db.session import get_db_connection, get_db
from backend.app.db.repositories.scans_repo import ScansRepository
from backend.app.db.repositories.discovery_repo import DiscoveryRepository
from backend.app.db.repositories.capture_repo import CaptureRepository
from backend.app.db.repositories.reports_repo import ReportsRepository
from backend.app.schemas.scanner import PortScanResultItem, ScanExecutionResponse
from backend.app.schemas.discovery import DiscoveredHostItem, HostDiscoveryResponse
from backend.app.schemas.capture import CaptureSessionResponse, CaptureStatistics
from backend.app.schemas.reports import ReportFormat, ReportMetadataItem, ReportType
from backend.app.services.scanner_service import ScannerService
from backend.app.services.discovery_service import DiscoveryService
from backend.app.reports.report_manager import ReportManager


def test_sqlite_db_initialization(tmp_path):
    """Verifies SQLite tables and indexes are created with WAL mode and foreign keys enabled."""
    test_db = tmp_path / "test_ani.db"
    conn = get_db_connection(test_db)
    init_db(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    tables = [r[0] for r in cursor.fetchall()]

    expected_tables = [
        "analytics_snapshots",
        "app_settings",
        "capture_sessions",
        "connection_flows",
        "discovered_hosts",
        "dns_records",
        "host_discoveries",
        "interface_snapshots",
        "reports",
        "scan_findings",
        "scans",
        "security_events",
    ]
    for tbl in expected_tables:
        assert tbl in tables, f"Expected table '{tbl}' was not created."

    # Check WAL pragma
    cursor.execute("PRAGMA journal_mode;")
    mode = cursor.fetchone()[0]
    assert mode.upper() == "WAL"

    conn.close()


def test_scan_repository_persistence():
    """Verifies that ScanExecutionResponse and individual findings persist to and load from SQLite."""
    now = datetime.now(timezone.utc)
    scan_id = "test-scan-persist-01"
    finding = PortScanResultItem(
        port=80,
        protocol="TCP",
        state="OPEN",
        service="HTTP",
        service_confidence="inferred",
        response_time_ms=2.45,
    )
    scan = ScanExecutionResponse(
        scan_id=scan_id,
        target="127.0.0.1",
        scan_type="TCP_CONNECT",
        status="completed",
        started_at=now,
        completed_at=now,
        duration_seconds=0.15,
        total_ports=1,
        open_ports=1,
        closed_ports=0,
        filtered_ports=0,
        no_response_ports=0,
        filtered_or_unknown_ports=0,
        results=[finding],
    )

    # Save to SQLite
    ScansRepository.save_scan(scan)

    # Load from SQLite
    loaded = ScansRepository.get_scan(scan_id)
    assert loaded is not None
    assert loaded.scan_id == scan_id
    assert loaded.target == "127.0.0.1"
    assert loaded.total_ports == 1
    assert loaded.open_ports == 1
    assert len(loaded.results) == 1
    assert loaded.results[0].port == 80
    assert loaded.results[0].state == "OPEN"

    # Query history list
    history = ScansRepository.list_history(limit=10)
    assert any(h.scan_id == scan_id for h in history)

    # Service layer integration
    ScannerService._scans.pop(scan_id, None)  # Evict from in-memory cache
    service_loaded = ScannerService.get_scan(scan_id)
    assert service_loaded is not None
    assert service_loaded.scan_id == scan_id


def test_discovery_repository_persistence():
    """Verifies that HostDiscoveryResponse and DiscoveredHostItem records persist to and load from SQLite."""
    now = datetime.now(timezone.utc)
    disc_id = "test-disc-persist-01"
    host = DiscoveredHostItem(
        ip_address="192.168.1.1",
        hostname="gateway.local",
        hostname_source="DNS_PTR",
        discovery_method="ARP",
        status="ONLINE",
        response_time_ms=1.23,
        mac_address="00:11:22:33:44:55",
        neighbor_state="REACHABLE",
        first_seen=now,
    )
    discovery = HostDiscoveryResponse(
        discovery_id=disc_id,
        cidr="192.168.1.0/24",
        method="AUTO",
        status="completed",
        started_at=now,
        completed_at=now,
        duration_seconds=1.5,
        total_probed=1,
        online_hosts_count=1,
        hosts=[host],
    )

    DiscoveryRepository.save_discovery(discovery)

    # Load from SQLite
    loaded = DiscoveryRepository.get_discovery(disc_id)
    assert loaded is not None
    assert loaded.discovery_id == disc_id
    assert loaded.cidr == "192.168.1.0/24"
    assert loaded.online_hosts_count == 1
    assert len(loaded.hosts) == 1
    assert loaded.hosts[0].ip_address == "192.168.1.1"
    assert loaded.hosts[0].mac_address == "00:11:22:33:44:55"

    # Service layer integration with cache eviction
    DiscoveryService._discoveries.pop(disc_id, None)
    service_loaded = DiscoveryService.get_discovery_by_id(disc_id)
    assert service_loaded is not None
    assert service_loaded.discovery_id == disc_id


def test_reports_repository_and_self_healing_sync(tmp_path):
    """Verifies that ReportMetadataItem persists to SQLite and self-healing ingests files on disk."""
    now = datetime.now(timezone.utc)
    report_id = "rpt-pers-001"
    filename = "ani_tcp_scan_test-persist.pdf"

    meta = ReportMetadataItem(
        report_id=report_id,
        title="Test Persistent Report",
        report_type=ReportType.TCP_SCAN,
        report_format=ReportFormat.PDF,
        source_id="scan-xyz",
        created_at=now,
        file_size_bytes=1024,
        item_count=5,
        filename=filename,
        download_url=f"/api/reports/{report_id}/download",
    )

    ReportsRepository.save_report(meta, session_digest="testdigest123")

    loaded = ReportsRepository.get_report(report_id)
    assert loaded is not None
    assert loaded.report_id == report_id
    assert loaded.filename == filename

    # Test self-healing sync from mock disk directory
    import uuid
    mock_reports_dir = tmp_path / "mock_reports"
    mock_reports_dir.mkdir()
    unique_fn = f"ani_udp_scan_source_{uuid.uuid4().hex[:8]}.json"
    mock_file = mock_reports_dir / unique_fn
    mock_file.write_text('{"report_type": "udp_scan"}', encoding="utf-8")

    synced = ReportsRepository.sync_from_disk(mock_reports_dir)
    assert synced == 1

    # Verify self-healed report is queryable
    healed = ReportsRepository.get_report(mock_file.name)
    assert healed is not None
    assert healed.filename == mock_file.name

