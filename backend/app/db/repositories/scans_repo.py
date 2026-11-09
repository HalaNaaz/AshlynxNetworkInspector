import sqlite3
from datetime import datetime, timezone
from typing import List, Optional, Union

from backend.app.db.session import get_db
from backend.app.schemas.scanner import (
    PortScanResultItem,
    ScanExecutionResponse,
    ScanHistoryItem,
    UdpScanExecutionResponse,
    UdpScanResultItem,
)


class ScansRepository:
    """SQLite repository for persisting and querying TCP and UDP scan results."""

    @classmethod
    def save_scan(
        cls,
        scan: Union[ScanExecutionResponse, UdpScanExecutionResponse],
        concurrency: int = 100,
        timeout: float = 1.0,
    ) -> None:
        """Persists a completed scan execution and its individual port findings."""
        with get_db() as conn:
            cursor = conn.cursor()

            # Determine counts
            filtered = getattr(scan, "filtered_ports", 0)
            no_resp = getattr(scan, "no_response_ports", 0)
            if hasattr(scan, "open_or_filtered_ports"):
                # UDP open_or_filtered maps to filtered
                filtered = scan.open_or_filtered_ports

            started_iso = scan.started_at.isoformat() if scan.started_at else datetime.now(timezone.utc).isoformat()
            completed_iso = scan.completed_at.isoformat() if scan.completed_at else datetime.now(timezone.utc).isoformat()

            cursor.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, scan_type, target, status, started_at, completed_at,
                    duration_seconds, total_ports, open_ports, closed_ports,
                    filtered_ports, no_response_ports, concurrency, timeout_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.scan_id,
                    scan.scan_type,
                    scan.target,
                    scan.status,
                    started_iso,
                    completed_iso,
                    scan.duration_seconds,
                    scan.total_ports,
                    scan.open_ports,
                    scan.closed_ports,
                    filtered,
                    no_resp,
                    concurrency,
                    timeout,
                ),
            )

            # Insert findings
            cursor.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan.scan_id,))
            for item in scan.results:
                cursor.execute(
                    """
                    INSERT INTO scan_findings (
                        scan_id, port, protocol, state, service_name, latency_ms
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan.scan_id,
                        item.port,
                        item.protocol,
                        item.state,
                        item.service,
                        item.response_time_ms,
                    ),
                )

    @classmethod
    def get_scan(cls, scan_id: str) -> Optional[Union[ScanExecutionResponse, UdpScanExecutionResponse]]:
        """Retrieves a scan execution by unique ID."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None

            cursor.execute(
                "SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY port ASC",
                (scan_id,),
            )
            finding_rows = cursor.fetchall()

            scan_type = row["scan_type"]
            started_at = datetime.fromisoformat(row["started_at"])
            completed_at = datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else started_at

            if scan_type == "UDP_DGRAM":
                udp_results = [
                    UdpScanResultItem(
                        port=f["port"],
                        protocol=f["protocol"],
                        state=f["state"],
                        service=f["service_name"] or "unknown",
                        service_confidence="inferred",
                        response_time_ms=f["latency_ms"] or 0.0,
                    )
                    for f in finding_rows
                ]
                return UdpScanExecutionResponse(
                    scan_id=row["scan_id"],
                    target=row["target"],
                    scan_type=scan_type,
                    status=row["status"],
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=row["duration_seconds"],
                    total_ports=row["total_ports"],
                    open_ports=row["open_ports"],
                    closed_ports=row["closed_ports"],
                    open_or_filtered_ports=row["filtered_ports"],
                    unknown_ports=row["no_response_ports"],
                    results=udp_results,
                )
            else:
                tcp_results = [
                    PortScanResultItem(
                        port=f["port"],
                        protocol=f["protocol"],
                        state=f["state"],
                        service=f["service_name"] or "unknown",
                        service_confidence="inferred",
                        response_time_ms=f["latency_ms"] or 0.0,
                    )
                    for f in finding_rows
                ]
                return ScanExecutionResponse(
                    scan_id=row["scan_id"],
                    target=row["target"],
                    scan_type=scan_type,
                    status=row["status"],
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=row["duration_seconds"],
                    total_ports=row["total_ports"],
                    open_ports=row["open_ports"],
                    closed_ports=row["closed_ports"],
                    filtered_ports=row["filtered_ports"],
                    no_response_ports=row["no_response_ports"],
                    filtered_or_unknown_ports=row["filtered_ports"] + row["no_response_ports"],
                    results=tcp_results,
                )

    @classmethod
    def list_history(cls, limit: int = 50, scan_type: Optional[str] = None) -> List[ScanHistoryItem]:
        """Returns recent scan history summaries from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            if scan_type:
                cursor.execute(
                    """
                    SELECT scan_id, target, scan_type, started_at, duration_seconds, total_ports, open_ports, status
                    FROM scans
                    WHERE scan_type = ?
                    ORDER BY started_at DESC
                    LIMIT ?
                    """,
                    (scan_type, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT scan_id, target, scan_type, started_at, duration_seconds, total_ports, open_ports, status
                    FROM scans
                    ORDER BY started_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            return [
                ScanHistoryItem(
                    scan_id=r["scan_id"],
                    target=r["target"],
                    scan_type=r["scan_type"],
                    started_at=datetime.fromisoformat(r["started_at"]),
                    duration_seconds=r["duration_seconds"],
                    total_ports=r["total_ports"],
                    open_ports=r["open_ports"],
                    status=r["status"],
                )
                for r in rows
            ]

    @classmethod
    def get_latest_scan(cls, scan_type: Optional[str] = None) -> Optional[Union[ScanExecutionResponse, UdpScanExecutionResponse]]:
        """Returns the most recent scan execution from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            if scan_type:
                cursor.execute(
                    "SELECT scan_id FROM scans WHERE scan_type = ? ORDER BY started_at DESC LIMIT 1",
                    (scan_type,),
                )
            else:
                cursor.execute("SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return None
            return cls.get_scan(row["scan_id"])

