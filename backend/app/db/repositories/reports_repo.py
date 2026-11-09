import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from backend.app.db.session import get_db
from backend.app.schemas.reports import ReportFormat, ReportMetadataItem, ReportType


class ReportsRepository:
    """SQLite repository for persisting and querying generated report metadata."""

    @classmethod
    def save_report(
        cls,
        report: ReportMetadataItem,
        session_digest: str = "",
        raw_payload_json: Optional[str] = None,
    ) -> None:
        """Persists a generated report metadata entry."""
        with get_db() as conn:
            cursor = conn.cursor()
            created_iso = report.created_at.isoformat() if report.created_at else datetime.now(timezone.utc).isoformat()
            rtype_str = report.report_type.value if hasattr(report.report_type, "value") else str(report.report_type)
            rfmt_str = report.report_format.value if hasattr(report.report_format, "value") else str(report.report_format)

            cursor.execute(
                """
                INSERT OR REPLACE INTO reports (
                    report_id, title, report_type, report_format, source_id,
                    created_at, file_size_bytes, item_count, filename, session_digest, raw_payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.report_id,
                    report.title,
                    rtype_str,
                    rfmt_str,
                    report.source_id or "",
                    created_iso,
                    report.file_size_bytes,
                    report.item_count,
                    report.filename,
                    session_digest,
                    raw_payload_json,
                ),
            )

    @classmethod
    def get_report(cls, report_id: str) -> Optional[ReportMetadataItem]:
        """Retrieves report metadata by report_id or filename."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM reports WHERE report_id = ? OR filename = ?",
                (report_id, report_id),
            )
            row = cursor.fetchone()
            if not row:
                return None

            return ReportMetadataItem(
                report_id=row["report_id"],
                title=row["title"],
                report_type=ReportType(row["report_type"]),
                report_format=ReportFormat(row["report_format"]),
                source_id=row["source_id"] or None,
                created_at=datetime.fromisoformat(row["created_at"]),
                file_size_bytes=row["file_size_bytes"],
                item_count=row["item_count"],
                filename=row["filename"],
                download_url=f"/api/reports/{row['report_id']}/download",
            )

    @classmethod
    def list_reports(
        cls, limit: int = 50, report_type: Optional[str] = None
    ) -> List[ReportMetadataItem]:
        """Lists generated reports ordered by creation date."""
        with get_db() as conn:
            cursor = conn.cursor()
            if report_type:
                cursor.execute(
                    """
                    SELECT * FROM reports
                    WHERE report_type = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (report_type, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM reports
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            items: List[ReportMetadataItem] = []
            for r in rows:
                try:
                    items.append(
                        ReportMetadataItem(
                            report_id=r["report_id"],
                            title=r["title"],
                            report_type=ReportType(r["report_type"]),
                            report_format=ReportFormat(r["report_format"]),
                            source_id=r["source_id"] or None,
                            created_at=datetime.fromisoformat(r["created_at"]),
                            file_size_bytes=r["file_size_bytes"],
                            item_count=r["item_count"],
                            filename=r["filename"],
                            download_url=f"/api/reports/{r['report_id']}/download",
                        )
                    )
                except Exception:
                    continue
            return items

    @classmethod
    def sync_from_disk(cls, reports_dir: Path) -> int:
        """Self-healing scanner: ingests existing report files from the reports directory into SQLite."""
        if not reports_dir.exists():
            return 0

        synced = 0
        with get_db() as conn:
            cursor = conn.cursor()
            for f in reports_dir.glob("ani_*.*"):
                if f.suffix.lower() not in (".pdf", ".csv", ".json"):
                    continue

                filename = f.name
                cursor.execute("SELECT report_id FROM reports WHERE filename = ?", (filename,))
                if cursor.fetchone():
                    continue  # Already indexed

                # Parse filename pattern: ani_<type>_<source_id>_<date>_<time>.<ext>
                parts = filename.split("_")
                ext = f.suffix.lower().lstrip(".")
                rtype_str = "tcp_scan"
                source_id = ""

                if len(parts) >= 3:
                    if parts[1] == "tcp" and parts[2] == "scan":
                        rtype_str = "tcp_scan"
                        source_id = parts[3] if len(parts) > 3 else ""
                    elif parts[1] == "udp" and parts[2] == "scan":
                        rtype_str = "udp_scan"
                        source_id = parts[3] if len(parts) > 3 else ""
                    elif parts[1] == "host" and parts[2] == "discovery":
                        rtype_str = "host_discovery"
                        source_id = parts[3] if len(parts) > 3 else ""
                    elif parts[1] == "traffic" and parts[2] == "analytics":
                        rtype_str = "traffic_analytics"
                        source_id = parts[3] if len(parts) > 3 else ""
                    elif parts[1] == "security" and parts[2] == "events":
                        rtype_str = "security_events"
                        source_id = parts[3] if len(parts) > 3 else ""
                    elif parts[1] == "system" and parts[2] == "baseline":
                        rtype_str = "system_baseline"
                        source_id = parts[3] if len(parts) > 3 else ""

                import hashlib
                report_id = f"rpt-{hashlib.sha256(filename.encode()).hexdigest()[:12]}"
                file_size = f.stat().st_size
                created_iso = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat()
                title = f"{rtype_str.replace('_', ' ').title()} ({ext.upper()})"

                try:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO reports (
                            report_id, title, report_type, report_format, source_id,
                            created_at, file_size_bytes, item_count, filename, session_digest
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            report_id,
                            title,
                            rtype_str,
                            ext,
                            source_id,
                            created_iso,
                            file_size,
                            1,
                            filename,
                            "self-healed",
                        ),
                    )
                    if cursor.rowcount > 0:
                        synced += 1
                except Exception:
                    pass
        return synced

