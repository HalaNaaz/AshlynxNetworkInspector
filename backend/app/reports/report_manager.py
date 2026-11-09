import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.reports.csv_generator import CsvReportGenerator
from backend.app.reports.data_collector import DataCollector, ReportPayload
from backend.app.reports.json_generator import JsonReportGenerator
from backend.app.reports.pdf_generator import PdfReportGenerator
from backend.app.schemas.reports import (
    ReportFormat,
    ReportGenerateRequest,
    ReportMetadataItem,
    ReportPreviewResponse,
    ReportSourceOption,
    ReportType,
)

SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")
MAX_STORED_REPORTS = 50


class ReportManager:
    """Thread-safe report orchestration, bounded storage lifecycle, and access control."""

    _lock = threading.Lock()
    _metadata: Dict[str, ReportMetadataItem] = {}
    _payload_cache: Dict[str, ReportPayload] = {}

    @classmethod
    def get_storage_dir(cls) -> Path:
        """Resolves and ensures local report storage directory."""
        reports_dir = Path(__file__).resolve().parent.parent.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        return reports_dir

    @classmethod
    def sanitize_id(cls, identifier: str) -> str:
        """Validates that an identifier contains only alphanumeric, dash, and underscore."""
        clean = identifier.strip()
        if not SAFE_ID_REGEX.match(clean):
            raise ValueError(f"Invalid identifier syntax: '{identifier}'. Special characters not allowed.")
        return clean

    @classmethod
    def get_safe_filepath(cls, filename: str) -> Path:
        """Resolves a filepath and validates against path traversal attacks."""
        if ".." in filename or "/" in filename or "\\" in filename:
            raise PermissionError("Path traversal attack detected and blocked.")

        base_name = os.path.basename(filename)
        storage_dir = cls.get_storage_dir().resolve()
        target_path = (storage_dir / base_name).resolve()

        if storage_dir != target_path.parent:
            raise PermissionError("Path traversal attack detected and blocked.")
        return target_path

    @classmethod
    def list_sources(cls) -> List[ReportSourceOption]:
        """Returns available telemetry sources across all active/historical engines."""
        return DataCollector.list_available_sources()

    @classmethod
    def generate_report(cls, request: ReportGenerateRequest) -> ReportMetadataItem:
        """Generates document according to specification, writes to disk, and indexes metadata."""
        with cls._lock:
            # 1. Collect structured data
            payload = DataCollector.collect_data(request)

            report_id = f"rpt-{uuid.uuid4().hex[:10]}"
            ext = request.report_format.value
            # Filename strictly conforms to: ani_<report_type>_<report_id>.<ext>
            filename = f"ani_{request.report_type.value}_{report_id}.{ext}"

            # 2. Serialize according to format
            if request.report_format == ReportFormat.PDF:
                file_bytes = PdfReportGenerator.generate(payload)
            elif request.report_format == ReportFormat.CSV:
                file_bytes = CsvReportGenerator.generate(payload)
            elif request.report_format == ReportFormat.JSON:
                file_bytes = JsonReportGenerator.generate(payload, report_id, request.include_raw_details)
            else:
                raise ValueError(f"Unsupported format: {request.report_format}")

            # 3. Enforce maximum capacity (Purge oldest if exceeding bounds)
            if len(cls._metadata) >= MAX_STORED_REPORTS:
                oldest_id = next(iter(cls._metadata))
                cls._delete_internal(oldest_id)

            # 4. Save to filesystem
            target_path = cls.get_safe_filepath(filename)
            with open(target_path, "wb") as f:
                f.write(file_bytes)

            file_size = len(file_bytes)
            item_count = len(payload.table_rows)

            meta = ReportMetadataItem(
                report_id=report_id,
                title=payload.title,
                report_type=request.report_type,
                report_format=request.report_format,
                source_id=payload.source_id,
                created_at=datetime.now(timezone.utc),
                file_size_bytes=file_size,
                item_count=item_count,
                filename=filename,
                download_url=f"/api/reports/{report_id}/download",
            )

            cls._metadata[report_id] = meta
            cls._payload_cache[report_id] = payload

            # Persist to SQLite
            try:
                from backend.app.db.repositories.reports_repo import ReportsRepository
                ReportsRepository.save_report(meta, session_digest=payload.session_digest)
            except Exception as exc:
                logger.warning("Could not persist report metadata %s to SQLite: %s", report_id, exc)

            logger.info(
                "Generated %s report %s (%s, %d bytes) saved to %s",
                request.report_format.value.upper(),
                report_id,
                request.report_type.value,
                file_size,
                filename,
            )

            return meta

    @classmethod
    def get_report_metadata(cls, report_id: str) -> Optional[ReportMetadataItem]:
        """Retrieves metadata record for a given report ID from memory or SQLite."""
        clean_id = cls.sanitize_id(report_id)
        if clean_id in cls._metadata:
            return cls._metadata[clean_id]

        try:
            from backend.app.db.repositories.reports_repo import ReportsRepository
            rep = ReportsRepository.get_report(clean_id)
            if rep:
                cls._metadata[clean_id] = rep
                return rep
        except Exception:
            pass
        return None

    @classmethod
    def get_report_file(cls, report_id: str) -> Tuple[Path, str, str]:
        """Resolves path, mime type, and safe download filename for HTTP file streaming."""
        clean_id = cls.sanitize_id(report_id)
        meta = cls.get_report_metadata(clean_id)
        if not meta:
            raise FileNotFoundError(f"Report ID '{report_id}' was not found in audit registry.")

        file_path = cls.get_safe_filepath(meta.filename)
        if not file_path.exists():
            raise FileNotFoundError(f"Report file '{meta.filename}' missing from physical disk.")

        mime_map = {
            ReportFormat.PDF: "application/pdf",
            ReportFormat.CSV: "text/csv; charset=utf-8",
            ReportFormat.JSON: "application/json",
        }
        mime_type = mime_map.get(meta.report_format, "application/octet-stream")
        return file_path, mime_type, meta.filename

    @classmethod
    def get_preview(cls, report_id: str) -> ReportPreviewResponse:
        """Returns structured preview payload for interactive UI inspection."""
        clean_id = cls.sanitize_id(report_id)
        meta = cls.get_report_metadata(clean_id)
        if not meta:
            raise FileNotFoundError(f"Report ID '{report_id}' not found.")

        payload = cls._payload_cache.get(clean_id)
        if not payload:
            # Fallback preview if cache was evicted
            return ReportPreviewResponse(
                report_id=meta.report_id,
                title=meta.title,
                report_type=meta.report_type,
                report_format=meta.report_format,
                created_at=meta.created_at,
                summary={"Message": "Full payload preview archived; file ready for download."},
                headers=["Report ID", "Format", "Size"],
                preview_rows=[[meta.report_id, meta.report_format.value, f"{meta.file_size_bytes} bytes"]],
                total_rows=1,
            )

        preview_rows = payload.table_rows[:10]  # top 10 preview rows

        json_preview: Optional[Dict[str, Any]] = None
        raw_content: Optional[str] = None

        if meta.report_format == ReportFormat.JSON:
            file_path = cls.get_safe_filepath(meta.filename)
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        raw_content = f.read()
                        json_preview = json.loads(raw_content)
                except Exception:
                    pass
            if not json_preview:
                raw_bytes = JsonReportGenerator.generate(payload, meta.report_id)
                raw_content = raw_bytes.decode("utf-8")
                json_preview = json.loads(raw_content)
        elif meta.report_format == ReportFormat.CSV:
            file_path = cls.get_safe_filepath(meta.filename)
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        raw_content = f.read()
                except Exception:
                    pass
            if not raw_content:
                raw_content = CsvReportGenerator.generate(payload).decode("utf-8")

        return ReportPreviewResponse(
            report_id=meta.report_id,
            title=meta.title,
            report_type=meta.report_type,
            report_format=meta.report_format,
            created_at=meta.created_at,
            summary={
                "Summary": payload.executive_summary,
                **payload.summary_metrics,
            },
            headers=payload.table_headers,
            preview_rows=preview_rows,
            total_rows=len(payload.table_rows),
            json_preview=json_preview,
            raw_content=raw_content,
        )

    @classmethod
    def list_history(cls, limit: int = 50) -> List[ReportMetadataItem]:
        """Lists reports in reverse chronological order from SQLite, falling back to memory."""
        try:
            from backend.app.db.repositories.reports_repo import ReportsRepository
            db_reports = ReportsRepository.list_reports(limit=limit)
            if db_reports:
                return db_reports
        except Exception:
            pass

        with cls._lock:
            items = list(cls._metadata.values())
            items.sort(key=lambda x: x.created_at, reverse=True)
            return items[:limit]

    @classmethod
    def delete_report(cls, report_id: str) -> bool:
        """Explicitly deletes a report from metadata register and disk."""
        with cls._lock:
            return cls._delete_internal(report_id)

    @classmethod
    def _delete_internal(cls, report_id: str) -> bool:
        clean_id = cls.sanitize_id(report_id)
        meta = cls._metadata.pop(clean_id, None)
        cls._payload_cache.pop(clean_id, None)

        if not meta:
            return False

        try:
            file_path = cls.get_safe_filepath(meta.filename)
            if file_path.exists():
                file_path.unlink()
                logger.info("Purged report file %s", meta.filename)
            return True
        except Exception as exc:
            logger.warning("Could not delete report file %s: %s", meta.filename, exc)
            return True
