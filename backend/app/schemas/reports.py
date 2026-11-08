from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReportType(str, Enum):
    SYSTEM_BASELINE = "system_baseline"
    TCP_SCAN = "tcp_scan"
    UDP_SCAN = "udp_scan"
    HOST_DISCOVERY = "host_discovery"
    CAPTURE_SESSION = "capture_session"
    TRAFFIC_ANALYTICS = "traffic_analytics"
    SECURITY_EVENTS = "security_events"


class ReportFormat(str, Enum):
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"


class ReportGenerateRequest(BaseModel):
    """Payload to trigger report generation."""

    report_type: ReportType = Field(..., description="Target data source domain for report generation")
    report_format: ReportFormat = Field(..., description="Output export format (pdf, csv, json)")
    source_id: Optional[str] = Field(None, description="Optional target scan ID, discovery ID, or capture session ID. If omitted, latest active/completed dataset is used.")
    title: Optional[str] = Field(None, max_length=120, description="Optional custom title for the generated report")
    notes: Optional[str] = Field(None, max_length=500, description="Optional executive notes or auditor comments")
    include_raw_details: bool = Field(True, description="Whether to include comprehensive line-item findings")


class ReportMetadataItem(BaseModel):
    """Metadata record representing a generated report file."""

    report_id: str = Field(..., description="Unique alphanumeric identifier for the report")
    title: str = Field(..., description="Display title of the report")
    report_type: ReportType = Field(..., description="Underlying telemetry source")
    report_format: ReportFormat = Field(..., description="File format")
    source_id: Optional[str] = Field(None, description="Associated source task or session ID")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC generation timestamp",
    )
    file_size_bytes: int = Field(0, description="File size on disk in bytes")
    item_count: int = Field(0, description="Number of primary records included in report")
    filename: str = Field(..., description="Safe filename for attachment download")
    download_url: str = Field(..., description="Relative download URI")


class ReportPreviewResponse(BaseModel):
    """Lightweight preview structure for UI inspection before or after download."""

    report_id: str
    title: str
    report_type: ReportType
    report_format: ReportFormat
    created_at: datetime
    summary: Dict[str, Any]
    headers: List[str]
    preview_rows: List[List[Any]]
    total_rows: int
    json_preview: Optional[Dict[str, Any]] = None
    raw_content: Optional[str] = None


class ReportSourceOption(BaseModel):
    """Available data source descriptor for frontend selection."""

    source_type: ReportType
    source_id: str
    label: str
    timestamp: Optional[datetime] = None
    item_count: int = 0
    is_latest: bool = False


class ReportSourcesResponse(BaseModel):
    """Collection of currently queryable sources across all ANI engines."""

    sources: List[ReportSourceOption]

