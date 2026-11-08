from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class ScannerStatusData(BaseModel):
    """Port scanner engine status and capabilities."""

    available: bool = Field(True, description="Whether scanner engine is active and available")
    status: str = Field("operational", description="Engine operational status code")
    message: str = Field(..., description="Human-readable status summary")
    engine_version: str = Field("0.3.0-hybrid", description="Scanner engine version")
    supported_methods: List[str] = Field(
        default_factory=lambda: ["TCP_CONNECT", "UDP_DGRAM"],
        description="Supported port scanning techniques",
    )
    max_concurrent_targets: int = Field(1, description="Maximum allowed concurrent scan targets")
    safe_mode_enforced: bool = Field(True, description="True if scans are restricted to authorized scopes")


class PortScanResultItem(BaseModel):
    """Result structure for an individual scanned TCP port."""

    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field("TCP", description="Transport protocol")
    state: str = Field(..., description="Port state: OPEN, CLOSED, FILTERED, NO_RESPONSE, or UNKNOWN")
    service: str = Field(..., description="Inferred network service name")
    service_confidence: str = Field("inferred", description="Confidence level: always inferred from port number")
    response_time_ms: float = Field(..., ge=0.0, description="Response latency in milliseconds")


class PortScanRequest(BaseModel):
    """Request payload to initiate a TCP port scan."""

    target: str = Field(..., min_length=1, description="Target IP address or 'localhost'")
    ports: Optional[List[int]] = Field(None, description="Explicit list of port numbers (1-65535)")
    port_range: Optional[str] = Field(None, description="Port range string, e.g. '1-1024' or '80-100'")
    preset: Optional[str] = Field(None, description="Preset name, e.g. 'common'")
    timeout: float = Field(1.0, ge=0.1, le=5.0, description="Connection timeout in seconds (0.1 to 5.0)")
    concurrency: int = Field(50, ge=1, le=100, description="Worker thread concurrency limit (1 to 100)")

    @field_validator("target")
    @classmethod
    def strip_target(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Target address cannot be empty")
        return cleaned


class ScanExecutionResponse(BaseModel):
    """Structured response returned after TCP scan completion."""

    scan_id: str = Field(..., description="Unique scan session identifier")
    target: str = Field(..., description="Scanned target host or IP")
    scan_type: str = Field("TCP_CONNECT", description="Scanning technique executed")
    status: str = Field("completed", description="Execution status: completed or failed")
    started_at: datetime = Field(..., description="UTC start timestamp")
    completed_at: datetime = Field(..., description="UTC completion timestamp")
    duration_seconds: float = Field(..., ge=0.0, description="Total scan runtime in seconds")
    total_ports: int = Field(..., ge=0, description="Total count of ports scanned")
    open_ports: int = Field(..., ge=0, description="Count of open ports")
    closed_ports: int = Field(..., ge=0, description="Count of closed ports")
    filtered_ports: int = Field(0, description="Count of explicitly filtered ports")
    no_response_ports: int = Field(0, description="Count of timed-out non-responsive ports")
    filtered_or_unknown_ports: int = Field(..., ge=0, description="Backwards-compatible aggregate of non-open/closed ports")
    results: List[PortScanResultItem] = Field(default_factory=list, description="Array of individual port findings")


class ScanValidationRequest(BaseModel):
    """Request payload to validate target and ports before scanning."""

    target: str = Field(..., min_length=1, description="Target IP or hostname")
    ports: Optional[List[int]] = Field(None, description="Port list")
    port_range: Optional[str] = Field(None, description="Port range")
    preset: Optional[str] = Field(None, description="Preset name")


class ScanValidationResponse(BaseModel):
    """Response returned from pre-scan validation check."""

    valid: bool = Field(..., description="True if target and ports satisfy safety policies")
    target_ip: Optional[str] = Field(None, description="Resolved IPv4 address")
    resolved_ports_count: int = Field(0, description="Total ports that would be scanned")
    resolved_ports_preview: List[int] = Field(default_factory=list, description="First few resolved ports")
    target_authorized: bool = Field(False, description="True if target falls within authorized CIDRs")
    error: Optional[str] = Field(None, description="Validation error message if invalid")


class ScanHistoryItem(BaseModel):
    """Metadata summary of an archived scan session."""

    scan_id: str = Field(..., description="Unique scan session identifier")
    target: str = Field(..., description="Scanned target")
    scan_type: str = Field(..., description="Scan method: TCP_CONNECT or UDP_DGRAM")
    started_at: datetime = Field(..., description="UTC start timestamp")
    duration_seconds: float = Field(..., description="Runtime in seconds")
    total_ports: int = Field(..., description="Total ports scanned")
    open_ports: int = Field(..., description="Open ports count")
    status: str = Field("completed", description="Execution status")


# ==================== UDP PORT SCANNER SCHEMAS ====================

class UdpScanResultItem(BaseModel):
    """Result structure for an individual scanned UDP port."""

    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field("UDP", description="Transport protocol")
    state: str = Field(..., description="UDP port state: OPEN, CLOSED, OPEN|FILTERED, or UNKNOWN")
    service: str = Field(..., description="Inferred UDP service name")
    service_confidence: str = Field("inferred", description="Confidence level: always inferred from port number")
    response_time_ms: float = Field(..., ge=0.0, description="Response latency in milliseconds")


class UdpScanRequest(BaseModel):
    """Request payload to initiate a UDP port scan."""

    target: str = Field(..., min_length=1, description="Target IP address or 'localhost'")
    ports: Optional[List[int]] = Field(None, description="Explicit list of UDP port numbers (1-65535)")
    port_range: Optional[str] = Field(None, description="Port range string, e.g. '53-161'")
    preset: Optional[str] = Field(None, description="Preset name, e.g. 'common'")
    timeout: float = Field(1.0, ge=0.1, le=5.0, description="Connection timeout in seconds (0.1 to 5.0)")
    concurrency: int = Field(20, ge=1, le=50, description="Worker thread concurrency limit (1 to 50 for UDP)")

    @field_validator("target")
    @classmethod
    def strip_target(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Target address cannot be empty")
        return cleaned


class UdpScanExecutionResponse(BaseModel):
    """Structured response returned after UDP scan completion."""

    scan_id: str = Field(..., description="Unique scan session identifier")
    target: str = Field(..., description="Scanned target host or IP")
    scan_type: str = Field("UDP_DGRAM", description="Scanning technique executed")
    status: str = Field("completed", description="Execution status: completed or failed")
    started_at: datetime = Field(..., description="UTC start timestamp")
    completed_at: datetime = Field(..., description="UTC completion timestamp")
    duration_seconds: float = Field(..., ge=0.0, description="Total scan runtime in seconds")
    total_ports: int = Field(..., ge=0, description="Total count of UDP ports scanned")
    open_ports: int = Field(..., ge=0, description="Count of confirmed open ports (received response)")
    closed_ports: int = Field(..., ge=0, description="Count of confirmed closed ports (ICMP Port Unreachable)")
    open_or_filtered_ports: int = Field(..., ge=0, description="Count of silent/unresponsive ports (OPEN|FILTERED)")
    unknown_ports: int = Field(0, description="Count of execution anomalies")
    results: List[UdpScanResultItem] = Field(default_factory=list, description="Array of individual UDP port findings")
