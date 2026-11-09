from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class DiscoveredHostItem(BaseModel):
    """Details for a single discovered host."""

    ip_address: str = Field(..., description="Target IPv4 address")
    hostname: Optional[str] = Field(None, description="Resolved reverse DNS PTR hostname if available")
    hostname_source: Optional[str] = Field("UNRESOLVED", description="Resolution source: DNS_PTR, HOSTS_FILE, SYSTEM_LOOPBACK, or UNRESOLVED")
    discovery_method: str = Field(..., description="Technique that confirmed host availability (ICMP_ECHO, TCP_CONNECT, ARP, AUTO, LOOPBACK)")
    status: str = Field(..., description="Host status: ONLINE or NO_RESPONSE")
    response_time_ms: Optional[float] = Field(None, description="Round-trip latency in milliseconds")
    mac_address: Optional[str] = Field(None, description="Physical hardware MAC address if resolved via ARP")
    neighbor_state: Optional[str] = Field(None, description="Neighbor table state: REACHABLE, PROBE, STALE, UNREACHABLE, PERMANENT, or None")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp host was identified")


class HostDiscoveryRequest(BaseModel):
    """Request payload to initiate host discovery across a subnet."""

    cidr: str = Field(..., min_length=3, description="IPv4 CIDR network range (e.g. 192.168.1.0/24 or 127.0.0.1/32)")
    method: str = Field("AUTO", description="Discovery method: AUTO, ICMP_ECHO, TCP_CONNECT, or ARP")
    timeout: float = Field(1.0, ge=0.2, le=5.0, description="Per-probe socket/ping timeout in seconds")
    max_hosts: int = Field(256, ge=1, le=1024, description="Maximum total addresses allowed in discovery job")
    concurrency: int = Field(30, ge=1, le=50, description="Concurrent probe workers")

    @field_validator("cidr")
    @classmethod
    def clean_cidr(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("CIDR notation cannot be empty")
        return cleaned


class HostDiscoveryResponse(BaseModel):
    """Structured response returned after discovery job completion."""

    discovery_id: str = Field(..., description="Unique discovery session identifier")
    cidr: str = Field(..., description="Scanned CIDR subnet")
    method: str = Field(..., description="Discovery technique applied")
    status: str = Field("completed", description="Job status")
    started_at: datetime = Field(..., description="UTC start timestamp")
    completed_at: datetime = Field(..., description="UTC completion timestamp")
    duration_seconds: float = Field(..., ge=0.0, description="Total runtime in seconds")
    total_probed: int = Field(..., ge=0, description="Total host addresses probed")
    online_hosts_count: int = Field(..., ge=0, description="Total responsive hosts identified")
    hosts: List[DiscoveredHostItem] = Field(default_factory=list, description="Array of host findings")


class DiscoveryValidationRequest(BaseModel):
    """Request payload to pre-validate a target CIDR."""

    cidr: str = Field(..., min_length=3, description="Target CIDR network")


class DiscoveryValidationResponse(BaseModel):
    """Response returned from pre-discovery validation."""

    valid: bool = Field(..., description="True if CIDR format and boundaries are valid")
    normalized_cidr: Optional[str] = Field(None, description="Normalized CIDR string")
    network_address: Optional[str] = Field(None, description="Network address")
    broadcast_address: Optional[str] = Field(None, description="Broadcast address")
    total_usable_hosts: int = Field(0, description="Count of usable host addresses")
    is_authorized: bool = Field(False, description="True if within allowed safe-mode subnets")
    error: Optional[str] = Field(None, description="Validation failure reason if invalid")


class DiscoveryHistoryItem(BaseModel):
    """Summary of a past host discovery job."""

    discovery_id: str = Field(..., description="Discovery job identifier")
    cidr: str = Field(..., description="Network probed")
    method: str = Field(..., description="Discovery technique")
    started_at: datetime = Field(..., description="UTC start timestamp")
    duration_seconds: float = Field(..., description="Total runtime")
    online_count: int = Field(..., description="Online hosts discovered")
    total_probed: int = Field(..., description="Total hosts evaluated")
    status: str = Field("completed", description="Execution status")


class HostDiscoveryStatusData(BaseModel):
    """Operational status of the Host Discovery Engine."""

    available: bool = Field(True, description="Whether Host Discovery engine is operational")
    status: str = Field("operational", description="Engine status")
    message: str = Field(..., description="Status summary")
    engine_version: str = Field("0.3.0", description="Discovery engine version")
    supported_methods: List[str] = Field(
        default_factory=lambda: ["AUTO", "ICMP_ECHO", "TCP_CONNECT", "ARP"],
        description="Supported host discovery techniques",
    )
    safe_mode_enforced: bool = Field(True, description="True if restricted to authorized private CIDRs")

