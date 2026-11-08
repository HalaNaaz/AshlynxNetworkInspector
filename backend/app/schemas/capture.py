from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


class CaptureEnvironmentData(BaseModel):
    """Diagnostic details regarding system packet capture capability."""

    capability_status: str = Field(
        ...,
        description="One of CAPTURE_READY, NPCAP_MISSING, SCAPY_MISSING, PERMISSION_DENIED, NO_INTERFACES, CAPTURE_UNAVAILABLE",
    )
    scapy_installed: bool = Field(..., description="Whether Scapy library is imported and available")
    scapy_version: Optional[str] = Field(None, description="Installed Scapy version")
    npcap_installed: bool = Field(..., description="Whether Npcap/WinPcap packet capture library is detected")
    driver_service_running: bool = Field(..., description="Whether Npcap kernel driver service is running")
    can_capture: bool = Field(..., description="True if real live packet capture can be initiated")
    message: str = Field(..., description="Human-readable capability summary")
    remediation_guide: Optional[str] = Field(None, description="Step-by-step guidance if dependencies are missing")


class CaptureInterfaceItem(BaseModel):
    """Network interface details available for packet sniffing."""

    id: str = Field(..., description="Unique interface identifier (GUID or name)")
    name: str = Field(..., description="Friendly adapter display name")
    description: Optional[str] = Field(None, description="Hardware driver description")
    ipv4_addresses: List[str] = Field(default_factory=list, description="Bound IPv4 addresses")
    ipv6_addresses: List[str] = Field(default_factory=list, description="Bound IPv6 addresses")
    mac_address: Optional[str] = Field(None, description="Hardware Ethernet MAC address")
    is_up: bool = Field(True, description="Interface operational state")
    speed_mbps: Optional[int] = Field(None, description="Link speed in Mbps")
    interface_type: str = Field("unknown", description="physical, virtual, loopback, or unknown")
    can_capture: bool = Field(True, description="True if supported by packet capture backend")


class PacketMetadataItem(BaseModel):
    """Metadata-only representation of a single captured frame (zero raw payload stored)."""

    packet_id: int = Field(..., description="Sequential packet identifier in this session")
    timestamp: datetime = Field(..., description="UTC timestamp frame was received")
    src_ip: str = Field(..., description="Source IPv4/IPv6 or ARP sender address")
    dst_ip: str = Field(..., description="Destination IPv4/IPv6 or ARP target address")
    src_port: Optional[int] = Field(None, description="Layer-4 source port if applicable")
    dst_port: Optional[int] = Field(None, description="Layer-4 destination port if applicable")
    protocol: str = Field(..., description="Protocol: TCP, UDP, ICMP, ARP, DNS, or OTHER")
    length: int = Field(..., description="Total packet length in bytes")
    tcp_flags: Optional[str] = Field(None, description="TCP flags string (e.g. SYN, ACK, RST)")
    dns_summary: Optional[str] = Field(None, description="Safely parsed DNS query name/type without payload")
    interface: str = Field(..., description="Interface on which frame was captured")
    session_id: str = Field(..., description="Capture session identifier")


class CaptureStatistics(BaseModel):
    """Live traffic statistics for an active or completed capture session."""

    total_captured: int = Field(0, description="Total frames captured since session start")
    retained_in_buffer: int = Field(0, description="Count of packets currently retained in ring buffer")
    dropped_packets: int = Field(0, description="Count of dropped frames reported by backend driver")
    tcp_count: int = Field(0, description="Total TCP segments identified")
    udp_count: int = Field(0, description="Total UDP datagrams identified")
    icmp_count: int = Field(0, description="Total ICMP messages identified")
    arp_count: int = Field(0, description="Total ARP frames identified")
    other_count: int = Field(0, description="Other/unrecognized protocol frames")
    bytes_captured: int = Field(0, description="Total volume in bytes captured")
    capture_duration_seconds: float = Field(0.0, description="Elapsed runtime in seconds")


class CaptureStartRequest(BaseModel):
    """Request payload to initiate a live packet capture session."""

    interface_id: str = Field(..., min_length=1, description="Target network interface ID or name")
    filter_preset: Optional[str] = Field("all", description="Predefined filter: all, tcp, udp, icmp, dns, arp, ip, ip6")
    custom_bpf_filter: Optional[str] = Field(None, description="Custom Berkeley Packet Filter expression")
    buffer_limit: int = Field(1000, ge=100, le=5000, description="Maximum in-memory packets retained before FIFO eviction")


class CaptureSessionResponse(BaseModel):
    """Details of a live or completed packet capture session."""

    session_id: str = Field(..., description="Unique capture session identifier")
    interface_id: str = Field(..., description="Bound capture interface")
    interface_name: str = Field(..., description="Friendly interface display name")
    status: str = Field(..., description="READY, CAPTURING, STOPPED, or ERROR")
    filter_bpf: str = Field("", description="Effective BPF filter expression")
    buffer_limit: int = Field(..., description="Maximum packet buffer size")
    started_at: datetime = Field(..., description="UTC start timestamp")
    stopped_at: Optional[datetime] = Field(None, description="UTC termination timestamp")
    duration_seconds: float = Field(..., description="Total session runtime in seconds")
    statistics: CaptureStatistics = Field(default_factory=CaptureStatistics, description="Traffic statistics")


class CapturePacketsResponse(BaseModel):
    """Paginated list of captured packet metadata items."""

    session_id: str = Field(..., description="Session identifier")
    total_matching: int = Field(..., description="Total matching packets in memory buffer")
    offset: int = Field(0, description="Starting index")
    limit: int = Field(100, description="Number of packets returned")
    packets: List[PacketMetadataItem] = Field(default_factory=list, description="Array of packet metadata")

