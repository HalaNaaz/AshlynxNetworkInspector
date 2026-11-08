from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class ProtocolDistributionItem(BaseModel):
    """Transport protocol distribution item (Zero double-counting guaranteed)."""

    protocol: str = Field(..., description="Transport protocol name: TCP, UDP, ICMP, ARP, OTHER")
    packet_count: int = Field(..., ge=0, description="Number of packets observed")
    byte_count: int = Field(..., ge=0, description="Total byte volume")
    percentage: float = Field(..., ge=0.0, le=100.0, description="Percentage of total transport packets")


class ApplicationProtocolItem(BaseModel):
    """Application-layer protocol summary (reported separately without inflating transport total)."""

    name: str = Field(..., description="Application protocol name e.g. DNS, HTTP, HTTPS, QUIC, DHCP, NTP")
    packet_count: int = Field(..., ge=0, description="Number of application packets")
    byte_count: int = Field(..., ge=0, description="Total byte volume")
    transport_layer: str = Field(..., description="Underlying transport protocol (UDP, TCP)")
    is_inferred: bool = Field(True, description="True if inferred from standard ports/headers without deep payload inspection")


class ProtocolAnalyticsResponse(BaseModel):
    """Response containing transport protocol distribution and application protocol breakdown."""

    session_id: str = Field(..., description="Capture session identifier")
    total_packets: int = Field(..., ge=0, description="Total captured packets")
    total_bytes: int = Field(..., ge=0, description="Total captured volume in bytes")
    transport_distribution: List[ProtocolDistributionItem] = Field(
        default_factory=list,
        description="Exclusive partition of transport layer protocols summing to total_packets",
    )
    application_breakdown: List[ApplicationProtocolItem] = Field(
        default_factory=list,
        description="Application layer protocols detected within transport streams",
    )


class BandwidthDataPoint(BaseModel):
    """Time-windowed bandwidth throughput metrics."""

    timestamp: datetime = Field(..., description="Bucket timestamp (UTC)")
    window_seconds: int = Field(..., description="Rolling aggregation window in seconds (1, 5, 30, 60)")
    bytes_total: int = Field(..., ge=0, description="Total bytes in this window")
    packets_total: int = Field(..., ge=0, description="Total packets in this window")
    bits_per_second: float = Field(..., ge=0.0, description="Instantaneous or rolling throughput in bits/sec")
    packets_per_second: float = Field(..., ge=0.0, description="Throughput in packets/sec")
    bytes_inbound: int = Field(0, ge=0, description="Bytes received by bound interface")
    bytes_outbound: int = Field(0, ge=0, description="Bytes transmitted by bound interface")
    bytes_local: int = Field(0, ge=0, description="Bytes exchanged locally on the host")
    bytes_unknown: int = Field(0, ge=0, description="Bytes with unproven direction")


class BandwidthAnalyticsResponse(BaseModel):
    """Current and historical bandwidth analytics for active or stopped capture session."""

    session_id: str = Field(..., description="Capture session identifier")
    current_window: int = Field(1, description="Active aggregation window (seconds)")
    current_bps: float = Field(0.0, description="Current throughput in bits/sec")
    current_pps: float = Field(0.0, description="Current throughput in packets/sec")
    peak_bps: float = Field(0.0, description="Peak throughput observed in bits/sec")
    peak_pps: float = Field(0.0, description="Peak throughput observed in packets/sec")
    average_packet_size_bytes: float = Field(0.0, description="Mean packet size across capture")
    total_bytes: int = Field(0, description="Cumulative bytes captured")
    total_packets: int = Field(0, description="Cumulative packets captured")
    data_points: List[BandwidthDataPoint] = Field(
        default_factory=list, description="Recent rolling bandwidth data points"
    )


class TopTalkerItem(BaseModel):
    """IP endpoint volume statistics."""

    ip_address: str = Field(..., description="IPv4 or IPv6 address")
    hostname: Optional[str] = Field(None, description="Resolved reverse DNS hostname if known")
    packet_count: int = Field(..., ge=0, description="Packets associated with this IP")
    byte_count: int = Field(..., ge=0, description="Total bytes associated with this IP")
    bytes_sent: int = Field(0, ge=0, description="Bytes transmitted by this IP")
    bytes_received: int = Field(0, ge=0, description="Bytes received by this IP")
    percentage: float = Field(..., ge=0.0, le=100.0, description="Participation percentage of total wire traffic")
    is_private: bool = Field(..., description="True if RFC1918, loopback, or link-local")
    ip_category: str = Field("PUBLIC_ROUTABLE", description="RFC1918, LOOPBACK, LINK_LOCAL, MULTICAST, BROADCAST, or PUBLIC_ROUTABLE")
    is_local_host: bool = Field(False, description="True if matches bound interface IP")


class TopTalkersResponse(BaseModel):
    """Top talkers grouped by source, destination, and combined volume."""

    session_id: str = Field(..., description="Capture session identifier")
    total_unique_ips: int = Field(0, description="Total unique IP endpoints observed")
    top_sources: List[TopTalkerItem] = Field(default_factory=list, description="Top 5 transmitting sources")
    top_destinations: List[TopTalkerItem] = Field(default_factory=list, description="Top 5 receiving destinations")
    top_combined: List[TopTalkerItem] = Field(default_factory=list, description="Top 10 highest-volume endpoints")


class ConnectionFlowItem(BaseModel):
    """Canonical 5-tuple network connection flow."""

    flow_id: str = Field(..., description="Canonical 5-tuple identifier")
    protocol: str = Field(..., description="Transport protocol: TCP, UDP")
    src_ip: str = Field(..., description="Initiator or lowest-endpoint IP")
    src_port: int = Field(..., ge=0, le=65535, description="Initiator or lowest-endpoint port")
    dst_ip: str = Field(..., description="Responder or highest-endpoint IP")
    dst_port: int = Field(..., ge=0, le=65535, description="Responder or highest-endpoint port")
    service: Optional[str] = Field(None, description="Identified service name if known")
    packet_count: int = Field(..., ge=1, description="Packets exchanged in flow")
    byte_count: int = Field(..., ge=0, description="Bytes exchanged in flow")
    first_seen: datetime = Field(..., description="Timestamp of first packet seen (UTC)")
    last_seen: datetime = Field(..., description="Timestamp of most recent packet seen (UTC)")
    duration_seconds: float = Field(0.0, description="Elapsed flow duration")
    is_bidirectional: bool = Field(False, description="True if packets observed in both directions")
    tcp_flags_observed: List[str] = Field(default_factory=list, description="Observed TCP flags")
    state: str = Field("ACTIVE", description="ACTIVE, ESTABLISHED, CLOSED, RESET, or TIMED_OUT")


class ConnectionsAnalyticsResponse(BaseModel):
    """Active and recent connection flow tracking."""

    session_id: str = Field(..., description="Capture session identifier")
    total_active_flows: int = Field(0, description="Count of currently active flows")
    total_flows_tracked: int = Field(0, description="Total unique flows tracked")
    flows: List[ConnectionFlowItem] = Field(default_factory=list, description="List of connection flows")


class DnsQueryItem(BaseModel):
    """Aggregated DNS domain query count."""

    query_name: str = Field(..., description="Queried domain name")
    count: int = Field(..., ge=1, description="Number of queries for this domain")
    percentage: float = Field(..., ge=0.0, le=100.0, description="Percentage of all DNS queries")


class DnsQueryTypeItem(BaseModel):
    """DNS query type breakdown."""

    qtype: str = Field(..., description="Query type: A, AAAA, CNAME, PTR, MX, TXT, HTTPS, OTHER")
    count: int = Field(..., ge=1, description="Number of queries")


class DnsResponseCodeItem(BaseModel):
    """DNS response code breakdown."""

    rcode: int = Field(..., ge=0, description="Numeric DNS response code")
    rcode_name: str = Field(..., description="Standard code name: NOERROR, NXDOMAIN, SERVFAIL, etc.")
    count: int = Field(..., ge=1, description="Number of responses")


class DnsAnalyticsResponse(BaseModel):
    """Aggregated DNS activity metrics."""

    session_id: str = Field(..., description="Capture session identifier")
    total_dns_packets: int = Field(0, description="Total DNS frames analyzed")
    total_queries: int = Field(0, description="Total DNS queries observed")
    total_responses: int = Field(0, description="Total DNS responses observed")
    unmatched_queries: int = Field(0, description="Queries without corresponding response in buffer")
    top_domains: List[DnsQueryItem] = Field(default_factory=list, description="Top queried domain names")
    query_types: List[DnsQueryTypeItem] = Field(default_factory=list, description="DNS query type distribution")
    response_codes: List[DnsResponseCodeItem] = Field(default_factory=list, description="Response status codes")
    is_redacted: bool = Field(False, description="True if domain names were privacy-masked or redacted")
    retention_limit: int = Field(500, description="Bounded maximum unique domain names retained in memory")


class TrafficTimelinePoint(BaseModel):
    """One second granularity timeline data point."""

    timestamp: datetime = Field(..., description="Second bucket timestamp (UTC)")
    second_offset: int = Field(..., description="Offset in seconds from session start")
    pps: float = Field(0.0, description="Packets per second")
    bps: float = Field(0.0, description="Bits per second")
    tcp_bytes: int = Field(0, description="TCP byte volume in this second")
    udp_bytes: int = Field(0, description="UDP byte volume in this second")
    icmp_bytes: int = Field(0, description="ICMP byte volume in this second")
    arp_bytes: int = Field(0, description="ARP byte volume in this second")
    other_bytes: int = Field(0, description="Other byte volume in this second")
    inbound_bytes: int = Field(0, description="Inbound bytes in this second")
    outbound_bytes: int = Field(0, description="Outbound bytes in this second")
    local_bytes: int = Field(0, description="Local loopback/internal bytes")
    unknown_bytes: int = Field(0, description="Unclassified direction bytes")


class TrafficTimelineResponse(BaseModel):
    """Time-series timeline of network traffic activity."""

    session_id: str = Field(..., description="Capture session identifier")
    total_seconds: int = Field(0, description="Total seconds of captured activity")
    points: List[TrafficTimelinePoint] = Field(default_factory=list, description="Second-by-second timeline points")


class AnalyticsOverviewResponse(BaseModel):
    """Executive KPI summary dashboard for traffic analytics."""

    session_id: str = Field(..., description="Capture session identifier")
    status: str = Field(..., description="READY, CAPTURING, STOPPED, or ERROR")
    duration_seconds: float = Field(0.0, description="Session elapsed duration")
    total_packets: int = Field(0, description="Total captured frames")
    total_bytes: int = Field(0, description="Total captured volume in bytes")
    current_bps: float = Field(0.0, description="Current bit rate (bits/sec)")
    current_pps: float = Field(0.0, description="Current packet rate (packets/sec)")
    peak_bps: float = Field(0.0, description="Peak bit rate observed")
    peak_pps: float = Field(0.0, description="Peak packet rate observed")
    active_flows_count: int = Field(0, description="Active 5-tuple connection flows")
    dns_queries_count: int = Field(0, description="Total DNS queries observed")
    top_protocol: str = Field("NONE", description="Predominant transport protocol")
    top_talker_ip: Optional[str] = Field(None, description="Highest-volume IP address")
    inbound_bytes: int = Field(0, description="Total inbound byte volume")
    outbound_bytes: int = Field(0, description="Total outbound byte volume")
    local_bytes: int = Field(0, description="Total local byte volume")
    unknown_bytes: int = Field(0, description="Total unclassified byte volume")

