import threading
from datetime import datetime, timezone
from typing import Optional, Set

from backend.app.analytics.bandwidth_analyzer import BandwidthAnalyzer
from backend.app.analytics.connection_analyzer import ConnectionAnalyzer
from backend.app.analytics.dns_analyzer import DnsAnalyzer
from backend.app.analytics.protocol_analyzer import ProtocolAnalyzer
from backend.app.analytics.top_talkers import TopTalkersAnalyzer
from backend.app.analytics.traffic_timeline import TrafficTimeline
from backend.app.schemas.analytics import (
    AnalyticsOverviewResponse,
    BandwidthAnalyticsResponse,
    ConnectionsAnalyticsResponse,
    DnsAnalyticsResponse,
    ProtocolAnalyticsResponse,
    TopTalkersResponse,
    TrafficTimelineResponse,
)
from backend.app.schemas.capture import PacketMetadataItem


class AnalyticsEngine:
    """Central Real-Time Traffic Analytics Engine coordinating all analytical sub-modules."""

    def __init__(
        self,
        session_id: str,
        interface_ips: Optional[Set[str]] = None,
    ):
        self.session_id = session_id
        self.interface_ips = interface_ips or set()
        self._lock = threading.Lock()

        self.created_at = datetime.now(timezone.utc)
        self.status = "CAPTURING"

        # Analytical components
        self.protocol_analyzer = ProtocolAnalyzer(session_id=session_id)
        self.bandwidth_analyzer = BandwidthAnalyzer(
            session_id=session_id, interface_ips=self.interface_ips
        )
        self.top_talkers = TopTalkersAnalyzer(
            session_id=session_id, interface_ips=self.interface_ips
        )
        self.connection_analyzer = ConnectionAnalyzer(session_id=session_id)
        self.dns_analyzer = DnsAnalyzer(session_id=session_id)
        self.traffic_timeline = TrafficTimeline(
            session_id=session_id, interface_ips=self.interface_ips
        )

    def set_status(self, status: str) -> None:
        """Updates session status (CAPTURING, STOPPED, ERROR)."""
        with self._lock:
            self.status = status

    def process_packet(self, meta: PacketMetadataItem, raw_packet=None) -> None:
        """Dispatches an incoming frame to all analytical sub-modules concurrently."""
        self.protocol_analyzer.process_packet(meta)
        self.bandwidth_analyzer.process_packet(meta)
        self.top_talkers.process_packet(meta)
        self.connection_analyzer.process_packet(meta)
        self.dns_analyzer.process_packet(meta, raw_packet=raw_packet)
        self.traffic_timeline.process_packet(meta)

    def get_overview(self) -> AnalyticsOverviewResponse:
        """Returns executive KPI metrics across all analyzers."""
        proto_dist = self.protocol_analyzer.get_distribution()
        bw = self.bandwidth_analyzer.get_bandwidth(window_seconds=1)
        tt = self.top_talkers.get_top_talkers()
        conns = self.connection_analyzer.get_connections(limit=1)
        dns = self.dns_analyzer.get_dns_analytics()

        # Find predominant transport protocol
        top_proto = "NONE"
        if proto_dist.transport_distribution:
            best_p = max(proto_dist.transport_distribution, key=lambda p: p.packet_count)
            if best_p.packet_count > 0:
                top_proto = best_p.protocol

        top_talker_ip = tt.top_combined[0].ip_address if tt.top_combined else None

        now = datetime.now(timezone.utc)
        duration = max(0.0, round((now - self.created_at).total_seconds(), 2))

        return AnalyticsOverviewResponse(
            session_id=self.session_id,
            status=self.status,
            duration_seconds=duration,
            total_packets=bw.total_packets,
            total_bytes=bw.total_bytes,
            current_bps=bw.current_bps,
            current_pps=bw.current_pps,
            peak_bps=bw.peak_bps,
            peak_pps=bw.peak_pps,
            active_flows_count=conns.total_active_flows,
            dns_queries_count=dns.total_queries,
            top_protocol=top_proto,
            top_talker_ip=top_talker_ip,
            inbound_bytes=self.bandwidth_analyzer.inbound_bytes,
            outbound_bytes=self.bandwidth_analyzer.outbound_bytes,
            local_bytes=self.bandwidth_analyzer.local_bytes,
            unknown_bytes=self.bandwidth_analyzer.unknown_bytes,
        )

    def get_protocols(self) -> ProtocolAnalyticsResponse:
        return self.protocol_analyzer.get_distribution()

    def get_bandwidth(self, window_seconds: int = 1) -> BandwidthAnalyticsResponse:
        return self.bandwidth_analyzer.get_bandwidth(window_seconds=window_seconds)

    def get_top_talkers(self) -> TopTalkersResponse:
        return self.top_talkers.get_top_talkers()

    def get_connections(self, limit: int = 100) -> ConnectionsAnalyticsResponse:
        return self.connection_analyzer.get_connections(limit=limit)

    def get_dns(self) -> DnsAnalyticsResponse:
        return self.dns_analyzer.get_dns_analytics()

    def get_timeline(self) -> TrafficTimelineResponse:
        return self.traffic_timeline.get_timeline()

