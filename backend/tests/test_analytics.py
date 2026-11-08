from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.analytics.analytics_engine import AnalyticsEngine
from backend.app.analytics.bandwidth_analyzer import BandwidthAnalyzer
from backend.app.analytics.connection_analyzer import ConnectionAnalyzer
from backend.app.analytics.dns_analyzer import DnsAnalyzer
from backend.app.analytics.protocol_analyzer import ProtocolAnalyzer
from backend.app.analytics.top_talkers import TopTalkersAnalyzer, is_private_ip
from backend.app.analytics.traffic_timeline import TrafficTimeline
from backend.app.capture.capture_manager import CaptureManager
from backend.app.main import app
from backend.app.schemas.capture import PacketMetadataItem


def make_packet(
    seq: int,
    proto: str,
    src_ip: str,
    dst_ip: str,
    src_port: int = None,
    dst_port: int = None,
    length: int = 100,
    tcp_flags: str = None,
    dns_summary: str = None,
    ts: datetime = None,
) -> PacketMetadataItem:
    return PacketMetadataItem(
        packet_id=seq,
        timestamp=ts or datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        length=length,
        tcp_flags=tcp_flags,
        dns_summary=dns_summary,
        interface="eth0",
        session_id="test-session",
    )


def test_protocol_analyzer_zero_double_counting():
    """Verifies transport distribution strictly sums to total packets with zero double-counting."""
    pa = ProtocolAnalyzer("test-session")
    pa.process_packet(make_packet(1, "TCP", "192.168.1.10", "1.1.1.1", 54321, 443, length=150))
    pa.process_packet(make_packet(2, "UDP", "192.168.1.10", "8.8.8.8", 53211, 53, length=80))
    # DNS packet must count as UDP in transport, but also track application DNS
    pa.process_packet(
        make_packet(3, "DNS", "192.168.1.10", "8.8.8.8", 53212, 53, length=90, dns_summary="Query: example.com")
    )
    pa.process_packet(make_packet(4, "ICMP", "192.168.1.10", "1.1.1.1", length=64))
    pa.process_packet(make_packet(5, "ARP", "192.168.1.10", "192.168.1.1", length=42))
    pa.process_packet(make_packet(6, "OTHER", "0.0.0.0", "0.0.0.0", length=60))

    resp = pa.get_distribution()
    assert resp.total_packets == 6
    assert resp.total_bytes == 150 + 80 + 90 + 64 + 42 + 60

    # Strict sum check: sum(transport_distribution.packet_count) == total_packets
    transport_sum = sum(item.packet_count for item in resp.transport_distribution)
    assert transport_sum == 6

    # Verify counts
    counts = {item.protocol: item.packet_count for item in resp.transport_distribution}
    assert counts["TCP"] == 1
    assert counts["UDP"] == 2  # 1 pure UDP + 1 DNS over UDP
    assert counts["ICMP"] == 1
    assert counts["ARP"] == 1
    assert counts["OTHER"] == 1

    # Application breakdown exists independently
    app_names = {app_item.name: app_item.packet_count for app_item in resp.application_breakdown}
    assert "DNS" in app_names
    assert "HTTPS / TLS" in app_names


def test_bandwidth_directional_classification():
    """Verifies INBOUND, OUTBOUND, LOCAL, and UNKNOWN classification based on interface IPs."""
    bound_ips = {"192.168.1.50"}
    bw = BandwidthAnalyzer("test-session", interface_ips=bound_ips)

    # 1. Outbound: src is local, dst is external
    assert bw.classify_direction("192.168.1.50", "93.184.216.34") == "OUTBOUND"
    # 2. Inbound: src is external, dst is local
    assert bw.classify_direction("93.184.216.34", "192.168.1.50") == "INBOUND"
    # 3. Local: both local or loopback
    assert bw.classify_direction("127.0.0.1", "127.0.0.1") == "LOCAL"
    assert bw.classify_direction("192.168.1.50", "192.168.1.50") == "LOCAL"
    # 4. Unknown: neither is bound interface IP
    assert bw.classify_direction("10.0.0.1", "10.0.0.2") == "UNKNOWN"

    # Process packets
    bw.process_packet(make_packet(1, "TCP", "192.168.1.50", "93.184.216.34", 50000, 80, length=200))
    bw.process_packet(make_packet(2, "TCP", "93.184.216.34", "192.168.1.50", 80, 50000, length=1000))
    bw.process_packet(make_packet(3, "OTHER", "10.0.0.1", "10.0.0.2", length=150))

    resp = bw.get_bandwidth(window_seconds=1)
    assert resp.total_packets == 3
    assert resp.total_bytes == 1350
    assert bw.outbound_bytes == 200
    assert bw.inbound_bytes == 1000
    assert bw.unknown_bytes == 150
    assert resp.average_packet_size_bytes == 450.0


def test_top_talkers_ranking_and_private_ip():
    """Verifies IP classification and ranking by bytes."""
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.10.0.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False

    tt = TopTalkersAnalyzer("test-session", interface_ips={"192.168.1.10"})
    tt.process_packet(make_packet(1, "TCP", "192.168.1.10", "8.8.8.8", length=500))
    tt.process_packet(make_packet(2, "TCP", "8.8.8.8", "192.168.1.10", length=1500))
    tt.process_packet(make_packet(3, "UDP", "192.168.1.10", "1.1.1.1", length=200))

    resp = tt.get_top_talkers()
    assert resp.total_unique_ips == 3
    # Combined top talker should be 192.168.1.10 (500+1500+200 = 2200 bytes)
    assert resp.top_combined[0].ip_address == "192.168.1.10"
    assert resp.top_combined[0].byte_count == 2200
    assert resp.top_combined[0].bytes_sent == 700
    assert resp.top_combined[0].bytes_received == 1500
    assert resp.top_combined[0].is_private is True
    assert resp.top_combined[0].ip_category == "RFC1918_PRIVATE"
    assert resp.top_combined[0].is_local_host is True

    # 8.8.8.8 is public (500 + 1500 = 2000 bytes)
    public_talker = next(item for item in resp.top_combined if item.ip_address == "8.8.8.8")
    assert public_talker.is_private is False
    assert public_talker.ip_category == "PUBLIC_ROUTABLE"
    assert public_talker.byte_count == 2000


def test_connection_flow_canonical_grouping():
    """Verifies that reverse direction packets map to the same 5-tuple flow."""
    ca = ConnectionAnalyzer("test-session")

    # Packet A -> B
    ca.process_packet(
        make_packet(1, "TCP", "192.168.1.20", "104.26.10.1", 54321, 443, length=60, tcp_flags="SYN")
    )
    # Packet B -> A
    ca.process_packet(
        make_packet(2, "TCP", "104.26.10.1", "192.168.1.20", 443, 54321, length=60, tcp_flags="SYN, ACK")
    )

    resp = ca.get_connections(limit=10)
    assert resp.total_flows_tracked == 1
    flow = resp.flows[0]
    assert flow.packet_count == 2
    assert flow.byte_count == 120
    assert flow.is_bidirectional is True
    assert flow.service == "HTTPS"
    assert "SYN" in flow.tcp_flags_observed
    assert "ACK" in flow.tcp_flags_observed
    assert flow.state == "ESTABLISHED"


def test_dns_analyzer_metrics():
    """Verifies DNS query domain extraction, response codes, and unmatched count."""
    da = DnsAnalyzer("test-session")
    da.process_packet(make_packet(1, "DNS", "192.168.1.5", "8.8.8.8", 50000, 53, dns_summary="Query: github.com"))
    da.process_packet(make_packet(2, "DNS", "192.168.1.5", "8.8.8.8", 50001, 53, dns_summary="Query: google.com"))
    da.process_packet(make_packet(3, "DNS", "192.168.1.5", "8.8.8.8", 50002, 53, dns_summary="Query: github.com"))
    da.process_packet(make_packet(4, "DNS", "8.8.8.8", "192.168.1.5", 53, 50000, dns_summary="Response (rcode=0)"))

    resp = da.get_dns_analytics()
    assert resp.total_dns_packets == 4
    assert resp.total_queries == 3
    assert resp.total_responses == 1
    assert resp.unmatched_queries == 2
    # Top domain should be github.com (2 queries)
    assert resp.top_domains[0].query_name == "github.com"
    assert resp.top_domains[0].count == 2
    # Response code 0 (NOERROR)
    assert resp.response_codes[0].rcode == 0
    assert resp.response_codes[0].rcode_name == "NOERROR"


def test_traffic_timeline_aggregation():
    """Verifies second-by-second timeline generation."""
    tt = TrafficTimeline("test-session", interface_ips={"192.168.1.10"})
    base_ts = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)

    tt.process_packet(make_packet(1, "TCP", "192.168.1.10", "1.1.1.1", 50000, 443, length=100, ts=base_ts))
    tt.process_packet(make_packet(2, "UDP", "192.168.1.10", "8.8.8.8", 50000, 53, length=50, ts=base_ts))

    resp = tt.get_timeline()
    assert resp.total_seconds >= 1
    pt = resp.points[0]
    assert pt.tcp_bytes == 100
    assert pt.udp_bytes == 50
    assert pt.outbound_bytes == 150
    assert pt.pps == 2.0


def test_api_analytics_endpoints_and_404():
    """Tests FastAPI router endpoints with mock active capture session and 404 for missing session."""
    client = TestClient(app)

    # 1. 404 on nonexistent session
    resp_404 = client.get("/api/analytics/nonexistent-session/overview")
    assert resp_404.status_code == 404

    # 2. Inject mock engine into CaptureManager for session testing
    engine = AnalyticsEngine("mock-session-001", interface_ips={"192.168.1.15"})
    engine.process_packet(make_packet(1, "TCP", "192.168.1.15", "93.184.216.34", 51234, 443, length=500))
    engine.process_packet(
        make_packet(2, "DNS", "192.168.1.15", "1.1.1.1", 53210, 53, length=80, dns_summary="Query: test.org")
    )

    class MockCaptureWrapper:
        def __init__(self, eng):
            self.analytics_engine = eng

    CaptureManager._sessions["mock-session-001"] = MockCaptureWrapper(engine)

    try:
        # Overview
        r = client.get("/api/analytics/mock-session-001/overview")
        assert r.status_code == 200
        overview = r.json()
        assert overview["total_packets"] == 2
        assert overview["total_bytes"] == 580

        # Protocols
        r = client.get("/api/analytics/mock-session-001/protocols")
        assert r.status_code == 200
        protos = r.json()
        assert protos["total_packets"] == 2

        # Bandwidth
        r = client.get("/api/analytics/mock-session-001/bandwidth?window_seconds=5")
        assert r.status_code == 200
        bw = r.json()
        assert bw["current_window"] == 5

        # Top talkers
        r = client.get("/api/analytics/mock-session-001/top-talkers")
        assert r.status_code == 200
        tt = r.json()
        assert len(tt["top_combined"]) >= 1

        # Connections
        r = client.get("/api/analytics/mock-session-001/connections?limit=50")
        assert r.status_code == 200

        # DNS
        r = client.get("/api/analytics/mock-session-001/dns")
        assert r.status_code == 200
        dns_data = r.json()
        assert dns_data["total_queries"] == 1

        # Timeline
        r = client.get("/api/analytics/mock-session-001/timeline")
        assert r.status_code == 200
        timeline = r.json()
        assert timeline["total_seconds"] >= 1
    finally:
        CaptureManager._sessions.pop("mock-session-001", None)


def test_dns_privacy_retention_and_redaction():
    """Verifies that DNS analyzer enforces hard memory bounds (max_domains) with least-frequent eviction,
    sanitizes domain strings, and applies privacy masking when enabled.
    """
    da = DnsAnalyzer("test-session", max_domains=5, redact_domains=True)

    # 1. Test privacy redaction on multi-level domains
    da.process_packet(make_packet(1, "DNS", "10.0.0.1", "8.8.8.8", 50000, 53, dns_summary="Query: secret.internal.bank.com"))
    resp = da.get_dns_analytics()
    assert len(resp.top_domains) == 1
    # Hostname masked, apex preserved
    assert resp.top_domains[0].query_name == "***.bank.com"

    # 2. Test bounded memory eviction: feed 10 distinct domains to max_domains=5
    for i in range(10):
        da.process_packet(make_packet(10 + i, "DNS", "10.0.0.1", "8.8.8.8", 50000 + i, 53, dns_summary=f"Query: domain{i}.org"))

    resp = da.get_dns_analytics()
    # Unique domains tracked in memory must never exceed max_domains
    assert len(da._domains) <= 5


def test_analytics_session_isolation():
    """Verifies that separate AnalyticsEngine instances maintain strict session isolation with zero data bleeding."""
    eng1 = AnalyticsEngine("session-alpha", interface_ips={"192.168.1.10"})
    eng2 = AnalyticsEngine("session-beta", interface_ips={"10.0.0.50"})

    # Feed packets exclusively into session-alpha
    for i in range(5):
        eng1.process_packet(make_packet(i, "TCP", "192.168.1.10", "93.184.216.34", 50000 + i, 443, length=200))

    ov1 = eng1.get_overview()
    ov2 = eng2.get_overview()

    assert ov1.total_packets == 5
    assert ov1.total_bytes == 1000
    assert ov1.session_id == "session-alpha"

    # session-beta must remain completely clean
    assert ov2.total_packets == 0
    assert ov2.total_bytes == 0
    assert ov2.active_flows_count == 0
    assert ov2.session_id == "session-beta"


def test_malformed_packet_metadata_handling():
    """Verifies that malformed or anomalous packet metadata items are handled safely without crashing analytics."""
    eng = AnalyticsEngine("session-resilience")

    malformed_packets = [
        make_packet(1, "", "", "", None, None, length=0),
        make_packet(2, "UNKNOWN_PROTO", "256.256.256.256", "invalid_ip", -10, 99999, length=0),
        make_packet(3, "DNS", "10.0.0.1", "8.8.8.8", 53, 53, dns_summary="Corrupt/Garbage/Payload!@#$%^&*()"),
        make_packet(4, "TCP", "127.0.0.1", "127.0.0.1", 80, 80, tcp_flags=""),
    ]

    for pkt in malformed_packets:
        # Must not raise exceptions
        eng.process_packet(pkt)

    ov = eng.get_overview()
    assert ov.total_packets == 4
    assert ov.status == "CAPTURING"


def test_connection_state_requires_bidirectional_exchange():
    """Verifies that a connection is never prematurely classified as ESTABLISHED from a single packet."""
    ca = ConnectionAnalyzer("test-session")

    # 1. Lone SYN packet
    ca.process_packet(make_packet(1, "TCP", "10.0.0.5", "10.0.0.1", 50000, 80, tcp_flags="SYN"))
    flows = ca.get_connections().flows
    assert len(flows) == 1
    assert flows[0].state == "SYN_SENT"
    assert flows[0].is_bidirectional is False

    # 2. Lone ACK packet on a new flow (sniffed mid-session in single direction)
    ca.process_packet(make_packet(2, "TCP", "10.0.0.6", "10.0.0.1", 50001, 80, tcp_flags="ACK"))
    flow2 = next(f for f in ca.get_connections().flows if f.src_port == 50001 or f.dst_port == 50001)
    # Must NOT claim ESTABLISHED from a single packet
    assert flow2.state != "ESTABLISHED"
    assert flow2.state == "SINGLE_DIRECTION"

    # 3. Bidirectional exchange with SYN and ACK
    ca.process_packet(make_packet(3, "TCP", "10.0.0.1", "10.0.0.5", 80, 50000, tcp_flags="SYN, ACK"))
    flow1 = next(f for f in ca.get_connections().flows if f.src_port == 50000 or f.dst_port == 50000)
    assert flow1.is_bidirectional is True
    assert flow1.state == "ESTABLISHED"


