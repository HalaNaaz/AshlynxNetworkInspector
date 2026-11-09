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


def test_dns_over_udp_parsing_scapy():
    """Verifies that genuine DNS-over-UDP frames are parsed into queries, responses, and domain records."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP
    from backend.app.capture.packet_parser import parse_packet_metadata

    da = DnsAnalyzer("dns-udp-session")

    # 1. Real Scapy UDP Query for example.com
    raw_query = IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    meta_q = parse_packet_metadata(raw_query, packet_id=1, session_id="dns-udp-session", interface_name="eth0")
    assert meta_q.protocol == "DNS"
    assert meta_q.dns_summary == "Query: example.com"
    da.process_packet(meta_q, raw_packet=raw_query)

    # 2. Real Scapy UDP Response with NOERROR
    raw_resp = (
        IP(src="8.8.8.8", dst="192.168.1.5")
        / UDP(sport=53, dport=54321)
        / DNS(qr=1, rcode=0, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    )
    meta_r = parse_packet_metadata(raw_resp, packet_id=2, session_id="dns-udp-session", interface_name="eth0")
    assert meta_r.protocol == "DNS"
    assert "Response (rcode=0)" in meta_r.dns_summary
    da.process_packet(meta_r, raw_packet=raw_resp)

    res = da.get_dns_analytics()
    assert res.total_dns_packets == 2
    assert res.total_queries == 1
    assert res.total_responses == 1
    assert res.unmatched_queries == 0
    assert len(res.top_domains) == 1
    assert res.top_domains[0].query_name == "example.com"
    assert res.response_codes[0].rcode == 0
    assert res.response_codes[0].rcode_name == "NOERROR"


def test_dns_over_tcp_rfc1035_framing_and_parsing():
    """Verifies RFC 1035 / RFC 7766 DNS-over-TCP framing with 2-byte prefix and message validation."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP
    from backend.app.capture.packet_parser import parse_packet_metadata

    da = DnsAnalyzer("dns-tcp-session")

    # 1. Construct valid DNS-over-TCP query with 2-byte length prefix
    dns_query_body = bytes(DNS(rd=1, qd=DNSQR(qname="tcp.example.com")))
    prefix = len(dns_query_body).to_bytes(2, byteorder="big")
    raw_tcp_query = (
        IP(src="192.168.29.59", dst="192.168.29.1")
        / TCP(sport=49152, dport=53, flags="PA")
        / (prefix + dns_query_body)
    )

    meta_q = parse_packet_metadata(raw_tcp_query, packet_id=1, session_id="dns-tcp-session", interface_name="Wi-Fi")
    assert meta_q.protocol == "TCP"
    assert meta_q.dns_summary == "Query: tcp.example.com"
    da.process_packet(meta_q, raw_packet=raw_tcp_query)

    # 2. Construct valid DNS-over-TCP response with 2-byte length prefix
    dns_resp_body = bytes(DNS(qr=1, rcode=0, qd=DNSQR(qname="tcp.example.com"), an=DNSRR(rrname="tcp.example.com", rdata="1.2.3.4")))
    prefix_resp = len(dns_resp_body).to_bytes(2, byteorder="big")
    raw_tcp_resp = (
        IP(src="192.168.29.1", dst="192.168.29.59")
        / TCP(sport=53, dport=49152, flags="PA")
        / (prefix_resp + dns_resp_body)
    )

    meta_r = parse_packet_metadata(raw_tcp_resp, packet_id=2, session_id="dns-tcp-session", interface_name="Wi-Fi")
    assert meta_r.protocol == "TCP"
    assert "Response (rcode=0)" in meta_r.dns_summary
    da.process_packet(meta_r, raw_packet=raw_tcp_resp)

    res = da.get_dns_analytics()
    assert res.total_dns_packets == 2
    assert res.total_queries == 1
    assert res.total_responses == 1
    assert len(res.top_domains) == 1
    assert res.top_domains[0].query_name == "tcp.example.com"
    assert res.response_codes[0].rcode == 0


def test_dns_over_tcp_control_frames_not_represented_as_dns():
    """Ensures TCP control packets (SYN, ACK, FIN) on port 53 are never claimed as DNS queries or responses."""
    from scapy.layers.inet import IP, TCP
    from backend.app.capture.packet_parser import parse_packet_metadata

    da = DnsAnalyzer("dns-control-session")

    # TCP SYN on port 53 (handshake start)
    syn_pkt = IP(src="192.168.29.59", dst="192.168.29.1") / TCP(sport=49152, dport=53, flags="S")
    meta_syn = parse_packet_metadata(syn_pkt, packet_id=1, session_id="dns-control-session", interface_name="Wi-Fi")
    assert meta_syn.protocol == "TCP"
    assert meta_syn.dns_summary is None
    da.process_packet(meta_syn, raw_packet=syn_pkt)

    # TCP ACK on port 53 (0 payload acknowledgement)
    ack_pkt = IP(src="192.168.29.59", dst="192.168.29.1") / TCP(sport=49152, dport=53, flags="A")
    meta_ack = parse_packet_metadata(ack_pkt, packet_id=2, session_id="dns-control-session", interface_name="Wi-Fi")
    assert meta_ack.protocol == "TCP"
    assert meta_ack.dns_summary is None
    da.process_packet(meta_ack, raw_packet=ack_pkt)

    # TCP FIN on port 53
    fin_pkt = IP(src="192.168.29.1", dst="192.168.29.59") / TCP(sport=53, dport=49152, flags="FA")
    meta_fin = parse_packet_metadata(fin_pkt, packet_id=3, session_id="dns-control-session", interface_name="Wi-Fi")
    assert meta_fin.protocol == "TCP"
    assert meta_fin.dns_summary is None
    da.process_packet(meta_fin, raw_packet=fin_pkt)

    res = da.get_dns_analytics()
    # Zero queries, zero responses, zero unvalidated DNS frames
    assert res.total_queries == 0
    assert res.total_responses == 0
    assert res.total_dns_packets == 0
    assert len(res.top_domains) == 0


def test_dns_over_tcp_malformed_and_incomplete_streams():
    """Verifies that incomplete stream fragments and corrupted payloads on port 53 do not parse as queries/responses."""
    from scapy.layers.inet import IP, TCP
    from backend.app.capture.packet_parser import parse_packet_metadata

    da = DnsAnalyzer("dns-malformed-session")

    # 1. Incomplete 1-byte payload (sub-prefix fragment)
    incomplete_prefix = IP(src="192.168.29.59", dst="192.168.29.1") / TCP(sport=49152, dport=53, flags="PA") / b"\x00"
    meta_1 = parse_packet_metadata(incomplete_prefix, packet_id=1, session_id="test", interface_name="Wi-Fi")
    assert meta_1.dns_summary is None
    da.process_packet(meta_1, raw_packet=incomplete_prefix)

    # 2. Incomplete segment: 2-byte prefix claims 60 bytes, but only 6 bytes delivered
    truncated_segment = (
        IP(src="192.168.29.59", dst="192.168.29.1")
        / TCP(sport=49152, dport=53, flags="PA")
        / (b"\x00\x3c\x12\x34\x01\x00")
    )
    meta_2 = parse_packet_metadata(truncated_segment, packet_id=2, session_id="test", interface_name="Wi-Fi")
    assert meta_2.dns_summary is None
    da.process_packet(meta_2, raw_packet=truncated_segment)

    # 3. Corrupted payload: valid length prefix (20 bytes), but inner payload is corrupted garbage bytes
    corrupt_segment = (
        IP(src="192.168.29.59", dst="192.168.29.1")
        / TCP(sport=49152, dport=53, flags="PA")
        / (b"\x00\x14" + b"\xff" * 20)
    )
    meta_3 = parse_packet_metadata(corrupt_segment, packet_id=3, session_id="test", interface_name="Wi-Fi")
    assert meta_3.dns_summary is None
    da.process_packet(meta_3, raw_packet=corrupt_segment)

    res = da.get_dns_analytics()
    assert res.total_queries == 0
    assert res.total_responses == 0
    assert len(res.top_domains) == 0


def test_bandwidth_directional_classification_gateway_vs_loopback():
    """Verifies that traffic to/from default gateway is classified as OUTBOUND/INBOUND (local_bytes strictly 0)."""
    bound_ips = {"192.168.29.59"}
    bw = BandwidthAnalyzer("gateway-bandwidth-session", interface_ips=bound_ips)

    # 40 packets host -> gateway (OUTBOUND wire transmission)
    for i in range(40):
        bw.process_packet(make_packet(i + 1, "TCP", "192.168.29.59", "192.168.29.1", 50000 + i, 53, length=66))

    # 40 packets gateway -> host (INBOUND wire reception)
    for i in range(40):
        bw.process_packet(make_packet(40 + i + 1, "TCP", "192.168.29.1", "192.168.29.59", 53, 50000 + i, length=66))

    # 80 packets total: 80 * 66 = 5280 bytes
    assert bw.total_packets == 80
    assert bw.total_bytes == 5280
    assert bw.outbound_bytes == 2640
    assert bw.inbound_bytes == 2640
    # Host Loopback Bytes must be strictly 0 because all packets traversed the physical/wireless link
    assert bw.local_bytes == 0

    # Inter-process loopback traffic (127.0.0.1)
    bw.process_packet(make_packet(81, "TCP", "127.0.0.1", "127.0.0.1", 8000, 5173, length=120))
    assert bw.local_bytes == 120
    assert bw.total_bytes == 5400


def test_protocol_analyzer_transport_vs_application_distinction():
    """Verifies strict exclusive transport partition (no double counting) with independent application breakdown."""
    pa = ProtocolAnalyzer("proto-dist-session")

    # 77 TCP control packets on port 53 (handshakes / unparsed control frames)
    for i in range(77):
        pa.process_packet(make_packet(i + 1, "TCP", "192.168.29.59", "192.168.29.1", 50000 + i, 53, length=60))

    # 2 UDP DNS query packets (validated)
    for i in range(2):
        pa.process_packet(
            make_packet(78 + i, "UDP", "192.168.29.59", "192.168.29.1", 60000 + i, 53, length=75, dns_summary="Query: test.org")
        )

    res = pa.get_distribution()
    assert res.total_packets == 79

    # Transport exclusive partition: sum of transport packet counts must exactly equal total_packets
    transport_sum = sum(item.packet_count for item in res.transport_distribution)
    assert transport_sum == 79

    tcp_item = next(item for item in res.transport_distribution if item.protocol == "TCP")
    udp_item = next(item for item in res.transport_distribution if item.protocol == "UDP")
    assert tcp_item.packet_count == 77
    assert udp_item.packet_count == 2

    # Application layer breakdown
    app_dns_tcp = next((a for a in res.application_breakdown if a.name == "DNS" and a.transport_layer == "TCP"), None)
    app_dns_udp = next((a for a in res.application_breakdown if a.name == "DNS" and a.transport_layer == "UDP"), None)

    assert app_dns_tcp is not None
    assert app_dns_tcp.packet_count == 77
    assert app_dns_tcp.is_inferred is True  # Port-inferred because no verified dns_summary

    assert app_dns_udp is not None
    assert app_dns_udp.packet_count == 2
    assert app_dns_udp.is_inferred is False  # Verified from dns_summary


