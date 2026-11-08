import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.capture.capture_engine import LiveCaptureEngine
from backend.app.capture.capture_manager import CaptureManager, PREDEFINED_BPF_FILTERS
from backend.app.capture.environment import (
    check_scapy_availability,
    evaluate_capture_environment,
)
from backend.app.capture.interface_manager import (
    classify_interface_type,
    list_capture_interfaces,
)
from backend.app.capture.packet_parser import format_tcp_flags, parse_packet_metadata
from backend.app.main import app

client = TestClient(app)


# ==================== 1. ENVIRONMENT TESTS ====================

def test_scapy_availability():
    """Verifies Scapy is detected in the environment."""
    is_avail, ver = check_scapy_availability()
    assert is_avail is True
    assert ver is not None


def test_evaluate_capture_environment():
    """Verifies capture environment capability diagnostic output."""
    env = evaluate_capture_environment()
    assert env.capability_status in (
        "CAPTURE_READY",
        "NPCAP_MISSING",
        "PERMISSION_DENIED",
        "SCAPY_MISSING",
    )
    assert env.scapy_installed is True
    assert isinstance(env.message, str)
    if not env.can_capture:
        assert env.remediation_guide is not None


# ==================== 2. INTERFACE MANAGER TESTS ====================

def test_interface_enumeration():
    """Verifies interfaces are discovered and properly classified."""
    ifaces = list_capture_interfaces()
    assert len(ifaces) > 0
    for iface in ifaces:
        assert iface.id is not None
        assert iface.name is not None
        assert iface.interface_type in ("physical", "virtual", "loopback", "unknown")


def test_classify_interface_type():
    """Verifies interface categorization rules."""
    assert classify_interface_type("Loopback Pseudo-Interface 1") == "loopback"
    assert classify_interface_type("Wi-Fi", "Intel Wi-Fi 6 AX201") == "physical"
    assert classify_interface_type("vEthernet (WSL)", "Hyper-V Virtual Adapter") == "virtual"


# ==================== 3. PACKET PARSER & PRIVACY TESTS ====================

class MockEthernetPacket:
    def __init__(self):
        self.time = 1700000000.0
        self.src = "00:11:22:33:44:55"
        self.dst = "66:77:88:99:AA:BB"

    def haslayer(self, layer_name):
        return layer_name == "Ether"

    def __getitem__(self, item):
        return self

    def __len__(self):
        return 64


class MockArpPacket:
    def __init__(self):
        self.time = 1700000000.0
        self.psrc = "192.168.1.1"
        self.pdst = "192.168.1.100"

    def haslayer(self, layer_name):
        return layer_name == "ARP"

    def __getitem__(self, item):
        return self

    def __len__(self):
        return 42


class MockTcpPacket:
    def __init__(self):
        self.time = 1700000000.0
        self.src = "192.168.1.50"
        self.dst = "192.168.1.1"
        self.proto = 6
        self.sport = 54321
        self.dport = 443
        self.flags = "SA"

    def haslayer(self, layer_name):
        return layer_name in ("IP", "TCP")

    def __getitem__(self, item):
        return self

    def __len__(self):
        return 74


class MockUdpDnsPacket:
    def __init__(self):
        self.time = 1700000000.0
        self.src = "192.168.1.50"
        self.dst = "8.8.8.8"
        self.proto = 17
        self.sport = 61234
        self.dport = 53
        self.qr = 0
        self.qd = self
        self.qname = b"google.com."

    def haslayer(self, layer_name):
        return layer_name in ("IP", "UDP", "DNS")

    def __getitem__(self, item):
        return self

    def __len__(self):
        return 88


def test_parse_tcp_metadata():
    """Verifies TCP frame metadata extraction and flag formatting."""
    pkt = MockTcpPacket()
    meta = parse_packet_metadata(pkt, packet_id=1, session_id="test-ses", interface_name="eth0")
    assert meta.protocol == "TCP"
    assert meta.src_ip == "192.168.1.50"
    assert meta.dst_ip == "192.168.1.1"
    assert meta.src_port == 54321
    assert meta.dst_port == 443
    assert "SYN" in meta.tcp_flags and "ACK" in meta.tcp_flags
    assert meta.length == 74


def test_parse_arp_metadata():
    """Verifies ARP frame metadata extraction."""
    pkt = MockArpPacket()
    meta = parse_packet_metadata(pkt, packet_id=2, session_id="test-ses", interface_name="eth0")
    assert meta.protocol == "ARP"
    assert meta.src_ip == "192.168.1.1"
    assert meta.dst_ip == "192.168.1.100"
    assert meta.src_port is None


def test_parse_dns_safe_metadata():
    """Verifies DNS frame extracts query name safely without raw payload."""
    pkt = MockUdpDnsPacket()
    meta = parse_packet_metadata(pkt, packet_id=3, session_id="test-ses", interface_name="eth0")
    assert meta.protocol == "DNS"
    assert meta.dns_summary == "Query: google.com"
    assert meta.src_port == 61234
    assert meta.dst_port == 53


def test_privacy_no_payload_stored():
    """Strict privacy test: verifies PacketMetadataItem contains zero raw payload fields."""
    pkt = MockTcpPacket()
    meta = parse_packet_metadata(pkt, packet_id=1, session_id="test-ses", interface_name="eth0")
    dump = meta.model_dump()
    # Forbidden sensitive payload keys
    for key in ("payload", "raw", "data", "password", "token", "cookie", "body"):
        assert key not in dump


# ==================== 4. CAPTURE ENGINE & BUFFER LIMITS ====================

def test_engine_buffer_eviction():
    """Verifies ring buffer oldest-entry eviction when buffer limit is exceeded."""
    engine = LiveCaptureEngine(
        session_id="test-evict",
        interface_id="test-if",
        interface_name="eth0",
        buffer_limit=100,  # Min allowed buffer limit
    )

    # Feed 150 mock packets
    for i in range(150):
        engine.feed_packet_for_testing(MockTcpPacket())

    stats = engine.get_statistics()
    assert stats.total_captured == 150
    assert stats.retained_in_buffer == 100  # Capped at buffer limit

    total_matching, pkts = engine.get_packets(offset=0, limit=200)
    assert total_matching == 100
    assert len(pkts) == 100
    # Newest packet first: packet_id 150
    assert pkts[0].packet_id == 150
    # Oldest retained packet: packet_id 51
    assert pkts[-1].packet_id == 51


def test_engine_clear_buffer():
    """Verifies clearing packet buffer while preserving cumulative counters."""
    engine = LiveCaptureEngine(
        session_id="test-clear",
        interface_id="test-if",
        interface_name="eth0",
        buffer_limit=100,
    )
    engine.feed_packet_for_testing(MockTcpPacket())
    engine.feed_packet_for_testing(MockUdpDnsPacket())

    assert engine.get_statistics().total_captured == 2
    assert engine.get_statistics().retained_in_buffer == 2

    engine.clear_buffer()
    stats = engine.get_statistics()
    assert stats.total_captured == 2  # Total remains 2
    assert stats.retained_in_buffer == 0


def test_engine_protocol_filter_and_search():
    """Verifies protocol filtering and search on captured packet buffer."""
    engine = LiveCaptureEngine(
        session_id="test-filter",
        interface_id="test-if",
        interface_name="eth0",
        buffer_limit=100,
    )
    engine.feed_packet_for_testing(MockTcpPacket())
    engine.feed_packet_for_testing(MockUdpDnsPacket())
    engine.feed_packet_for_testing(MockArpPacket())

    # Filter TCP
    total_tcp, tcp_pkts = engine.get_packets(protocol="TCP")
    assert total_tcp == 1
    assert tcp_pkts[0].protocol == "TCP"

    # Search IP
    total_search, search_pkts = engine.get_packets(search="google.com")
    assert total_search == 1
    assert search_pkts[0].protocol == "DNS"


# ==================== 5. API ENDPOINTS TESTS ====================

def test_api_capture_status():
    """Tests GET /api/capture/status endpoint."""
    resp = client.get("/api/capture/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "capability_status" in data["data"]


def test_api_capture_interfaces():
    """Tests GET /api/capture/interfaces endpoint."""
    resp = client.get("/api/capture/interfaces")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert isinstance(data["data"], list)
    assert len(data["data"]) > 0


def test_api_session_lifecycle_with_mock_engine():
    """Tests session inspection, packet retrieval, and statistics endpoints."""
    engine = LiveCaptureEngine(
        session_id="mock-session-123",
        interface_id="if-test",
        interface_name="eth0",
        buffer_limit=100,
    )
    engine.feed_packet_for_testing(MockTcpPacket())
    CaptureManager.register_test_engine(engine)

    # 1. Retrieve session
    resp = client.get(f"/api/capture/sessions/{engine.session_id}")
    assert resp.status_code == 200
    assert resp.json()["data"]["session_id"] == engine.session_id

    # 2. Retrieve statistics
    stats_resp = client.get(f"/api/capture/sessions/{engine.session_id}/statistics")
    assert stats_resp.status_code == 200
    assert stats_resp.json()["data"]["total_captured"] == 1

    # 3. Retrieve packets
    pkts_resp = client.get(f"/api/capture/sessions/{engine.session_id}/packets")
    assert pkts_resp.status_code == 200
    assert len(pkts_resp.json()["data"]["packets"]) == 1

    # 4. Clear buffer
    clear_resp = client.post(f"/api/capture/sessions/{engine.session_id}/clear")
    assert clear_resp.status_code == 200
    assert clear_resp.json()["data"]["cleared"] is True


def test_api_bpf_filter_validation():
    """Tests BPF filter resolution and illegal character rejection."""
    assert CaptureManager.resolve_effective_filter("tcp", None) == "tcp"
    assert CaptureManager.resolve_effective_filter("dns", None) == "port 53"
    assert CaptureManager.resolve_effective_filter(None, "host 10.0.0.1") == "host 10.0.0.1"

    # Reject shell injection
    with pytest.raises(ValueError):
        CaptureManager.resolve_effective_filter(None, "port 80; rm -rf /")

