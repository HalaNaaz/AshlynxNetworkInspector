from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.capture.capture_manager import CaptureManager
from backend.app.main import app
from backend.app.schemas.capture import PacketMetadataItem
from backend.app.security.baseline_manager import SessionBaselineManager
from backend.app.security.correlation_engine import CorrelationEngine
from backend.app.security.detection_engine import SecurityDetectionEngine
from backend.app.security.event_manager import EventManager, sanitize_text
from backend.app.security.risk_scorer import RiskScorer
from backend.app.security.rules.connection_anomaly import ConnectionChurnRule, RepeatedRstRule
from backend.app.security.rules.dns_anomaly import DnsLongDomainRule, DnsNxdomainSurgeRule, DnsQueryBurstRule
from backend.app.security.rules.port_scan import HorizontalPortScanRule, SynHeavyReconRule, VerticalPortScanRule
from backend.app.security.rules.suspicious_ports import SuspiciousServiceRule
from backend.app.security.rules.traffic_spike import TrafficSpikeRule


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
        session_id="test-sec-session",
    )


def test_risk_scorer_bounds_and_severity():
    """Verifies that risk score is strictly bounded [0, 100] and maps to valid bands."""
    for sev in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        score, band = RiskScorer.calculate_risk_score(sev, confidence=0.8, observed_ratio=1.5)
        assert 0 <= score <= 100
        assert band in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    # High ratio and correlation caps cleanly at 100
    score, band = RiskScorer.calculate_risk_score("CRITICAL", confidence=1.0, observed_ratio=100.0, is_correlated=True)
    assert score <= 100
    assert band == "CRITICAL"


def test_baseline_manager_warmup_and_activation():
    """Verifies baseline states: WARMING_UP (< 10 samples) vs ACTIVE (>= 10 samples)."""
    bm = SessionBaselineManager("test-session", min_samples=5)
    assert bm.status == "WARMING_UP"
    assert bm.is_ready() is False

    for i in range(4):
        bm.feed_sample(bps=100000, pps=50)
    assert bm.status == "WARMING_UP"
    assert bm.is_ready() is False

    bm.feed_sample(bps=120000, pps=60)
    assert bm.status == "ACTIVE"
    assert bm.is_ready() is True
    stats = bm.get_stats()
    assert stats["samples"] == 5
    assert stats["mean_bps"] > 0


def test_vertical_port_scan_detection():
    """Verifies vertical port scan detection when one source probes multiple ports on one host."""
    rule = VerticalPortScanRule()
    rule.threshold = 5.0  # 5 ports for testing

    events = []
    for port in range(1, 7):
        pkt = make_packet(port, "TCP", "10.0.0.99", "192.168.1.50", 40000 + port, port, tcp_flags="SYN")
        res = rule.evaluate(pkt, "test-session")
        if res:
            events.append(res)

    assert len(events) >= 1
    ev = events[0]
    assert ev.rule_id == "RULE_PORT_SCAN_VERTICAL"
    assert ev.source_ip == "10.0.0.99"
    assert ev.destination_ip == "192.168.1.50"
    assert ev.category == "PORT_SCAN"
    assert len(ev.related_ports) >= 5


def test_horizontal_port_scan_detection():
    """Verifies horizontal port scan detection when one source probes the same port on multiple hosts."""
    rule = HorizontalPortScanRule()
    rule.threshold = 4.0

    events = []
    for i in range(1, 6):
        pkt = make_packet(i, "TCP", "10.0.0.88", f"192.168.1.{i}", 50000, 22, tcp_flags="SYN")
        res = rule.evaluate(pkt, "test-session")
        if res:
            events.append(res)

    assert len(events) >= 1
    ev = events[0]
    assert ev.rule_id == "RULE_PORT_SCAN_HORIZONTAL"
    assert ev.source_ip == "10.0.0.88"
    assert ev.target_port == 22


def test_syn_heavy_recon_detection():
    """Verifies detection of repeated standalone SYN packets."""
    rule = SynHeavyReconRule()
    rule.threshold = 5.0

    events = []
    for i in range(1, 7):
        pkt = make_packet(i, "TCP", "10.0.0.77", "192.168.1.10", 40000 + i, 8080, tcp_flags="SYN")
        res = rule.evaluate(pkt, "test-session")
        if res:
            events.append(res)

    assert len(events) >= 1
    ev = events[0]
    assert ev.rule_id == "RULE_SYN_RECON"
    assert ev.source_ip == "10.0.0.77"


def test_repeated_rst_detection():
    """Verifies detection of TCP RST flood/rejection storm."""
    rule = RepeatedRstRule()
    rule.threshold = 5.0

    events = []
    for i in range(1, 7):
        pkt = make_packet(i, "TCP", "192.168.1.200", "10.0.0.1", 80, 50000 + i, tcp_flags="RST, ACK")
        res = rule.evaluate(pkt, "test-session")
        if res:
            events.append(res)

    assert len(events) >= 1
    ev = events[0]
    assert ev.rule_id == "RULE_REPEATED_RST"
    assert ev.source_ip == "192.168.1.200"


def test_connection_churn_detection():
    """Verifies rapid connection creation/churn detection."""
    rule = ConnectionChurnRule()
    rule.threshold = 6.0

    events = []
    for i in range(1, 8):
        pkt = make_packet(i, "TCP", "10.0.0.66", f"1.1.1.{i}", 30000 + i, 443, tcp_flags="SYN")
        res = rule.evaluate(pkt, "test-session")
        if res:
            events.append(res)

    assert len(events) >= 1
    ev = events[0]
    assert ev.rule_id == "RULE_CONNECTION_CHURN"
    assert ev.source_ip == "10.0.0.66"
    assert len(ev.related_ips) >= 6


def test_traffic_spike_with_baseline():
    """Verifies traffic spike detection only triggers when baseline is active and throughput exceeds threshold."""
    rule = TrafficSpikeRule()
    rule.threshold = 2.0
    bm = SessionBaselineManager("test-session", min_samples=3)

    # 1. Warm-up state: no alert
    for _ in range(2):
        bm.feed_sample(bps=100_000, pps=50)

    pkt_huge = make_packet(1, "TCP", "10.0.0.5", "10.0.0.1", length=500_000)
    assert rule.evaluate(pkt_huge, "test-session", baseline_manager=bm) is None

    # 2. Activate baseline
    bm.feed_sample(bps=100_000, pps=50)
    assert bm.is_ready() is True

    # 3. Huge traffic packet exceeding 2x mean baseline
    ev = rule.evaluate(pkt_huge, "test-session", baseline_manager=bm)
    assert ev is not None
    assert ev.rule_id == "RULE_TRAFFIC_SPIKE"
    assert ev.category == "TRAFFIC_SPIKE"


def test_dns_anomalies():
    """Verifies DNS query burst, NXDOMAIN surge, and long domain detection."""
    burst_rule = DnsQueryBurstRule()
    burst_rule.threshold = 4.0
    burst_events = []
    for i in range(1, 6):
        pkt = make_packet(i, "DNS", "10.0.0.44", "8.8.8.8", 50000 + i, 53, dns_summary="Query: test.org")
        res = burst_rule.evaluate(pkt, "test-session")
        if res:
            burst_events.append(res)
    assert len(burst_events) >= 1
    assert burst_events[0].rule_id == "RULE_DNS_QUERY_BURST"

    nx_rule = DnsNxdomainSurgeRule()
    nx_rule.threshold = 3.0
    nx_events = []
    for i in range(1, 5):
        pkt = make_packet(i, "DNS", "8.8.8.8", "10.0.0.44", 53, 50000 + i, dns_summary="Response (rcode=3)")
        res = nx_rule.evaluate(pkt, "test-session")
        if res:
            nx_events.append(res)
    assert len(nx_events) >= 1
    assert nx_events[0].rule_id == "RULE_DNS_NXDOMAIN_SURGE"

    long_rule = DnsLongDomainRule()
    long_rule.threshold = 30.0
    pkt_long = make_packet(
        10,
        "DNS",
        "10.0.0.44",
        "8.8.8.8",
        50000,
        53,
        dns_summary="Query: abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz.org",
    )
    ev_long = long_rule.evaluate(pkt_long, "test-session")
    assert ev_long is not None
    assert ev_long.rule_id == "RULE_DNS_LONG_DOMAIN"


def test_suspicious_service_rule():
    """Verifies that traffic to sensitive ports (SSH 22, SMB 445, RDP 3389) is flagged with inferred attribution."""
    rule = SuspiciousServiceRule()
    pkt_rdp = make_packet(1, "TCP", "10.0.0.33", "192.168.1.100", 54321, 3389)
    ev = rule.evaluate(pkt_rdp, "test-session")
    assert ev is not None
    assert ev.rule_id == "RULE_SUSPICIOUS_SERVICE"
    assert ev.target_port == 3389
    assert "Inferred" in ev.detection_name


def test_correlation_engine():
    """Verifies orthogonal multi-vector correlation elevates risk score and sets correlation_id."""
    ce = CorrelationEngine(window_seconds=30)
    rule_v = VerticalPortScanRule()
    rule_v.threshold = 2.0
    ev1 = rule_v.evaluate(make_packet(1, "TCP", "10.0.0.22", "192.168.1.5", 50001, 80, tcp_flags="SYN"), "test-session")
    ev1 = rule_v.evaluate(make_packet(2, "TCP", "10.0.0.22", "192.168.1.5", 50002, 81, tcp_flags="SYN"), "test-session")
    assert ev1 is not None

    corr1 = ce.correlate(ev1)
    assert corr1.correlation_id is None  # Single rule so far

    # Add different orthogonal rule (SUSPICIOUS_SERVICE) on same source
    rule_s = SuspiciousServiceRule()
    ev2 = rule_s.evaluate(make_packet(3, "TCP", "10.0.0.22", "192.168.1.100", 50003, 445), "test-session")
    assert ev2 is not None

    corr2 = ce.correlate(ev2)
    assert corr2.correlation_id is not None
    assert "CORR-10.0.0.22" in corr2.correlation_id
    assert corr2.risk_score >= ev2.risk_score  # Elevation applied
    assert "Correlated across 2 independent security categories" in corr2.evidence_summary


def test_correlation_coupled_rules_no_risk_inflation():
    """Verifies that coupled transport rules (Horizontal Scan + Connection Churn) do NOT escalate risk score."""
    ce = CorrelationEngine(window_seconds=30)

    # 1. Horizontal scan event
    rule_h = HorizontalPortScanRule()
    rule_h.threshold = 2.0
    ev1 = rule_h.evaluate(make_packet(1, "TCP", "10.0.0.99", "1.1.1.1", 50001, 22, tcp_flags="SYN"), "test-session")
    ev1 = rule_h.evaluate(make_packet(2, "TCP", "10.0.0.99", "1.1.1.2", 50002, 22, tcp_flags="SYN"), "test-session")
    assert ev1 is not None
    ce.correlate(ev1)

    # 2. Connection churn event on same source
    rule_c = ConnectionChurnRule()
    rule_c.threshold = 2.0
    ev2 = rule_c.evaluate(make_packet(3, "TCP", "10.0.0.99", "2.2.2.1", 50003, 80, tcp_flags="SYN"), "test-session")
    ev2 = rule_c.evaluate(make_packet(4, "TCP", "10.0.0.99", "2.2.2.2", 50004, 80, tcp_flags="SYN"), "test-session")
    assert ev2 is not None
    orig_risk = ev2.risk_score

    corr2 = ce.correlate(ev2)
    assert corr2.correlation_id is not None
    assert "CORR-10.0.0.99" in corr2.correlation_id
    # Risk score must remain unescalated for purely coupled transport rules
    assert corr2.risk_score == orig_risk
    assert "risk unescalated to prevent co-dependent inflation" in corr2.evidence_summary


def test_event_manager_lifecycle_and_notes():
    """Verifies event lifecycle transitions, analyst note sanitization, and audit history."""
    em = EventManager(max_events=10)
    rule = SuspiciousServiceRule()
    ev = rule.evaluate(make_packet(1, "TCP", "10.0.0.11", "192.168.1.1", 50000, 22), "session-alpha")
    assert ev is not None

    em.record_event(ev)
    eid = ev.event_id

    # 1. Update status to INVESTIGATING
    updated = em.update_status(eid, "INVESTIGATING", analyst_name="Senior Analyst")
    assert updated.status == "INVESTIGATING"
    assert any("Senior Analyst" in log for log in updated.audit_trail)

    # 2. Add note with attempted script injection
    bad_note = "<script>alert('pwned')</script>Investigating SSH probe from dev host."
    updated = em.add_note(eid, bad_note, author="Analyst A")
    assert "<script>" not in updated.analyst_notes[0]
    assert "Investigating SSH probe from dev host." in updated.analyst_notes[0]

    # 3. Resolve event
    updated = em.update_status(eid, "RESOLVED", analyst_name="Senior Analyst")
    assert updated.status == "RESOLVED"


def test_api_security_endpoints_and_validation():
    """Tests FastAPI router endpoints for /api/security/."""
    client = TestClient(app)

    # 1. 404 when no session active
    r404 = client.get("/api/security/events?session_id=nonexistent")
    assert r404.status_code == 404

    # 2. Setup mock security engine
    engine = SecurityDetectionEngine("mock-sec-session")
    rule = SuspiciousServiceRule()
    ev = rule.evaluate(make_packet(1, "TCP", "10.0.0.5", "192.168.1.1", 50000, 3389), "mock-sec-session")
    assert ev is not None
    engine.event_manager.record_event(ev)

    class MockCaptureWrapper:
        def __init__(self, eng):
            self.security_engine = eng

    CaptureManager._sessions["mock-sec-session"] = MockCaptureWrapper(engine)

    try:
        # Overview
        r = client.get("/api/security/overview?session_id=mock-sec-session")
        assert r.status_code == 200
        ov = r.json()
        assert ov["status"]["total_events_detected"] >= 1

        # Events list
        r = client.get("/api/security/events?session_id=mock-sec-session")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 1
        eid = data["events"][0]["event_id"]

        # Single event
        r = client.get(f"/api/security/events/{eid}")
        assert r.status_code == 200

        # Update status
        r = client.patch(
            f"/api/security/events/{eid}/status",
            json={"status": "INVESTIGATING", "analyst_name": "Test Analyst"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "INVESTIGATING"

        # Invalid status 422
        r_bad = client.patch(f"/api/security/events/{eid}/status", json={"status": "MALICIOUS_STATUS"})
        assert r_bad.status_code == 422

        # Add note
        r = client.post(
            f"/api/security/events/{eid}/notes",
            json={"note": "Verified authorized test traffic.", "author": "Test Analyst"},
        )
        assert r.status_code == 200

        # Rules list
        r = client.get("/api/security/rules")
        assert r.status_code == 200
        rules = r.json()
        assert len(rules) >= 5

        # Update rule
        target_rule = rules[0]["rule_id"]
        r = client.patch(
            f"/api/security/rules/{target_rule}",
            json={"threshold": 20.0, "window_seconds": 15},
        )
        assert r.status_code == 200
        assert r.json()["threshold"] == 20.0

        # Timeline
        r = client.get("/api/security/timeline?session_id=mock-sec-session")
        assert r.status_code == 200
    finally:
        CaptureManager._sessions.pop("mock-sec-session", None)


def test_browser_https_traffic_no_false_positive_horizontal_scan():
    """Verifies that ordinary browser HTTPS traffic (12 distinct CDN hosts with ACK/data transfers)
    does NOT trigger a false positive Horizontal Port Sweep event.
    """
    rule = HorizontalPortScanRule()
    assert rule.web_port_threshold == 20.0

    # 1. Simulate 12 distinct CDN hosts with established data transfers (ACK)
    events = []
    for i in range(1, 13):
        pkt = make_packet(i, "TCP", "192.168.29.59", f"142.250.190.{i}", 50000 + i, 443, tcp_flags="ACK")
        ev = rule.evaluate(pkt, "test-session")
        if ev:
            events.append(ev)
    assert len(events) == 0  # Zero alerts on established data packets

    # 2. Simulate 12 distinct CDN hosts with initial SYNs (below web threshold 20)
    for i in range(1, 13):
        pkt = make_packet(100 + i, "TCP", "192.168.29.59", f"142.250.190.{i}", 51000 + i, 443, tcp_flags="SYN")
        ev = rule.evaluate(pkt, "test-session")
        if ev:
            events.append(ev)
    assert len(events) == 0  # 12 SYNs does not exceed web_port_threshold (20.0)


def test_genuine_horizontal_scan_on_port_443():
    """Verifies that a genuine aggressive port sweep on port 443 (>= 20 target hosts with SYN)
    triggers an alert with multi-destination evidence preserved.
    """
    rule = HorizontalPortScanRule()
    rule.web_port_threshold = 20.0

    events = []
    for i in range(1, 23):
        pkt = make_packet(i, "TCP", "10.0.0.88", f"192.168.1.{i}", 50000 + i, 443, tcp_flags="SYN")
        ev = rule.evaluate(pkt, "test-session")
        if ev:
            events.append(ev)

    assert len(events) >= 1
    ev = events[0]
    assert ev.rule_id == "RULE_PORT_SCAN_HORIZONTAL"
    assert ev.target_port == 443
    assert ev.destination_ip is None
    assert len(ev.related_ips) >= 20
    assert "192.168.1.1" in ev.related_ips
    assert "192.168.1.20" in ev.related_ips
    assert "sampled targets:" in ev.evidence_summary


def test_connection_churn_flow_vs_packet_separation():
    """Verifies that high packet volume on an existing flow does NOT trigger connection churn,
    while rapid creation of distinct new flows does.
    """
    rule = ConnectionChurnRule()
    rule.threshold = 10.0

    # 1. 50 data packets on the SAME single flow (10.0.0.5 -> 1.1.1.1:443 with ACK)
    events = []
    for i in range(1, 51):
        pkt = make_packet(i, "TCP", "10.0.0.5", "1.1.1.1", 54321, 443, tcp_flags="ACK")
        ev = rule.evaluate(pkt, "test-session")
        if ev:
            events.append(ev)
    assert len(events) == 0  # Zero churn alerts on data stream

    # 2. 12 distinct new connection initiations with SYN
    for i in range(1, 13):
        pkt = make_packet(100 + i, "TCP", "10.0.0.5", f"1.1.1.{i}", 50000 + i, 443, tcp_flags="SYN")
        ev = rule.evaluate(pkt, "test-session")
        if ev:
            events.append(ev)
    assert len(events) >= 1
    assert events[0].rule_id == "RULE_CONNECTION_CHURN"
    assert len(events[0].related_ips) >= 10


def test_baseline_dependent_vs_independent_rules():
    """Verifies that RuleEngine properly suppresses baseline-dependent rules (TrafficSpikeRule)
    during WARMING_UP, while executing baseline-independent deterministic rules (SuspiciousServiceRule).
    """
    engine = SecurityDetectionEngine(session_id="test-baseline-session")
    assert engine.baseline_manager.status == "WARMING_UP"

    # 1. Massive volume packet that would exceed threshold if baseline were active
    pkt_vol = make_packet(1, "TCP", "10.0.0.1", "10.0.0.2", 50000, 80, length=500_000)
    evs = engine.process_packet(pkt_vol)
    # Traffic spike must not trigger because baseline is WARMING_UP
    assert not any(e.rule_id == "RULE_TRAFFIC_SPIKE" for e in evs)

    # 2. Deterministic sensitive port packet (port 445 SMB) evaluated immediately
    pkt_smb = make_packet(2, "TCP", "10.0.0.1", "10.0.0.2", 50001, 445)
    evs_smb = engine.process_packet(pkt_smb)
    assert any(e.rule_id == "RULE_SUSPICIOUS_SERVICE" for e in evs_smb)


def test_multiple_destination_evidence_integrity():
    """Verifies that horizontal scans and connection churn accurately report distinct destination IPs
    and never invent or display null destination addresses.
    """
    rule = HorizontalPortScanRule()
    rule.threshold = 5.0
    targets = [f"10.20.30.{i}" for i in range(1, 7)]

    events = []
    for i, tgt in enumerate(targets):
        pkt = make_packet(i, "TCP", "10.0.0.99", tgt, 40000 + i, 22, tcp_flags="SYN")
        ev = rule.evaluate(pkt, "test-session")
        if ev:
            events.append(ev)

    assert len(events) >= 1
    ev = events[0]
    # Check that related_ips preserves all distinct targets
    for tgt in targets[:5]:
        assert tgt in ev.related_ips
    assert ev.destination_ip is None  # Multi-target representation
    assert str(len(ev.related_ips)) in ev.observed_value

