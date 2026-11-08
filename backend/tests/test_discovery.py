import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.discovery.host_discovery import (
    discover_hosts_concurrent,
    is_ip_loopback,
    probe_arp,
    probe_single_host,
    resolve_reverse_dns,
)
from backend.app.main import app
from backend.app.services.discovery_service import DiscoveryService

client = TestClient(app)


def test_cidr_validation_loopback():
    """Tests CIDR parsing and authorization for loopback and RFC-1918."""
    valid, net, is_auth, err = DiscoveryService.parse_and_validate_cidr("127.0.0.1/32")
    assert valid is True
    assert is_auth is True
    assert net is not None
    assert str(net) == "127.0.0.1/32"

    valid2, net2, is_auth2, err2 = DiscoveryService.parse_and_validate_cidr("192.168.1.0/24")
    assert valid2 is True
    assert is_auth2 is True
    assert net2 is not None


def test_cidr_validation_unauthorized_public():
    """Tests rejection of public IP subnets outside safe-mode boundaries."""
    valid, net, is_auth, err = DiscoveryService.parse_and_validate_cidr("8.8.8.0/24")
    assert valid is False
    assert is_auth is False
    assert "outside authorized safe-mode boundaries" in (err or "")


def test_cidr_validation_malformed():
    """Tests rejection of malformed or invalid CIDR syntax."""
    valid, net, is_auth, err = DiscoveryService.parse_and_validate_cidr("invalid-cidr-string")
    assert valid is False
    assert net is None


def test_probe_single_host_loopback():
    """Tests probing localhost address with AUTO and TCP_CONNECT methods."""
    res_tcp = probe_single_host("127.0.0.1", method="TCP_CONNECT", timeout=0.5)
    assert res_tcp.ip_address == "127.0.0.1"
    assert res_tcp.status in ("ONLINE", "NO_RESPONSE")

    res_auto = probe_single_host("127.0.0.1", method="AUTO", timeout=0.5)
    assert res_auto.ip_address == "127.0.0.1"
    assert res_auto.status == "ONLINE"
    # Never claim ARP for loopback
    assert res_auto.discovery_method != "ARP"
    assert res_auto.discovery_method in ("LOOPBACK", "TCP_CONNECT", "ICMP_ECHO")


def test_loopback_discovery_no_fake_mac():
    """Verifies loopback discovery never reports an all-zero MAC address."""
    res = probe_single_host("127.0.0.1", method="AUTO", timeout=0.5)
    assert res.mac_address is None
    assert res.mac_address != "00:00:00:00:00:00"


def test_arp_loopback_rejection():
    """Verifies probe_arp rejects loopback and returns False."""
    is_online, mac, lat = probe_arp("127.0.0.1")
    assert is_online is False
    assert mac is None


def test_reverse_dns_resolution_and_source():
    """Tests reverse DNS source representation (SYSTEM_LOOPBACK or HOSTS_FILE)."""
    hostname, source = resolve_reverse_dns("127.0.0.1")
    assert source in ("SYSTEM_LOOPBACK", "HOSTS_FILE")
    assert hostname in ("localhost", "ashlnx.com") or isinstance(hostname, str)


def test_reverse_dns_failure_handling():
    """Tests that unresolvable IPs return Unresolved and UNRESOLVED source."""
    # Test Documentation-net IP (RFC 5737)
    hostname, source = resolve_reverse_dns("192.0.2.1")
    assert hostname == "Unresolved"
    assert source == "UNRESOLVED"


def test_discovery_concurrent_sweep():
    """Tests concurrent discovery execution over a small IP list."""
    ips = ["127.0.0.1"]
    findings = discover_hosts_concurrent(ips, method="TCP_CONNECT", timeout=0.3, concurrency=2)
    assert len(findings) == 1
    assert findings[0].ip_address == "127.0.0.1"


def test_utc_timestamp_serialization():
    """Verifies that discovery timestamps are timezone-aware in UTC."""
    res = probe_single_host("127.0.0.1", method="AUTO", timeout=0.5)
    assert res.first_seen.tzinfo is not None
    assert res.first_seen.tzinfo == timezone.utc


def test_discovery_api_status():
    """Tests GET /api/discovery/status endpoint."""
    resp = client.get("/api/discovery/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["data"]["available"] is True
    assert data["data"]["status"] == "operational"


def test_discovery_api_validate():
    """Tests POST /api/discovery/validate endpoint."""
    resp = client.post("/api/discovery/validate", json={"cidr": "127.0.0.1/32"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["data"]["valid"] is True
    assert data["data"]["total_usable_hosts"] == 1


def test_discovery_api_scan_workflow():
    """Tests full lifecycle: POST /api/discovery/scan, GET by id, history, and latest."""
    resp = client.post(
        "/api/discovery/scan",
        json={"cidr": "127.0.0.1/32", "method": "TCP_CONNECT", "timeout": 0.5, "concurrency": 2},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    discovery_id = data["data"]["discovery_id"]
    assert discovery_id is not None
    assert data["data"]["total_probed"] == 1

    # Verify no fake MAC returned
    hosts = data["data"]["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["mac_address"] is None or hosts[0]["mac_address"] != "00:00:00:00:00:00"

    # Retrieve by ID
    id_resp = client.get(f"/api/discovery/scans/{discovery_id}")
    assert id_resp.status_code == 200
    assert id_resp.json()["data"]["discovery_id"] == discovery_id

    # Retrieve history
    hist_resp = client.get("/api/discovery/history")
    assert hist_resp.status_code == 200
    hist_items = hist_resp.json()["data"]
    assert len(hist_items) >= 1
    assert hist_items[0]["discovery_id"] == discovery_id

    # Retrieve latest
    latest_resp = client.get("/api/discovery/latest")
    assert latest_resp.status_code == 200
    assert latest_resp.json()["data"]["discovery_id"] == discovery_id
