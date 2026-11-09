import ipaddress
import socket
from typing import Dict, List, Optional
import psutil

from backend.app.core.logging import logger
from backend.app.schemas.network import NetworkInterface, NetworkInterfacesData, NetworkSummaryData
from backend.app.schemas.scanner import ScannerStatusData
from backend.app.schemas.traffic import TrafficStatusData


def get_default_gateway_map() -> Dict[str, str]:
    """Dynamically resolves default gateway for active IP interfaces."""
    gw_map: Dict[str, str] = {}
    try:
        from scapy.all import conf
        route_entry = conf.route.route("8.8.8.8")
        if route_entry and len(route_entry) >= 3:
            local_ip = str(route_entry[1])
            gateway_ip = str(route_entry[2])
            if gateway_ip and gateway_ip != "0.0.0.0":
                gw_map[local_ip] = gateway_ip
    except Exception:
        pass
    return gw_map


def classify_interface_type(name: str) -> str:
    """Categorizes interface media type."""
    lower = name.lower()
    if "loopback" in lower:
        return "loopback"
    if any(k in lower for k in ("virtual", "vmware", "vbox", "virtualbox", "hyper-v", "vethernet", "tap", "tun", "vpn", "wsl")):
        return "virtual"
    if any(k in lower for k in ("wi-fi", "wifi", "wlan", "wireless", "ethernet", "realtek", "intel", "gigabit", "broadcom", "eth")):
        return "physical"
    return "unknown"


class NetworkService:
    """Service handling network interface discovery, traffic counters, and engine telemetry."""

    @staticmethod
    def get_network_interfaces() -> NetworkInterfacesData:
        """Inspects OS network interfaces and returns addresses, MACs, subnets, gateways, and operational status."""
        interfaces_list: List[NetworkInterface] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception as e:
            logger.error("Failed to retrieve network interface information from psutil: %s", str(e))
            return NetworkInterfacesData(total_interfaces=0, interfaces=[])

        af_link = getattr(psutil, "AF_LINK", None)
        gw_map = get_default_gateway_map()

        for iface_name, addr_entries in addrs.items():
            ipv4_addr: Optional[str] = None
            ipv6_addr: Optional[str] = None
            mac_addr: Optional[str] = None
            subnet_cidr: Optional[str] = None

            for entry in addr_entries:
                if entry.family == socket.AF_INET:
                    ipv4_addr = entry.address
                    if entry.address and entry.netmask:
                        try:
                            net = ipaddress.IPv4Network(f"{entry.address}/{entry.netmask}", strict=False)
                            subnet_cidr = str(net)
                        except Exception:
                            pass
                elif entry.family == socket.AF_INET6:
                    if entry.address and not entry.address.startswith("fe80"):
                        ipv6_addr = entry.address
                elif af_link is not None and entry.family == af_link:
                    mac_addr = entry.address
                elif str(entry.family) in ("-1", "AF_LINK") or (
                    hasattr(entry, "address") and entry.address and len(entry.address.split("-")) == 6
                ) or (
                    hasattr(entry, "address") and entry.address and len(entry.address.split(":")) == 6
                ):
                    if not mac_addr and entry.family not in (socket.AF_INET, socket.AF_INET6):
                        mac_addr = entry.address

            is_up: Optional[bool] = None
            speed: Optional[int] = None
            if iface_name in stats:
                stat = stats[iface_name]
                is_up = stat.isup
                speed = stat.speed if stat.speed > 0 else None

            gw = gw_map.get(ipv4_addr) if ipv4_addr else None
            itype = classify_interface_type(iface_name)

            interfaces_list.append(
                NetworkInterface(
                    name=iface_name,
                    ipv4_address=ipv4_addr,
                    mac_address=mac_addr,
                    is_up=is_up,
                    speed_mbps=speed,
                    subnet_cidr=subnet_cidr,
                    gateway=gw,
                    ipv6_address=ipv6_addr,
                    interface_type=itype,
                )
            )

        # Sort interfaces so active interfaces with IPv4 appear first
        interfaces_list.sort(
            key=lambda iface: (
                iface.is_up is True,
                iface.ipv4_address is not None,
                iface.gateway is not None,
                iface.name,
            ),
            reverse=True,
        )

        return NetworkInterfacesData(
            total_interfaces=len(interfaces_list),
            interfaces=interfaces_list,
        )

    @staticmethod
    def get_network_summary() -> NetworkSummaryData:
        """Retrieves system-wide cumulative network traffic counters."""
        try:
            counters = psutil.net_io_counters()
            return NetworkSummaryData(
                bytes_sent=counters.bytes_sent,
                bytes_recv=counters.bytes_recv,
                packets_sent=counters.packets_sent,
                packets_recv=counters.packets_recv,
                errin=counters.errin,
                errout=counters.errout,
                dropin=counters.dropin,
                dropout=counters.dropout,
            )
        except Exception as e:
            logger.error("Failed to retrieve network summary counters: %s", str(e))
            return NetworkSummaryData(
                bytes_sent=0,
                bytes_recv=0,
                packets_sent=0,
                packets_recv=0,
            )

    @staticmethod
    def get_scanner_status() -> ScannerStatusData:
        """Returns port scanner availability and supported scan methods."""
        from backend.app.services.scanner_service import ScannerService
        return ScannerService.get_status()

    @staticmethod
    def get_traffic_status() -> TrafficStatusData:
        """Returns packet capture availability and supported protocol analysis."""
        return TrafficStatusData(
            available=False,
            status="standby_phase_1",
            message="Traffic analyzer foundation initialized. Live packet capture engine will be implemented in Phase 2.",
            engine_version="0.1.0-alpha",
            supported_protocols=["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"],
            live_capture_ready=False,
            payload_storage_enabled=False,
        )

