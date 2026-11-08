import socket
from typing import List, Optional
import psutil

from backend.app.core.logging import logger
from backend.app.schemas.network import NetworkInterface, NetworkInterfacesData, NetworkSummaryData
from backend.app.schemas.scanner import ScannerStatusData
from backend.app.schemas.traffic import TrafficStatusData


class NetworkService:
    """Service handling network interface discovery, traffic counters, and engine telemetry."""

    @staticmethod
    def get_network_interfaces() -> NetworkInterfacesData:
        """Inspects OS network interfaces and returns addresses, MACs, and operational status."""
        interfaces_list: List[NetworkInterface] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception as e:
            logger.error("Failed to retrieve network interface information from psutil: %s", str(e))
            return NetworkInterfacesData(total_interfaces=0, interfaces=[])

        # Link layer address constant for MAC addresses
        af_link = getattr(psutil, "AF_LINK", None)

        for iface_name, addr_entries in addrs.items():
            ipv4_addr: Optional[str] = None
            mac_addr: Optional[str] = None

            for entry in addr_entries:
                # Check for IPv4
                if entry.family == socket.AF_INET:
                    ipv4_addr = entry.address
                # Check for MAC address (AF_LINK or family == -1 on some Windows builds)
                elif af_link is not None and entry.family == af_link:
                    mac_addr = entry.address
                elif str(entry.family) in ("-1", "AF_LINK") or (
                    hasattr(entry, "address") and entry.address and len(entry.address.split("-")) == 6
                ) or (
                    hasattr(entry, "address") and entry.address and len(entry.address.split(":")) == 6
                ):
                    if not mac_addr and entry.family != socket.AF_INET and entry.family != socket.AF_INET6:
                        mac_addr = entry.address

            is_up: Optional[bool] = None
            speed: Optional[int] = None
            if iface_name in stats:
                stat = stats[iface_name]
                is_up = stat.isup
                speed = stat.speed if stat.speed > 0 else None

            interfaces_list.append(
                NetworkInterface(
                    name=iface_name,
                    ipv4_address=ipv4_addr,
                    mac_address=mac_addr,
                    is_up=is_up,
                    speed_mbps=speed,
                )
            )

        # Sort interfaces so active interfaces with IPv4 appear first
        interfaces_list.sort(
            key=lambda iface: (
                iface.is_up is True,
                iface.ipv4_address is not None,
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

