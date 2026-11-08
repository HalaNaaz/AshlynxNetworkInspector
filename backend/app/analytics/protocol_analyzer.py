import threading
from typing import Dict, List
from backend.app.schemas.analytics import (
    ApplicationProtocolItem,
    ProtocolAnalyticsResponse,
    ProtocolDistributionItem,
)
from backend.app.schemas.capture import PacketMetadataItem


class ProtocolAnalyzer:
    """Analyzes Layer 3/4 transport protocols with zero double-counting,

    and identifies common application protocols independently.
    """

    SUPPORTED_TRANSPORTS = ("TCP", "UDP", "ICMP", "ARP", "OTHER")

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0

        # Transport counts and bytes (strict exclusive partition)
        self._transport_packets: Dict[str, int] = {k: 0 for k in self.SUPPORTED_TRANSPORTS}
        self._transport_bytes: Dict[str, int] = {k: 0 for k in self.SUPPORTED_TRANSPORTS}

        # Application layer tracking (non-additive to transport partition)
        # key: (app_name, transport) -> {"packets": int, "bytes": int}
        self._app_protocols: Dict[tuple, Dict[str, int]] = {}

    def process_packet(self, meta: PacketMetadataItem) -> None:
        """Processes a single captured packet metadata item."""
        with self._lock:
            self.total_packets += 1
            self.total_bytes += meta.length

            # 1. Transport classification (Exclusive partition)
            proto_upper = (meta.protocol or "OTHER").upper()
            if proto_upper == "TCP":
                transport = "TCP"
            elif proto_upper in ("UDP", "DNS"):
                transport = "UDP"
            elif proto_upper in ("ICMP", "ICMPV6"):
                transport = "ICMP"
            elif proto_upper == "ARP":
                transport = "ARP"
            else:
                transport = "OTHER"

            self._transport_packets[transport] += 1
            self._transport_bytes[transport] += meta.length

            # 2. Application layer identification (Inferred from standard ports/headers)
            app_name = None
            if proto_upper == "DNS" or meta.src_port == 53 or meta.dst_port == 53:
                app_name = "DNS"
            elif meta.src_port == 443 or meta.dst_port == 443:
                app_name = "HTTPS / TLS" if transport == "TCP" else "QUIC / HTTP3"
            elif meta.src_port == 80 or meta.dst_port == 80:
                app_name = "HTTP"
            elif meta.src_port in (67, 68) or meta.dst_port in (67, 68):
                app_name = "DHCP"
            elif meta.src_port == 123 or meta.dst_port == 123:
                app_name = "NTP"
            elif meta.src_port == 22 or meta.dst_port == 22:
                app_name = "SSH"

            if app_name:
                key = (app_name, transport)
                if key not in self._app_protocols:
                    self._app_protocols[key] = {"packets": 0, "bytes": 0}
                self._app_protocols[key]["packets"] += 1
                self._app_protocols[key]["bytes"] += meta.length

    def get_distribution(self) -> ProtocolAnalyticsResponse:
        """Returns protocol distribution with guaranteed zero double-counting."""
        with self._lock:
            transport_items: List[ProtocolDistributionItem] = []
            for transport in self.SUPPORTED_TRANSPORTS:
                pkts = self._transport_packets[transport]
                b = self._transport_bytes[transport]
                pct = round((pkts / self.total_packets * 100.0), 2) if self.total_packets > 0 else 0.0
                transport_items.append(
                    ProtocolDistributionItem(
                        protocol=transport,
                        packet_count=pkts,
                        byte_count=b,
                        percentage=pct,
                    )
                )

            app_items: List[ApplicationProtocolItem] = []
            for (name, transport), stats in sorted(
                self._app_protocols.items(), key=lambda kv: kv[1]["packets"], reverse=True
            ):
                app_items.append(
                    ApplicationProtocolItem(
                        name=name,
                        packet_count=stats["packets"],
                        byte_count=stats["bytes"],
                        transport_layer=transport,
                        is_inferred=True,
                    )
                )

            return ProtocolAnalyticsResponse(
                session_id=self.session_id,
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                transport_distribution=transport_items,
                application_breakdown=app_items,
            )

