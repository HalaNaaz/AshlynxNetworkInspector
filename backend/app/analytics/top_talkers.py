import ipaddress
import threading
from typing import Dict, List, Optional, Set
from backend.app.schemas.analytics import TopTalkerItem, TopTalkersResponse
from backend.app.schemas.capture import PacketMetadataItem


def classify_ip_category(ip_str: str) -> str:
    """Classifies an IP address into distinct network scopes without conflating categories."""
    clean = (ip_str or "").strip()
    if not clean:
        return "RESERVED"
    if clean in ("255.255.255.255", "0.0.0.0"):
        return "BROADCAST" if clean == "255.255.255.255" else "RESERVED"
    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_loopback:
            return "LOOPBACK"
        if ip.is_multicast:
            return "MULTICAST"
        if ip.is_link_local:
            return "LINK_LOCAL"
        if ip.is_private:
            return "RFC1918_PRIVATE"
        if ip.is_reserved:
            return "RESERVED"
        return "PUBLIC_ROUTABLE"
    except ValueError:
        return "RESERVED"


def is_private_ip(ip_str: str) -> bool:
    """Returns True if IP address is RFC1918, loopback, or link-local."""
    cat = classify_ip_category(ip_str)
    return cat in ("RFC1918_PRIVATE", "LOOPBACK", "LINK_LOCAL")


class EndpointStats:
    """Accumulates volume and transmission metrics for an IP address."""

    def __init__(self, ip: str, is_local: bool):
        self.ip = ip
        self.packet_count = 0
        self.byte_count = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.ip_category = classify_ip_category(ip)
        self.is_private = self.ip_category in ("RFC1918_PRIVATE", "LOOPBACK", "LINK_LOCAL")
        self.is_local_host = is_local


class TopTalkersAnalyzer:
    """Tracks and ranks top bandwidth consumers across source, destination, and combined streams."""

    def __init__(self, session_id: str, interface_ips: Optional[Set[str]] = None, max_endpoints: int = 1000):
        self.session_id = session_id
        self.interface_ips: Set[str] = {ip.strip() for ip in (interface_ips or set()) if ip and ip.strip()}
        self.max_endpoints = max_endpoints
        self._lock = threading.Lock()

        self.total_packets = 0
        self.total_bytes = 0

        self._sources: Dict[str, EndpointStats] = {}
        self._destinations: Dict[str, EndpointStats] = {}
        self._combined: Dict[str, EndpointStats] = {}

    def process_packet(self, meta: PacketMetadataItem) -> None:
        """Updates talker statistics from a packet metadata item with bounded capacity."""
        src = (meta.src_ip or "").strip()
        dst = (meta.dst_ip or "").strip()
        length = meta.length

        with self._lock:
            self.total_packets += 1
            self.total_bytes += length

            if src:
                if src not in self._sources and len(self._sources) < self.max_endpoints:
                    self._sources[src] = EndpointStats(src, src in self.interface_ips)
                if src in self._sources:
                    self._sources[src].packet_count += 1
                    self._sources[src].byte_count += length
                    self._sources[src].bytes_sent += length

                if src not in self._combined and len(self._combined) < self.max_endpoints:
                    self._combined[src] = EndpointStats(src, src in self.interface_ips)
                if src in self._combined:
                    self._combined[src].packet_count += 1
                    self._combined[src].byte_count += length
                    self._combined[src].bytes_sent += length

            if dst:
                if dst not in self._destinations and len(self._destinations) < self.max_endpoints:
                    self._destinations[dst] = EndpointStats(dst, dst in self.interface_ips)
                if dst in self._destinations:
                    self._destinations[dst].packet_count += 1
                    self._destinations[dst].byte_count += length
                    self._destinations[dst].bytes_received += length

                if dst not in self._combined and len(self._combined) < self.max_endpoints:
                    self._combined[dst] = EndpointStats(dst, dst in self.interface_ips)
                if dst in self._combined:
                    self._combined[dst].packet_count += 1
                    self._combined[dst].byte_count += length
                    self._combined[dst].bytes_received += length

    def _build_items(self, stats_dict: Dict[str, EndpointStats], limit: int) -> List[TopTalkerItem]:
        sorted_stats = sorted(stats_dict.values(), key=lambda s: s.byte_count, reverse=True)[:limit]
        items: List[TopTalkerItem] = []
        for s in sorted_stats:
            # Participation percentage represents volume involving this IP relative to total wire volume
            pct = round((s.byte_count / self.total_bytes * 100.0), 2) if self.total_bytes > 0 else 0.0
            items.append(
                TopTalkerItem(
                    ip_address=s.ip,
                    hostname=None,
                    packet_count=s.packet_count,
                    byte_count=s.byte_count,
                    bytes_sent=s.bytes_sent,
                    bytes_received=s.bytes_received,
                    percentage=pct,
                    is_private=s.is_private,
                    ip_category=s.ip_category,
                    is_local_host=s.is_local_host,
                )
            )
        return items

    def get_top_talkers(self) -> TopTalkersResponse:
        """Returns the top talkers ranking."""
        with self._lock:
            top_src = self._build_items(self._sources, 5)
            top_dst = self._build_items(self._destinations, 5)
            top_comb = self._build_items(self._combined, 10)

            return TopTalkersResponse(
                session_id=self.session_id,
                total_unique_ips=len(self._combined),
                top_sources=top_src,
                top_destinations=top_dst,
                top_combined=top_comb,
            )
