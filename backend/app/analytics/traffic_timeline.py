import collections
import threading
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Set
from backend.app.schemas.analytics import TrafficTimelinePoint, TrafficTimelineResponse
from backend.app.schemas.capture import PacketMetadataItem


class SecondTimelineBucket:
    """Timeline stats for a single integer second."""

    def __init__(self, timestamp: datetime, second_offset: int):
        self.timestamp = timestamp
        self.second_offset = second_offset
        self.packets_total = 0
        self.bytes_total = 0
        self.tcp_bytes = 0
        self.udp_bytes = 0
        self.icmp_bytes = 0
        self.arp_bytes = 0
        self.other_bytes = 0
        self.inbound_bytes = 0
        self.outbound_bytes = 0
        self.local_bytes = 0
        self.unknown_bytes = 0


class TrafficTimeline:
    """Aggregates second-by-second time-series metrics for visualization."""

    def __init__(
        self,
        session_id: str,
        interface_ips: Optional[Set[str]] = None,
        max_points: int = 300,
    ):
        self.session_id = session_id
        self.interface_ips: Set[str] = {ip.strip() for ip in (interface_ips or set()) if ip and ip.strip()}
        self.max_points = max_points
        self._lock = threading.Lock()

        self._start_epoch: Optional[int] = None
        self._buckets: Dict[int, SecondTimelineBucket] = {}
        self._order: Deque[int] = collections.deque(maxlen=max_points)

    def _classify_direction(self, src: str, dst: str) -> str:
        src = (src or "").strip()
        dst = (dst or "").strip()
        if src.startswith("127.") or dst.startswith("127.") or src == "::1" or dst == "::1":
            return "LOCAL"
        if not self.interface_ips:
            return "UNKNOWN"
        src_is_local = src in self.interface_ips
        dst_is_local = dst in self.interface_ips
        if src_is_local and dst_is_local:
            return "LOCAL"
        elif src_is_local:
            return "OUTBOUND"
        elif dst_is_local:
            return "INBOUND"
        else:
            return "UNKNOWN"

    def process_packet(self, meta: PacketMetadataItem) -> None:
        """Processes packet into second-by-second timeline buckets."""
        pkt_time = meta.timestamp if meta.timestamp.tzinfo else meta.timestamp.replace(tzinfo=timezone.utc)
        sec_epoch = int(pkt_time.timestamp())
        length = meta.length
        proto = (meta.protocol or "OTHER").upper()
        direction = self._classify_direction(meta.src_ip, meta.dst_ip)

        with self._lock:
            if self._start_epoch is None:
                self._start_epoch = sec_epoch

            if sec_epoch not in self._buckets:
                if len(self._order) >= self.max_points:
                    evicted = self._order.popleft()
                    self._buckets.pop(evicted, None)

                bucket_dt = datetime.fromtimestamp(sec_epoch, tz=timezone.utc)
                offset = max(0, sec_epoch - self._start_epoch)
                self._buckets[sec_epoch] = SecondTimelineBucket(timestamp=bucket_dt, second_offset=offset)
                self._order.append(sec_epoch)

            b = self._buckets[sec_epoch]
            b.packets_total += 1
            b.bytes_total += length

            if proto == "TCP":
                b.tcp_bytes += length
            elif proto in ("UDP", "DNS"):
                b.udp_bytes += length
            elif proto in ("ICMP", "ICMPV6"):
                b.icmp_bytes += length
            elif proto == "ARP":
                b.arp_bytes += length
            else:
                b.other_bytes += length

            if direction == "INBOUND":
                b.inbound_bytes += length
            elif direction == "OUTBOUND":
                b.outbound_bytes += length
            elif direction == "LOCAL":
                b.local_bytes += length
            else:
                b.unknown_bytes += length

    def get_timeline(self) -> TrafficTimelineResponse:
        """Returns time series points ordered chronologically."""
        with self._lock:
            points: List[TrafficTimelinePoint] = []
            for sec in sorted(self._buckets.keys()):
                b = self._buckets[sec]
                points.append(
                    TrafficTimelinePoint(
                        timestamp=b.timestamp,
                        second_offset=b.second_offset,
                        pps=float(b.packets_total),
                        bps=round(b.bytes_total * 8.0, 2),
                        tcp_bytes=b.tcp_bytes,
                        udp_bytes=b.udp_bytes,
                        icmp_bytes=b.icmp_bytes,
                        arp_bytes=b.arp_bytes,
                        other_bytes=b.other_bytes,
                        inbound_bytes=b.inbound_bytes,
                        outbound_bytes=b.outbound_bytes,
                        local_bytes=b.local_bytes,
                        unknown_bytes=b.unknown_bytes,
                    )
                )

            return TrafficTimelineResponse(
                session_id=self.session_id,
                total_seconds=len(points),
                points=points,
            )

