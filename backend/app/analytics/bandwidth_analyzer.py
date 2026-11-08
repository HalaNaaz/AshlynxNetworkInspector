import collections
import threading
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Set
from backend.app.schemas.analytics import BandwidthAnalyticsResponse, BandwidthDataPoint
from backend.app.schemas.capture import PacketMetadataItem


class SecondBucket:
    """Bucket storing volume metrics for a single integer second."""

    def __init__(self, timestamp: datetime):
        self.timestamp = timestamp
        self.bytes_total = 0
        self.packets_total = 0
        self.bytes_inbound = 0
        self.bytes_outbound = 0
        self.bytes_local = 0
        self.bytes_unknown = 0


class BandwidthAnalyzer:
    """Calculates directional traffic throughput across rolling time windows."""

    def __init__(
        self,
        session_id: str,
        interface_ips: Optional[Set[str]] = None,
        max_history_seconds: int = 300,
    ):
        self.session_id = session_id
        self.interface_ips: Set[str] = {ip.strip() for ip in (interface_ips or set()) if ip and ip.strip()}
        self.max_history_seconds = max_history_seconds
        self._lock = threading.Lock()

        # Cumulative totals
        self.total_bytes = 0
        self.total_packets = 0
        self.inbound_bytes = 0
        self.outbound_bytes = 0
        self.local_bytes = 0
        self.unknown_bytes = 0

        # Peak records
        self.peak_bps = 0.0
        self.peak_pps = 0.0

        # History keyed by integer second epoch
        self._buckets: Dict[int, SecondBucket] = {}
        self._bucket_order: Deque[int] = collections.deque(maxlen=max_history_seconds)

    def classify_direction(self, src_ip: str, dst_ip: str) -> str:
        """Determines traffic direction relative to the captured interface.

        Labels direction UNKNOWN if it cannot be proven using the interface's local IPs.
        """
        src = (src_ip or "").strip()
        dst = (dst_ip or "").strip()

        # Check loopback
        if src.startswith("127.") or dst.startswith("127.") or src == "::1" or dst == "::1":
            return "LOCAL"

        if not self.interface_ips:
            # If no interface IP is bound, direction cannot be proven safely
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
        """Updates bandwidth counters incrementally."""
        direction = self.classify_direction(meta.src_ip, meta.dst_ip)
        length = meta.length
        pkt_time = meta.timestamp if meta.timestamp.tzinfo else meta.timestamp.replace(tzinfo=timezone.utc)
        sec_epoch = int(pkt_time.timestamp())

        with self._lock:
            self.total_bytes += length
            self.total_packets += 1

            if direction == "INBOUND":
                self.inbound_bytes += length
            elif direction == "OUTBOUND":
                self.outbound_bytes += length
            elif direction == "LOCAL":
                self.local_bytes += length
            else:
                self.unknown_bytes += length

            if sec_epoch not in self._buckets:
                if len(self._bucket_order) >= self.max_history_seconds:
                    oldest_sec = self._bucket_order.popleft()
                    self._buckets.pop(oldest_sec, None)

                bucket_dt = datetime.fromtimestamp(sec_epoch, tz=timezone.utc)
                self._buckets[sec_epoch] = SecondBucket(timestamp=bucket_dt)
                self._bucket_order.append(sec_epoch)

            bucket = self._buckets[sec_epoch]
            bucket.bytes_total += length
            bucket.packets_total += 1

            if direction == "INBOUND":
                bucket.bytes_inbound += length
            elif direction == "OUTBOUND":
                bucket.bytes_outbound += length
            elif direction == "LOCAL":
                bucket.bytes_local += length
            else:
                bucket.bytes_unknown += length

            # Update peak 1-second records
            instant_bps = bucket.bytes_total * 8.0
            instant_pps = float(bucket.packets_total)
            if instant_bps > self.peak_bps:
                self.peak_bps = instant_bps
            if instant_pps > self.peak_pps:
                self.peak_pps = instant_pps

    def get_bandwidth(self, window_seconds: int = 1) -> BandwidthAnalyticsResponse:
        """Computes bandwidth analytics over rolling window."""
        window_seconds = max(1, min(window_seconds, 60))

        with self._lock:
            now_sec = int(datetime.now(timezone.utc).timestamp())
            sorted_epochs = sorted(self._buckets.keys())

            # Data points list for frontend charts
            data_points: List[BandwidthDataPoint] = []
            for sec in sorted_epochs:
                b = self._buckets[sec]
                data_points.append(
                    BandwidthDataPoint(
                        timestamp=b.timestamp,
                        window_seconds=1,
                        bytes_total=b.bytes_total,
                        packets_total=b.packets_total,
                        bits_per_second=b.bytes_total * 8.0,
                        packets_per_second=float(b.packets_total),
                        bytes_inbound=b.bytes_inbound,
                        bytes_outbound=b.bytes_outbound,
                        bytes_local=b.bytes_local,
                        bytes_unknown=b.bytes_unknown,
                    )
                )

            # Calculate current throughput in the last window_seconds
            recent_epochs = [
                sec for sec in sorted_epochs if (now_sec - sec) <= window_seconds and (now_sec - sec) >= 0
            ]
            if not recent_epochs and sorted_epochs:
                # If clock slightly shifted or inactive, take last N epochs
                recent_epochs = sorted_epochs[-window_seconds:]

            window_bytes = sum(self._buckets[sec].bytes_total for sec in recent_epochs)
            window_pkts = sum(self._buckets[sec].packets_total for sec in recent_epochs)
            effective_duration = float(max(1, len(recent_epochs) if recent_epochs else window_seconds))

            current_bps = round((window_bytes * 8.0) / effective_duration, 2)
            current_pps = round(window_pkts / effective_duration, 2)

            avg_pkt_size = round(self.total_bytes / self.total_packets, 2) if self.total_packets > 0 else 0.0

            return BandwidthAnalyticsResponse(
                session_id=self.session_id,
                current_window=window_seconds,
                current_bps=current_bps,
                current_pps=current_pps,
                peak_bps=round(self.peak_bps, 2),
                peak_pps=round(self.peak_pps, 2),
                average_packet_size_bytes=avg_pkt_size,
                total_bytes=self.total_bytes,
                total_packets=self.total_packets,
                data_points=data_points,
            )

