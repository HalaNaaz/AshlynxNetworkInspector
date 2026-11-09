import collections
import threading
import time
from datetime import datetime, timezone
from typing import Deque, List, Optional, Set, Tuple

from backend.app.analytics.analytics_engine import AnalyticsEngine
from backend.app.capture.environment import evaluate_capture_environment
from backend.app.capture.packet_parser import parse_packet_metadata
from backend.app.core.logging import logger
from backend.app.schemas.capture import (
    CaptureSessionResponse,
    CaptureStatistics,
    PacketMetadataItem,
)
from backend.app.security.detection_engine import SecurityDetectionEngine


class LiveCaptureEngine:
    """Thread-safe live network packet capture engine with bounded memory ring buffer."""

    def __init__(
        self,
        session_id: str,
        interface_id: str,
        interface_name: str,
        filter_bpf: str = "",
        buffer_limit: int = 1000,
        interface_ips: Optional[Set[str]] = None,
    ):
        self.session_id = session_id
        self.interface_id = interface_id
        self.interface_name = interface_name
        self.filter_bpf = filter_bpf
        self.buffer_limit = max(100, min(buffer_limit, 5000))
        self.interface_ips = interface_ips or set()

        # Thread-safe packet storage with bounded capacity (oldest packet evicted on limit)
        self._lock = threading.Lock()
        self._packets: Deque[PacketMetadataItem] = collections.deque(maxlen=self.buffer_limit)
        self._packet_seq = 0

        # Analytics Engine integration
        self.analytics_engine = AnalyticsEngine(
            session_id=self.session_id,
            interface_ips=self.interface_ips,
        )

        # Security Intelligence & Anomaly Detection Engine integration
        self.security_engine = SecurityDetectionEngine(session_id=self.session_id)

        # Live counters
        self._total_captured = 0
        self._dropped_packets = 0
        self._tcp_count = 0
        self._udp_count = 0
        self._icmp_count = 0
        self._arp_count = 0
        self._other_count = 0
        self._bytes_captured = 0

        # State management
        self.status = "READY"
        self.started_at: datetime = datetime.now(timezone.utc)
        self.stopped_at: Optional[datetime] = None
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self.error_message: Optional[str] = None

    def start(self) -> None:
        """Launches the background packet capture thread."""
        with self._lock:
            if self.status == "CAPTURING":
                raise ValueError(f"Session {self.session_id} is already capturing.")

            env = evaluate_capture_environment()
            if not env.can_capture:
                self.status = "ERROR"
                self.error_message = env.message
                raise RuntimeError(f"{env.capability_status}: {env.message}")

            self.status = "CAPTURING"
            self.started_at = datetime.now(timezone.utc)
            self.stopped_at = None
            self._stop_event.clear()
            self.analytics_engine.created_at = self.started_at
            self.analytics_engine.stopped_at = None
            self.analytics_engine._final_duration = None
            self.analytics_engine.set_status("CAPTURING")

        self._worker_thread = threading.Thread(
            target=self._run_sniff_loop,
            name=f"capture-{self.session_id[:8]}",
            daemon=True,
        )
        self._worker_thread.start()
        logger.info(
            "Live capture started [%s] on interface '%s' (filter='%s', buffer=%d)",
            self.session_id,
            self.interface_name,
            self.filter_bpf,
            self.buffer_limit,
        )

    def stop(self) -> None:
        """Signals the sniffer thread to terminate cleanly and updates session state."""
        with self._lock:
            if self.status != "CAPTURING":
                return
            self.status = "STOPPED"
            self.stopped_at = datetime.now(timezone.utc)
            self._stop_event.set()

        self.analytics_engine.set_status("STOPPED", stopped_at=self.stopped_at)
        logger.info("Live capture stopped [%s]: total %d frames captured", self.session_id, self._total_captured)

    def _packet_callback(self, pkt) -> None:
        """Processes each frame received from Scapy in real time."""
        if self._stop_event.is_set():
            return

        with self._lock:
            self._packet_seq += 1
            meta = parse_packet_metadata(
                packet=pkt,
                packet_id=self._packet_seq,
                session_id=self.session_id,
                interface_name=self.interface_name,
            )

            # Update traffic counters
            self._total_captured += 1
            self._bytes_captured += meta.length

            if meta.protocol == "TCP":
                self._tcp_count += 1
            elif meta.protocol in ("UDP", "DNS"):
                self._udp_count += 1
            elif meta.protocol in ("ICMP", "ICMPv6"):
                self._icmp_count += 1
            elif meta.protocol == "ARP":
                self._arp_count += 1
            else:
                self._other_count += 1

            self._packets.append(meta)

        # Dispatch to real-time analytics engine
        self.analytics_engine.process_packet(meta, raw_packet=pkt)

        # Dispatch to passive security detection engine
        self.security_engine.process_packet(meta)

    def feed_packet_for_testing(self, pkt) -> None:
        """Feeds a mock or synthesized packet into the capture buffer for testing."""
        self._packet_callback(pkt)

    def _run_sniff_loop(self) -> None:
        """Background thread executing Scapy sniff."""
        try:
            from scapy.all import sniff

            sniff_kwargs = {
                "iface": self.interface_name,
                "prn": self._packet_callback,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "store": False,
            }
            if self.filter_bpf:
                sniff_kwargs["filter"] = self.filter_bpf

            sniff(**sniff_kwargs)
        except Exception as exc:
            logger.error("Capture worker error in session [%s]: %s", self.session_id, exc)
            with self._lock:
                self.status = "ERROR"
                self.error_message = str(exc)
                self.stopped_at = datetime.now(timezone.utc)
            self.analytics_engine.set_status("ERROR", stopped_at=self.stopped_at)

    def get_statistics(self) -> CaptureStatistics:
        """Returns snapshot of current session statistics."""
        with self._lock:
            now = datetime.now(timezone.utc)
            end_time = self.stopped_at or now
            duration = max(0.0, round((end_time - self.started_at).total_seconds(), 2))

            return CaptureStatistics(
                total_captured=self._total_captured,
                retained_in_buffer=len(self._packets),
                dropped_packets=self._dropped_packets,
                tcp_count=self._tcp_count,
                udp_count=self._udp_count,
                icmp_count=self._icmp_count,
                arp_count=self._arp_count,
                other_count=self._other_count,
                bytes_captured=self._bytes_captured,
                capture_duration_seconds=duration,
            )

    def get_session_summary(self) -> CaptureSessionResponse:
        """Returns structured session summary details."""
        stats = self.get_statistics()
        return CaptureSessionResponse(
            session_id=self.session_id,
            interface_id=self.interface_id,
            interface_name=self.interface_name,
            status=self.status,
            filter_bpf=self.filter_bpf,
            buffer_limit=self.buffer_limit,
            started_at=self.started_at,
            stopped_at=self.stopped_at,
            duration_seconds=stats.capture_duration_seconds,
            statistics=stats,
        )

    def get_packets(
        self,
        offset: int = 0,
        limit: int = 100,
        protocol: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[int, List[PacketMetadataItem]]:
        """Retrieves paginated packet items from the bounded ring buffer."""
        with self._lock:
            # Newest packets first
            packet_list = list(reversed(self._packets))

        filtered = packet_list
        if protocol and protocol.upper() != "ALL":
            p_upper = protocol.upper()
            filtered = [p for p in filtered if p.protocol.upper() == p_upper]

        if search:
            s_lower = search.strip().lower()
            filtered = [
                p
                for p in filtered
                if (
                    s_lower in p.src_ip.lower()
                    or s_lower in p.dst_ip.lower()
                    or s_lower in p.protocol.lower()
                    or (p.src_port and s_lower in str(p.src_port))
                    or (p.dst_port and s_lower in str(p.dst_port))
                    or (p.dns_summary and s_lower in p.dns_summary.lower())
                )
            ]

        total_matching = len(filtered)
        start = max(0, offset)
        end = start + max(1, min(limit, 500))
        paginated = filtered[start:end]

        return total_matching, paginated

    def clear_buffer(self) -> None:
        """Clears the display packet ring buffer while retaining cumulative statistics."""
        with self._lock:
            self._packets.clear()

