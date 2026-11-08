import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from backend.app.schemas.analytics import ConnectionFlowItem, ConnectionsAnalyticsResponse
from backend.app.schemas.capture import PacketMetadataItem

WELL_KNOWN_SERVICES = {
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    5353: "mDNS",
    1900: "SSDP",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


class FlowRecord:
    """Internal state representation of a single canonical network flow."""

    def __init__(
        self,
        flow_id: str,
        protocol: str,
        ep1_ip: str,
        ep1_port: int,
        ep2_ip: str,
        ep2_port: int,
        service: Optional[str],
        first_seen: datetime,
    ):
        self.flow_id = flow_id
        self.protocol = protocol
        self.ep1_ip = ep1_ip
        self.ep1_port = ep1_port
        self.ep2_ip = ep2_ip
        self.ep2_port = ep2_port
        self.service = service
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.packet_count = 0
        self.byte_count = 0
        self.directions_seen: Set[str] = set()
        self.tcp_flags: Set[str] = set()
        self.state = "ACTIVE"

    def update(self, src_ip: str, src_port: int, length: int, timestamp: datetime, flags_str: Optional[str]):
        self.packet_count += 1
        self.byte_count += length
        self.last_seen = timestamp

        # Track direction
        dir_key = f"{src_ip}:{src_port}"
        self.directions_seen.add(dir_key)

        # Parse TCP flags
        if flags_str:
            for flag in [f.strip() for f in flags_str.split(",") if f.strip()]:
                self.tcp_flags.add(flag)

        # Evaluate state for TCP
        if self.protocol == "TCP":
            if "RST" in self.tcp_flags:
                self.state = "RESET"
            elif "FIN" in self.tcp_flags and len(self.directions_seen) > 1:
                self.state = "CLOSED"
            elif "SYN" in self.tcp_flags and "ACK" in self.tcp_flags and len(self.directions_seen) > 1:
                # Confirmed bidirectional handshake
                self.state = "ESTABLISHED"
            elif "SYN" in self.tcp_flags:
                self.state = "SYN_SENT"
            elif len(self.directions_seen) > 1:
                self.state = "ACTIVE"
            else:
                self.state = "SINGLE_DIRECTION"
        else:
            self.state = "ACTIVE"

    def to_schema(self) -> ConnectionFlowItem:
        duration = max(0.0, round((self.last_seen - self.first_seen).total_seconds(), 2))
        return ConnectionFlowItem(
            flow_id=self.flow_id,
            protocol=self.protocol,
            src_ip=self.ep1_ip,
            src_port=self.ep1_port,
            dst_ip=self.ep2_ip,
            dst_port=self.ep2_port,
            service=self.service,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            duration_seconds=duration,
            is_bidirectional=len(self.directions_seen) > 1,
            tcp_flags_observed=sorted(list(self.tcp_flags)),
            state=self.state,
        )


class ConnectionAnalyzer:
    """Tracks and classifies Layer 4 connection flows using canonical 5-tuples."""

    def __init__(self, session_id: str, max_flows: int = 1000):
        self.session_id = session_id
        self.max_flows = max_flows
        self._lock = threading.Lock()
        self._flows: Dict[str, FlowRecord] = {}

    def _canonical_flow_id(self, proto: str, src_ip: str, src_p: int, dst_ip: str, dst_p: int) -> tuple:
        ep1 = (src_ip, src_p)
        ep2 = (dst_ip, dst_p)
        if ep1 <= ep2:
            canonical_key = f"{proto}:{ep1[0]}:{ep1[1]}<->{ep2[0]}:{ep2[1]}"
            return canonical_key, ep1[0], ep1[1], ep2[0], ep2[1]
        else:
            canonical_key = f"{proto}:{ep2[0]}:{ep2[1]}<->{ep1[0]}:{ep1[1]}"
            return canonical_key, ep2[0], ep2[1], ep1[0], ep1[1]

    def process_packet(self, meta: PacketMetadataItem) -> None:
        """Processes packet into canonical 5-tuple flow."""
        proto = (meta.protocol or "").upper()
        if proto not in ("TCP", "UDP", "DNS"):
            return

        flow_proto = "UDP" if proto in ("UDP", "DNS") else "TCP"
        src_port = meta.src_port or 0
        dst_port = meta.dst_port or 0

        # Ignore 0-port packets
        if src_port == 0 and dst_port == 0:
            return

        flow_id, ep1_ip, ep1_p, ep2_ip, ep2_p = self._canonical_flow_id(
            flow_proto, meta.src_ip, src_port, meta.dst_ip, dst_port
        )

        pkt_time = meta.timestamp if meta.timestamp.tzinfo else meta.timestamp.replace(tzinfo=timezone.utc)

        with self._lock:
            if flow_id not in self._flows:
                # Evict oldest if full
                if len(self._flows) >= self.max_flows:
                    self._evict_oldest_flow()

                service = WELL_KNOWN_SERVICES.get(min(ep1_p, ep2_p)) or WELL_KNOWN_SERVICES.get(max(ep1_p, ep2_p))
                if not service and proto == "DNS":
                    service = "DNS"

                self._flows[flow_id] = FlowRecord(
                    flow_id=flow_id,
                    protocol=flow_proto,
                    ep1_ip=ep1_ip,
                    ep1_port=ep1_p,
                    ep2_ip=ep2_ip,
                    ep2_port=ep2_p,
                    service=service,
                    first_seen=pkt_time,
                )

            flow = self._flows[flow_id]
            flow.update(
                src_ip=meta.src_ip,
                src_port=src_port,
                length=meta.length,
                timestamp=pkt_time,
                flags_str=meta.tcp_flags,
            )

    def _evict_oldest_flow(self) -> None:
        """Evicts closed or least recently seen flow when limit is exceeded."""
        closed_candidates = [f for f in self._flows.values() if f.state in ("CLOSED", "RESET")]
        if closed_candidates:
            victim = min(closed_candidates, key=lambda f: f.last_seen)
        else:
            victim = min(self._flows.values(), key=lambda f: f.last_seen)
        self._flows.pop(victim.flow_id, None)

    def get_connections(self, limit: int = 100) -> ConnectionsAnalyticsResponse:
        """Returns tracked connection flows sorted by most recent activity."""
        with self._lock:
            sorted_flows = sorted(self._flows.values(), key=lambda f: f.last_seen, reverse=True)[:limit]
            active_count = sum(1 for f in self._flows.values() if f.state in ("ACTIVE", "ESTABLISHED"))
            return ConnectionsAnalyticsResponse(
                session_id=self.session_id,
                total_active_flows=active_count,
                total_flows_tracked=len(self._flows),
                flows=[f.to_schema() for f in sorted_flows],
            )

