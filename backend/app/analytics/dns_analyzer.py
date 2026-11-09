import re
import threading
from typing import Dict, List, Optional
from backend.app.schemas.analytics import (
    DnsAnalyticsResponse,
    DnsQueryItem,
    DnsQueryTypeItem,
    DnsResponseCodeItem,
)
from backend.app.schemas.capture import PacketMetadataItem

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}


class DnsAnalyzer:
    """Analyzes DNS queries, responses, domains, query types, and status codes.

    Enforces strict privacy controls: bounded retention (max 500 domains),
    zero payload storage, safe ASCII domain sanitization, and configurable redaction.
    """

    def __init__(self, session_id: str, max_domains: int = 500, redact_domains: bool = False):
        self.session_id = session_id
        self.max_domains = max_domains
        self.redact_domains = redact_domains
        self._lock = threading.Lock()

        self.total_dns_packets = 0
        self.total_queries = 0
        self.total_responses = 0

        self._domains: Dict[str, int] = {}
        self._qtypes: Dict[str, int] = {}
        self._rcodes: Dict[int, int] = {}

    def _sanitize_and_record_domain(self, qname: str) -> None:
        """Sanitizes and records domain name with bounded memory retention."""
        if not qname:
            return
        # Bounded length & strip dangerous characters
        cleaned = "".join(ch for ch in qname[:253] if ch.isalnum() or ch in (".", "-")).lower()
        if not cleaned:
            return

        if self.redact_domains:
            # Privacy redaction: keep apex domain, mask hostnames e.g. ***.example.com
            parts = cleaned.split(".")
            if len(parts) > 2:
                cleaned = f"***.{'.'.join(parts[-2:])}"

        if cleaned not in self._domains and len(self._domains) >= self.max_domains:
            # Evict least frequently queried domain
            victim = min(self._domains.keys(), key=lambda k: self._domains[k])
            self._domains.pop(victim, None)

        self._domains[cleaned] = self._domains.get(cleaned, 0) + 1

    def process_packet(self, meta: PacketMetadataItem, raw_packet=None) -> None:
        """Processes DNS packet using raw Scapy packet if provided, or metadata fallback.

        Strictly validates DNS messages:
        - UDP: Validated via Scapy DNS layer or meta.dns_summary.
        - TCP: Validated via RFC 1035 / RFC 7766 2-byte length prefix framing or meta.dns_summary.
        - TCP control frames (SYN, ACK, FIN), incomplete segments, or malformed payloads
          are never represented as successfully parsed DNS queries or responses.
        """
        is_port_53 = (meta.src_port == 53 or meta.dst_port == 53)
        is_dns_proto = (meta.protocol == "DNS")
        if not (is_dns_proto or is_port_53):
            return

        with self._lock:
            # 1. Prefer inspecting raw Scapy packet if available
            parsed_from_raw = False
            if raw_packet is not None:
                # Check UDP DNS layer
                if hasattr(raw_packet, "haslayer") and raw_packet.haslayer("DNS"):
                    try:
                        dns = raw_packet["DNS"]
                        qr = getattr(dns, "qr", 0)
                        if qr == 0:
                            self.total_queries += 1
                            if getattr(dns, "qd", None):
                                qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".").lower()
                                self._sanitize_and_record_domain(qname)
                                qtype_num = getattr(dns.qd, "qtype", 1)
                                qtype_str = QTYPE_NAMES.get(qtype_num, f"TYPE{qtype_num}")
                                self._qtypes[qtype_str] = self._qtypes.get(qtype_str, 0) + 1
                        else:
                            self.total_responses += 1
                            rcode_num = getattr(dns, "rcode", 0)
                            self._rcodes[rcode_num] = self._rcodes.get(rcode_num, 0) + 1
                        parsed_from_raw = True
                    except Exception:
                        parsed_from_raw = False

                # Check TCP DNS framing (RFC 1035 Section 4.2.2 / RFC 7766)
                elif hasattr(raw_packet, "haslayer") and raw_packet.haslayer("TCP") and is_port_53:
                    try:
                        tcp_payload = bytes(getattr(raw_packet["TCP"], "payload", b""))
                        if len(tcp_payload) >= 2:
                            msg_len = int.from_bytes(tcp_payload[:2], byteorder="big")
                            if 12 <= msg_len <= len(tcp_payload) - 2:
                                from scapy.layers.dns import DNS
                                dns = DNS(tcp_payload[2 : 2 + msg_len])
                                opcode = getattr(dns, "opcode", 0)
                                rcode_num = getattr(dns, "rcode", 0)
                                qdcount = getattr(dns, "qdcount", 0)
                                if opcode <= 5 and rcode_num <= 10 and qdcount <= 100:
                                    qr = getattr(dns, "qr", 0)
                                    if qr == 0:
                                        qd = getattr(dns, "qd", None)
                                        if isinstance(qd, list):
                                            qd = qd[0] if qd else None
                                        if qd and getattr(qd, "qname", None) and qd.qname != b".":
                                            self.total_queries += 1
                                            qname = qd.qname.decode("utf-8", errors="ignore").rstrip(".").lower()
                                            self._sanitize_and_record_domain(qname)
                                            qtype_num = getattr(qd, "qtype", 1)
                                            qtype_str = QTYPE_NAMES.get(qtype_num, f"TYPE{qtype_num}")
                                            self._qtypes[qtype_str] = self._qtypes.get(qtype_str, 0) + 1
                                            parsed_from_raw = True
                                    else:
                                        self.total_responses += 1
                                        self._rcodes[rcode_num] = self._rcodes.get(rcode_num, 0) + 1
                                        parsed_from_raw = True
                    except Exception:
                        parsed_from_raw = False

            # 2. Fallback to dns_summary in meta
            parsed_from_summary = False
            if not parsed_from_raw and meta.dns_summary:
                summary = meta.dns_summary
                if summary.startswith("Query"):
                    self.total_queries += 1
                    parsed_from_summary = True
                    # Extract domain after colon
                    if ":" in summary:
                        domain_part = summary.split(":", 1)[1].strip()
                        domain = domain_part.split("[")[0].strip().lower()
                        self._sanitize_and_record_domain(domain)
                    # Extract query type if in parentheses
                    match_type = re.search(r"Query\s*\(([^)]+)\)", summary)
                    qtype = match_type.group(1) if match_type else "A"
                    self._qtypes[qtype] = self._qtypes.get(qtype, 0) + 1
                elif "Response" in summary:
                    self.total_responses += 1
                    parsed_from_summary = True
                    match = re.search(r"rcode=(\d+)", summary)
                    if match:
                        rcode_val = int(match.group(1))
                    elif "NOERROR" in summary:
                        rcode_val = 0
                    elif "NXDOMAIN" in summary:
                        rcode_val = 3
                    elif "SERVFAIL" in summary:
                        rcode_val = 2
                    elif "REFUSED" in summary:
                        rcode_val = 5
                    else:
                        rcode_val = 0
                    self._rcodes[rcode_val] = self._rcodes.get(rcode_val, 0) + 1

            # 3. Increment total DNS frames only for genuine DNS frames
            # Only count frames that carry a validated DNS message or UDP port 53 traffic.
            # Pure TCP transport control frames (SYN, ACK, FIN) with 0 payload are excluded.
            if parsed_from_raw or parsed_from_summary or is_dns_proto:
                self.total_dns_packets += 1
            elif raw_packet is not None and hasattr(raw_packet, "haslayer") and raw_packet.haslayer("UDP") and is_port_53:
                self.total_dns_packets += 1

    def get_dns_analytics(self) -> DnsAnalyticsResponse:
        """Returns aggregated DNS analytics."""
        with self._lock:
            unmatched = max(0, self.total_queries - self.total_responses)

            # Top domains
            sorted_domains = sorted(self._domains.items(), key=lambda kv: kv[1], reverse=True)[:10]
            domain_items: List[DnsQueryItem] = []
            for dom, count in sorted_domains:
                pct = round((count / self.total_queries * 100.0), 2) if self.total_queries > 0 else 0.0
                domain_items.append(DnsQueryItem(query_name=dom, count=count, percentage=pct))

            # Query types
            sorted_qtypes = sorted(self._qtypes.items(), key=lambda kv: kv[1], reverse=True)
            qtype_items = [DnsQueryTypeItem(qtype=qt, count=cnt) for qt, cnt in sorted_qtypes]

            # Response codes
            sorted_rcodes = sorted(self._rcodes.items(), key=lambda kv: kv[0])
            rcode_items = [
                DnsResponseCodeItem(
                    rcode=rc,
                    rcode_name=RCODE_NAMES.get(rc, f"RCODE_{rc}"),
                    count=cnt,
                )
                for rc, cnt in sorted_rcodes
            ]

            return DnsAnalyticsResponse(
                session_id=self.session_id,
                total_dns_packets=self.total_dns_packets,
                total_queries=self.total_queries,
                total_responses=self.total_responses,
                unmatched_queries=unmatched,
                top_domains=domain_items,
                query_types=qtype_items,
                response_codes=rcode_items,
            )

