from datetime import datetime, timezone
from typing import Optional

from backend.app.schemas.capture import PacketMetadataItem


def format_tcp_flags(flags_val) -> Optional[str]:
    """Formats numeric or string TCP flags into a human-readable string."""
    if not flags_val:
        return None

    # Handle Scapy FlagValue or int
    flag_str = str(flags_val).upper()
    flag_names = []
    if "S" in flag_str:
        flag_names.append("SYN")
    if "A" in flag_str:
        flag_names.append("ACK")
    if "F" in flag_str:
        flag_names.append("FIN")
    if "R" in flag_str:
        flag_names.append("RST")
    if "P" in flag_str:
        flag_names.append("PSH")
    if "U" in flag_str:
        flag_names.append("URG")

    return ", ".join(flag_names) if flag_names else flag_str


def parse_dns_over_tcp(tcp_layer) -> Optional[str]:
    """Inspects a TCP segment for an RFC 1035 / RFC 7766 DNS message.

    DNS over TCP is prefixed by a 2-byte big-endian message length field.
    Returns dns_summary string if a complete, valid DNS message is parsed, otherwise None.
    Does NOT classify TCP control frames (SYN, ACK, FIN), incomplete stream segments,
    or corrupted payload bytes as DNS messages.
    """
    try:
        raw_payload = bytes(getattr(tcp_layer, "payload", b""))
        if len(raw_payload) < 2:
            return None

        msg_len = int.from_bytes(raw_payload[:2], byteorder="big")
        # Standard DNS header is minimum 12 bytes
        if msg_len < 12 or len(raw_payload) < 2 + msg_len:
            return None

        dns_raw = raw_payload[2 : 2 + msg_len]
        from scapy.layers.dns import DNS
        dns = DNS(dns_raw)

        # Validate DNS header plausibility (RFC 1035 / RFC 6895)
        opcode = getattr(dns, "opcode", 0)
        if opcode > 5:
            return None
        rcode = getattr(dns, "rcode", 0)
        if rcode > 10:
            return None
        qdcount = getattr(dns, "qdcount", 0)
        if qdcount > 100:
            return None

        qr = getattr(dns, "qr", 0)
        if qr == 0:
            qd = getattr(dns, "qd", None)
            if isinstance(qd, list):
                qd = qd[0] if qd else None
            if qd and getattr(qd, "qname", None) and qd.qname != b".":
                qname = qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                return f"Query: {qname}"
            return None
        elif qr == 1:
            rcode_val = getattr(dns, "rcode", 0)
            return f"Response (rcode={rcode_val})"
        return None
    except Exception:
        return None


def parse_packet_metadata(
    packet,
    packet_id: int,
    session_id: str,
    interface_name: str,
) -> PacketMetadataItem:
    """Parses a Scapy frame into a strictly metadata-only PacketMetadataItem.
    
    Zero payload bytes, application bodies, credentials, or cookies are stored.
    """
    ts = datetime.now(timezone.utc)
    if hasattr(packet, "time") and packet.time:
        try:
            ts = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
        except Exception:
            pass

    length = len(packet) if hasattr(packet, "__len__") else 0
    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol = "OTHER"
    tcp_flags: Optional[str] = None
    dns_summary: Optional[str] = None

    # 1. ARP layer
    if packet.haslayer("ARP"):
        protocol = "ARP"
        arp = packet["ARP"]
        src_ip = getattr(arp, "psrc", "0.0.0.0")
        dst_ip = getattr(arp, "pdst", "0.0.0.0")

    # 2. IPv4 layer
    elif packet.haslayer("IP"):
        ip = packet["IP"]
        src_ip = getattr(ip, "src", "0.0.0.0")
        dst_ip = getattr(ip, "dst", "0.0.0.0")
        proto_num = getattr(ip, "proto", 0)

        if packet.haslayer("TCP"):
            protocol = "TCP"
            tcp = packet["TCP"]
            src_port = int(getattr(tcp, "sport", 0))
            dst_port = int(getattr(tcp, "dport", 0))
            tcp_flags = format_tcp_flags(getattr(tcp, "flags", None))
            if src_port == 53 or dst_port == 53:
                dns_summary = parse_dns_over_tcp(tcp)
        elif packet.haslayer("UDP"):
            protocol = "UDP"
            udp = packet["UDP"]
            src_port = int(getattr(udp, "sport", 0))
            dst_port = int(getattr(udp, "dport", 0))

            # Safely extract DNS query name/type without payload
            if packet.haslayer("DNS"):
                protocol = "DNS"
                try:
                    dns = packet["DNS"]
                    if getattr(dns, "qr", 0) == 0 and getattr(dns, "qd", None):
                        qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        dns_summary = f"Query: {qname}"
                    elif getattr(dns, "qr", 0) == 1:
                        rcode_val = getattr(dns, "rcode", 0)
                        dns_summary = f"Response (rcode={rcode_val})"
                except Exception:
                    dns_summary = "DNS Message"
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
        else:
            protocol = f"IPv4 (proto={proto_num})"

    # 3. IPv6 layer
    elif packet.haslayer("IPv6"):
        ip6 = packet["IPv6"]
        src_ip = getattr(ip6, "src", "::")
        dst_ip = getattr(ip6, "dst", "::")

        if packet.haslayer("TCP"):
            protocol = "TCP"
            tcp = packet["TCP"]
            src_port = int(getattr(tcp, "sport", 0))
            dst_port = int(getattr(tcp, "dport", 0))
            tcp_flags = format_tcp_flags(getattr(tcp, "flags", None))
            if src_port == 53 or dst_port == 53:
                dns_summary = parse_dns_over_tcp(tcp)
        elif packet.haslayer("UDP"):
            protocol = "UDP"
            udp = packet["UDP"]
            src_port = int(getattr(udp, "sport", 0))
            dst_port = int(getattr(udp, "dport", 0))
            if packet.haslayer("DNS"):
                protocol = "DNS"
                try:
                    dns = packet["DNS"]
                    if getattr(dns, "qr", 0) == 0 and getattr(dns, "qd", None):
                        qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        dns_summary = f"Query: {qname}"
                    elif getattr(dns, "qr", 0) == 1:
                        rcode_val = getattr(dns, "rcode", 0)
                        dns_summary = f"Response (rcode={rcode_val})"
                except Exception:
                    dns_summary = "DNS Message"
        elif packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMPv6EchoReply"):
            protocol = "ICMPv6"
        else:
            protocol = "IPv6"

    # 4. Ethernet fallback
    elif packet.haslayer("Ether"):
        protocol = "ETHERNET"
        eth = packet["Ether"]
        src_ip = getattr(eth, "src", "00:00:00:00:00:00")
        dst_ip = getattr(eth, "dst", "00:00:00:00:00:00")

    return PacketMetadataItem(
        packet_id=packet_id,
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags=tcp_flags,
        dns_summary=dns_summary,
        interface=interface_name,
        session_id=session_id,
    )

