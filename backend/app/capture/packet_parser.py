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
                        dns_summary = f"Response (rcode={getattr(dns, 'rcode', 0)})"
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
        elif packet.haslayer("UDP"):
            protocol = "UDP"
            udp = packet["UDP"]
            src_port = int(getattr(udp, "sport", 0))
            dst_port = int(getattr(udp, "dport", 0))
            if packet.haslayer("DNS"):
                protocol = "DNS"
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

