import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from backend.app.core.logging import logger
from backend.app.schemas.scanner import UdpScanResultItem

# Local port-to-service mapping for common UDP services
COMMON_UDP_SERVICES: Dict[int, str] = {
    53: "DNS",
    67: "DHCP-SERVER",
    68: "DHCP-CLIENT",
    69: "TFTP",
    123: "NTP",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    161: "SNMP",
    162: "SNMP-TRAP",
    500: "ISAKMP",
    514: "SYSLOG",
    1900: "SSDP",
    4500: "IPSEC-NAT-T",
}

COMMON_UDP_PORTS_PRESET: List[int] = sorted(list(COMMON_UDP_SERVICES.keys()))

# Minimal protocol-appropriate payloads for common UDP services
UDP_PROBES: Dict[int, bytes] = {
    # Minimal DNS query header for root NS
    53: b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01",
    # Standard NTP v3 client mode packet (48 bytes)
    123: b"\x1b" + b"\x00" * 47,
    # SNMPv1 GET request for sysDescr
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    # SSDP M-SEARCH packet
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    # NetBIOS Name Service Node Status Request
    137: b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01",
}

# Error codes indicating ICMP Port Unreachable received by OS socket layer
ICMP_PORT_UNREACHABLE_CODES = {
    errno.ECONNREFUSED,
    getattr(errno, "ECONNRESET", 10054),
    10054,  # Windows WSAECONNRESET (generated when target returns ICMP Port Unreachable on connected UDP socket)
    10061,  # Windows WSAECONNREFUSED
}

TIMEOUT_CODES = {
    errno.ETIMEDOUT,
    10060,  # Windows WSAETIMEDOUT
    10035,  # Windows WSAEWOULDBLOCK
}


def resolve_inferred_udp_service(port: int) -> str:
    """Infers standard service name associated with the given UDP port."""
    if port in COMMON_UDP_SERVICES:
        return COMMON_UDP_SERVICES[port]

    try:
        service_name = socket.getservbyport(port, "udp")
        return service_name.upper()
    except (OSError, socket.error):
        return "UNKNOWN"


def get_probe_payload(port: int) -> bytes:
    """Returns safe, minimal protocol probe or a neutral 2-byte datagram."""
    return UDP_PROBES.get(port, b"\x00\x00")


def scan_single_udp_port(target_ip: str, port: int, timeout: float = 1.0) -> UdpScanResultItem:
    """Probes a single UDP port using a connected UDP socket to catch ICMP port-unreachable notifications.
    
    States:
      - OPEN: Valid UDP response received.
      - CLOSED: ICMP Destination / Port Unreachable confirmed (e.g. WSAECONNRESET 10054 or ECONNREFUSED).
      - OPEN|FILTERED: Socket timed out with no response (silence could be an active service or firewall drop).
      - UNKNOWN: Probing anomaly or unhandled socket error.
    """
    sock = None
    start_time = time.perf_counter()
    state = "OPEN|FILTERED"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # On Windows, disable SIO_UDP_CONNRESET errors on unconnected sockets if needed,
        # but for connected sockets, connect() enables Winsock to report ICMP Port Unreachable via WSAECONNRESET.
        sock.connect((target_ip, port))

        payload = get_probe_payload(port)
        sock.send(payload)

        # Await potential reply from UDP service
        data = sock.recv(2048)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        if len(data) > 0:
            state = "OPEN"
        else:
            state = "OPEN|FILTERED"

    except (socket.timeout, TimeoutError):
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        state = "OPEN|FILTERED"
    except OSError as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        err_no = getattr(e, "errno", None) or getattr(e, "winerror", None)

        if err_no in ICMP_PORT_UNREACHABLE_CODES:
            state = "CLOSED"
        elif err_no in TIMEOUT_CODES:
            state = "OPEN|FILTERED"
        else:
            logger.debug("UDP scan error on %s:%d (errno %s): %s", target_ip, port, err_no, str(e))
            state = "OPEN|FILTERED"
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.debug("Unexpected error scanning UDP %s:%d: %s", target_ip, port, str(exc))
        state = "UNKNOWN"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    inferred_service = resolve_inferred_udp_service(port)

    return UdpScanResultItem(
        port=port,
        protocol="UDP",
        state=state,
        service=inferred_service,
        service_confidence="inferred",
        response_time_ms=elapsed_ms,
    )


def scan_udp_ports_concurrent(
    target_ip: str,
    ports: List[int],
    timeout: float = 1.0,
    concurrency: int = 20,
) -> List[UdpScanResultItem]:
    """Executes UDP datagram scanning concurrently with a controlled worker pool."""
    max_workers = max(1, min(concurrency, 50))
    results: List[UdpScanResultItem] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_single_udp_port, target_ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                port = futures[future]
                logger.error("Failed UDP scan task for %s:%d: %s", target_ip, port, str(e))
                results.append(
                    UdpScanResultItem(
                        port=port,
                        protocol="UDP",
                        state="UNKNOWN",
                        service=resolve_inferred_udp_service(port),
                        service_confidence="inferred",
                        response_time_ms=0.0,
                    )
                )

    results.sort(key=lambda item: item.port)
    return results

