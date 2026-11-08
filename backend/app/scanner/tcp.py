import errno
import socket
import time
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.app.core.logging import logger
from backend.app.schemas.scanner import PortScanResultItem

# Local port-to-service mapping for common TCP services
COMMON_TCP_SERVICES: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MONGODB",
}

COMMON_PORTS_PRESET: List[int] = sorted(list(COMMON_TCP_SERVICES.keys()))

# Error codes representing explicit connection refusal (RST) across OSes
REFUSED_CODES = {
    errno.ECONNREFUSED,
    10061,  # Windows WSAECONNREFUSED
    getattr(errno, "WSAECONNREFUSED", 10061),
}

# Error codes representing explicit administrative/firewall filtering
FILTERED_CODES = {
    errno.EPERM,
    errno.EACCES,
    10013,  # Windows WSAEACCES
    getattr(errno, "WSAEACCES", 10013),
}

# Error codes representing timeouts across OSes
TIMEOUT_CODES = {
    errno.ETIMEDOUT,
    10060,  # Windows WSAETIMEDOUT
    getattr(errno, "WSAETIMEDOUT", 10060),
    10035,  # Windows WSAEWOULDBLOCK (connect_ex timed out before handshake finished)
    getattr(errno, "WSAEWOULDBLOCK", 10035),
}


def resolve_inferred_service(port: int) -> str:
    """Infers standard service name associated with the given TCP port.
    
    Service is labeled as 'inferred' because port number alone does not verify the service identity.
    """
    if port in COMMON_TCP_SERVICES:
        return COMMON_TCP_SERVICES[port]

    try:
        service_name = socket.getservbyport(port, "tcp")
        return service_name.upper()
    except (OSError, socket.error):
        return "UNKNOWN"


def scan_single_tcp_port(target_ip: str, port: int, timeout: float = 1.0) -> PortScanResultItem:
    """Executes a single TCP connect scan against target_ip:port.
    
    Accurately classifies state:
      - OPEN: Handshake confirmed.
      - CLOSED: Target explicitly refused connection (RST / ECONNREFUSED).
      - FILTERED: Explicit administrative / firewall filtering evidence.
      - NO_RESPONSE: Socket timed out without conclusive evidence of a filter.
      - UNKNOWN: Probing anomaly or unclassified socket failure.
    """
    sock = None
    start_time = time.perf_counter()
    state = "UNKNOWN"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex returns 0 on successful three-way handshake
        res = sock.connect_ex((target_ip, port))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if res == 0:
            state = "OPEN"
        elif res in REFUSED_CODES:
            state = "CLOSED"
        elif res in FILTERED_CODES:
            state = "FILTERED"
        elif res in TIMEOUT_CODES:
            state = "NO_RESPONSE"
        else:
            state = "NO_RESPONSE"
    except (socket.timeout, TimeoutError):
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        state = "NO_RESPONSE"
    except socket.error as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        err_num = getattr(e, "errno", None)
        if err_num in REFUSED_CODES:
            state = "CLOSED"
        elif err_num in FILTERED_CODES:
            state = "FILTERED"
        elif err_num in TIMEOUT_CODES:
            state = "NO_RESPONSE"
        else:
            state = "UNKNOWN"
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.debug("Unexpected error scanning port %s:%d - %s", target_ip, port, str(exc))
        state = "UNKNOWN"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    inferred_service = resolve_inferred_service(port)

    return PortScanResultItem(
        port=port,
        protocol="TCP",
        state=state,
        service=inferred_service,
        service_confidence="inferred",
        response_time_ms=elapsed_ms,
    )


def scan_ports_concurrent(
    target_ip: str,
    ports: List[int],
    timeout: float = 1.0,
    concurrency: int = 50,
) -> List[PortScanResultItem]:
    """Executes TCP Connect scanning concurrently across the specified port list.
    
    Limits maximum concurrent worker threads to protect system resources.
    Returns sorted list of PortScanResultItem objects.
    """
    max_workers = max(1, min(concurrency, 100))
    results: List[PortScanResultItem] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_single_tcp_port, target_ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                port = futures[future]
                logger.error("Failed scan task for %s:%d: %s", target_ip, port, str(e))
                results.append(
                    PortScanResultItem(
                        port=port,
                        protocol="TCP",
                        state="UNKNOWN",
                        service=resolve_inferred_service(port),
                        service_confidence="inferred",
                        response_time_ms=0.0,
                    )
                )

    # Sort results ascending by port number
    results.sort(key=lambda item: item.port)
    return results
