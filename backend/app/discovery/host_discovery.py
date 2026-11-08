import ctypes
import errno
import ipaddress
import os
import platform
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from backend.app.core.logging import logger
from backend.app.schemas.discovery import DiscoveredHostItem

# Common ports used for TCP connection-based host discovery
DISCOVERY_TCP_PORTS = [80, 443, 22, 135, 445]

IS_WINDOWS = platform.system().lower() == "windows"


def is_ip_loopback(ip: str) -> bool:
    """Checks whether the given IPv4 address belongs to the 127.0.0.0/8 loopback range."""
    try:
        return ipaddress.ip_address(ip.strip()).is_loopback
    except Exception:
        return ip.strip().startswith("127.")


def get_hosts_file_mappings() -> Dict[str, str]:
    """Reads system hosts file to detect locally configured hostnames."""
    mappings: Dict[str, str] = {}
    hosts_path = (
        os.path.expandvars(r"%SystemRoot%\System32\drivers\etc\hosts")
        if IS_WINDOWS
        else "/etc/hosts"
    )
    try:
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Remove trailing inline comments
                    if "#" in line:
                        line = line.split("#", 1)[0].strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        host_ip = parts[0]
                        host_name = parts[1]
                        mappings[host_ip] = host_name
    except Exception as exc:
        logger.debug("Failed reading hosts file: %s", exc)
    return mappings


def resolve_reverse_dns(ip: str) -> Tuple[str, str]:
    """Attempts reverse DNS resolution, distinguishing DNS PTR, HOSTS_FILE, and SYSTEM_LOOPBACK.
    
    Returns:
        Tuple of (hostname, source)
    """
    if is_ip_loopback(ip):
        # Loopback interface
        hosts = get_hosts_file_mappings()
        if ip in hosts and hosts[ip].lower() not in ("localhost", "127.0.0.1"):
            # Expose that this custom name originated from local hosts file
            return hosts[ip], "HOSTS_FILE"
        return "localhost", "SYSTEM_LOOPBACK"

    hosts = get_hosts_file_mappings()
    if ip in hosts:
        return hosts[ip], "HOSTS_FILE"

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host != ip:
            return host, "DNS_PTR"
    except (socket.herror, socket.gaierror, OSError):
        pass

    return "Unresolved", "UNRESOLVED"


def probe_arp(ip: str) -> Tuple[bool, Optional[str], Optional[float]]:
    """Probes host via Address Resolution Protocol (ARP) on local subnet.
    
    On Windows, uses native SendARP API (iphlpapi.dll). Never probes loopback targets.
    Returns (is_online, mac_address, latency_ms).
    """
    if not IS_WINDOWS or is_ip_loopback(ip):
        return False, None, None

    start_time = time.perf_counter()
    try:
        dest_ip = struct.unpack("<L", socket.inet_aton(ip))[0]
        mac_addr = (ctypes.c_byte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_addr), ctypes.byref(mac_len))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if res == 0:
            # Reject all-zero MAC address (never a valid Ethernet MAC)
            if all(b == 0 for b in bytearray(mac_addr)):
                return False, None, None
            mac_str = ":".join(f"{b & 0xff:02X}" for b in bytearray(mac_addr))
            if mac_str == "00:00:00:00:00:00":
                return False, None, None
            return True, mac_str, elapsed_ms
        return False, None, None
    except Exception as exc:
        logger.debug("ARP probe exception for %s: %s", ip, str(exc))
        return False, None, None


def probe_icmp(ip: str, timeout_sec: float = 1.0) -> Tuple[bool, Optional[float]]:
    """Sends a single ICMP Echo Request using the OS ping utility without requiring raw socket privileges."""
    start_time = time.perf_counter()
    timeout_ms = max(100, int(timeout_sec * 1000))

    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec))), ip]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_sec + 0.5,
        )
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        if proc.returncode == 0:
            return True, elapsed_ms
        return False, None
    except Exception as exc:
        logger.debug("ICMP ping exception for %s: %s", ip, str(exc))
        return False, None


def probe_tcp_connect(ip: str, timeout_sec: float = 0.5) -> Tuple[bool, Optional[float]]:
    """Probes standard administrative and web ports with TCP connect."""
    for port in DISCOVERY_TCP_PORTS:
        start_time = time.perf_counter()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_sec)
            res = sock.connect_ex((ip, port))
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # 0 = OPEN, 10061/ECONNREFUSED = CLOSED (host actively replied with RST)
            if res in (0, errno.ECONNREFUSED, 10061, getattr(errno, "WSAECONNREFUSED", 10061)):
                return True, elapsed_ms
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    return False, None


def probe_single_host(
    ip: str,
    method: str = "AUTO",
    timeout: float = 1.0,
) -> DiscoveredHostItem:
    """Dispatches host discovery against a single IPv4 address using the specified method."""
    method_upper = method.upper()
    is_online = False
    effective_method = method_upper
    latency: Optional[float] = None
    mac_addr: Optional[str] = None
    loopback = is_ip_loopback(ip)

    if loopback:
        # Loopback addresses cannot be discovered via ARP and have no Ethernet MAC
        if method_upper == "ARP":
            is_online = False
            effective_method = "ARP"
            mac_addr = None
            latency = None
        else:
            # Measure loopback responsiveness via TCP connect or ICMP
            tcp_online, tcp_lat = probe_tcp_connect(ip, min(timeout, 0.5))
            if tcp_online:
                is_online = True
                effective_method = "LOOPBACK" if method_upper == "AUTO" else method_upper
                latency = tcp_lat
            else:
                icmp_online, icmp_lat = probe_icmp(ip, timeout)
                if icmp_online:
                    is_online = True
                    effective_method = "LOOPBACK" if method_upper == "AUTO" else method_upper
                    latency = icmp_lat
                else:
                    is_online = True
                    effective_method = "LOOPBACK"
                    latency = 0.1
            mac_addr = None
    elif method_upper == "ARP":
        is_online, mac_addr, latency = probe_arp(ip)
    elif method_upper == "ICMP_ECHO":
        is_online, latency = probe_icmp(ip, timeout)
    elif method_upper == "TCP_CONNECT":
        is_online, latency = probe_tcp_connect(ip, min(timeout, 0.5))
    else:
        # AUTO: Tri-phase discovery strategy for non-loopback hosts
        # 1. Try ARP first (fastest for local subnet)
        arp_online, arp_mac, arp_lat = probe_arp(ip)
        if arp_online and arp_mac:
            is_online = True
            effective_method = "ARP"
            mac_addr = arp_mac
            latency = arp_lat
        else:
            # 2. Try ICMP Echo
            icmp_online, icmp_lat = probe_icmp(ip, timeout)
            if icmp_online:
                is_online = True
                effective_method = "ICMP_ECHO"
                latency = icmp_lat
            else:
                # 3. Try TCP Connect
                tcp_online, tcp_lat = probe_tcp_connect(ip, min(timeout, 0.5))
                if tcp_online:
                    is_online = True
                    effective_method = "TCP_CONNECT"
                    latency = tcp_lat

    # Sanity check: never output an all-zero MAC
    if mac_addr == "00:00:00:00:00:00":
        mac_addr = None

    hostname, hostname_source = (
        resolve_reverse_dns(ip) if is_online else ("Unresolved", "UNRESOLVED")
    )

    return DiscoveredHostItem(
        ip_address=ip,
        hostname=hostname,
        hostname_source=hostname_source,
        discovery_method=effective_method,
        status="ONLINE" if is_online else "NO_RESPONSE",
        response_time_ms=latency,
        mac_address=mac_addr,
        first_seen=datetime.now(timezone.utc),
    )


def discover_hosts_concurrent(
    ip_list: List[str],
    method: str = "AUTO",
    timeout: float = 1.0,
    concurrency: int = 30,
) -> List[DiscoveredHostItem]:
    """Dispatches discovery workers concurrently across candidate host IPs."""
    max_workers = max(1, min(concurrency, 50))
    results: List[DiscoveredHostItem] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(probe_single_host, ip, method, timeout): ip
            for ip in ip_list
        }
        for future in as_completed(futures):
            try:
                item = future.result()
                results.append(item)
            except Exception as e:
                ip = futures[future]
                logger.error("Error discovering host %s: %s", ip, str(e))
                results.append(
                    DiscoveredHostItem(
                        ip_address=ip,
                        hostname="Unresolved",
                        hostname_source="UNRESOLVED",
                        discovery_method=method,
                        status="NO_RESPONSE",
                        response_time_ms=None,
                        mac_address=None,
                        first_seen=datetime.now(timezone.utc),
                    )
                )

    # Sort results by IP address numerically
    try:
        results.sort(key=lambda h: int(ipaddress.IPv4Address(h.ip_address)))
    except Exception:
        results.sort(key=lambda h: h.ip_address)

    return results
