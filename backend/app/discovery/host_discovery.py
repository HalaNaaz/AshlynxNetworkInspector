import ctypes
import errno
import ipaddress
import os
import platform
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from backend.app.core.logging import logger
from backend.app.schemas.discovery import DiscoveredHostItem

# Common ports used for TCP connection-based host discovery
DISCOVERY_TCP_PORTS = [80, 443, 22, 135, 445]

IS_WINDOWS = platform.system().lower() == "windows"

# Optional layer-2 raw packet transmission via Scapy/Npcap
try:
    from scapy.all import ARP, Ether, srp1
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False


class ArpProbeResult(tuple):
    """Container for ARP probe findings, supporting both 3-tuple unpacking and named attributes."""

    def __new__(
        cls,
        is_online: bool,
        mac_address: Optional[str],
        latency_ms: Optional[float],
        neighbor_state: Optional[str] = None,
    ):
        return super().__new__(cls, (is_online, mac_address, latency_ms))

    def __init__(
        self,
        is_online: bool,
        mac_address: Optional[str],
        latency_ms: Optional[float],
        neighbor_state: Optional[str] = None,
    ):
        self.is_online = is_online
        self.mac_address = mac_address
        self.latency_ms = latency_ms
        self.neighbor_state = neighbor_state


def is_valid_mac_address(mac: Optional[str]) -> bool:
    """Strictly validates physical Ethernet MAC address.

    Rejects None, empty strings, all-zero ('00:00:00:00:00:00'),
    broadcast ('FF:FF:FF:FF:FF:FF'), and malformed MAC strings.
    """
    if not mac:
        return False
    clean = mac.strip().upper().replace("-", ":")
    parts = clean.split(":")
    if len(parts) != 6:
        return False
    try:
        bytes_val = [int(p, 16) for p in parts]
    except ValueError:
        return False
    if all(b == 0 for b in bytes_val) or all(b == 0xFF for b in bytes_val):
        return False
    return True


# Windows IP Helper API (iphlpapi.dll) Neighbor Cache structures
if IS_WINDOWS:
    from ctypes import wintypes

    class SOCKADDR_INET(ctypes.Structure):
        _fields_ = [
            ("si_family", ctypes.c_ushort),
            ("pad1", ctypes.c_ushort),
            ("ipv4_addr", ctypes.c_ubyte * 4),
            ("pad2", ctypes.c_ubyte * 20),
        ]

    class MIB_IPNET_ROW2(ctypes.Structure):
        _fields_ = [
            ("Address", SOCKADDR_INET),
            ("InterfaceIndex", ctypes.c_uint32),
            ("InterfaceLuid", ctypes.c_uint64),
            ("PhysicalAddress", ctypes.c_ubyte * 32),
            ("PhysicalAddressLength", ctypes.c_uint32),
            ("State", ctypes.c_uint32),
            ("Flags", ctypes.c_ubyte),
            ("ReachabilityTime", ctypes.c_uint32),
        ]

    class MIB_IPNET_TABLE2(ctypes.Structure):
        _fields_ = [
            ("NumEntries", wintypes.DWORD),
            ("pad", wintypes.DWORD),
            ("Table", MIB_IPNET_ROW2 * 1),
        ]

    NEIGHBOR_STATE_MAP = {
        0: "UNINITIALIZED",
        1: "INCOMPLETE",
        2: "PROBE",
        3: "DELAY",
        4: "STALE",
        5: "REACHABLE",
        6: "PERMANENT",
        7: "UNREACHABLE",
    }
else:
    NEIGHBOR_STATE_MAP = {}

_neighbor_cache_lock = threading.Lock()
_neighbor_cache_snapshot: Dict[str, Tuple[Optional[str], str]] = {}
_neighbor_cache_timestamp: float = 0.0


def get_windows_neighbor_table_snapshot() -> Dict[str, Tuple[Optional[str], str]]:
    """Captures a snapshot of the Windows Neighbor Table (ARP cache)."""
    snapshot: Dict[str, Tuple[Optional[str], str]] = {}
    if not IS_WINDOWS:
        return snapshot

    try:
        pTable = ctypes.POINTER(MIB_IPNET_TABLE2)()
        res = ctypes.windll.iphlpapi.GetIpNetTable2(ctypes.c_ushort(2), ctypes.byref(pTable))
        if res == 0 and pTable:
            try:
                table = pTable.contents
                rows = ctypes.cast(
                    ctypes.addressof(table.Table),
                    ctypes.POINTER(MIB_IPNET_ROW2 * table.NumEntries),
                ).contents
                for r in rows:
                    entry_ip = ".".join(str(b) for b in r.Address.ipv4_addr)
                    mac_bytes = list(r.PhysicalAddress)[: r.PhysicalAddressLength]
                    mac_str = ":".join(f"{b:02X}" for b in mac_bytes) if mac_bytes else None
                    if not is_valid_mac_address(mac_str):
                        mac_str = None
                    st = NEIGHBOR_STATE_MAP.get(r.State, "UNKNOWN")
                    snapshot[entry_ip] = (mac_str, st)
            finally:
                ctypes.windll.iphlpapi.FreeMibTable(pTable)
    except Exception as exc:
        logger.debug("Failed querying Windows neighbor table: %s", exc)

    return snapshot


def get_cached_neighbor_entry(ip: str, max_age_sec: float = 1.0) -> Tuple[Optional[str], str]:
    """Retrieves neighbor entry from cached snapshot to minimize kernel IOCTL overhead."""
    global _neighbor_cache_snapshot, _neighbor_cache_timestamp
    if not IS_WINDOWS:
        return None, "UNREACHABLE"

    now = time.monotonic()
    if now - _neighbor_cache_timestamp >= max_age_sec or not _neighbor_cache_snapshot:
        with _neighbor_cache_lock:
            if now - _neighbor_cache_timestamp >= max_age_sec or not _neighbor_cache_snapshot:
                _neighbor_cache_snapshot = get_windows_neighbor_table_snapshot()
                _neighbor_cache_timestamp = now

    entry = _neighbor_cache_snapshot.get(ip)
    if entry:
        return entry
    return None, "UNINITIALIZED"


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


def probe_arp(ip: str, timeout: float = 1.0) -> ArpProbeResult:
    """Probes host via Address Resolution Protocol (ARP) on local subnet.
    
    Measurement Architecture:
    1. Loopback addresses never have an ARP layer and are rejected.
    2. Primary: Layer-2 wire ARP request/reply using Scapy with high-resolution monotonic
       clock (time.perf_counter()) measuring actual round-trip frame exchange independently.
       Targeted BPF filter (arp and src host {ip}) prevents cross-thread packet contamination.
    3. Fallback: Native Windows SendARP / GetIpNetTable2.
       If raw wire timing cannot be captured reliably, verifies physical presence and MAC,
       but reports latency as None (unavailable) per Secure by Design to prevent recording
       Windows kernel retransmission timer quantization artifacts (~1000ms/2000ms/3000ms).
    4. Enforces that 00:00:00:00:00:00 is never treated as a valid MAC address.
    5. Preserves REACHABLE, PROBE, STALE, and UNREACHABLE neighbor cache states.
    """
    if is_ip_loopback(ip):
        return ArpProbeResult(False, None, None, "UNREACHABLE")

    # Step 1: Attempt high-precision Layer-2 ARP measurement via Scapy/Npcap
    if HAS_SCAPY:
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
            t0 = time.perf_counter()
            ans = srp1(pkt, timeout=min(timeout, 1.0), filter=f"arp and src host {ip}", verbose=0)
            t1 = time.perf_counter()

            if ans and ARP in ans and ans[ARP].op == 2:
                raw_mac = ans[ARP].hwsrc
                if is_valid_mac_address(raw_mac):
                    mac_formatted = ":".join(f"{int(x, 16):02X}" for x in raw_mac.split(":"))
                    latency_ms = round((t1 - t0) * 1000, 2)
                    _, nstate = get_cached_neighbor_entry(ip) if IS_WINDOWS else (None, "REACHABLE")
                    effective_state = nstate if nstate not in ("UNKNOWN", "UNINITIALIZED") else "REACHABLE"
                    return ArpProbeResult(True, mac_formatted, latency_ms, effective_state)
        except Exception as exc:
            logger.debug("Scapy raw ARP probe unavailable for %s: %s", ip, exc)

    # Step 2: Fallback to Windows SendARP / Neighbor Table
    if IS_WINDOWS:
        cached_mac, nstate = get_cached_neighbor_entry(ip)
        if cached_mac and nstate in ("REACHABLE", "PERMANENT"):
            # Known reachable neighbor, but sub-millisecond wire latency unavailable without raw capture
            return ArpProbeResult(True, cached_mac, None, nstate)

        try:
            dest_ip = struct.unpack("<L", socket.inet_aton(ip))[0]
            mac_addr = (ctypes.c_byte * 6)()
            mac_len = ctypes.c_ulong(6)
            res = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_addr), ctypes.byref(mac_len))
            if res == 0:
                raw_mac = ":".join(f"{b & 0xFF:02X}" for b in bytearray(mac_addr))
                if is_valid_mac_address(raw_mac):
                    _, updated_st = get_cached_neighbor_entry(ip, max_age_sec=0.0)
                    effective_state = updated_st if updated_st not in ("UNKNOWN", "UNINITIALIZED") else "REACHABLE"
                    # As required: report latency as None (unavailable) rather than recording kernel timer artifacts
                    return ArpProbeResult(True, raw_mac, None, effective_state)

            _, failed_st = get_cached_neighbor_entry(ip, max_age_sec=0.0)
            effective_state = failed_st if failed_st not in ("UNKNOWN", "UNINITIALIZED") else "UNREACHABLE"
            return ArpProbeResult(False, None, None, effective_state)
        except Exception as exc:
            logger.debug("SendARP exception for %s: %s", ip, exc)

    return ArpProbeResult(False, None, None, "UNREACHABLE")


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
    neighbor_state: Optional[str] = None
    loopback = is_ip_loopback(ip)

    if loopback:
        # Loopback addresses cannot be discovered via ARP and have no Ethernet MAC
        neighbor_state = "PERMANENT"
        if method_upper == "ARP":
            is_online = False
            effective_method = "ARP"
            mac_addr = None
            latency = None
            neighbor_state = "UNREACHABLE"
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
        arp_res = probe_arp(ip, timeout)
        is_online = arp_res.is_online
        mac_addr = arp_res.mac_address
        latency = arp_res.latency_ms
        neighbor_state = arp_res.neighbor_state
    elif method_upper == "ICMP_ECHO":
        is_online, latency = probe_icmp(ip, timeout)
        if is_online and IS_WINDOWS:
            cached_mac, nstate = get_cached_neighbor_entry(ip)
            if cached_mac:
                mac_addr = cached_mac
            neighbor_state = nstate
    elif method_upper == "TCP_CONNECT":
        is_online, latency = probe_tcp_connect(ip, min(timeout, 0.5))
        if is_online and IS_WINDOWS:
            cached_mac, nstate = get_cached_neighbor_entry(ip)
            if cached_mac:
                mac_addr = cached_mac
            neighbor_state = nstate
    else:
        # AUTO: Tri-phase discovery strategy for non-loopback hosts
        # 1. Try ARP first (fastest for local subnet)
        arp_res = probe_arp(ip, timeout)
        if arp_res.is_online and arp_res.mac_address:
            is_online = True
            effective_method = "ARP"
            mac_addr = arp_res.mac_address
            latency = arp_res.latency_ms
            neighbor_state = arp_res.neighbor_state
        else:
            neighbor_state = arp_res.neighbor_state
            # 2. Try ICMP Echo
            icmp_online, icmp_lat = probe_icmp(ip, timeout)
            if icmp_online:
                is_online = True
                effective_method = "ICMP_ECHO"
                latency = icmp_lat
                if not mac_addr and IS_WINDOWS:
                    cached_mac, nstate = get_cached_neighbor_entry(ip)
                    if cached_mac:
                        mac_addr = cached_mac
                    if nstate != "UNKNOWN":
                        neighbor_state = nstate
            else:
                # 3. Try TCP Connect
                tcp_online, tcp_lat = probe_tcp_connect(ip, min(timeout, 0.5))
                if tcp_online:
                    is_online = True
                    effective_method = "TCP_CONNECT"
                    latency = tcp_lat
                    if not mac_addr and IS_WINDOWS:
                        cached_mac, nstate = get_cached_neighbor_entry(ip)
                        if cached_mac:
                            mac_addr = cached_mac
                        if nstate != "UNKNOWN":
                            neighbor_state = nstate

    # Sanity check: never output an all-zero or broadcast MAC
    if mac_addr and not is_valid_mac_address(mac_addr):
        mac_addr = None

    # Never record timeout duration as successful response latency
    if not is_online:
        latency = None
        if not neighbor_state or neighbor_state in ("UNKNOWN", "UNINITIALIZED"):
            neighbor_state = "UNREACHABLE"

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
        neighbor_state=neighbor_state,
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
                        neighbor_state="UNREACHABLE",
                        first_seen=datetime.now(timezone.utc),
                    )
                )

    # Sort results by IP address numerically
    try:
        results.sort(key=lambda h: int(ipaddress.IPv4Address(h.ip_address)))
    except Exception:
        results.sort(key=lambda h: h.ip_address)

    return results
