import platform
import psutil
from typing import Dict, List, Optional

from backend.app.core.logging import logger
from backend.app.schemas.capture import CaptureInterfaceItem

IS_WINDOWS = platform.system().lower() == "windows"


def classify_interface_type(name: str, desc: Optional[str] = None) -> str:
    """Classifies an interface as physical, virtual, loopback, or unknown."""
    lower = f"{name} {desc or ''}".lower()
    if "loopback" in lower or "127.0.0.1" in lower:
        return "loopback"
    if any(k in lower for k in ("virtual", "vmware", "vbox", "virtualbox", "hyper-v", "vethernet", "tap", "tun", "vpn", "wsl")):
        return "virtual"
    if any(k in lower for k in ("wi-fi", "wifi", "wlan", "wireless", "ethernet", "realtek", "intel", "gigabit", "pcie", "broadcom")):
        return "physical"
    return "unknown"


def list_capture_interfaces() -> List[CaptureInterfaceItem]:
    """Enumerates system network adapters with hardware descriptions, addresses, and capture readiness."""
    items: List[CaptureInterfaceItem] = []

    # Map psutil addresses and stats
    addrs_by_name = psutil.net_if_addrs()
    stats_by_name = psutil.net_if_stats()

    # Query Scapy Windows interfaces if available for friendly names and descriptions
    scapy_ifaces_by_name: Dict[str, dict] = {}
    if IS_WINDOWS:
        try:
            from scapy.arch.windows import get_windows_if_list
            for win_if in get_windows_if_list():
                w_name = win_if.get("name")
                if w_name:
                    scapy_ifaces_by_name[w_name] = win_if
        except Exception as exc:
            logger.debug("Failed querying Scapy Windows interface list: %s", exc)

    for iface_name, addr_list in addrs_by_name.items():
        ipv4_list: List[str] = []
        ipv6_list: List[str] = []
        mac_addr: Optional[str] = None

        for addr in addr_list:
            if addr.family == psutil.AF_LINK or (hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK):
                if addr.address and addr.address != "00:00:00:00:00:00":
                    mac_addr = addr.address
            elif str(addr.family) in ("AddressFamily.AF_INET", "2"):
                if addr.address:
                    ipv4_list.append(addr.address)
            elif str(addr.family) in ("AddressFamily.AF_INET6", "23", "10", "30"):
                if addr.address and not addr.address.startswith("fe80"):
                    ipv6_list.append(addr.address)

        stat = stats_by_name.get(iface_name)
        is_up = stat.isup if stat else True
        speed = stat.speed if stat and stat.speed > 0 else None

        # Look up friendly description from Scapy mapping
        win_meta = scapy_ifaces_by_name.get(iface_name, {})
        description = win_meta.get("description") or iface_name
        guid = win_meta.get("guid") or iface_name

        iface_type = classify_interface_type(iface_name, description)
        can_capture = iface_type != "loopback" or not IS_WINDOWS  # On Windows, standard Npcap captures Ethernet/Wi-Fi

        items.append(
            CaptureInterfaceItem(
                id=guid,
                name=iface_name,
                description=description,
                ipv4_addresses=ipv4_list,
                ipv6_addresses=ipv6_list,
                mac_address=mac_addr,
                is_up=is_up,
                speed_mbps=speed,
                interface_type=iface_type,
                can_capture=can_capture,
            )
        )

    # Sort interfaces: physical active adapters first
    items.sort(key=lambda i: (not i.is_up, i.interface_type != "physical", i.name))
    return items


def find_interface_by_id_or_name(target: str) -> Optional[CaptureInterfaceItem]:
    """Finds an interface by GUID, name, or description."""
    target_clean = target.strip().lower()
    for item in list_capture_interfaces():
        if (
            item.id.lower() == target_clean
            or item.name.lower() == target_clean
            or (item.description and item.description.lower() == target_clean)
        ):
            return item
    return None

