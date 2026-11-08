import asyncio
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.discovery.host_discovery import discover_hosts_concurrent
from backend.app.schemas.discovery import (
    DiscoveredHostItem,
    DiscoveryHistoryItem,
    DiscoveryValidationResponse,
    HostDiscoveryRequest,
    HostDiscoveryResponse,
    HostDiscoveryStatusData,
)


class DiscoveryService:
    """Service layer managing subnet host discovery, CIDR validation, and discovery results."""

    _discoveries: Dict[str, HostDiscoveryResponse] = {}
    _history: List[DiscoveryHistoryItem] = []
    _latest_discovery: Optional[HostDiscoveryResponse] = None

    @classmethod
    def parse_and_validate_cidr(
        cls, cidr: str
    ) -> Tuple[bool, Optional[ipaddress.IPv4Network], bool, Optional[str]]:
        """Parses and validates a CIDR string.
        
        Returns:
            Tuple of (valid, network_obj, is_authorized, error_message)
        """
        cleaned = cidr.strip()
        if not cleaned:
            return False, None, False, "CIDR network string cannot be empty."

        # Handle plain single IP shorthand (e.g. 192.168.1.1 -> 192.168.1.1/32)
        if "/" not in cleaned:
            cleaned = f"{cleaned}/32"

        try:
            net = ipaddress.ip_network(cleaned, strict=False)
            if net.version != 4:
                return False, None, False, "Only IPv4 subnets are currently supported."
        except ValueError as exc:
            return False, None, False, f"Invalid CIDR notation: {exc}"

        # Safe-mode boundary enforcement: must be contained in allowed networks
        is_authorized = False
        for allowed in settings.allowed_scan_networks:
            try:
                allowed_net = ipaddress.ip_network(allowed, strict=False)
                if net.subnet_of(allowed_net) or (net == allowed_net):
                    is_authorized = True
                    break
            except ValueError:
                continue

        if not is_authorized:
            return (
                False,
                net,
                False,
                f"Subnet '{net}' is outside authorized safe-mode boundaries. Allowed ranges: {', '.join(settings.allowed_scan_networks)}",
            )

        return True, net, True, None

    @classmethod
    def validate_discovery_config(cls, cidr: str) -> DiscoveryValidationResponse:
        """Evaluates a CIDR string and returns structured validation status."""
        valid, net, is_authorized, error = cls.parse_and_validate_cidr(cidr)
        if not valid or net is None:
            return DiscoveryValidationResponse(
                valid=False,
                normalized_cidr=str(net) if net else None,
                network_address=str(net.network_address) if net else None,
                broadcast_address=str(net.broadcast_address) if net else None,
                total_usable_hosts=0,
                is_authorized=is_authorized,
                error=error,
            )

        # Calculate usable host count
        if net.prefixlen == 32:
            usable = 1
        elif net.prefixlen == 31:
            usable = 2
        else:
            usable = max(0, net.num_addresses - 2)

        return DiscoveryValidationResponse(
            valid=True,
            normalized_cidr=str(net),
            network_address=str(net.network_address),
            broadcast_address=str(net.broadcast_address),
            total_usable_hosts=usable,
            is_authorized=is_authorized,
            error=None,
        )

    @classmethod
    def get_host_ips_for_network(
        cls, net: ipaddress.IPv4Network, max_hosts: int = 256
    ) -> List[str]:
        """Extracts candidate host IP addresses from a validated network."""
        if net.prefixlen == 32:
            return [str(net.network_address)]
        elif net.prefixlen == 31:
            return [str(ip) for ip in net]
        else:
            # network.hosts() generates all usable hosts excluding network & broadcast
            ips = []
            for ip in net.hosts():
                ips.append(str(ip))
                if len(ips) >= max_hosts:
                    break
            return ips

    @classmethod
    async def execute_discovery(
        cls, request: HostDiscoveryRequest
    ) -> HostDiscoveryResponse:
        """Executes concurrent host discovery over the specified CIDR network."""
        valid, net, is_authorized, error = cls.parse_and_validate_cidr(request.cidr)
        if not valid or net is None:
            raise ValueError(error or "Invalid or unauthorized CIDR network.")

        ip_list = cls.get_host_ips_for_network(net, max_hosts=request.max_hosts)
        if not ip_list:
            raise ValueError("No usable host IP addresses found in the specified subnet.")

        discovery_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        logger.info(
            "Starting host discovery [%s]: cidr=%s (usable_ips=%d), method=%s, concurrency=%d",
            discovery_id,
            str(net),
            len(ip_list),
            request.method,
            request.concurrency,
        )

        # Offload concurrent network probing to thread pool to prevent blocking async event loop
        host_findings: List[DiscoveredHostItem] = await asyncio.to_thread(
            discover_hosts_concurrent,
            ip_list=ip_list,
            method=request.method,
            timeout=request.timeout,
            concurrency=request.concurrency,
        )

        completed_at = datetime.now(timezone.utc)
        duration_seconds = round((completed_at - started_at).total_seconds(), 3)
        online_count = sum(1 for h in host_findings if h.status == "ONLINE")

        response = HostDiscoveryResponse(
            discovery_id=discovery_id,
            cidr=str(net),
            method=request.method,
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            total_probed=len(host_findings),
            online_hosts_count=online_count,
            hosts=host_findings,
        )

        # Store session record and history summary
        cls._discoveries[discovery_id] = response
        cls._latest_discovery = response

        history_item = DiscoveryHistoryItem(
            discovery_id=discovery_id,
            cidr=str(net),
            method=request.method,
            started_at=started_at,
            duration_seconds=duration_seconds,
            online_count=online_count,
            total_probed=len(host_findings),
            status="completed",
        )
        cls._history.insert(0, history_item)
        if len(cls._history) > 100:
            cls._history = cls._history[:100]

        logger.info(
            "Completed host discovery [%s]: duration=%.2fs, probed=%d, online=%d",
            discovery_id,
            duration_seconds,
            len(host_findings),
            online_count,
        )

        return response

    @classmethod
    def get_discovery_by_id(cls, discovery_id: str) -> Optional[HostDiscoveryResponse]:
        """Retrieves a discovery result by unique ID."""
        return cls._discoveries.get(discovery_id)

    @classmethod
    def get_history(cls, limit: int = 50) -> List[DiscoveryHistoryItem]:
        """Returns recent discovery job history summaries."""
        return cls._history[:limit]

    @classmethod
    def get_latest_discovery(cls) -> Optional[HostDiscoveryResponse]:
        """Returns the most recent discovery run, if any."""
        return cls._latest_discovery

    @classmethod
    def get_status(cls) -> HostDiscoveryStatusData:
        """Returns the current operational status of the Host Discovery Engine."""
        return HostDiscoveryStatusData(
            available=True,
            status="operational",
            message="Host Discovery Engine is active and ready for subnet scans.",
            engine_version="0.3.0",
            supported_methods=["AUTO", "ICMP_ECHO", "TCP_CONNECT", "ARP"],
            safe_mode_enforced=True,
        )

