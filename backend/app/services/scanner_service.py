import asyncio
import ipaddress
import socket
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.scanner.tcp import (
    COMMON_PORTS_PRESET,
    scan_ports_concurrent,
)
from backend.app.scanner.udp import (
    COMMON_UDP_PORTS_PRESET,
    scan_udp_ports_concurrent,
)
from backend.app.schemas.scanner import (
    PortScanRequest,
    PortScanResultItem,
    ScanExecutionResponse,
    ScanHistoryItem,
    ScannerStatusData,
    ScanValidationRequest,
    ScanValidationResponse,
    UdpScanRequest,
    UdpScanExecutionResponse,
    UdpScanResultItem,
)


class ScannerService:
    """Service layer managing TCP and UDP port scanning, validation, and historical results."""

    # In-memory storage for active session scans and history
    _scans: Dict[str, ScanExecutionResponse] = {}
    _udp_scans: Dict[str, UdpScanExecutionResponse] = {}
    _history: List[ScanHistoryItem] = []
    _latest_scan: Optional[ScanExecutionResponse] = None
    _latest_udp_scan: Optional[UdpScanExecutionResponse] = None

    @classmethod
    def resolve_target_ip(cls, target: str) -> str:
        """Resolves target hostname or IP to an IPv4 address.
        
        Translates 'localhost' to 127.0.0.1. Rejects unresolvable or invalid IPs.
        """
        cleaned = target.strip().lower()
        if not cleaned:
            raise ValueError("Target host or IP address cannot be empty.")

        if cleaned == "localhost":
            return "127.0.0.1"

        try:
            parsed = ipaddress.ip_address(cleaned)
            if parsed.version != 4:
                raise ValueError("Only IPv4 targets are supported in this phase.")
            return cleaned
        except ValueError:
            try:
                resolved_ip = socket.gethostbyname(cleaned)
                return resolved_ip
            except Exception:
                raise ValueError(f"Invalid target address or hostname: '{target}'")

    @classmethod
    def verify_target_authorized(cls, target_ip: str) -> bool:
        """Enforces safe-mode boundaries against configured allowed CIDRs.
        
        Permits only localhost and authorized private subnets (RFC-1918) by default.
        """
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            for cidr in settings.allowed_scan_networks:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in net:
                    return True
            return False
        except Exception:
            return False

    @classmethod
    def resolve_ports(
        cls,
        ports: Optional[List[int]] = None,
        port_range: Optional[str] = None,
        preset: Optional[str] = None,
        is_udp: bool = False,
    ) -> List[int]:
        """Parses and consolidates port inputs into a deduplicated, sorted list of valid integers."""
        collected_ports = set()
        default_preset = COMMON_UDP_PORTS_PRESET if is_udp else COMMON_PORTS_PRESET

        # Check for explicitly passed empty inputs
        if ports is not None and len(ports) == 0:
            raise ValueError("Port list cannot be empty.")
        if port_range is not None and not port_range.strip():
            raise ValueError("Port range cannot be empty.")

        # Handle preset
        if preset and preset.lower() in ("common", "default", "standard"):
            collected_ports.update(default_preset)

        # Handle explicit port list
        if ports:
            for p in ports:
                if not isinstance(p, int) or p < 1 or p > 65535:
                    raise ValueError(f"Port '{p}' is outside valid port range (1-65535).")
                collected_ports.add(p)

        # Handle port range string (e.g. "1-1024" or "80,443,8080")
        if port_range:
            parts = [part.strip() for part in port_range.split(",") if part.strip()]
            for part in parts:
                if "-" in part:
                    range_bounds = part.split("-")
                    if len(range_bounds) != 2:
                        raise ValueError(f"Malformed port range format: '{part}'")
                    try:
                        start_port = int(range_bounds[0])
                        end_port = int(range_bounds[1])
                    except ValueError:
                        raise ValueError(f"Non-integer boundaries in range: '{part}'")

                    if start_port > end_port:
                        raise ValueError(f"Invalid range bounds: start ({start_port}) cannot be greater than end ({end_port}).")
                    if start_port < 1 or end_port > 65535:
                        raise ValueError(f"Port range '{part}' exceeds valid boundaries (1-65535).")

                    for p in range(start_port, end_port + 1):
                        collected_ports.add(p)
                else:
                    try:
                        single_p = int(part)
                    except ValueError:
                        raise ValueError(f"Invalid port value: '{part}'")
                    if single_p < 1 or single_p > 65535:
                        raise ValueError(f"Port '{single_p}' is outside valid port range (1-65535).")
                    collected_ports.add(single_p)

        # If nothing specified, default to preset
        if not collected_ports and ports is None and port_range is None and preset is None:
            collected_ports.update(default_preset)

        resolved_list = sorted(list(collected_ports))

        if not resolved_list:
            raise ValueError("No valid ports specified for scan.")

        if len(resolved_list) > 1024:
            raise ValueError(
                f"Maximum allowed ports per scan is 1024 (requested {len(resolved_list)})."
            )

        return resolved_list

    @classmethod
    def validate_request(cls, req: ScanValidationRequest, is_udp: bool = False) -> ScanValidationResponse:
        """Validates target address, authorization, and port scope without dispatching scan."""
        try:
            target_ip = cls.resolve_target_ip(req.target)
            is_auth = cls.verify_target_authorized(target_ip)
            if not is_auth:
                return ScanValidationResponse(
                    valid=False,
                    target_ip=target_ip,
                    resolved_ports_count=0,
                    resolved_ports_preview=[],
                    target_authorized=False,
                    error=f"Target '{target_ip}' is outside authorized scanning boundaries (safe-mode active: localhost & RFC-1918 only).",
                )

            ports = cls.resolve_ports(req.ports, req.port_range, req.preset, is_udp=is_udp)
            return ScanValidationResponse(
                valid=True,
                target_ip=target_ip,
                resolved_ports_count=len(ports),
                resolved_ports_preview=ports[:10],
                target_authorized=True,
                error=None,
            )
        except ValueError as ve:
            return ScanValidationResponse(
                valid=False,
                target_ip=None,
                resolved_ports_count=0,
                resolved_ports_preview=[],
                target_authorized=False,
                error=str(ve),
            )
        except Exception as exc:
            return ScanValidationResponse(
                valid=False,
                target_ip=None,
                resolved_ports_count=0,
                resolved_ports_preview=[],
                target_authorized=False,
                error=f"Unexpected validation error: {str(exc)}",
            )

    # ==================== TCP SCAN EXECUTION ====================

    @classmethod
    async def execute_scan(cls, req: PortScanRequest) -> ScanExecutionResponse:
        """Executes a TCP Connect port scan asynchronously without blocking the FastAPI event loop."""
        target_ip = cls.resolve_target_ip(req.target)
        if not cls.verify_target_authorized(target_ip):
            raise ValueError(
                f"Target '{target_ip}' is outside authorized scanning boundaries (safe-mode active: localhost & RFC-1918 only)."
            )

        ports = cls.resolve_ports(req.ports, req.port_range, req.preset, is_udp=False)
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        started_at = datetime.now(timezone.utc)

        logger.info(
            "Starting TCP connect scan %s against %s (%d ports, timeout=%.1fs, concurrency=%d)",
            scan_id,
            target_ip,
            len(ports),
            req.timeout,
            req.concurrency,
        )

        results: List[PortScanResultItem] = await asyncio.to_thread(
            scan_ports_concurrent,
            target_ip=target_ip,
            ports=ports,
            timeout=req.timeout,
            concurrency=req.concurrency,
        )

        completed_at = datetime.now(timezone.utc)
        duration = round((completed_at - started_at).total_seconds(), 2)

        open_count = sum(1 for r in results if r.state == "OPEN")
        closed_count = sum(1 for r in results if r.state == "CLOSED")
        filtered_count = sum(1 for r in results if r.state == "FILTERED")
        no_response_count = sum(1 for r in results if r.state == "NO_RESPONSE")
        other_unknown = sum(1 for r in results if r.state == "UNKNOWN")

        filtered_or_unknown_total = filtered_count + no_response_count + other_unknown

        response = ScanExecutionResponse(
            scan_id=scan_id,
            target=target_ip,
            scan_type="TCP_CONNECT",
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            total_ports=len(results),
            open_ports=open_count,
            closed_ports=closed_count,
            filtered_ports=filtered_count,
            no_response_ports=no_response_count,
            filtered_or_unknown_ports=filtered_or_unknown_total,
            results=results,
        )

        cls._scans[scan_id] = response
        cls._latest_scan = response
        cls._history.insert(
            0,
            ScanHistoryItem(
                scan_id=scan_id,
                target=target_ip,
                scan_type="TCP_CONNECT",
                started_at=started_at,
                duration_seconds=duration,
                total_ports=len(results),
                open_ports=open_count,
                status="completed",
            ),
        )

        logger.info(
            "Completed TCP scan %s: %d open, %d closed, %d no_response, %d filtered in %.2fs",
            scan_id,
            open_count,
            closed_count,
            no_response_count,
            filtered_count,
            duration,
        )

        return response

    # ==================== UDP SCAN EXECUTION ====================

    @classmethod
    async def execute_udp_scan(cls, req: UdpScanRequest) -> UdpScanExecutionResponse:
        """Executes a UDP datagram port scan asynchronously without blocking the event loop."""
        target_ip = cls.resolve_target_ip(req.target)
        if not cls.verify_target_authorized(target_ip):
            raise ValueError(
                f"Target '{target_ip}' is outside authorized scanning boundaries (safe-mode active: localhost & RFC-1918 only)."
            )

        ports = cls.resolve_ports(req.ports, req.port_range, req.preset, is_udp=True)
        scan_id = f"udp-{uuid.uuid4().hex[:8]}"
        started_at = datetime.now(timezone.utc)

        logger.info(
            "Starting UDP scan %s against %s (%d ports, timeout=%.1fs, concurrency=%d)",
            scan_id,
            target_ip,
            len(ports),
            req.timeout,
            req.concurrency,
        )

        results: List[UdpScanResultItem] = await asyncio.to_thread(
            scan_udp_ports_concurrent,
            target_ip=target_ip,
            ports=ports,
            timeout=req.timeout,
            concurrency=req.concurrency,
        )

        completed_at = datetime.now(timezone.utc)
        duration = round((completed_at - started_at).total_seconds(), 2)

        open_count = sum(1 for r in results if r.state == "OPEN")
        closed_count = sum(1 for r in results if r.state == "CLOSED")
        open_or_filtered_count = sum(1 for r in results if r.state == "OPEN|FILTERED")
        unknown_count = sum(1 for r in results if r.state == "UNKNOWN")

        response = UdpScanExecutionResponse(
            scan_id=scan_id,
            target=target_ip,
            scan_type="UDP_DGRAM",
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            total_ports=len(results),
            open_ports=open_count,
            closed_ports=closed_count,
            open_or_filtered_ports=open_or_filtered_count,
            unknown_ports=unknown_count,
            results=results,
        )

        cls._udp_scans[scan_id] = response
        cls._latest_udp_scan = response
        cls._history.insert(
            0,
            ScanHistoryItem(
                scan_id=scan_id,
                target=target_ip,
                scan_type="UDP_DGRAM",
                started_at=started_at,
                duration_seconds=duration,
                total_ports=len(results),
                open_ports=open_count,
                status="completed",
            ),
        )

        logger.info(
            "Completed UDP scan %s: %d open, %d closed, %d open|filtered in %.2fs",
            scan_id,
            open_count,
            closed_count,
            open_or_filtered_count,
            duration,
        )

        return response

    @classmethod
    def get_scan(cls, scan_id: str) -> Optional[Union[ScanExecutionResponse, UdpScanExecutionResponse]]:
        """Retrieves a historical scan (TCP or UDP) by its unique ID.

        If not in active memory, attempts to load from archived report exports in backend/reports.
        """
        if scan_id in cls._scans:
            return cls._scans[scan_id]
        if scan_id in cls._udp_scans:
            return cls._udp_scans[scan_id]

        # Disk fallback: inspect backend/reports for archived scan JSON
        try:
            from pathlib import Path
            import json
            reports_dir = Path(__file__).resolve().parent.parent.parent / "reports"
            for jf in reports_dir.glob(f"*{scan_id}*.json"):
                with open(jf, "r", encoding="utf-8") as f:
                    jdata = json.load(f)
                if jdata.get("report_type") == "tcp_scan" and "findings" in jdata:
                    findings = [PortScanResultItem(**it) for it in jdata["findings"]]
                    tot = len(findings)
                    opn = sum(1 for it in findings if it.state == "OPEN")
                    cls_cnt = sum(1 for it in findings if it.state == "CLOSED")
                    flt = sum(1 for it in findings if it.state == "FILTERED")
                    no_resp = sum(1 for it in findings if it.state == "NO_RESPONSE")
                    exp_date_str = jdata.get("export_date") or jdata.get("generated_at") or datetime.now(timezone.utc).isoformat()
                    try:
                        ts = datetime.fromisoformat(exp_date_str)
                    except Exception:
                        ts = datetime.now(timezone.utc)
                    dur = jdata.get("metrics", {}).get("Duration (s)", 1.02)
                    tgt = jdata.get("source", {}).get("target") or jdata.get("scope_and_target", {}).get("Target Host") or "127.0.0.1"
                    scan_obj = ScanExecutionResponse(
                        scan_id=scan_id,
                        target=tgt,
                        scan_type="TCP_CONNECT",
                        status="completed",
                        started_at=ts,
                        completed_at=ts,
                        duration_seconds=float(dur),
                        total_ports=tot,
                        open_ports=opn,
                        closed_ports=cls_cnt,
                        filtered_ports=flt,
                        no_response_ports=no_resp,
                        filtered_or_unknown_ports=flt + no_resp,
                        results=findings,
                    )
                    cls._scans[scan_id] = scan_obj
                    if cls._latest_scan is None:
                        cls._latest_scan = scan_obj
                    return scan_obj
        except Exception as e:
            logger.warning("Could not load scan %s from archive: %s", scan_id, e)

        return None

    @classmethod
    def get_history(cls, limit: int = 50) -> List[ScanHistoryItem]:
        """Returns recent scan history records (both TCP and UDP)."""
        return cls._history[:limit]

    @classmethod
    def get_latest_scan(cls) -> Optional[ScanExecutionResponse]:
        """Returns the most recent TCP scan result."""
        return cls._latest_scan

    @classmethod
    def get_latest_udp_scan(cls) -> Optional[UdpScanExecutionResponse]:
        """Returns the most recent UDP scan result."""
        return cls._latest_udp_scan

    @classmethod
    def get_status(cls) -> ScannerStatusData:
        """Returns operational engine status for Engine A."""
        return ScannerStatusData(
            available=True,
            status="operational",
            message="Dual-engine TCP Connect and UDP Port Scanner is active and operational.",
            engine_version="0.3.0-hybrid",
            supported_methods=["TCP_CONNECT", "UDP_DGRAM"],
            max_concurrent_targets=1,
            safe_mode_enforced=True,
        )
