from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.schemas.common import ApiResponse
from backend.app.schemas.discovery import (
    DiscoveryHistoryItem,
    DiscoveryValidationRequest,
    DiscoveryValidationResponse,
    HostDiscoveryRequest,
    HostDiscoveryResponse,
    HostDiscoveryStatusData,
)
from backend.app.services.discovery_service import DiscoveryService

router = APIRouter(prefix="/discovery", tags=["Host Discovery"])


@router.get("/status", response_model=ApiResponse[HostDiscoveryStatusData])
async def get_discovery_status() -> ApiResponse[HostDiscoveryStatusData]:
    """Returns host discovery engine status, supported probing techniques, and availability."""
    data = DiscoveryService.get_status()
    return ApiResponse(
        success=True,
        message=data.message,
        data=data,
    )


@router.post("/validate", response_model=ApiResponse[DiscoveryValidationResponse])
async def validate_discovery_cidr(
    request: DiscoveryValidationRequest,
) -> ApiResponse[DiscoveryValidationResponse]:
    """Pre-validates CIDR subnet notation, size, and safe-mode authorization without running discovery."""
    result = DiscoveryService.validate_discovery_config(request.cidr)
    return ApiResponse(
        success=result.valid,
        message="Subnet is valid and authorized for discovery."
        if result.valid
        else (result.error or "Validation failed"),
        data=result,
    )


@router.post("/scan", response_model=ApiResponse[HostDiscoveryResponse])
async def execute_host_discovery(
    request: HostDiscoveryRequest,
) -> ApiResponse[HostDiscoveryResponse]:
    """Executes subnet host discovery using ARP, ICMP echo, TCP connect, or AUTO triage."""
    try:
        discovery_result = await DiscoveryService.execute_discovery(request)
        return ApiResponse(
            success=True,
            message=(
                f"Host discovery {discovery_result.discovery_id} completed: "
                f"{discovery_result.online_hosts_count} online hosts identified across "
                f"{discovery_result.total_probed} scanned addresses in {discovery_result.duration_seconds}s."
            ),
            data=discovery_result,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Subnet discovery failed: {exc}",
        )


@router.get("/scans/{discovery_id}", response_model=ApiResponse[HostDiscoveryResponse])
async def get_discovery_by_id(
    discovery_id: str,
) -> ApiResponse[HostDiscoveryResponse]:
    """Retrieves full results for a previously executed subnet discovery session."""
    discovery = DiscoveryService.get_discovery_by_id(discovery_id)
    if not discovery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host discovery session '{discovery_id}' not found.",
        )
    return ApiResponse(
        success=True,
        message="Discovery session retrieved successfully.",
        data=discovery,
    )


@router.get("/history", response_model=ApiResponse[List[DiscoveryHistoryItem]])
async def get_discovery_history(
    limit: int = Query(50, ge=1, le=100, description="Max history items to retrieve"),
) -> ApiResponse[List[DiscoveryHistoryItem]]:
    """Retrieves chronological summary records of completed host discovery operations."""
    items = DiscoveryService.get_history(limit=limit)
    return ApiResponse(
        success=True,
        message=f"Retrieved {len(items)} host discovery history records.",
        data=items,
    )


@router.get("/latest", response_model=ApiResponse[Optional[HostDiscoveryResponse]])
async def get_latest_discovery() -> ApiResponse[Optional[HostDiscoveryResponse]]:
    """Retrieves the most recent subnet host discovery run, or null if no scans have been performed."""
    latest = DiscoveryService.get_latest_discovery()
    return ApiResponse(
        success=True,
        message="Latest host discovery record retrieved."
        if latest
        else "No host discoveries executed in this session.",
        data=latest,
    )

