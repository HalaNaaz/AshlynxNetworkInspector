from typing import List, Optional, Union
from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.common import ApiResponse
from backend.app.schemas.scanner import (
    PortScanRequest,
    ScanExecutionResponse,
    ScanHistoryItem,
    ScannerStatusData,
    ScanValidationRequest,
    ScanValidationResponse,
    UdpScanRequest,
    UdpScanExecutionResponse,
)
from backend.app.services.scanner_service import ScannerService

router = APIRouter(prefix="/scanner", tags=["Port Scanner"])


@router.get("/status", response_model=ApiResponse[ScannerStatusData])
async def get_scanner_status() -> ApiResponse[ScannerStatusData]:
    """Returns port scanner engine status, supported scan methods, and availability."""
    data = ScannerService.get_status()
    return ApiResponse(
        success=True,
        message=data.message,
        data=data,
    )


# ==================== TCP SCANNER ENDPOINTS ====================

@router.post("/validate", response_model=ApiResponse[ScanValidationResponse])
async def validate_scan_config(request: ScanValidationRequest) -> ApiResponse[ScanValidationResponse]:
    """Pre-validates TCP target authorization, address resolution, and port ranges without scanning."""
    result = ScannerService.validate_request(request, is_udp=False)
    return ApiResponse(
        success=result.valid,
        message="Scan configuration valid" if result.valid else (result.error or "Validation failed"),
        data=result,
    )


@router.post("/scan", response_model=ApiResponse[ScanExecutionResponse])
async def execute_port_scan(request: PortScanRequest) -> ApiResponse[ScanExecutionResponse]:
    """Executes a custom TCP Connect scan against an authorized target address."""
    try:
        scan_result = await ScannerService.execute_scan(request)
        return ApiResponse(
            success=True,
            message=f"TCP Connect scan {scan_result.scan_id} completed: {scan_result.open_ports} open, {scan_result.closed_ports} closed, {scan_result.no_response_ports} no response.",
            data=scan_result,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan execution error: {str(exc)}",
        )


@router.get("/scans/{scan_id}", response_model=ApiResponse[Union[ScanExecutionResponse, UdpScanExecutionResponse]])
async def get_scan_result(scan_id: str) -> ApiResponse[Union[ScanExecutionResponse, UdpScanExecutionResponse]]:
    """Retrieves full results and findings for a specific scan session ID (TCP or UDP)."""
    scan = ScannerService.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan session '{scan_id}' not found.",
        )
    return ApiResponse(
        success=True,
        message="Scan session retrieved",
        data=scan,
    )


@router.get("/history", response_model=ApiResponse[List[ScanHistoryItem]])
async def get_scan_history() -> ApiResponse[List[ScanHistoryItem]]:
    """Returns archived scan session summaries in reverse chronological order."""
    history = ScannerService.get_history()
    return ApiResponse(
        success=True,
        message=f"Retrieved {len(history)} historical scan record(s)",
        data=history,
    )


@router.get("/latest", response_model=ApiResponse[Optional[ScanExecutionResponse]])
async def get_latest_scan() -> ApiResponse[Optional[ScanExecutionResponse]]:
    """Returns the most recent TCP scan findings for dashboard telemetry."""
    latest = ScannerService.get_latest_scan()
    return ApiResponse(
        success=True,
        message="Latest scan retrieved" if latest else "No scans executed yet in session",
        data=latest,
    )


# ==================== UDP SCANNER ENDPOINTS ====================

@router.post("/udp/validate", response_model=ApiResponse[ScanValidationResponse])
async def validate_udp_scan_config(request: ScanValidationRequest) -> ApiResponse[ScanValidationResponse]:
    """Pre-validates UDP target authorization, address resolution, and port ranges without scanning."""
    result = ScannerService.validate_request(request, is_udp=True)
    return ApiResponse(
        success=result.valid,
        message="UDP scan configuration valid" if result.valid else (result.error or "Validation failed"),
        data=result,
    )


@router.post("/udp/scan", response_model=ApiResponse[UdpScanExecutionResponse])
async def execute_udp_port_scan(request: UdpScanRequest) -> ApiResponse[UdpScanExecutionResponse]:
    """Executes a UDP datagram scan against an authorized target address."""
    try:
        scan_result = await ScannerService.execute_udp_scan(request)
        return ApiResponse(
            success=True,
            message=f"UDP scan {scan_result.scan_id} completed: {scan_result.open_ports} open, {scan_result.closed_ports} closed, {scan_result.open_or_filtered_ports} open|filtered.",
            data=scan_result,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"UDP scan execution error: {str(exc)}",
        )


@router.get("/udp/latest", response_model=ApiResponse[Optional[UdpScanExecutionResponse]])
async def get_latest_udp_scan() -> ApiResponse[Optional[UdpScanExecutionResponse]]:
    """Returns the most recent UDP scan findings for dashboard telemetry."""
    latest = ScannerService.get_latest_udp_scan()
    return ApiResponse(
        success=True,
        message="Latest UDP scan retrieved" if latest else "No UDP scans executed yet in session",
        data=latest,
    )
