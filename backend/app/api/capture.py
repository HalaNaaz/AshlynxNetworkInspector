from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.capture.capture_manager import CaptureManager
from backend.app.capture.environment import evaluate_capture_environment
from backend.app.capture.interface_manager import list_capture_interfaces
from backend.app.schemas.capture import (
    CaptureEnvironmentData,
    CaptureInterfaceItem,
    CapturePacketsResponse,
    CaptureSessionResponse,
    CaptureStartRequest,
    CaptureStatistics,
)
from backend.app.schemas.common import ApiResponse

router = APIRouter(prefix="/capture", tags=["Live Packet Capture (Engine B)"])


@router.get("/status", response_model=ApiResponse[CaptureEnvironmentData])
async def get_capture_environment_status() -> ApiResponse[CaptureEnvironmentData]:
    """Evaluates Npcap, Scapy, and driver readiness for live packet capture."""
    env = evaluate_capture_environment()
    return ApiResponse(
        success=True,
        message=env.message,
        data=env,
    )


@router.get("/interfaces", response_model=ApiResponse[List[CaptureInterfaceItem]])
async def get_capture_interfaces() -> ApiResponse[List[CaptureInterfaceItem]]:
    """Lists system network interfaces with hardware descriptions, addresses, and capture readiness."""
    ifaces = list_capture_interfaces()
    return ApiResponse(
        success=True,
        message=f"Discovered {len(ifaces)} network interfaces.",
        data=ifaces,
    )


@router.post("/start", response_model=ApiResponse[CaptureSessionResponse])
async def start_capture_session(
    request: CaptureStartRequest,
) -> ApiResponse[CaptureSessionResponse]:
    """Initiates live packet capture on the selected interface with BPF filtering."""
    try:
        session = CaptureManager.start_capture(request)
        return ApiResponse(
            success=True,
            message=f"Packet capture session {session.session_id} started on interface '{session.interface_name}'.",
            data=session,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except RuntimeError as re:
        # Dependency/Npcap missing error
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(re))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start packet capture: {exc}",
        )


@router.post("/stop", response_model=ApiResponse[CaptureSessionResponse])
async def stop_capture_session() -> ApiResponse[CaptureSessionResponse]:
    """Terminates the active live packet capture session cleanly."""
    try:
        session = CaptureManager.stop_capture()
        return ApiResponse(
            success=True,
            message=f"Capture session {session.session_id} stopped. Total {session.statistics.total_captured} frames captured.",
            data=session,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop capture: {exc}",
        )


@router.get("/sessions", response_model=ApiResponse[List[CaptureSessionResponse]])
async def list_capture_sessions() -> ApiResponse[List[CaptureSessionResponse]]:
    """Returns all packet capture sessions executed in this server lifecycle."""
    sessions = CaptureManager.get_all_sessions()
    return ApiResponse(
        success=True,
        message=f"Retrieved {len(sessions)} capture sessions.",
        data=sessions,
    )


@router.get("/sessions/{session_id}", response_model=ApiResponse[CaptureSessionResponse])
async def get_session_by_id(session_id: str) -> ApiResponse[CaptureSessionResponse]:
    """Retrieves metadata and status for a specific capture session."""
    engine = CaptureManager.get_session_by_id(session_id)
    if not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{session_id}' not found.",
        )
    return ApiResponse(
        success=True,
        message="Capture session retrieved successfully.",
        data=engine.get_session_summary(),
    )


@router.get("/sessions/{session_id}/statistics", response_model=ApiResponse[CaptureStatistics])
async def get_session_statistics(session_id: str) -> ApiResponse[CaptureStatistics]:
    """Retrieves live packet traffic statistics for a capture session."""
    engine = CaptureManager.get_session_by_id(session_id)
    if not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{session_id}' not found.",
        )
    return ApiResponse(
        success=True,
        message="Session statistics retrieved.",
        data=engine.get_statistics(),
    )


@router.get("/sessions/{session_id}/packets", response_model=ApiResponse[CapturePacketsResponse])
async def get_session_packets(
    session_id: str,
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (TCP, UDP, ICMP, ARP, DNS, ALL)"),
    search: Optional[str] = Query(None, description="Search by IP, port, or protocol"),
) -> ApiResponse[CapturePacketsResponse]:
    """Retrieves paginated packet metadata items from the in-memory ring buffer (zero payload contents)."""
    engine = CaptureManager.get_session_by_id(session_id)
    if not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{session_id}' not found.",
        )

    total, packets = engine.get_packets(offset=offset, limit=limit, protocol=protocol, search=search)
    return ApiResponse(
        success=True,
        message=f"Retrieved {len(packets)} of {total} matching packets.",
        data=CapturePacketsResponse(
            session_id=session_id,
            total_matching=total,
            offset=offset,
            limit=limit,
            packets=packets,
        ),
    )


@router.post("/sessions/{session_id}/clear", response_model=ApiResponse[dict])
async def clear_session_buffer(session_id: str) -> ApiResponse[dict]:
    """Clears the display buffer for a session while retaining cumulative counts."""
    engine = CaptureManager.get_session_by_id(session_id)
    if not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture session '{session_id}' not found.",
        )
    engine.clear_buffer()
    return ApiResponse(
        success=True,
        message="Display packet buffer cleared.",
        data={"session_id": session_id, "cleared": True},
    )

