from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.capture.capture_manager import CaptureManager
from backend.app.schemas.analytics import (
    AnalyticsOverviewResponse,
    BandwidthAnalyticsResponse,
    ConnectionsAnalyticsResponse,
    DnsAnalyticsResponse,
    ProtocolAnalyticsResponse,
    TopTalkersResponse,
    TrafficTimelineResponse,
)

router = APIRouter(prefix="/analytics", tags=["Traffic Analytics"])


def _resolve_analytics_engine(session_id: str):
    """Resolves AnalyticsEngine for session_id or latest session."""
    target_id = None if session_id.lower() in ("latest", "active", "current") else session_id
    engine = CaptureManager.get_analytics_engine(target_id)
    if not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Traffic analytics session '{session_id}' not found. Please start a capture session first.",
        )
    return engine


@router.get(
    "/{session_id}/overview",
    response_model=AnalyticsOverviewResponse,
    summary="Get analytics executive summary KPIs",
)
def get_analytics_overview(session_id: str):
    engine = _resolve_analytics_engine(session_id)
    return engine.get_overview()


@router.get(
    "/{session_id}/protocols",
    response_model=ProtocolAnalyticsResponse,
    summary="Get transport protocol distribution and application protocol breakdown",
)
def get_protocol_analytics(session_id: str):
    engine = _resolve_analytics_engine(session_id)
    return engine.get_protocols()


@router.get(
    "/{session_id}/bandwidth",
    response_model=BandwidthAnalyticsResponse,
    summary="Get bandwidth throughput and rolling window statistics",
)
def get_bandwidth_analytics(
    session_id: str,
    window_seconds: int = Query(1, ge=1, le=60, description="Rolling aggregation window in seconds"),
):
    engine = _resolve_analytics_engine(session_id)
    return engine.get_bandwidth(window_seconds=window_seconds)


@router.get(
    "/{session_id}/top-talkers",
    response_model=TopTalkersResponse,
    summary="Get top transmitting and receiving endpoints",
)
def get_top_talkers_analytics(session_id: str):
    engine = _resolve_analytics_engine(session_id)
    return engine.get_top_talkers()


@router.get(
    "/{session_id}/connections",
    response_model=ConnectionsAnalyticsResponse,
    summary="Get active and tracked connection flows",
)
def get_connection_flows_analytics(
    session_id: str,
    limit: int = Query(100, ge=1, le=500, description="Maximum flows to return"),
):
    engine = _resolve_analytics_engine(session_id)
    return engine.get_connections(limit=limit)


@router.get(
    "/{session_id}/dns",
    response_model=DnsAnalyticsResponse,
    summary="Get DNS query names, response codes, and query types",
)
def get_dns_analytics(session_id: str):
    engine = _resolve_analytics_engine(session_id)
    return engine.get_dns()


@router.get(
    "/{session_id}/timeline",
    response_model=TrafficTimelineResponse,
    summary="Get second-by-second traffic timeline time series",
)
def get_traffic_timeline(session_id: str):
    engine = _resolve_analytics_engine(session_id)
    return engine.get_timeline()
