from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.capture.capture_manager import CaptureManager
from backend.app.schemas.security import (
    AddEventNoteRequest,
    EventStatusUpdateRequest,
    RuleConfigItem,
    RuleUpdateRequest,
    SecurityEventItem,
    SecurityEventsListResponse,
    SecurityOverviewResponse,
    SecurityStatusResponse,
    SecurityTimelineResponse,
)

router = APIRouter(prefix="/security", tags=["Security Intelligence & Anomaly Detection (Phase 6)"])


def _resolve_security_engine(session_id: Optional[str] = None):
    """Resolves SecurityDetectionEngine for a given session or latest session."""
    target_id = None if not session_id or session_id.lower() in ("latest", "active", "current", "all") else session_id
    engine = CaptureManager.get_security_engine(target_id)
    if not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security detection engine not active for session '{session_id or 'latest'}'. Please initiate a capture session first.",
        )
    return engine


@router.get(
    "/status",
    response_model=SecurityStatusResponse,
    summary="Get passive security engine diagnostic status and baseline readiness",
)
def get_security_status(session_id: Optional[str] = Query(None, description="Optional target session ID")):
    engine = _resolve_security_engine(session_id)
    overview = engine.get_overview()
    return overview.status


@router.get(
    "/overview",
    response_model=SecurityOverviewResponse,
    summary="Get executive security posture overview, category breakdown, and top sources",
)
def get_security_overview(session_id: Optional[str] = Query(None, description="Optional target session ID")):
    engine = _resolve_security_engine(session_id)
    return engine.get_overview()


@router.get(
    "/events",
    response_model=SecurityEventsListResponse,
    summary="Get paginated, filtered security detection events",
)
def list_security_events(
    session_id: Optional[str] = Query(None, description="Filter by capture session ID"),
    severity: Optional[str] = Query(None, description="Filter: INFO, LOW, MEDIUM, HIGH, CRITICAL"),
    category: Optional[str] = Query(None, description="Filter: PORT_SCAN, CONNECTION, TRAFFIC_SPIKE, DNS, SUSPICIOUS_SERVICE"),
    status: Optional[str] = Query(None, description="Filter: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Pagination limit"),
):
    engine = _resolve_security_engine(session_id)
    return engine.list_events(
        severity=severity,
        category=category,
        status=status,
        source_ip=source_ip,
        offset=offset,
        limit=limit,
    )


def _find_event_across_sessions(event_id: str):
    """Finds an event across all active and historical sessions."""
    # First check active or latest
    engine = CaptureManager.get_security_engine(None)
    if engine:
        ev = engine.get_event(event_id)
        if ev:
            return ev, engine

    # Then search all sessions in memory
    for sess in CaptureManager._sessions.values():
        eng = getattr(sess, "security_engine", None)
        if eng:
            ev = eng.get_event(event_id)
            if ev:
                return ev, eng

    # Fallback to persistent SQLite repository across restarts
    try:
        from backend.app.db.repositories.security_repo import SecurityRepository
        db_ev = SecurityRepository.get_event(event_id)
        if db_ev:
            eng = CaptureManager.get_security_engine(db_ev.session_id)
            if not eng:
                from backend.app.security.detection_engine import SecurityDetectionEngine
                eng = SecurityDetectionEngine(session_id=db_ev.session_id)
            eng.event_manager._events[db_ev.event_id] = db_ev
            return db_ev, eng
    except Exception:
        pass

    return None, None


@router.get(
    "/events/{event_id}",
    response_model=SecurityEventItem,
    summary="Get detailed investigation evidence for a specific security event",
)
def get_security_event(event_id: str):
    ev, _ = _find_event_across_sessions(event_id)
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )
    return ev


@router.patch(
    "/events/{event_id}/status",
    response_model=SecurityEventItem,
    summary="Update event investigation lifecycle status",
)
@router.post(
    "/events/{event_id}/status",
    response_model=SecurityEventItem,
    summary="Update event investigation lifecycle status (POST compatibility)",
)
def update_event_status(event_id: str, request: EventStatusUpdateRequest):
    ev, engine = _find_event_across_sessions(event_id)
    if not ev or not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )
    try:
        updated = engine.update_event_status(event_id, request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return updated


@router.post(
    "/events/{event_id}/notes",
    response_model=SecurityEventItem,
    summary="Append a validated analyst investigation note with audit logging",
)
def add_event_note(event_id: str, request: AddEventNoteRequest):
    ev, engine = _find_event_across_sessions(event_id)
    if not ev or not engine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )
    try:
        updated = engine.add_event_note(event_id, request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return updated


@router.get(
    "/timeline",
    response_model=SecurityTimelineResponse,
    summary="Get chronological timeline of detected security events",
)
def get_security_timeline(session_id: Optional[str] = Query(None, description="Optional target session ID")):
    engine = _resolve_security_engine(session_id)
    return engine.get_timeline()


@router.get(
    "/rules",
    response_model=List[RuleConfigItem],
    summary="List all registered detection rules and operational thresholds",
)
def list_detection_rules():
    engine = _resolve_security_engine(None)
    return engine.list_rules()


@router.get(
    "/rules/{rule_id}",
    response_model=RuleConfigItem,
    summary="Get configuration parameters for a specific detection rule",
)
def get_detection_rule(rule_id: str):
    engine = _resolve_security_engine(None)
    rule = engine.rule_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    return rule.to_config()


@router.patch(
    "/rules/{rule_id}",
    response_model=RuleConfigItem,
    summary="Safely update detection rule threshold, window size, or enabled status",
)
def update_detection_rule(rule_id: str, request: RuleUpdateRequest):
    engine = _resolve_security_engine(None)
    updated = engine.update_rule(rule_id, request)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    return updated


@router.get(
    "/sessions/{session_id}/events",
    response_model=SecurityEventsListResponse,
    summary="Get security events strictly isolated to a specific capture session",
)
def get_session_security_events(
    session_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    engine = _resolve_security_engine(session_id)
    return engine.list_events(session_id=session_id, offset=offset, limit=limit)
