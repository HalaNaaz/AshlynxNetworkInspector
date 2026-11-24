import uuid
from datetime import datetime, timezone
import pytest
from backend.app.capture.capture_manager import CaptureManager
from backend.app.db.repositories.capture_repo import CaptureRepository
from backend.app.schemas.capture import CaptureSessionResponse, CaptureStatistics


def test_recover_interrupted_sessions_on_restart():
    """Verifies that orphaned CAPTURING sessions in SQLite are marked as INTERRUPTED upon server recovery."""
    test_session_id = f"test-crash-{uuid.uuid4().hex[:8]}"

    # Simulate a session left in CAPTURING status before restart
    dummy_session = CaptureSessionResponse(
        session_id=test_session_id,
        interface_id="if-01",
        interface_name="eth0",
        status="CAPTURING",
        filter_bpf="",
        buffer_limit=1000,
        started_at=datetime.now(timezone.utc),
        stopped_at=None,
        duration_seconds=12.5,
        statistics=CaptureStatistics(total_captured=42, bytes_captured=4200),
    )
    CaptureRepository.save_capture_session(dummy_session)

    # Verify initial stored state is CAPTURING
    row = CaptureRepository.get_capture_session(test_session_id)
    assert row is not None
    assert row["status"] == "CAPTURING"

    # Execute recovery function
    recovered = CaptureRepository.recover_interrupted_sessions()
    assert recovered >= 1

    # Verify session is now INTERRUPTED and stopped_at is populated
    updated_row = CaptureRepository.get_capture_session(test_session_id)
    assert updated_row["status"] == "INTERRUPTED"
    assert updated_row["stopped_at"] is not None


def test_capture_manager_restores_session_after_in_memory_eviction():
    """Verifies that CaptureManager resurrects session metadata from SQLite when in-memory dictionary is cleared."""
    test_session_id = f"test-persist-{uuid.uuid4().hex[:8]}"

    dummy_session = CaptureSessionResponse(
        session_id=test_session_id,
        interface_id="if-saved",
        interface_name="Ethernet 2",
        status="STOPPED",
        filter_bpf="tcp",
        buffer_limit=2000,
        started_at=datetime.now(timezone.utc),
        stopped_at=datetime.now(timezone.utc),
        duration_seconds=60.0,
        statistics=CaptureStatistics(total_captured=150, bytes_captured=15000),
    )
    CaptureRepository.save_capture_session(dummy_session)

    # Wipe in-memory dictionary completely (simulating server reboot)
    CaptureManager._sessions.clear()
    CaptureManager._active_engine = None

    # Retrieve by ID -> should be resurrected from SQLite
    resurrected = CaptureManager.get_session_by_id(test_session_id)
    assert resurrected is not None
    assert resurrected.session_id == test_session_id
    assert resurrected.interface_name == "Ethernet 2"
    assert resurrected.status == "STOPPED"

    summary = resurrected.get_session_summary()
    assert summary.session_id == test_session_id
    assert summary.statistics.total_captured == 150

    # Verify get_all_sessions includes the resurrected session
    all_sessions = CaptureManager.get_all_sessions()
    session_ids = [s.session_id for s in all_sessions]
    assert test_session_id in session_ids

    # Verify analytics and security engines can be resolved
    analytics = CaptureManager.get_analytics_engine(test_session_id)
    assert analytics is not None
    assert analytics.session_id == test_session_id

    security = CaptureManager.get_security_engine(test_session_id)
    assert security is not None
    assert security.session_id == test_session_id
