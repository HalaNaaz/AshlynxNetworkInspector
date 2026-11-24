import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

from backend.app.analytics.analytics_engine import AnalyticsEngine
from backend.app.capture.capture_engine import LiveCaptureEngine
from backend.app.capture.environment import evaluate_capture_environment
from backend.app.capture.interface_manager import (
    find_interface_by_id_or_name,
    list_capture_interfaces,
)
from backend.app.core.logging import logger
from backend.app.schemas.capture import (
    CaptureInterfaceItem,
    CaptureSessionResponse,
    CaptureStartRequest,
    CaptureStatistics,
)
from backend.app.security.detection_engine import SecurityDetectionEngine

PREDEFINED_BPF_FILTERS = {
    "all": "",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "dns": "port 53",
    "arp": "arp",
    "ip": "ip",
    "ip6": "ip6",
}


class HistoricalCaptureSession:
    """Read-only adapter for historical capture sessions restored from SQLite (VULN-003)."""

    def __init__(self, data: dict):
        self.session_id = data["session_id"]
        self.interface_id = data.get("interface_id") or "restored-if"
        self.interface_name = data.get("interface_name") or "unknown"
        self.status = data.get("status") or "STOPPED"
        self.filter_bpf = data.get("filter_bpf") or ""
        self.buffer_limit = data.get("buffer_limit") or 1000

        started = data.get("started_at")
        if isinstance(started, str):
            try:
                self.started_at = datetime.fromisoformat(started)
            except Exception:
                self.started_at = datetime.now(timezone.utc)
        elif isinstance(started, datetime):
            self.started_at = started
        else:
            self.started_at = datetime.now(timezone.utc)

        stopped = data.get("stopped_at")
        if isinstance(stopped, str):
            try:
                self.stopped_at = datetime.fromisoformat(stopped)
            except Exception:
                self.stopped_at = None
        elif isinstance(stopped, datetime):
            self.stopped_at = stopped
        else:
            self.stopped_at = None

        self.duration_seconds = float(data.get("duration_seconds") or 0.0)
        self._total_captured = int(data.get("total_captured") or 0)
        self._bytes_captured = int(data.get("bytes_captured") or 0)
        self._dropped_packets = int(data.get("dropped_packets") or 0)

        # Reconstructed analytics engine proxy / instance
        self.analytics_engine = AnalyticsEngine(session_id=self.session_id)
        self.analytics_engine.set_status(self.status, stopped_at=self.stopped_at)
        snap = data.get("analytics")
        if snap:
            self.analytics_engine._total_packets = int(snap.get("total_packets") or self._total_captured)
            self.analytics_engine._total_bytes = int(snap.get("total_bytes") or self._bytes_captured)
            self.analytics_engine._final_duration = float(snap.get("duration_seconds") or self.duration_seconds)
            self.analytics_engine.bandwidth_tracker.inbound_bytes = int(snap.get("inbound_bytes") or 0)
            self.analytics_engine.bandwidth_tracker.outbound_bytes = int(snap.get("outbound_bytes") or 0)
            self.analytics_engine.bandwidth_tracker.local_bytes = int(snap.get("local_bytes") or 0)

        # Security engine populated with SQLite events
        self.security_engine = SecurityDetectionEngine(session_id=self.session_id)
        try:
            from backend.app.db.repositories.security_repo import SecurityRepository
            db_events = SecurityRepository.list_events(session_id=self.session_id, limit=200)
            for ev in db_events:
                self.security_engine.event_manager._events[ev.event_id] = ev
        except Exception:
            pass

    def get_statistics(self) -> CaptureStatistics:
        return CaptureStatistics(
            total_captured=self._total_captured,
            retained_in_buffer=0,
            dropped_packets=self._dropped_packets,
            packets_received=self._total_captured,
            packets_processed=self._total_captured,
            queue_depth=0,
            tcp_count=0,
            udp_count=0,
            icmp_count=0,
            arp_count=0,
            other_count=0,
            bytes_captured=self._bytes_captured,
            capture_duration_seconds=self.duration_seconds,
        )

    def get_session_summary(self) -> CaptureSessionResponse:
        return CaptureSessionResponse(
            session_id=self.session_id,
            interface_id=self.interface_id,
            interface_name=self.interface_name,
            status=self.status,
            filter_bpf=self.filter_bpf,
            buffer_limit=self.buffer_limit,
            started_at=self.started_at,
            stopped_at=self.stopped_at,
            duration_seconds=self.duration_seconds,
            statistics=self.get_statistics(),
        )

    def get_packets(self, offset: int = 0, limit: int = 100, protocol: Optional[str] = None, search: Optional[str] = None):
        return (0, [])

    def clear_buffer(self) -> None:
        pass


class CaptureManager:
    """Singleton service coordinating packet capture sessions, interfaces, and filter validation."""

    _active_engine: Optional[LiveCaptureEngine] = None
    _sessions: Dict[str, LiveCaptureEngine] = {}

    @classmethod
    def resolve_effective_filter(
        cls, preset: Optional[str], custom_bpf: Optional[str]
    ) -> str:
        """Resolves and validates effective BPF filter expression."""
        if custom_bpf and custom_bpf.strip():
            # Basic validation of custom BPF expression
            clean = custom_bpf.strip()
            # Reject dangerous shell injection attempts if any
            if any(ch in clean for ch in (";", "|", "&", "`", "$", "\n", "\r")):
                raise ValueError("Custom BPF filter contains illegal characters.")
            return clean

        preset_clean = (preset or "all").strip().lower()
        if preset_clean in PREDEFINED_BPF_FILTERS:
            return PREDEFINED_BPF_FILTERS[preset_clean]

        raise ValueError(
            f"Unknown filter preset '{preset}'. Allowed: {', '.join(PREDEFINED_BPF_FILTERS.keys())}"
        )

    @classmethod
    def start_capture(cls, request: CaptureStartRequest) -> CaptureSessionResponse:
        """Validates configuration and launches a live capture session."""
        if cls._active_engine and cls._active_engine.status == "CAPTURING":
            raise ValueError(
                f"Capture session {cls._active_engine.session_id} is already in progress. Stop it before starting a new one."
            )

        # 1. Validate environment capability
        env = evaluate_capture_environment()
        if not env.can_capture:
            raise RuntimeError(f"{env.capability_status}: {env.message}")

        # 2. Validate interface
        iface = find_interface_by_id_or_name(request.interface_id)
        if not iface:
            raise ValueError(f"Network interface '{request.interface_id}' not found.")

        # 3. Resolve BPF filter
        effective_bpf = cls.resolve_effective_filter(
            request.filter_preset, request.custom_bpf_filter
        )

        session_id = f"cap-{uuid.uuid4().hex[:12]}"
        bound_ips = set(iface.ipv4_addresses + iface.ipv6_addresses)
        engine = LiveCaptureEngine(
            session_id=session_id,
            interface_id=iface.id,
            interface_name=iface.name,
            filter_bpf=effective_bpf,
            buffer_limit=request.buffer_limit,
            interface_ips=bound_ips,
        )

        engine.start()
        cls._active_engine = engine
        cls._sessions[session_id] = engine

        summary = engine.get_session_summary()
        try:
            from backend.app.db.repositories.capture_repo import CaptureRepository
            CaptureRepository.save_capture_session(summary)
        except Exception as exc:
            logger.warning("Could not persist initial capture session %s to SQLite: %s", session_id, exc)

        return summary

    @classmethod
    def stop_capture(cls) -> CaptureSessionResponse:
        """Stops the currently running packet capture session."""
        if not cls._active_engine or cls._active_engine.status != "CAPTURING":
            raise ValueError("No active packet capture session is currently running.")

        cls._active_engine.stop()
        summary = cls._active_engine.get_session_summary()

        try:
            from backend.app.db.repositories.capture_repo import CaptureRepository
            CaptureRepository.update_capture_session(
                session_id=summary.session_id,
                status="STOPPED",
                stopped_at=summary.stopped_at,
                duration_seconds=summary.duration_seconds,
                total_captured=summary.statistics.total_captured,
                bytes_captured=summary.statistics.bytes_captured,
                dropped_packets=summary.statistics.dropped_packets,
            )
            overview = cls._active_engine.analytics_engine.get_overview()
            flows_resp = cls._active_engine.analytics_engine.get_connections(limit=200)
            CaptureRepository.save_analytics_snapshot(summary.session_id, overview)
            CaptureRepository.save_connection_flows(summary.session_id, flows_resp.flows)
        except Exception as exc:
            logger.warning("Could not persist capture session %s closure to SQLite: %s", summary.session_id, exc)

        return summary

    @classmethod
    def get_active_engine(cls) -> Optional[LiveCaptureEngine]:
        """Returns the currently capturing engine instance if active."""
        if cls._active_engine and cls._active_engine.status == "CAPTURING":
            return cls._active_engine
        return None

    @classmethod
    def get_active_or_latest_engine(cls) -> Optional[Union[LiveCaptureEngine, HistoricalCaptureSession]]:
        """Returns the active engine or the most recent session engine from memory or SQLite."""
        if cls._active_engine:
            return cls._active_engine
        if cls._sessions:
            # Return last created session
            last_id = list(cls._sessions.keys())[-1]
            return cls._sessions[last_id]

        # Fall back to SQLite most recent session (VULN-003)
        try:
            from backend.app.db.repositories.capture_repo import CaptureRepository
            past = CaptureRepository.list_capture_sessions(limit=1)
            if past:
                return cls.get_session_by_id(past[0]["session_id"])
        except Exception as exc:
            logger.debug("Could not resolve latest session from SQLite: %s", exc)
        return None

    @classmethod
    def get_session_by_id(cls, session_id: str) -> Optional[Union[LiveCaptureEngine, HistoricalCaptureSession]]:
        """Retrieves a capture engine instance by its session ID, falling back to SQLite."""
        if session_id in cls._sessions:
            return cls._sessions[session_id]

        # Fall back to SQLite persistence (VULN-003)
        try:
            from backend.app.db.repositories.capture_repo import CaptureRepository
            row = CaptureRepository.get_capture_session(session_id)
            if row:
                restored = HistoricalCaptureSession(row)
                cls._sessions[session_id] = restored
                return restored
        except Exception as exc:
            logger.warning("Error restoring session %s from SQLite: %s", session_id, exc)

        return None

    @classmethod
    def get_all_sessions(cls) -> List[CaptureSessionResponse]:
        """Returns summaries of all capture sessions, merging in-memory and SQLite records."""
        summaries: Dict[str, CaptureSessionResponse] = {
            engine.session_id: engine.get_session_summary()
            for engine in cls._sessions.values()
        }

        try:
            from backend.app.db.repositories.capture_repo import CaptureRepository
            db_sessions = CaptureRepository.list_capture_sessions(limit=100)
            for row in db_sessions:
                sid = row["session_id"]
                if sid not in summaries:
                    restored = HistoricalCaptureSession(row)
                    summaries[sid] = restored.get_session_summary()
        except Exception as exc:
            logger.warning("Could not list historical capture sessions from SQLite: %s", exc)

        # Sort descending by started_at
        return sorted(
            summaries.values(),
            key=lambda s: s.started_at or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    @classmethod
    def get_analytics_engine(cls, session_id: Optional[str] = None):
        """Retrieves AnalyticsEngine for a given session, or active/latest session."""
        if session_id:
            engine = cls.get_session_by_id(session_id)
        else:
            engine = cls.get_active_or_latest_engine()

        if engine and hasattr(engine, "analytics_engine"):
            return engine.analytics_engine
        return None

    @classmethod
    def get_security_engine(cls, session_id: Optional[str] = None):
        """Retrieves SecurityDetectionEngine for a given session, or active/latest session."""
        if session_id:
            engine = cls.get_session_by_id(session_id)
        else:
            engine = cls.get_active_or_latest_engine()

        if engine and hasattr(engine, "security_engine"):
            return engine.security_engine
        return None

    @classmethod
    def register_test_engine(cls, engine: LiveCaptureEngine) -> None:
        """Helper for test harness to inject a mock engine."""
        cls._active_engine = engine
        cls._sessions[engine.session_id] = engine
