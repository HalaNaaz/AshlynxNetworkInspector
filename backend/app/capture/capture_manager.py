import uuid
from typing import Dict, List, Optional

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
)

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

        return engine.get_session_summary()

    @classmethod
    def stop_capture(cls) -> CaptureSessionResponse:
        """Stops the currently running packet capture session."""
        if not cls._active_engine or cls._active_engine.status != "CAPTURING":
            raise ValueError("No active packet capture session is currently running.")

        cls._active_engine.stop()
        summary = cls._active_engine.get_session_summary()
        return summary

    @classmethod
    def get_active_engine(cls) -> Optional[LiveCaptureEngine]:
        """Returns the currently capturing engine instance if active."""
        if cls._active_engine and cls._active_engine.status == "CAPTURING":
            return cls._active_engine
        return None

    @classmethod
    def get_active_or_latest_engine(cls) -> Optional[LiveCaptureEngine]:
        """Returns the active engine or the most recent session engine."""
        if cls._active_engine:
            return cls._active_engine
        if cls._sessions:
            # Return last created session
            last_id = list(cls._sessions.keys())[-1]
            return cls._sessions[last_id]
        return None

    @classmethod
    def get_session_by_id(cls, session_id: str) -> Optional[LiveCaptureEngine]:
        """Retrieves a capture engine instance by its session ID."""
        return cls._sessions.get(session_id)

    @classmethod
    def get_all_sessions(cls) -> List[CaptureSessionResponse]:
        """Returns summaries of all capture sessions executed in this lifecycle."""
        return [engine.get_session_summary() for engine in cls._sessions.values()]

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

