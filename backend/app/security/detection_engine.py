import threading
from typing import List, Optional

from backend.app.schemas.capture import PacketMetadataItem
from backend.app.schemas.security import (
    AddEventNoteRequest,
    EventStatusUpdateRequest,
    RuleConfigItem,
    RuleUpdateRequest,
    SecurityEventItem,
    SecurityEventsListResponse,
    SecurityOverviewResponse,
    SecurityTimelineResponse,
)
from backend.app.security.baseline_manager import SessionBaselineManager
from backend.app.security.correlation_engine import CorrelationEngine
from backend.app.security.event_manager import EventManager
from backend.app.security.rule_engine import RuleEngine


class SecurityDetectionEngine:
    """Master Security Intelligence & Anomaly Detection Engine for a capture session.

    Operates in passive analysis mode: evaluates live packet metadata, tracks session baselines,
    correlates multi-vector indicators, and maintains audited security incident lifecycles.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._lock = threading.Lock()

        # Analytical components
        self.baseline_manager = SessionBaselineManager(session_id=session_id)
        self.rule_engine = RuleEngine()
        self.correlation_engine = CorrelationEngine()
        self.event_manager = EventManager()

    def process_packet(self, meta: PacketMetadataItem) -> List[SecurityEventItem]:
        """Evaluates an incoming frame against all security rules and correlation logic."""
        # 1. Rule evaluation
        raw_events = self.rule_engine.evaluate_packet(
            meta=meta,
            session_id=self.session_id,
            baseline_manager=self.baseline_manager,
        )

        final_events: List[SecurityEventItem] = []
        for ev in raw_events:
            # 2. Multi-vector correlation
            correlated_ev = self.correlation_engine.correlate(ev)
            # 3. Lifecycle recording
            stored_ev = self.event_manager.record_event(correlated_ev)
            final_events.append(stored_ev)

        return final_events

    def feed_baseline_sample(self, bps: float, pps: float, dns_rate: float = 0.0) -> None:
        """Feeds periodic wire telemetry into behavioral baseline tracker."""
        self.baseline_manager.feed_sample(bps=bps, pps=pps, dns_rate=dns_rate)

    def get_overview(self) -> SecurityOverviewResponse:
        """Returns security posture overview."""
        return self.event_manager.get_overview(
            session_id=self.session_id,
            baseline_manager=self.baseline_manager,
        )

    def list_events(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        source_ip: Optional[str] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> SecurityEventsListResponse:
        """Returns paginated, filtered security events."""
        return self.event_manager.list_events(
            session_id=self.session_id,
            severity=severity,
            category=category,
            status=status,
            source_ip=source_ip,
            offset=offset,
            limit=limit,
        )

    def get_event(self, event_id: str) -> Optional[SecurityEventItem]:
        return self.event_manager.get_event(event_id)

    def update_event_status(self, event_id: str, request: EventStatusUpdateRequest) -> Optional[SecurityEventItem]:
        return self.event_manager.update_status(
            event_id=event_id,
            new_status=request.status,
            analyst_name=request.analyst_name,
        )

    def add_event_note(self, event_id: str, request: AddEventNoteRequest) -> Optional[SecurityEventItem]:
        return self.event_manager.add_note(
            event_id=event_id,
            note_text=request.note,
            author=request.author,
        )

    def get_timeline(self) -> SecurityTimelineResponse:
        return self.event_manager.get_timeline(session_id=self.session_id)

    def list_rules(self) -> List[RuleConfigItem]:
        return self.rule_engine.list_rules()

    def update_rule(self, rule_id: str, update: RuleUpdateRequest) -> Optional[RuleConfigItem]:
        return self.rule_engine.update_rule(rule_id=rule_id, update=update)

