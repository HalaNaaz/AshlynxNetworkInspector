import collections
import threading
from typing import Deque, Dict, List, Optional
from backend.app.schemas.security import SecurityEventItem


class CorrelationEngine:
    """Correlates security findings across shared IP entities within sliding time windows."""

    def __init__(self, window_seconds: int = 60, max_tracked_entities: int = 500):
        self.window_seconds = window_seconds
        self.max_tracked_entities = max_tracked_entities
        self._lock = threading.Lock()

        # entity key (source_ip) -> Deque of (timestamp, event_id, rule_id)
        self._entity_events: Dict[str, Deque[dict]] = {}

    def correlate(self, event: SecurityEventItem) -> SecurityEventItem:
        """Evaluates an event for entity correlation and updates correlation metadata."""
        src = event.source_ip
        if not src:
            return event

        now_epoch = event.last_seen.timestamp()

        with self._lock:
            if src not in self._entity_events:
                if len(self._entity_events) >= self.max_tracked_entities:
                    self._entity_events.pop(next(iter(self._entity_events)))
                self._entity_events[src] = collections.deque(maxlen=100)

            dq = self._entity_events[src]
            dq.append({
                "epoch": now_epoch,
                "event_id": event.event_id,
                "rule_id": event.rule_id,
                "category": event.category,
            })

            # Trim older than window
            window_start = now_epoch - self.window_seconds
            while dq and dq[0]["epoch"] < window_start:
                dq.popleft()

            distinct_rules = {e["rule_id"] for e in dq}
            distinct_categories = {e["category"] for e in dq}

            # Coupled transport rate rules that must not escalate risk between themselves
            COUPLED_TRANSPORT_RULES = {"RULE_PORT_SCAN_HORIZONTAL", "RULE_CONNECTION_CHURN", "RULE_SYN_RECON"}
            is_purely_coupled = distinct_rules.issubset(COUPLED_TRANSPORT_RULES)

            if len(distinct_rules) >= 2:
                corr_id = f"CORR-{src.replace(':', '-')}"
                event.correlation_id = corr_id

                # Orthogonal multi-vector correlation: findings span >= 2 independent categories
                # AND are not merely co-dependent transport rate rules
                if len(distinct_categories) >= 2 and not is_purely_coupled:
                    # Bounded confidence elevation (+0.05, max 0.95)
                    event.confidence = min(0.95, round(event.confidence + 0.05, 2))
                    # Moderate risk score bump (+5, max 100)
                    event.risk_score = min(100, event.risk_score + 5)
                    if event.risk_score >= 90:
                        event.severity = "CRITICAL"
                    elif event.risk_score >= 70:
                        event.severity = "HIGH"

                    event.evidence_summary += (
                        f" [Correlated across {len(distinct_categories)} independent security categories "
                        f"({', '.join(sorted(distinct_categories))}) on source {src} in {self.window_seconds}s]."
                    )
                else:
                    # Grouped under the same threat entity without artificial risk escalation
                    event.evidence_summary += (
                        f" [Grouped with {len(distinct_rules)} related observations on source {src} "
                        f"in {self.window_seconds}s; risk unescalated to prevent co-dependent inflation]."
                    )

        return event

