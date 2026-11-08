import collections
import time
import uuid
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

from backend.app.schemas.capture import PacketMetadataItem
from backend.app.schemas.security import SecurityEventItem
from backend.app.security.risk_scorer import RiskScorer
from backend.app.security.rules.base_rule import BaseSecurityRule


class RepeatedRstRule(BaseSecurityRule):
    """Detects elevated TCP RST observations indicating rejection storms or teardown anomalies."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_REPEATED_RST",
            name="Repeated TCP RST Observations",
            category="CONNECTION",
            description="A high concentration of TCP RST packets was observed for an endpoint, indicating explicit connection rejections or abrupt teardown storms.",
            threshold=15.0,  # 15 RST packets
            window_seconds=10,
            cooldown_seconds=30,
            severity_default="LOW",
            is_baseline_dependent=False,
        )
        self._history: Dict[str, Deque[float]] = {}

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or meta.protocol != "TCP" or not meta.tcp_flags or "RST" not in meta.tcp_flags:
            return None

        src = meta.src_ip
        now_epoch = meta.timestamp.timestamp() if meta.timestamp else time.time()

        if src not in self._history:
            if len(self._history) > 500:
                self._history.pop(next(iter(self._history)))
            self._history[src] = collections.deque(maxlen=200)

        dq = self._history[src]
        dq.append(now_epoch)

        window_start = now_epoch - self.window_seconds
        while dq and dq[0] < window_start:
            dq.popleft()

        if len(dq) >= int(self.threshold):
            if not self.is_in_cooldown(src, now_epoch):
                self.record_trigger(src, now_epoch)
                observed_ratio = len(dq) / self.threshold
                risk_score, severity = RiskScorer.calculate_risk_score(
                    base_severity=self.severity_default,
                    confidence=0.70,
                    observed_ratio=observed_ratio,
                )
                return SecurityEventItem(
                    event_id=f"SEC-{uuid.uuid4().hex[:8]}",
                    session_id=session_id,
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    category=self.category,
                    severity=severity,
                    confidence=0.70,
                    risk_score=risk_score,
                    source_ip=src,
                    destination_ip=meta.dst_ip,
                    related_ips=[meta.dst_ip] if meta.dst_ip else [],
                    target_port=meta.dst_port,
                    first_seen=datetime.fromtimestamp(dq[0], tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=len(dq),
                    evidence_summary=f"Endpoint {src} produced {len(dq)} TCP RST packets within {self.window_seconds}s.",
                    detection_threshold=f">= {int(self.threshold)} RST packets in {self.window_seconds}s",
                    observed_value=f"{len(dq)} RST packets",
                    recommended_action="Inspect destination service availability or check for firewall/port knocking rejection responses.",
                )
        return None


class ConnectionChurnRule(BaseSecurityRule):
    """Detects rapid connection churn or flow surge: an endpoint opening an unusually high number of distinct connection flows."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_CONNECTION_CHURN",
            name="Rapid Connection Flow Churn Observed",
            category="CONNECTION",
            description="An endpoint opened an unusually high number of distinct connection flows in a brief interval.",
            threshold=25.0,  # 25 distinct connection flows
            window_seconds=10,
            cooldown_seconds=30,
            severity_default="MEDIUM",
            is_baseline_dependent=False,
        )
        # key: src_ip -> Deque of (timestamp, dst_ip, dst_port)
        self._history: Dict[str, Deque] = {}

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or meta.protocol not in ("TCP", "UDP") or not meta.dst_ip:
            return None

        # For TCP, count connection initiation (SYN) or distinct destination socket tuples to measure actual flow creation
        if meta.protocol == "TCP" and meta.tcp_flags:
            flags = [f.strip().upper() for f in meta.tcp_flags.split(",") if f.strip()]
            # Only connection initiation packets (SYN) represent new flow creations
            if "SYN" not in flags or "ACK" in flags:
                return None

        src = meta.src_ip
        now_epoch = meta.timestamp.timestamp() if meta.timestamp else time.time()

        if src not in self._history:
            if len(self._history) > 500:
                self._history.pop(next(iter(self._history)))
            self._history[src] = collections.deque(maxlen=300)

        dq = self._history[src]
        dq.append((now_epoch, meta.dst_ip, meta.dst_port))

        window_start = now_epoch - self.window_seconds
        while dq and dq[0][0] < window_start:
            dq.popleft()

        unique_flows = {(dst_ip, dst_port) for _, dst_ip, dst_port in dq}
        if len(unique_flows) >= int(self.threshold):
            if not self.is_in_cooldown(src, now_epoch):
                self.record_trigger(src, now_epoch)
                observed_ratio = len(unique_flows) / self.threshold
                risk_score, severity = RiskScorer.calculate_risk_score(
                    base_severity=self.severity_default,
                    confidence=0.75,
                    observed_ratio=observed_ratio,
                )
                unique_dests = sorted(list({dst_ip for _, dst_ip, _ in dq}))
                sample_dests = ", ".join(unique_dests[:5])
                more_suffix = f" (+{len(unique_dests) - 5} more)" if len(unique_dests) > 5 else ""
                return SecurityEventItem(
                    event_id=f"SEC-{uuid.uuid4().hex[:8]}",
                    session_id=session_id,
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    category=self.category,
                    severity=severity,
                    confidence=0.75,
                    risk_score=risk_score,
                    source_ip=src,
                    destination_ip=None,
                    related_ips=unique_dests,
                    first_seen=datetime.fromtimestamp(dq[0][0], tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=len(dq),
                    evidence_summary=(
                        f"Endpoint {src} initiated {len(unique_flows)} distinct connection flows across "
                        f"{len(unique_dests)} destination hosts within {self.window_seconds}s "
                        f"(sampled targets: {sample_dests}{more_suffix})."
                    ),
                    detection_threshold=f">= {int(self.threshold)} distinct connection flows in {self.window_seconds}s",
                    observed_value=f"{len(unique_flows)} distinct flows in {self.window_seconds}s",
                    recommended_action="Inspect source processes for aggressive polling, connection pooling misconfiguration, or automated web scrapers.",
                )
        return None

