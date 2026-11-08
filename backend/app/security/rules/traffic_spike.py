import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from backend.app.schemas.capture import PacketMetadataItem
from backend.app.schemas.security import SecurityEventItem
from backend.app.security.risk_scorer import RiskScorer
from backend.app.security.rules.base_rule import BaseSecurityRule


class TrafficSpikeRule(BaseSecurityRule):
    """Detects sudden spikes in throughput exceeding the empirical session baseline.

    Uses cautious labels and avoids firing during baseline warm-up.
    """

    def __init__(self):
        super().__init__(
            rule_id="RULE_TRAFFIC_SPIKE",
            name="Unusual Traffic Volume Surge Observed",
            category="TRAFFIC_SPIKE",
            description="Wire throughput significantly exceeded the empirical baseline established during this capture session.",
            threshold=3.5,  # 3.5x baseline mean
            window_seconds=5,
            cooldown_seconds=60,
            severity_default="LOW",
            is_baseline_dependent=True,
        )
        self._current_sec_bytes = 0
        self._current_sec_epoch = 0

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or not baseline_manager or not baseline_manager.is_ready():
            return None

        now_epoch = int(meta.timestamp.timestamp()) if meta.timestamp else int(time.time())
        if now_epoch != self._current_sec_epoch:
            self._current_sec_epoch = now_epoch
            self._current_sec_bytes = meta.length
        else:
            self._current_sec_bytes += meta.length

        current_bps = self._current_sec_bytes * 8.0
        stats = baseline_manager.get_stats()
        mean_bps = stats.get("mean_bps", 0.0)

        # Require a non-trivial minimum threshold (e.g. 500 Kbps) to avoid alerting on idle baselines
        if mean_bps > 50_000 and current_bps >= (mean_bps * self.threshold):
            entity_key = f"spike:{session_id}"
            if not self.is_in_cooldown(entity_key, float(now_epoch)):
                self.record_trigger(entity_key, float(now_epoch))
                ratio = round(current_bps / mean_bps, 2)
                risk_score, severity = RiskScorer.calculate_risk_score(
                    base_severity=self.severity_default,
                    confidence=0.70,
                    observed_ratio=ratio,
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
                    source_ip=meta.src_ip,
                    destination_ip=meta.dst_ip,
                    related_ips=[meta.dst_ip] if meta.dst_ip else [],
                    first_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=1,
                    evidence_summary=f"Instantaneous throughput ({current_bps / 1000:.1f} Kbps) reached {ratio}x the session baseline mean ({mean_bps / 1000:.1f} Kbps across {stats.get('samples', 0)} samples).",
                    detection_threshold=f"> {self.threshold}x baseline mean (with baseline active)",
                    observed_value=f"{ratio}x baseline ({current_bps / 1000:.1f} Kbps)",
                    recommended_action="Review active processes and file transfer activity. Check whether large downloads, streaming, or network backups were initiated.",
                )
        return None

