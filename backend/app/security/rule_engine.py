import threading
from typing import Dict, List, Optional

from backend.app.schemas.capture import PacketMetadataItem
from backend.app.schemas.security import RuleConfigItem, RuleUpdateRequest, SecurityEventItem
from backend.app.security.rules.base_rule import BaseSecurityRule
from backend.app.security.rules.connection_anomaly import ConnectionChurnRule, RepeatedRstRule
from backend.app.security.rules.dns_anomaly import DnsLongDomainRule, DnsNxdomainSurgeRule, DnsQueryBurstRule
from backend.app.security.rules.port_scan import HorizontalPortScanRule, SynHeavyReconRule, VerticalPortScanRule
from backend.app.security.rules.suspicious_ports import SuspiciousServiceRule
from backend.app.security.rules.traffic_spike import TrafficSpikeRule


class RuleEngine:
    """Registry and dispatcher for passive security detection rules."""

    def __init__(self):
        self._lock = threading.Lock()
        self._rules: Dict[str, BaseSecurityRule] = {}

        # Register default suite of detection rules
        default_rules = [
            VerticalPortScanRule(),
            HorizontalPortScanRule(),
            SynHeavyReconRule(),
            RepeatedRstRule(),
            ConnectionChurnRule(),
            TrafficSpikeRule(),
            DnsQueryBurstRule(),
            DnsNxdomainSurgeRule(),
            DnsLongDomainRule(),
            SuspiciousServiceRule(),
        ]
        for r in default_rules:
            self._rules[r.rule_id] = r

    def evaluate_packet(
        self,
        meta: PacketMetadataItem,
        session_id: str,
        baseline_manager=None,
    ) -> List[SecurityEventItem]:
        """Evaluates an incoming frame against all active rules in parallel."""
        events: List[SecurityEventItem] = []
        with self._lock:
            active_rules = [r for r in self._rules.values() if r.enabled]

        for rule in active_rules:
            # Baseline-dependent rules require an active/ready baseline before evaluation
            if rule.is_baseline_dependent and (baseline_manager is None or not baseline_manager.is_ready()):
                continue

            try:
                ev = rule.evaluate(meta, session_id, baseline_manager=baseline_manager)
                if ev:
                    events.append(ev)
            except Exception:
                # Individual rule evaluation failure must never crash the capture worker
                pass

        return events

    def list_rules(self) -> List[RuleConfigItem]:
        """Returns configurations of all registered rules."""
        with self._lock:
            return [r.to_config() for r in self._rules.values()]

    def get_rule(self, rule_id: str) -> Optional[BaseSecurityRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def update_rule(self, rule_id: str, update: RuleUpdateRequest) -> Optional[RuleConfigItem]:
        """Applies configuration updates to a rule without code execution."""
        with self._lock:
            rule = self._rules.get(rule_id)
            if not rule:
                return None
            rule.update_config(
                enabled=update.enabled,
                threshold=update.threshold,
                window_seconds=update.window_seconds,
                cooldown_seconds=update.cooldown_seconds,
                web_port_threshold=update.web_port_threshold,
            )
            return rule.to_config()

