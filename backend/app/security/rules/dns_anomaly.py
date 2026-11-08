import collections
import time
import uuid
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

from backend.app.schemas.capture import PacketMetadataItem
from backend.app.schemas.security import SecurityEventItem
from backend.app.security.risk_scorer import RiskScorer
from backend.app.security.rules.base_rule import BaseSecurityRule


class DnsQueryBurstRule(BaseSecurityRule):
    """Detects rapid bursts of DNS queries from a single source host."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_DNS_QUERY_BURST",
            name="Unusual DNS Query Burst Observed",
            category="DNS",
            description="A high concentration of DNS queries was issued by a single source host within a brief window.",
            threshold=20.0,  # 20 queries in 5s
            window_seconds=5,
            cooldown_seconds=30,
            severity_default="LOW",
        )
        self._history: Dict[str, Deque[float]] = {}

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled:
            return None
        is_dns = meta.protocol == "DNS" or meta.dst_port == 53
        if not is_dns:
            return None

        # Check if query (or fallback to port 53 outbound)
        if meta.dns_summary and "Response" in meta.dns_summary:
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
                    confidence=0.75,
                    observed_ratio=observed_ratio,
                )
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
                    destination_ip=meta.dst_ip,
                    related_ips=[meta.dst_ip] if meta.dst_ip else [],
                    target_port=53,
                    related_ports=[53],
                    first_seen=datetime.fromtimestamp(dq[0], tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=len(dq),
                    evidence_summary=f"Host {src} generated {len(dq)} DNS queries within {self.window_seconds}s.",
                    detection_threshold=f">= {int(self.threshold)} queries in {self.window_seconds}s",
                    observed_value=f"{len(dq)} queries",
                    recommended_action="Inspect the client system for browser tab storms, misconfigured local resolvers, or automated domain lookups.",
                )
        return None


class DnsNxdomainSurgeRule(BaseSecurityRule):
    """Detects repeated NXDOMAIN responses indicating domain probing or resolution failures."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_DNS_NXDOMAIN_SURGE",
            name="Repeated DNS NXDOMAIN Responses Observed",
            category="DNS",
            description="Multiple non-existent domain (NXDOMAIN) responses were returned to a client, suggesting failed lookups, stale configurations, or domain probing.",
            threshold=6.0,  # 6 NXDOMAIN responses
            window_seconds=10,
            cooldown_seconds=30,
            severity_default="MEDIUM",
        )
        self._history: Dict[str, Deque[float]] = {}

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled:
            return None
        # Check if response code is NXDOMAIN (rcode=3)
        if not meta.dns_summary or "rcode=3" not in meta.dns_summary:
            return None

        dst = meta.dst_ip  # Client receiving the NXDOMAIN
        now_epoch = meta.timestamp.timestamp() if meta.timestamp else time.time()

        if dst not in self._history:
            if len(self._history) > 500:
                self._history.pop(next(iter(self._history)))
            self._history[dst] = collections.deque(maxlen=100)

        dq = self._history[dst]
        dq.append(now_epoch)

        window_start = now_epoch - self.window_seconds
        while dq and dq[0] < window_start:
            dq.popleft()

        if len(dq) >= int(self.threshold):
            if not self.is_in_cooldown(dst, now_epoch):
                self.record_trigger(dst, now_epoch)
                observed_ratio = len(dq) / self.threshold
                risk_score, severity = RiskScorer.calculate_risk_score(
                    base_severity=self.severity_default,
                    confidence=0.80,
                    observed_ratio=observed_ratio,
                )
                return SecurityEventItem(
                    event_id=f"SEC-{uuid.uuid4().hex[:8]}",
                    session_id=session_id,
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    category=self.category,
                    severity=severity,
                    confidence=0.80,
                    risk_score=risk_score,
                    source_ip=meta.src_ip,
                    destination_ip=dst,
                    related_ips=[dst] if dst else [],
                    target_port=53,
                    related_ports=[53],
                    first_seen=datetime.fromtimestamp(dq[0], tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=len(dq),
                    evidence_summary=f"Client {dst} received {len(dq)} NXDOMAIN responses within {self.window_seconds}s.",
                    detection_threshold=f">= {int(self.threshold)} NXDOMAIN responses in {self.window_seconds}s",
                    observed_value=f"{len(dq)} NXDOMAIN responses",
                    recommended_action="Inspect queried domain names. Check whether local applications are attempting to resolve retired servers or probing random subdomains.",
                )
        return None


class DnsLongDomainRule(BaseSecurityRule):
    """Detects unusually long queried domain names with privacy-preserving metadata handling."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_DNS_LONG_DOMAIN",
            name="Unusually Long Domain Query Observed",
            category="DNS",
            description="A DNS query for a domain exceeding standard operational length was observed.",
            threshold=65.0,  # 65 chars
            window_seconds=10,
            cooldown_seconds=60,
            severity_default="LOW",
        )

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or not meta.dns_summary or not meta.dns_summary.startswith("Query:"):
            return None

        raw_domain = meta.dns_summary.replace("Query:", "").strip()
        dom_len = len(raw_domain)

        if dom_len >= int(self.threshold):
            src = meta.src_ip
            now_epoch = meta.timestamp.timestamp() if meta.timestamp else time.time()
            entity_key = f"{src}:{raw_domain[:30]}"

            if not self.is_in_cooldown(entity_key, now_epoch):
                self.record_trigger(entity_key, now_epoch)
                # Redact domain for privacy: display masked prefix and apex
                masked_dom = raw_domain[:15] + "..." + raw_domain[-20:] if dom_len > 40 else raw_domain
                risk_score, severity = RiskScorer.calculate_risk_score(
                    base_severity=self.severity_default,
                    confidence=0.65,
                    observed_ratio=dom_len / self.threshold,
                )
                return SecurityEventItem(
                    event_id=f"SEC-{uuid.uuid4().hex[:8]}",
                    session_id=session_id,
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    category=self.category,
                    severity=severity,
                    confidence=0.65,
                    risk_score=risk_score,
                    source_ip=src,
                    destination_ip=meta.dst_ip,
                    related_ips=[meta.dst_ip] if meta.dst_ip else [],
                    target_port=53,
                    related_ports=[53],
                    first_seen=meta.timestamp if meta.timestamp else datetime.now(timezone.utc),
                    last_seen=meta.timestamp if meta.timestamp else datetime.now(timezone.utc),
                    observation_count=1,
                    evidence_summary=f"Host {src} queried an unusually long domain of {dom_len} characters: '{masked_dom}'.",
                    detection_threshold=f">= {int(self.threshold)} characters in domain name",
                    observed_value=f"{dom_len} characters",
                    recommended_action="Investigate query origin. Note that cloud CDNs, anti-spam lookups, and security products frequently use long legitimate domains.",
                )
        return None

