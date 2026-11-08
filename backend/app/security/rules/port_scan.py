import collections
import time
import uuid
from datetime import datetime, timezone
from typing import Deque, Dict, Optional, Set, Tuple

from backend.app.schemas.capture import PacketMetadataItem
from backend.app.schemas.security import SecurityEventItem
from backend.app.security.risk_scorer import RiskScorer
from backend.app.security.rules.base_rule import BaseSecurityRule


class VerticalPortScanRule(BaseSecurityRule):
    """Detects vertical port scanning: a single source probing multiple ports on one host."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_PORT_SCAN_VERTICAL",
            name="Vertical Port Scan Pattern Observed",
            category="PORT_SCAN",
            description="A single source address probed multiple distinct destination ports on a single target host within a short time window.",
            threshold=12.0,  # 12 unique ports
            window_seconds=10,
            cooldown_seconds=30,
            severity_default="HIGH",
            is_baseline_dependent=False,
        )
        # key: (src_ip, dst_ip) -> Deque of (timestamp, dst_port)
        self._history: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = {}

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or not meta.dst_port or meta.protocol not in ("TCP", "UDP"):
            return None

        # For TCP, require connection initiation (SYN without ACK) to distinguish probes from established data transfers
        if meta.protocol == "TCP" and meta.tcp_flags:
            flags = [f.strip().upper() for f in meta.tcp_flags.split(",") if f.strip()]
            if "SYN" not in flags or "ACK" in flags:
                return None

        src = meta.src_ip
        dst = meta.dst_ip
        now_epoch = meta.timestamp.timestamp() if meta.timestamp else time.time()
        pair_key = (src, dst)

        if pair_key not in self._history:
            if len(self._history) > 500:
                self._history.pop(next(iter(self._history)))
            self._history[pair_key] = collections.deque(maxlen=200)

        dq = self._history[pair_key]
        dq.append((now_epoch, meta.dst_port))

        # Filter to sliding window
        window_start = now_epoch - self.window_seconds
        while dq and dq[0][0] < window_start:
            dq.popleft()

        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= int(self.threshold):
            entity_key = f"{src}->{dst}"
            if not self.is_in_cooldown(entity_key, now_epoch):
                self.record_trigger(entity_key, now_epoch)
                observed_ratio = len(unique_ports) / self.threshold
                risk_score, severity = RiskScorer.calculate_risk_score(
                    base_severity=self.severity_default,
                    confidence=0.85,
                    observed_ratio=observed_ratio,
                )
                sample_ports = sorted(list(unique_ports))[:10]
                return SecurityEventItem(
                    event_id=f"SEC-{uuid.uuid4().hex[:8]}",
                    session_id=session_id,
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    category=self.category,
                    severity=severity,
                    confidence=0.85,
                    risk_score=risk_score,
                    source_ip=src,
                    destination_ip=dst,
                    related_ips=[dst],
                    target_port=sample_ports[0] if sample_ports else None,
                    related_ports=sample_ports,
                    first_seen=datetime.fromtimestamp(dq[0][0], tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=len(dq),
                    evidence_summary=f"Source {src} probed {len(unique_ports)} distinct ports on {dst} within {self.window_seconds}s (sample ports: {sample_ports}).",
                    detection_threshold=f">= {int(self.threshold)} unique ports in {self.window_seconds}s",
                    observed_value=f"{len(unique_ports)} unique ports in {self.window_seconds}s",
                    recommended_action="Inspect source host for port scanning utility or reconnaissance activity. Verify whether the target host runs services on probed ports.",
                )
        return None


class HorizontalPortScanRule(BaseSecurityRule):
    """Detects horizontal port scanning: a single source probing the same port across multiple hosts."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_PORT_SCAN_HORIZONTAL",
            name="Horizontal Port Sweep Pattern Observed",
            category="PORT_SCAN",
            description="A single source address probed the same destination port across multiple distinct hosts within a short time window.",
            threshold=8.0,  # 8 unique destination hosts for non-web ports
            window_seconds=10,
            cooldown_seconds=30,
            severity_default="MEDIUM",
            is_baseline_dependent=False,
            web_port_threshold=20.0,  # Calibrated for ports 80/443 to avoid browser CDN false positives
        )
        # key: (src_ip, dst_port) -> Deque of (timestamp, dst_ip)
        self._history: Dict[Tuple[str, int], Deque[Tuple[float, str]]] = {}

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or not meta.dst_port or meta.protocol not in ("TCP", "UDP"):
            return None

        # For TCP, require connection initiation (SYN without ACK) to distinguish sweep probes from established web data transfers
        if meta.protocol == "TCP" and meta.tcp_flags:
            flags = [f.strip().upper() for f in meta.tcp_flags.split(",") if f.strip()]
            if "SYN" not in flags or "ACK" in flags:
                return None

        src = meta.src_ip
        dst_p = meta.dst_port
        now_epoch = meta.timestamp.timestamp() if meta.timestamp else time.time()
        key = (src, dst_p)

        # Calibrated threshold: standard web ports (80/443) have natural CDN fan-out during normal browsing
        is_web_port = dst_p in (80, 443)
        effective_threshold = (self.web_port_threshold or 20.0) if is_web_port else self.threshold

        if key not in self._history:
            if len(self._history) > 500:
                self._history.pop(next(iter(self._history)))
            self._history[key] = collections.deque(maxlen=300)

        dq = self._history[key]
        dq.append((now_epoch, meta.dst_ip))

        window_start = now_epoch - self.window_seconds
        while dq and dq[0][0] < window_start:
            dq.popleft()

        unique_hosts = {h for _, h in dq}
        if len(unique_hosts) >= int(effective_threshold):
            entity_key = f"{src}:{dst_p}"
            if not self.is_in_cooldown(entity_key, now_epoch):
                self.record_trigger(entity_key, now_epoch)
                observed_ratio = len(unique_hosts) / effective_threshold
                risk_score, severity = RiskScorer.calculate_risk_score(
                    base_severity=self.severity_default,
                    confidence=0.80,
                    observed_ratio=observed_ratio,
                )
                related_targets = sorted(list(unique_hosts))
                sample_targets = ", ".join(related_targets[:5])
                more_suffix = f" (+{len(related_targets) - 5} more)" if len(related_targets) > 5 else ""
                probe_type = "TCP SYN" if meta.protocol == "TCP" else "UDP datagram"
                return SecurityEventItem(
                    event_id=f"SEC-{uuid.uuid4().hex[:8]}",
                    session_id=session_id,
                    rule_id=self.rule_id,
                    detection_name=self.name,
                    category=self.category,
                    severity=severity,
                    confidence=0.80,
                    risk_score=risk_score,
                    source_ip=src,
                    destination_ip=None,
                    related_ips=related_targets,
                    target_port=dst_p,
                    related_ports=[dst_p],
                    first_seen=datetime.fromtimestamp(dq[0][0], tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=len(dq),
                    evidence_summary=(
                        f"Source {src} initiated {probe_type} connection attempts on port {dst_p} across "
                        f"{len(unique_hosts)} distinct destination hosts within {self.window_seconds}s "
                        f"(sampled targets: {sample_targets}{more_suffix})."
                    ),
                    detection_threshold=f">= {int(effective_threshold)} target hosts on port {dst_p} in {self.window_seconds}s",
                    observed_value=f"{len(unique_hosts)} destination hosts ({len(dq)} probes)",
                    recommended_action="Investigate source host for automated worm scanning, lateral movement reconnaissance, or subnet enumeration activity.",
                )
        return None


class SynHeavyReconRule(BaseSecurityRule):
    """Detects SYN-heavy reconnaissance: elevated SYN packets without handshakes."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_SYN_RECON",
            name="SYN-Heavy Reconnaissance Observed",
            category="PORT_SCAN",
            description="A single source generated repeated TCP SYN packets without established connections.",
            threshold=15.0,  # 15 SYN packets
            window_seconds=10,
            cooldown_seconds=30,
            severity_default="MEDIUM",
        )
        self._history: Dict[str, Deque[float]] = {}

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or meta.protocol != "TCP" or not meta.tcp_flags:
            return None

        # Check if packet is SYN-only (no ACK)
        flags = [f.strip().upper() for f in meta.tcp_flags.split(",") if f.strip()]
        if "SYN" not in flags or "ACK" in flags:
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
                    target_port=meta.dst_port,
                    related_ports=[meta.dst_port] if meta.dst_port else [],
                    first_seen=datetime.fromtimestamp(dq[0], tz=timezone.utc),
                    last_seen=datetime.fromtimestamp(now_epoch, tz=timezone.utc),
                    observation_count=len(dq),
                    evidence_summary=f"Source {src} transmitted {len(dq)} standalone SYN packets within {self.window_seconds}s.",
                    detection_threshold=f">= {int(self.threshold)} SYN packets in {self.window_seconds}s",
                    observed_value=f"{len(dq)} SYN packets",
                    recommended_action="Inspect network connection attempts. Verify whether source host is performing half-open SYN port scans.",
                )
        return None

