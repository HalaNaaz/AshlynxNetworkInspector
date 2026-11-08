import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from backend.app.schemas.capture import PacketMetadataItem
from backend.app.schemas.security import SecurityEventItem
from backend.app.security.risk_scorer import RiskScorer
from backend.app.security.rules.base_rule import BaseSecurityRule

SENSITIVE_PORT_GROUPS: Dict[int, Dict[str, str]] = {
    22: {"service": "SSH (Inferred)", "group": "REMOTE_ADMIN", "desc": "Remote terminal shell service"},
    23: {"service": "Telnet (Inferred)", "group": "INSECURE_ADMIN", "desc": "Unencrypted legacy remote shell"},
    3389: {"service": "RDP (Inferred)", "group": "REMOTE_DESKTOP", "desc": "Windows Remote Desktop Protocol"},
    445: {"service": "SMB (Inferred)", "group": "FILE_SHARING", "desc": "Server Message Block file sharing"},
    139: {"service": "NetBIOS-SSN (Inferred)", "group": "FILE_SHARING", "desc": "NetBIOS session service"},
    3306: {"service": "MySQL (Inferred)", "group": "DATABASE", "desc": "Relational database network port"},
    5432: {"service": "PostgreSQL (Inferred)", "group": "DATABASE", "desc": "Relational database network port"},
    1433: {"service": "MSSQL (Inferred)", "group": "DATABASE", "desc": "Microsoft SQL server network port"},
    1521: {"service": "Oracle-DB (Inferred)", "group": "DATABASE", "desc": "Oracle database listener port"},
    6379: {"service": "Redis (Inferred)", "group": "DATABASE", "desc": "In-memory datastore port"},
    27017: {"service": "MongoDB (Inferred)", "group": "DATABASE", "desc": "Document database port"},
    5900: {"service": "VNC (Inferred)", "group": "REMOTE_DESKTOP", "desc": "Virtual Network Computing desktop"},
}


class SuspiciousServiceRule(BaseSecurityRule):
    """Monitors observed traffic directed at sensitive administrative or database ports."""

    def __init__(self):
        super().__init__(
            rule_id="RULE_SUSPICIOUS_SERVICE",
            name="Sensitive Service Port Activity Observed",
            category="SUSPICIOUS_SERVICE",
            description="Network traffic was observed targeting sensitive administrative, database, or file-sharing service ports (Service identity inferred from Layer-4 port numbers).",
            threshold=1.0,  # 1 observed attempt
            window_seconds=10,
            cooldown_seconds=60,
            severity_default="LOW",
        )

    def evaluate(self, meta: PacketMetadataItem, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        if not self.enabled or not meta.dst_port:
            return None

        port = meta.dst_port
        if port not in SENSITIVE_PORT_GROUPS:
            return None

        info = SENSITIVE_PORT_GROUPS[port]
        src = meta.src_ip
        dst = meta.dst_ip
        now_epoch = meta.timestamp.timestamp() if meta.timestamp else time.time()
        entity_key = f"{src}->{dst}:{port}"

        if not self.is_in_cooldown(entity_key, now_epoch):
            self.record_trigger(entity_key, now_epoch)

            # Assign higher base severity to Telnet / SMB exposure
            default_sev = "MEDIUM" if port in (23, 445) else "LOW"

            risk_score, severity = RiskScorer.calculate_risk_score(
                base_severity=default_sev,
                confidence=0.85,
                observed_ratio=1.0,
            )

            return SecurityEventItem(
                event_id=f"SEC-{uuid.uuid4().hex[:8]}",
                session_id=session_id,
                rule_id=self.rule_id,
                detection_name=f"Traffic Observed to {info['service']} Port {port}",
                category=self.category,
                severity=severity,
                confidence=0.85,
                risk_score=risk_score,
                source_ip=src,
                destination_ip=dst,
                related_ips=[dst] if dst else [],
                target_port=port,
                related_ports=[port],
                first_seen=meta.timestamp if meta.timestamp else datetime.now(timezone.utc),
                last_seen=meta.timestamp if meta.timestamp else datetime.now(timezone.utc),
                observation_count=1,
                evidence_summary=f"Inferred {info['service']} ({info['desc']}) access attempt from {src} to {dst}:{port}.",
                detection_threshold=f"Target port matches monitored sensitive group ({info['group']})",
                observed_value=f"Port {port} ({info['service']})",
                recommended_action=f"Verify whether {info['service']} access from {src} to {dst} is an authorized administrative activity. Confirm firewall access policies.",
            )
        return None

