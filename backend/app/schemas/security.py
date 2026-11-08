from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SecurityEventItem(BaseModel):
    """Normalized security observation item produced by passive detection engine."""

    event_id: str = Field(..., description="Unique event identifier e.g. SEC-8a1f4b")
    session_id: str = Field(..., description="Associated capture session ID")
    rule_id: str = Field(..., description="Detection rule ID e.g. RULE_PORT_SCAN_VERTICAL")
    detection_name: str = Field(..., description="Human-readable detection title")
    category: str = Field(..., description="PORT_SCAN, CONNECTION, TRAFFIC_SPIKE, DNS, SUSPICIOUS_SERVICE")
    severity: str = Field(..., description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Evidence certainty score between 0.0 and 1.0")
    risk_score: int = Field(..., ge=0, le=100, description="Explainable composite score between 0 and 100")
    source_ip: Optional[str] = Field(None, description="Identified source IP address if attributed")
    destination_ip: Optional[str] = Field(None, description="Target destination IP address if attributed")
    target_port: Optional[int] = Field(None, description="Target port if applicable")
    related_ports: List[int] = Field(default_factory=list, description="Associated ports involved in detection")
    related_ips: List[str] = Field(default_factory=list, description="Associated or targeted destination IP addresses")
    first_seen: datetime = Field(..., description="Initial observation timestamp (UTC)")
    last_seen: datetime = Field(..., description="Most recent observation timestamp (UTC)")
    observation_count: int = Field(1, ge=1, description="Deduplicated observation occurrences")
    evidence_summary: str = Field(..., description="Empirical evidence justifying the finding")
    detection_threshold: str = Field(..., description="Configured rule threshold")
    observed_value: str = Field(..., description="Empirical value measured during window")
    recommended_action: str = Field(..., description="Defensive investigation guidance for SOC analyst")
    status: str = Field(
        "NEW",
        description="Event lifecycle: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE",
    )
    analyst_notes: List[str] = Field(default_factory=list, description="Audited analyst investigation notes")
    audit_trail: List[str] = Field(default_factory=list, description="Audit log of state modifications")
    correlation_id: Optional[str] = Field(None, description="Group ID of correlated observations")


class SecurityStatusResponse(BaseModel):
    """Diagnostic status of passive detection engine and baseline readiness."""

    is_enabled: bool = Field(True, description="Whether anomaly detection engine is active")
    active_rules_count: int = Field(..., description="Count of currently enabled detection rules")
    baseline_status: str = Field(..., description="WARMING_UP, READY, or ACTIVE")
    baseline_samples: int = Field(..., description="Number of baseline time samples gathered")
    baseline_min_samples: int = Field(..., description="Minimum samples required before baseline alert activation")
    total_events_detected: int = Field(0, description="Cumulative events detected in this session")
    critical_events: int = Field(0, description="Critical severity event count")
    high_events: int = Field(0, description="High severity event count")
    medium_events: int = Field(0, description="Medium severity event count")
    low_events: int = Field(0, description="Low severity event count")
    info_events: int = Field(0, description="Informational event count")
    active_investigations: int = Field(0, description="Events marked ACKNOWLEDGED or INVESTIGATING")
    resolved_events: int = Field(0, description="Events marked RESOLVED or FALSE_POSITIVE")


class RuleConfigItem(BaseModel):
    """Configuration contract for a passive security detection rule."""

    rule_id: str = Field(..., description="Identifier e.g. RULE_PORT_SCAN_VERTICAL")
    name: str = Field(..., description="Display title")
    category: str = Field(..., description="PORT_SCAN, CONNECTION, TRAFFIC_SPIKE, DNS, SUSPICIOUS_SERVICE")
    description: str = Field(..., description="What the rule monitors and why")
    enabled: bool = Field(True, description="Whether rule evaluates live packets")
    threshold: float = Field(..., description="Numeric trigger threshold")
    window_seconds: int = Field(..., description="Observation sliding window size in seconds")
    cooldown_seconds: int = Field(..., description="Alert suppression cooldown period in seconds")
    severity_default: str = Field(..., description="Default severity band")
    is_baseline_dependent: bool = Field(False, description="Whether rule requires active baseline before firing")
    web_port_threshold: Optional[float] = Field(None, description="Calibrated threshold for web ports 80/443 if applicable")


class RuleUpdateRequest(BaseModel):
    """Safe parameter updates for detection rules (no arbitrary code execution)."""

    enabled: Optional[bool] = Field(None, description="Enable or disable rule")
    threshold: Optional[float] = Field(None, gt=0, description="New threshold value")
    web_port_threshold: Optional[float] = Field(None, gt=0, description="Web port threshold if supported")
    window_seconds: Optional[int] = Field(None, ge=1, le=3600, description="Window size in seconds")
    cooldown_seconds: Optional[int] = Field(None, ge=1, le=86400, description="Cooldown in seconds")


class EventStatusUpdateRequest(BaseModel):
    """Request to update event investigation status."""

    status: str = Field(..., description="NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    analyst_name: Optional[str] = Field("Security Analyst", max_length=100, description="Analyst identity for audit trail")


class AddEventNoteRequest(BaseModel):
    """Validated analyst note addition."""

    note: str = Field(..., min_length=1, max_length=1000, description="Sanitized analyst note text")
    author: Optional[str] = Field("Security Analyst", max_length=100, description="Analyst identity")


class SecurityEventsListResponse(BaseModel):
    """Paginated list of security detection events."""

    total: int = Field(..., description="Total matching events")
    session_id: Optional[str] = Field(None, description="Filtered capture session ID")
    events: List[SecurityEventItem] = Field(default_factory=list, description="Array of security events")


class TopThreatSourceItem(BaseModel):
    """Attributed source IP involved in security observations."""

    source_ip: str = Field(..., description="Observed source IP")
    event_count: int = Field(..., description="Events associated with this IP")
    highest_severity: str = Field(..., description="Highest severity observed")
    associated_rules: List[str] = Field(default_factory=list, description="Rule IDs triggered by this source")


class SecurityOverviewResponse(BaseModel):
    """Executive KPI overview for security intelligence dashboard."""

    session_id: Optional[str] = Field(None, description="Active or queried session")
    status: SecurityStatusResponse = Field(..., description="Engine status and count breakdown")
    category_breakdown: Dict[str, int] = Field(default_factory=dict, description="Counts by category")
    top_sources: List[TopThreatSourceItem] = Field(default_factory=list, description="Top observed source IPs")
    recent_events: List[SecurityEventItem] = Field(default_factory=list, description="Most recent security events")


class SecurityTimelinePoint(BaseModel):
    """Time-bucketed security event frequency."""

    timestamp: datetime = Field(..., description="Bucket timestamp")
    critical_count: int = Field(0, description="Critical events in bucket")
    high_count: int = Field(0, description="High events in bucket")
    medium_count: int = Field(0, description="Medium events in bucket")
    low_count: int = Field(0, description="Low events in bucket")
    info_count: int = Field(0, description="Info events in bucket")


class SecurityTimelineResponse(BaseModel):
    """Chronological security events timeline."""

    total_points: int = Field(0, description="Number of timeline points")
    points: List[SecurityTimelinePoint] = Field(default_factory=list, description="Timeline points")

