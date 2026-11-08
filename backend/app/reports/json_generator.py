import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.core.config import settings
from backend.app.reports.data_collector import ReportPayload
from backend.app.schemas.reports import ReportType


class JsonReportGenerator:
    """Serializes ReportPayload into structured, standardized JSON audit records adhering to ANI Schema.

    Adheres to the official ANI JSON Export Contract:
    - Top-level fields:
        report_id, product, application_version, report_type, generated_at,
        source: { target, scan_id },
        summary: { total_ports, open, closed, no_response, ... },
        findings: [ { port, state, ... } ],
        limitations: [ ... ]
    - Valid JSON, UTF-8 encoded
    - Proper null handling (None -> null)
    - Zero CSV content or markdown fences
    - No raw payload bytes or credentials
    """

    @classmethod
    def generate(
        cls,
        payload: ReportPayload,
        report_id: str = "",
        include_raw_details: bool = True,
    ) -> bytes:
        rep_id = report_id or f"rpt-{payload.source_id}"

        # 1. Structured Findings (Always an array of objects, never CSV string arrays)
        findings: List[Dict[str, Any]] = []
        if payload.raw_items:
            findings = payload.raw_items
        elif payload.table_rows:
            # Map table rows with headers to objects
            for row in payload.table_rows:
                row_dict = {
                    str(h).lower().replace(" ", "_"): (col if col is not None else None)
                    for h, col in zip(payload.table_headers, row)
                }
                findings.append(row_dict)

        # 2. Extract Source Object
        target_val = (
            payload.scope_info.get("Target Host")
            or payload.scope_info.get("Target Subnet")
            or ("localhost" if payload.report_type == ReportType.SYSTEM_BASELINE else None)
        )
        source_id_val = payload.source_id if payload.source_id not in ("system", "") else None
        source_obj: Dict[str, Any] = {
            "target": target_val,
            "scan_id": source_id_val,
        }

        # 3. Build Domain-Specific Structured Summary
        if payload.report_type == ReportType.TCP_SCAN:
            total_p = payload.summary_metrics.get("Total Ports Probed", len(findings))
            open_p = payload.summary_metrics.get("Open Ports", 0)
            closed_p = payload.summary_metrics.get("Closed (RST)", 0)
            no_resp_p = payload.summary_metrics.get(
                "No Response (Timed Out)",
                payload.summary_metrics.get("Filtered / No Response", 0),
            )
            structured_summary: Dict[str, Any] = {
                "total_ports": total_p,
                "open": open_p,
                "closed": closed_p,
                "no_response": no_resp_p,
                "duration_seconds": payload.summary_metrics.get("Duration (s)", 0.0),
                "narrative": payload.executive_summary,
            }
        elif payload.report_type == ReportType.UDP_SCAN:
            structured_summary = {
                "total_ports": payload.summary_metrics.get("Total UDP Probed", len(findings)),
                "open": payload.summary_metrics.get("Open UDP Ports", 0),
                "closed": payload.summary_metrics.get("Closed (ICMP Unreachable)", 0),
                "open_or_filtered": payload.summary_metrics.get("Open | Filtered", 0),
                "duration_seconds": payload.summary_metrics.get("Duration (s)", 0.0),
                "narrative": payload.executive_summary,
            }
        elif payload.report_type == ReportType.HOST_DISCOVERY:
            structured_summary = {
                "total_probed": payload.summary_metrics.get("Hosts Probed", len(findings)),
                "online": payload.summary_metrics.get("Active Hosts", 0),
                "duration_seconds": payload.summary_metrics.get("Sweep Duration (s)", 0.0),
                "narrative": payload.executive_summary,
            }
        else:
            structured_summary = {
                **payload.summary_metrics,
                "narrative": payload.executive_summary,
            }

        # 4. Canonical ANI Schema Payload
        data: Dict[str, Any] = {
            # Standardized Contract (PART 2 C)
            "report_id": rep_id,
            "product": settings.app_name,
            "application_version": settings.app_version,
            "version": settings.app_version,  # Compatibility alias
            "report_type": payload.report_type.value,
            "generated_at": payload.generated_at.isoformat(),
            "export_date": payload.generated_at.isoformat(),  # Compatibility alias
            "source": source_obj,
            "source_session_id": source_id_val,  # Compatibility alias
            "summary": structured_summary,
            "executive_summary": payload.executive_summary,  # Compatibility alias
            "metrics": payload.summary_metrics,
            "engines": payload.engines_status,
            "findings": findings,
            "limitations": payload.limitations,
            # Extended Metadata & Scope Sections
            "metadata": {
                "product": settings.app_name,
                "abbreviation": settings.app_short_name,
                "version": settings.app_version,
                "report_title": payload.title,
                "report_type": payload.report_type.value,
                "source_identifier": payload.source_id,
                "generated_at_utc": payload.generated_at.isoformat(),
                "compliance_classification": "INTERNAL_SECURITY_AUDIT",
            },
            "scope_and_target": payload.scope_info,
            "telemetry_breakdown": payload.telemetry_details,
            "security_posture": payload.security_posture,
            "recommendations": payload.recommendations,
        }

        json_str = json.dumps(data, indent=2, default=str)
        return json_str.encode("utf-8")
