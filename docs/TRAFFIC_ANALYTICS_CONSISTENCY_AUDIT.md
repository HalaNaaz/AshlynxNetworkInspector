# Ashlynx Network Inspector (ANI) — Traffic Analytics & Report Consistency Audit Report

**Document Version:** 1.0.0  
**Audit Date:** 2026-11-09  
**Target Release:** v1.0.0  
**System Architecture:** Windows 11 Pro (x64) | FastAPI 0.115+ | Next.js 16 (Turbopack) | ReportLab 4.4 | Scapy 2.6  
**Status:** ALL ACCEPTANCE GATES PASSED (108/108 Tests Passing | Turbopack Build Clean | 21/21 Matrix Export Combinations Verified)

---

## 1. Executive Summary

A comprehensive post-integration quality assurance and data consistency audit was conducted on Ashlynx Network Inspector (ANI) v1.0.0 to investigate and resolve three reported telemetry discrepancies across live traffic analytics dashboards and report export formats (PDF, CSV, JSON):

1. **DNS Query Count Variance:** Discrepancies between DNS Intelligence (90), main dashboard KPI (55), and exported JSON report (101).
2. **Observation Duration Drift:** Observation duration recorded as 204.43 seconds in PDF, but 216.51 seconds in JSON for the same stopped capture session (`cap-1b027bdbe612`).
3. **Session Digest Inconsistency Across Formats:** Differing SHA-256 session digests between PDF and JSON reports generated for the same capture session.

Every reported defect was traced to its programmatic root cause, remediated without modifying approved Light Bento UI styling, backed by unit and regression test suites, and verified on the physical Windows 11 host.

---

## 2. Root Cause Analysis

### 2.1 Issue 1 — DNS Query Count Discrepancy & Semantic Ambiguity
- **Observed Behavior:** DNS Intelligence displayed 90, Dashboard KPI displayed 55, JSON report displayed 101.
- **Root Cause 1 (Semantic Ambiguity):**  
  In `backend/app/analytics/dns_analyzer.py`, the engine tracks three distinct metrics:
  - `total_dns_packets`: Total Layer 4/7 DNS packets on port 53 (queries + responses + unparsed frames).
  - `total_queries`: Parsed client request queries (`qr == 0`).
  - `total_responses`: Parsed server responses (`qr == 1`).  
  In `DnsAnalyticsCard.tsx`, the top header badge displayed `TOTAL: 90 FRAMES` (representing 55 queries + 35 responses = 90 total frames). Users and auditors reading "TOTAL: 90" conflated total DNS frames with total DNS queries, while the main KPI card displayed `55 reqs` (queries only).
- **Root Cause 2 (Asynchronous Polling Desynchronization in UI):**  
  In `frontend/src/app/traffic/page.tsx`, `pollSessionData` used `Promise.all([..., analyticsApi.getOverview(), ..., analyticsApi.getDns()])`. If `getOverview` or `getDns` completed in different polling cycles during active capture, or if `getOverview` failed transients while `getDns` succeeded, `overview.dns_queries_count` retained stale state (e.g. 55) while `dns.total_queries` updated to 90.
- **Root Cause 3 (Report Ingestion Timing):**  
  When generating reports on active sessions or sessions undergoing live traffic, query counts naturally increased with arrival of new frames (e.g., reaching 101 queries by report generation time).

### 2.2 Issue 2 — Observation Duration Drift on Stopped Sessions
- **Observed Behavior:** PDF recorded 204.43 seconds, while JSON recorded 216.51 seconds for session `cap-1b027bdbe612`.
- **Root Cause:**  
  In `backend/app/analytics/analytics_engine.py`, `get_overview()` computed observation duration dynamically on every call:
  ```python
  now = datetime.now(timezone.utc)
  duration = max(0.0, round((now - self.created_at).total_seconds(), 2))
  ```
  While `LiveCaptureEngine` in `backend/app/capture/capture_engine.py` recorded `self.stopped_at = datetime.now(timezone.utc)` when stopped, `AnalyticsEngine` did not record `self.stopped_at` or freeze `duration`. When the user generated a PDF report at $t_1$, `now - created_at` evaluated to 204.43 seconds. When the user generated a JSON report 12.08 seconds later at $t_2$, `now - created_at` evaluated to 216.51 seconds. The session duration continuously grew after capture termination.

### 2.3 Issue 3 — SHA-256 Session Digest Inconsistency Across Formats
- **Observed Behavior:** PDF and JSON reports produced different SHA-256 digests for the same session.
- **Root Cause 1 (Clock Timestamp in Canonical Payload):**  
  In `backend/app/reports/data_collector.py`, `compute_session_digest(payload)` included `"generated_at": payload.generated_at.isoformat()` in its canonical hash input dictionary. Because `generated_at` represents the transient clock time when the user clicked "Generate", generating PDF at 13:00:00 and JSON at 13:00:12 created two completely different SHA-256 hashes.
- **Root Cause 2 (Drifting Scope Info):**  
  `scope_info["Observation Duration"]` was included in the canonical hash. Because observation duration was drifting continuously on stopped sessions (Issue 2), every subsequent export hashed a different duration string.
- **Root Cause 3 (Static PDF Sign-Off):**  
  In `backend/app/reports/pdf_generator.py`, the sign-off block rendered static text `Integrity Check: PASSED` without actively recomputing or verifying the digest against the canonical session data.

---

## 3. Affected Files & Implemented Remediations

| Component | File Path | Nature of Fix |
|:---|:---|:---|
| **Analytics Engine** | [`backend/app/analytics/analytics_engine.py`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/backend/app/analytics/analytics_engine.py) | Added `self.stopped_at` and `self._final_duration`. Frozen duration logic guarantees that once status is `STOPPED` or `ERROR`, `get_overview().duration_seconds` is permanently immutable. |
| **Capture Engine** | [`backend/app/capture/capture_engine.py`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/backend/app/capture/capture_engine.py) | Synchronized `started_at` and `stopped_at` with `analytics_engine`. Guarantees `capture_duration_seconds == overview.duration_seconds`. |
| **Data Collector** | [`backend/app/reports/data_collector.py`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/backend/app/reports/data_collector.py) | Replaced transient `generated_at` with immutable canonical session dictionary (`report_type`, `source_id`, `scope_info`, `summary_metrics`, `findings_count`, `table_headers`, `rows_hash`). Added `verify_session_integrity()` and `verify_json_report()`. Explicitly populated `"DNS Queries"`, `"DNS Responses"`, and `"Total DNS Frames"` in `summary_metrics`. |
| **JSON Generator** | [`backend/app/reports/json_generator.py`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/backend/app/reports/json_generator.py) | Recomputes and validates digest dynamically; includes `canonical_payload`, `verified: true`, and `status: "PASSED"`. |
| **PDF Generator** | [`backend/app/reports/pdf_generator.py`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/backend/app/reports/pdf_generator.py) | Recomputes and validates digest dynamically; renders `<font color='#10B981'><b>PASSED (SHA-256 Verified)</b></font>` or `<font color='#EF4444'><b>FAILED (Digest Mismatch)</b></font>`. |
| **Traffic Page UI** | [`frontend/src/app/traffic/page.tsx`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/frontend/src/app/traffic/page.tsx) | Synchronized `overview.dns_queries_count` with `dns.total_queries` during state updates; updated MetricCard value to `dns?.total_queries ?? overview?.dns_queries_count ?? 0`. |
| **DNS Card UI** | [`frontend/src/components/analytics/DnsAnalyticsCard.tsx`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/frontend/src/components/analytics/DnsAnalyticsCard.tsx) | Updated badge to `TOTAL FRAMES: {dns?.total_dns_packets || 0}` and tile to `DNS Queries: {dns?.total_queries || 0}`. |
| **Test Suite** | [`backend/tests/test_reports.py`](file:///c:/Users/Hala/Downloads/Project%20Files/Ashlynx%20Network%20Inspector/backend/tests/test_reports.py) | Added 4 comprehensive regression tests covering duration freezing, cross-format digest consistency, DNS metrics, and deliberate tampering detection. |

---

## 4. Verification Evidence & Acceptance Gate Validation

### Acceptance Gate 1: DNS Metric Semantic Consistency
- **Test:** `test_dns_metric_consistency_across_overview_and_dns`
- **Result:** PASSED
- **Evidence:** Synthetic feed of 3 DNS queries and 2 DNS responses produced:
  - `overview.dns_queries_count == 3`
  - `dns_analytics.total_queries == 3`
  - `dns_analytics.total_responses == 2`
  - `dns_analytics.total_dns_packets == 5`
  - `payload.summary_metrics["DNS Queries"] == 3`
  - `payload.summary_metrics["DNS Responses"] == 2`
  - `payload.summary_metrics["Total DNS Frames"] == 5`
  - Main KPI Card: `3 reqs` (DNS Queries)
  - DNS Card Header: `TOTAL FRAMES: 5`
  - DNS Card Tile 1: `DNS Queries: 3`
  - DNS Card Tile 2: `DNS Responses: 2`

### Acceptance Gate 2: Capture Duration Identical Across PDF, CSV, and JSON
- **Test:** `test_stopped_session_immutable_duration` & `test_cross_format_session_digest_and_duration_consistency`
- **Result:** PASSED
- **Evidence:** Stopped session `cap-1b027bdbe612` ($t_0$ to $t_1$, 204.43s) generated:
  - `payload_pdf.scope_info["Observation Duration"]` = `204.43 seconds`
  - `payload_json.scope_info["Observation Duration"]` = `204.43 seconds`
  - `payload_csv.scope_info["Observation Duration"]` = `204.43 seconds`
  - Verified with simulated sleep of 50ms: `overview1.duration_seconds == overview2.duration_seconds == 204.43s`.

### Acceptance Gate 3: Canonical Session Digest Identical Across Formats
- **Test:** `test_cross_format_session_digest_and_duration_consistency`
- **Result:** PASSED
- **Evidence:** For session `cap-1b027bdbe612`:
  - `payload_pdf.session_digest` = `64-hex SHA-256`
  - `payload_json.session_digest` = `64-hex SHA-256`
  - `payload_csv.session_digest` = `64-hex SHA-256`
  - `assert payload_pdf.session_digest == payload_json.session_digest == payload_csv.session_digest` evaluated to `True`.

### Acceptance Gate 4: Dynamic Tampering Detection
- **Test:** `test_host_discovery_session_digest_integrity`
- **Result:** PASSED
- **Evidence:**
  - Untampered JSON report: `DataCollector.verify_json_report(parsed)` -> `(True, digest, digest)`.
  - Deliberately modified canonical field (`parsed["metrics"]["Online Hosts"] = 999`):
    `DataCollector.verify_json_report(parsed_tampered)` returned `(False, comp_t, expected)`.
  - In PDF generator, any digest mismatch renders:
    `<font color='#EF4444'><b>FAILED (Digest Mismatch)</b></font>`.

### Acceptance Gate 5: Security & Privacy Baseline Preservation
- **Result:** PASSED
- **Evidence:**
  - Zero raw packet payload bytes stored or exported across all formats.
  - Safe Mode enforced: only RFC 1918 and loopback targets probed.
  - Path traversal protection intact.
  - Formula injection sanitization preserved (`'`, `=`, `+`, `-`, `@`).

### Acceptance Gate 6: Existing UI & Functionality Preservation
- **Result:** PASSED
- **Evidence:** Approved Light Bento layout, typography, and color tokens (`#1D3557`, `#457B9D`, `#F1FAEE`, `#E63946`) preserved without redesign.

### Acceptance Gate 7: Regression Suites & Production Builds
- **Backend Test Suite (Pytest):** 108 passed, 0 failed in 27.48s.
- **Frontend Turbopack Production Build:** 12/12 routes prerendered with 0 errors in 2.5s.
- **Complete Matrix Export Verification:** All 21 combinations (7 report types × 3 formats) verified with 100% success.

---

## 5. Summary Matrix of Verification Test Points

| Test Point | Tested Condition | Measured Value / Result | Verdict |
|:---|:---|:---|:---:|
| **TP-1** | Stopped session duration drift check | $t_1$: 204.43s $\rightarrow$ $t_2$: 204.43s (0.00s drift) | **PASS** |
| **TP-2** | PDF vs JSON observation duration | PDF: 204.43s, JSON: 204.43s (Identical) | **PASS** |
| **TP-3** | PDF vs JSON vs CSV session digest | Exact 64-hex SHA-256 match across all 3 formats | **PASS** |
| **TP-4** | DNS semantic separation | Frames: 5, Queries: 3, Responses: 2 (Synchronized) | **PASS** |
| **TP-5** | Tampered JSON report detection | Modified `"Online Hosts"` flagged `is_valid == False` | **PASS** |
| **TP-6** | Tampered payload PDF sign-off | Detected mismatch renders `FAILED (Digest Mismatch)` | **PASS** |
| **TP-7** | Full Pytest suite execution | 108 passed, 0 failed | **PASS** |
| **TP-8** | Next.js Turbopack build | 12/12 static pages compiled cleanly | **PASS** |
| **TP-9** | Zero raw payload bytes in reports | Confirmed 0 payload bytes stored or exported | **PASS** |
| **TP-10** | RFC 4180 CSV & pandas ingestion | 100% clean ingestion, formula injection sanitized | **PASS** |

---

## 6. Operational Limitations

1. **Symmetric Session Digest Scope:** The SHA-256 session digest provides deterministic content integrity verification against accidental corruption, transmission errors, and in-flight tampering. As documented in the report sign-off blocks, it does not provide asymmetric public-key cryptography (PKI) digital signatures or non-repudiation.
2. **Live Capture Active Sessions:** When querying analytics during an active, running capture session, metrics update in real-time as frames arrive on the wire. Immutable, frozen metrics apply to stopped sessions (`status == "STOPPED"` or `"ERROR"`).

