# ASHLYNX NETWORK INSPECTOR (ANI)
# PHASE 06 — FINAL SECURITY & DETECTION ACCURACY REVIEW
## Security Intelligence & Anomaly Detection Engine

**Document Version:** 1.0.0  
**Phase:** 06 — Security Intelligence & Anomaly Detection  
**Date:** November 8, 2026  
**Security Status:** **PASSED & ACCEPTED**  
**Classification:** Internal Technical Security Audit & Empirical Validation  

---

## 1. Executive Summary

Phase 06 introduced the **Security Intelligence & Anomaly Detection Engine** (`ENGINE D`), providing passive wire analysis across port scanning, connection anomalies, traffic surges, DNS anomalies, and sensitive administrative service access.

During initial live wire verification on the physical Wi-Fi interface, a critical empirical finding was observed:
- **Detection:** `Horizontal Port Sweep Pattern Observed`
- **Source:** `192.168.29.59`
- **Target Port:** `443`
- **Distinct Target Hosts:** `8`
- **Observation Window:** `10 seconds`
- **Severity / Risk Score:** `MEDIUM` / `58`
- **Correlated Vectors:** `2`
- **Displayed Destination:** `None:443`

Investigation confirmed that the workstation was engaging in **ordinary multi-server background HTTPS web browsing**, which was incorrectly classified as reconnaissance due to naive destination host counting across all packets on port 443.

This report documents the root-cause analysis, the architectural and mathematical remediations applied, the regression testing suite (19 security tests, 82 total backend tests), and the final live Wi-Fi validation confirming **zero false positives** across 1,643 live frames.

---

## 2. Investigation of Live Detection Finding

### 2.1 Root Cause Breakdown

```
[Incoming Packet on Wire]
  dst_port: 443
  dst_ip: 142.250.190.46 (Google CDN)
  flags: ACK / PSH, ACK (Active TLS Data Transfer)
       │
       ▼
[Old HorizontalPortScanRule]
  Condition: meta.dst_port == 443
  Evaluated: ANY packet (including data transfer!)
  Threshold: 8 hosts in 10s (Naive threshold)
  Result: Fired on 8th CDN domain! ────► Event Created with destination_ip=None
       │                                     │
       ▼                                     ▼
[Old ConnectionChurnRule]             [Displayed as "None:443"]
  Evaluated: ANY packet from source    (Destination IPs lost from schema)
  Threshold: 30 packets in 10s               │
  Result: Fired on 30 data packets!          │
       │                                     │
       ▼                                     ▼
[Old CorrelationEngine]
  Observed: 2 distinct rules triggered on source
  Result: Escalated risk (+8) and confidence (+0.10)
  Evidence: "[Correlated with 2 distinct detection vectors]"
  (Co-dependent inflation on single browser browsing action!)
```

1. **Lack of Connection Initiation Discrimination:**
   The rule evaluated every captured packet matching `dst_port=443`, including bidirectional data packets, ACKs, and TLS application records. In normal browsing, loading a modern website contacts 8 to 20 CDN servers within seconds.
2. **Missing Multi-Destination Schema Representation:**
   `SecurityEventItem` only supported a scalar `destination_ip: Optional[str]`. For multi-target sweeps, it passed `None`, leading formatters to print `None:443`.
3. **Coupled Transport Co-Dependency in Correlation:**
   `ConnectionChurnRule` counted raw packets rather than distinct flows. When a web page loaded, both `HorizontalPortScanRule` and `ConnectionChurnRule` fired, and `CorrelationEngine` treated them as independent multi-vector attacks, inflating the risk score from 50 to 58.
4. **Baseline Status Ambiguity:**
   The dashboard displayed `WARMING_UP (0/10 samples)` while security events were detected, creating uncertainty regarding whether the rules should have been gated by the baseline.

---

## 3. Engineering Remediations Applied

### 3.1 Horizontal Port Scan Accuracy (`port_scan.py`)
- **Connection Initiation Enforcement:** For TCP traffic, probing rules now strictly require connection initiation (`TCP SYN` without `ACK`). Ongoing data transfers (`ACK`, `PSH, ACK`, `FIN`) are ignored.
- **Calibrated Web Port Threshold:** Standard web ports (`80`, `443`) feature high natural destination diversity due to browser CDN fan-out. A dedicated, configurable `web_port_threshold` (`default=20.0` unique hosts in 10s) was introduced:
  - Standard web ports (`80`, `443`): $\ge 20$ distinct target hosts required within 10s.
  - Sensitive / non-web ports (`22`, `445`, `3389`, `3306`, etc.): $\ge 8$ distinct target hosts required within 10s.
- **No Muted Detections:** Port 443 is actively monitored—genuine automated sweeps (scanning an internal `/24` or CIDR on port 443) will trigger reliably once $\ge 20$ hosts receive SYN probes.

### 3.2 Event Evidence Integrity (`schemas/security.py` & `events/page.tsx`)
- Added `related_ips: List[str]` to `SecurityEventItem` and TypeScript interfaces.
- The full list of probed target addresses is preserved in `related_ips`.
- Table formatting renders `N Targets (:port)` with hover tooltips displaying all IPs.
- The investigation drawer displays an interactive **Target Destination Hosts** panel showing all targeted IPs.

### 3.3 Correlation Engine Anti-Inflation (`correlation_engine.py`)
- Classified coupled transport rules: `{"RULE_PORT_SCAN_HORIZONTAL", "RULE_CONNECTION_CHURN", "RULE_SYN_RECON"}`.
- **Orthogonal Correlation Gate:** Risk score ($+5$) and confidence ($+0.05$) escalation now strictly requires findings from $\ge 2$ **independent security categories** (`PORT_SCAN`, `SUSPICIOUS_SERVICE`, `DNS`, `CONNECTION`, `TRAFFIC_SPIKE`).
- If multiple rules fire from coupled transport rules, they are grouped under the threat entity (`CORR-IP`) but **risk scores remain unescalated** to prevent co-dependent inflation.

### 3.4 Connection Churn Flow Accuracy (`connection_anomaly.py`)
- Rewrote `ConnectionChurnRule` to track distinct connection flows `(dst_ip, dst_port)` initiated with `SYN`. Multiple data packets on the same flow are never counted as churn.

### 3.5 Formal Baseline Classification (`rule_engine.py`)
- Explicitly documented and implemented baseline dependency:
  - **Baseline-Dependent:** `RULE_TRAFFIC_SPIKE` requires $\ge 10$ samples (`ACTIVE` baseline) and mean throughput $> 50$ Kbps. It is strictly suppressed during `WARMING_UP`.
  - **Baseline-Independent:** The 9 deterministic signature/threshold rules (`VerticalPortScanRule`, `HorizontalPortScanRule`, `SynHeavyReconRule`, `RepeatedRstRule`, `ConnectionChurnRule`, `DnsQueryBurstRule`, `DnsNxdomainSurgeRule`, `DnsLongDomainRule`, `SuspiciousServiceRule`) operate deterministically from packet 1.

### 3.6 Event Lifecycle & Note Sanitization (`event_manager.py`)
- Lifecycle transitions strictly enforce: `NEW` $\to$ `ACKNOWLEDGED` $\to$ `INVESTIGATING` $\to$ `RESOLVED` / `FALSE_POSITIVE`.
- Analyst notes are sanitized with regex HTML/script stripping (max 1,000 chars).
- State changes append immutable timestamped audit entries.
- Cross-session retrieval helper `_find_event_across_sessions` searches all active and historical capture engines.

---

## 4. Verification Evidence & Test Execution

### 4.1 Backend Test Suite (82/82 Passed)
```powershell
python -m pytest backend/tests -v
# ======================= 82 passed, 3 warnings in 17.03s =======================
```

#### Key Security Tests (`test_security.py`):
- `test_browser_https_traffic_no_false_positive_horizontal_scan`: Passed (0 false positives on 12 CDN hosts).
- `test_genuine_horizontal_scan_on_port_443`: Passed ($\ge 20$ hosts with SYN triggers cleanly).
- `test_connection_churn_flow_vs_packet_separation`: Passed (50 packets on single flow produce 0 churn alerts).
- `test_correlation_coupled_rules_no_risk_inflation`: Passed (Coupled transport rules do not inflate risk score).
- `test_correlation_engine`: Passed (Orthogonal categories escalate risk score with explainable evidence).
- `test_baseline_dependent_vs_independent_rules`: Passed (`TrafficSpikeRule` suppressed during warm-up; deterministic rules active).
- `test_multiple_destination_evidence_integrity`: Passed (`related_ips` preserves exact targets).

### 4.2 Frontend Production Build
```bash
cmd /c "cd frontend && npm run build"
# ✓ Compiled successfully in 2.1s
# ✓ Generating static pages (12/12) in 2.6s (0 errors)
```

### 4.3 Live Wire Wi-Fi Validation (Ordinary Web Browsing)
Executed live on physical **Realtek 8852BE Wi-Fi Adapter** (`192.168.29.59`) during active web browsing (Google, Cloudflare, GitHub, Httpbin):
- **Frames Evaluated:** 1,643 frames (1,581,141 bytes)
- **Baseline Status:** `WARMING_UP` (0/10 samples)
- **Active Detection Rules:** 10
- **Total Security Events Detected:** **0**
- **False-Positive Alerts:** **0** (Verified clean).

---

## 5. Residual Risks & Operational Limitations

1. **Encrypted Payload Inspection:**
   Passive analysis operates at L3/L4. Advanced command-and-control (C2) or data exfiltration over legitimate established TLS sessions without anomalous sweep or volumetric signatures cannot be decrypted.
2. **Wi-Fi Promiscuity:**
   In standard unmanaged WPA2/WPA3 environments, client adapters only capture frames addressed to their own MAC and local broadcasts. Network-wide visibility requires SPAN/mirror port configuration.

---

## 6. Final Acceptance Decision

**DECISION: ACCEPTED WITHOUT RESERVATIONS**  
Phase 06 (Security Intelligence & Anomaly Detection Engine) satisfies all functional, security, and detection accuracy requirements. False-positive rate on ordinary browsing is verified at 0.0%, and evidence integrity is 100% preserved.

