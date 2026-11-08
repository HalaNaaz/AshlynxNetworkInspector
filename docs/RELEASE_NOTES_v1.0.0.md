# ASHLYNX NETWORK INSPECTOR (ANI)
# RELEASE NOTES — VERSION 1.0.0 (OFFICIAL RELEASE)
**Date:** November 2026 • **Milestone:** Complete Platform Release  
**Repository:** [https://github.com/HalaNaaz/AshlynxNetworkInspector](https://github.com/HalaNaaz/AshlynxNetworkInspector) • **Release Tag:** [`v1.0.0`](https://github.com/HalaNaaz/AshlynxNetworkInspector/releases/tag/v1.0.0)

---

## 🚀 Welcome to Ashlynx Network Inspector v1.0.0

Ashlynx Network Inspector (ANI) has achieved its official **v1.0.0 Production Release**. This milestone completes all engineering phases, delivering an integrated, high-performance network security inspection, real-time traffic analysis, passive behavioral anomaly detection, and compliance reporting platform.

---

## 🌟 Highlights & Key Capabilities

### 1. Dual-Engine Port Scanner (Engine A)
- **TCP Connect Engine**: High-speed concurrent port scanning using native Python `socket.connect_ex()`. Accurate error classification: `OPEN`, `CLOSED` (`ECONNREFUSED` / RST), `FILTERED`, `NO_RESPONSE` / `UNKNOWN`.
- **UDP Datagram Engine**: Connected UDP socket probes with protocol-specific payloads (DNS, NTP, SNMP, SSDP, NetBIOS) and ICMP Port Unreachable detection (`WSAECONNRESET` 10054 on Windows).

### 2. Live Packet Capture & Network Interfaces (Engine B)
- **Npcap & Scapy Live Capture**: Non-blocking background worker thread capturing live physical wire traffic (verified on Realtek 8852BE Wi-Fi adapter).
- **Metadata-Only Wire Processing**: Zero raw payload persistence; zero credential or session token leakage.
- **Strict Transport Protocol Partition**: Zero double-counting Layer-3/4 transport breakdown ($\sum \text{transport} = \text{total packets}$).

### 3. Real-Time Traffic Analytics (Engine B+)
- **Directional Bandwidth**: High-resolution bit rate (bps) and packet rate (pps) tracking across 1s, 5s, 30s, and 60s windows with directional attribution (`INBOUND`, `OUTBOUND`, `LOCAL`, `UNKNOWN`).
- **Top Talkers Ranking**: Transmitting and receiving volume rankings with private/public address classification.
- **Canonical 5-Tuple Connection Tracking**: Bidirectional flow reconstruction with TCP handshake state progression.
- **DNS Intelligence**: Domain query frequency, query types (`A`, `AAAA`, `CNAME`, `PTR`, `MX`, `TXT`, `HTTPS`), and response code metrics with domain redaction.

### 4. Subnet Host Discovery (Engine C)
- Multi-vector subnet sweeps across IPv4 CIDRs (`AUTO`, Windows `SendARP`, ICMP Echo ping, TCP connect).
- Distinguishes reverse DNS PTR from local hosts file (`HOSTS_FILE`) and system loopback (`SYSTEM_LOOPBACK`).

### 5. Passive Security Intelligence & Anomaly Detection (Engine D)
- **10 Modular Detection Rules**: Vertical Port Scans, Horizontal Port Sweeps, Rapid SYN Bursts, Connection Churn, Repeated RST, Baseline Traffic Spikes, DNS Bursts, NXDOMAIN Enumeration, Suspicious Domain Lengths, Sensitive Services Access.
- **Dynamic Behavioral Baselines**: Session-scoped rolling baseline with a 10-sample warmup period to eliminate cold-start false positives.
- **Multi-Vector Correlation Engine**: Correlates co-occurring anomalies by source IP without inflating primary event counts.
- **Full Incident Lifecycle**: `NEW` $\to$ `ACKNOWLEDGED` $\to$ `INVESTIGATING` $\to$ `RESOLVED` / `FALSE_POSITIVE` with sanitized notes and immutable audit trails.

### 6. Multi-Source Compliance Reporting (Engine E)
- **7 Data Sources**: System Baseline & Telemetry, TCP Scans, UDP Scans, Host Discovery, Packet Capture Sessions, Traffic Analytics, and Security Events.
- **3 Independent Export Formats**:
  - **PDF**: 10-section publication-quality document built with ReportLab, complete with Light Bento color palette, Bento metrics cards, primary findings table, security evaluation, and two-pass `Page X of Y` numbering.
  - **CSV**: RFC 4180-compliant comma-separated tabular data with single consistent header row, formula injection sanitization, and pandas compatibility.
  - **JSON**: Standardized audit schema with target inventory, executive summary, KPI metrics, raw findings, and complete preview isolation.
- **Security & Storage Protection**: Strict identifier validation, path traversal defense, and bounded 50-file storage.
- **Interactive Reports Workstation**: Dedicated UI (`/reports`) featuring domain selector, live multi-format interactive preview panel (JSON syntax viewer, CSV tabular view, PDF document preview), and report archive table.

---

## 📦 Verification & Quality Standard

- **Automated Tests:** 95 / 95 passed (100% test success across all 11 test suites).
- **Frontend Build:** 12 App Router routes compiled cleanly with 0 TypeScript errors.
- **UI Design System:** Light Bento (`#F1FAEE`, `#A8DADC`, `#457B9D`, `#1D3557`, `#E63946`).
