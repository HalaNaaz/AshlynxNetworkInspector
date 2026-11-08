# ASHLYNX NETWORK INSPECTOR (ANI)
# SECURE BY DESIGN SPECIFICATION & SECURITY POLICY
**Version:** `1.0.0` • **Classification:** Operational Standard

---

## 1. Security Architecture Principles

Ashlynx Network Inspector was designed and implemented strictly under **Secure by Design** requirements. Every interface, socket, data structure, and endpoint adheres to defense-in-depth principles:

### 1.1 Zero Shell & Subprocess Execution
- All port scans, datagrams, and network probes are executed using native Python standard libraries (`socket`, `ipaddress`, `ctypes`) and memory-safe Scapy/Npcap calls.
- Arbitrary command invocation, shell pipes, `os.system()`, and unsanitized `subprocess.Popen()` are strictly prohibited.

### 1.2 Zero Persistent Raw Payloads (Metadata-Only Architecture)
- ANI functions as a defensive security observer, not a wiretap.
- Application layer payloads (e.g., HTTP POST bodies, credentials, authorization bearer tokens, TLS encrypted records) are never extracted, logged, retained in memory, or written to disk.
- Wire analysis is performed exclusively on Layer-2/3/4 packet headers and DNS metadata.

### 1.3 Safe-Mode Boundary Enforcement
- Scanning engines (TCP, UDP, Host Discovery) validate all target IPs and CIDRs against a strict authorization boundary:
  - Loopback (`127.0.0.0/8`, `::1`)
  - RFC 1918 Private Subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - APIPA Link-Local (`169.254.0.0/16`)
- Scans directed toward unauthorized public IP addresses are rejected with HTTP 400 Bad Request before socket allocation.

### 1.4 Path Traversal & File Download Protection
- Report generation endpoints enforce strict identifier validation (`^[a-zA-Z0-9_\-]+$`).
- Filepaths are resolved strictly inside the designated `backend/reports/` directory using `os.path.basename` and root path containment checks.
- Any attempt to inject `..`, `/`, `\`, or absolute paths triggers an immediate `PermissionError` and HTTP 403/400.

### 1.5 Strict Input Validation & Type Safety
- All HTTP requests are validated using strict Pydantic models with explicit min/max boundaries on ports, timeouts, concurrency, and CIDRs.
- BPF filter strings are sanitized to block dangerous punctuation and control characters.

---

## 2. Threat Model & Abuse Cases Matrix

| Threat Vector | Attack Scenario | ANI Defensive Countermeasure |
|---|---|---|
| **Arbitrary Network Scanning** | Malicious actor attempts to probe public critical infrastructure via ANI. | **Safe-Mode Boundary Enforcement**: Strict IP/CIDR validation rejects non-private targets. |
| **Command Injection** | Attacker injects shell characters in BPF filters or scan target strings. | **Zero Subprocess Execution**: Native socket calls only; regex sanitization of BPF expressions. |
| **Path Traversal** | Attacker requests `../../etc/passwd` via report download API. | **Safe Path Resolver**: Rejects path delimiters (`/`, `\`, `..`); verifies path stays within storage root. |
| **Memory Exhaustion (DoS)** | Prolonged high-throughput wire capture causes Out-Of-Memory. | **Bounded Ring Buffer**: `collections.deque(maxlen=N)` automatically evicts oldest packets. |
| **Confidential Data Leakage** | Credentials captured from unencrypted wire traffic stored in reports. | **Payload Privacy Standard**: Only Layer-3/4 headers and DNS query names parsed; zero payloads kept. |
| **False Positive Alarm Storms** | Normal HTTPS web browsing triggers horizontal port sweep alerts. | **Smart Rule Calibration**: Connection state confirmation (`SYN` without `ACK`) and higher web port thresholds. |

---

## 3. Vulnerability Reporting & Disclosure

To report a vulnerability or security flaw in Ashlynx Network Inspector, please open a private security advisory or contact the project security maintainer:

- **Repository:** https://github.com/Halanaaz1401/AshlynNetworkInspector
- **Security Policy:** All reported vulnerabilities will receive an initial triage response within 48 hours.

