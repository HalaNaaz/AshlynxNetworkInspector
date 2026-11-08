# Ashlynx Network Inspector (ANI) Architecture Specification

## Overview
Ashlynx Network Inspector (ANI) is an independent network security platform combining two primary engines:
- **ENGINE A — Network Scanner**: TCP Connect scanning, UDP scanning, host discovery, service identification, and port state detection.
- **ENGINE B — Network Traffic Analyzer**: Live packet capture, protocol identification, traffic statistics, connection monitoring, and anomaly detection.

## High-Level Topology

```
+-------------------------------------------------------------+
|                     Next.js SOC Frontend                    |
|       (React 19, TypeScript, Tailwind CSS, Recharts)        |
+-------------------------------------------------------------+
                              |
                     REST API & JSON Responses
                              |
+-------------------------------------------------------------+
|                     FastAPI Backend Gateway                 |
|       (Centralized Config, Structured Logging, CORS)        |
+-------------------------------------------------------------+
            |                                     |
+------------------------+             +------------------------+
|  ENGINE A: SCANNER     |             |  ENGINE B: ANALYZER    |
|  - TCP Connect Scan    |             |  - Scapy Sniffer       |
|  - UDP Datagram Probe  |             |  - Protocol Decoder    |
|  - Scope Restrictions  |             |  - Payload Discard     |
+------------------------+             +------------------------+
```

## Security & Privacy Guardrails
1. **Localhost Binding**: Development backend binds exclusively to `127.0.0.1`.
2. **CORS Whitelisting**: Restricted strictly to authorized frontend origins (`http://localhost:3000`, `http://127.0.0.1:3000`).
3. **No Raw Payload Retention**: Packet payload bytes are discarded at the capture layer; only headers and metadata are processed.
4. **Scope Authorization**: Scans restricted by default to loopback and private RFC-1918 subnets.
5. **No Shell Invocations**: Zero arbitrary system command execution via API endpoints.

