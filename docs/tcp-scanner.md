# Ashlynx Network Inspector (ANI)
## Engine A — TCP Connect Port Scanner Specification

Version: `0.2.0-tcp` (Phase 2 Milestone)

---

## 1. Methodology & Overview

Engine A is an independent, custom-engineered TCP Connect port scanner implemented natively in Python using the `socket` standard library. It does not wrap Nmap or external binary utilities.

### The TCP Three-Way Handshake
TCP Connect scanning relies on completing the standard TCP 3-way connection sequence:
1. **SYN**: ANI sends a SYN segment to target `IP:Port`.
2. **SYN-ACK** / **RST**:
   - If the listening service is active, the operating system kernel returns `SYN-ACK`. ANI completes the handshake with `ACK` (or the OS kernel completes it via `connect_ex`), establishing an `OPEN` state.
   - If the port is not listening, the target host kernel returns an explicit `RST` segment, raising `ECONNREFUSED` (code 10061 on Windows, 111 on Linux) and establishing a `CLOSED` state.
   - If a firewall, packet filter, or network device drops the packet without response, the socket times out, resulting in a conservative `FILTERED` or `UNKNOWN` state.
3. **Socket Teardown**: The connection is immediately closed cleanly via `sock.close()` to release the socket descriptor and avoid lingering connections.

---

## 2. Port State Classification

| State | Criterion | Evidence |
|---|---|---|
| **`OPEN`** | Successful 3-way handshake | `sock.connect_ex()` returned `0`. Target machine accepted TCP connection. |
| **`CLOSED`** | Active refusal | Kernel returned explicit RST (`ECONNREFUSED` / 10061). Target host is reachable but no service is listening. |
| **`FILTERED`** | Timeout / Unreachable | Socket timed out (`ETIMEDOUT` / 10060 / 10035) or network returned ICMP host/network unreachable. No definitive determination possible. |
| **`UNKNOWN`** | Execution error | Unexpected socket exception or driver-level anomaly during transmission. |

> **Safety Rule**: Connection timeouts are **never** classified as closed ports. Conservative classification prevents false assumptions regarding firewall presence or service status.

---

## 3. Inferred Service Identification

Engine A maps recognized port numbers against a local database of standardized IANA and common application ports:
- **Port 20/21**: FTP-DATA / FTP
- **Port 22**: SSH
- **Port 23**: TELNET
- **Port 25**: SMTP
- **Port 53**: DNS
- **Port 80 / 8080**: HTTP / HTTP-ALT
- **Port 110**: POP3
- **Port 135 / 139 / 445**: MS-RPC / NetBIOS / SMB
- **Port 143**: IMAP
- **Port 443 / 8443**: HTTPS / HTTPS-ALT
- **Port 3306**: MySQL
- **Port 3389**: RDP
- **Port 5432**: PostgreSQL
- **Port 5900**: VNC
- **Port 6379**: Redis
- **Port 27017**: MongoDB

### Fallback & Confidence
If the port is not in the hardcoded table, Engine A queries `socket.getservbyport(port, "tcp")`. If unrecognized, it defaults to `"UNKNOWN"`.

**Service Confidence**: Every service label carries `service_confidence: "inferred"`. Port numbers alone do not guarantee what software is listening on a given port (e.g. an HTTP server running on port 2222 or custom software on port 80).

---

## 4. Safety Guardrails & Limits

1. **Target Authorization Filter**:
   - Scans are restricted by default to:
     - `127.0.0.1/32` (Loopback)
     - `10.0.0.0/8` (Private RFC-1918)
     - `172.16.0.0/12` (Private RFC-1918)
     - `192.168.0.0/16` (Private RFC-1918)
   - Public IP scanning is explicitly prohibited by default to prevent unauthorized network reconnaissance.
2. **Resource Boundaries**:
   - Maximum ports per scan: **1,024**.
   - Default connection timeout: **1.0 second** (Configurable from 0.1s to 5.0s).
   - Maximum worker concurrency: **100 threads** (Default: 50).
3. **No Exploitation or Evasion**:
   - Zero SYN stealth tricks, packet fragmentation, or firewall evasion logic.
   - Non-blocking execution via `asyncio.to_thread` prevents event loop blocking.

---

## 5. API Reference

### `GET /api/scanner/status`
Returns Engine A operational status and supported scanning methods.

### `POST /api/scanner/validate`
Validates target IP authorization, DNS resolution, and port ranges without dispatching a scan.
**Request**:
```json
{
  "target": "127.0.0.1",
  "preset": "common"
}
```

### `POST /api/scanner/scan`
Executes a TCP Connect scan across the requested ports.
**Request**:
```json
{
  "target": "127.0.0.1",
  "ports": [22, 80, 443, 3306],
  "timeout": 1.0,
  "concurrency": 50
}
```
**Response**:
```json
{
  "success": true,
  "data": {
    "scan_id": "scan-3e8a91f2",
    "target": "127.0.0.1",
    "scan_type": "TCP_CONNECT",
    "status": "completed",
    "started_at": "2026-11-08T13:00:00Z",
    "completed_at": "2026-11-08T13:00:02Z",
    "duration_seconds": 2.01,
    "total_ports": 4,
    "open_ports": 1,
    "closed_ports": 3,
    "filtered_or_unknown_ports": 0,
    "results": [
      {
        "port": 80,
        "protocol": "TCP",
        "state": "OPEN",
        "service": "HTTP",
        "service_confidence": "inferred",
        "response_time_ms": 0.35
      }
    ]
  }
}
```

### `GET /api/scanner/scans/{scan_id}`
Retrieves full result findings for a specific scan ID.

### `GET /api/scanner/history`
Returns chronological list of recent scan session metadata.

### `GET /api/scanner/latest`
Returns the most recent scan findings for dashboard telemetry.

