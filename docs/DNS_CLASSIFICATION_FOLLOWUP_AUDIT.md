# Ashlynx Network Inspector (ANI) v1.0.0
# DNS Classification, TCP Framing & Local Traffic Follow-Up Audit

**Target Session Audited:** `cap-c5085d3ecb00`  
**Execution Context:** Real-network live capture session  
**Local Interface:** `Realtek 8852BE Wi-Fi 6` (`192.168.29.59`)  
**Gateway / Local DNS:** `192.168.29.1`  
**Date:** 2026-11-09  

---

## 1. Executive Summary & Problem Statement

An engineering investigation was conducted on live capture session `cap-c5085d3ecb00` to resolve three specific analytical discrepancies observed across the Traffic Analytics dashboard and generated reports:

1. **Protocol Disconnect:**
   - **Application Layer Intelligence** reported `77 DNS/TCP` packets and `2 DNS/UDP` packets.
   - **DNS Intelligence** reported only `2 queries`, `0 responses`, and `79 total DNS frames`.
2. **DNS Message Validity:**
   - The 77 TCP packets involving port 53 were classified as "DNS" solely by port number without genuine DNS message parsing or validation.
3. **Directional Metric Definition:**
   - **Local Network Bytes** reported `0 bytes`, despite 80 packets (5,318 bytes) exchanged between the host (`192.168.29.59`) and the local subnet gateway (`192.168.29.1`).

---

## 2. Root Cause Analysis

### Issue 1 & 2: Blind Port Classification vs. Genuine DNS Message Parsing

#### The Mechanism in `ProtocolAnalyzer` and `DnsAnalyzer`
In the previous implementation:
1. `ProtocolAnalyzer.process_packet()` checked:
   ```python
   if proto_upper == "DNS" or meta.src_port == 53 or meta.dst_port == 53:
       app_name = "DNS"
   ```
   Every frame with transport port 53 was labeled as `app_name = "DNS"`. Because 77 packets had transport protocol `TCP`, `ProtocolAnalyzer` recorded `("DNS", "TCP"): 77 pkts`. The 2 packets with transport protocol `UDP` were recorded as `("DNS", "UDP"): 2 pkts`.

2. `DnsAnalyzer.process_packet()` checked:
   ```python
   is_dns = (meta.protocol == "DNS") or (meta.src_port == 53 or meta.dst_port == 53)
   if is_dns:
       self.total_dns_packets += 1
   ```
   This blindly incremented `self.total_dns_packets` for all 79 packets (77 TCP + 2 UDP).

3. `DnsAnalyzer` then attempted to inspect the raw Scapy packet:
   ```python
   if hasattr(raw_packet, "haslayer") and raw_packet.haslayer("DNS"):
       # Parse query / response ...
   ```
   - In Scapy, UDP DNS datagrams automatically possess the `DNS` layer (`haslayer("DNS") == True`). Hence, the 2 UDP packets were parsed as queries (`total_queries = 2`).
   - For TCP frames on port 53, Scapy's default dissectors **never attach a `DNS` layer** (`haslayer("DNS") == False`), because TCP is a stream protocol (Layer 4) with framing requirements.
   - Furthermore, in a real TCP connection to port 53 (such as connection testing, port scanning, or keep-alives), most frames are **TCP transport control frames** (`SYN`, `SYN-ACK`, `ACK`, `FIN`, `RST`) with **0 payload bytes**.
   - Because `haslayer("DNS")` was `False` and `meta.dns_summary` was `None`, none of the 77 TCP frames were parsed.
   - **Result:** `total_dns_packets = 79`, `total_queries = 2`, `total_responses = 0`.

---

### Issue 3: DNS-over-TCP Framing Specifications (RFC 1035 & RFC 7766)

Unlike UDP, where each datagram encapsulates a standalone DNS message, TCP is an unstructured byte stream. 

RFC 1035 Section 4.2.2 and RFC 7766 mandate explicit two-byte framing:
$$\text{Frame} = [\text{2-byte Length Prefix } N \text{ (big-endian)}] + [N\text{-byte RFC 1035 DNS Message}]$$

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|     Message Length (16 bits)  |                               |
+-------------------------------+       DNS Header & Payload    |
|                                       (minimum 12 bytes)      |
+---------------------------------------------------------------+
```

#### Stream Segmentation & Dissection Limitations
- **TCP Control Frames (0 payload):** Handshake (`SYN`, `SYN-ACK`, `ACK`) and teardown (`FIN`, `RST`) packets carry 0 payload bytes. They contain no DNS data and must never be counted as DNS message frames.
- **Sub-Prefix Fragments ($< 2$ bytes):** Packets carrying fewer than 2 bytes cannot even specify message length.
- **Incomplete Segments ($< 2 + N$ bytes):** Without a stateful TCP stream reassembly engine, individual segmented frames cannot be parsed into complete DNS messages.
- **Malformed / Corrupted Payloads:** Raw payloads claiming length $N$ with invalid opcodes ($> 5$), invalid rcodes ($> 10$), or corrupt question sections must be discarded, not misidentified as responses.

---

### Issue 4: Directional Metric Definition & Gateway Traffic Accounting

In session `cap-c5085d3ecb00`, 80 packets (5,318 bytes) were exchanged between the host (`192.168.29.59`) and the default gateway (`192.168.29.1`), but `Local Network Bytes` reported `0`.

#### Exact Metric Definition in `BandwidthAnalyzer`
`BandwidthAnalyzer.classify_direction(src_ip, dst_ip)` evaluates traffic relative to the captured interface IP addresses (`interface_ips`):
- `OUTBOUND`: `src_ip in interface_ips and dst_ip not in interface_ips` (Wire transmission TX).
- `INBOUND`: `dst_ip in interface_ips and src_ip not in interface_ips` (Wire reception RX).
- `LOCAL`: `src_ip.startswith("127.") or dst_ip.startswith("127.") or (src_ip in interface_ips and dst_ip in interface_ips)` (Inter-process loopback or host-internal self-addressed traffic).
- `UNKNOWN`: Promiscuous traffic where neither endpoint matches the interface.

$$\text{Total Volume} = \text{Inbound (RX)} + \text{Outbound (TX)} + \text{Local (Loopback)} + \text{Unknown}$$

#### The Semantic Mislabeling in Reports
- Traffic exchanged with `192.168.29.1` physically left the host's wireless adapter (Outbound TX) or arrived at the wireless adapter (Inbound RX).
- The metric was defined in `schemas/analytics.py` as:
  ```python
  local_bytes: int = Field(0, description="Local loopback/internal bytes")
  ```
- However, `data_collector.py` labeled this field `"Local Network Bytes"`.
- This led users to expect local LAN subnet traffic (such as gateway traffic) to appear under that metric.
- Had gateway traffic been classified as `LOCAL`, it would have subtracted from `INBOUND` and `OUTBOUND`, falsifying real-time wire throughput.
- **Resolution:** The metric was corrected and renamed to `"Host Loopback Bytes"` in report telemetry to clearly denote host-internal/loopback traffic, preserving wire volume conservation.

---

## 3. Implementation Changes

### 1. DNS-over-TCP Dissection in `packet_parser.py`
Implemented `parse_dns_over_tcp(tcp_layer)` with RFC 1035 2-byte prefix decoding, minimum 12-byte header validation, opcode/rcode sanity checks, and safe exception isolation:
- Inspects TCP payload on port 53.
- Requires `len(raw_payload) >= 2 + msg_len` and `msg_len >= 12`.
- Validates `opcode <= 5`, `rcode <= 10`, `qdcount <= 100`, and `qname != b"."`.
- Sets `dns_summary = "Query: <name>"` or `"Response (rcode=<val>)"` only when validated.
- Leaves `dns_summary = None` for control frames (SYN, ACK, FIN) and incomplete stream fragments.

### 2. Validated Message Tracking in `dns_analyzer.py`
- Integrated RFC 1035 TCP framing into `DnsAnalyzer.process_packet()`.
- Validated DNS queries and responses over both UDP and TCP.
- Excluded TCP control frames (SYN, ACK, FIN) and unvalidated packets from `self.total_dns_packets`.
- Ensured `total_dns_packets` reflects genuine DNS message frames, preventing phantom counts.

### 3. Transport vs. Application Distinction in `protocol_analyzer.py`
- Preserved strict exclusive transport partitioning (`TCP`, `UDP`, `ICMP`, `ARP`, `OTHER`).
- Enhanced `ApplicationProtocolItem` to distinguish validated application packets (`is_inferred = False`) from port-inferred packets (`is_inferred = True`).
- Guaranteed zero double-counting across the transport layer.

### 4. Telemetry Precision in `data_collector.py`
- Updated report telemetry dictionary from `"Local Network Bytes"` to `"Host Loopback Bytes"`.
- Documented metric semantics across all analytics modules.

---

## 4. Verification Evidence & Test Results

### Regression Test Suite (`backend/tests/test_analytics.py`)

Six new regression tests were added and verified:

```python
# 1. Genuine DNS-over-UDP query & response
test_dns_over_udp_parsing_scapy() -> PASSED

# 2. RFC 1035 / RFC 7766 DNS-over-TCP with 2-byte prefix framing
test_dns_over_tcp_rfc1035_framing_and_parsing() -> PASSED

# 3. TCP control frames (SYN, ACK, FIN) on port 53 excluded from DNS metrics
test_dns_over_tcp_control_frames_not_represented_as_dns() -> PASSED

# 4. Incomplete stream fragments and corrupted payloads safely ignored
test_dns_over_tcp_malformed_and_incomplete_streams() -> PASSED

# 5. Gateway traffic classified as OUTBOUND/INBOUND with local_bytes == 0
test_bandwidth_directional_classification_gateway_vs_loopback() -> PASSED

# 6. Transport exclusive partition vs. application breakdown (zero double counting)
test_protocol_analyzer_transport_vs_application_distinction() -> PASSED
```

### Full Test Suite Execution Summary
- **Command:** `python -m pytest backend/tests -q`
- **Result:** `114 passed, 0 failed in 28.18s`
- **Suite Breakdown:**
  - `test_analytics.py`: 17 passed
  - `test_capture.py`: 12 passed
  - `test_discovery.py`: 19 passed
  - `test_reports.py`: 21 passed
  - `test_scanner.py`: 22 passed
  - `test_security.py`: 23 passed

### Frontend Production Build
- **Command:** `npm run build`
- **Result:** `12/12 static routes compiled successfully` with Next.js Turbopack:
  ```text
  Route (app)
  ┌ ○ /
  ├ ○ /_not-found
  ├ ○ /discovery
  ├ ○ /events
  ├ ○ /history
  ├ ○ /interfaces
  ├ ○ /reports
  ├ ○ /scanner
  ├ ○ /settings
  └ ○ /traffic
  ```

---

## 5. Architectural Boundaries & Limitations

1. **TCP Stream Segmentation Boundary:**
   ANI operates as a passive, non-intrusive metadata analyzer without full multi-segment TCP stream reassembly. When a DNS-over-TCP message is fragmented across multiple TCP packets, individual fragments lacking the complete prefix-delimited message are safely marked as unparsed TCP segments rather than corrupted DNS data.
2. **Payload Privacy Guarantee:**
   In compliance with Safe Mode, zero packet payload bodies, credentials, or application data are logged or retained. Only the DNS query domain name and standard response codes are extracted for telemetry.

