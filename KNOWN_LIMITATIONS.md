# ASHLYNX NETWORK INSPECTOR (ANI)
# KNOWN LIMITATIONS & OPERATIONAL BOUNDARIES
**Version:** `1.0.0` • **Release Date:** November 2026

---

## 1. Operating System & Platform Boundaries

1. **Windows 11 / Windows Workstation Focus**:
   - High-performance live packet capture requires the **Npcap** kernel driver installed in "WinPcap API-compatible mode".
   - Hardware MAC address resolution in host discovery utilizes the Windows native `iphlpapi.dll SendARP` API. On Linux or macOS, host discovery gracefully falls back to ICMP Echo ping and TCP Connect probing.
2. **Loopback Adapter Behavior**:
   - Loopback traffic (`127.0.0.1`) does not possess an Ethernet MAC address; the system correctly reports MAC as `Not applicable` / `null` rather than an invalid all-zero string `00:00:00:00:00:00`.
   - Windows Npcap supports loopback capture via the "Npcap Loopback Adapter", but raw packet flags may differ slightly from physical Wi-Fi/Ethernet NICs.

---

## 2. Network Protocol & Scanning Boundaries

1. **Safe-Mode Authorization Scopes**:
   - By design, active port scanning and subnet discovery are restricted to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.0.0/16`. Probing public internet IP addresses is rejected to prevent accidental unauthorized reconnaissance.
2. **UDP Scanning Semantics**:
   - UDP is fundamentally connectionless. While ANI transmits protocol-appropriate datagrams (DNS, NTP, SNMP) and monitors for ICMP Port Unreachable responses, firewall-filtered or silent ports remain classified as `OPEN|FILTERED`. This is compliant with RFC 792 and standard network security conventions.
3. **Payload Inspection Policy**:
   - ANI does not perform TLS decryption, deep packet inspection (DPI) of encrypted payloads, or payload reassembly. This is an intentional architectural decision to uphold data privacy and prevent credential exposure.

---

## 3. Storage & Scale Boundaries

1. **Bounded Ring Buffers**:
   - Live packet capture maintains a bounded ring buffer of up to 5,000 frames (default 1,000) in memory. Oldest frames are automatically evicted under FIFO queuing.
2. **Bounded Report Archive**:
   - Report history maintains up to 50 generated PDF, CSV, and JSON files on disk. When generating the 51st report, the oldest report is automatically purged.

