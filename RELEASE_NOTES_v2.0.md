# Ashlynx Network Inspector (ANI) v2.0.0
## Release Notes — Core Architecture Hardening & Concurrency Release

**Release Version:** `2.0.0`
**Release Date:** November 24, 2026
**Engineering Lead & Author:** Hala Naaz (AshlynxCyber)
**Repository:** [https://github.com/HalaNaaz/AshlynxNetworkInspector](https://github.com/HalaNaaz/AshlynxNetworkInspector)
**Status:** PRODUCTION READY

---

## Overview

Ashlynx Network Inspector (ANI) v2.0.0 is a major architectural and security hardening release. Following the comprehensive system audit (`ANI_V2_INITIAL_AUDIT.md`), this release systematically resolves the top five identified vulnerabilities and architectural bottlenecks, transforming ANI into an enterprise-ready, local-first defensive network intelligence workstation.

Key highlights of this release include:
- **Administrative Bearer Token Authentication** protecting all sensitive control-plane and mutation endpoints.
- **Decoupled Packet Ingestion Pipeline** featuring a bounded FIFO queue and dedicated analysis worker thread pool.
- **SQLite Historical Session Restoration** and self-healing startup recovery for interrupted capture runs.
- **Strict CORS Hardening** eliminating wildcard headers and validating trusted origins.
- **Event Loop Threadpool Offloading** ensuring database and file I/O operations never block concurrent requests or health checks.
- **Expanded Test Coverage**: The backend test suite expanded from 119 to **146 passing tests** across 18 test modules, accompanied by 8 passing frontend unit tests and an optimized Next.js 16 Turbopack production build.

---

## Remediated Vulnerabilities & Security Enhancements

### 1. Administrative Bearer Token Authentication (VULN-001 / SEC-019)
- **Severity**: Critical (CVSS 9.1)
- **Problem**: In v1.0.0, all 52 REST API routes operated unauthenticated. Any local process or browser tab on `localhost` could initiate active scans, start packet capture, modify detection rules, or delete audit reports.
- **Solution**:
  - Implemented `backend/app/core/security.py` providing cryptographic token resolution and verification.
  - Secured tokens can be provided via `ANI_API_TOKEN` environment variable or are auto-generated as 32-byte urlsafe cryptographic secrets (`secrets.token_urlsafe(32)`) persisted to `backend/data/.ani_token` with 0600 file permissions.
  - Enforced `Depends(verify_api_token)` with constant-time HMAC comparison across all 11 control-plane endpoints (captures, scans, reports, rule mutations, event status updates).
  - Diagnostic endpoints (`GET /api/health`, `/docs`, `/openapi.json`) remain publicly accessible.
  - Updated `frontend/src/lib/api.ts` to attach `Authorization: Bearer <token>`.

### 2. High-Throughput Decoupled Packet Queue (VULN-002 / SEC-020)
- **Severity**: High (CVSS 7.5)
- **Problem**: Live packet sniffing executed packet parsing, 6 analytical modules, 10 security detection rules, and database writes directly on the Scapy capture thread, causing driver socket overruns under high PPS bursts.
- **Solution**:
  - Introduced a thread-safe bounded FIFO queue (`queue.Queue(maxsize=10000)`) in `LiveCaptureEngine`.
  - Non-blocking callback: Scapy's `_packet_callback` pushes packets onto the queue with `put_nowait()`.
  - Saturated queue handling: If the queue fills, `dropped_packets` increments cleanly without blocking the capture loop.
  - Dedicated analysis worker thread `_run_processing_loop` drains queued frames, executes metadata extraction, appends to the ring buffer, and dispatches to analytics and detection engines.
  - Graceful drainage: Drains remaining packets on session stop with a 3.0s timeout.
  - Added `packets_received`, `packets_processed`, and `queue_depth` telemetry to `CaptureStatistics`.

### 3. Historical Session Restoration & Crash Recovery (VULN-003 / SEC-021)
- **Severity**: Medium (CVSS 5.3)
- **Problem**: Capture sessions existed only in an in-memory dictionary. Server reboots cleared the session index, returning 404 on historical session IDs despite complete records existing in SQLite. Furthermore, crashed sessions stayed permanently marked as `CAPTURING`.
- **Solution**:
  - Implemented `CaptureRepository.recover_interrupted_sessions()` at server startup (`main.py` lifespan), automatically transitioning orphaned `CAPTURING` sessions to `INTERRUPTED`.
  - Implemented `HistoricalCaptureSession` adapter in `CaptureManager`, rehydrating session summaries, statistics, and analytics/security engine proxies from SQLite on demand.
  - Updated `get_session_by_id()` and `get_all_sessions()` to seamlessly merge active memory sessions with historical SQLite records.

### 4. Hardened Local CORS Configuration (VULN-004 / SEC-022)
- **Severity**: Medium (CVSS 5.0)
- **Problem**: `CORSMiddleware` used wildcard headers (`allow_headers=["*"]`) combined with `allow_credentials=True`.
- **Solution**:
  - Explicitly restricted `cors_allow_methods` to `["GET", "POST", "PATCH", "DELETE", "OPTIONS"]`.
  - Explicitly restricted `cors_allow_headers` to `["Content-Type", "Authorization", "Accept", "X-Requested-With", "Origin"]`.
  - Added Pydantic field validator in `Settings` forbidding wildcard `*` origins whenever credentials are enabled.

### 5. Event Loop Non-Blocking Threadpool Offloading (VULN-005 / SEC-023)
- **Severity**: Medium (CVSS 4.5)
- **Problem**: Blocking SQLite database queries and synchronous disk operations inside `async def` route handlers blocked FastAPI's main asyncio event loop.
- **Solution**:
  - Converted blocking synchronous routes in `capture.py`, `reports.py`, `scanner.py`, `discovery.py`, `network.py`, and `traffic.py` from `async def` to standard synchronous `def` functions.
  - FastAPI automatically offloads standard `def` routes to its worker thread pool (`anyio.to_thread.run_sync`), preventing event loop starvation during database transactions and PDF/CSV report generation.

---

## Test Suite & Verification Summary

| Test Domain | Target Files | Tests Passed | Status |
| :--- | :--- | :---: | :---: |
| **API Authentication** | `backend/tests/test_auth.py` | 18 | PASSED |
| **Capture Concurrency & Queue** | `backend/tests/test_capture_concurrency.py` | 3 | PASSED |
| **Session Restoration & Crash Recovery** | `backend/tests/test_session_restoration.py` | 2 | PASSED |
| **CORS Hardening** | `backend/tests/test_cors.py` | 3 | PASSED |
| **Event Loop Concurrency** | `backend/tests/test_event_loop_concurrency.py` | 1 | PASSED |
| **Core Packet Capture & BPF** | `backend/tests/test_capture.py` | 15 | PASSED |
| **Traffic Analytics Engine** | `backend/tests/test_analytics.py` | 11 | PASSED |
| **Passive Security Intelligence** | `backend/tests/test_security.py` | 19 | PASSED |
| **Compliance & Executive Reports** | `backend/tests/test_reports.py` | 19 | PASSED |
| **Active TCP Port Reconnaissance** | `backend/tests/test_scanner.py` | 14 | PASSED |
| **Active UDP Port Reconnaissance** | `backend/tests/test_udp_scanner.py` | 7 | PASSED |
| **Subnet Host Discovery** | `backend/tests/test_discovery.py` | 14 | PASSED |
| **End-to-End System Integration** | `backend/tests/test_e2e_integration.py` | 5 | PASSED |
| **Database Persistence & Migrations** | `backend/tests/test_persistence.py` | 4 | PASSED |
| **Host Network Telemetry** | `backend/tests/test_network.py` | 5 | PASSED |
| **Traffic Service Diagnostics** | `backend/tests/test_traffic.py` | 5 | PASSED |
| **Health Check & Runtime Status** | `backend/tests/test_health.py` | 1 | PASSED |
| **Total Backend Test Suite** | **All 18 pytest modules** | **146** | **100% PASSED** |
| **Frontend Unit Tests** | `frontend/src/tests/*.test.mjs` | **8** | **100% PASSED** |
| **Frontend Production Build** | Next.js 16.4.5 Turbopack | **12 Routes** | **100% PASSED** |

---

## Upgrade & Migration Notes

1. **API Token Configuration**:
   - For automated environments or CI/CD pipelines, set the environment variable:
     ```bash
     export ANI_API_TOKEN="your-secure-secret-token"
     ```
   - For local development, ANI will automatically create `backend/data/.ani_token` on startup if none exists.
2. **Frontend Communication**:
   - The Next.js frontend automatically picks up `NEXT_PUBLIC_API_TOKEN` if defined, or reads dynamic session tokens via `localStorage.getItem("ani_api_token")`.
3. **Database Schema**:
   - Fully backward-compatible with SQLite schema migrations. Interrupted sessions from previous crashes are automatically recovered to `INTERRUPTED` on initial startup.
