# Ashlynx Network Inspector (ANI) v2.0
# Vulnerability Remediation & Architecture Verification Report

**Document:** `ANI_V2_REMEDIATION_REPORT.md`
**Date:** November 24, 2026
**Project:** Ashlynx Network Inspector (ANI) v2.0
**Author:** Hala Naaz (AshlynxCyber)
**Status:** COMPLETE & VERIFIED

---

## Executive Summary

This report documents the comprehensive remediation of the first five high-priority architectural and security findings identified in `ANI_V2_INITIAL_AUDIT.md` for **Ashlynx Network Inspector (ANI) v2.0**.

All five vulnerabilities—ranging from Critical administrative API exposure to High-concurrency capture pipeline bottlenecks and Medium-severity persistence and event loop starvation issues—have been fully remediated, verified, and integrated into the ANI codebase.

### Key Remediation Achievements
1. **Administrative Access Control**: Implemented cryptographically secure Bearer token authentication protecting all 11 control-plane endpoints (captures, scans, reports, rule mutations, event status updates) while preserving unauthenticated access for health checks and OpenAPI specifications.
2. **High-Throughput Packet Decoupling**: Replaced synchronous packet callback execution with a bounded producer-consumer queue (`queue.Queue(maxsize=10000)`) and background analysis worker pool, preventing packet loss and Npcap driver buffer overflows under high PPS conditions.
3. **Historical Session Restoration**: Implemented SQLite-backed session rehydration in `CaptureManager`, eliminating in-memory state loss across server restarts and auto-recovering orphaned `CAPTURING` sessions to `INTERRUPTED`.
4. **CORS Hardening**: Eliminated wildcard headers and unconstrained methods, validating strict localhost origins and disallowing wildcard configurations when credentials are enabled.
5. **Event Loop Non-Blocking Architecture**: Converted blocking synchronous SQLite and filesystem route handlers from `async def` to standard `def`, allowing FastAPI to automatically offload them to its worker thread pool and preventing asyncio event loop starvation.
6. **Authoritative Test Suite Growth**: Expanded the backend test suite from 119 to **146 passing tests** (100% pass rate, zero regressions, zero skipped or disabled tests) alongside **8 passing frontend unit tests** and a successful Next.js 16 production build.

---

## 1. Summary of Remediated Findings

| Finding ID | Vulnerability Title | Severity | CWE | Remediation Status | Remediated Files | Verification Tests |
| :--- | :--- | :---: | :--- | :---: | :--- | :--- |
| **VULN-001** | Unauthenticated Administrative API Endpoints | **CRITICAL** (9.1) | CWE-306, CWE-862 | **REMEDIATED** | `backend/app/core/security.py`<br>`backend/app/core/config.py`<br>`backend/app/main.py`<br>`backend/app/api/*.py`<br>`frontend/src/lib/api.ts` | `test_auth.py`<br>(18 tests passed) |
| **VULN-002** | Synchronous Capture Worker Socket Overrun DoS | **HIGH** (7.5) | CWE-400, CWE-770 | **REMEDIATED** | `backend/app/capture/capture_engine.py`<br>`backend/app/schemas/capture.py` | `test_capture_concurrency.py`<br>`test_capture.py`<br>(18 tests passed) |
| **VULN-003** | In-Memory Session Disconnection on Process Reload | **MEDIUM** (5.3) | CWE-662, CWE-665 | **REMEDIATED** | `backend/app/capture/capture_manager.py`<br>`backend/app/db/repositories/capture_repo.py`<br>`backend/app/main.py` | `test_session_restoration.py`<br>`test_persistence.py`<br>(6 tests passed) |
| **VULN-004** | Overly Permissive CORS with Credentials Enabled | **MEDIUM** (5.0) | CWE-942 | **REMEDIATED** | `backend/app/core/config.py`<br>`backend/app/main.py` | `test_cors.py`<br>(3 tests passed) |
| **VULN-005** | Synchronous SQLite Queries in Async FastAPI Handlers | **MEDIUM** (4.5) | CWE-400 | **REMEDIATED** | `backend/app/api/capture.py`<br>`backend/app/api/reports.py`<br>`backend/app/api/scanner.py`<br>`backend/app/api/discovery.py`<br>`backend/app/api/network.py`<br>`backend/app/api/traffic.py` | `test_event_loop_concurrency.py`<br>(1 test passed) |

---

## 2. Detailed Technical Remediations

### 2.1 VULN-001: Unauthenticated Administrative API Endpoints (CRITICAL)
- **Problem**: In ANI v1.0.0, none of the 52 REST API routes required credentials. Any local process or browser tab on `localhost` could initiate active scans against arbitrary IP addresses, start promiscuous packet capture, alter detection rules, or delete security audit reports.
- **Root Cause**: Absence of an authentication dependency in FastAPI route declarations and configuration.
- **Remediation**:
  - Implemented `backend/app/core/security.py` providing cryptographic token resolution and validation:
    1. Reads token from `ANI_API_TOKEN` environment variable if configured.
    2. Falls back to persistent secret file in `backend/data/.ani_token`.
    3. Auto-generates a high-entropy 32-byte urlsafe cryptographic token (`secrets.token_urlsafe(32)`) on first startup, writing to `.ani_token` with restricted permissions.
  - Applied `Depends(verify_api_token)` using `hmac.compare_digest` across all administrative endpoints:
    - Capture controls: `POST /api/capture/start`, `POST /api/capture/stop`, `POST /api/capture/sessions/{id}/clear`
    - Active Reconnaissance: `POST /api/scanner/scan`, `POST /api/scanner/udp/scan`, `POST /api/discovery/scan`
    - Report Controls: `POST /api/reports/generate`, `DELETE /api/reports/{id}`
    - Security Mutations: `PATCH /api/security/rules/{id}`, `PATCH/POST /api/security/events/{id}/status`, `POST /api/security/events/{id}/notes`
  - Kept public diagnostics (`GET /api/health`, `/docs`, `/openapi.json`) open.
  - Updated `frontend/src/lib/api.ts` to seamlessly attach `Authorization: Bearer <token>` from environment variables or local workstation storage.
  - Updated `.gitignore` to ensure `.ani_token` is never committed.

### 2.2 VULN-002: Synchronous Packet Capture Worker Pipeline (HIGH)
- **Problem**: Scapy's `sniff(prn=_packet_callback)` callback executed metadata extraction, 6 analytical modules, 10 security detection rules, and database writes directly on Scapy's capture thread. Under bursty traffic, this blocked Scapy from reading the Npcap socket, causing driver-level packet drops.
- **Root Cause**: Tight coupling between the wire ingestion loop and the analytical processing pipeline.
- **Remediation**:
  - Replaced synchronous callback execution in `LiveCaptureEngine` with a decoupled producer-consumer queue:
    - Bounded FIFO queue: `self._packet_queue = queue.Queue(maxsize=10000)`.
    - Non-blocking callback: `_packet_callback` places raw frames directly onto the queue using `put_nowait()`.
    - Drop counter: If the queue is saturated, `dropped_packets` increments cleanly without stalling Scapy.
    - Analysis worker: Dedicated background thread `_run_processing_loop` drains packets, parses metadata, appends to the bounded ring buffer, and dispatches to `AnalyticsEngine` and `SecurityDetectionEngine`.
    - Graceful shutdown: Cleanly drains queued packets upon session `stop()` with a 3.0s timeout.
  - Enhanced `CaptureStatistics` schema with `packets_received`, `packets_processed`, and `queue_depth`.

### 2.3 VULN-003: In-Memory Session Disconnection After Process Reload (MEDIUM)
- **Problem**: `CaptureManager` maintained active sessions in a transient Python dictionary (`_sessions`). When the server restarted, active and completed sessions were lost from memory, causing `/api/capture/sessions/{id}` to return 404 despite complete session telemetry existing in SQLite. Furthermore, sessions in `CAPTURING` status at the moment of a process crash remained permanently stuck as `CAPTURING`.
- **Root Cause**: Purely in-memory session index without database rehydration logic.
- **Remediation**:
  - In `backend/app/main.py` lifespan: Implemented startup recovery `CaptureRepository.recover_interrupted_sessions()` which transitions orphaned `CAPTURING` sessions to `INTERRUPTED` with timestamps.
  - In `backend/app/capture/capture_manager.py`:
    - Implemented `HistoricalCaptureSession` adapter that rehydrates session summaries, statistics, and proxies `AnalyticsEngine` and `SecurityDetectionEngine` using snapshots and event tables from SQLite.
    - Updated `get_session_by_id()` to query SQLite when an ID is not in active memory, caching the restored session.
    - Updated `get_all_sessions()` to merge active memory sessions with historical SQLite records, sorting chronologically.

### 2.4 VULN-004: Overly Permissive CORS Configuration (MEDIUM)
- **Problem**: `CORSMiddleware` in `backend/app/main.py` used wildcard headers (`allow_headers=["*"]`) combined with `allow_credentials=True`.
- **Root Cause**: Incomplete configuration hardening.
- **Remediation**:
  - Constrained `cors_allow_methods` to `["GET", "POST", "PATCH", "DELETE", "OPTIONS"]`.
  - Constrained `cors_allow_headers` to explicit headers: `["Content-Type", "Authorization", "Accept", "X-Requested-With", "Origin"]`.
  - Added Pydantic field validator in `backend/app/core/config.py` forbidding wildcard `"*"` in `cors_origins` whenever `allow_credentials=True`.

### 2.5 VULN-005: Synchronous SQLite Operations Inside Async API Routes (MEDIUM)
- **Problem**: Multiple route handlers that perform blocking SQLite database queries, PDF/CSV disk generation, or hardware interface queries were defined as `async def`. Under FastAPI, an `async def` function runs on the main asyncio event loop, blocking all concurrent I/O.
- **Root Cause**: Misuse of `async def` on CPU-bound and blocking synchronous library calls.
- **Remediation**:
  - Audited all route handlers across `capture.py`, `reports.py`, `scanner.py`, `discovery.py`, `network.py`, and `traffic.py`.
  - Converted blocking synchronous routes from `async def` to standard `def`.
  - FastAPI now automatically offloads these synchronous route handlers to its external `anyio` worker thread pool, keeping the main asyncio event loop unblocked for concurrent requests, health checks, and active scans.

---

## 3. Test & Verification Results

### 3.1 Backend Test Suite (Pytest)
```text
Platform: win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
Plugins: anyio-4.14.2, asyncio-1.4.0, cov-7.1.0
Test Files Executed: 18 files across backend/tests
Total Tests: 146 passed, 14 deprecation warnings in 33.52s
Result: 100% PASSED (0 failures, 0 errors, 0 skipped)
```

#### New Dedicated Verification Test Modules
1. `backend/tests/test_auth.py` (18 tests):
   - Verified unauthenticated rejection (HTTP 401) across all 11 administrative endpoints.
   - Verified invalid token rejection (HTTP 401).
   - Verified valid Bearer token authorization.
   - Verified unauthenticated access to `GET /api/health` and `/openapi.json`.
   - Verified token generation, filesystem persistence, and caching.
2. `backend/tests/test_capture_concurrency.py` (3 tests):
   - Verified bounded queue isolation and non-blocking callback.
   - Verified worker thread queue draining and traffic counter accuracy.
   - Verified queue saturation and `dropped_packets` accounting under capacity overflow.
3. `backend/tests/test_session_restoration.py` (2 tests):
   - Verified startup recovery of orphaned `CAPTURING` sessions to `INTERRUPTED`.
   - Verified `CaptureManager` session resurrection from SQLite after in-memory dictionary eviction.
4. `backend/tests/test_cors.py` (3 tests):
   - Verified allowed origin CORS preflight response and headers.
   - Verified disallowed origin CORS rejection.
   - Verified Pydantic validation error when wildcard `*` is specified.
5. `backend/tests/test_event_loop_concurrency.py` (1 test):
   - Verified concurrent execution of blocking endpoints alongside health checks without event loop starvation.

### 3.2 Frontend Test Suite & Production Build
- **Unit Tests**: `node --test frontend/src/tests/*.test.mjs`
  - 8 tests executed, 8 passed, 0 failed in 218ms.
- **Production Build**: `next build` (Next.js 16.4.5 Turbopack)
  - TypeScript validation: Complete with zero errors.
  - Page generation: All 12 static routes compiled and prerendered successfully.

---

## 4. Architectural Verification Checklist

- [x] Zero Raw Packet Payload Storage (Metadata-only parsing maintained strictly).
- [x] Zero Hardcoded Secrets (Dynamic token generation or `ANI_API_TOKEN` environment variable).
- [x] Zero Regressions on Existing Functionality (All 119 baseline tests + 27 new tests pass).
- [x] Thread-Safe Database Transactions (WAL mode and connection isolation preserved).
- [x] Clean Git Working Directory (No credentials, `.ani_token`, or databases staged).
