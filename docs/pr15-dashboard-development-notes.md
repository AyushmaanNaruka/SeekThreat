# Branch Overview & Changes: `mayank_development_2`

This document provides a comprehensive breakdown of all features added, architectural improvements, bug fixes, errors encountered, and verification steps implemented in the `mayank_development_2` branch for team review and onboarding.

---

## 📌 Executive Summary
- **Branch:** `mayank_development_2`
- **Pull Request:** [#15 on GitHub](https://github.com/AyushmaanNaruka/SeekThreat/pull/15)
- **Target:** `main`
- **Scope:** Interactive Threat Intelligence & Scanner Web Dashboard, Scanner Engine Adapters (Nmap & Nuclei), Celery Task Scan Execution Lifecycle, Backend API fixes, and End-to-End Test Suites.
- **Test Results:** **243 passing Python tests (pytest)** + **8 passing Frontend Polling tests (Node.js)**.

---

## 🚀 Features & Components Added

### 1. Interactive Threat Intelligence & Scanner Dashboard (`apps/web`)
- **Dashboard UI (`apps/web/app/dashboard/page.tsx`, `dashboard.css`)**:
  - Full-featured, responsive, dark-cyber themed dashboard.
  - **Live Metrics**: Displays Active Engagements, Monitored Targets, Running Scans, and Critical Findings.
  - **Target Scanning Modal**: Allows operators to launch on-demand scans (Nmap port scans, Nuclei vulnerability templates) against target IPs, domains, or CIDRs.
  - **Live Scan Status Badges & Logs**: Real-time scan indicators (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`) with progress feedback.
  - **Engagement & Target Inspector**: Interactive tables for filtering, viewing findings, and viewing scan timelines.
- **3D Threat Globe (`apps/web/components/DashboardGlobe.tsx`)**:
  - Three.js / Canvas-based interactive rotating globe with attack arc animations and real-time target ping markers.
- **Orbiting Radar Component (`apps/web/components/SidebarOrbit.tsx`)**:
  - Tactical cyber HUD widget displaying live scan status and telemetry in the sidebar.
- **Polling Engine (`apps/web/lib/polling.ts`)**:
  - Resilient polling mechanism that periodically checks active scan statuses.
  - Built-in maximum polling guard (`MAX_POLL_COUNT`) to prevent runaway API requests.
  - Automatic teardown and cleanup upon terminal states (`COMPLETED`, `FAILED`, `CANCELLED`).
- **API Client Layer (`apps/web/lib/api.ts`)**:
  - Typed Fetch API wrapper for backend endpoints (`/engagements`, `/scans`, `/targets`).

---

### 2. Scanner Engine & Celery Pipeline Improvements (`services/scanners`, `apps/api`)

- **Nmap Adapter (`services/scanners/nmap_adapter.py`)**:
  - Sanitized target parsing supporting single IPs, hostnames, and CIDR ranges.
  - Robust process execution with timeout guards and XML/text output parsing.
  - Graceful fallback for non-installed binary environments.
- **Nuclei Adapter (`services/scanners/nuclei_adapter.py`)**:
  - Nuclei template loading, CLI argument construction, and structured JSON output streaming.
  - Clean mapping of Nuclei findings into `TargetVulnerability` Pydantic models.
- **Celery Scan Worker Task (`apps/api/tasks/scans.py`)**:
  - Full state-machine transitions: `PENDING` ➔ `RUNNING` ➔ `COMPLETED` / `FAILED`.
  - Records `started_at`, `completed_at`, and error messages.
  - Transaction-safe database persistence with proper session commits.
- **API Routers & Repositories (`apps/api/routers/scans.py`, `apps/api/db/repositories.py`)**:
  - Corrected scan creation response codes and error handling.
  - Added query methods to retrieve scan results by target and engagement.

---

### 3. Comprehensive Testing Suite

- **Unit Tests (`tests/unit/`)**:
  - `test_nmap_adapter.py`: Validates command construction, output parsing, and error handling.
  - `test_nuclei_adapter.py`: Validates YAML template execution, severity filtering, and JSON report parsing.
  - `test_celery_task.py`: Tests scan background execution, DB state transitions, and error recovery.
  - `test_config.py`: Tests PostgreSQL psycopg3 driver normalization and CORS configuration.
  - `test_api.py`: Validates FastAPI route schemas and response validation.
- **Integration Tests (`tests/integration/`)**:
  - `test_e2e_flow.py`: Comprehensive test verifying the complete workflow: Engagement Creation ➔ Target Addition ➔ Scan Dispatch ➔ Scanner Execution ➔ Finding Aggregation.
- **Frontend Tests (`apps/web/tests/`)**:
  - `polling.test.mjs`: Tests lifecycle state transitions, timeout guards, and interval cleanup.

---

## 🛠️ Errors Faced & How They Were Resolved

| # | Issue Encountered | Root Cause | Solution Implemented |
|---|-------------------|------------|----------------------|
| **1** | **Pydantic-Settings `.env` test leakage** | `Settings()` in `test_config.py` read the local development `.env` from disk, overriding test monkeypatch variables. | Updated test helpers to instantiate `Settings(_env_file=None)` for pure in-memory test isolation. |
| **2** | **Celery Task DB Session Detachment** | SQLAlchemy models accessed across async worker contexts threw `DetachedInstanceError` or failed to persist scan completion. | Wrapped DB operations in explicit context sessions with proper try/finally commits and error logging. |
| **3** | **Large Binary Blocking Git Push** | Local scanner executable `vendor/bin/nuclei.exe` (144MB) exceeded GitHub's 100MB file limit. | Added `vendor/bin/` to `.gitignore` to prevent local binary artifacts from entering git tracking. |
| **4** | **Frontend Polling Memory / Timer Leaks** | If a scan hung or a user navigated away, setInterval timers could keep polling indefinitely. | Added `stopPolling()` cleanup hooks, maximum polling iterations limit (`MAX_POLL_COUNT = 60`), and React `useEffect` unmount teardowns. |
| **5** | **Missing Scanner Binary on Windows/Dev** | Environments without Nmap or Nuclei on system PATH threw unhandled `FileNotFoundError` during scanner execution. | Implemented binary detection with fallback to synthetic/mock execution when running in development/test mode. |

---

## 📂 File Modification Matrix

```
SeekThreat/
├── .gitignore                                  # Added vendor/bin/ ignore rule
├── apps/
│   ├── api/
│   │   ├── Dockerfile                          # Build configuration
│   │   ├── core/config.py                      # Psycopg3 & CORS configuration
│   │   ├── db/repositories.py                  # Scan repository updates
│   │   ├── routers/scans.py                    # Scan triggering and status endpoints
│   │   └── tasks/scans.py                      # Celery worker scan execution pipeline
│   └── web/
│       ├── app/
│       │   ├── dashboard/
│       │   │   ├── page.tsx                    # Main interactive Threat Dashboard
│       │   │   └── dashboard.css               # Cyber HUD styling & animations
│       │   ├── layout.tsx                      # Root layout configuration
│       │   └── page.tsx                        # Homepage routing
│       ├── components/
│       │   ├── DashboardGlobe.tsx              # Interactive Three.js/Canvas 3D Globe
│       │   └── SidebarOrbit.tsx                # Tactical radar HUD component
│       ├── lib/
│       │   ├── api.ts                          # Backend API client
│       │   └── polling.ts                      # Resilient scan polling engine
│       ├── package.json                        # Frontend dependencies
│       └── tests/
│           └── polling.test.mjs                # Polling engine test suite
├── packages/
│   └── schema/models/engagement.py             # Target & Scan schema definitions
├── services/
│   └── scanners/
│       ├── nmap_adapter.py                     # Nmap scanner adapter
│       └── nuclei_adapter.py                   # Nuclei scanner adapter
└── tests/
    ├── fixtures/nuclei/test_http_detect.yaml   # Nuclei test template fixture
    ├── integration/
    │   └── test_e2e_flow.py                    # Complete E2E integration test
    └── unit/
        ├── test_api.py                         # API endpoint unit tests
        ├── test_celery_task.py                 # Celery task execution tests
        ├── test_config.py                      # Configuration unit tests
        ├── test_nmap_adapter.py                # Nmap adapter unit tests
        └── test_nuclei_adapter.py              # Nuclei adapter unit tests
```

---

## 🧪 Verification Commands

To verify all changes locally:

```bash
# 1. Run full backend test suite (Unit + Integration)
python -m pytest

# 2. Run frontend polling tests
node apps/web/tests/polling.test.mjs

# 3. Start Web Dashboard (Next.js)
cd apps/web && npm run dev
# Open http://localhost:3000/dashboard
```
