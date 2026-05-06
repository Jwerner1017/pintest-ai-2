# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform synthesizing best elements from leading cybersecurity tools (KaliGPT inspiration) with Claude Sonnet 4.5 for intelligent assistance.

## User Personas
1. **Security Professional** — Full-time pentester needing efficient workflow
2. **Ethical Hacker** — Bug bounty hunter requiring quick reconnaissance
3. **Security Student** — Learning cybersecurity concepts with AI guidance
4. **IT Administrator** — Running security assessments on company infrastructure

## Core Requirements
- JWT-based authentication with role-based access + TOTP MFA
- Dark theme default (light mode available)
- Hybrid UI: Visual dashboard + CLI terminal
- AI assistant powered by Claude Sonnet 4.5
- Modular architecture for scan types
- Async scan execution with real-time progress + cancellation
- AI-generated executive summaries

## Implementation History

### v1.0 (Feb 2026)
- JWT auth, AI chat (Claude Sonnet 4.5), mocked scans, dashboard, reports

### v1.1 (Feb 2026)
- Modular React refactor (`src/pages/`, `components/layout/`, `contexts/`)
- Real Nmap recon with mock fallback
- Shodan host intel endpoint + UI
- PDF report export (ReportLab)
- TOTP MFA full lifecycle

### v1.2 (Feb 2026)
- Real vulnerability scans (nmap NSE + HTTP probe + TLS check) with risk score & OWASP mapping
- Real network analysis (nmap host discovery + service mapping + anomaly heuristics)
- Async scan execution + real-time progress polling

### v1.3 (Feb 2026)
- ✅ **Backend split**: monolithic `server.py` (~700 lines) → 55-line app + `core/` (db, security, models) + `routers/` (auth, scans, reports, chat, dashboard)
- ✅ **AI scan summariser**: `POST /api/scans/{id}/summary` returns Claude-generated 3-bullet executive summary, cached in DB after first call
- ✅ **Scan cancellation**: `POST /api/scans/{id}/cancel` + in-memory `_active_tasks` dict + asyncio task cancellation; UI Cancel button on progress bar
- ✅ **Orphan janitor**: startup hook `reap_orphaned_scans()` flips stuck `running` scans to `failed` with stage 'Orphaned (server restarted)'
- ✅ **Race-safe completion**: `_execute_scan` only sets `status='completed'` if scan is still `running` (prevents late-completion overwriting a cancellation)

## Technical Architecture
```
/app/
├── backend/
│   ├── server.py           # Thin app composition (~55 lines)
│   ├── core/
│   │   ├── db.py           # Mongo singleton
│   │   ├── security.py     # JWT, bcrypt, get_current_user, MFA tokens
│   │   └── models.py       # Pydantic models
│   ├── routers/
│   │   ├── auth.py         # register, login, login/mfa, me, mfa setup/enable/disable
│   │   ├── scans.py        # POST/GET/DELETE/cancel/summary scans + Shodan + janitor
│   │   ├── reports.py      # generate, list, pdf
│   │   ├── chat.py         # Claude chat + history
│   │   └── dashboard.py    # stats + trends
│   ├── services/
│   │   ├── nmap_service.py
│   │   ├── vuln_service.py
│   │   ├── network_service.py
│   │   ├── shodan_service.py
│   │   ├── report_service.py
│   │   └── mfa_service.py
│   ├── tests/
│   │   ├── backend_test.py        # v1.0/v1.1 legacy regression
│   │   ├── test_scans_v12.py      # v1.2 async + real engines
│   │   └── test_v13_features.py   # v1.3 split + cancel + AI summary + janitor
│   ├── requirements.txt
│   └── .env                # MONGO_URL, DB_NAME, EMERGENT_LLM_KEY, SHODAN_API_KEY (optional)
├── frontend/src/
│   ├── App.js              # Routing only (~45 lines)
│   ├── contexts/AuthContext.js
│   ├── hooks/useScanPolling.js
│   ├── components/
│   │   ├── layout/{Sidebar,Header,MainLayout}.js
│   │   ├── routes/ProtectedRoute.js
│   │   ├── settings/MFASettings.js
│   │   └── scans/{ScanProgress,AIScanSummary}.js
│   └── pages/{Login,Register,Dashboard,Recon,Vulnerabilities,Network,Assistant,Terminal,Reports,Settings}Page.js
└── memory/{PRD.md,test_credentials.md}
```

## Key API Endpoints
- `POST /api/auth/register` / `/login` / `/login/mfa`
- `GET /api/auth/me`, `/auth/mfa/status`
- `POST /api/auth/mfa/setup` / `/enable` / `/disable`
- `POST /api/scans` → returns immediately with `{status:'running', progress:0}`
- `POST /api/scans/{id}/cancel` → mark cancelled, kill task
- `POST /api/scans/{id}/summary` → Claude-generated 3-bullet exec summary (cached)
- `GET /api/scans` / `/scans/{id}` (polling target)
- `POST /api/shodan/lookup`, `GET /api/shodan/status`
- `POST /api/reports/generate`, `GET /api/reports`, `GET /api/reports/{id}/pdf`
- `POST /api/chat` (Claude Sonnet 4.5)
- `GET /api/dashboard/stats`

## Container Constraints
- nmap binary at `/usr/bin/nmap` (installed via `apt-get install nmap`)
- No CAP_NET_RAW → must use `-sT` (TCP connect) and `-PS` for discovery
- Single uvicorn worker — `_active_tasks` dict is per-process

## Prioritized Backlog

### P1 (High Priority)
- NVD CVE enrichment for vuln findings (link to CVSS, exploit DBs)
- Configurable scan presets (fast / thorough / stealth)
- Migrate `@app.on_event('startup')` to FastAPI lifespan context manager
- AI summary: store generation timestamp + model name for audit

### P2 (Medium Priority)
- Scan scheduling (cron-style)
- Email notifications on critical findings
- Team collaboration & sharing
- Custom vulnerability database

### P3 (Nice to Have)
- Mobile responsive polish
- Dark web monitoring integration
- Compliance mapping (PCI-DSS, NIST, expand OWASP)
- AI-powered remediation suggestions per finding
- Export to SARIF for CI/CD pipeline integration

## Next Tasks
1. NVD CVE enrichment
2. Configurable scan presets
3. Lifespan migration
