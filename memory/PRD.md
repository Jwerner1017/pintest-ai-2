# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform synthesizing best elements from leading cybersecurity tools (KaliGPT inspiration) with Claude Sonnet 4.5 for intelligent assistance.

## User Personas
1. **Security Professional** — Full-time pentester needing efficient workflow
2. **Ethical Hacker** — Bug bounty hunter requiring quick reconnaissance
3. **Security Student** — Learning cybersecurity concepts with AI guidance
4. **IT Administrator** — Running security assessments on company infrastructure

## Core Requirements (Static)
- JWT-based authentication with role-based access + TOTP MFA
- Dark theme default (light mode available)
- Hybrid UI: Visual dashboard + CLI terminal
- AI assistant powered by Claude Sonnet 4.5
- Modular architecture for scan types
- Async scan execution with real-time progress

## What's Been Implemented

### v1.0 (Feb 2026)
- JWT auth, AI chat (Claude Sonnet 4.5), mocked scans, dashboard, reports

### v1.1 (Feb 2026)
- ✅ Modular React refactor (`src/pages/`, `components/layout/`, `contexts/`)
- ✅ Real Nmap recon (`services/nmap_service.py`) with mock fallback
- ✅ Shodan host intel endpoint + UI (requires `SHODAN_API_KEY`)
- ✅ PDF report export via ReportLab
- ✅ TOTP MFA full lifecycle (setup → enable → 2-step login → disable)

### v1.2 (Feb 2026)
- ✅ **Real vulnerability scans**: nmap NSE `--script vuln` + HTTP probe (security headers, server banner, robots.txt, insecure cookies) + TLS cert check
- ✅ **Real network analysis**: nmap host discovery (`-sn -PS`) + service mapping (`-sT -sV --top-ports 50`) + anomaly heuristics (telnet/ftp/rdp/snmp/wide-attack-surface)
- ✅ **Async scan execution**: POST `/api/scans` returns immediately with `status='running'`; background `asyncio.create_task` runs the scan and updates `progress` (0-100) + `stage` in MongoDB
- ✅ **Real-time progress UI**: `useScanPolling` hook + `ScanProgress` component on Recon/Vuln/Network pages
- ✅ Risk score (0-10) and OWASP Top-10 mapping in vuln results
- ✅ datetime now uses timezone-aware UTC throughout

## Technical Architecture
```
/app/
├── backend/
│   ├── server.py           # Routes & auth (~700 lines — flag for split next iteration)
│   ├── services/
│   │   ├── nmap_service.py       # recon
│   │   ├── vuln_service.py       # NSE vuln + HTTP probe + TLS
│   │   ├── network_service.py    # host discovery + service map
│   │   ├── shodan_service.py
│   │   ├── report_service.py     # PDF
│   │   └── mfa_service.py
│   ├── tests/
│   │   ├── backend_test.py       # legacy regression (async-aware)
│   │   └── test_scans_v12.py     # v1.2 specific
│   ├── requirements.txt
│   └── .env                # MONGO_URL, DB_NAME, EMERGENT_LLM_KEY, SHODAN_API_KEY (optional)
├── frontend/
│   └── src/
│       ├── App.js                # Routing only (~45 lines)
│       ├── contexts/AuthContext.js
│       ├── hooks/useScanPolling.js
│       ├── components/
│       │   ├── layout/{Sidebar,Header,MainLayout}.js
│       │   ├── routes/ProtectedRoute.js
│       │   ├── settings/MFASettings.js
│       │   └── scans/ScanProgress.js
│       ├── pages/{Login,Register,Dashboard,Recon,Vulnerabilities,Network,Assistant,Terminal,Reports,Settings}Page.js
│       └── lib/api.js
└── memory/{PRD.md,test_credentials.md}
```

## Key API Endpoints
- `POST /api/auth/register` / `/login` / `/login/mfa`
- `GET /api/auth/me`, `/auth/mfa/status`
- `POST /api/auth/mfa/setup` / `/enable` / `/disable`
- `POST /api/scans` → returns immediately with `{status:'running', progress:0}`
- `GET /api/scans` / `/scans/{id}` (polling target)
- `POST /api/shodan/lookup`, `GET /api/shodan/status`
- `POST /api/reports/generate`, `GET /api/reports`, `GET /api/reports/{id}/pdf`
- `POST /api/chat` (Claude Sonnet 4.5)
- `GET /api/dashboard/stats`

## Container Constraints
- nmap binary at `/usr/bin/nmap` (installed via `apt-get install nmap`)
- No CAP_NET_RAW → must use `-sT` (TCP connect) and `-PS` for discovery; raw-socket scans blocked
- pyotp + qrcode for MFA, reportlab for PDF, requests + python-nmap + shodan in `requirements.txt`

## Prioritized Backlog

### P1 (High Priority)
- Split `server.py` into routers (auth, scans, reports, chat) — file is now 700 lines
- AI scan summariser: feed nmap+probe results into Claude for executive 3-bullet risk summary
- Scan cancellation endpoint + janitor for orphaned 'running' scans on backend restart
- Configurable scan presets (fast / thorough / stealth)

### P2 (Medium Priority)
- Scan scheduling (cron-style)
- Email notifications on critical findings
- Team collaboration & sharing
- Custom vulnerability database / CVE enrichment via NVD API

### P3 (Nice to Have)
- Mobile responsive polish
- Dark web monitoring integration
- Compliance mapping (PCI-DSS, NIST, expand OWASP)
- AI-powered remediation suggestions per finding

## Next Tasks
1. Server.py split into routers
2. AI scan summariser
3. Scan cancellation + orphan-janitor
