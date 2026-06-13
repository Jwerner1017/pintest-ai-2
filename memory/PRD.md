# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform synthesizing best elements from leading cybersecurity tools (KaliGPT inspiration) with Claude Sonnet 4.5 for intelligent assistance. Surfaces purpose-built security Linux distributions (DEFT, BackBox, Kodachi, Pentoo) contextually based on the work being performed.

## User Personas
1. **Security Professional** — Full-time pentester needing efficient workflow
2. **Ethical Hacker** — Bug bounty hunter requiring quick reconnaissance
3. **Security Student** — Learning cybersecurity concepts with AI guidance
4. **IT Administrator** — Running security assessments on company infrastructure
5. **DFIR Responder** — Incident response and forensics specialist

## Core Requirements
- JWT-based authentication with role-based access + TOTP MFA
- Dark theme default (light mode available)
- Hybrid UI: Visual dashboard + CLI terminal
- AI assistant powered by Claude Sonnet 4.5
- Modular architecture (routers + services + core)
- Async scan execution with real-time progress + cancellation
- Configurable scan presets (fast / thorough / stealth)
- NVD CVE enrichment for service-version detections
- AI-generated executive summaries (with model + timestamp audit)
- Specialised toolkit recommendations (DEFT/BackBox/Kodachi/Pentoo)

## Implementation History

### v1.0 — JWT auth, AI chat, mocked scans, dashboard, reports
### v1.1 — Modular React refactor, real Nmap recon, Shodan, PDF, TOTP MFA
### v1.2 — Real vuln (nmap NSE + HTTP probe + TLS), real network (host discovery + service map), async scans + polling
### v1.3 — Server.py split into routers + core, AI scan summariser, cancellation + orphan janitor

### v1.4 (Feb 2026)
- ✅ **NVD CVE enrichment**: `services/nvd_service.py` queries NIST NVD API with 24h Mongo-backed cache; verified finding 5 CVEs for OpenSSH 7.4 with CVSS scores. Optional `NVD_API_KEY` increases rate limit (50/30s vs 5/30s anonymous).
- ✅ **Scan presets**: fast / thorough / stealth per scan_type. `GET /api/scans/presets` exposes metadata; `options.preset` selects at scan creation.
- ✅ **Lifespan migration**: replaced deprecated `@app.on_event` with `@asynccontextmanager lifespan` (FastAPI 0.93+ recommended).
- ✅ **AI summary metadata**: stores `ai_summary_model` and `ai_summary_generated_at` (ISO8601) on the scan doc; returned on subsequent fetches for audit.
- ✅ **Specialised distros**: DEFT, BackBox, Kodachi, Pentoo curated and surfaced via:
   - `GET /api/distros`, `/distros/{id}`, `/distros/recommend/{scan_type}`
   - Toolkits page (`/toolkits`) — catalogue UI
   - Inline recommendation cards on Recon/Vuln/Network results
   - AI assistant system prompt addendum (Claude now recommends distros contextually)

## Technical Architecture
```
/app/
├── backend/
│   ├── server.py             # ~55 line app composition + lifespan
│   ├── core/
│   │   ├── db.py             # Mongo singleton
│   │   ├── security.py       # JWT, bcrypt, MFA tokens
│   │   └── models.py         # Pydantic models
│   ├── routers/
│   │   ├── auth.py           # register, login, login/mfa, me, mfa setup/enable/disable
│   │   ├── scans.py          # POST/GET/DELETE/cancel/summary/presets + Shodan + janitor
│   │   ├── reports.py        # generate, list, pdf
│   │   ├── chat.py           # Claude chat + history (system prompt includes distros)
│   │   ├── dashboard.py      # stats + trends
│   │   └── distros.py        # distros catalogue + recommendations
│   ├── services/
│   │   ├── nmap_service.py
│   │   ├── vuln_service.py   # nmap NSE + HTTP + TLS + NVD enrichment
│   │   ├── network_service.py
│   │   ├── shodan_service.py
│   │   ├── report_service.py
│   │   ├── mfa_service.py
│   │   ├── presets.py        # fast/thorough/stealth definitions
│   │   ├── nvd_service.py    # NIST NVD API with Mongo cache
│   │   └── distros.py        # DEFT / BackBox / Kodachi / Pentoo + recommendations
│   ├── tests/                # backend_test, test_scans_v12, test_v13_features, test_v14_features, test_v14_distros
│   ├── requirements.txt
│   └── .env                  # MONGO_URL, DB_NAME, EMERGENT_LLM_KEY, SHODAN_API_KEY?, NVD_API_KEY?
├── frontend/src/
│   ├── App.js                # Routing only (~50 lines)
│   ├── contexts/AuthContext.js
│   ├── hooks/useScanPolling.js
│   ├── components/
│   │   ├── layout/{Sidebar,Header,MainLayout}.js
│   │   ├── routes/ProtectedRoute.js
│   │   ├── settings/MFASettings.js
│   │   └── scans/{ScanProgress,AIScanSummary,PresetSelector,DistroRecommendation}.js
│   └── pages/{Login,Register,Dashboard,Recon,Vulnerabilities,Network,Assistant,Terminal,Reports,Settings,Toolkits}Page.js
└── memory/{PRD.md,test_credentials.md}
```

## Key API Endpoints
- Auth: `POST /api/auth/register|login|login/mfa`, `GET /api/auth/me|mfa/status`, MFA setup/enable/disable
- Scans: `POST /api/scans` (queued async), `GET /api/scans|{id}`, `POST /api/scans/{id}/cancel|summary`, `GET /api/scans/presets`
- Shodan: `POST /api/shodan/lookup`, `GET /api/shodan/status`
- Reports: `POST /api/reports/generate`, `GET /api/reports|{id}/pdf`
- Chat: `POST /api/chat` (Claude Sonnet 4.5 with distros awareness), `GET /api/chat/history`
- Dashboard: `GET /api/dashboard/stats|vulnerability-trends`
- Distros: `GET /api/distros|{id}|recommend/{scan_type}`

## Container Constraints
- nmap binary at `/usr/bin/nmap` — **reinstall via `apt-get install -y nmap` after container rebuilds** (not persisted)
- No CAP_NET_RAW → uses `-sT` (TCP connect) and `-PS` discovery
- Single uvicorn worker — `_active_tasks` dict is per-process

## Prioritized Backlog

### P1 (High Priority)
- Persist nmap install via a startup script or container image rebuild
- Configurable scan presets exposed as per-type custom args (advanced mode)
- Scan scheduling (cron-style)
- Email/Slack notifications on critical findings (with AI summary + PDF)

### P2 (Medium Priority)
- SARIF export for CI/CD pipeline integration
- Team collaboration & shared workspaces
- Custom vulnerability database / private CVE feed
- Per-distro tool launcher integration (SSH into distro VM)

### P3 (Nice to Have)
- Mobile responsive polish
- Dark web monitoring integration
- Compliance mapping (PCI-DSS, NIST, expand OWASP)
- AI-powered remediation suggestions per finding
- Distro version/release tracker (auto-update DEFT/BackBox/Kodachi/Pentoo release info)

## Next Tasks
1. Make nmap install survive container restarts
2. Email/Slack alerts on critical findings
3. SARIF export
