# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform synthesizing best elements from leading cybersecurity tools (KaliGPT inspiration) with Claude Sonnet 4.5 for intelligent assistance.

## User Personas
1. **Security Professional** - Full-time pentester needing efficient workflow
2. **Ethical Hacker** - Bug bounty hunter requiring quick reconnaissance
3. **Security Student** - Learning cybersecurity concepts with AI guidance
4. **IT Administrator** - Running security assessments on company infrastructure

## Core Requirements (Static)
- JWT-based authentication with role-based access + TOTP MFA
- Dark theme default (light mode available)
- Hybrid UI: Visual dashboard + CLI terminal
- AI assistant powered by Claude Sonnet 4.5
- Modular architecture for scan types

## What's Been Implemented

### v1.0 (Feb 2026)
- Backend: JWT auth, AI chat (Claude Sonnet 4.5), mocked scans, dashboard, reports
- Frontend: Dark theme, dashboard, recon/vuln/network pages, AI assistant, terminal, reports, settings

### v1.1 (Feb 2026) — Modular refactor + real tooling
- ✅ Refactored monolithic `App.js` (1109 lines) into modular structure under `src/pages/`, `src/components/layout/`, `src/contexts/`, `src/lib/`
- ✅ Real **Nmap** integration via `python-nmap` (recon scans now run live with mock fallback)
- ✅ **Shodan** host intel endpoint + UI card on Reconnaissance page (requires `SHODAN_API_KEY`)
- ✅ **PDF export** for reports via ReportLab — endpoint `GET /api/reports/{id}/pdf`
- ✅ **TOTP MFA** (pyotp + qrcode): setup, enable, disable; two-step login flow
- ✅ Backend split into `services/` (nmap, shodan, report, mfa)

## Technical Architecture
```
/app/
├── backend/
│   ├── server.py           # Routes & auth
│   ├── services/
│   │   ├── nmap_service.py
│   │   ├── shodan_service.py
│   │   ├── report_service.py
│   │   └── mfa_service.py
│   ├── requirements.txt
│   └── .env                # MONGO_URL, DB_NAME, EMERGENT_LLM_KEY, SHODAN_API_KEY (optional)
├── frontend/
│   └── src/
│       ├── App.js          # Routing only (~45 lines)
│       ├── contexts/AuthContext.js
│       ├── components/
│       │   ├── layout/{Sidebar,Header,MainLayout}.js
│       │   ├── routes/ProtectedRoute.js
│       │   └── settings/MFASettings.js
│       ├── pages/{Login,Register,Dashboard,Recon,Vulnerabilities,Network,Assistant,Terminal,Reports,Settings}Page.js
│       └── lib/api.js
└── memory/{PRD.md,test_credentials.md}
```

## Key API Endpoints
- `POST /api/auth/register` / `/login` / `/login/mfa`
- `GET /api/auth/me`, `/auth/mfa/status`
- `POST /api/auth/mfa/setup` / `/enable` / `/disable`
- `POST /api/scans` (recon → real nmap, vuln/network → mocked)
- `GET /api/scans` / `/scans/{id}`
- `POST /api/shodan/lookup`, `GET /api/shodan/status`
- `POST /api/reports/generate`, `GET /api/reports`, `GET /api/reports/{id}/pdf`
- `POST /api/chat` (Claude Sonnet 4.5)
- `GET /api/dashboard/stats`

## Prioritized Backlog

### P1 (High Priority)
- Metasploit/Burp-inspired exploitation module
- Wireshark/Zeek behavioural network analysis
- Real-time scan progress (WebSocket / polling)
- Configurable scan presets

### P2 (Medium Priority)
- Scan scheduling / automation
- Team collaboration & sharing
- Email notifications (alerts on critical findings)
- Custom vulnerability database

### P3 (Nice to Have)
- Mobile responsive polish
- Dark web monitoring integration
- Compliance mapping (PCI-DSS, OWASP, NIST)
- AI-powered remediation suggestions

## Next Tasks
1. Exploitation module (P1)
2. Network behavioural analytics (P1)
3. Scheduling & notifications (P2)
