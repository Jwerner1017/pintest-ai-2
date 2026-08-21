# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform synthesizing best elements from leading cybersecurity tools with Claude Sonnet 4.5 for intelligent assistance. Surfaces purpose-built security Linux distributions (DEFT, BackBox, Kodachi, Pentoo) contextually. Exports findings as PDF, SARIF 2.1 (CI/CD), and AI executive summaries.

## User Personas
1. **Security Professional** — Full-time pentester needing efficient workflow
2. **Ethical Hacker** — Bug bounty hunter requiring quick reconnaissance
3. **Security Student** — Learning cybersecurity concepts with AI guidance
4. **IT Administrator** — Running security assessments on company infrastructure
5. **DFIR Responder** — Incident response and forensics specialist
6. **DevSecOps Engineer** — Pipes scan results into CI/CD via SARIF

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
- SARIF 2.1 export for CI/CD pipeline integration
- Self-healing container (auto-installs nmap on startup if missing)

## Implementation History
- **v1.0** JWT auth, AI chat, mocked scans, dashboard, reports
- **v1.1** Modular React refactor, real Nmap, Shodan, PDF, TOTP MFA
- **v1.2** Real vuln + network scans, async polling
- **v1.3** Server split into routers, AI summariser, cancellation + orphan janitor
- **v1.4** NVD CVE enrichment, scan presets, lifespan, AI summary metadata, DEFT/BackBox/Kodachi/Pentoo distros

### v1.5 (Feb 2026)
- ✅ **Self-healing nmap install**: lifespan startup hook `_ensure_nmap_installed()` runs `apt-get install -y nmap` if missing.
- ✅ **Runtime nmap detection**: services now use `_nmap_available()` at call-time.
- ✅ **SARIF 2.1 export**: `GET /api/scans/{id}/sarif` and `GET /api/reports/{id}/sarif` for GitHub Code Scanning / GitLab SAST.
- ✅ Frontend SARIF download button on each report card.

### v1.9 (Feb 2026) — Hands-free Terminal + Safer Scheduler Delete
- ✅ **Terminal rewritten** as a real CLI over the async scan endpoints. Commands: `help`, `clear`, `whoami`, `scans`, `scan <target> [preset]`, `vuln <target> [preset]`, `netscan <cidr> [preset]`, `cancel <prefix>`, `summary <prefix>`, `xml <prefix>`, `ai <query>`. Includes ArrowUp/ArrowDown history recall, auto-scroll, scan_id prefix resolution, streaming progress lines, and direct blob download for XML.
- ✅ **Scheduler delete confirmation** — clicking delete now opens a Radix AlertDialog (`data-testid='delete-schedule-dialog'`) that shows the schedule name/cron/target before the destructive action.
- ✅ 8/8 new terminal backend endpoint tests, 23/23 v17+v18 regression, full Playwright flow (scan lifecycle to completion + AlertDialog cancel/confirm).

### v1.8 (Feb 2026) — Cron-style scan scheduler + non-blocking startup
- ✅ **Scheduler CRUD** — `POST/GET/PATCH/DELETE /api/schedules` with 5-field cron validation via `croniter`, per-user isolation, invalid cron/scan_type → 400.
- ✅ **Background dispatcher** — `services/scheduler.py` runs a 20-second asyncio tick loop that fires `enqueue_scheduled_scan()` for any enabled schedule whose `next_run_at <= now`, advances the cron cursor, and stamps `last_run_at` + `last_scan_id`. Fault-tolerant: bad schedules disable themselves instead of hot-looping.
- ✅ **Frontend `/scheduler`** — new page with cron templates (15min/hourly/6h/daily/weekly), scan-type + preset selectors, pause/resume switch, delete, next/last-run timestamps, and links back to the scan pages.
- ✅ **Non-blocking startup** — `_ensure_nmap_installed()` now runs under `await asyncio.to_thread(...)` so the event loop is not blocked during the (~15s) apt install on cold containers.
- ✅ 12/12 new pytest tests including a live 60-90s dispatch verification; 21/22 regression pass (only the stale v1.5.0 version assertion, now bumped to 1.8.0).

### v1.7 (Feb 2026) — Raw nmap XML evidence export
- ✅ **`GET /api/scans/{id}/nmap-xml`** streams the raw nmap XML stored at `scan.results.nmap_xml` as `application/xml` with `Content-Disposition: attachment; filename="pentestai-scan-{scan_id}.xml"`.
- ✅ **Download XML button** on `ReconPage`, `VulnerabilitiesPage`, `NetworkPage` (`data-testid="download-nmap-xml-button"`) — appears only when scan is completed AND `results.nmap_xml` is present.
- ✅ Verified: 11/11 pytest tests + 3/3 playwright pages (auth, cross-user 404, unauth 401 all covered).

### v1.6 (Feb 2026) — One-click "Launch in distro"
- ✅ **`GET /api/distros/{id}/launch?target=&scan_id=`** returns a self-contained bash script for BackBox / Pentoo / DEFT / Kodachi pre-loaded with `PENTESTAI_TARGET` env var.
   - BackBox & Pentoo → Docker workflows (`docker run backbox/backbox:latest`, `gentoo/stage3:latest`)
   - DEFT → informational (ISO download + `dd` command — evidence work requires live media)
   - Kodachi → informational (ISO + qemu-system + Tor/proxychains commands — anti-forensic, live-only)
- ✅ **CR/LF & control-char sanitisation** — `_sanitize()` strips CR/LF/tabs and non-printable chars before shell-quoting; verified injection-safe (attempted `evil.com\ntouch /tmp/PWNED\n#` payload is squashed into an inert single-quoted string).
- ✅ **Launch buttons** in ToolkitsPage (per distro card) and DistroRecommendation (per recommended distro on scan results, passes `target` + `scan_id` from the completed scan).
- ✅ **Self-healing nmap install**: lifespan startup hook `_ensure_nmap_installed()` runs `apt-get install -y nmap` if missing (≤2s noop / ~15s install). Container can now be rebuilt without manual intervention.
- ✅ **Runtime nmap detection**: services now call `_nmap_available()` at scan-execute time instead of module-import time, so newly-installed nmap is picked up without a reload.
- ✅ **SARIF 2.1 export**: `GET /api/scans/{id}/sarif` and `GET /api/reports/{id}/sarif` produce SARIF 2.1.0 JSON consumable by GitHub Code Scanning, GitLab SAST, Azure DevOps. Includes proper severity mapping (critical/high→error, medium→warning, low→note, info→none), CVSS-numeric `security-severity`, rule deduplication, and aggregated multi-scan runs for reports.
- ✅ **Frontend SARIF download**: button on each report card next to PDF, downloads `pentestai-report-{id}.sarif`.

## Technical Architecture
```
/app/
├── backend/
│   ├── server.py             # ~80 line app composition + lifespan + nmap self-heal (v1.5.0)
│   ├── core/
│   │   ├── db.py
│   │   ├── security.py
│   │   └── models.py
│   ├── routers/
│   │   ├── auth.py
│   │   ├── scans.py          # + cancel + summary + presets + sarif
│   │   ├── reports.py        # + sarif
│   │   ├── chat.py
│   │   ├── dashboard.py
│   │   └── distros.py
│   ├── services/
│   │   ├── nmap_service.py        # runtime _nmap_available()
│   │   ├── vuln_service.py        # runtime _nmap_available()
│   │   ├── network_service.py     # runtime _nmap_available()
│   │   ├── shodan_service.py
│   │   ├── report_service.py
│   │   ├── mfa_service.py
│   │   ├── presets.py
│   │   ├── nvd_service.py
│   │   ├── distros.py
│   │   └── sarif_service.py       # NEW: SARIF 2.1 builder
│   ├── tests/                # 6 pytest files (backend_test, scans_v12, v13, v14_features, v14_distros, v15_features)
│   └── .env
├── frontend/src/
│   ├── App.js
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
- Scans: `POST /api/scans` (queued async), `GET /api/scans|{id}`, `POST /api/scans/{id}/cancel|summary`, `GET /api/scans/presets`, **`GET /api/scans/{id}/sarif`**
- Shodan: `POST /api/shodan/lookup`, `GET /api/shodan/status`
- Reports: `POST /api/reports/generate`, `GET /api/reports|{id}/pdf|{id}/sarif`
- Chat: `POST /api/chat`, `GET /api/chat/history`
- Dashboard: `GET /api/dashboard/stats|vulnerability-trends`
- Distros: `GET /api/distros|{id}|recommend/{scan_type}`

## Container Constraints
- nmap now self-installs at startup via lifespan hook — no manual intervention needed
- No CAP_NET_RAW → uses `-sT` (TCP connect) and `-PS` discovery
- Single uvicorn worker — `_active_tasks` dict is per-process

## Prioritized Backlog

### P1 (High Priority)
- Email/Slack alerts on critical findings (auto-deliver AI summary + PDF/SARIF)
- Scan scheduling (cron-style automation)
- Move startup `subprocess.run(apt-get)` off the event loop (asyncio.to_thread) — minor

### P2 (Medium Priority)
- Team collaboration & shared workspaces
- Custom vulnerability database / private CVE feed
- Per-distro tool launcher (SSH into distro VM)
- Webhook on scan completion for external orchestration

### P3 (Nice to Have)
- Mobile responsive polish
- Dark web monitoring integration
- Compliance mapping (PCI-DSS, NIST, expand OWASP)
- AI-powered remediation suggestions per finding
- Distro release tracker

## Next Tasks
1. Email/Slack alerts (P1)
2. Scan scheduling (P1)
3. Webhook on scan completion (P2)
