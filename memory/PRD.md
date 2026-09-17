# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform with Claude Sonnet 4.5, Shodan OSINT, bulk scanning, scheduling, PDF reports, real-time WebSocket progress, and modular architecture.

## What's Been Implemented

### v1.0-1.4 (Earlier)
- JWT authentication, dark theme
- Real network scanning (DNS, WHOIS, Ports)
- Shodan OSINT, CVE Details from NVD
- Bulk scanning with CIDR support
- Scheduled scans with auto-execute
- PDF report generation
- WebSocket real-time progress
- Concurrent scanning (5 parallel)

### v1.5 - Modular Frontend & Export (Sep 2026)
- **Frontend Modularization**:
  - `src/context/AuthContext.jsx` - Authentication context
  - `src/components/layout/` - Sidebar, Header, MainLayout
  - `src/pages/` - LoginPage, RegisterPage
  - `src/lib/api.js` - API configuration
  - Reduced App.js from 119KB to 62KB (48% smaller)
  
- **CSV/JSON Export**:
  - Export any scan to CSV or JSON format
  - Includes ports, DNS records, vulnerabilities, Shodan data
  - Download buttons on Recon results page
  - Endpoint: GET /api/scans/{id}/export?format=csv|json

## Features Summary

### Backend (FastAPI + MongoDB)
- ✅ JWT Authentication
- ✅ AI Chat (Claude Sonnet 4.5)
- ✅ Real Reconnaissance (DNS, WHOIS, Ports)
- ✅ Shodan OSINT Integration
- ✅ Bulk Scanning with CIDR + Concurrent execution
- ✅ Scheduled Scans with Auto-Execute (APScheduler)
- ✅ CVE Details from NVD with caching
- ✅ PDF Report Generation (reportlab)
- ✅ CSV/JSON Export
- ✅ WebSocket for real-time progress

### Frontend (React + Tailwind + ShadcnUI)
- ✅ Modular architecture with separate files
- ✅ Dashboard with metrics
- ✅ Reconnaissance with CSV/JSON export
- ✅ Bulk Scan with WebSocket live progress
- ✅ Scheduled Scans page
- ✅ Reports with PDF download
- ✅ AI Assistant + Terminal
- ✅ Settings page

## File Structure

```
/app/frontend/src/
├── App.js                    # Main app (62KB, reduced from 119KB)
├── context/
│   └── AuthContext.jsx       # Auth provider
├── components/
│   └── layout/
│       ├── Sidebar.jsx
│       ├── Header.jsx
│       ├── MainLayout.jsx
│       └── index.js
├── pages/
│   ├── LoginPage.jsx
│   └── RegisterPage.jsx
└── lib/
    └── api.js

/app/backend/
├── server.py                 # API endpoints + scheduler
└── scanner.py                # Network scanner + Shodan
```

## API Endpoints

### Export
- GET /api/scans/{id}/export?format=csv - Export scan as CSV
- GET /api/scans/{id}/export?format=json - Export scan as JSON

### Reports
- GET /api/reports/{id}/pdf - Download PDF report

## Implementation History
- **v1.0** JWT auth, AI chat, mocked scans, dashboard, reports
- **v1.1** Modular React refactor, real Nmap, Shodan, PDF, TOTP MFA
- **v1.2** Real vuln + network scans, async polling
- **v1.3** Server split into routers, AI summariser, cancellation + orphan janitor
- **v1.4** NVD CVE enrichment, scan presets, lifespan, AI summary metadata, DEFT/BackBox/Kodachi/Pentoo distros

### P0 (Next)
- Further frontend modularization (extract all pages)
- MFA authentication
- Email notifications on scan completion

### P1 (High)
- Team collaboration features
- Custom vulnerability database
- Export multiple scans as single ZIP

### P2 (Medium)
- Dark web monitoring
- Compliance framework mapping
- Mobile-responsive improvements

## Key Files
- `/app/frontend/src/App.js` - Main React app (modular imports)
- `/app/backend/server.py` - All API endpoints
- `/app/backend/scanner.py` - Network scanner + Shodan
- `/app/memory/test_credentials.md` - Test credentials
