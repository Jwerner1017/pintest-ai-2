# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform synthesizing best elements from leading cybersecurity tools with Claude Sonnet 4.5 for intelligent assistance and Shodan for internet-wide device intelligence.

## User Personas
1. **Security Professional** - Full-time pentester needing efficient workflow
2. **Ethical Hacker** - Bug bounty hunter requiring quick reconnaissance
3. **Security Student** - Learning cybersecurity concepts with AI guidance
4. **IT Administrator** - Running security assessments on company infrastructure

## Core Requirements (Static)
- JWT-based authentication with role-based access
- Dark theme default (light mode available)
- Hybrid UI: Visual dashboard + CLI terminal
- AI assistant powered by Claude Sonnet 4.5
- Modular architecture for scan types

## What's Been Implemented

### v1.0 - Initial MVP (Feb 2026)
- JWT-based authentication system
- Basic UI with dark theme
- Mocked scan endpoints
- AI chat with Claude Sonnet 4.5

### v1.1 - Real Scanner Implementation (Sep 2026)
- **REAL Network Scanner** replacing all mock data:
  - Live DNS lookups using `dnspython`
  - Real WHOIS queries using `python-whois`
  - Async port scanning using Python sockets
  - OS detection based on open port signatures
  - Automatic vulnerability analysis

### v1.2 - Shodan Integration (Sep 2026)
- **Shodan OSINT Integration**:
  - Organization, ISP, ASN identification
  - Geolocation (city, country)
  - Service banner detection with versions (OpenSSH 6.6.1p1, Apache 2.4.7, etc.)
  - Real CVE detection from Shodan's vulnerability database
  - Merged port/service data from Shodan and local scans
  - Beautiful UI display with cyan "OSINT" badges

### Backend (FastAPI + MongoDB)
- ✅ User authentication (register, login, JWT tokens)
- ✅ AI chat endpoint with Claude Sonnet 4.5 (Emergent LLM Key)
- ✅ **Real** reconnaissance scanning (DNS, WHOIS, ports, vulns)
- ✅ **Shodan** integration for OSINT data
- ✅ **Real** vulnerability assessment with CVE detection
- ✅ Network analysis (MOCKED - requires elevated privileges)
- ✅ Scan management (create, list, get, delete)
- ✅ Dashboard statistics
- ✅ Report generation
- ✅ Activity logging

### Frontend (React + Tailwind + ShadcnUI)
- ✅ Login/Register pages
- ✅ Dashboard with metrics and quick actions
- ✅ Reconnaissance module with **real** scan results
- ✅ **Shodan Intelligence** display (org, ISP, ASN, location, services, CVEs)
- ✅ Vulnerability assessment page
- ✅ Network analysis page
- ✅ AI Assistant chat interface
- ✅ Terminal interface with AI integration
- ✅ Reports page (select scans, generate reports)
- ✅ Settings page (theme toggle)
- ✅ Collapsible sidebar navigation

## Test Results
- **Backend: 100%** - All API endpoints tested
- **Frontend: 100%** - All E2E flows passed
- **Shodan: Verified** - Returns real org, ISP, ASN, services, CVEs

## Prioritized Backlog

### P0 (Critical - Next Sprint)
- Export reports to PDF format
- MFA authentication

### P1 (High Priority)
- Real-time scan progress indicators
- Collaborative team features
- Scan scheduling/automation
- Frontend code refactoring (split App.js into components)

### P2 (Medium Priority)
- Custom vulnerability database
- API key management UI for 3rd party services
- Advanced reporting templates
- Notification system (email alerts)
- Dynamic dashboard stats

### P3 (Nice to Have)
- Mobile app version
- Dark web monitoring integration
- Compliance framework mapping (PCI-DSS, OWASP)
- AI-powered remediation suggestions

## Technical Architecture
```
Frontend (React) -> Backend (FastAPI) -> MongoDB
                       |
                       +-> Claude Sonnet 4.5 (Emergent LLM Key)
                       |
                       +-> Real Network Scanner (DNS, WHOIS, Ports)
                       |
                       +-> Shodan API (OSINT, CVEs, Services)
```

## Key Files
- `/app/backend/server.py` - API endpoints, auth, AI integration
- `/app/backend/scanner.py` - Real network scanner + Shodan integration
- `/app/frontend/src/App.js` - All React components
- `/app/memory/test_credentials.md` - Test user credentials

## Known Limitations
1. Network analysis is simulated (requires root privileges for packet capture)
2. Frontend in single App.js file (Babel plugin bug workaround)
3. No pagination on list endpoints
4. Scan runs synchronously (may timeout for large targets)
