# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform synthesizing best elements from leading cybersecurity tools (KaliGPT inspiration) with Claude Sonnet 4.5 for intelligent assistance.

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
  - Live DNS lookups using `dnspython` (A, AAAA, MX, NS, TXT, CNAME, SOA records)
  - Real WHOIS queries using `python-whois` (registrar, dates, nameservers)
  - Async port scanning using Python sockets (20 common ports)
  - OS detection based on open port signatures
  - Automatic vulnerability analysis based on exposed ports:
    - CRITICAL: Exposed MongoDB, Redis
    - HIGH: Exposed Telnet, RDP, MySQL
    - MEDIUM: FTP, missing HTTPS, missing SPF
- Removed ~70 lines of dead mock code
- Added proper JWT_SECRET validation (fails fast if not set)
- Added `mocked: true` flag to network scan results

### Backend (FastAPI + MongoDB)
- ✅ User authentication (register, login, JWT tokens)
- ✅ AI chat endpoint with Claude Sonnet 4.5 (Emergent LLM Key)
- ✅ **Real** reconnaissance scanning (DNS, WHOIS, ports, vulns)
- ✅ **Real** vulnerability assessment based on port scan
- ✅ Network analysis (MOCKED - requires elevated privileges)
- ✅ Scan management (create, list, get, delete)
- ✅ Dashboard statistics
- ✅ Report generation
- ✅ Activity logging

### Frontend (React + Tailwind + ShadcnUI)
- ✅ Login/Register pages
- ✅ Dashboard with metrics and quick actions
- ✅ Reconnaissance module with **real** scan results (IP, DNS, WHOIS, ports, vulns)
- ✅ Vulnerability assessment page
- ✅ Network analysis page
- ✅ AI Assistant chat interface
- ✅ Terminal interface with AI integration
- ✅ Reports page (select scans, generate reports)
- ✅ Settings page (theme toggle)
- ✅ Collapsible sidebar navigation

## Test Results (Sep 2026)
- **Backend: 100%** - 19/19 pytest tests passed
- **Frontend: 100%** - All Playwright E2E flows passed
- Test suite at `/app/backend/tests/backend_test.py`

## Prioritized Backlog

### P0 (Critical - Next Sprint)
- Shodan API integration (waiting for user API key)
- Export reports to PDF format
- MFA authentication

### P1 (High Priority)
- Real-time scan progress indicators
- Collaborative team features
- Scan scheduling/automation
- Frontend code refactoring (split App.js into components)

### P2 (Medium Priority)
- Custom vulnerability database
- API key management for 3rd party services
- Advanced reporting templates
- Notification system (email alerts)
- Dynamic dashboard stats (active_scans, vulnerability trends)

### P3 (Nice to Have)
- Mobile app version
- Dark web monitoring integration
- Compliance framework mapping (PCI-DSS, OWASP)
- AI-powered remediation suggestions

## Technical Architecture
```
Frontend (React) -> Backend (FastAPI) -> MongoDB
                       |
                       v
            Claude Sonnet 4.5 (Emergent LLM Key)
                       |
                       v
            Real Network Scanner (DNS, WHOIS, Ports)
```

## Key Files
- `/app/backend/server.py` - API endpoints, auth, AI integration
- `/app/backend/scanner.py` - Real network scanner module
- `/app/frontend/src/App.js` - All React components
- `/app/memory/test_credentials.md` - Test user credentials

## Known Limitations
1. Network analysis is simulated (requires root privileges for packet capture)
2. Frontend in single App.js file (Babel plugin bug workaround)
3. No pagination on list endpoints
4. Scan runs synchronously (may timeout for large targets)
