# PentestAI Platform - Product Requirements Document

## Overview
AI-enhanced penetration testing platform with Claude Sonnet 4.5 AI assistant, Shodan OSINT integration, bulk scanning, and automated scheduling.

## What's Been Implemented

### v1.0 - Initial MVP (Feb 2026)
- JWT-based authentication
- Basic UI with dark theme
- AI chat with Claude Sonnet 4.5

### v1.1 - Real Scanner (Sep 2026)
- Real network scanning (DNS, WHOIS, Ports)
- Vulnerability analysis based on open ports

### v1.2 - Shodan Integration (Sep 2026)
- Organization, ISP, ASN identification
- Service banner detection with versions
- Real CVE detection from Shodan

### v1.3 - Bulk Scan, Scheduling & CVE Details (Sep 2026)
- **Bulk Scanning**: Scan multiple targets (up to 256) or CIDR ranges (/24 max)
- **Scheduled Scans**: Daily, weekly, monthly automatic scans with manual trigger
- **CVE Details**: Click any CVE to see NVD details (description, CVSS, affected products, references)
- CVSS v2 to severity derivation when v3 not available
- 24-hour caching for CVE lookups

## Features Summary

### Backend (FastAPI + MongoDB)
- ✅ JWT Authentication
- ✅ AI Chat (Claude Sonnet 4.5)
- ✅ Real Reconnaissance (DNS, WHOIS, Ports)
- ✅ Shodan OSINT Integration
- ✅ Bulk Scanning with CIDR support
- ✅ Scheduled Scans (daily/weekly/monthly)
- ✅ CVE Details from NVD with caching
- ✅ Report Generation

### Frontend (React + Tailwind + ShadcnUI)
- ✅ Dashboard with metrics
- ✅ Reconnaissance page with Shodan data
- ✅ Bulk Scan page (targets + CIDR)
- ✅ Scheduled Scans page
- ✅ CVE Details modal
- ✅ AI Assistant chat
- ✅ Terminal interface
- ✅ Reports page
- ✅ Settings page

## API Endpoints

### Auth
- POST /api/auth/register
- POST /api/auth/login

### Scans
- POST /api/scans
- GET /api/scans
- GET /api/scans/{id}
- DELETE /api/scans/{id}

### Bulk Scans
- POST /api/bulk-scans
- GET /api/bulk-scans
- GET /api/bulk-scans/{id}

### Scheduled Scans
- POST /api/scheduled-scans
- GET /api/scheduled-scans
- GET /api/scheduled-scans/{id}
- PATCH /api/scheduled-scans/{id}?enabled=true/false
- DELETE /api/scheduled-scans/{id}
- POST /api/scheduled-scans/{id}/run

### CVE
- GET /api/cve/{cve_id}

### Reports
- POST /api/reports
- GET /api/reports

## Test Results (Sep 2026)
- Backend: 95% (20/21 tests passed)
- Frontend: 100% (all E2E flows work)

## Known Limitations
1. Network analysis is simulated (requires root privileges)
2. Frontend in single App.js file (1824 lines)
3. Scheduled scans require manual trigger (no background scheduler)
4. NVD API may rate limit CVE lookups

## Prioritized Backlog

### P0 (Next)
- Background scheduler for automatic scan execution (APScheduler)
- PDF report export
- MFA authentication

### P1 (High)
- Frontend modularization
- Real-time scan progress with WebSocket
- Concurrent bulk scanning with semaphore

### P2 (Medium)
- Custom vulnerability database
- Email notifications
- Team collaboration features

## Key Files
- `/app/backend/server.py` - All API endpoints
- `/app/backend/scanner.py` - Network scanner + Shodan
- `/app/frontend/src/App.js` - All React components
- `/app/memory/test_credentials.md` - Test credentials
