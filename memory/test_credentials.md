# Test Credentials for PentestAI Platform

## Test User Account
- **Email**: tester@example.com
- **Password**: test123456
- **Username**: tester
- **Role**: tester

## API Keys (Backend .env)
- **Shodan API Key**: Configured in `/app/backend/.env`
- **Emergent LLM Key**: Configured for Claude Sonnet 4.5

## Notes
- Created via `/api/auth/register` endpoint
- JWT token expires after 24 hours
- Can be used for all authenticated endpoints
