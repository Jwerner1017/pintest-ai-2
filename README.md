# PentestAI (`pintest-ai-2`)

FastAPI + MongoDB backend, React (CRA + craco) frontend.

Single and bulk scans both call `routers.scans.run_scan_engine`. Bulk defaults to the `fast` preset.

## Environment variables

Templates (names only) are in [`backend/.env.example`](backend/.env.example) and [`frontend/.env.example`](frontend/.env.example). Copy each one to `.env` in the same folder. `.env` files are gitignored, so never commit real values.

### Backend (`backend/.env`)

| Name | Required | Purpose |
|---|---|---|
| `MONGO_URL` | **yes** | MongoDB connection string. The server won't start without it. |
| `DB_NAME` | **yes** | MongoDB database name. The server won't start without it. |
| `JWT_SECRET` | **yes** | Secret used to sign login JWTs. Use a long random value. The server won't start without it. |
| `CORS_ORIGINS` | no | Comma-separated allowed origins (default `*`) |
| `EMERGENT_LLM_KEY` | no | Emergent LLM key for the AI assistant, scan summaries, and remediation. AI features are unavailable without it. |
| `SHODAN_API_KEY` | no | Enables the Shodan lookups |
| `NVD_API_KEY` | no | Raises the NVD CVE API rate limit (5 → 50 requests / 30s) |
| `NVD_ENRICHMENT_DISABLED` | no | `1`/`true` turns off NVD CVE enrichment |
| `PENTESTAI_DISABLE_SCHEDULER` | no | `1`/`true` skips starting the scheduled-scan scheduler |

### Frontend (`frontend/.env`)

| Name | Required | Purpose |
|---|---|---|
| `REACT_APP_BACKEND_URL` | **yes** | Base URL of the backend. The app calls `${REACT_APP_BACKEND_URL}/api/...`. The backend test suites also read it. |
| `ENABLE_HEALTH_CHECK` | no | `true` enables the dev-server health-check plugin (craco) |
| `DISABLE_VISUAL_EDITS` | no | `true` disables the visual-edits dev plugin (craco) |

## Run locally

Backend (Python 3.11):

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
# emergentintegrations comes from Emergent's package index, not PyPI:
pip install -r requirements.txt --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/
cp .env.example .env   # then fill in MONGO_URL, DB_NAME, JWT_SECRET
uvicorn server:app --reload --port 8001
```

Frontend (Node 18+ and Yarn 1):

```bash
cd frontend
cp .env.example .env
yarn install
yarn start
```

## Checks

- CI (`.github/workflows/ci.yml`) installs the backend requirements (minus `emergentintegrations`) and runs `pytest backend/tests/test_app_boots.py`, which imports the app and checks its routes. It needs no database or secrets.
- Most other files in `backend/tests/` are integration tests that call a running deployment through `REACT_APP_BACKEND_URL` and need MongoDB.
