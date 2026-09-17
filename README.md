# PentestAI (`pintest-ai-2`)

FastAPI + MongoDB backend, React frontend.

Single and bulk scans both call `routers.scans.run_scan_engine`. Bulk defaults to the `fast` preset.

Required env: `JWT_SECRET`, `MONGO_URL`, `DB_NAME`.
