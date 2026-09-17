# Existing JWT Authentication Regression Playbook

This application uses the existing Bearer JWT flow. The current hardening change only removes the fallback secret.

1. Confirm `JWT_SECRET` is present in `/app/backend/.env` without printing its value.
2. Restart the backend and verify startup succeeds; unset `JWT_SECRET` in an isolated import check and confirm it fails fast.
3. Register a temporary user and confirm an access token is returned.
4. Call `GET /api/auth/me` with that Bearer token and confirm the same user is returned.
5. Confirm a missing, malformed, and expired token returns 401/403.
6. Confirm existing MFA token encode/decode regression tests still pass.