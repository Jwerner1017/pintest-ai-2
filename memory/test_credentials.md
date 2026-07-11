# PentestAI Test Credentials

Authentication uses dynamic registration. Create a new test user via:

```
POST /api/auth/register
{ "email": "test@example.com", "password": "password123", "username": "test" }
```

## Demo Account
Created via `/api/auth/register`. No seeded admin account.

- **Email**: testuser@example.com
- **Password**: password123
- **Username**: testuser
- **Role**: tester (default)

## MFA Test Flow
1. Register or login to get JWT.
2. POST `/api/auth/mfa/setup` (Bearer JWT) → returns `secret`, `otpauth_uri`, `qr_code`.
3. Generate TOTP code: `python3 -c "import pyotp;print(pyotp.TOTP('<secret>').now())"`.
4. POST `/api/auth/mfa/enable` with `{"code":"<6-digits>"}` → enables MFA.
5. Subsequent `/api/auth/login` returns `{ mfa_required: true, mfa_token }`.
6. POST `/api/auth/login/mfa` with `{ mfa_token, code }` → returns `access_token`.
