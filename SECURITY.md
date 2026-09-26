# Security model

unmask aggregates personal data, so the deployment itself is a high-value target.

## Data at rest
- Entity values and attributes and target values are encrypted with Fernet before insert
  (`app/crypto.py`, `EncryptedText` / `EncryptedJSON` column types).
- Equality lookups use an HMAC-SHA256 blind index with its own key.
- Keys are loaded from the application service's environment only and must be managed
  separately from the database (see README > Key management).

## Authentication & sessions
- Argon2id password hashes; unknown emails are verified against a dummy hash to avoid
  account enumeration by timing.
- Login rate limiting per account (5 failures / 15 min) and per IP (20 / 15 min), backed by
  Redis.
- Signed, `HttpOnly`, `SameSite=Lax` session cookies (`Secure` in production); the session
  is cleared on login.
- CSRF tokens on every state-changing request (form field or `X-CSRF-Token` header for htmx).
- Local-only post-login redirects.

## HTTP hardening
- Strict CSP (no inline scripts), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`
  (outbound links never leak case URLs), HSTS in production, `no-store` on private pages.

## Third-party tools
- Invoked only as subprocesses or via HTTP APIs; never imported.
- Installed into a root-owned virtualenv the app user cannot modify.
- Run with a scrubbed environment, a temporary working directory, no shell, `--` before
  user-supplied values, input validation, and a timeout.
- Planned (Phase 2): tool execution in a dedicated worker service with restricted egress.

## Audit
- `access_log` records logins (including failures and lockouts), case creation and views,
  scans, entity confirmations and health checks. Rows keep their data if the case is deleted.

## Reporting a vulnerability
Please report security issues privately to the maintainer rather than opening a public issue.
