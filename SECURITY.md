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
- One virtualenv per tool; Amass is verified against its published SHA-256 checksum.
- API keys reach tools through a 0600 config file in the throwaway working directory, never
  on the command line (where other processes could read them).
- Tools run on a dedicated worker service, separate from the web tier. Restricting that
  service's egress to the tools' data sources is recommended where the platform allows it.

## Data minimisation
- h8mail breach results never store cleartext passwords or hashes: only that a credential
  was exposed, its kind, and a 12-character keyed HMAC fingerprint for spotting reuse
  (keyed, so it cannot be brute-forced back to the password from a database dump).
- Holehe always runs with `--no-password-recovery`, so lookups never send the subject a
  password-reset email or SMS.

## Audit
- `access_log` records logins (including failures and lockouts), case creation and views,
  scans, entity confirmations and health checks. Rows keep their data if the case is deleted.

## Reporting a vulnerability
Please report security issues privately to the maintainer rather than opening a public issue.
