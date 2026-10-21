# API v1

A versioned JSON API for scripts and other systems. Schema: `GET /api/v1/openapi.json`
(OpenAPI 3, no key needed). A Python client with no dependencies is in
`clients/python/unmask_client.py`.

## Keys

Create a key on **Account → API keys**. It is shown once, then stored only as a SHA-256
fingerprint; the list shows its prefix (`umk_1a2b3c4d_…`), permissions, last use and expiry
(30, 90 or 365 days). Revoking takes effect immediately. A person can hold ten active keys.

```
curl -H "Authorization: Bearer umk_..." https://unmask.example.org/api/v1/me
```

A key acts as the person who made it: it sees exactly the cases they can see, and stops
working if their account is deactivated or they have not accepted the current terms.

| Permission | Allows |
|---|---|
| `cases:read` | list cases, read a case's targets and scan history, poll a scan |
| `findings:read` | findings, graph, paths and STIX, **for cases with a written analyst assessment** |
| `scans:write` | start a scan (counts against the daily scan limit) |

## Endpoints

| Method | Path | Permission | Returns |
|---|---|---|---|
| GET | `/api/v1/me` | any | the key's owner, name, prefix, permissions, expiry |
| GET | `/api/v1/cases` | `cases:read` | `{"cases": [{id, name, created_at, sample, findings, assessment_written}]}` |
| GET | `/api/v1/cases/{id}` | `cases:read` | targets, authorisation note, the last 20 scans |
| GET | `/api/v1/cases/{id}/findings?include=visible\|confirmed\|all` | `findings:read` | the JSON export format (`unmask-case-export`) |
| GET | `/api/v1/cases/{id}/stix?include=…` | `findings:read` | a STIX 2.1 bundle, TLP:AMBER |
| GET | `/api/v1/cases/{id}/bundle` | `findings:read` | the evidence bundle (ZIP) with its manifest hash in `X-Manifest-SHA256` |
| GET | `/api/v1/cases/{id}/graph` | `findings:read` | findings and links, each link with its evidence |
| GET | `/api/v1/cases/{id}/paths?a=…&b=…` | `findings:read` | the strongest evidence paths between two findings |
| POST | `/api/v1/cases/{id}/scans` | `scans:write` | 202 and the scan (or the one already running) |
| GET | `/api/v1/cases/{id}/scans/{number}` | `cases:read` | that scan's status and progress |

Errors are JSON: `{"error": "…", "status": 403}`.

| Status | Meaning |
|---|---|
| 401 | no key, an unknown key, or a revoked or expired one |
| 403 | the key lacks the permission, or its owner must accept the terms |
| 404 | no such case, or not one the key's owner can see |
| 409 | findings requested for a case without a written assessment |
| 429 | more than 120 requests a minute for this key, or the daily scan limit |

## Rules it follows

- The same visibility as the app; nothing is reachable that the owner could not open.
- Findings leave the platform only with a written assessment, as for exports.
- Every request that reads a case or its findings is in the case's audit log, with the key's
  prefix (`api_export`, `api_view_case`, `run_scan`, …).
- Sample cases can be read but not scanned.

## Compatibility

Within v1, fields are only added, never renamed or removed, and an endpoint's meaning does not
change. Anything that would break a client goes into `/api/v2`, and v1 keeps working alongside
it for at least six months after v2 ships.

## Not yet

Signed outbound webhooks (scan finished, watch-mode changes) and per-key case restrictions are
on the roadmap; today a key sees all of its owner's cases.
