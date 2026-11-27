# HoneyAPI JSON API Reference

All state-changing `/console` and `/api` requests require:
- Valid `honeyapi_session` HttpOnly cookie
- `X-CSRF-Token` header matching the session's `csrf_token`

All errors return:
```json
{"error": {"code": "ERROR_CODE", "message": "..."}}
```
Stable codes: `AUTH_REQUIRED`, `FORBIDDEN`, `VALIDATION_FAILED`, `PAYLOAD_TOO_LARGE`, `RATE_LIMITED`, `NOT_FOUND`, `INTERNAL`.

## Auth (`/console`)
- `POST /console/login` — Body: `{"username", "password"}`. Sets `honeyapi_session` cookie, returns `{username, role, csrf_token}`.
- `POST /console/logout` — Revokes session and clears cookie.
- `GET /console/me` — Returns `{username, role, csrf_token}`.

## Decoy Endpoints (Public, No Auth)
- `GET/POST /wp-login.php`
- `GET /admin`
- `GET /.env`
- `GET /api/v1/users`
- `GET /api/v1/users/{id}`
- `POST /api/v1/login`
- `GET /backup.zip`

## Data & Telemetry (`/api`, Analyst + Admin; Viewer gets redacted subset)
- `GET /api/requests?fp=&rule=&severity=&from=&to=&page=`
- `GET /api/requests/{request_id}`
- `GET /api/fingerprints`
- `GET /api/fingerprints/{fingerprint_id}/timeline`
- `GET /api/alerts?status=`
- `POST /api/alerts/{alert_id}/ack` — Body: `{"confirm": true}`
- `GET /api/stats`
- `POST /api/replay` — Multipart `.jsonl` upload (max 1 MB).

## Admin (`/api/admin`, Admin Only)
- `GET /api/admin/rules/{rule_id}`
- `PUT /api/admin/rules/{rule_id}` — Body: `{"enabled", "threshold", "window_s", "confirm": true}`
- `GET /api/admin/audit?page=`
- `POST /api/admin/users` — Body: `{"username", "password", "role"}`
- `DELETE /api/admin/users/{user_id}`
