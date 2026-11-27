# HoneyAPI — Role A Handoff & Integration Guide

Hi team! All **Role A (Backend, Data, Auth, Decoy Routes, Pipeline, Admin, Hardening)** tasks (**A1–A10**) are done. Here is a simple, complete guide to what has been built and how **B, C, and D** can plug into it.

---

## 1. Git Branches
All Role A work is split into small commits across these branches (each built on top of the previous one):
- `feature/a-db-schema` (A1, A2)
- `feature/a-auth-rbac` (A3, A4)
- `feature/a-decoy-routes` (A5, A6)
- `feature/a-admin-audit` (A7, A8)
- `feature/a-ratelimit-hardening` (A9, A10 — **latest, has everything**)

---

## 2. How to Run Locally
```bash
python -m venv venv
venv\Scripts\activate        # Windows (or source venv/bin/activate on Mac/Linux)
pip install -r requirements.txt
uvicorn app.main:app --reload
```
- On startup, `app/main.py` automatically runs `seed_db()`, which creates `honeyapi.db` (SQLite), creates all 11 tables + triggers, and seeds 3 users (`admin`, `analyst`, `viewer`), 8 decoy endpoints, and 5 default rules.
- If `HONEYAPI_ADMIN_PASSWORD` / `HONEYAPI_ANALYST_PASSWORD` / `HONEYAPI_VIEWER_PASSWORD` are not set in `.env`, random passwords are generated and printed once in the terminal.
- **Note:** Password hashing uses `argon2` by default and automatically falls back to `bcrypt` if `argon2-cffi` is missing.

---

## 3. What Was Built

### Database (`app/db/`)
- `schema.sql`: 11 SQLite tables (`users`, `sessions`, `decoy_endpoints`, `synthetic_records`, `requests_log`, `fingerprints`, `rule_results`, `decisions`, `rule_config`, `alerts`, `audit_events`).
- **Append-only audit:** `audit_events` has SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers that block any modification (`RAISE(ABORT, 'audit is append-only')`).
- `repo.py`: Parameterized `sqlite3` helpers (`db_session`, `fetch_one`, `fetch_all`, `execute`, `insert_audit_event`). No raw string-formatted SQL anywhere.
- `seed.py`: Seeds users, default decoy routes, and default `rule_config` rows (`scanner`, `cred_stuffing`, `enumeration`, `injection`, `rate_spike`).

### Auth, RBAC & Security (`app/security/`, `app/api/auth.py`)
- **Login/Logout/Me:** `POST /console/login`, `POST /console/logout`, `GET /console/me`.
- **Sessions:** `HttpOnly`, `SameSite=Lax` cookie (`honeyapi_session`) with 30-minute sliding idle timeout.
- **Lockout:** 5 failed logins lock the account for 60 seconds.
- **CSRF:** All state-changing requests (`POST`, `PUT`, `DELETE`, `PATCH`) must send the `X-CSRF-Token` header (returned by `/console/login` and `/console/me`).
- **RBAC:** `require_role("admin", ...)` enforces roles server-side and logs `AUTHZ_DENIED` to `audit_events` on unauthorized access.
- **Redaction (`redaction.py`):** Masks `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-CSRF-Token`, `Bearer ...`, and `password=` / `token=` / `secret=` values with `[REDACTED]`.
- **Rate Limiting (`ratelimit.py`):** Sliding-window in-memory rate limiter (used on `/api/replay`, ready for any other sensitive route).
- **Safe Errors (`errors.py`):** Every error returns `{"error": {"code": "...", "message": "..."}}` with stable codes (`AUTH_REQUIRED`, `FORBIDDEN`, `VALIDATION_FAILED`, `PAYLOAD_TOO_LARGE`, `RATE_LIMITED`, `NOT_FOUND`, `INTERNAL`). Stack traces are never exposed.

### Decoy Routes & Pipeline (`app/api/decoy.py`, `app/pipeline.py`)
- **Public Decoys (no auth):** `/wp-login.php` (GET/POST), `/admin` (GET), `/.env` (GET), `/api/v1/users` (GET), `/api/v1/users/{id}` (GET), `/api/v1/login` (POST), `/backup.zip` (GET).
- **Body Cap:** Requests larger than 1 MB (`MAX_BODY_BYTES`) are rejected with `413 PAYLOAD_TOO_LARGE`.
- **Pipeline (`process_request()`):** Currently normalizes, redacts secrets, creates/updates a stub fingerprint, logs to `requests_log`, and writes a stub `info` decision.

### Data, Admin & Replay APIs (`app/api/data.py`, `app/api/admin.py`, `app/api/replay.py`)
- Full endpoint list is in `docs/api.md`.
- `viewer` role automatically gets `src_ip` redacted as `[REDACTED]` on `/api/requests`.
- `PUT /api/admin/rules/{rule_id}` requires `"confirm": true`, bumps `version`, and logs old + new values to `audit_events`.
- `POST /api/replay` accepts `.jsonl` files (max 1 MB), validates every line, maps `sim_ip` and `sim_ua` to headers, and runs each line through `process_request()`.

---

## 4. Notes for Each Teammate

### For B (Security Engine & Fixtures) — Most Important
1. **Plug into `app/pipeline.py`:**
   - Right now `process_request()` in `app/pipeline.py` uses `_normalize_fallback()` and a stub fingerprint/decision.
   - Once your `app/engine/` modules (`normalize.py`, `fingerprint.py`, `rules.py`, `scoring.py`, `alerts.py`, `timeline.py`, `synthetic.py`) are ready, we will replace the stub calls in `process_request()` with your pure functions and save `rule_results` and `alerts` into SQLite.
2. **Rule Config:**
   - `rule_config` in SQLite already has rows for `scanner`, `cred_stuffing`, `enumeration`, `injection`, and `rate_spike` with `enabled`, `threshold`, `window_s`, and `version`.
3. **Fixture Format for `/api/replay`:**
   - Each line in `.jsonl` should be a JSON object with `method` (e.g. `"GET"`), `path` (e.g. `"/api/v1/users/1"`), and optional `sim_ip`, `sim_ua`, `headers`, `query`, `body`.
4. **Redaction:**
   - Check `app/security/redaction.py` so your `normalize.py` uses the exact same redaction rules.

### For C (Frontend & Export)
- You own `app/api/console.py`, `app/api/export.py`, `app/templates/*`, and `app/static/*`.
- All JSON APIs are ready under `/api/*` (see `docs/api.md`).
- Remember to include `X-CSRF-Token` on all `POST`/`PUT`/`DELETE` fetch calls from the UI.

### For D (Testing & QA)
- You can test against `app/main.py` using FastAPI `TestClient` with a temporary SQLite DB (`HONEYAPI_DB_PATH`).
- All error codes, RBAC denials, `audit_events` append-only triggers, and `/api/replay` validation are ready to test.
