# HoneyAPI: Deception and Intrusion Telemetry Service

A non-production decoy API that runs on `localhost`, records and fingerprints unauthorized interactions, scores behavior using explainable rules, raises alerts, and exports sanitized telemetry.

## Quick Start

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
# source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Project Structure

- `app/main.py` — FastAPI app factory & router mounting
- `app/config.py` — Settings, paths, limits
- `app/api/` — HTTP routes (auth, decoy, console, data, admin, export)
- `app/security/` — Passwords, CSRF, RBAC, rate limiting, redaction, error handling
- `app/engine/` — Pure-Python detection & scoring engine
- `app/db/` — SQLite schema, parameterized repository, seed script
- `app/templates/` & `app/static/` — Jinja2 + Chart.js UI
- `fixtures/` — Safe sample traffic (JSONL)
- `tests/` — Automated pytest suite
- `docs/` — Architecture/DFD, threat model, guides, test results
