"""
HoneyAPI Role A — Full Test Suite
Tests against live uvicorn server at localhost:8000.
Run from HoneyAPI/ folder: python run_tests.py [admin_password] [analyst_password] [viewer_password]
"""
import json
import sqlite3
import sys
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8000"

# Passwords: pass as CLI args or set in DB_PATH / .env
# python run_tests.py AdminPass AnalystPass ViewerPass
ADMIN_PW  = sys.argv[1] if len(sys.argv) > 1 else input("Admin password: ")
ANALYST_PW = sys.argv[2] if len(sys.argv) > 2 else input("Analyst password: ")
VIEWER_PW  = sys.argv[3] if len(sys.argv) > 3 else input("Viewer password: ")

DB_PATH = str(Path(__file__).parent / "honeyapi.db")

PASS = "[PASS]"
FAIL = "[FAIL]"
results: list[bool] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    results.append(condition)
    suffix = f" -- {detail}" if detail else ""
    print(f"  {PASS if condition else FAIL} {label}{suffix}", flush=True)


def section(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}", flush=True)


def login(username: str, password: str) -> tuple[httpx.Client, httpx.Response]:
    s = httpx.Client(follow_redirects=False)
    r = s.post(f"{BASE}/console/login", json={"username": username, "password": password})
    csrf = r.json().get("csrf_token", "") if r.status_code == 200 else ""
    s.headers.update({"X-CSRF-Token": csrf})
    return s, r


# ── 1. Health ──────────────────────────────────────────────────
section("1. Health Check")
r = httpx.get(f"{BASE}/health")
check("GET /health -> 200", r.status_code == 200)
check("Returns {status: ok}", r.json() == {"status": "ok"})

# ── 2. Decoy Endpoints ─────────────────────────────────────────
section("2. Public Decoy Endpoints (no auth required)")
anon = httpx.Client(follow_redirects=False)
for path, method, expected in [
    ("/.env",            "GET",  200),
    ("/admin",           "GET",  401),
    ("/wp-login.php",    "GET",  200),
    ("/wp-login.php",    "POST", 401),
    ("/api/v1/users",    "GET",  200),
    ("/api/v1/users/42", "GET",  200),
    ("/api/v1/login",    "POST", 401),
    ("/backup.zip",      "GET",  200),
]:
    r = anon.request(method, f"{BASE}{path}")
    check(f"{method} {path} -> {expected}", r.status_code == expected)

# ── 3. Payload Too Large ───────────────────────────────────────
section("3. Payload Too Large (T-final)")
big = b"x" * (1024 * 1024 + 1)
r = anon.post(f"{BASE}/wp-login.php", content=big, headers={"content-length": str(len(big))})
check("Oversized body -> 413", r.status_code == 413)
check("Code: PAYLOAD_TOO_LARGE", r.json().get("error", {}).get("code") == "PAYLOAD_TOO_LARGE")

# ── 4. Unauthenticated access ──────────────────────────────────
section("4. Unauthenticated Access -> 401")
for path in ["/api/requests", "/api/fingerprints", "/api/stats", "/api/alerts", "/api/admin/audit"]:
    r = anon.get(f"{BASE}{path}")
    check(f"GET {path} -> 401", r.status_code == 401)
    check("Code: AUTH_REQUIRED", r.json().get("error", {}).get("code") == "AUTH_REQUIRED")

# ── 5. Login / Logout / Me ─────────────────────────────────────
section("5. Login / Logout / Me")
admin_s, r = login("admin", ADMIN_PW)
check("Admin login -> 200", r.status_code == 200)
check("Returns csrf_token", "csrf_token" in r.json())
check("Returns role=admin", r.json().get("role") == "admin")

r2 = anon.post(f"{BASE}/console/login", json={"username": "admin", "password": "wrong"})
check("Wrong password -> 401", r2.status_code == 401)
check("Generic message", "Invalid credentials" in r2.json().get("error", {}).get("message", ""))

r3 = admin_s.get(f"{BASE}/console/me")
check("GET /console/me returns current user", r3.json().get("role") == "admin")

r4 = admin_s.post(f"{BASE}/console/logout")
check("Logout -> 200", r4.status_code == 200)
r5 = admin_s.get(f"{BASE}/api/requests")
check("After logout /api/requests -> 401", r5.status_code == 401)
admin_s, _ = login("admin", ADMIN_PW)  # re-login for remaining tests

# ── 6. CSRF Protection ─────────────────────────────────────────
section("6. CSRF Protection")
no_csrf = httpx.Client(cookies=admin_s.cookies, follow_redirects=False)
r = no_csrf.post(f"{BASE}/console/logout")  # no X-CSRF-Token header
check("POST /console/logout without CSRF -> 403", r.status_code == 403)
check("Code: FORBIDDEN", r.json().get("error", {}).get("code") == "FORBIDDEN")

# ── 7. RBAC ───────────────────────────────────────────────────
section("7. RBAC -- Role Enforcement")
viewer_s, _ = login("viewer", VIEWER_PW)
check("Viewer -> GET /api/admin/audit -> 403", viewer_s.get(f"{BASE}/api/admin/audit").status_code == 403)
check("Viewer -> GET /api/requests/:id -> 403", viewer_s.get(f"{BASE}/api/requests/fake-id").status_code == 403)

analyst_s, _ = login("analyst", ANALYST_PW)
check("Analyst -> GET /api/admin/audit -> 403", analyst_s.get(f"{BASE}/api/admin/audit").status_code == 403)
check("Analyst -> GET /api/requests -> 200", analyst_s.get(f"{BASE}/api/requests").status_code == 200)

# ── 8. Viewer src_ip Redaction (T6) ───────────────────────────
section("8. Viewer src_ip Redaction (T6)")
anon.get(f"{BASE}/.env")  # ensure a log entry
viewer_s2, _ = login("viewer", VIEWER_PW)
items = viewer_s2.get(f"{BASE}/api/requests").json().get("items", [])
if items:
    check("src_ip is [REDACTED] for viewer", all(i.get("src_ip") == "[REDACTED]" for i in items))
else:
    check("src_ip redaction (no items)", True, "skipped")

# ── 9. Requests logged to SQLite ──────────────────────────────
section("9. Requests Logged to SQLite")
conn = sqlite3.connect(DB_PATH)
rows = conn.execute("SELECT count(*) FROM requests_log").fetchone()[0]
check("requests_log has entries", rows > 0, f"{rows} rows")
conn.close()

# ── 10. Login Lockout ─────────────────────────────────────────
section("10. Login Lockout (5 failed -> RATE_LIMITED)")
conn = sqlite3.connect(DB_PATH)
conn.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE username='analyst'")
conn.commit(); conn.close()
lock_s = httpx.Client(follow_redirects=False)
codes = [lock_s.post(f"{BASE}/console/login", json={"username": "analyst", "password": "wrong"}).status_code for _ in range(6)]
check("Attempts 1-4 -> 401", all(c == 401 for c in codes[:4]), str(codes[:4]))
check("Attempt 5 -> 429 RATE_LIMITED", codes[4] == 429, str(codes[4]))
check("Attempt 6 -> 429 RATE_LIMITED", codes[5] == 429, str(codes[5]))

# ── 11. Admin Rule Update & Audit Trail ───────────────────────
section("11. Admin Rule Update & Audit Trail")
admin_s, _ = login("admin", ADMIN_PW)
old_v = admin_s.get(f"{BASE}/api/admin/rules/rate_spike").json().get("version")
r = admin_s.put(f"{BASE}/api/admin/rules/rate_spike",
    json={"enabled": True, "threshold": 5.0, "window_s": 10, "confirm": True})
check("PUT /api/admin/rules/rate_spike -> 200", r.status_code == 200)
check("Version bumped", r.json().get("version") != old_v, f"{old_v} -> {r.json().get('version')}")
r2 = admin_s.put(f"{BASE}/api/admin/rules/rate_spike",
    json={"enabled": True, "threshold": 5.0, "window_s": 10, "confirm": False})
check("PUT without confirm=True -> 400", r2.status_code == 400)
audit_items = admin_s.get(f"{BASE}/api/admin/audit").json().get("items", [])
updates = [x for x in audit_items if x.get("action") == "RULE_UPDATE"]
check("RULE_UPDATE in audit log", len(updates) > 0)
if updates:
    detail = json.loads(updates[0].get("detail_json", "{}"))
    check("Audit log has old+new values", "old" in detail and "new" in detail)

# ── 12. Append-Only Audit (T-final) ───────────────────────────
section("12. Append-Only Audit Log (T-final)")
conn = sqlite3.connect(DB_PATH)
for op, sql in [("DELETE", "DELETE FROM audit_events"), ("UPDATE", "UPDATE audit_events SET actor='x'")]:
    try:
        conn.execute(sql); conn.commit()
        check(f"{op} audit_events blocked", False, "trigger missing!")
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        check(f"{op} audit_events -> trigger blocks it", "audit is append-only" in str(e))
conn.close()

# ── 13. Fixture Replay ────────────────────────────────────────
section("13. Fixture Replay (/api/replay)")
admin_s, _ = login("admin", ADMIN_PW)
jsonl = (
    b'{"method":"GET","path":"/api/v1/users","sim_ip":"10.0.0.5","sim_ua":"sqlmap/1.7"}\n'
    b'{"method":"POST","path":"/wp-login.php","sim_ip":"10.0.0.6","body":"password=secret"}\n'
)
r = admin_s.post(f"{BASE}/api/replay", files={"file": ("s.jsonl", jsonl, "text/plain")})
check("Valid .jsonl replay -> 200", r.status_code == 200)
check("Replayed count = 2", r.json().get("replayed") == 2)
r = admin_s.post(f"{BASE}/api/replay", files={"file": ("s.txt", b"hello", "text/plain")})
check(".txt file -> 400", r.status_code == 400)
r = admin_s.post(f"{BASE}/api/replay", files={"file": ("big.jsonl", b"x" * (1024 * 1024 + 1), "text/plain")})
check("Oversized .jsonl -> 413", r.status_code == 413)
r = admin_s.post(f"{BASE}/api/replay", files={"file": ("bad.jsonl", b"not json\n", "text/plain")})
check("Invalid JSON line -> 400", r.status_code == 400)

# ── 14. Stats & Fingerprints ──────────────────────────────────
section("14. Stats & Fingerprints")
admin_s, _ = login("admin", ADMIN_PW)
r = admin_s.get(f"{BASE}/api/stats")
check("GET /api/stats -> 200", r.status_code == 200)
check("Has total_requests", "total_requests" in r.json())
r = admin_s.get(f"{BASE}/api/fingerprints")
check("GET /api/fingerprints -> 200", r.status_code == 200)
check("Has items list", "items" in r.json())

# ── Summary ───────────────────────────────────────────────────
section("SUMMARY")
total, passed = len(results), sum(results)
print(f"\n  Total: {total}  |  Passed: {passed}  |  Failed: {total - passed}")
print("\n  All tests passed!\n" if total == passed else f"\n  {total - passed} test(s) failed\n")
sys.exit(0 if total == passed else 1)
