import os
import secrets
import time
import uuid
from pathlib import Path

from app.config import DB_PATH
from app.db.repo import db_session, fetch_one, init_db

try:
    from argon2 import PasswordHasher

    _ph = PasswordHasher()

    def _hash_password(password: str) -> str:
        return _ph.hash(password)
except ImportError:
    import bcrypt

    def _hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def seed_db(db_path: Path | str = DB_PATH) -> dict[str, str]:
    """Initialize schema and seed default users, decoys, and rule_config.

    Returns a dict of {username: plaintext_password} for newly created users
    (empty if users already existed).
    """
    init_db(db_path)
    now = time.time()
    generated_passwords: dict[str, str] = {}

    default_users = [
        ("admin", "admin", os.getenv("HONEYAPI_ADMIN_PASSWORD")),
        ("analyst", "analyst", os.getenv("HONEYAPI_ANALYST_PASSWORD")),
        ("viewer", "viewer", os.getenv("HONEYAPI_VIEWER_PASSWORD")),
    ]

    default_decoys = [
        ("decoy-wp-login-get", "GET", "/wp-login.php", '{"status": "ok", "form": "wp-login"}', 200),
        ("decoy-wp-login-post", "POST", "/wp-login.php", '{"error": "invalid_credentials"}', 401),
        ("decoy-admin", "GET", "/admin", '{"status": "login_required"}', 401),
        ("decoy-env", "GET", "/.env", "APP_ENV=production\nDB_HOST=10.0.0.12\n", 200),
        ("decoy-users-list", "GET", "/api/v1/users", '{"users": []}', 200),
        ("decoy-users-id", "GET", "/api/v1/users/{id}", '{"user": {}}', 200),
        ("decoy-api-login", "POST", "/api/v1/login", '{"error": "unauthorized"}', 401),
        ("decoy-backup", "GET", "/backup.zip", "PK\x03\x04SYNTHETIC_BACKUP", 200),
    ]

    default_rules = [
        ("scanner", 1, 4.0, 60, "1.0"),
        ("cred_stuffing", 1, 8.0, 30, "1.0"),
        ("enumeration", 1, 5.0, 60, "1.0"),
        ("injection", 1, 1.0, 60, "1.0"),
        ("rate_spike", 1, 10.0, 10, "1.0"),
    ]

    with db_session(db_path) as conn:
        for username, role, env_pw in default_users:
            existing = fetch_one(conn, "SELECT id FROM users WHERE username = ?", (username,))
            if existing is None:
                pw = env_pw or secrets.token_urlsafe(14)
                conn.execute(
                    """
                    INSERT INTO users (id, username, pw_hash, role, failed_logins, locked_until, created_at)
                    VALUES (?, ?, ?, ?, 0, NULL, ?)
                    """,
                    (str(uuid.uuid4()), username, _hash_password(pw), role, now),
                )
                if env_pw is None:
                    generated_passwords[username] = pw

        for decoy_id, method, path_pattern, template, status_code in default_decoys:
            conn.execute(
                """
                INSERT OR IGNORE INTO decoy_endpoints (id, method, path_pattern, response_template, status_code, enabled)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (decoy_id, method, path_pattern, template, status_code),
            )

        for rule_id, enabled, threshold, window_s, version in default_rules:
            conn.execute(
                """
                INSERT OR IGNORE INTO rule_config (rule_id, enabled, threshold, window_s, version, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, 'seed', ?)
                """,
                (rule_id, enabled, threshold, window_s, version, now),
            )

    return generated_passwords


if __name__ == "__main__":
    creds = seed_db()
    if creds:
        print("Seeded users (save these passwords, they will not be shown again):")
        for user, pw in creds.items():
            print(f"  {user}: {pw}")
    else:
        print("Database already seeded.")
