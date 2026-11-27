import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("HONEYAPI_DB_PATH", BASE_DIR / "honeyapi.db"))
SCHEMA_PATH = Path(__file__).resolve().parent / "db" / "schema.sql"

SESSION_IDLE_TIMEOUT_S = int(os.getenv("HONEYAPI_SESSION_IDLE_S", "1800"))
MAX_BODY_BYTES = int(os.getenv("HONEYAPI_MAX_BODY_BYTES", str(1024 * 1024)))
MAX_REPLAY_BYTES = int(os.getenv("HONEYAPI_MAX_REPLAY_BYTES", str(1024 * 1024)))
SECRET_KEY = os.getenv("HONEYAPI_SECRET_KEY", "dev-only-change-in-env")

