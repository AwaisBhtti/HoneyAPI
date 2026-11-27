-- HoneyAPI SQLite Schema
-- Append-only audit enforcement + parameterized application tables

PRAGMA foreign_keys = ON;

-- 1. Users & RBAC
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    created_at REAL NOT NULL
);

-- 2. Sessions (HttpOnly cookie sessions + CSRF token)
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Config-driven Decoy Endpoints (FR-1)
CREATE TABLE IF NOT EXISTS decoy_endpoints (
    id TEXT PRIMARY KEY,
    method TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    response_template TEXT NOT NULL,
    status_code INTEGER NOT NULL DEFAULT 200,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    UNIQUE (method, path_pattern)
);

-- 4. Synthetic Records with Tripwire Tags (FR-2)
CREATE TABLE IF NOT EXISTS synthetic_records (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    tripwire_tag TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);

-- 5. Fingerprints (FR-3)
CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    components_json TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1
);

-- 6. Normalized Requests Log (secrets redacted before insert)
CREATE TABLE IF NOT EXISTS requests_log (
    request_id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query_json TEXT NOT NULL DEFAULT '{}',
    headers_json TEXT NOT NULL DEFAULT '[]',
    ua TEXT NOT NULL DEFAULT '',
    body_excerpt TEXT NOT NULL DEFAULT '',
    body_len INTEGER NOT NULL DEFAULT 0,
    decoy_id TEXT,
    fingerprint_id TEXT,
    FOREIGN KEY (decoy_id) REFERENCES decoy_endpoints(id) ON DELETE SET NULL,
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(fingerprint_id) ON DELETE SET NULL
);

-- 7. Rule Evaluation Results (FR-4)
CREATE TABLE IF NOT EXISTS rule_results (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    fingerprint_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    triggered INTEGER NOT NULL CHECK (triggered IN (0, 1)),
    score REAL NOT NULL,
    threshold REAL NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (request_id) REFERENCES requests_log(request_id) ON DELETE CASCADE
);

-- 8. Aggregated Decisions (FR-4)
CREATE TABLE IF NOT EXISTS decisions (
    request_id TEXT PRIMARY KEY,
    total_score REAL NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence REAL NOT NULL,
    recommended_action TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES requests_log(request_id) ON DELETE CASCADE
);

-- 9. Dynamic Rule Configuration
CREATE TABLE IF NOT EXISTS rule_config (
    rule_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    threshold REAL NOT NULL,
    window_s INTEGER NOT NULL,
    version TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at REAL NOT NULL
);

-- 10. Alerts (FR-5)
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    fingerprint_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    recommended_action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'closed')),
    created_at REAL NOT NULL,
    ack_by TEXT
);

-- 11. Append-Only Audit Events
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    request_id TEXT
);

-- Append-only enforcement triggers on audit_events
CREATE TRIGGER IF NOT EXISTS prevent_audit_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit is append-only');
END;

-- Query performance indexes
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_log_ts ON requests_log(ts);
CREATE INDEX IF NOT EXISTS idx_requests_log_fp ON requests_log(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_rule_results_req ON rule_results(request_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);

