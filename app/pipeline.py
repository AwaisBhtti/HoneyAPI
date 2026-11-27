import json
import time
import uuid
from typing import Any

from app.db.repo import db_session, execute, fetch_one
from app.security.redaction import redact_headers, redact_text


def _normalize_fallback(
    *,
    src_ip: str,
    method: str,
    path: str,
    query: dict[str, str],
    headers: list[tuple[str, str]],
    body_text: str,
    decoy_id: str | None,
) -> dict[str, Any]:
    """Fallback normalizer when app.engine.normalize is not yet merged."""
    redacted_headers = redact_headers(headers)
    ua = ""
    for k, v in redacted_headers:
        if k.lower() == "user-agent":
            ua = v[:256]
            break

    return {
        "request_id": str(uuid.uuid4()),
        "ts": time.time(),
        "src_ip": src_ip,
        "method": method.upper(),
        "path": path[:2048],
        "query": {k[:64]: redact_text(v)[:256] for k, v in query.items()},
        "headers": redacted_headers,
        "user_agent": ua,
        "body_excerpt": redact_text(body_text[:1024]),
        "body_len": len(body_text.encode("utf-8", errors="ignore")),
        "decoy_id": decoy_id,
    }


def process_request(
    *,
    src_ip: str,
    method: str,
    path: str,
    query: dict[str, str],
    headers: list[tuple[str, str]],
    body_text: str,
    decoy_id: str | None = None,
) -> dict[str, Any]:
    """Run the 7-stage pipeline: normalize -> fingerprint -> rules -> decide -> store -> alert."""
    norm = _normalize_fallback(
        src_ip=src_ip,
        method=method,
        path=path,
        query=query,
        headers=headers,
        body_text=body_text,
        decoy_id=decoy_id,
    )

    # Stub fingerprint & decision until B's engine modules are merged
    fp_id = f"fp-{uuid.uuid5(uuid.NAMESPACE_DNS, norm['user_agent'] or norm['src_ip']).hex[:12]}"
    now = norm["ts"]

    with db_session() as conn:
        existing_fp = fetch_one(conn, "SELECT fingerprint_id, request_count FROM fingerprints WHERE fingerprint_id = ?", (fp_id,))
        if existing_fp is None:
            execute(
                conn,
                """
                INSERT INTO fingerprints (fingerprint_id, version, components_json, first_seen, last_seen, request_count)
                VALUES (?, 'fp-1.0', ?, ?, ?, 1)
                """,
                (fp_id, json.dumps({"ua": norm["user_agent"]}), now, now),
            )
        else:
            execute(
                conn,
                "UPDATE fingerprints SET last_seen = ?, request_count = request_count + 1 WHERE fingerprint_id = ?",
                (now, fp_id),
            )

        execute(
            conn,
            """
            INSERT INTO requests_log (
                request_id, ts, src_ip, method, path, query_json, headers_json,
                ua, body_excerpt, body_len, decoy_id, fingerprint_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                norm["request_id"],
                now,
                norm["src_ip"],
                norm["method"],
                norm["path"],
                json.dumps(norm["query"]),
                json.dumps(norm["headers"]),
                norm["user_agent"],
                norm["body_excerpt"],
                norm["body_len"],
                norm["decoy_id"],
                fp_id,
            ),
        )

        execute(
            conn,
            """
            INSERT INTO decisions (request_id, total_score, severity, confidence, recommended_action)
            VALUES (?, 0.0, 'info', 0.5, 'monitor')
            """,
            (norm["request_id"],),
        )

    return {
        "request_id": norm["request_id"],
        "fingerprint_id": fp_id,
        "severity": "info",
        "total_score": 0.0,
    }
