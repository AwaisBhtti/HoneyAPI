from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.db.repo import db_session, execute, fetch_all, fetch_one, insert_audit_event
from app.security.csrf import verify_csrf_token
from app.security.rbac import require_role

router = APIRouter(prefix="/api", tags=["data"])


class AckRequest(BaseModel):
    confirm: bool = False


@router.get("/requests")
def list_requests(
    fp: str | None = Query(default=None),
    rule: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    from_ts: float | None = Query(default=None, alias="from"),
    to_ts: float | None = Query(default=None, alias="to"),
    page: int = Query(default=1, ge=1, le=1000),
    session: dict[str, Any] = Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    limit = 50
    offset = (page - 1) * limit
    clauses: list[str] = []
    params: list[Any] = []

    if fp:
        clauses.append("r.fingerprint_id = ?")
        params.append(fp)
    if severity:
        clauses.append("d.severity = ?")
        params.append(severity)
    if from_ts is not None:
        clauses.append("r.ts >= ?")
        params.append(from_ts)
    if to_ts is not None:
        clauses.append("r.ts <= ?")
        params.append(to_ts)
    if rule:
        clauses.append("EXISTS (SELECT 1 FROM rule_results rr WHERE rr.request_id = r.request_id AND rr.rule_id = ? AND rr.triggered = 1)")
        params.append(rule)

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT r.request_id, r.ts, r.src_ip, r.method, r.path, r.decoy_id, r.fingerprint_id,
               d.total_score, d.severity, d.recommended_action
        FROM requests_log r
        LEFT JOIN decisions d ON d.request_id = r.request_id
        {where_sql}
        ORDER BY r.ts DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    with db_session() as conn:
        rows = fetch_all(conn, sql, tuple(params))

    if session["role"] == "viewer":
        for row in rows:
            row["src_ip"] = "[REDACTED]"

    return {"page": page, "items": rows}


@router.get("/requests/{request_id}")
def get_request_detail(
    request_id: str,
    session: dict[str, Any] = Depends(require_role("admin", "analyst")),
) -> dict[str, Any]:
    with db_session() as conn:
        req = fetch_one(conn, "SELECT * FROM requests_log WHERE request_id = ?", (request_id,))
        if req is None:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "NOT_FOUND", "message": "Request not found"}},
            )
        decision = fetch_one(conn, "SELECT * FROM decisions WHERE request_id = ?", (request_id,))
        rules = fetch_all(conn, "SELECT * FROM rule_results WHERE request_id = ?", (request_id,))
    return {"request": req, "decision": decision, "rule_results": rules}


@router.get("/fingerprints")
def list_fingerprints(
    session: dict[str, Any] = Depends(require_role("admin", "analyst")),
) -> dict[str, Any]:
    with db_session() as conn:
        rows = fetch_all(conn, "SELECT * FROM fingerprints ORDER BY last_seen DESC LIMIT 100")
    return {"items": rows}


@router.get("/fingerprints/{fingerprint_id}/timeline")
def get_fingerprint_timeline(
    fingerprint_id: str,
    session: dict[str, Any] = Depends(require_role("admin", "analyst")),
) -> dict[str, Any]:
    with db_session() as conn:
        fp = fetch_one(conn, "SELECT * FROM fingerprints WHERE fingerprint_id = ?", (fingerprint_id,))
        if fp is None:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "NOT_FOUND", "message": "Fingerprint not found"}},
            )
        events = fetch_all(
            conn,
            """
            SELECT r.request_id, r.ts, r.method, r.path, r.decoy_id,
                   d.total_score, d.severity, d.recommended_action
            FROM requests_log r
            LEFT JOIN decisions d ON d.request_id = r.request_id
            WHERE r.fingerprint_id = ?
            ORDER BY r.ts ASC
            """,
            (fingerprint_id,),
        )
    return {"fingerprint": fp, "timeline": events}


@router.get("/alerts")
def list_alerts(
    status: str | None = Query(default=None),
    session: dict[str, Any] = Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    with db_session() as conn:
        if status:
            rows = fetch_all(conn, "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT 100", (status,))
        else:
            rows = fetch_all(conn, "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100")
    return {"items": rows}


@router.post("/alerts/{alert_id}/ack")
def ack_alert(
    alert_id: str,
    payload: AckRequest,
    session: dict[str, Any] = Depends(require_role("admin", "analyst")),
    _: None = Depends(verify_csrf_token),
) -> dict[str, str]:
    if not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "Confirmation required"}},
        )
    with db_session() as conn:
        alert = fetch_one(conn, "SELECT id, status FROM alerts WHERE id = ?", (alert_id,))
        if alert is None:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "NOT_FOUND", "message": "Alert not found"}},
            )
        execute(
            conn,
            "UPDATE alerts SET status = 'ack', ack_by = ? WHERE id = ?",
            (session["username"], alert_id),
        )
        insert_audit_event(
            conn,
            actor=session["username"],
            role=session["role"],
            action="ALERT_ACK",
            target=alert_id,
            result="success",
        )
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/stats")
def get_stats(
    session: dict[str, Any] = Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    with db_session() as conn:
        by_severity = fetch_all(
            conn,
            "SELECT severity, COUNT(*) AS count FROM decisions GROUP BY severity",
        )
        by_rule = fetch_all(
            conn,
            "SELECT rule_id, COUNT(*) AS count FROM rule_results WHERE triggered = 1 GROUP BY rule_id",
        )
        total_requests = fetch_one(conn, "SELECT COUNT(*) AS count FROM requests_log") or {"count": 0}
        open_alerts = fetch_one(conn, "SELECT COUNT(*) AS count FROM alerts WHERE status = 'open'") or {"count": 0}
    return {
        "total_requests": total_requests["count"],
        "open_alerts": open_alerts["count"],
        "by_severity": by_severity,
        "by_rule": by_rule,
    }
