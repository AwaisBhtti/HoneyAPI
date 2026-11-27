import json
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.config import MAX_REPLAY_BYTES
from app.db.repo import db_session, insert_audit_event
from app.pipeline import process_request
from app.security.csrf import verify_csrf_token
from app.security.ratelimit import rate_limit
from app.security.rbac import require_role

router = APIRouter(prefix="/api", tags=["replay"])

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


@router.post("/replay")
async def replay_fixtures(
    file: UploadFile = File(...),
    session: dict[str, Any] = Depends(require_role("admin", "analyst")),
    _: None = Depends(verify_csrf_token),
    __: None = Depends(rate_limit("replay", max_requests=10, window_s=60)),
) -> dict[str, Any]:
    filename = file.filename or ""
    if not filename.lower().endswith(".jsonl"):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "Only .jsonl files are accepted"}},
        )

    raw = await file.read(MAX_REPLAY_BYTES + 1)
    if len(raw) > MAX_REPLAY_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": {"code": "PAYLOAD_TOO_LARGE", "message": "Fixture file exceeds 1 MB limit"}},
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "File must be valid UTF-8"}},
        )

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "Fixture file is empty"}},
        )

    results: list[dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "VALIDATION_FAILED", "message": f"Invalid JSON on line {idx}"}},
            )

        if not isinstance(item, dict):
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "VALIDATION_FAILED", "message": f"Line {idx} must be a JSON object"}},
            )

        method = str(item.get("method", "GET")).upper()
        path = str(item.get("path", ""))
        if method not in ALLOWED_METHODS or not path.startswith("/"):
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "VALIDATION_FAILED", "message": f"Invalid method or path on line {idx}"}},
            )

        sim_ip = str(item.get("sim_ip") or "127.0.0.1")
        sim_ua = str(item.get("sim_ua") or "HoneyAPI-Replay/1.0")
        raw_headers = item.get("headers") or []
        headers: list[tuple[str, str]] = [("user-agent", sim_ua)]
        if isinstance(raw_headers, list):
            for pair in raw_headers:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    headers.append((str(pair[0]), str(pair[1])))
        elif isinstance(raw_headers, dict):
            for k, v in raw_headers.items():
                headers.append((str(k), str(v)))

        query = item.get("query") or {}
        if not isinstance(query, dict):
            query = {}
        body = str(item.get("body") or "")

        res = process_request(
            src_ip=sim_ip,
            method=method,
            path=path,
            query={str(k): str(v) for k, v in query.items()},
            headers=headers,
            body_text=body,
            decoy_id=None,
        )
        results.append(res)

    with db_session() as conn:
        insert_audit_event(
            conn,
            actor=session["username"],
            role=session["role"],
            action="FIXTURE_REPLAY",
            target=filename,
            result="success",
            detail={"count": len(results)},
        )

    return {"replayed": len(results), "results": results}
