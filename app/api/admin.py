import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.db.repo import db_session, execute, fetch_all, fetch_one, insert_audit_event
from app.security.csrf import verify_csrf_token
from app.security.passwords import hash_password
from app.security.rbac import require_role

router = APIRouter(prefix="/api/admin", tags=["admin"])


class RuleUpdateRequest(BaseModel):
    enabled: bool
    threshold: float = Field(gt=0.0, le=10000.0)
    window_s: int = Field(ge=1, le=86400)
    confirm: bool = False


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(pattern="^(admin|analyst|viewer)$")


def _bump_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) == 2 and parts[1].isdigit():
        return f"{parts[0]}.{int(parts[1]) + 1}"
    return f"{version}.1"


@router.get("/rules/{rule_id}")
def get_rule(
    rule_id: str,
    session: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    with db_session() as conn:
        rule = fetch_one(conn, "SELECT * FROM rule_config WHERE rule_id = ?", (rule_id,))
    if rule is None:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "Rule not found"}},
        )
    return rule


@router.put("/rules/{rule_id}")
def update_rule(
    rule_id: str,
    payload: RuleUpdateRequest,
    session: dict[str, Any] = Depends(require_role("admin")),
    _: None = Depends(verify_csrf_token),
) -> dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "Confirmation required"}},
        )

    now = time.time()
    with db_session() as conn:
        old = fetch_one(conn, "SELECT * FROM rule_config WHERE rule_id = ?", (rule_id,))
        if old is None:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "NOT_FOUND", "message": "Rule not found"}},
            )
        new_version = _bump_version(old["version"])
        execute(
            conn,
            """
            UPDATE rule_config
            SET enabled = ?, threshold = ?, window_s = ?, version = ?, updated_by = ?, updated_at = ?
            WHERE rule_id = ?
            """,
            (
                1 if payload.enabled else 0,
                payload.threshold,
                payload.window_s,
                new_version,
                session["username"],
                now,
                rule_id,
            ),
        )
        insert_audit_event(
            conn,
            actor=session["username"],
            role=session["role"],
            action="RULE_UPDATE",
            target=rule_id,
            result="success",
            detail={
                "old": {
                    "enabled": bool(old["enabled"]),
                    "threshold": old["threshold"],
                    "window_s": old["window_s"],
                    "version": old["version"],
                },
                "new": {
                    "enabled": payload.enabled,
                    "threshold": payload.threshold,
                    "window_s": payload.window_s,
                    "version": new_version,
                },
            },
        )
        updated = fetch_one(conn, "SELECT * FROM rule_config WHERE rule_id = ?", (rule_id,))
    return updated or {}


@router.get("/audit")
def list_audit_events(
    page: int = Query(default=1, ge=1, le=1000),
    session: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    limit = 50
    offset = (page - 1) * limit
    with db_session() as conn:
        rows = fetch_all(
            conn,
            "SELECT * FROM audit_events ORDER BY ts DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
    return {"page": page, "items": rows}


@router.post("/users", status_code=201)
def create_user(
    payload: CreateUserRequest,
    session: dict[str, Any] = Depends(require_role("admin")),
    _: None = Depends(verify_csrf_token),
) -> dict[str, Any]:
    user_id = str(uuid.uuid4())
    now = time.time()
    with db_session() as conn:
        existing = fetch_one(conn, "SELECT id FROM users WHERE username = ?", (payload.username,))
        if existing is not None:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "VALIDATION_FAILED", "message": "Username already exists"}},
            )
        execute(
            conn,
            """
            INSERT INTO users (id, username, pw_hash, role, failed_logins, locked_until, created_at)
            VALUES (?, ?, ?, ?, 0, NULL, ?)
            """,
            (user_id, payload.username, hash_password(payload.password), payload.role, now),
        )
        insert_audit_event(
            conn,
            actor=session["username"],
            role=session["role"],
            action="USER_CREATE",
            target=payload.username,
            result="success",
            detail={"role": payload.role},
        )
    return {"id": user_id, "username": payload.username, "role": payload.role}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    session: dict[str, Any] = Depends(require_role("admin")),
    _: None = Depends(verify_csrf_token),
) -> dict[str, str]:
    if user_id == session["user_id"]:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "Cannot delete current user"}},
        )
    with db_session() as conn:
        target = fetch_one(conn, "SELECT id, username FROM users WHERE id = ?", (user_id,))
        if target is None:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "NOT_FOUND", "message": "User not found"}},
            )
        execute(conn, "DELETE FROM users WHERE id = ?", (user_id,))
        insert_audit_event(
            conn,
            actor=session["username"],
            role=session["role"],
            action="USER_DELETE",
            target=target["username"],
            result="success",
        )
    return {"status": "deleted", "user_id": user_id}
