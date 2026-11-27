import secrets
import time
from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.config import SESSION_IDLE_TIMEOUT_S
from app.db.repo import db_session, execute, fetch_one, insert_audit_event
from app.security.csrf import generate_csrf_token, verify_csrf_token
from app.security.passwords import verify_password

router = APIRouter(prefix="/console", tags=["auth"])

SESSION_COOKIE_NAME = "honeyapi_session"
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 60


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def _auth_error(message: str = "Invalid credentials") -> HTTPException:
    return HTTPException(
        status_code=401,
        detail={"error": {"code": "AUTH_REQUIRED", "message": message}},
    )


def get_current_session(
    request: Request,
    session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    if not session_id:
        raise _auth_error("Authentication required")

    now = time.time()
    with db_session() as conn:
        row = fetch_one(
            conn,
            """
            SELECT s.id AS session_id, s.user_id, s.csrf_token, s.expires_at, s.revoked,
                   u.username, u.role
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.id = ?
            """,
            (session_id,),
        )
        if row is None or row["revoked"] == 1 or row["expires_at"] < now:
            raise _auth_error("Session expired or invalid")

        # Sliding idle expiry
        new_expiry = now + SESSION_IDLE_TIMEOUT_S
        execute(conn, "UPDATE sessions SET expires_at = ? WHERE id = ?", (new_expiry, session_id))

    request.state.session = row
    return row


@router.post("/login")
def login(payload: LoginRequest, response: Response) -> dict[str, Any]:
    now = time.time()
    with db_session() as conn:
        user = fetch_one(
            conn,
            "SELECT id, username, pw_hash, role, failed_logins, locked_until FROM users WHERE username = ?",
            (payload.username,),
        )
        if user is None:
            insert_audit_event(
                conn,
                actor=payload.username,
                role="unauthenticated",
                action="LOGIN",
                target="console",
                result="failure",
                detail={"reason": "invalid_credentials"},
            )
            raise _auth_error()

        if user["locked_until"] is not None and user["locked_until"] > now:
            insert_audit_event(
                conn,
                actor=user["username"],
                role=user["role"],
                action="LOGIN",
                target="console",
                result="locked",
                detail={"locked_until": user["locked_until"]},
            )
            raise HTTPException(
                status_code=429,
                detail={"error": {"code": "RATE_LIMITED", "message": "Too many failed attempts; try again later"}},
            )

        if not verify_password(payload.password, user["pw_hash"]):
            failed = user["failed_logins"] + 1
            locked_until = (now + LOCKOUT_SECONDS) if failed >= MAX_FAILED_LOGINS else None
            execute(
                conn,
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (failed, locked_until, user["id"]),
            )
            insert_audit_event(
                conn,
                actor=user["username"],
                role=user["role"],
                action="LOGIN",
                target="console",
                result="failure",
                detail={"failed_logins": failed},
            )
            if locked_until is not None:
                raise HTTPException(
                    status_code=429,
                    detail={"error": {"code": "RATE_LIMITED", "message": "Too many failed attempts; try again later"}},
                )
            raise _auth_error()

        # Reset failed logins on success
        execute(
            conn,
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )

        session_id = secrets.token_hex(32)
        csrf_token = generate_csrf_token()
        expires_at = now + SESSION_IDLE_TIMEOUT_S

        execute(
            conn,
            """
            INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at, revoked)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (session_id, user["id"], csrf_token, now, expires_at),
        )
        insert_audit_event(
            conn,
            actor=user["username"],
            role=user["role"],
            action="LOGIN",
            target="console",
            result="success",
        )

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=SESSION_IDLE_TIMEOUT_S,
        path="/",
    )
    return {
        "username": user["username"],
        "role": user["role"],
        "csrf_token": csrf_token,
    }


@router.post("/logout")
def logout(
    response: Response,
    session: dict[str, Any] = Depends(get_current_session),
    _: None = Depends(verify_csrf_token),
) -> dict[str, str]:
    with db_session() as conn:
        execute(conn, "UPDATE sessions SET revoked = 1 WHERE id = ?", (session["session_id"],))
        insert_audit_event(
            conn,
            actor=session["username"],
            role=session["role"],
            action="LOGOUT",
            target="console",
            result="success",
        )
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@router.get("/me")
def me(session: dict[str, Any] = Depends(get_current_session)) -> dict[str, Any]:
    return {
        "username": session["username"],
        "role": session["role"],
        "csrf_token": session["csrf_token"],
    }
