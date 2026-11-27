from typing import Any, Callable

from fastapi import Depends, HTTPException

from app.api.auth import get_current_session
from app.db.repo import db_session, insert_audit_event


def require_role(*allowed_roles: str) -> Callable[..., dict[str, Any]]:
    """FastAPI dependency enforcing server-side role checks."""

    def _dependency(session: dict[str, Any] = Depends(get_current_session)) -> dict[str, Any]:
        if session["role"] not in allowed_roles:
            with db_session() as conn:
                insert_audit_event(
                    conn,
                    actor=session["username"],
                    role=session["role"],
                    action="AUTHZ_DENIED",
                    target="endpoint",
                    result="forbidden",
                    detail={"required_roles": list(allowed_roles)},
                )
            raise HTTPException(
                status_code=403,
                detail={"error": {"code": "FORBIDDEN", "message": "Insufficient permissions"}},
            )
        return session

    return _dependency
