import secrets
from fastapi import Header, HTTPException, Request

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf_token(
    request: Request,
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> None:
    """Validate X-CSRF-Token against the session's csrf_token on state-changing requests."""
    if request.method in SAFE_METHODS:
        return

    session = getattr(request.state, "session", None)
    if session is None:
        return

    expected = session.get("csrf_token", "")
    if not x_csrf_token or not secrets.compare_digest(x_csrf_token, expected):
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "FORBIDDEN", "message": "Invalid or missing CSRF token"}},
        )
