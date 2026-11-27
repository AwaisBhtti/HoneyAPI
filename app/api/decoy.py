import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response

from app.config import MAX_BODY_BYTES
from app.db.repo import db_session, fetch_all
from app.pipeline import process_request

router = APIRouter(tags=["decoys"])

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _match_decoy(method: str, path: str, decoys: list[dict[str, Any]]) -> dict[str, Any] | None:
    for decoy in decoys:
        if not decoy["enabled"] or decoy["method"].upper() != method:
            continue
        pattern = decoy["path_pattern"]
        if pattern == path:
            return decoy
        if "{id}" in pattern:
            regex = "^" + re.escape(pattern).replace(r"\{id\}", r"[^/]+") + "$"
            if re.match(regex, path):
                return decoy
    return None


async def _handle_decoy(request: Request) -> Response:
    method = request.method.upper()
    if method not in ALLOWED_METHODS:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "Unsupported HTTP method"}},
        )

    path = request.url.path
    if len(path) > 2048:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "VALIDATION_FAILED", "message": "Path too long"}},
        )

    body_bytes = await request.body()
    if len(body_bytes) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": {"code": "PAYLOAD_TOO_LARGE", "message": "Request body exceeds limit"}},
        )

    with db_session() as conn:
        decoys = fetch_all(conn, "SELECT id, method, path_pattern, response_template, status_code, enabled FROM decoy_endpoints")

    matched = _match_decoy(method, path, decoys)
    if matched is None:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "Not found"}},
        )

    src_ip = request.headers.get("x-sim-ip") or (request.client.host if request.client else "127.0.0.1")
    headers = [(k, v) for k, v in request.headers.items()]
    query = dict(request.query_params)
    body_text = body_bytes.decode("utf-8", errors="replace")

    process_request(
        src_ip=src_ip,
        method=method,
        path=path,
        query=query,
        headers=headers,
        body_text=body_text,
        decoy_id=matched["id"],
    )

    content_type = "application/json" if matched["response_template"].lstrip().startswith("{") else "text/plain"
    return Response(
        content=matched["response_template"],
        status_code=matched["status_code"],
        media_type=content_type,
    )


@router.api_route("/wp-login.php", methods=["GET", "POST"])
@router.api_route("/admin", methods=["GET"])
@router.api_route("/.env", methods=["GET"])
@router.api_route("/api/v1/users", methods=["GET"])
@router.api_route("/api/v1/users/{item_id}", methods=["GET"])
@router.api_route("/api/v1/login", methods=["POST"])
@router.api_route("/backup.zip", methods=["GET"])
async def decoy_endpoint(request: Request) -> Response:
    return await _handle_decoy(request)
