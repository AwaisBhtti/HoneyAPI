"""FR-1 normalization: turn a RawRequest into a safe NormalizedRequest.

Pure function, no FastAPI or database imports. Rules:
  * method must be on a whitelist
  * path is decoded ONCE, dot-segments removed, length capped
  * raw_path keeps dot-segments so the injection rule can still see traversal
  * query/header/body values are truncated and secrets are redacted
  * header ORDER is preserved (the fingerprint depends on it)
"""
from __future__ import annotations

import re
import time
import uuid
from urllib.parse import unquote

from app.engine.models import NormalizedRequest, RawRequest, ValidationError
from app.security.redaction import REDACTED, redact_dict, redact_headers, redact_text

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

MAX_PATH = 2048
MAX_QUERY_PARAMS = 50
MAX_QUERY_KEY = 64
MAX_QUERY_VALUE = 256
MAX_HEADERS = 100
MAX_HEADER_VALUE = 512
MAX_USER_AGENT = 256
MAX_BODY_EXCERPT = 1024
MAX_IP = 64

# A's redaction misses secrets inside JSON bodies, e.g. {"password": "x"}.
_JSON_SECRET_RE = re.compile(
    r'(?i)("(?:password|passwd|pwd|secret|token|access_token|refresh_token|'
    r'api_key|apikey|private_key)"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\s]+)'
)


def _printable(text: str) -> str:
    """Show control characters as literal \\xNN so logs and UI stay safe."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)


def _resolve_dot_segments(path: str) -> str:
    parts: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    resolved = "/" + "/".join(parts)
    if path.endswith("/") and resolved != "/":
        resolved += "/"
    return resolved


def _redact_body(text: str) -> str:
    text = _JSON_SECRET_RE.sub(lambda m: m.group(1) + '"' + REDACTED + '"', text)
    return redact_text(text)


def normalize_request(raw: RawRequest, *, now: float | None = None) -> NormalizedRequest:
    method = (raw.method or "").upper()
    if method not in ALLOWED_METHODS:
        raise ValidationError("unsupported HTTP method")

    if not isinstance(raw.path, str) or not raw.path.startswith("/"):
        raise ValidationError("path must start with '/'")
    if len(raw.path) > MAX_PATH:
        raise ValidationError("path too long")

    raw_path = _printable(unquote(raw.path))[:MAX_PATH]  # decode exactly once
    path = _resolve_dot_segments(raw_path)

    clean_q = redact_dict({str(k): str(v) for k, v in list(raw.query.items())[:MAX_QUERY_PARAMS]})
    query = {k[:MAX_QUERY_KEY]: _printable(str(v))[:MAX_QUERY_VALUE] for k, v in clean_q.items()}

    headers: list[tuple[str, str]] = []
    for k, v in redact_headers(list(raw.headers)[:MAX_HEADERS]):
        headers.append((k.lower()[:64], _printable(v)[:MAX_HEADER_VALUE]))

    user_agent = next((v[:MAX_USER_AGENT] for k, v in headers if k == "user-agent"), "")

    body_text = raw.body_text or ""
    body_excerpt = _printable(_redact_body(body_text[:4096]))[:MAX_BODY_EXCERPT]
    body_len = len(body_text.encode("utf-8", errors="ignore"))

    return NormalizedRequest(
        request_id=str(uuid.uuid4()),
        ts=time.time() if now is None else now,
        src_ip=(raw.src_ip or "unknown")[:MAX_IP],
        method=method,
        path=path,
        query=query,
        headers=headers,
        user_agent=user_agent,
        body_excerpt=body_excerpt,
        body_len=body_len,
        decoy_id=raw.decoy_id,
        raw_path=raw_path,
    )