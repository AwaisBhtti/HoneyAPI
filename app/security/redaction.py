import re
from typing import Any

REDACTED = "[REDACTED]"

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}

SENSITIVE_FIELD_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "pw_hash",
}

_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[a-z0-9\-._~+/]+=*")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api_key|apikey)\s*([=:])\s*([^\s&;,\"']+)"
)


def redact_text(text: str) -> str:
    if not text:
        return text
    text = _BEARER_RE.sub(r"\1 " + REDACTED, text)
    text = _KV_SECRET_RE.sub(r"\1\2" + REDACTED, text)
    return text


def redact_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for k, v in headers:
        if k.lower() in SENSITIVE_HEADER_KEYS:
            result.append((k, REDACTED))
        else:
            result.append((k, redact_text(v)))
    return result


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if k.lower() in SENSITIVE_FIELD_KEYS:
            out[k] = REDACTED
        elif isinstance(v, dict):
            out[k] = redact_dict(v)
        elif isinstance(v, str):
            out[k] = redact_text(v)
        else:
            out[k] = v
    return out
