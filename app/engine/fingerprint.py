"""FR-3 fingerprinting (Role B). Pure Python, deterministic.

Identity (fingerprint_id) uses only STABLE parts: source IP, header order and
User-Agent family. Timing bucket and path sequence change on every request, so
they are recorded in `components` as evidence but do not change the identity.
"""
from __future__ import annotations

import hashlib

from app.engine.models import Fingerprint, NormalizedRequest

FP_VERSION = "fp-1.0"
PATH_SEQ_LEN = 5

# (substring in lowercase User-Agent, family name); first match wins.
_UA_FAMILIES = [
    ("sqlmap", "sqlmap"),
    ("nikto", "nikto"),
    ("nmap", "nmap"),
    ("gobuster", "gobuster"),
    ("dirbuster", "dirbuster"),
    ("wpscan", "wpscan"),
    ("hydra", "hydra"),
    ("masscan", "masscan"),
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("go-http-client", "go-http-client"),
    ("curl", "curl"),
    ("wget", "wget"),
    ("mozilla", "browser"),
]


def ua_family(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if not ua:
        return "empty"
    for needle, family in _UA_FAMILIES:
        if needle in ua:
            return family
    return "other"


def _sha(text: str, n: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def _actor_history(req: NormalizedRequest, recent: list[NormalizedRequest]) -> list[NormalizedRequest]:
    """Earlier requests from the same source IP, oldest first."""
    mine = [r for r in recent if r.src_ip == req.src_ip and r.request_id != req.request_id and r.ts <= req.ts]
    return sorted(mine, key=lambda r: r.ts)


def timing_bucket(gap_s: float | None) -> str:
    if gap_s is None:
        return "first"
    if gap_s < 0.2:
        return "burst"
    if gap_s < 1.0:
        return "fast"
    if gap_s < 10.0:
        return "normal"
    return "slow"


def compute_fingerprint(req: NormalizedRequest, recent: list[NormalizedRequest]) -> Fingerprint:
    history = _actor_history(req, recent)

    header_order_hash = _sha(",".join(name for name, _ in req.headers))
    family = ua_family(req.user_agent)

    gap = (req.ts - history[-1].ts) if history else None
    bucket = timing_bucket(gap)

    paths = [r.path for r in history][-(PATH_SEQ_LEN - 1):] + [req.path]
    path_seq_hash = _sha("|".join(paths))

    identity = f"{FP_VERSION}|{req.src_ip}|{header_order_hash}|{family}"
    return Fingerprint(
        fingerprint_id="fp-" + _sha(identity),
        version=FP_VERSION,
        components={
            "header_order_hash": header_order_hash,
            "ua_family": family,
            "timing_bucket": bucket,
            "path_seq_hash": path_seq_hash,
        },
    )