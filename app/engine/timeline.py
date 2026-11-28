"""FR-6 session timeline (Role B). Pure Python.

An *event* is a plain dict so the backend can build it straight from database
rows:  {"ts", "request_id", "method", "path", "severity", "total_score",
        "reasons": [str, ...]}   ("reasons" optional)
"""
from __future__ import annotations

from typing import Any

from app.engine.models import Decision, NormalizedRequest, TimelineEntry, ValidationError

REQUIRED_KEYS = ("ts", "request_id", "method", "path", "severity", "total_score")


def event_from(req: NormalizedRequest, decision: Decision) -> dict[str, Any]:
    return {
        "ts": req.ts,
        "request_id": req.request_id,
        "method": req.method,
        "path": req.path,
        "severity": decision.severity,
        "total_score": decision.total_score,
        "reasons": [r.reason for r in decision.results if r.triggered],
    }


def build_timeline(events: list[dict[str, Any]]) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    for ev in events:
        missing = [k for k in REQUIRED_KEYS if k not in ev]
        if missing:
            raise ValidationError(f"timeline event missing keys: {', '.join(missing)}")
        reasons = ev.get("reasons") or []
        summary = "; ".join(reasons) if reasons else "normal request, no rule triggered"
        entries.append(TimelineEntry(
            ts=float(ev["ts"]),
            request_id=str(ev["request_id"]),
            method=str(ev["method"]),
            path=str(ev["path"]),
            severity=str(ev["severity"]),
            total_score=float(ev["total_score"]),
            summary=summary,
        ))
    entries.sort(key=lambda e: e.ts)  # stable: equal timestamps keep input order
    return entries