"""FR-5 alerting (Role B). Pure Python: caller supplies existing alerts and config.

maybe_alert() returns an Alert or None. It applies, in order:
  1. severity gate      (>= min_severity)
  2. alert rate limit   (max_per_window alerts per fingerprint per rate_window_s)
  3. dedupe             (same fingerprint + rule within dedupe_window_s, unless severity escalated)
"""
from __future__ import annotations

import time
from typing import Any

from app.engine.models import SEVERITIES, Alert, Decision

DEFAULT_ALERT_CONFIG: dict[str, Any] = {
    "min_severity": "medium",
    "dedupe_window_s": 60,
    "max_per_window": 5,
    "rate_window_s": 300,
}

MAX_EVIDENCE_IDS = 20


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0


def maybe_alert(
    decision: Decision,
    existing_alerts: list[Alert],
    cfg: dict[str, Any] | None = None,
    *,
    now: float | None = None,
) -> Alert | None:
    c = {**DEFAULT_ALERT_CONFIG, **(cfg or {})}
    now = time.time() if now is None else now

    if _rank(decision.severity) < _rank(c["min_severity"]):
        return None

    triggered = [r for r in decision.results if r.triggered]
    if not triggered:
        return None
    top = max(triggered, key=lambda r: r.score)

    mine = [a for a in existing_alerts if a.fingerprint_id == decision.fingerprint_id]

    recent = [a for a in mine if now - a.created_at < c["rate_window_s"]]
    if len(recent) >= c["max_per_window"]:
        return None

    same_rule = [a for a in mine if a.rule_id == top.rule_id and now - a.created_at < c["dedupe_window_s"]]
    if same_rule and _rank(decision.severity) <= max(_rank(a.severity) for a in same_rule):
        return None

    evidence: list[str] = []
    for r in triggered:
        for rid in r.evidence.get("request_ids", []):
            if rid not in evidence:
                evidence.append(rid)
    if decision.request_id not in evidence:
        evidence.append(decision.request_id)

    return Alert(
        fingerprint_id=decision.fingerprint_id,
        rule_id=top.rule_id,
        severity=decision.severity,
        evidence_ids=evidence[-MAX_EVIDENCE_IDS:],
        recommended_action=decision.recommended_action,
        created_at=now,
    )