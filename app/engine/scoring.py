"""FR-4 decision scoring (Role B). Pure Python.

Formula (also documented in docs/scoring.md):
  total_score = min(100, top_triggered_score + 10 * (other_triggered_rules))
  severity    : 0 info | <30 low | <55 medium | <80 high | >=80 critical
  confidence  : 0.6 if nothing triggered, else
                min(0.95, 0.5 + 0.15 * other_triggered + 0.3 * top_score / 100)
  action      : info/low monitor | medium review | high investigate | critical recommend_block
"""
from __future__ import annotations

from app.engine.models import Decision, Fingerprint, NormalizedRequest, RuleResult

BONUS_PER_EXTRA_RULE = 10.0

_ACTIONS = {
    "info": "monitor",
    "low": "monitor",
    "medium": "review",
    "high": "investigate",
    "critical": "recommend_block",
}


def severity_for(score: float) -> str:
    if score <= 0:
        return "info"
    if score < 30:
        return "low"
    if score < 55:
        return "medium"
    if score < 80:
        return "high"
    return "critical"


def decide(req: NormalizedRequest, fp: Fingerprint, results: list[RuleResult]) -> Decision:
    triggered = [r for r in results if r.triggered]
    if triggered:
        top = max(r.score for r in triggered)
        extra = len(triggered) - 1
        total = round(min(100.0, top + BONUS_PER_EXTRA_RULE * extra), 1)
        confidence = round(min(0.95, 0.5 + 0.15 * extra + 0.3 * top / 100.0), 2)
    else:
        total, confidence = 0.0, 0.6

    severity = severity_for(total)
    return Decision(
        request_id=req.request_id,
        fingerprint_id=fp.fingerprint_id,
        total_score=total,
        severity=severity,
        confidence=confidence,
        results=list(results),
        recommended_action=_ACTIONS[severity],
    )


def explain(decision: Decision) -> str:
    """Human-readable explanation built from the rule reasons."""
    triggered = [r for r in decision.results if r.triggered]
    if not triggered:
        return "No rule triggered; request looks normal."
    head = (f"{decision.severity.upper()} (score {decision.total_score:g}, "
            f"confidence {decision.confidence:g}): {len(triggered)} rule(s) triggered.")
    lines = [f"- [{r.rule_id} v{r.rule_version}] {r.reason}" for r in triggered]
    return "\n".join([head, *lines, f"Recommended action: {decision.recommended_action}"])