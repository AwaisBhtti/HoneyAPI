"""FR-4 detection rules (Role B). Pure Python, explainable, no side effects.

Every rule returns a RuleResult carrying rule_id, version, threshold, a
human-readable reason and evidence. "Actor" = requests sharing the same
src_ip as the current request (same notion the fingerprint uses).
Patterns are only MATCHED against text, never executed.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from app.engine.models import Fingerprint, NormalizedRequest, RuleResult

DEFAULT_CONFIG: dict[str, dict[str, Any]] = {
    "scanner": {"enabled": True, "threshold": 4.0, "window_s": 60, "version": "1.0"},
    "cred_stuffing": {"enabled": True, "threshold": 8.0, "window_s": 30, "version": "1.0"},
    "enumeration": {"enabled": True, "threshold": 5.0, "window_s": 60, "version": "1.0"},
    "injection": {"enabled": True, "threshold": 1.0, "window_s": 60, "version": "1.0"},
    "rate_spike": {"enabled": True, "threshold": 10.0, "window_s": 10, "version": "1.0"},
}

RuleFn = Callable[[NormalizedRequest, Fingerprint, list[NormalizedRequest], dict[str, Any]], RuleResult]
_RULES: dict[str, RuleFn] = {}


def register(rule_id: str) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        _RULES[rule_id] = fn
        return fn
    return deco


def evaluate_rules(
    req: NormalizedRequest,
    fp: Fingerprint,
    recent: list[NormalizedRequest],
    cfg: dict[str, dict[str, Any]] | None = None,
) -> list[RuleResult]:
    cfg = cfg if cfg is not None else DEFAULT_CONFIG
    results: list[RuleResult] = []
    for rule_id, fn in _RULES.items():
        c = cfg.get(rule_id, DEFAULT_CONFIG.get(rule_id))
        if not c or not c.get("enabled", True):
            continue
        results.append(fn(req, fp, recent, c))
    return results


# ---------- shared helpers ----------

def window_requests(req: NormalizedRequest, recent: list[NormalizedRequest], window_s: float) -> list[NormalizedRequest]:
    """Same-actor requests inside the window ending at req.ts, INCLUDING req, oldest first."""
    mine = [
        r for r in recent
        if r.src_ip == req.src_ip and r.request_id != req.request_id
        and req.ts - window_s <= r.ts <= req.ts
    ]
    mine.sort(key=lambda r: r.ts)
    return mine + [req]


def scale_score(count: float, threshold: float) -> float:
    """50 at the threshold, 100 at twice the threshold."""
    return round(min(100.0, 100.0 * count / (2.0 * threshold)), 1)


def make_result(rule_id: str, c: dict[str, Any], triggered: bool, score: float,
                reason: str, evidence: dict[str, Any]) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        rule_version=str(c["version"]),
        triggered=triggered,
        score=score if triggered else 0.0,
        threshold=float(c["threshold"]),
        reason=reason,
        evidence=evidence,
    )


# ---------- rule: injection ----------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sqli_tautology", re.compile(r"(?i)['\"]?\s*\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+")),
    ("sqli_union", re.compile(r"(?i)\bunion\b\s+(all\s+)?select\b")),
    ("sqli_stacked", re.compile(r"(?i);\s*(drop|delete|insert|update|alter)\s+\w+")),
    ("sqli_time", re.compile(r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay")),
    ("sqli_schema", re.compile(r"(?i)\binformation_schema\b")),
    ("sqli_comment", re.compile(r"'\s*(--|#)")),
    ("xss_script", re.compile(r"(?i)<\s*script\b")),
    ("xss_handler", re.compile(r"(?i)\bon(error|load|click|mouseover|focus)\s*=")),
    ("xss_js_uri", re.compile(r"(?i)javascript\s*:")),
    ("path_traversal", re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini|windows[\\/]system32)")),
    ("cmd_injection", re.compile(r"(?i)(;|\||&&)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|\$\(")),
]


def _injection_targets(req: NormalizedRequest) -> list[tuple[str, str]]:
    targets = [("path", req.raw_path or req.path)]
    targets += [(f"query:{k}", v) for k, v in req.query.items()]
    targets.append(("body", req.body_excerpt))
    return targets


@register("injection")
def rule_injection(req, fp, recent, c) -> RuleResult:
    matches: list[dict[str, str]] = []
    for where, text in _injection_targets(req):
        for name, pattern in _INJECTION_PATTERNS:
            if text and pattern.search(text):
                matches.append({"where": where, "pattern": name})

    categories = {m["pattern"].split("_")[0] if m["pattern"] != "path_traversal" else "traversal" for m in matches}
    count = len(matches)
    triggered = count >= c["threshold"]
    score = min(100.0, 60.0 + 20.0 * (len(categories) - 1)) if triggered else 0.0
    if matches:
        detail = ", ".join(f'{m["pattern"]} in {m["where"]}' for m in matches[:5])
        reason = f"injection: {count} suspicious pattern(s) matched ({detail}), threshold={c['threshold']:g}"
    else:
        reason = f"injection: no suspicious patterns found, threshold={c['threshold']:g}"
    return make_result("injection", c, triggered, score, reason,
                       {"request_ids": [req.request_id], "matches": matches})