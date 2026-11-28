"""Shared data contracts for the HoneyAPI security engine (Role B).

These classes are the "language" every stage of the pipeline speaks.
Pure Python only: no FastAPI, no database imports in this package.
Changing a field here is a contract change: tell the whole team.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ValidationError(Exception):
    """Raised by the engine when input is malformed or unsafe."""


@dataclass(frozen=True)
class RawRequest:
    """What the web layer hands to the engine BEFORE cleaning."""
    src_ip: str
    method: str
    path: str
    query: dict[str, str]
    headers: list[tuple[str, str]]
    body_text: str
    decoy_id: str | None = None


@dataclass(frozen=True)
class NormalizedRequest:
    """A cleaned, safe, redacted request. Only this moves between stages."""
    request_id: str
    ts: float
    src_ip: str
    method: str
    path: str
    query: dict[str, str]
    headers: list[tuple[str, str]]  # ORDER PRESERVED, secrets redacted
    user_agent: str
    body_excerpt: str
    body_len: int
    decoy_id: str | None = None


@dataclass(frozen=True)
class Fingerprint:
    fingerprint_id: str
    version: str
    components: dict[str, Any]


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    rule_version: str
    triggered: bool
    score: float
    threshold: float
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    request_id: str
    fingerprint_id: str
    total_score: float
    severity: str  # info | low | medium | high | critical
    confidence: float
    results: list[RuleResult]
    recommended_action: str


@dataclass(frozen=True)
class Alert:
    fingerprint_id: str
    rule_id: str
    severity: str
    evidence_ids: list[str]
    recommended_action: str
    created_at: float


@dataclass(frozen=True)
class TimelineEntry:
    ts: float
    request_id: str
    method: str
    path: str
    severity: str
    total_score: float
    summary: str


RULE_IDS = ("scanner", "cred_stuffing", "enumeration", "injection", "rate_spike")
SEVERITIES = ("info", "low", "medium", "high", "critical")