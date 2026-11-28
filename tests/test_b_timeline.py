import pytest

from app.engine.fingerprint import compute_fingerprint
from app.engine.models import ValidationError
from app.engine.rules import evaluate_rules
from app.engine.scoring import decide
from app.engine.timeline import build_timeline, event_from
from tests.test_b_rules import make_req


def ev(rid, ts, path="/", severity="info", score=0.0, reasons=None):
    return {"ts": ts, "request_id": rid, "method": "GET", "path": path,
            "severity": severity, "total_score": score, "reasons": reasons or []}


def test_entries_sorted_by_time():
    out = build_timeline([ev("b", 105.0), ev("a", 100.0), ev("c", 110.0)])
    assert [e.request_id for e in out] == ["a", "b", "c"]


def test_equal_timestamps_keep_input_order():
    out = build_timeline([ev("x", 100.0), ev("y", 100.0)])
    assert [e.request_id for e in out] == ["x", "y"]


def test_summary_uses_reasons_or_normal_text():
    out = build_timeline([
        ev("a", 1.0),
        ev("b", 2.0, severity="high", score=60.0, reasons=["injection: 1 match", "scanner: 4 paths"]),
    ])
    assert "normal request" in out[0].summary
    assert out[1].summary == "injection: 1 match; scanner: 4 paths"
    assert out[1].severity == "high" and out[1].total_score == 60.0


def test_missing_keys_rejected():
    with pytest.raises(ValidationError):
        build_timeline([{"ts": 1.0, "request_id": "a"}])


def test_empty_input_gives_empty_timeline():
    assert build_timeline([]) == []


def test_event_from_engine_objects_round_trip():
    req = make_req("r1", 100.0, query={"id": "' OR '1'='1"})
    fp = compute_fingerprint(req, [])
    decision = decide(req, fp, evaluate_rules(req, fp, []))
    event = event_from(req, decision)
    assert event["request_id"] == "r1" and event["severity"] == decision.severity
    entry = build_timeline([event])[0]
    assert "injection" in entry.summary