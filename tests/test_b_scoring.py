import pytest

from app.engine.fingerprint import compute_fingerprint
from app.engine.models import RuleResult
from app.engine.scoring import decide, explain, severity_for
from tests.test_b_rules import make_req


def rr(rule_id="scanner", triggered=True, score=50.0, reason="because"):
    return RuleResult(rule_id, "1.0", triggered, score if triggered else 0.0, 4.0, reason, {})


def do_decide(results):
    req = make_req()
    return decide(req, compute_fingerprint(req, []), results)


def test_nothing_triggered_is_info():
    d = do_decide([rr(triggered=False), rr("injection", triggered=False)])
    assert d.total_score == 0.0 and d.severity == "info"
    assert d.confidence == 0.6 and d.recommended_action == "monitor"


def test_single_rule_uses_its_score():
    d = do_decide([rr(score=50.0), rr("injection", triggered=False)])
    assert d.total_score == 50.0 and d.severity == "medium"
    assert d.recommended_action == "review"


def test_extra_triggered_rules_add_bonus_and_confidence():
    one = do_decide([rr(score=50.0)])
    two = do_decide([rr(score=50.0), rr("rate_spike", score=40.0)])
    assert two.total_score == 60.0 and two.severity == "high"
    assert two.confidence > one.confidence


def test_total_score_capped_at_100():
    d = do_decide([rr(score=95.0), rr("a", score=90.0), rr("b", score=90.0)])
    assert d.total_score == 100.0 and d.severity == "critical"
    assert d.recommended_action == "recommend_block"


def test_confidence_capped():
    d = do_decide([rr(score=100.0)] + [rr(f"r{i}", score=100.0) for i in range(5)])
    assert d.confidence == 0.95


@pytest.mark.parametrize("score,expected", [
    (0, "info"), (10, "low"), (29.9, "low"), (30, "medium"), (54.9, "medium"),
    (55, "high"), (79.9, "high"), (80, "critical"), (100, "critical"),
])
def test_severity_bands(score, expected):
    assert severity_for(score) == expected


def test_decision_carries_ids_and_all_results():
    results = [rr(), rr("injection", triggered=False)]
    d = do_decide(results)
    assert d.request_id == "r1" and d.fingerprint_id.startswith("fp-")
    assert len(d.results) == 2


def test_explain_lists_triggered_reasons():
    text = explain(do_decide([rr(reason="4 distinct sensitive paths"), rr("injection", triggered=False)]))
    assert "MEDIUM" in text and "[scanner v1.0] 4 distinct sensitive paths" in text
    assert "injection" not in text


def test_explain_when_clean():
    assert "No rule triggered" in explain(do_decide([rr(triggered=False)]))