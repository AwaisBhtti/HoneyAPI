from app.engine.alerts import maybe_alert
from app.engine.models import Alert, Decision, RuleResult


def result(rule_id="scanner", score=50.0, triggered=True, ids=("r1",)):
    return RuleResult(rule_id, "1.0", triggered, score if triggered else 0.0, 4.0, "why",
                      {"request_ids": list(ids)})


def decision(severity="medium", results=None, fp="fp-1", rid="r9"):
    results = results if results is not None else [result()]
    return Decision(rid, fp, 50.0, severity, 0.7, results, "review")


def old_alert(created_at, rule_id="scanner", severity="medium", fp="fp-1"):
    return Alert(fp, rule_id, severity, ["r1"], "review", created_at)


def test_low_severity_makes_no_alert():
    assert maybe_alert(decision("low"), [], now=1000.0) is None
    assert maybe_alert(decision("info", results=[result(triggered=False)]), [], now=1000.0) is None


def test_medium_severity_makes_alert_with_evidence():
    a = maybe_alert(decision("medium", [result(ids=("r1", "r2"))]), [], now=1000.0)
    assert a is not None
    assert a.rule_id == "scanner" and a.severity == "medium" and a.created_at == 1000.0
    assert a.evidence_ids == ["r1", "r2", "r9"]
    assert a.recommended_action == "review"


def test_top_scoring_rule_names_the_alert():
    d = decision("high", [result("scanner", 50.0), result("injection", 80.0)])
    assert maybe_alert(d, [], now=1000.0).rule_id == "injection"


def test_duplicate_within_window_suppressed():
    assert maybe_alert(decision(), [old_alert(980.0)], now=1000.0) is None


def test_duplicate_after_window_allowed():
    assert maybe_alert(decision(), [old_alert(900.0)], now=1000.0) is not None


def test_escalation_within_window_allowed():
    a = maybe_alert(decision("high"), [old_alert(980.0, severity="medium")], now=1000.0)
    assert a is not None and a.severity == "high"


def test_different_rule_or_actor_not_deduped():
    assert maybe_alert(decision(), [old_alert(980.0, rule_id="injection")], now=1000.0) is not None
    assert maybe_alert(decision(), [old_alert(980.0, fp="fp-other")], now=1000.0) is not None


def test_rate_limit_caps_alerts_per_actor():
    flood = [old_alert(900.0 + i, rule_id=f"r{i}") for i in range(5)]
    assert maybe_alert(decision("high"), flood, now=1000.0) is None


def test_rate_limit_window_expires():
    flood = [old_alert(0.0 + i, rule_id=f"r{i}") for i in range(5)]
    assert maybe_alert(decision("high"), flood, now=1000.0) is not None


def test_config_overrides_min_severity():
    assert maybe_alert(decision("low"), [], {"min_severity": "low"}, now=1000.0) is not None