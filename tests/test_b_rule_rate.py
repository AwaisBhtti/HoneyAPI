from app.engine.rules import rule_rate_spike
from tests.test_b_rules import make_req, run


def burst(n, start=100.0, step=0.5, ip="10.0.0.1", path="/"):
    return [make_req(f"h{i}", start + i * step, ip=ip, path=path) for i in range(n)]


def test_triggers_at_threshold():
    res = run(rule_rate_spike, make_req("cur", 104.5), burst(9), "rate_spike")
    assert res.triggered
    assert "10 request(s)" in res.reason and "threshold=10" in res.reason
    assert res.evidence["request_count"] == 10 and res.evidence["rate_per_s"] == 1.0


def test_below_threshold_not_triggered():
    res = run(rule_rate_spike, make_req("cur", 104.0), burst(8), "rate_spike")
    assert not res.triggered and res.score == 0.0


def test_slow_traffic_not_triggered():
    slow = burst(20, step=5.0)  # one request every 5s
    res = run(rule_rate_spike, make_req("cur", 200.0), slow, "rate_spike")
    assert not res.triggered


def test_bigger_burst_scores_higher():
    small = run(rule_rate_spike, make_req("cur", 104.5), burst(9), "rate_spike")
    big = run(rule_rate_spike, make_req("cur", 104.5), burst(19), "rate_spike")
    assert big.score > small.score


def test_other_actors_ignored():
    res = run(rule_rate_spike, make_req("cur", 104.5), burst(15, ip="9.9.9.9"), "rate_spike")
    assert not res.triggered


def test_any_path_counts():
    recent = [make_req(f"h{i}", 100.0 + i * 0.3, path=f"/p{i}") for i in range(9)]
    res = run(rule_rate_spike, make_req("cur", 103.0, path="/other"), recent, "rate_spike")
    assert res.triggered