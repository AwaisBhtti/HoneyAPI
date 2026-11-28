from app.engine.rules import longest_sequential_run, rule_enumeration, split_id_path
from tests.test_b_rules import make_req, run


def id_requests(ids, parent="/api/v1/users", start=100.0, step=1.0, ip="10.0.0.1"):
    return [make_req(f"h{i}", start + i * step, ip=ip, path=f"{parent}/{n}") for i, n in enumerate(ids)]


def current(n, ts, parent="/api/v1/users", ip="10.0.0.1"):
    return make_req("cur", ts, ip=ip, path=f"{parent}/{n}")


def test_sequential_ids_trigger_at_threshold():
    res = run(rule_enumeration, current(5, 104.0), id_requests([1, 2, 3, 4]), "enumeration")
    assert res.triggered
    assert "5 distinct ID(s) under /api/v1/users" in res.reason
    assert "longest sequential run 5" in res.reason and "threshold=5" in res.reason
    assert res.evidence["id_range"] == [1, 5]


def test_below_threshold_not_triggered():
    res = run(rule_enumeration, current(4, 103.0), id_requests([1, 2, 3]), "enumeration")
    assert not res.triggered and res.score == 0.0


def test_same_id_repeated_is_not_enumeration():
    res = run(rule_enumeration, current(7, 110.0), id_requests([7] * 9), "enumeration")
    assert not res.triggered


def test_random_ids_trigger_but_score_lower_than_sequential():
    rand = run(rule_enumeration, current(150, 104.0), id_requests([3, 17, 42, 99]), "enumeration")
    seq = run(rule_enumeration, current(5, 104.0), id_requests([1, 2, 3, 4]), "enumeration")
    assert rand.triggered and rand.evidence["longest_sequential_run"] == 1
    assert seq.score > rand.score


def test_ids_under_different_parents_are_not_mixed():
    recent = id_requests([1, 2], parent="/api/v1/users") + id_requests([3, 4], parent="/api/v1/orders", start=102.0)
    res = run(rule_enumeration, current(9, 105.0, parent="/api/v1/items"), recent, "enumeration")
    assert not res.triggered


def test_non_numeric_paths_ignored():
    recent = [make_req(f"h{i}", 100.0 + i, path=f"/page/{name}") for i, name in enumerate("abcdef")]
    res = run(rule_enumeration, make_req("cur", 107.0, path="/page/g"), recent, "enumeration")
    assert not res.triggered and res.evidence["distinct_ids"] == 0


def test_old_requests_outside_window_ignored():
    res = run(rule_enumeration, current(5, 100.0), id_requests([1, 2, 3, 4], start=0.0), "enumeration")
    assert not res.triggered


def test_other_actors_ignored():
    res = run(rule_enumeration, current(5, 104.0), id_requests([1, 2, 3, 4], ip="9.9.9.9"), "enumeration")
    assert not res.triggered


def test_helpers():
    assert split_id_path("/api/v1/users/42") == ("/api/v1/users", 42)
    assert split_id_path("/api/v1/users") is None
    assert longest_sequential_run([5, 1, 2, 3, 9]) == 3
    assert longest_sequential_run([]) == 0