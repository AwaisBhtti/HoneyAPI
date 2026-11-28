from app.engine.rules import DEFAULT_CONFIG, is_sensitive_path, rule_scanner
from tests.test_b_rules import make_req, run

SENSITIVE = ["/.env", "/admin", "/wp-login.php", "/backup.zip", "/phpmyadmin"]


def history(paths, start=100.0, step=1.0, ip="10.0.0.1", ua="curl/8.0"):
    return [make_req(f"h{i}", start + i * step, ip=ip, path=p, ua=ua) for i, p in enumerate(paths)]


def test_scanner_triggers_on_many_distinct_sensitive_paths():
    recent = history(SENSITIVE[:3])
    current = make_req("cur", 103.0, path=SENSITIVE[3])
    res = run(rule_scanner, current, recent, "scanner")
    assert res.triggered
    assert "4 distinct sensitive path(s)" in res.reason and "threshold=4" in res.reason
    assert len(res.evidence["paths"]) == 4


def test_scanner_not_triggered_below_threshold():
    recent = history(SENSITIVE[:2])
    res = run(rule_scanner, make_req("cur", 102.0, path=SENSITIVE[2]), recent, "scanner")
    assert not res.triggered and res.score == 0.0


def test_repeating_same_path_does_not_count_as_distinct():
    recent = history(["/admin"] * 6)
    res = run(rule_scanner, make_req("cur", 107.0, path="/admin"), recent, "scanner")
    assert not res.triggered


def test_scanner_triggers_on_known_scanner_user_agent():
    res = run(rule_scanner, make_req(path="/", ua="sqlmap/1.7#stable"), [], "scanner")
    assert res.triggered and res.score >= 80
    assert res.evidence["scanner_ua"] == "sqlmap"


def test_old_requests_outside_window_are_ignored():
    recent = history(SENSITIVE[:3], start=0.0)  # ~100s before current, window is 60s
    res = run(rule_scanner, make_req("cur", 100.0, path=SENSITIVE[3]), recent, "scanner")
    assert not res.triggered


def test_other_actors_are_ignored():
    recent = history(SENSITIVE[:3], ip="9.9.9.9")
    res = run(rule_scanner, make_req("cur", 103.0, path=SENSITIVE[3]), recent, "scanner")
    assert not res.triggered


def test_normal_browsing_is_not_scanning():
    recent = history(["/", "/about", "/products", "/contact"])
    res = run(rule_scanner, make_req("cur", 104.0, path="/blog"), recent, "scanner")
    assert not res.triggered


def test_sensitive_path_helper():
    assert is_sensitive_path("/.git/config")
    assert is_sensitive_path("/ADMIN/")
    assert not is_sensitive_path("/products")