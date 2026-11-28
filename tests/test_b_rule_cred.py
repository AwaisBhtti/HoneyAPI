from app.engine.rules import extract_username, is_login_path, rule_cred_stuffing
from tests.test_b_rules import make_req, run


def login_posts(n, usernames=None, path="/wp-login.php", start=100.0, step=1.0, ip="10.0.0.1"):
    out = []
    for i in range(n):
        user = usernames[i] if usernames else f"user{i}"
        body = f"log={user}&pwd=[REDACTED]"
        out.append(make_req(f"h{i}", start + i * step, ip=ip, method="POST", path=path, body=body))
    return out


def current_post(ts, user="current", path="/wp-login.php", ip="10.0.0.1", body=None):
    return make_req("cur", ts, ip=ip, method="POST", path=path, body=body or f"log={user}&pwd=[REDACTED]")


def test_triggers_at_threshold_with_many_usernames():
    res = run(rule_cred_stuffing, current_post(107.0), login_posts(7), "cred_stuffing")
    assert res.triggered
    assert "8 login POST(s) with 8 distinct username(s)" in res.reason
    assert "credential stuffing" in res.reason and "threshold=8" in res.reason
    assert res.evidence["distinct_usernames"] == 8


def test_not_triggered_below_threshold():
    res = run(rule_cred_stuffing, current_post(106.0), login_posts(6), "cred_stuffing")
    assert not res.triggered and res.score == 0.0


def test_same_username_repeated_is_brute_force():
    recent = login_posts(7, usernames=["admin"] * 7)
    res = run(rule_cred_stuffing, current_post(107.0, user="admin"), recent, "cred_stuffing")
    assert res.triggered and "brute force" in res.reason


def test_json_login_body_username_extracted():
    assert extract_username('{"username": "bob", "password": "[REDACTED]"}') == "bob"
    assert extract_username("log=admin&pwd=[REDACTED]") == "admin"
    assert extract_username("nothing here") is None


def test_get_requests_are_not_login_attempts():
    recent = [make_req(f"g{i}", 100.0 + i, path="/wp-login.php") for i in range(10)]
    res = run(rule_cred_stuffing, make_req("cur", 111.0, path="/wp-login.php"), recent, "cred_stuffing")
    assert not res.triggered


def test_posts_to_non_login_paths_are_ignored():
    recent = login_posts(10, path="/api/v1/comments")
    res = run(rule_cred_stuffing, current_post(111.0, path="/api/v1/comments"), recent, "cred_stuffing")
    assert not res.triggered


def test_requests_outside_window_are_ignored():
    recent = login_posts(10, start=0.0)
    res = run(rule_cred_stuffing, current_post(100.0), recent, "cred_stuffing")
    assert not res.triggered


def test_other_actors_are_ignored():
    res = run(rule_cred_stuffing, current_post(107.0), login_posts(10, ip="9.9.9.9"), "cred_stuffing")
    assert not res.triggered


def test_usernames_not_stored_in_evidence():
    res = run(rule_cred_stuffing, current_post(107.0), login_posts(7), "cred_stuffing")
    assert "user0" not in str(res.evidence)


def test_login_path_helper():
    assert is_login_path("/wp-login.php") and is_login_path("/api/v1/login/")
    assert not is_login_path("/api/v1/users")