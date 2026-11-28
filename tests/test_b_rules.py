import pytest

from app.engine.fingerprint import compute_fingerprint
from app.engine.models import NormalizedRequest
from app.engine.rules import DEFAULT_CONFIG, evaluate_rules, rule_injection


def make_req(rid="r1", ts=100.0, ip="10.0.0.1", method="GET", path="/admin",
             query=None, body="", ua="curl/8.0", raw_path=None):
    return NormalizedRequest(
        request_id=rid, ts=ts, src_ip=ip, method=method, path=path,
        query=query or {}, headers=[("host", "x"), ("user-agent", ua)],
        user_agent=ua, body_excerpt=body, body_len=len(body),
        raw_path=raw_path if raw_path is not None else path,
    )


def run(rule_fn, req, recent=None, rule_id="injection"):
    fp = compute_fingerprint(req, recent or [])
    return rule_fn(req, fp, recent or [], DEFAULT_CONFIG[rule_id])


# ---------- injection ----------

@pytest.mark.parametrize("query,expected", [
    ({"id": "' OR '1'='1"}, "sqli_tautology"),
    ({"q": "1 UNION SELECT user, pass FROM users"}, "sqli_union"),
    ({"q": "x'; DROP TABLE users"}, "sqli_stacked"),
    ({"q": "1 AND sleep(5)"}, "sqli_time"),
    ({"q": "<script>alert(1)</script>"}, "xss_script"),
    ({"q": "<img src=x onerror=alert(1)>"}, "xss_handler"),
    ({"q": "javascript:alert(1)"}, "xss_js_uri"),
    ({"f": "x; cat /etc/hosts"}, "cmd_injection"),
])
def test_injection_detected_in_query(query, expected):
    res = run(rule_injection, make_req(query=query))
    assert res.triggered
    assert expected in [m["pattern"] for m in res.evidence["matches"]]


def test_injection_detects_traversal_in_raw_path():
    req = make_req(path="/etc/passwd", raw_path="/a/../../etc/passwd")
    res = run(rule_injection, req)
    assert res.triggered
    assert any(m["pattern"] == "path_traversal" and m["where"] == "path" for m in res.evidence["matches"])


def test_injection_detected_in_body():
    res = run(rule_injection, make_req(method="POST", body="user=a' OR 1=1 --"))
    assert res.triggered
    assert res.evidence["matches"][0]["where"] == "body"


@pytest.mark.parametrize("path,query", [
    ("/api/v1/users/12", {}),
    ("/wp-login.php", {"redirect_to": "/dashboard"}),
    ("/search", {"q": "order=asc", "name": "Alex O'Brien"}),
    ("/admin", {"sort": "name", "note": "select the best color"}),
])
def test_injection_benign_not_triggered(path, query):
    res = run(rule_injection, make_req(path=path, query=query))
    assert not res.triggered
    assert res.score == 0.0


def test_injection_result_is_explainable():
    res = run(rule_injection, make_req(query={"id": "' OR '1'='1"}))
    assert res.rule_id == "injection" and res.rule_version == "1.0"
    assert res.threshold == 1.0
    assert "sqli_tautology in query:id" in res.reason and "threshold=1" in res.reason
    assert res.evidence["request_ids"] == ["r1"]


def test_more_categories_raise_score():
    one = run(rule_injection, make_req(query={"q": "' OR '1'='1"}))
    two = run(rule_injection, make_req(query={"q": "' OR '1'='1", "r": "<script>"}))
    assert two.score > one.score


# ---------- evaluate_rules ----------

def test_evaluate_rules_skips_disabled_rules():
    cfg = {k: dict(v) for k, v in DEFAULT_CONFIG.items()}
    cfg["injection"]["enabled"] = False
    req = make_req(query={"id": "' OR '1'='1"})
    results = evaluate_rules(req, compute_fingerprint(req, []), [], cfg)
    assert "injection" not in [r.rule_id for r in results]


def test_evaluate_rules_uses_threshold_from_config():
    cfg = {k: dict(v) for k, v in DEFAULT_CONFIG.items()}
    cfg["injection"]["threshold"] = 3.0
    req = make_req(query={"id": "' OR '1'='1"})
    res = [r for r in evaluate_rules(req, compute_fingerprint(req, []), [], cfg) if r.rule_id == "injection"][0]
    assert not res.triggered and res.threshold == 3.0