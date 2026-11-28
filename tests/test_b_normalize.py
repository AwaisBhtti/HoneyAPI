import pytest

from app.engine.models import RawRequest, ValidationError
from app.engine.normalize import normalize_request


def make_raw(**over):
    base = dict(
        src_ip="10.0.0.1", method="get", path="/admin", query={},
        headers=[("Host", "x"), ("User-Agent", "curl/8.0"), ("Accept", "*/*")],
        body_text="", decoy_id=None,
    )
    base.update(over)
    return RawRequest(**base)


def test_basic_request_is_cleaned():
    n = normalize_request(make_raw())
    assert n.method == "GET"
    assert n.path == "/admin"
    assert n.user_agent == "curl/8.0"
    assert n.request_id


def test_bad_method_rejected():
    with pytest.raises(ValidationError):
        normalize_request(make_raw(method="HACK"))


def test_path_must_start_with_slash():
    with pytest.raises(ValidationError):
        normalize_request(make_raw(path="admin"))


def test_path_too_long_rejected():
    with pytest.raises(ValidationError):
        normalize_request(make_raw(path="/" + "a" * 3000))


def test_dot_segments_removed_but_raw_path_keeps_them():
    n = normalize_request(make_raw(path="/a/b/../../etc/passwd"))
    assert n.path == "/etc/passwd"
    assert ".." in n.raw_path


def test_path_decoded_only_once():
    n = normalize_request(make_raw(path="/x%2527"))
    assert n.raw_path == "/x%27"


def test_header_order_preserved_and_lowercased():
    n = normalize_request(make_raw())
    assert [k for k, _ in n.headers] == ["host", "user-agent", "accept"]


def test_authorization_and_cookie_redacted():
    n = normalize_request(make_raw(headers=[
        ("Authorization", "Bearer abc123"), ("Cookie", "s=1"), ("User-Agent", "x")]))
    assert dict(n.headers)["authorization"] == "[REDACTED]"
    assert dict(n.headers)["cookie"] == "[REDACTED]"


def test_form_body_password_redacted():
    n = normalize_request(make_raw(method="POST", body_text="username=a&password=hunter2"))
    assert "hunter2" not in n.body_excerpt


def test_json_body_password_redacted():
    n = normalize_request(make_raw(method="POST", body_text='{"user": "a", "password": "hunter2"}'))
    assert "hunter2" not in n.body_excerpt
    assert '"user": "a"' in n.body_excerpt


def test_query_secret_redacted_and_truncated():
    n = normalize_request(make_raw(query={"token": "abc", "q": "z" * 999}))
    assert n.query["token"] == "[REDACTED]"
    assert len(n.query["q"]) == 256


def test_body_excerpt_capped_and_len_reported():
    n = normalize_request(make_raw(method="POST", body_text="a" * 5000))
    assert len(n.body_excerpt) == 1024
    assert n.body_len == 5000


def test_control_characters_made_visible():
    n = normalize_request(make_raw(path="/a%00b"))
    assert "\x00" not in n.raw_path and "\\x00" in n.raw_path


def test_sql_injection_string_is_kept_inert():
    n = normalize_request(make_raw(query={"id": "' OR '1'='1"}))
    assert n.query["id"] == "' OR '1'='1"


def test_deterministic_timestamp_when_given():
    assert normalize_request(make_raw(), now=123.0).ts == 123.0