from app.engine.fingerprint import compute_fingerprint, timing_bucket, ua_family
from app.engine.models import NormalizedRequest


def req(rid="r1", ts=100.0, ip="10.0.0.1", path="/admin", ua="curl/8.0",
        header_names=("host", "user-agent", "accept")):
    headers = [(n, ua if n == "user-agent" else "x") for n in header_names]
    return NormalizedRequest(
        request_id=rid, ts=ts, src_ip=ip, method="GET", path=path, query={},
        headers=headers, user_agent=ua, body_excerpt="", body_len=0,
    )


def test_same_tool_twice_matches():
    a = compute_fingerprint(req("r1", 100.0), [])
    b = compute_fingerprint(req("r2", 105.0, path="/.env"), [])
    assert a.fingerprint_id == b.fingerprint_id


def test_different_tools_differ():
    curl = compute_fingerprint(req(ua="curl/8.0"), [])
    sqlmap = compute_fingerprint(req(ua="sqlmap/1.7", header_names=("user-agent", "host")), [])
    assert curl.fingerprint_id != sqlmap.fingerprint_id


def test_same_tool_different_ip_differs():
    a = compute_fingerprint(req(ip="10.0.0.1"), [])
    b = compute_fingerprint(req(ip="10.0.0.2"), [])
    assert a.fingerprint_id != b.fingerprint_id


def test_header_order_changes_fingerprint():
    a = compute_fingerprint(req(header_names=("host", "user-agent", "accept")), [])
    b = compute_fingerprint(req(header_names=("accept", "host", "user-agent")), [])
    assert a.fingerprint_id != b.fingerprint_id


def test_id_format_and_version():
    fp = compute_fingerprint(req(), [])
    assert fp.fingerprint_id.startswith("fp-") and len(fp.fingerprint_id) == 15
    assert fp.version == "fp-1.0"


def test_deterministic():
    assert compute_fingerprint(req(), []) == compute_fingerprint(req(), [])


def test_ua_families():
    assert ua_family("sqlmap/1.7#stable") == "sqlmap"
    assert ua_family("Mozilla/5.0 (X11)") == "browser"
    assert ua_family("") == "empty"
    assert ua_family("weird-bot") == "other"


def test_timing_buckets():
    assert timing_bucket(None) == "first"
    assert timing_bucket(0.05) == "burst"
    assert timing_bucket(0.5) == "fast"
    assert timing_bucket(3) == "normal"
    assert timing_bucket(30) == "slow"


def test_timing_uses_same_ip_history_only():
    other_ip = req("r0", 99.95, ip="9.9.9.9")
    same_ip = req("r0b", 99.9, ip="10.0.0.1")
    fp = compute_fingerprint(req("r1", 100.0), [other_ip, same_ip])
    assert fp.components["timing_bucket"] == "burst"
    fp2 = compute_fingerprint(req("r1", 100.0), [other_ip])
    assert fp2.components["timing_bucket"] == "first"


def test_path_sequence_changes_with_history_but_not_identity():
    first = compute_fingerprint(req("r1", 100.0, path="/a"), [])
    second = compute_fingerprint(req("r2", 101.0, path="/a"), [req("r1", 100.0, path="/z")])
    assert first.components["path_seq_hash"] != second.components["path_seq_hash"]
    assert first.fingerprint_id == second.fingerprint_id