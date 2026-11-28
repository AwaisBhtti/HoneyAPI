"""Generate the safe HoneyAPI evaluation fixtures (Role B).

Run from the project root:   python tools/make_fixtures.py

Every line is inert test data for localhost replay. Extra fields:
  t     seconds offset (used by the offline evaluator; live replay ignores it)
  label "benign" or "malicious" (used for FP/FN measurement)
  case  which evaluation case the line belongs to
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "fixtures"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) HoneyAPI-Fixture/1.0"


def line(t, method, path, ip, ua, label, case, query=None, headers=None, body=""):
    d = {"t": t, "method": method, "path": path, "sim_ip": ip, "sim_ua": ua,
         "label": label, "case": case}
    if query:
        d["query"] = query
    if headers:
        d["headers"] = headers
    if body:
        d["body"] = body
    return d


def write(name, lines):
    lines = sorted(lines, key=lambda d: d["t"])
    (OUT / name).write_text("".join(json.dumps(d) + "\n" for d in lines), encoding="utf-8")
    print(f"wrote {name}: {len(lines)} lines")


def normal():
    out = []
    plan = {
        "10.1.0.1": ["/", "/about", "/products"],
        "10.1.0.2": ["/", "/contact", "/products"],
        "10.1.0.3": ["/", "/blog", "/about"],
        "10.1.0.4": ["/", "/products", "/blog"],
    }
    for n, (ip, paths) in enumerate(plan.items()):
        for i, p in enumerate(paths):
            out.append(line(n * 3 + i * 20.0, "GET", p, ip, BROWSER, "benign", "Baseline"))
    out.append(line(61.0, "POST", "/wp-login.php", "10.1.0.2", BROWSER, "benign", "Baseline",
                    body="log=alice&pwd=fixture-not-a-real-password"))
    out.append(line(70.0, "GET", "/search", "10.1.0.3", BROWSER, "benign", "Baseline",
                    query={"q": "O'Brien order=asc"}))
    out.append(line(75.0, "GET", "/api/v1/users", "10.1.0.4", BROWSER, "benign", "Baseline"))
    return out


def t1_scanner():
    out = []
    paths = ["/", "/.env", "/admin", "/wp-login.php", "/backup.zip", "/phpmyadmin", "/.git/config"]
    for i, p in enumerate(paths):
        out.append(line(i * 0.5, "GET", p, "10.2.0.5", "curl/8.5.0", "malicious", "T1"))
    for i, p in enumerate(["/", "/cgi-bin/test", "/admin"]):
        out.append(line(10 + i * 0.5, "GET", p, "10.2.0.9", "Mozilla/5.00 (Nikto/2.5.0)", "malicious", "T1"))
    return out


def t2_credstuff():
    return [line(i * 1.5, "POST", "/wp-login.php", "10.3.0.7", "python-requests/2.31.0",
                 "malicious", "T2", body=f"log=user{i:02d}&pwd=FakePass{i}!") for i in range(12)]


def t3_enum():
    return [line(i * 1.5, "GET", f"/api/v1/users/{i}", "10.4.0.3", "Go-http-client/1.1",
                 "malicious", "T3") for i in range(1, 11)]


def t4_injection():
    ua = "curl/8.5.0"
    ip = "10.5.0.8"
    out = [
        line(0, "GET", "/api/v1/users", ip, ua, "malicious", "T4", query={"id": "' OR '1'='1"}),
        line(3, "GET", "/search", ip, ua, "malicious", "T4",
             query={"q": "1 UNION SELECT username, password FROM users"}),
        line(6, "GET", "/search", ip, ua, "malicious", "T4", query={"q": "<script>alert(1)</script>"}),
        line(9, "GET", "/files/../../etc/passwd", ip, ua, "malicious", "T4"),
        line(12, "POST", "/api/v1/login", ip, ua, "malicious", "T4",
             body='{"username": "admin\' --", "password": "x"}'),
        line(15, "GET", "/ping", ip, ua, "malicious", "T4", query={"host": "127.0.0.1; cat /etc/passwd"}),
        line(2, "GET", "/search", "10.5.0.20", BROWSER, "benign", "T4", query={"q": "shoes"}),
        line(8, "GET", "/products", "10.5.0.20", BROWSER, "benign", "T4"),
    ]
    return out


def t5_ratespike():
    return [line(i * 0.2, "GET", "/", "10.6.0.2", "ApacheBench/2.3", "malicious", "T5") for i in range(30)]


def t6_privacy():
    ip, ua = "10.7.0.4", BROWSER
    return [
        line(0, "GET", "/api/v1/users", ip, ua, "benign", "T6",
             headers={"Authorization": "Bearer FAKE-bearer-token-ABC123"},
             query={"token": "FAKE-query-token-XYZ789"}),
        line(10, "POST", "/wp-login.php", ip, ua, "benign", "T6",
             body="log=privacy_test&pwd=FAKE-form-password-111"),
        line(20, "POST", "/api/v1/login", ip, ua, "benign", "T6",
             body='{"username": "t6user", "password": "FAKE-json-password-222"}'),
        line(30, "GET", "/admin", ip, ua, "benign", "T6",
             headers={"Cookie": "session=FAKE-cookie-value-333", "X-API-Key": "FAKE-api-key-444"}),
    ]


def malformed():
    raw = [
        json.dumps({"method": "GET", "path": "/ok"}),
        "this is not json",
        "[1, 2, 3]",
        json.dumps({"method": "HACK", "path": "/x"}),
        json.dumps({"method": "GET", "path": "no-leading-slash"}),
        json.dumps({"method": "GET", "path": "/" + "a" * 3000}),
    ]
    (OUT / "malformed.jsonl").write_text("\n".join(raw) + "\n", encoding="utf-8")
    print(f"wrote malformed.jsonl: {len(raw)} lines")


def expected():
    data = {
        "normal.jsonl": {"case": "Baseline", "expected_rules": [], "expect_alert": False},
        "t1_scanner.jsonl": {"case": "T1", "expected_rules": ["scanner"], "expect_alert": True},
        "t2_credstuff.jsonl": {"case": "T2", "expected_rules": ["cred_stuffing"], "expect_alert": True},
        "t3_enum.jsonl": {"case": "T3", "expected_rules": ["enumeration"], "expect_alert": True},
        "t4_injection.jsonl": {"case": "T4", "expected_rules": ["injection"], "expect_alert": True},
        "t5_ratespike.jsonl": {"case": "T5", "expected_rules": ["rate_spike"], "expect_alert": True},
        "t6_privacy.jsonl": {
            "case": "T6", "expected_rules": [], "expect_alert": False,
            "forbidden_strings": [
                "FAKE-bearer-token-ABC123", "FAKE-query-token-XYZ789", "FAKE-form-password-111",
                "FAKE-json-password-222", "FAKE-cookie-value-333", "FAKE-api-key-444",
            ],
        },
        "malformed.jsonl": {"case": "T-final", "expect_reject_lines": [2, 3, 4, 5, 6]},
    }
    (OUT / "expected.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("wrote expected.json")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    write("normal.jsonl", normal())
    write("t1_scanner.jsonl", t1_scanner())
    write("t2_credstuff.jsonl", t2_credstuff())
    write("t3_enum.jsonl", t3_enum())
    write("t4_injection.jsonl", t4_injection())
    write("t5_ratespike.jsonl", t5_ratespike())
    write("t6_privacy.jsonl", t6_privacy())
    malformed()
    expected()