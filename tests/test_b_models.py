import dataclasses

import pytest

from app.engine.models import (
    Decision, Fingerprint, NormalizedRequest, RuleResult, ValidationError,
)


def make_request():
    return NormalizedRequest(
        request_id="r1", ts=1.0, src_ip="127.0.0.1", method="GET",
        path="/admin", query={}, headers=[("host", "x")],
        user_agent="curl/8", body_excerpt="", body_len=0,
    )


def test_normalized_request_is_frozen():
    req = make_request()
    with pytest.raises(dataclasses.FrozenInstanceError):
        req.path = "/hacked"


def test_decoy_id_defaults_to_none():
    assert make_request().decoy_id is None


def test_rule_result_evidence_defaults_to_empty_dict():
    r = RuleResult("scanner", "1.0", False, 0.0, 10.0, "ok")
    assert r.evidence == {}


def test_decision_holds_results():
    r = RuleResult("scanner", "1.0", True, 80.0, 10.0, "many paths")
    d = Decision("r1", "fp-1", 80.0, "high", 0.8, [r], "block")
    assert d.results[0].rule_id == "scanner"


def test_fingerprint_fields():
    fp = Fingerprint("abc", "fp-1.0", {"ua_family": "curl"})
    assert fp.version == "fp-1.0"


def test_validation_error_is_an_exception():
    with pytest.raises(ValidationError):
        raise ValidationError("bad input")