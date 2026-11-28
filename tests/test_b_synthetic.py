import pytest

from app.engine.synthetic import KINDS, generate_synthetic_record


@pytest.mark.parametrize("kind", KINDS)
def test_same_seed_gives_same_record(kind):
    assert generate_synthetic_record(kind, 5) == generate_synthetic_record(kind, 5)


@pytest.mark.parametrize("kind", KINDS)
def test_different_seed_gives_different_record(kind):
    assert generate_synthetic_record(kind, 5) != generate_synthetic_record(kind, 6)


@pytest.mark.parametrize("kind", KINDS)
def test_record_is_tagged_synthetic_with_tripwire(kind):
    rec = generate_synthetic_record(kind, 1)
    assert rec["synthetic"] is True
    assert rec["tripwire_tag"].startswith("HNY-")


def test_user_email_uses_fake_domain():
    assert generate_synthetic_record("user", 3)["email"].endswith("@example.test")


def test_secrets_are_marked_fake():
    assert generate_synthetic_record("token", 1)["token"].startswith("FAKE-")
    assert generate_synthetic_record("credential", 1)["password"].startswith("FAKE-")


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        generate_synthetic_record("bitcoin_wallet", 1)