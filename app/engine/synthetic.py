"""FR-2 synthetic data for decoy responses (Role B).

Deterministic by seed, obviously fake, and tagged with a tripwire tag so any
later use of this data can be traced back to the decoy. Pure Python.
"""
from __future__ import annotations

import random
from typing import Any

KINDS = ("user", "token", "credential")

_FIRST = ["alex", "sam", "jordan", "taylor", "casey", "morgan", "riley", "jamie"]
_LAST = ["stone", "rivera", "khan", "meyer", "ito", "silva", "novak", "frost"]
_ROLES = ["editor", "support", "billing", "intern"]


def _tripwire(rng: random.Random) -> str:
    return "HNY-" + "".join(rng.choice("0123456789abcdef") for _ in range(8))


def generate_synthetic_record(kind: str, seed: int) -> dict[str, Any]:
    if kind not in KINDS:
        raise ValueError(f"unknown synthetic kind: {kind}")

    rng = random.Random(f"{kind}:{seed}")
    tag = _tripwire(rng)
    record: dict[str, Any] = {"synthetic": True, "kind": kind, "tripwire_tag": tag}

    if kind == "user":
        first, last = rng.choice(_FIRST), rng.choice(_LAST)
        record.update({
            "id": seed,
            "username": f"{first}.{last}",
            "email": f"{first}.{last}@example.test",
            "role": rng.choice(_ROLES),
        })
    elif kind == "token":
        record.update({"token": f"FAKE-{tag}-" + "".join(rng.choice("0123456789abcdef") for _ in range(16))})
    else:  # credential
        record.update({
            "username": f"svc_{rng.choice(_LAST)}",
            "password": f"FAKE-{tag}-{rng.randint(1000, 9999)}",
            "host": "db.example.test",
        })
    return record