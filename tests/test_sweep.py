import json
from pathlib import Path

import pytest

from keyhole.sweep import MAX_TEXT_CHARS, SweepError, swept

VECTORS = json.loads(
    (Path(__file__).parents[1] / "vectors" / "sweep.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: repr(c["input"])[:30])
def test_sweep_vectors(case):
    assert swept(case["input"]) == case["expected"]


@pytest.mark.parametrize("raw", VECTORS["refused"], ids=repr)
def test_sweep_refuses_invisible_only(raw):
    with pytest.raises(SweepError):
        swept(raw)


def test_sweep_refuses_over_cap():
    with pytest.raises(SweepError):
        swept("x" * (MAX_TEXT_CHARS + 1))


def test_sweep_cap_boundary():
    assert len(swept("x" * MAX_TEXT_CHARS)) == MAX_TEXT_CHARS
