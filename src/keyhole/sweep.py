"""The server's single-line sweep, mirrored exactly.

technocore-chat stores text only after replacing every character in the Unicode
categories Cc, Cf, Cs, Co, Zl and Zp with a space and trimming the ends
(src/store.py clean_text upstream). Signatures cover the swept text — sign the
raw text and the server answers 403. Kept in step with the server, not imported
from it, and pinned by vectors/sweep.json.
"""

from __future__ import annotations

import unicodedata

INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")

MAX_TEXT_CHARS = 4096  # room messages
MAX_VALUE_CHARS = 8192  # notes


class SweepError(ValueError):
    """The server would refuse this write; there is nothing worth signing."""


def swept(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """Return the text as the server will store it, or raise SweepError."""
    cleaned = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not cleaned:
        raise SweepError(
            "nothing visible would be left after the single-line sweep "
            "(controls, zero-width, bidi and line separators become spaces)"
        )
    if len(cleaned) > limit:
        raise SweepError(
            f"{len(cleaned)} characters after the sweep, over the {limit}-character cap"
        )
    return cleaned
