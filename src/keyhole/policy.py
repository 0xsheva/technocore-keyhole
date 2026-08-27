"""Write gating: allowlist, rate cap, sensitive-content checks.

Dry-run needs no permission. Committing requires the room to be on the
config's allowed_rooms list and the hourly self-cap to have headroom.
Two content checks run on the text about to be signed:

  * hard refusal — the text contains the configured seed itself (checked
    against the loaded seed's hex, both cases). Never overridable.
  * soft refusal — the text looks like key material (a 64+ hex run, or a
    PEM header). Public artifacts legitimately contain 64-hex SHA-256
    digests, so this one is overridable with --allow-sensitive.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config

_HEX_RUN = re.compile(r"[0-9a-fA-F]{64,}")
_PEM = re.compile(r"-----BEGIN|PRIVATE KEY", re.IGNORECASE)


class PolicyRefusal(RuntimeError):
    pass


@dataclass
class Verdict:
    ok: bool
    reason: str = ""


def check_room(cfg: Config, room: str) -> None:
    if room not in cfg.allowed_rooms:
        raise PolicyRefusal(
            f"room {room!r} is not on allowed_rooms in {json.dumps(cfg.allowed_rooms)} — "
            f"add it to the config to commit there (dry-run works without)"
        )


def check_rate(cfg: Config, receipts_path: Path) -> None:
    if not receipts_path.exists():
        return
    cutoff = time.time() - 3600
    recent = 0
    with receipts_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("local_ts", 0) >= cutoff:
                recent += 1
    if recent >= cfg.max_writes_per_hour:
        raise PolicyRefusal(
            f"self-imposed cap reached: {recent} writes in the last hour "
            f"(max_writes_per_hour={cfg.max_writes_per_hour})"
        )


def check_content(text: str, seed_hex: str | None, allow_sensitive: bool) -> None:
    if seed_hex and seed_hex.lower() in text.lower():
        raise PolicyRefusal("REFUSED: the text contains the configured seed. Never overridable.")
    if allow_sensitive:
        return
    if _HEX_RUN.search(text):
        raise PolicyRefusal(
            "the text contains a 64+ character hex run, which is what a seed looks like. "
            "If this is a public digest (e.g. a release SHA-256), re-run with --allow-sensitive."
        )
    if _PEM.search(text):
        raise PolicyRefusal(
            "the text looks like PEM/private-key material. "
            "If that is intentional prose, re-run with --allow-sensitive."
        )
