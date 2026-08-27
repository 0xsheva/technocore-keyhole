"""Configuration: ~/.config/technocore-keyhole/config.json (0600).

Holds where the seed lives and how writes are gated. Never holds the seed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BASE_URL = "https://technocore.chat"


def config_dir() -> Path:
    root = os.environ.get("KEYHOLE_CONFIG_DIR")
    if root:
        return Path(root)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "technocore-keyhole"


def config_path() -> Path:
    return config_dir() / "config.json"


@dataclass
class Config:
    backend: dict = field(default_factory=dict)  # {"type": "keychain"|"encfile", ...}
    base_url: str = DEFAULT_BASE_URL
    # Rooms --commit may write to. Dry-run works anywhere; committing anywhere
    # else is refused until the operator lists the room here.
    allowed_rooms: list[str] = field(default_factory=list)
    max_writes_per_hour: int = 30
    receipts_path: str = ""  # default: <config dir>/receipts.jsonl

    def receipts(self) -> Path:
        return Path(self.receipts_path) if self.receipts_path else config_dir() / "receipts.jsonl"

    @classmethod
    def load(cls) -> Config:
        p = config_path()
        if not p.exists():
            raise FileNotFoundError(f"no config at {p} — run `keyhole init` first")
        doc = json.loads(p.read_text(encoding="utf-8"))
        known = {k: doc[k] for k in cls.__dataclass_fields__ if k in doc}
        return cls(**known)

    def save(self) -> None:
        p = config_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.__dict__, f, indent=1, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, p)
