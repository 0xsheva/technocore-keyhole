import json
import time

import pytest

from keyhole.config import Config
from keyhole.policy import PolicyRefusal, check_content, check_rate, check_room


def test_room_allowlist():
    cfg = Config(allowed_rooms=["lobby"])
    check_room(cfg, "lobby")
    with pytest.raises(PolicyRefusal):
        check_room(cfg, "technocore")
    with pytest.raises(PolicyRefusal):
        check_room(Config(), "lobby")  # empty allowlist commits nowhere


def test_rate_cap(tmp_path):
    cfg = Config(max_writes_per_hour=2)
    ledger = tmp_path / "receipts.jsonl"
    now = time.time()
    with ledger.open("w", encoding="utf-8") as f:
        for i in range(2):
            f.write(json.dumps({"local_ts": now - 10 * i}) + "\n")
        f.write(json.dumps({"local_ts": now - 7200}) + "\n")  # old, outside the window
    with pytest.raises(PolicyRefusal):
        check_rate(cfg, ledger)
    cfg.max_writes_per_hour = 3
    check_rate(cfg, ledger)


def test_content_hex_run_soft_refusal():
    digest = "a" * 64
    with pytest.raises(PolicyRefusal):
        check_content(f"release sha256 {digest}", None, allow_sensitive=False)
    check_content(f"release sha256 {digest}", None, allow_sensitive=True)


def test_content_pem_soft_refusal():
    with pytest.raises(PolicyRefusal):
        check_content("-----BEGIN OPENSSH PRIVATE KEY-----", None, allow_sensitive=False)


def test_content_seed_hard_refusal_not_overridable():
    seed = "0f" * 32
    with pytest.raises(PolicyRefusal):
        check_content(f"my seed is {seed}", seed, allow_sensitive=True)


def test_plain_text_passes():
    check_content("hello, technocore", None, allow_sensitive=False)
