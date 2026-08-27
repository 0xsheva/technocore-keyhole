import json
import os

import pytest
from cryptography.exceptions import InvalidTag

from keyhole.encfile import load_seed, store_seed

SEED = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")


def test_roundtrip(tmp_path):
    p = tmp_path / "seed.enc.json"
    store_seed(p, SEED, "correct horse")
    assert load_seed(p, "correct horse") == SEED
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["format"] == "technocore-keyhole-seed" and doc["kdf"]["name"] == "scrypt"
    assert SEED.hex() not in p.read_text(encoding="utf-8").lower()  # never stored in clear


def test_wrong_passphrase_fails_closed(tmp_path):
    p = tmp_path / "seed.enc.json"
    store_seed(p, SEED, "right")
    with pytest.raises(InvalidTag):
        load_seed(p, "wrong")


def test_tampered_ciphertext_fails_closed(tmp_path):
    p = tmp_path / "seed.enc.json"
    store_seed(p, SEED, "pw")
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["ct"] = doc["ct"][:-4] + ("AAAA" if not doc["ct"].endswith("AAAA") else "BBBB")
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(InvalidTag):
        load_seed(p, "pw")


def test_refuses_overwrite_and_bad_inputs(tmp_path):
    p = tmp_path / "seed.enc.json"
    store_seed(p, SEED, "pw")
    with pytest.raises(FileExistsError):
        store_seed(p, SEED, "pw")  # O_EXCL: an existing seed file is never clobbered
    with pytest.raises(ValueError):
        store_seed(tmp_path / "other.json", b"short", "pw")
    (tmp_path / "not-a-seed.json").write_text(
        '{"format": "something-else", "v": 1}', encoding="utf-8"
    )
    with pytest.raises(ValueError):
        load_seed(tmp_path / "not-a-seed.json", "pw")


@pytest.mark.skipif(
    os.name == "nt",
    reason="0o600 is a POSIX concept; on Windows the profile directory's NTFS ACLs apply",
)
def test_mode_is_owner_only(tmp_path):
    p = tmp_path / "seed.enc.json"
    store_seed(p, SEED, "pw")
    assert (p.stat().st_mode & 0o777) == 0o600
