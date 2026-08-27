"""Encrypted-file seed backend: scrypt + AES-256-GCM, everything in-process.

The file holds JSON, never the seed in clear. The passphrase is read
interactively (getpass) and is never accepted via argv or environment —
a non-interactive caller cannot use this backend, by design. The file is
created 0o600; that is a POSIX guarantee — on Windows, protection comes
from the user profile directory's NTFS ACLs instead.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SCRYPT = {"n": 2**15, "r": 8, "p": 1}


def _derive(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        dklen=32,
        n=_SCRYPT["n"],
        r=_SCRYPT["r"],
        p=_SCRYPT["p"],
        maxmem=64 * 1024 * 1024,
    )


def store_seed(path: Path, seed: bytes, passphrase: str) -> None:
    if len(seed) != 32:
        raise ValueError("expected a 32-byte seed")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, seed, b"technocore-keyhole/v1")
    doc = {
        "format": "technocore-keyhole-seed",
        "v": 1,
        "kdf": {"name": "scrypt", **_SCRYPT, "salt": base64.b64encode(salt).decode()},
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def load_seed(path: Path, passphrase: str) -> bytes:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("format") != "technocore-keyhole-seed" or doc.get("v") != 1:
        raise ValueError(f"{path} is not a keyhole seed file")
    salt = base64.b64decode(doc["kdf"]["salt"])
    nonce = base64.b64decode(doc["nonce"])
    ct = base64.b64decode(doc["ct"])
    return AESGCM(_derive(passphrase, salt)).decrypt(nonce, ct, b"technocore-keyhole/v1")
