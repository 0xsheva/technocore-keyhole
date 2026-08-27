"""Seed backends and signing. The seed exists only inside this process.

Rules enforced here, not merely documented:
  * the seed is never printed, logged, or included in an exception message;
  * it is never placed in a child process's argv or environment;
  * signing happens in-process via `cryptography` (no subprocess signer).

Backends:
  * keychain — reads an EXISTING macOS Keychain generic password
    (`security find-generic-password -w`; the secret arrives on stdout,
    captured in-process). keyhole never writes to the Keychain: creating the
    item is the operator's own interactive step, so the seed never transits
    this tool's argv.
  * encfile — scrypt+AES-GCM file created by `keyhole init`; passphrase via
    interactive getpass only.

The canonical strings match upstream scripts/sign.py:
    say:  <room>|<nonce>|<swept text>
    note: <ns>|<key>|<nonce>|<swept value>
"""

from __future__ import annotations

import getpass
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import didkey
from .config import Config
from .encfile import load_seed
from .sweep import MAX_TEXT_CHARS, MAX_VALUE_CHARS, swept

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class SeedError(RuntimeError):
    """The seed could not be obtained. The message never contains key material."""


def _seed_from_keychain(service: str, account: str) -> bytes:
    try:
        proc = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except OSError:
        raise SeedError(
            "the keychain backend requires macOS (the `security` tool was not found); "
            "use the encfile backend on this platform: `keyhole init`"
        ) from None
    if proc.returncode != 0:
        raise SeedError(
            f"macOS Keychain item not found or not readable (service={service!r}, "
            f"account={account!r}). Create it yourself with:\n"
            f"  security add-generic-password -s {service} -a {account} -w\n"
            f"(the trailing -w prompts for the 64-hex seed interactively)"
        )
    value = proc.stdout.strip()
    if not _HEX64.fullmatch(value):
        raise SeedError("Keychain item exists but is not a 64-hex-character Ed25519 seed")
    return bytes.fromhex(value)


def _seed_from_encfile(path: str) -> bytes:
    if not sys.stdin.isatty():
        raise SeedError(
            "the encfile backend needs an interactive passphrase prompt; "
            "run this command in your own terminal"
        )
    passphrase = getpass.getpass("keyhole seed passphrase: ")
    try:
        return load_seed(Path(path), passphrase)
    except Exception:
        # `from None` on purpose: the original exception could name paths or
        # cipher internals, and this message must stay key-material-free.
        raise SeedError(
            "could not decrypt the seed file (wrong passphrase, or damaged file)"
        ) from None


@dataclass
class Signer:
    key: Ed25519PrivateKey

    @classmethod
    def from_config(cls, cfg: Config) -> Signer:
        backend = cfg.backend or {}
        kind = backend.get("type")
        if kind == "keychain":
            seed = _seed_from_keychain(backend["service"], backend["account"])
        elif kind == "encfile":
            seed = _seed_from_encfile(backend["path"])
        else:
            raise SeedError("no seed backend configured — run `keyhole init`")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def did(self) -> str:
        return didkey.did_from_public_bytes(self.key.public_key().public_bytes_raw())

    def contains_seed(self, text: str) -> bool:
        """True if the text contains this key's seed as contiguous hex (either case).

        The comparison is the whole point of loading the seed here; the hex stays
        local to this method and is never returned, stored or logged. Contiguous
        matching only — split or re-encoded seeds are not detected, which is why
        the soft key-material checks in policy.py also exist.
        """
        seed_hex = self.key.private_bytes_raw().hex()
        return seed_hex in text.lower()

    def sign_say(self, room: str, nonce: str, text: str) -> tuple[str, str]:
        """(swept_text, signature) for a room message."""
        if not didkey.NONCE_RE.fullmatch(nonce):
            raise ValueError(f"nonce must be 1-19 ASCII digits, got {nonce!r}")
        clean = swept(text, MAX_TEXT_CHARS)
        sig = didkey.encode_signature(self.key.sign(f"{room}|{nonce}|{clean}".encode()))
        return clean, sig

    def sign_note(self, ns: str, key_name: str, nonce: str, value: str) -> tuple[str, str]:
        """(swept_value, signature) for a signed note (room-owners / room-allow only)."""
        if not didkey.NONCE_RE.fullmatch(nonce):
            raise ValueError(f"nonce must be 1-19 ASCII digits, got {nonce!r}")
        clean = swept(value, MAX_VALUE_CHARS)
        sig = didkey.encode_signature(self.key.sign(f"{ns}|{key_name}|{nonce}|{clean}".encode()))
        return clean, sig


def public_did(cfg: Config) -> str:
    """The DID for the configured backend (loads the seed once, in-process)."""
    return Signer.from_config(cfg).did
