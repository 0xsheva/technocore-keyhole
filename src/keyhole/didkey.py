"""did:key (Ed25519) encoding, decoding and offline signature verification.

Matches upstream technocore-chat src/didkey.py semantics: only ed25519-pub
(z6Mk…) keys, 48 multibase characters, 86-character unpadded base64url
signatures, 1-19 ASCII-digit nonces. Verification here uses `cryptography`
(upstream verifies with libsodium; the two agree on valid/tampered verdicts,
which is what receipt verification needs).
"""

from __future__ import annotations

import base64
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFIX = "did:key:"
MULTICODEC_ED25519 = b"\xed\x01"  # varint ed25519-pub; base58-encodes to the fixed z6Mk head
MULTIBASE_CHARS = 48
SIG_CHARS = 86

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}

DID_RE = re.compile(rf"{PREFIX}z6Mk[1-9A-HJ-NP-Za-km-z]{{{MULTIBASE_CHARS - 4}}}")
SIG_RE = re.compile(rf"[A-Za-z0-9_-]{{{SIG_CHARS}}}")
NONCE_RE = re.compile(r"[0-9]{1,19}")


class DidError(ValueError):
    """Not a usable did:key."""


class SignatureError(ValueError):
    """A well-formed DID whose signature does not cover this message."""


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    return out


def _b58decode(raw: str) -> bytes:
    n = 0
    for ch in raw:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            raise DidError(f"bad did:key: {ch!r} is not base58btc")
        n = n * 58 + digit
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def did_from_public_bytes(pub: bytes) -> str:
    """did:key:z6Mk… for 32 raw Ed25519 public-key bytes."""
    if len(pub) != 32:
        raise DidError(f"expected 32 public-key bytes, got {len(pub)}")
    mb = "z" + _b58encode(MULTICODEC_ED25519 + pub)
    if len(mb) != MULTIBASE_CHARS:
        raise DidError(f"internal: bad multibase length {len(mb)}")
    return PREFIX + mb


def public_key_bytes(did: str) -> bytes:
    """The 32 raw Ed25519 public-key bytes of a did:key, or raise DidError."""
    if not isinstance(did, str) or not did.startswith(PREFIX):
        raise DidError(f"bad did:key: expected {PREFIX}z6Mk…")
    mb = did[len(PREFIX) :]
    if len(mb) != MULTIBASE_CHARS or not mb.startswith("z"):
        raise DidError(f"bad did:key: expected {MULTIBASE_CHARS} multibase characters starting 'z'")
    decoded = _b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise DidError("bad did:key: only ed25519-pub (z6Mk…) keys are accepted")
    return decoded[2:]


def abbreviate(did: str) -> str:
    mb = did[len(PREFIX) :]
    return f"{mb[:4]}…{mb[-4:]}"


def encode_signature(raw: bytes) -> str:
    """86 unpadded base64url characters — the encoding the server's SIG_RE expects."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def verify(did: str, signature: str, message: str) -> None:
    """Raise unless `signature` is `did`'s Ed25519 signature over `message` (UTF-8)."""
    key = Ed25519PublicKey.from_public_bytes(public_key_bytes(did))
    if not SIG_RE.fullmatch(signature or ""):
        raise DidError(f"bad signature encoding: expected {SIG_CHARS} base64url characters")
    raw = base64.urlsafe_b64decode(signature + "==")
    try:
        key.verify(raw, message.encode("utf-8"))
    except InvalidSignature:
        raise SignatureError("signature does not cover this message") from None
