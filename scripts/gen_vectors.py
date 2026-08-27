"""Regenerate vectors/*.json from the TEST seed. Dev-only.

The seed below is a PUBLIC test constant, present in this repository on
purpose so that any implementation can reproduce the signatures. It signs
nothing real and must never be used for an identity.

Run: uv run python scripts/gen_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyhole import didkey
from keyhole.signer import Signer
from keyhole.sweep import SweepError, swept

TEST_SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

SWEEP_CASES = [
    ("hello world", "hello world"),
    ("  padded  ", "padded"),
    ("line1\nline2", "line1 line2"),
    ("tab\there", "tab here"),
    ("he​llo", "he llo"),  # zero-width space (Cf)
    ("‮abc", "abc"),  # bidi override swept then trimmed
    ("tag\U000e0041end", "tag end"),  # Unicode tag character (Co-range Cf tag)
    ("para sep end", "para sep end"),  # Zl / Zp
    ("👨‍👩‍👧", "👨 👩 👧"),  # ZWJ family flattens (documented upstream)
    ("こんにちは世界", "こんにちは世界"),
    ("emoji 🎉 stays", "emoji 🎉 stays"),
]

REFUSED = ["", "​​", "\n\n", "   "]

SIGN_CASES = [
    {"room": "lobby", "nonce": "1", "text_raw": "hello world"},
    {"room": "lobby", "nonce": "2", "text_raw": "line1\nline2"},
    {
        "room": "technocore",
        "nonce": "1787000000000",
        "text_raw": "ぬれた鍵は 使わない — keyhole test",
    },
    {"room": "d-test", "nonce": "999", "text_raw": "he​llo bidi‮ mix"},
]


def main() -> None:
    out_dir = Path(__file__).resolve().parents[1] / "vectors"
    out_dir.mkdir(exist_ok=True)

    sweep_doc = {
        "description": "technocore-chat single-line sweep: Unicode categories "
        "Cc/Cf/Cs/Co/Zl/Zp become spaces, then the ends are trimmed.",
        "cases": [{"input": i, "expected": e} for i, e in SWEEP_CASES],
        "refused": REFUSED,
    }
    (out_dir / "sweep.json").write_text(json.dumps(sweep_doc, ensure_ascii=False, indent=1) + "\n")

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(TEST_SEED_HEX))
    signer = Signer(key)
    cases = []
    for c in SIGN_CASES:
        clean, sig = signer.sign_say(c["room"], c["nonce"], c["text_raw"])
        cases.append(
            {
                **c,
                "text_swept": clean,
                "message": f"{c['room']}|{c['nonce']}|{clean}",
                "sig": sig,
            }
        )
        didkey.verify(signer.did, sig, f"{c['room']}|{c['nonce']}|{clean}")
    sign_doc = {
        "description": "Ed25519 say-signed vectors. RFC 8032 signing is deterministic, "
        "so any correct implementation reproduces `sig` exactly. "
        "TEST seed only — never an identity.",
        "seed_hex_TEST_ONLY": TEST_SEED_HEX,
        "did": signer.did,
        "canonical": "<room>|<nonce>|<text after sweep>, UTF-8",
        "signature_encoding": "base64url, unpadded, 86 chars",
        "nonce_rule": "1-19 ASCII digits, strictly increasing per key per room",
        "cases": cases,
    }
    (out_dir / "signing.json").write_text(json.dumps(sign_doc, ensure_ascii=False, indent=1) + "\n")

    for raw in REFUSED:
        try:
            swept(raw)
        except SweepError:
            continue
        raise SystemExit(f"expected refusal for {raw!r}")
    print(
        f"wrote {out_dir}/sweep.json ({len(SWEEP_CASES)} cases) and "
        f"signing.json ({len(cases)} cases), did={signer.did}"
    )


if __name__ == "__main__":
    main()
