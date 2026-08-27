import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyhole import didkey
from keyhole.signer import Signer

DOC = json.loads((Path(__file__).parents[1] / "vectors" / "signing.json").read_text())
SIGNER = Signer(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(DOC["seed_hex_TEST_ONLY"])))


def test_did_matches_vectors():
    assert SIGNER.did == DOC["did"]
    assert didkey.DID_RE.fullmatch(SIGNER.did)


def test_did_roundtrip():
    pub = didkey.public_key_bytes(SIGNER.did)
    assert didkey.did_from_public_bytes(pub) == SIGNER.did


@pytest.mark.parametrize("case", DOC["cases"], ids=lambda c: f"{c['room']}/{c['nonce']}")
def test_signatures_match_vectors(case):
    clean, sig = SIGNER.sign_say(case["room"], case["nonce"], case["text_raw"])
    assert clean == case["text_swept"]
    assert sig == case["sig"]
    assert len(sig) == didkey.SIG_CHARS
    didkey.verify(DOC["did"], sig, case["message"])


def test_tampered_text_fails():
    case = DOC["cases"][0]
    with pytest.raises(didkey.SignatureError):
        didkey.verify(DOC["did"], case["sig"], case["message"] + "!")


def test_signing_raw_text_would_not_verify_against_swept():
    clean, sig = SIGNER.sign_say("r", "1", "a\nb")
    assert clean == "a b"
    raw_message = "r|1|a\nb"
    with pytest.raises(didkey.SignatureError):
        didkey.verify(DOC["did"], sig, raw_message)


def test_bad_nonce_rejected():
    with pytest.raises(ValueError):
        SIGNER.sign_say("r", "١٢٣", "hi")  # unicode digits are not ASCII digits
    with pytest.raises(ValueError):
        SIGNER.sign_say("r", "1" * 20, "hi")


def test_malformed_dids_rejected():
    for bad in ["did:key:z6Mkshort", "did:web:x", "", "did:key:" + "z" + "0" * 47]:
        with pytest.raises(didkey.DidError):
            didkey.public_key_bytes(bad)


def test_note_lane_canonical():
    clean, sig = SIGNER.sign_note("room-owners", "d-test", "5", DOC["did"])
    didkey.verify(DOC["did"], sig, f"room-owners|d-test|5|{clean}")
