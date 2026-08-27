"""CLI behavior without any network or key material. Dry-run must load no seed."""

import json

import pytest

from keyhole import cli
from keyhole.config import Config


@pytest.fixture
def cfg_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYHOLE_CONFIG_DIR", str(tmp_path))
    return tmp_path


def _write_config(tmp_path, **kw):
    cfg = Config(backend={"type": "keychain", "service": "svc", "account": "acct"}, **kw)
    cfg.save()
    return cfg


def test_no_config_is_an_error(cfg_dir, capsys):
    assert cli.main(["say", "lobby", "hi"]) == cli.EXIT_ERROR
    assert "keyhole init" in capsys.readouterr().err


def test_dry_run_loads_no_seed_and_shows_swept_text(cfg_dir, capsys, monkeypatch):
    _write_config(cfg_dir)

    def boom(*a, **k):  # any attempt to reach the keychain fails the test
        raise AssertionError("dry run must not touch the seed backend")

    monkeypatch.setattr("keyhole.signer._seed_from_keychain", boom)
    assert cli.main(["say", "lobby", "line1\nline2", "--json"]) == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["dry_run"] is True
    assert out["text_after_sweep"] == "line1 line2"


def test_commit_refused_off_allowlist_before_seed(cfg_dir, capsys, monkeypatch):
    _write_config(cfg_dir, allowed_rooms=["lobby"])
    monkeypatch.setattr(
        "keyhole.signer._seed_from_keychain",
        lambda *a: (_ for _ in ()).throw(AssertionError("must refuse before seed load")),
    )
    assert cli.main(["say", "technocore", "hi", "--commit"]) == cli.EXIT_POLICY
    assert "allowed_rooms" in capsys.readouterr().err


def test_hex_run_refused_in_dry_run(cfg_dir, capsys):
    _write_config(cfg_dir)
    assert cli.main(["say", "lobby", "seed? " + "a" * 64]) == cli.EXIT_POLICY
    assert "--allow-sensitive" in capsys.readouterr().err


def test_commit_posts_and_appends_receipt(cfg_dir, capsys, monkeypatch):
    _write_config(cfg_dir, allowed_rooms=["lobby"])
    seed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    monkeypatch.setattr("keyhole.signer._seed_from_keychain", lambda *a: bytes.fromhex(seed))

    sent = {}

    def fake_post(base, room, did, sig, nonce, text):
        sent.update(room=room, did=did, sig=sig, nonce=nonce, text=text)
        return {"posted": {"from": did, "seq": 42, "ts": "2026-08-27T00:00:00Z"}}

    monkeypatch.setattr("keyhole.cli.post_signed_say", fake_post)
    assert cli.main(["say", "lobby", "hello there", "--commit", "--json"]) == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["posted"]["seq"] == 42
    from keyhole import didkey

    didkey.verify(sent["did"], sent["sig"], f"lobby|{sent['nonce']}|{sent['text']}")

    assert cli.main(["verify"]) == cli.EXIT_OK
    assert "1/1" in capsys.readouterr().out


def test_server_refusal_is_exit_3_and_not_retried(cfg_dir, capsys, monkeypatch):
    _write_config(cfg_dir, allowed_rooms=["lobby"])
    seed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    monkeypatch.setattr("keyhole.signer._seed_from_keychain", lambda *a: bytes.fromhex(seed))
    calls = {"n": 0}

    def refuse(*a, **k):
        calls["n"] += 1
        from keyhole.client import ServerRefusal

        raise ServerRefusal(429, "retry after: 12s")

    monkeypatch.setattr("keyhole.cli.post_signed_say", refuse)
    assert cli.main(["say", "lobby", "hello", "--commit"]) == cli.EXIT_SERVER
    assert calls["n"] == 1
    assert "do not immediately retry" in capsys.readouterr().err


def test_verify_empty_ledger_ok(cfg_dir, capsys):
    _write_config(cfg_dir)
    assert cli.main(["verify"]) == cli.EXIT_OK


def test_verify_reads_one_snapshot_under_the_ledger_lock(cfg_dir, capsys):
    """P2: verify must serialize against commits — while a commit holds the
    ledger lock, verify blocks instead of reading a torn snapshot."""
    import threading

    from keyhole.config import Config
    from keyhole.receipts import ledger_lock

    _write_config(cfg_dir)
    path = Config.load().receipts()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    started, finished = threading.Event(), threading.Event()
    rc = {}

    def run():
        started.set()
        rc["v"] = cli.main(["verify"])
        finished.set()

    with ledger_lock(path):
        t = threading.Thread(target=run)
        t.start()
        assert started.wait(2)
        assert not finished.wait(0.4)  # blocked while the "commit" holds the lock
    assert finished.wait(5)
    t.join()
    assert rc["v"] == cli.EXIT_OK


def test_verify_ledger_in_readonly_location_falls_back_locklessly(tmp_path, monkeypatch, capsys):
    """A third-party file on a read-only path cannot get a lock sidecar; verify
    must still work there rather than erroring."""
    import os

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from keyhole.receipts import append
    from keyhole.signer import Signer

    signer = Signer(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED)))
    ro = tmp_path / "ro"
    ro.mkdir()
    shared = ro / "receipts.jsonl"
    clean, sig = signer.sign_say("lobby", "1", "read-only case")
    append(
        shared,
        {
            "kind": "say",
            "base_url": "https://example.invalid",
            "room": "lobby",
            "did": signer.did,
            "nonce": "1",
            "text": clean,
            "sig": sig,
            "seq": 1,
            "server_ts": "2026-08-28T00:00:00Z",
        },
    )
    os.chmod(ro, 0o555)
    try:
        monkeypatch.setenv("KEYHOLE_CONFIG_DIR", str(tmp_path / "no-config"))
        assert cli.main(["verify", "--ledger", str(shared)]) == cli.EXIT_OK
        assert "1/1 receipts verified" in capsys.readouterr().out
    finally:
        os.chmod(ro, 0o755)


def test_verify_ledger_third_party_needs_no_config(tmp_path, monkeypatch, capsys):
    """Blocker: a third party must be able to verify a shared JSONL with no
    keyhole config of their own."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from keyhole.receipts import append, head
    from keyhole.signer import Signer

    signer = Signer(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED)))
    shared = tmp_path / "shared-receipts.jsonl"
    for i in ["1", "2"]:
        clean, sig = signer.sign_say("lobby", i, f"public statement {i}")
        append(
            shared,
            {
                "kind": "say",
                "base_url": "https://example.invalid",
                "room": "lobby",
                "did": signer.did,
                "nonce": i,
                "text": clean,
                "sig": sig,
                "seq": int(i),
                "server_ts": "2026-08-28T00:00:00Z",
            },
        )
    anchor = head(shared)["head"]

    monkeypatch.setenv("KEYHOLE_CONFIG_DIR", str(tmp_path / "no-config-here"))
    assert cli.main(["verify", "--ledger", str(shared)]) == cli.EXIT_OK
    assert cli.main(["verify", "--ledger", str(shared), "--expect-head", anchor]) == cli.EXIT_OK
    capsys.readouterr()

    lines = shared.read_text(encoding="utf-8").splitlines()
    doc = json.loads(lines[0])
    doc["text"] = "forged"
    shared.write_text(
        "\n".join([json.dumps(doc, separators=(",", ":"))] + lines[1:]) + "\n", encoding="utf-8"
    )
    assert cli.main(["verify", "--ledger", str(shared)]) == cli.EXIT_ERROR
    assert cli.main(["verify", "--ledger", str(tmp_path / "missing.jsonl")]) == cli.EXIT_ERROR


SEED = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


def _arm(monkeypatch):
    monkeypatch.setattr("keyhole.signer._seed_from_keychain", lambda *a: bytes.fromhex(SEED))
    calls = []

    def fake_post(base, room, did, sig, nonce, text):
        calls.append(nonce)
        return {"posted": {"from": did, "seq": len(calls), "ts": "2026-08-28T00:00:00Z"}}

    monkeypatch.setattr("keyhole.cli.post_signed_say", fake_post)
    return calls


def test_commit_refuses_text_containing_actual_seed(cfg_dir, capsys, monkeypatch):
    """P1: --allow-sensitive must never allow the configured seed itself out."""
    _write_config(cfg_dir, allowed_rooms=["lobby"])
    calls = _arm(monkeypatch)
    rc = cli.main(["say", "lobby", f"leak {SEED.upper()} end", "--commit", "--allow-sensitive"])
    assert rc == cli.EXIT_POLICY
    assert calls == []  # nothing was posted
    assert "Never overridable" in capsys.readouterr().err


def test_init_saves_nothing_on_bad_keychain(cfg_dir, capsys, monkeypatch):
    """P2: a failed backend validation must not leave (or clobber) a config."""
    from keyhole.config import config_path
    from keyhole.signer import SeedError

    def missing(*a):
        raise SeedError("item not found")

    monkeypatch.setattr("keyhole.signer._seed_from_keychain", missing)
    assert cli.main(["init", "--use-keychain", "svc", "acct"]) == cli.EXIT_ERROR
    assert not config_path().exists()
    monkeypatch.setattr("keyhole.signer._seed_from_keychain", lambda *a: bytes.fromhex(SEED))
    assert cli.main(["init", "--use-keychain", "svc", "acct"]) == cli.EXIT_OK  # no --force needed


def test_explicit_nonce_must_strictly_increase(cfg_dir, capsys, monkeypatch):
    """P2: --nonce may not replay or rewind past the recorded ledger."""
    _write_config(cfg_dir, allowed_rooms=["lobby"])
    calls = _arm(monkeypatch)
    assert cli.main(["say", "lobby", "first", "--commit", "--nonce", "100"]) == cli.EXIT_OK
    assert cli.main(["say", "lobby", "replay", "--commit", "--nonce", "100"]) == cli.EXIT_ERROR
    assert cli.main(["say", "lobby", "rewind", "--commit", "--nonce", "99"]) == cli.EXIT_ERROR
    assert "strictly increase" in capsys.readouterr().err
    assert cli.main(["say", "lobby", "onward", "--commit", "--nonce", "101"]) == cli.EXIT_OK
    assert calls == ["100", "101"]


def test_expect_head_is_a_checkpoint_not_an_exact_match(cfg_dir, capsys, monkeypatch):
    """P2: anchoring a head must survive later legitimate appends (the anchor
    post itself advances the ledger), and still catch truncation past it."""
    _write_config(cfg_dir, allowed_rooms=["lobby"])
    _arm(monkeypatch)
    assert cli.main(["say", "lobby", "one", "--commit"]) == cli.EXIT_OK
    assert cli.main(["say", "lobby", "two", "--commit"]) == cli.EXIT_OK
    assert cli.main(["receipts", "head"]) == cli.EXIT_OK
    recorded = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert recorded["entries"] == 2

    # a later legitimate append must NOT invalidate the recorded checkpoint
    assert cli.main(["say", "lobby", "three", "--commit"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["verify", "--expect-head", recorded["head"]]) == cli.EXIT_OK
    assert "checkpoint matched at entry 2/3" in capsys.readouterr().out

    # truncating past the anchor removes the checkpoint line -> failure
    from keyhole.config import Config

    ledger = Config.load().receipts()
    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text(lines[0] + "\n", encoding="utf-8")  # keep only entry 1

    assert cli.main(["verify"]) == cli.EXIT_OK  # documented limitation: chain alone passes
    assert cli.main(["verify", "--expect-head", recorded["head"]]) == cli.EXIT_ERROR
    assert "CHECKPOINT MISSING" in capsys.readouterr().out


def test_unverifiable_200_response_records_pending_receipt(cfg_dir, capsys, monkeypatch):
    """P2: a 200 whose payload is not the posted echo must not crash after the
    signature was already sent — record the receipt as unverified, exit 3."""
    _write_config(cfg_dir, allowed_rooms=["lobby"])
    monkeypatch.setattr("keyhole.signer._seed_from_keychain", lambda *a: bytes.fromhex(SEED))
    monkeypatch.setattr("keyhole.cli.post_signed_say", lambda *a: {"posted": "ok"})
    assert cli.main(["say", "lobby", "odd server", "--commit"]) == cli.EXIT_SERVER
    assert "status=unverified" in capsys.readouterr().err

    from keyhole.config import Config

    raw = Config.load().receipts().read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in raw if line]
    assert len(entries) == 1
    assert entries[0]["status"] == "unverified" and entries[0]["seq"] is None
    assert cli.main(["verify"]) == cli.EXIT_OK  # the signature itself still verifies
