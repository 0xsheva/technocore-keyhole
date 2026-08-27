import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyhole.receipts import append, export_json, last_nonce, verify_ledger
from keyhole.signer import Signer

SEED = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SIGNER = Signer(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED)))


def _commit(path: Path, room: str, nonce: str, text: str) -> dict:
    clean, sig = SIGNER.sign_say(room, nonce, text)
    return append(
        path,
        {
            "kind": "say",
            "base_url": "https://example.invalid",
            "room": room,
            "did": SIGNER.did,
            "nonce": nonce,
            "text": clean,
            "sig": sig,
            "seq": 1,
            "server_ts": "2026-08-27T00:00:00Z",
        },
    )


def test_append_verify_chain(tmp_path):
    ledger = tmp_path / "receipts.jsonl"
    _commit(ledger, "lobby", "1", "first")
    _commit(ledger, "lobby", "2", "second")
    _commit(ledger, "other", "1", "third")
    checks = verify_ledger(ledger)
    assert len(checks) == 3
    assert all(c.ok for c in checks), [c.detail for c in checks]
    assert last_nonce(ledger, "lobby") == 2
    assert last_nonce(ledger, "other") == 1
    assert last_nonce(ledger, "none") == 0


def test_tampered_text_detected(tmp_path):
    ledger = tmp_path / "receipts.jsonl"
    _commit(ledger, "lobby", "1", "first")
    _commit(ledger, "lobby", "2", "second")
    lines = ledger.read_text().splitlines()
    doc = json.loads(lines[0])
    doc["text"] = "forged"
    lines[0] = json.dumps(doc, ensure_ascii=True, separators=(",", ":"))
    ledger.write_text("\n".join(lines) + "\n")
    checks = verify_ledger(ledger)
    assert not checks[0].ok and "signature" in checks[0].detail
    assert (
        not checks[1].ok and "chain" in checks[1].detail
    )  # rewritten line 1 breaks prev of line 2


def test_deleted_line_detected(tmp_path):
    ledger = tmp_path / "receipts.jsonl"
    _commit(ledger, "lobby", "1", "first")
    _commit(ledger, "lobby", "2", "second")
    _commit(ledger, "lobby", "3", "third")
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join([lines[0], lines[2]]) + "\n")
    checks = verify_ledger(ledger)
    assert checks[0].ok
    assert not checks[1].ok and "chain" in checks[1].detail


def test_head_tracks_tail_and_detects_truncation(tmp_path):
    from keyhole.receipts import head

    ledger = tmp_path / "receipts.jsonl"
    assert head(ledger) == {"entries": 0, "head": "genesis"}
    _commit(ledger, "lobby", "1", "first")
    h1 = head(ledger)
    _commit(ledger, "lobby", "2", "second")
    h2 = head(ledger)
    assert h2["entries"] == 2 and h2["head"] != h1["head"]

    lines = ledger.read_text().splitlines()
    ledger.write_text(lines[0] + "\n")
    assert all(c.ok for c in verify_ledger(ledger))  # chain alone cannot see tail truncation
    assert head(ledger) == h1  # but the anchored head reveals it


def test_find_checkpoint(tmp_path):
    from keyhole.receipts import find_checkpoint, head

    ledger = tmp_path / "receipts.jsonl"
    assert find_checkpoint(ledger, "genesis") == (0, 0)
    _commit(ledger, "lobby", "1", "first")
    h1 = head(ledger)["head"]
    _commit(ledger, "lobby", "2", "second")
    _commit(ledger, "lobby", "3", "third")
    assert find_checkpoint(ledger, h1) == (1, 3)  # anchor survives appends
    assert find_checkpoint(ledger, head(ledger)["head"]) == (3, 3)
    assert find_checkpoint(ledger, "f" * 64) == (-1, 3)  # unknown anchor
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join(lines[1:]) + "\n")  # drop entry 1
    assert find_checkpoint(ledger, h1) == (-1, 2)  # anchored prefix gone


def test_inspect_ledger_reads_one_snapshot(tmp_path, monkeypatch):
    from keyhole.receipts import head, inspect_ledger

    ledger = tmp_path / "receipts.jsonl"
    _commit(ledger, "lobby", "1", "first")
    anchor = head(ledger)["head"]

    original_open = Path.open
    reads = 0

    def counted_open(path, *args, **kwargs):
        nonlocal reads
        if path == ledger:
            reads += 1
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted_open)
    checks, current_head, checkpoint = inspect_ledger(ledger, anchor)
    assert reads == 1
    assert all(check.ok for check in checks)
    assert current_head["head"] == anchor
    assert checkpoint == (1, 1)


def test_concurrent_locked_commits_keep_chain_intact(tmp_path):
    """Threads doing read-nonce -> append under ledger_lock must yield an
    intact chain and strictly increasing nonces (the unlocked interleaving
    breaks prev / reuses nonces)."""
    import threading

    from keyhole.receipts import last_nonce, ledger_lock

    ledger = tmp_path / "receipts.jsonl"
    barrier = threading.Barrier(8)

    def commit_once():
        barrier.wait()
        with ledger_lock(ledger):
            nonce = str(last_nonce(ledger, "lobby") + 1)
            clean, sig = SIGNER.sign_say("lobby", nonce, f"msg {nonce}")
            append(
                ledger,
                {
                    "kind": "say",
                    "base_url": "https://example.invalid",
                    "room": "lobby",
                    "did": SIGNER.did,
                    "nonce": nonce,
                    "text": clean,
                    "sig": sig,
                    "seq": int(nonce),
                    "server_ts": "2026-08-28T00:00:00Z",
                },
            )

    threads = [threading.Thread(target=commit_once) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    checks = verify_ledger(ledger)
    assert len(checks) == 8 and all(c.ok for c in checks), [c.detail for c in checks]
    nonces = [int(json.loads(line)["nonce"]) for line in ledger.read_text().splitlines() if line]
    assert nonces == sorted(nonces) and len(set(nonces)) == 8


def test_export_shape(tmp_path):
    ledger = tmp_path / "receipts.jsonl"
    _commit(ledger, "lobby", "1", "first")
    doc = json.loads(export_json(ledger))
    assert doc["format"] == "technocore-keyhole-receipts"
    assert len(doc["entries"]) == 1
    assert doc["entries"][0]["prev"] == "genesis"
