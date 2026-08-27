"""Append-only receipt ledger, offline-verifiable.

One JSON line per committed signed write. Each entry chains to the previous
line via prev = SHA-256 of that line's exact bytes, so edits and deletions
BEFORE the final line are detectable. Truncating the tail (or deleting the
whole file) is NOT detectable from the file alone — anchor `head()` somewhere
external (a signed room post, a git commit) and check it with
`keyhole verify --expect-head` to close that hole. Verification recomputes the
Ed25519 check over the canonical string — the server drops the signature after
verifying (upstream issue #66), so this ledger is the durable, re-verifiable
record.

A receipt proves that this key signed this text for this room at roughly this
time. It does not prove the message is still retained by the server, nor that
the signed URL is single-use forever (upstream documents nonce burial), nor
anything about quality, endorsement or eligibility.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import didkey

# Portable exclusive file lock. fcntl is Unix-only, and importing it at module
# top would make the whole CLI unimportable on Windows — where the encfile
# backend is otherwise fully supported. Both branches block until the lock is
# held: the commit critical section legitimately outlives msvcrt's built-in
# ~10s patience (a 30s HTTP timeout, an interactive passphrase prompt), and a
# waiter that gives up would either crash the second commit or, worse, let a
# caller mistake contention for "no lock available" and proceed unserialized.
if os.name == "nt":  # pragma: no cover — exercised by the Windows CI job
    import errno
    import msvcrt

    def _lock_file(f):
        f.seek(0)
        while True:
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError as exc:
                # LK_LOCK raises after ~10 one-second attempts; that is
                # contention, not failure — keep waiting, like flock does.
                if exc.errno not in (errno.EDEADLK, errno.EACCES):
                    raise

    def _unlock_file(f):
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock_file(f):
        fcntl.flock(f, fcntl.LOCK_EX)

    def _unlock_file(f):
        fcntl.flock(f, fcntl.LOCK_UN)


@contextmanager
def ledger_lock(path: Path):
    """Serialize a commit's critical section (nonce read → POST → append)
    across processes and threads. Without it, two concurrent commits read the
    same last nonce and the same tail line, and the loser's `prev` no longer
    matches — a broken chain. The lock is taken on a sidecar file, never on
    the ledger itself (the upstream store uses the same pattern, for the same
    reason: the data file's inode may be replaced, a sidecar's is stable).
    Contention always WAITS, on every platform — the only OSError this raises
    is the sidecar failing to be created at all (read-only location), which is
    the one case where a read-only caller may degrade to lockless."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "w", encoding="utf-8") as f:
        _lock_file(f)
        try:
            yield
        finally:
            _unlock_file(f)


def _sha256_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _canonical(entry: dict) -> str:
    if entry.get("kind") == "note":
        return f"{entry['ns']}|{entry['key']}|{entry['nonce']}|{entry['text']}"
    return f"{entry['room']}|{entry['nonce']}|{entry['text']}"


def _ledger_lines(path: Path) -> list[tuple[int, str]]:
    """Read nonblank ledger lines once, preserving source line numbers."""
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [
            (line_no, line)
            for line_no, raw in enumerate(f, start=1)
            if (line := raw.rstrip("\n")).strip()
        ]


def append(path: Path, entry: dict) -> dict:
    """Add prev/local_ts, append as one line, return the completed entry."""
    prev = "genesis"
    if path.exists():
        last = ""
        with path.open(encoding="utf-8") as f:
            for raw in f:
                if raw.strip():
                    last = raw.rstrip("\n")
        if last:
            prev = _sha256_line(last)
    entry = {"v": 1, "local_ts": round(time.time(), 3), **entry, "prev": prev}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n")
    return entry


def last_nonce(path: Path, room: str) -> int:
    """Highest nonce this ledger has recorded for a room (0 if none)."""
    best = 0
    if not path.exists():
        return best
    with path.open(encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                e = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if e.get("room") == room:
                try:
                    best = max(best, int(e.get("nonce", 0)))
                except (TypeError, ValueError):
                    pass
    return best


def head(path: Path) -> dict:
    """{'entries': N, 'head': SHA-256 of the last line} ('genesis' when empty).

    The chain alone cannot prove the ledger was not truncated from the end.
    Publish this value externally as a CHECKPOINT: `verify --expect-head`
    later checks that the anchored line still exists in the chain, which
    guarantees the prefix up to it is intact. Appends made after anchoring
    are expected and do not invalidate the checkpoint.
    """
    return _head_from_lines(_ledger_lines(path))


def _head_from_lines(lines: list[tuple[int, str]]) -> dict:
    last = lines[-1][1] if lines else ""
    return {"entries": len(lines), "head": _sha256_line(last) if last else "genesis"}


def find_checkpoint(path: Path, head_hash: str) -> tuple[int, int]:
    """(index, total): the 1-based position of the line whose SHA-256 equals
    `head_hash`, or (-1, total) when no line matches. 'genesis' is the empty
    prefix and always matches at index 0. A missing checkpoint means the
    prefix up to that anchor was truncated or rewritten since it was recorded.
    """
    return _find_checkpoint_in_lines(_ledger_lines(path), head_hash)


def _find_checkpoint_in_lines(lines: list[tuple[int, str]], head_hash: str) -> tuple[int, int]:
    idx = 0 if head_hash == "genesis" else -1
    for entry_no, (_line_no, line) in enumerate(lines, start=1):
        if _sha256_line(line) == head_hash:
            idx = entry_no
    return idx, len(lines)


@dataclass
class Check:
    line_no: int
    ok: bool
    detail: str


def _verify_lines(lines: list[tuple[int, str]]) -> list[Check]:
    results: list[Check] = []
    prev_hash = "genesis"
    for line_no, line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            results.append(Check(line_no, False, "unparseable line"))
            prev_hash = _sha256_line(line)
            continue
        problems = []
        if e.get("prev") != prev_hash:
            problems.append("chain broken (prev mismatch)")
        try:
            didkey.verify(e["did"], e["sig"], _canonical(e))
        except Exception as exc:
            problems.append(f"signature: {exc}")
        results.append(Check(line_no, not problems, "; ".join(problems) or "ok"))
        prev_hash = _sha256_line(line)
    return results


def inspect_ledger(
    path: Path, expected_head: str | None = None
) -> tuple[list[Check], dict, tuple[int, int] | None]:
    """Verify chain, head and checkpoint from one in-memory snapshot."""
    lines = _ledger_lines(path)
    checkpoint = (
        _find_checkpoint_in_lines(lines, expected_head) if expected_head is not None else None
    )
    return _verify_lines(lines), _head_from_lines(lines), checkpoint


def verify_ledger(path: Path) -> list[Check]:
    """Signature + chain check for every line. Offline; no network."""
    return _verify_lines(_ledger_lines(path))


def export_json(path: Path) -> str:
    """The ledger as a JSON array (community evidence format, not any official
    standard; a TCR-1 exporter can be added once upstream issue #281 settles)."""
    entries = []
    if path.exists():
        with path.open(encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if raw:
                    try:
                        entries.append(json.loads(raw))
                    except json.JSONDecodeError:
                        entries.append({"unparseable": raw})
    return json.dumps(
        {"format": "technocore-keyhole-receipts", "v": 1, "entries": entries},
        ensure_ascii=False,
        indent=1,
    )
