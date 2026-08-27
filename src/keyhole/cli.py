"""keyhole — sign Technocore writes without ever showing the model the key.

Exit codes: 0 ok (including dry-run), 1 error, 2 policy refusal, 3 server refusal.
"""

from __future__ import annotations

import argparse
import errno
import getpass
import json
import secrets
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from . import __version__, didkey
from .client import ServerRefusal, post_signed_say
from .config import Config, config_path
from .encfile import store_seed
from .policy import PolicyRefusal, check_content, check_rate, check_room
from .receipts import (
    append,
    export_json,
    head,
    inspect_ledger,
    last_nonce,
    ledger_lock,
)
from .signer import SeedError, Signer
from .sweep import MAX_TEXT_CHARS, SweepError, swept

EXIT_OK, EXIT_ERROR, EXIT_POLICY, EXIT_SERVER = 0, 1, 2, 3


def _fail(msg: str, code: int) -> int:
    print(f"keyhole: {msg}", file=sys.stderr)
    return code


def cmd_init(args: argparse.Namespace) -> int:
    if config_path().exists() and not args.force:
        return _fail(
            f"{config_path()} already exists (use --force to overwrite the CONFIG; "
            "seeds are never overwritten)",
            EXIT_ERROR,
        )
    cfg = Config()
    if args.use_keychain:
        service, account = args.use_keychain
        cfg.backend = {"type": "keychain", "service": service, "account": account}
        # Validate the backend BEFORE saving: a bad item must not leave a config
        # behind (or clobber a good one under --force).
        try:
            did = Signer.from_config(cfg).did
        except SeedError as exc:
            return _fail(str(exc), EXIT_ERROR)
        cfg.save()
        print(f"config: {config_path()}")
        print(f"backend: macOS Keychain (service={service}, account={account})")
        print(f"did: {did}")
        return EXIT_OK
    # encfile: generate in-process, store encrypted, never print the seed.
    if not sys.stdin.isatty():
        return _fail(
            "encfile init needs an interactive terminal for the passphrase "
            "(or use --use-keychain SERVICE ACCOUNT for an existing Keychain item)",
            EXIT_ERROR,
        )
    seed_path = config_path().parent / "seed.enc.json"
    if seed_path.exists():
        return _fail(f"{seed_path} already exists — refusing to touch an existing seed", EXIT_ERROR)
    p1 = getpass.getpass("new seed passphrase: ")
    p2 = getpass.getpass("repeat passphrase: ")
    if p1 != p2 or not p1:
        return _fail("passphrases empty or not identical", EXIT_ERROR)
    seed = secrets.token_bytes(32)
    store_seed(seed_path, seed, p1)
    cfg.backend = {"type": "encfile", "path": str(seed_path)}
    cfg.save()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    did = didkey.did_from_public_bytes(
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    )
    print(f"config: {config_path()}")
    print(f"seed:   {seed_path} (encrypted; back it up, remember the passphrase)")
    print(f"did:    {did}")
    print("The seed was not displayed and will never be.")
    return EXIT_OK


def cmd_did(_: argparse.Namespace) -> int:
    try:
        print(Signer.from_config(Config.load()).did)
    except (FileNotFoundError, SeedError) as exc:
        return _fail(str(exc), EXIT_ERROR)
    return EXIT_OK


def cmd_say(args: argparse.Namespace) -> int:
    try:
        cfg = Config.load()
    except FileNotFoundError as exc:
        return _fail(str(exc), EXIT_ERROR)
    try:
        clean = swept(args.text, MAX_TEXT_CHARS)
    except SweepError as exc:
        return _fail(str(exc), EXIT_ERROR)
    try:
        check_content(clean, seed_hex=None, allow_sensitive=args.allow_sensitive)
    except PolicyRefusal as exc:
        return _fail(str(exc), EXIT_POLICY)

    if not args.commit:
        out = {
            "dry_run": True,
            "room": args.room,
            "text_after_sweep": clean,
            "base_url": cfg.base_url,
            "note": "no seed was loaded, nothing was signed or sent; re-run with --commit",
        }
        print(
            json.dumps(out, ensure_ascii=False, indent=1)
            if args.json
            else f"DRY RUN — nothing sent.\nroom: {args.room}\ntext (as it will be stored):\n"
            f"  {clean}\nCommit with: keyhole say {args.room!r} … --commit"
        )
        return EXIT_OK

    try:
        check_room(cfg, args.room)
    except PolicyRefusal as exc:
        return _fail(str(exc), EXIT_POLICY)
    # Everything that reads or advances the ledger runs under the ledger lock,
    # so concurrent commits serialize: without it, two processes read the same
    # last nonce and the same tail line, and the loser's receipt breaks the
    # prev-chain (and its nonce may be refused by the server).
    with ledger_lock(cfg.receipts()):
        try:
            check_rate(cfg, cfg.receipts())
        except PolicyRefusal as exc:
            return _fail(str(exc), EXIT_POLICY)
        try:
            signer = Signer.from_config(cfg)
        except SeedError as exc:
            return _fail(str(exc), EXIT_ERROR)
        # The hard check, now that the seed is in memory anyway: the configured seed
        # itself never leaves this machine, --allow-sensitive or not (design rule 1).
        if signer.contains_seed(clean):
            return _fail(
                "REFUSED: the text contains the configured seed. Never overridable.", EXIT_POLICY
            )

        last = last_nonce(cfg.receipts(), args.room)
        if args.nonce:
            if not didkey.NONCE_RE.fullmatch(args.nonce):
                return _fail(f"nonce must be 1-19 ASCII digits, got {args.nonce!r}", EXIT_ERROR)
            if int(args.nonce) <= last:
                return _fail(
                    f"nonce {args.nonce} is not greater than the last recorded nonce {last} "
                    f"for room {args.room!r} — nonces must strictly increase per key per room",
                    EXIT_ERROR,
                )
            nonce = args.nonce
        else:
            nonce = str(max(int(time.time() * 1000), last + 1))
        try:
            clean2, sig = signer.sign_say(args.room, nonce, args.text)
        except (ValueError, SweepError) as exc:
            return _fail(str(exc), EXIT_ERROR)
        try:
            resp = post_signed_say(cfg.base_url, args.room, signer.did, sig, nonce, clean2)
        except ServerRefusal as exc:
            hint = (
                " (server said stop — do not immediately retry)" if exc.status in (422, 429) else ""
            )
            return _fail(f"{exc}{hint}", EXIT_SERVER)

        posted = resp.get("posted") if isinstance(resp, dict) else None
        if not isinstance(posted, dict):
            posted = None  # a 200 whose payload is not the posted echo (e.g. a string)
        verified = posted is not None and posted.get("from") == signer.did
        entry = {
            "kind": "say",
            "base_url": cfg.base_url,
            "room": args.room,
            "did": signer.did,
            "nonce": nonce,
            "text": clean2,
            "sig": sig,
            "seq": (posted or {}).get("seq"),
            "server_ts": (posted or {}).get("ts"),
            "status": "confirmed" if verified else "unverified",
        }
        entry = append(cfg.receipts(), entry)
    if not verified:
        print(
            "warning: the server's 200 response did not echo a verified signed post; "
            "receipt recorded with status=unverified — inspect the response:",
            file=sys.stderr,
        )
        print(json.dumps(resp, ensure_ascii=False)[:800], file=sys.stderr)
        return EXIT_SERVER
    out = {"posted": posted, "receipt": {k: entry[k] for k in ("room", "seq", "nonce", "prev")}}
    print(
        json.dumps(out, ensure_ascii=False, indent=1)
        if args.json
        else f"posted: room={args.room} seq={posted.get('seq')} nonce={nonce}\n"
        f"receipt appended: {cfg.receipts()}"
    )
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    if args.ledger:
        # Third-party mode: verify someone else's shared JSONL. Needs no config,
        # no seed, no network — everything required is in the file itself.
        path = Path(args.ledger)
        if not path.exists():
            return _fail(f"no ledger at {path}", EXIT_ERROR)
    else:
        try:
            path = Config.load().receipts()
        except FileNotFoundError as exc:
            return _fail(str(exc), EXIT_ERROR)
    # Read chain, head and checkpoint from one in-memory snapshot. The lock also
    # serializes this read against our own commits; a read-only third-party file
    # can safely fall back because inspect_ledger opens the source only once.
    with ExitStack() as stack:
        try:
            stack.enter_context(ledger_lock(path))
        except OSError as exc:
            lockless_ok = args.ledger and exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS)
            if not lockless_ok:
                return _fail(f"could not lock ledger {path}: {exc}", EXIT_ERROR)
        checks, h, checkpoint = inspect_ledger(path, args.expect_head)
        bad = [c for c in checks if not c.ok]
        cp_idx, head_ok = None, True
        if checkpoint is not None:
            cp_idx, _total = checkpoint
            head_ok = cp_idx >= 0
    if args.json:
        doc = {
            "entries": len(checks),
            "failed": [{"line": c.line_no, "detail": c.detail} for c in bad],
            "head": h["head"],
        }
        if args.expect_head is not None:
            doc["checkpoint_found"] = head_ok
            if head_ok:
                doc["checkpoint_entry"] = cp_idx
        print(json.dumps(doc, indent=1))
    else:
        for c in bad:
            print(f"line {c.line_no}: {c.detail}")
        print(f"{len(checks) - len(bad)}/{len(checks)} receipts verified ({path})")
        print(f"head: {h['head']} ({h['entries']} entries)")
        if args.expect_head is not None:
            if head_ok:
                print(
                    f"checkpoint matched at entry {cp_idx}/{h['entries']} — the prefix "
                    f"up to it is intact (appends after anchoring are expected)"
                )
            else:
                print(
                    f"CHECKPOINT MISSING: {args.expect_head} is not in the chain — the "
                    f"prefix up to that anchor was truncated or rewritten"
                )
    return EXIT_OK if not bad and head_ok else EXIT_ERROR


def cmd_receipts(args: argparse.Namespace) -> int:
    try:
        cfg = Config.load()
    except FileNotFoundError as exc:
        return _fail(str(exc), EXIT_ERROR)
    if args.action == "export":
        print(export_json(cfg.receipts()))
        return EXIT_OK
    if args.action == "head":
        print(json.dumps(head(cfg.receipts())))
        return EXIT_OK
    path = cfg.receipts()
    if not path.exists():
        print("no receipts yet")
        return EXIT_OK
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                print(
                    f"{str(e.get('server_ts') or '?'):32} {str(e.get('room') or '?'):20} "
                    f"seq={e.get('seq')} nonce={e.get('nonce')}"
                )
            except json.JSONDecodeError:
                print("?? unparseable line")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keyhole",
        description="Sign technocore.chat writes without the key ever entering an LLM context.",
    )
    parser.add_argument("--version", action="version", version=f"technocore-keyhole {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="configure a seed backend (never displays the seed)")
    p.add_argument(
        "--use-keychain",
        nargs=2,
        metavar=("SERVICE", "ACCOUNT"),
        help="reference an EXISTING macOS Keychain generic password",
    )
    p.add_argument("--force", action="store_true", help="overwrite the config file (never a seed)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("did", help="print the public did:key")
    p.set_defaults(func=cmd_did)

    p = sub.add_parser("say", help="signed room message (DRY-RUN unless --commit)")
    p.add_argument("room")
    p.add_argument("text")
    p.add_argument("--commit", action="store_true", help="actually sign and POST")
    p.add_argument(
        "--allow-sensitive",
        action="store_true",
        help="permit 64+ hex runs / PEM-looking text (e.g. public digests)",
    )
    p.add_argument("--nonce", help="override the nonce (1-19 ASCII digits)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_say)

    p = sub.add_parser("verify", help="offline-verify every receipt (signatures + chain)")
    p.add_argument(
        "--ledger",
        metavar="PATH",
        help="verify this receipts JSONL instead of the configured ledger. "
        "Third-party verification: needs no keyhole config, seed, or "
        "network. Share the raw .jsonl — an export re-serializes lines "
        "and would break the hash chain",
    )
    p.add_argument(
        "--expect-head",
        metavar="SHA256",
        help="require this externally recorded head to still exist as a "
        "checkpoint in the chain — proves the prefix up to it is intact "
        "and detects truncation past the anchor, which the chain alone "
        "cannot; appends made after anchoring are expected and fine",
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("receipts", help="list, export, or print the head of the ledger")
    p.add_argument("action", choices=["list", "export", "head"], nargs="?", default="list")
    p.set_defaults(func=cmd_receipts)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
