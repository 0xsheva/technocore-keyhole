"""Minimal HTTP client for the signed lane. Stdlib only.

Automated writes use POST, not the GET write lane — a GET that writes turns
every URL-fetcher into a confused deputy, and upstream documents that hazard.
422 (cross-sender duplicate) and 429 are STOP signals: surfaced verbatim,
never retried here.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

USER_AGENT = "technocore-keyhole/0.1"
TIMEOUT = 30


class ServerRefusal(RuntimeError):
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body[:500]}")


def post_signed_say(base_url: str, room: str, did: str, sig: str, nonce: str, text: str) -> dict:
    """POST the signed message; return the server's parsed JSON response.

    `text` must already be the swept text the signature covers — the server
    re-sweeps idempotently, so the stored bytes match what was signed.
    """
    url = f"{base_url.rstrip('/')}/r/{room}?format=json"
    payload = json.dumps(
        {"did": did, "sig": sig, "nonce": nonce, "text": text},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ServerRefusal(exc.code, body) from None
    except urllib.error.URLError as exc:
        raise ServerRefusal(0, f"could not reach {base_url}: {exc.reason}") from None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}
