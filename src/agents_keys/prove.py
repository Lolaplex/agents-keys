"""Board login challenge for prove. Stdlib HTTP only."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


def fetch_challenge(
    board_url: str,
    did: str,
    scope: dict[str, str] | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    origin = board_url.rstrip("/")
    body: dict[str, Any] = {"verb": "challenge", "did": did}
    if scope:
        body["scope"] = scope
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        origin + "/login",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"challenge failed: {raw}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"challenge failed: {e}") from e
    parsed = json.loads(raw) if raw else {}
    nonce = str(parsed.get("nonce") or "")
    if nonce == "":
        raise RuntimeError(f"challenge failed: {raw}")
    return parsed
