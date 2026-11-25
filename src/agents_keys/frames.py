"""Canonical ws-frame/1 signing (ws:announce / ws:revoke payloads)."""
from __future__ import annotations

import json

from .store import load, sign_b64url, verify_did

FRAME_DOMAIN = "ws-frame/1"
_STRIP = ("sig", "signature")


def canonical_frame_bytes(kind: str, payload: dict) -> bytes:
    """`ws-frame/1\n<kind>\n<canonical-json>`; sig/signature keys stripped."""
    if not isinstance(kind, str) or not kind or "\n" in kind or "\r" in kind:
        raise ValueError("frame kind must be a non-empty string without CR/LF")
    if not isinstance(payload, dict):
        raise ValueError("frame payload must be a dict")
    body = {k: v for k, v in payload.items() if k not in _STRIP}
    canon = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return f"{FRAME_DOMAIN}\n{kind}\n{canon}".encode("utf-8")


def sign_frame(slug: str, kind: str, payload: dict) -> dict:
    """Frame = payload + did + kind + base64url sig over the canonical bytes."""
    key, did, _path = load(slug)
    frame = {k: v for k, v in payload.items() if k not in _STRIP}
    frame["did"] = did
    frame["kind"] = kind
    frame["sig"] = sign_b64url(key, canonical_frame_bytes(kind, frame))
    return frame


def verify_frame(did: str, kind: str, frame: dict) -> None:
    """Raise ValueError unless `frame` is a `kind` frame signed by `did`."""
    if not isinstance(frame, dict):
        raise ValueError("frame must be a dict")
    if frame.get("did") != did:
        raise ValueError("frame did mismatch")
    if frame.get("kind") != kind:
        raise ValueError("frame kind mismatch")
    sig = frame.get("sig")
    if not isinstance(sig, str):
        raise ValueError("frame missing sig")
    verify_did(did, canonical_frame_bytes(kind, frame), sig)
