"""Agent Ed25519 files: ~/.agents/keys/<slug>.ed25519 (libsodium secret)."""
from __future__ import annotations

import os
import re
from pathlib import Path

from nacl.signing import SigningKey

_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def slug_ok(slug: str) -> bool:
    return bool(_SLUG.match(slug))


def keys_dir() -> Path:
    env = os.environ.get("AGENTS_KEYS_DIR", "").strip()
    if env:
        return Path(env)
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or ""
    if not home:
        raise RuntimeError("HOME / USERPROFILE unset")
    return Path(home) / ".agents" / "keys"


def key_path(slug: str) -> Path:
    if not slug_ok(slug):
        raise ValueError("slug must be lowercase [a-z0-9._-], start with a letter or digit")
    return keys_dir() / f"{slug}.ed25519"


def _b58_encode(data: bytes) -> str:
    digits = [0]
    for byte in data:
        carry = byte
        for i, d in enumerate(digits):
            carry += d * 256
            digits[i] = carry % 58
            carry //= 58
        while carry:
            digits.append(carry % 58)
            carry //= 58
    pad = 0
    for byte in data:
        if byte != 0:
            break
        pad += 1
    return ("1" * pad) + "".join(_B58[d] for d in reversed(digits))


def _b58_decode(base58: str) -> bytes:
    if base58 == "":
        return b""
    map_ = {c: i for i, c in enumerate(_B58)}
    digits = [0]
    for char in base58:
        if char not in map_:
            raise ValueError("invalid base58 character")
        carry = map_[char]
        for i, d in enumerate(digits):
            carry += d * 58
            digits[i] = carry % 256
            carry //= 256
        while carry:
            digits.append(carry % 256)
            carry //= 256
    pad = 0
    for char in base58:
        if char != "1":
            break
        pad += 1
    return b"\x00" * pad + bytes(reversed(digits))


def _trim_trailing_crlf(data: bytes) -> bytes:
    while data.endswith((b"\n", b"\r")):
        data = data[:-1]
    return data


def signing_key_from_file(path: Path | str) -> SigningKey:
    raw = Path(path).read_bytes()
    if len(raw) == 64:
        return SigningKey(raw[:32])
    if len(raw) == 32:
        return SigningKey(raw)
    if raw.endswith((b"\n", b"\r")):
        raw = _trim_trailing_crlf(raw)
    if len(raw) == 64:
        return SigningKey(raw[:32])
    if len(raw) == 32:
        return SigningKey(raw)
    try:
        text = raw.decode("ascii").strip().lower()
    except UnicodeDecodeError:
        raise ValueError("key file must be 64-byte secret, 32-byte seed, or hex of either")
    if len(text) == 128 and all(c in "0123456789abcdef" for c in text):
        blob = bytes.fromhex(text)
        return SigningKey(blob[:32])
    if len(text) == 64 and all(c in "0123456789abcdef" for c in text):
        return SigningKey(bytes.fromhex(text))
    raise ValueError("key file must be 64-byte secret, 32-byte seed, or hex of either")


def did_key_from_signing_key(key: SigningKey) -> str:
    prefixed = b"\xed\x01" + bytes(key.verify_key)
    return "did:key:z" + _b58_encode(prefixed)


def did_from_path(path: Path | str) -> str:
    return did_key_from_signing_key(signing_key_from_file(path))


def sign_hex(key: SigningKey, message: str) -> str:
    return key.sign(message.encode("utf-8")).signature.hex()


def load(slug: str) -> tuple[SigningKey, str, Path]:
    path = key_path(slug)
    if not path.is_file():
        raise FileNotFoundError(f"missing {path}")
    key = signing_key_from_file(path)
    return key, did_key_from_signing_key(key), path


def sodium_secret_bytes(key: SigningKey) -> bytes:
    return key.encode() + key.verify_key.encode()


def mint(slug: str) -> dict[str, str]:
    path = key_path(slug)
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_file():
        raise FileExistsError(f"key already exists: {path}")
    key = SigningKey.generate()
    path.write_bytes(sodium_secret_bytes(key))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return {"slug": slug, "path": str(path), "did": did_key_from_signing_key(key)}
