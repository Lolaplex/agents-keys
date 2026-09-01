"""OpenSSH ssh-ed25519 import/export (same 32-byte key as did:key)."""
from __future__ import annotations

import base64
import struct
from pathlib import Path

from nacl.signing import SigningKey

from .store import did_key_from_signing_key, signing_key_from_file, sodium_secret_bytes


def _ssh_wire_pubkey(pub: bytes) -> bytes:
    if len(pub) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    key_type = b"ssh-ed25519"
    return struct.pack(">I", len(key_type)) + key_type + struct.pack(">I", len(pub)) + pub


def ssh_ed25519_pubkey_line(key: SigningKey, comment: str = "agents-keys") -> str:
    pub = bytes(key.verify_key)
    blob = base64.b64encode(_ssh_wire_pubkey(pub)).decode("ascii")
    return f"ssh-ed25519 {blob} {comment}"


def _read_ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ValueError("truncated ssh string length")
    (length,) = struct.unpack(">I", data[offset : offset + 4])
    offset += 4
    end = offset + length
    if end > len(data):
        raise ValueError("truncated ssh string payload")
    return data[offset:end], end


def signing_key_from_openssh_private(path: Path | str) -> SigningKey:
    raw = Path(path).read_bytes()
    if not raw.startswith(b"openssh-key-v1\x00"):
        raise ValueError("not an OpenSSH private key (openssh-key-v1)")
    offset = 15
    cipher, offset = _read_ssh_string(raw, offset)
    kdf, offset = _read_ssh_string(raw, offset)
    _kdf_opts, offset = _read_ssh_string(raw, offset)
    if cipher != b"none" or kdf != b"none":
        raise ValueError("encrypted OpenSSH keys are not supported; use an unencrypted key")
    if offset + 4 > len(raw):
        raise ValueError("truncated key count")
    (num_keys,) = struct.unpack(">I", raw[offset : offset + 4])
    offset += 4
    if num_keys != 1:
        raise ValueError("only single-key OpenSSH files are supported")
    _pub_blob, offset = _read_ssh_string(raw, offset)
    priv_blob, offset = _read_ssh_string(raw, offset)
    check1 = struct.unpack(">I", priv_blob[0:4])[0]
    check2 = struct.unpack(">I", priv_blob[4:8])[0]
    if check1 != check2:
        raise ValueError("OpenSSH private key checkints mismatch")
    pos = 8
    key_type, pos = _read_ssh_string(priv_blob, pos)
    if key_type != b"ssh-ed25519":
        raise ValueError(f"unsupported OpenSSH key type: {key_type!r}")
    _pub, pos = _read_ssh_string(priv_blob, pos)
    priv, pos = _read_ssh_string(priv_blob, pos)
    if len(priv) < 32:
        raise ValueError("Ed25519 private blob too short")
    return SigningKey(priv[:32])


def import_key_file(slug_path: Path, source: Path | str) -> dict[str, str]:
    source = Path(source)
    if not source.is_file():
        raise FileNotFoundError(f"missing {source}")
    raw = source.read_bytes()
    if raw.startswith(b"openssh-key-v1"):
        key = signing_key_from_openssh_private(source)
    else:
        key = signing_key_from_file(source)
    slug_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if slug_path.is_file():
        raise FileExistsError(f"key already exists: {slug_path}")
    slug_path.write_bytes(sodium_secret_bytes(key))
    try:
        import os

        os.chmod(slug_path, 0o600)
    except OSError:
        pass
    did = did_key_from_signing_key(key)
    return {"path": str(slug_path), "did": did}
