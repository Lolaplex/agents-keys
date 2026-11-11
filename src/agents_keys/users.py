"""Host users file: <host>/users.json (alias -> user + did:key).

agents-keys owns this file. Schema: {"users": {"<alias>": {"did": "did:key:..."}}}.
Legacy `<host>/identity.json` migrates in once (C80 carries the file move).
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def users_file() -> Path:
    env = os.environ.get("AGENTS_USERS_FILE", "").strip()
    if env:
        return Path(env)
    legacy_env = os.environ.get("AGENTS_IDENTITY_PATH", "").strip()
    if legacy_env:
        import warnings
        warnings.warn(
            "AGENTS_IDENTITY_PATH is deprecated; use AGENTS_USERS_FILE",
            DeprecationWarning, stacklevel=2,
        )
        return Path(legacy_env)
    from agents_workspace import Host
    return Host.from_env().users_file()


def _legacy_identity_path() -> Path:
    from agents_workspace import Host
    return Host.from_env().dir / "identity.json"


def migrate_identity(users_path: Path | None = None,
                     identity_path: Path | None = None) -> Path | None:
    """Lift a legacy identity.json into <host>/users.json once.

    Returns the users path when a migration happened, else None.
    """
    target = users_path or users_file()
    if target.exists():
        return None
    src = identity_path or _legacy_identity_path()
    if not src.is_file() or src == target:
        return None
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, target)
    return target


def bind_did(alias: str, did: str, users_path: Path | None = None) -> None:
    """Record did:key for an alias (e.g. 'felix', 'telegram:42')."""
    target = users_path or users_file()
    data: dict = {"users": {}}
    if target.exists():
        try:
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("users"), dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            pass
    row = data["users"].setdefault(alias, {})
    row["did"] = did
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, target)


def lookup_did(alias: str, users_path: Path | None = None) -> str | None:
    target = users_path or users_file()
    if not target.exists():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    row = (data.get("users") or {}).get(alias)
    return row.get("did") if isinstance(row, dict) else None
