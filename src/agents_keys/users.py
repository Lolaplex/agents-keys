"""Host users file: <host>/users.json (user_id -> aliases + did:key).

agents-keys owns this file. Canonical schema:
{"users": {"u_<12hex>": {"id": "u_<12hex>", "aliases": ["..."], "did": "did:key:..."}}}.
Legacy `<host>/identity.json` migrates in once (C80 carries the file move).
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path


def _host_dir_fallback() -> Path:
    raw = os.environ.get("AGENTS_HOST_DIR", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".agents").resolve()


def users_file() -> Path:
    try:
        from agents_workspace import Host

        return Host.from_env().users_file(os.environ)
    except ImportError:
        env = os.environ.get("AGENTS_USERS_FILE", "").strip()
        if env:
            return Path(env).expanduser().resolve()
        legacy_env = os.environ.get("AGENTS_IDENTITY_PATH", "").strip()
        if legacy_env:
            import warnings

            warnings.warn(
                "AGENTS_IDENTITY_PATH is deprecated; use AGENTS_USERS_FILE",
                DeprecationWarning,
                stacklevel=2,
            )
            return Path(legacy_env).expanduser().resolve()
        return _host_dir_fallback() / "users.json"


def _legacy_identity_path() -> Path:
    try:
        from agents_workspace import Host

        return Host.from_env().dir / "identity.json"
    except ImportError:
        return _host_dir_fallback() / "identity.json"


def _mint_user_id(existing: dict) -> str:
    uid = "u_" + uuid.uuid4().hex[:12]
    while uid in existing:
        uid = "u_" + uuid.uuid4().hex[:12]
    return uid


def _find_by_alias(users: dict, alias: str) -> tuple[str, dict] | None:
    for key, row in users.items():
        if not isinstance(row, dict):
            continue
        aliases = row.get("aliases")
        if isinstance(aliases, list) and alias in [str(a) for a in aliases]:
            return key, row
    return None


def _upgrade_legacy_row(users: dict, legacy_key: str, alias: str) -> tuple[str, dict]:
    legacy_row = users.pop(legacy_key)
    if not isinstance(legacy_row, dict):
        legacy_row = {"did": str(legacy_row)} if legacy_row else {}
    uid = _mint_user_id(users)
    raw_aliases = legacy_row.get("aliases")
    aliases = (
        [str(a) for a in raw_aliases if a]
        if isinstance(raw_aliases, list)
        else []
    )
    for item in (legacy_key, alias):
        if item and item not in aliases:
            aliases.append(item)
    row = {**legacy_row, "id": uid, "aliases": aliases}
    users[uid] = row
    return uid, row


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


def bind_did(
    alias: str,
    did: str,
    users_path: Path | None = None,
    user_id: str = "",
) -> str:
    """Record did:key for an alias (e.g. 'alice', 'telegram:42') under canonical u_<12hex>."""
    target = users_path or users_file()
    data: dict = {"users": {}}
    if target.exists():
        try:
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("users"), dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            pass
    users: dict = data["users"]
    req_uid = (user_id or "").strip()

    uid = ""
    row: dict | None = None
    if req_uid:
        uid = req_uid
        existing = users.get(uid)
        if isinstance(existing, dict):
            row = existing
        else:
            row = {"id": uid, "aliases": []}
            users[uid] = row
    elif alias:
        hit = _find_by_alias(users, alias)
        if hit is not None:
            key, found = hit
            existing_id = str(found.get("id") or "").strip()
            if existing_id:
                uid = existing_id
                row = found
            else:
                uid, row = _upgrade_legacy_row(users, key, alias)
        else:
            direct = users.get(alias)
            if isinstance(direct, dict):
                if str(direct.get("id") or "").strip() == alias:
                    uid = alias
                    row = direct
                else:
                    uid, row = _upgrade_legacy_row(users, alias, alias)
            elif direct:
                uid, row = _upgrade_legacy_row(users, alias, alias)

    if row is None:
        uid = req_uid or _mint_user_id(users)
        row = {"id": uid, "aliases": [alias] if alias else []}
        users[uid] = row
    else:
        row["id"] = uid
        raw_aliases = row.get("aliases")
        aliases = (
            [str(a) for a in raw_aliases if a]
            if isinstance(raw_aliases, list)
            else []
        )
        if alias and uid != alias and alias not in aliases:
            aliases.append(alias)
        row["aliases"] = aliases

    row["did"] = did
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, target)
    return uid


def lookup_did(alias: str, users_path: Path | None = None) -> str | None:
    target = users_path or users_file()
    if not target.exists():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    users = data.get("users")
    if not isinstance(users, dict):
        return None
    for _uid, row in users.items():
        if not isinstance(row, dict):
            continue
        aliases = row.get("aliases")
        if isinstance(aliases, list) and alias in [str(a) for a in aliases]:
            did = row.get("did")
            return str(did) if did else None
    for uid, row in users.items():
        if not isinstance(row, dict):
            continue
        if uid == alias or row.get("id") == alias:
            did = row.get("did")
            return str(did) if did else None
    return None
