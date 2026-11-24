"""Local did:key pin store (<host>/keys/known-dids.jsonl)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PinRecord:
    did: str
    locators: list[str]

    def to_dict(self) -> dict:
        return {"did": self.did, "locators": self.locators}


class PinMismatchError(RuntimeError):
    pass


def pins_path() -> Path:
    env = os.environ.get("AGENTS_KNOWN_DIDS_FILE", "").strip()
    if env:
        return Path(env)
    legacy_env = os.environ.get("AGENTS_KNOWN_DIDS", "").strip()
    if legacy_env:
        import warnings
        warnings.warn(
            "AGENTS_KNOWN_DIDS is deprecated; use AGENTS_KNOWN_DIDS_FILE",
            DeprecationWarning, stacklevel=2,
        )
        return Path(legacy_env)
    try:
        from agents_workspace import Host

        return Host.from_env().keys / "known-dids.jsonl"
    except ImportError:
        raw = os.environ.get("AGENTS_HOST_DIR", "").strip()
        host_dir = Path(raw).expanduser() if raw else Path.home() / ".agents"
        return host_dir / "keys" / "known-dids.jsonl"


def _legacy_pins_path() -> Path:
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or ""
    return Path(home) / ".agents" / "known-dids.jsonl" if home else Path("~/.agents/known-dids.jsonl")


def load_pins(path: Path | None = None) -> list[PinRecord]:
    p = path or pins_path()
    if not p.is_file() and path is None:
        legacy = _legacy_pins_path()
        if legacy.is_file():
            p = legacy  # one-time read; C80 moves the file
    if not p.is_file():
        return []
    out: list[PinRecord] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        did = str(obj.get("did") or "")
        locators = obj.get("locators") or []
        if did == "":
            continue
        if not isinstance(locators, list):
            locators = []
        out.append(PinRecord(did=did, locators=[str(x) for x in locators]))
    return out


def save_pins(records: list[PinRecord], path: Path | None = None) -> None:
    p = path or pins_path()
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = [json.dumps(r.to_dict(), separators=(",", ":")) for r in records]
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def find_pin(did: str, records: list[PinRecord] | None = None) -> PinRecord | None:
    records = records if records is not None else load_pins()
    for r in records:
        if r.did == did:
            return r
    return None


def find_pins_by_locators(
    locators: list[str], records: list[PinRecord] | None = None
) -> list[PinRecord]:
    """Every record whose locators match, case-insensitive (strip + lower)."""
    records = records if records is not None else load_pins()
    wanted = {loc.strip().lower() for loc in locators}
    return [
        r for r in records
        if wanted & {loc.strip().lower() for loc in r.locators}
    ]


def find_pin_by_locator(locators: list[str], records: list[PinRecord] | None = None) -> PinRecord | None:
    hits = find_pins_by_locators(locators, records)
    return hits[0] if hits else None


def upsert_pin(did: str, locators: list[str], *, tofu: bool = True) -> PinRecord:
    records = load_pins()
    existing = find_pin(did, records)
    loc_set = sorted(set(locators))
    if existing is None:
        rec = PinRecord(did=did, locators=loc_set)
        records.append(rec)
        save_pins(records)
        return rec
    if existing.did != did:
        raise PinMismatchError(f"pin conflict for {did}")
    merged = sorted(set(existing.locators) | set(locators))
    if not tofu and merged != sorted(existing.locators):
        if set(existing.locators) != set(locators):
            raise PinMismatchError(f"locator set changed for pinned {did}")
    existing.locators = merged
    save_pins(records)
    return existing


def assert_can_pin(did: str, locators: list[str]) -> None:
    wanted = {loc.strip().lower() for loc in locators}
    for rec in load_pins():
        overlap = {loc for loc in rec.locators if loc.strip().lower() in wanted}
        if overlap and rec.did != did:
            joined = ", ".join(sorted(overlap))
            raise PinMismatchError(
                f"locator(s) {joined} already pinned to {rec.did}; document has {did}"
            )


def pin_locator(did: str, locators: list[str]) -> PinRecord:
    assert_can_pin(did, locators)
    return upsert_pin(did, locators, tofu=True)


def check_keys_match_pin(
    keys: list[str],
    primary: str | None = None,
    *,
    pinned_did: str | None = None,
    locators: list[str] | tuple[str, ...] = (),
) -> tuple[bool, str | None]:
    """Return (match, pinned_did). If no pin, match is True and pinned_did is None.
    Locator pins win: every record matching a served locator is checked before
    the did pin, and any pinned did that differs from the served primary is a
    TOFU break (match=False, expected pinned did returned)."""
    primary = primary if primary is not None else (keys[0] if keys else None)
    if pinned_did is not None and pinned_did != primary:
        return False, pinned_did
    if primary is None:
        return False, pinned_did
    for rec in find_pins_by_locators(locators):
        if rec.did != primary:
            return False, rec.did
    rec = find_pin(primary)
    if rec is None:
        return True, None
    return True, rec.did
