"""Local did:key pin store (~/.agents/known-dids.jsonl)."""
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
    env = os.environ.get("AGENTS_KNOWN_DIDS", "").strip()
    if env:
        return Path(env)
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or ""
    if not home:
        raise RuntimeError("HOME / USERPROFILE unset")
    return Path(home) / ".agents" / "known-dids.jsonl"


def load_pins(path: Path | None = None) -> list[PinRecord]:
    p = path or pins_path()
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
    loc_set = set(locators)
    for rec in load_pins():
        overlap = set(rec.locators) & loc_set
        if overlap and rec.did != did:
            joined = ", ".join(sorted(overlap))
            raise PinMismatchError(
                f"locator(s) {joined} already pinned to {rec.did}; document has {did}"
            )


def pin_locator(did: str, locators: list[str]) -> PinRecord:
    assert_can_pin(did, locators)
    return upsert_pin(did, locators, tofu=True)


def check_keys_match_pin(keys: list[str], pinned_did: str | None) -> tuple[bool, str | None]:
    """Return (match, pinned_did). If no pin, match is True and pinned_did is None."""
    if not keys:
        return False, pinned_did
    primary = keys[0]
    rec = find_pin(primary)
    if rec is None:
        return True, None
    if primary != rec.did:
        return False, rec.did
    return True, rec.did
