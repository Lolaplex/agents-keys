"""Resolve locators to did:key principals via live did.json fetch."""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from .pins import PinMismatchError, check_keys_match_pin, find_pin, pin_locator
from .store import _b58_decode, _b58_encode


@dataclass
class ResolveResult:
    did: str
    keys: list[str]
    locators: list[str]
    source_url: str | None
    pinned: bool
    match: bool

    def to_dict(self) -> dict:
        return {
            "did": self.did,
            "keys": self.keys,
            "locators": self.locators,
            "source_url": self.source_url,
            "pinned": self.pinned,
            "match": self.match,
        }


def _fetch_json(url: str, timeout: float = 8.0) -> dict:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json, application/did+ld+json, */*"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        raise RuntimeError(f"fetch failed: {e}") from e
    if len(raw) > 65536:
        raw = raw[:65536]
    doc = json.loads(raw) if raw else {}
    if not isinstance(doc, dict):
        raise RuntimeError("did document is not a JSON object")
    return doc


def _pub_bytes_to_did(pub: bytes) -> str | None:
    if len(pub) != 32:
        return None
    prefixed = b"\xed\x01" + pub
    return "did:key:z" + _b58_encode(prefixed)


def _multibase_ed25519_to_did(multibase: str) -> str | None:
    if not multibase.startswith("z"):
        return None
    try:
        raw = _b58_decode(multibase[1:])
    except ValueError:
        return None
    if len(raw) < 34 or raw[0] != 0xED or raw[1] != 0x01:
        return None
    return _pub_bytes_to_did(raw[2:34])


def _jwk_ed25519_to_did(jwk: dict) -> str | None:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    x = jwk.get("x")
    if not isinstance(x, str) or x == "":
        return None
    pad = "=" * ((4 - len(x) % 4) % 4)
    try:
        pub = base64.urlsafe_b64decode(x + pad)
    except Exception:
        return None
    return _pub_bytes_to_did(pub)


def extract_ed25519_dids(doc: dict) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()

    def add(did: str | None) -> None:
        if did and did.startswith("did:key:z") and did not in seen:
            seen.add(did)
            keys.append(did)

    aka = doc.get("alsoKnownAs") or []
    if isinstance(aka, list):
        for entry in aka:
            if isinstance(entry, str) and entry.startswith("did:key:"):
                add(entry)

    vms = doc.get("verificationMethod") or []
    if isinstance(vms, list):
        for vm in vms:
            if not isinstance(vm, dict):
                continue
            vm_type = str(vm.get("type") or "")
            if "Ed25519" in vm_type or vm_type == "Multikey":
                mb = vm.get("publicKeyMultibase")
                if isinstance(mb, str):
                    add(_multibase_ed25519_to_did(mb))
            jwk = vm.get("publicKeyJwk")
            if isinstance(jwk, dict):
                add(_jwk_ed25519_to_did(jwk))

    return keys


def _locator_to_fetch(locator: str) -> tuple[str, list[str]]:
    locator = locator.strip()
    locators = [locator]
    if locator.startswith("did:key:"):
        return locator, locators
    if locator.startswith("mailto:"):
        email = locator[len("mailto:") :].lower()
        m = re.match(r"^[^@]+@([^@]+)$", email)
        if not m:
            raise ValueError("invalid mailto locator")
        domain = m.group(1)
        url = f"https://{domain}/.well-known/did.json"
        return url, locators + [f"did:web:{domain}"]
    if locator.startswith("did:web:"):
        rest = locator[len("did:web:") :]
        host = rest.split(":", 1)[0].replace("%3A", ":").replace("%3a", ":")
        path = ""
        if ":" in rest:
            path = "/" + rest.split(":", 1)[1].replace(":", "/")
        url = f"https://{host}{path}/did.json" if path else f"https://{host}/.well-known/did.json"
        return url, locators
    if locator.startswith("http://") or locator.startswith("https://"):
        return locator, locators
    raise ValueError("locator must be did:key, mailto, did:web, or https URL")


def resolve_locator(locator: str, *, pin: bool = False) -> ResolveResult:
    fetch_target, locators = _locator_to_fetch(locator)
    source_url: str | None = None
    keys: list[str] = []

    if fetch_target.startswith("did:key:"):
        keys = [fetch_target]
    else:
        source_url = fetch_target
        doc = _fetch_json(fetch_target)
        if locator.startswith("mailto:"):
            want = locator.lower()
            aka = doc.get("alsoKnownAs") or []
            if not isinstance(aka, list) or want not in [str(a).lower() for a in aka]:
                raise RuntimeError(f"home did.json does not cite {locator}")
        keys = extract_ed25519_dids(doc)
        if not keys:
            raise RuntimeError("no Ed25519 did:key found in document")

    primary = keys[0]
    if pin:
        pin_locator(primary, locators)
        pinned = True
        match = True
    else:
        pinned = find_pin(primary) is not None
        match, _ = check_keys_match_pin(keys, primary)

    return ResolveResult(
        did=primary,
        keys=keys,
        locators=locators,
        source_url=source_url,
        pinned=pinned,
        match=match,
    )
