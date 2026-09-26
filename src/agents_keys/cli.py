"""CLI for agents-keys."""
from __future__ import annotations

import argparse
import json
import re
import sys

from . import __version__
from .pins import PinMismatchError
from .prove import fetch_challenge
from .resolve import resolve_locator
from .ssh import import_key_file, ssh_ed25519_pubkey_line
from .store import did_from_path, key_path, load, mint, sign_hex


def help_json() -> dict:
    return {
        "name": "agents-keys",
        "version": __version__,
        "commands": {
            "mint": {
                "usage": "agents-keys mint <slug>",
                "description": "Write ~/.agents/keys/<slug>.ed25519. Print did:key only.",
            },
            "import": {
                "usage": "agents-keys import <slug> <path>",
                "description": "Import unencrypted OpenSSH or sodium secret; print did:key only.",
            },
            "did": {
                "usage": "agents-keys did <slug>",
                "description": "Derive did:key from the key file.",
            },
            "ssh-pubkey": {
                "usage": "agents-keys ssh-pubkey <slug>",
                "description": "Print one ssh-ed25519 public line for the slug key.",
            },
            "sign": {
                "usage": "agents-keys sign <slug> <nonce>",
                "description": "Ed25519 signature hex over the nonce.",
            },
            "prove": {
                "usage": "agents-keys prove <slug> <board-url> [--verb VERB] [--handle HANDLE] [--successor-did DID]",
                "description": "Challenge the board and print {did, nonce, signature, event_signature?}.",
            },
            "resolve": {
                "usage": "agents-keys resolve <locator>",
                "description": "Fetch did.json / mailto home doc; print keys JSON.",
            },
            "pin": {
                "usage": "agents-keys pin <locator>",
                "description": "Resolve locator and TOFU-pin did:key to ~/.agents/known-dids.jsonl.",
            },
        },
        "flags": ["--help-json"],
        "env": ["AGENTS_KEYS_DIR", "AGENTS_KNOWN_DIDS"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agents-keys",
        description="Mint and sign agent Ed25519 keys. Secret stays on this machine.",
    )
    parser.add_argument("--help-json", action="store_true", help="Emit machine-readable CLI spec as JSON.")
    sub = parser.add_subparsers(dest="command")
    mint_p = sub.add_parser("mint", help="Create a key file and print did:key")
    mint_p.add_argument("slug")
    imp_p = sub.add_parser("import", help="Import a key file and print did:key")
    imp_p.add_argument("slug")
    imp_p.add_argument("path")
    did_p = sub.add_parser("did", help="Print did:key from an existing file")
    did_p.add_argument("slug")
    ssh_p = sub.add_parser("ssh-pubkey", help="Print ssh-ed25519 public line")
    ssh_p.add_argument("slug")
    sign_p = sub.add_parser("sign", help="Sign a nonce")
    sign_p.add_argument("slug")
    sign_p.add_argument("nonce")
    prove_p = sub.add_parser("prove", help="Board challenge + signature JSON")
    prove_p.add_argument("slug")
    prove_p.add_argument("board_url")
    prove_p.add_argument("--verb", default="")
    prove_p.add_argument("--handle", default="")
    prove_p.add_argument("--successor-did", default="")
    resolve_p = sub.add_parser("resolve", help="Resolve locator to did:key JSON")
    resolve_p.add_argument("locator")
    pin_p = sub.add_parser("pin", help="Resolve and pin did:key (TOFU)")
    pin_p.add_argument("locator")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.help_json:
        try:
            from .updates import check_for_updates
            check_for_updates("agents-keys", __version__)
        except Exception:
            pass
    if args.help_json:
        print(json.dumps(help_json(), indent=2))
        return 0
    try:
        if args.command == "mint":
            out = mint(args.slug)
            print(out["did"])
            print(
                f"wrote {out['path']} (secret, 0600). Prove with: agents-keys prove {args.slug} <board-url>",
                file=sys.stderr,
            )
            return 0
        if args.command == "import":
            out = import_key_file(key_path(args.slug), args.path)
            print(out["did"])
            print(f"wrote {out['path']} (secret, 0600).", file=sys.stderr)
            return 0
        if args.command == "did":
            print(did_from_path(key_path(args.slug)))
            return 0
        if args.command == "ssh-pubkey":
            key, _did, _path = load(args.slug)
            print(ssh_ed25519_pubkey_line(key))
            return 0
        if args.command == "sign":
            key, _did, _path = load(args.slug)
            print(sign_hex(key, args.nonce))
            return 0
        if args.command == "prove":
            board = args.board_url.rstrip("/")
            if not re.match(r"^https?://", board, re.I):
                print("prove needs a board URL (https://…)", file=sys.stderr)
                return 2
            key, did, _path = load(args.slug)
            scope: dict[str, str] = {}
            if args.verb:
                scope["verb"] = args.verb
            if args.handle:
                scope["handle"] = args.handle
            if args.successor_did:
                scope["successor_did"] = args.successor_did
            challenge = fetch_challenge(board, did, scope or None)
            nonce = str(challenge["nonce"])
            out: dict[str, str] = {
                "did": did,
                "nonce": nonce,
                "signature": sign_hex(key, nonce),
            }
            event_canonical = challenge.get("event_canonical")
            if isinstance(event_canonical, str) and event_canonical:
                out["event_signature"] = sign_hex(key, event_canonical)
            print(json.dumps(out, separators=(",", ":")))
            return 0
        if args.command == "resolve":
            result = resolve_locator(args.locator, pin=False)
            print(json.dumps(result.to_dict(), separators=(",", ":")))
            return 0 if result.match else 3
        if args.command == "pin":
            result = resolve_locator(args.locator, pin=True)
            print(json.dumps(result.to_dict(), separators=(",", ":")))
            return 0
    except PinMismatchError as e:
        print(str(e), file=sys.stderr)
        return 3
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 1
    except (ValueError, RuntimeError, OSError) as e:
        print(str(e), file=sys.stderr)
        return 1
    parser.print_help()
    return 0
