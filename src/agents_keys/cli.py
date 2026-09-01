"""CLI for agents-keys."""
from __future__ import annotations

import argparse
import json
import re
import sys

from . import __version__
from .prove import fetch_challenge
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
            "did": {
                "usage": "agents-keys did <slug>",
                "description": "Derive did:key from the key file.",
            },
            "sign": {
                "usage": "agents-keys sign <slug> <nonce>",
                "description": "Ed25519 signature hex over the nonce.",
            },
            "prove": {
                "usage": "agents-keys prove <slug> <board-url>",
                "description": "Challenge the board and print {did, nonce, signature}.",
            },
        },
        "flags": ["--help-json"],
        "env": ["AGENTS_KEYS_DIR"],
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
    did_p = sub.add_parser("did", help="Print did:key from an existing file")
    did_p.add_argument("slug")
    sign_p = sub.add_parser("sign", help="Sign a nonce")
    sign_p.add_argument("slug")
    sign_p.add_argument("nonce")
    prove_p = sub.add_parser("prove", help="Board challenge + signature JSON")
    prove_p.add_argument("slug")
    prove_p.add_argument("board_url")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.help_json:
        print(json.dumps(help_json(), indent=2))
        return 0
    try:
        if args.command == "mint":
            out = mint(args.slug)
            print(out["did"])
            print(f"wrote {out['path']} (secret, 0600). Prove with: agents-keys prove {args.slug} <board-url>", file=sys.stderr)
            return 0
        if args.command == "did":
            print(did_from_path(key_path(args.slug)))
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
            nonce = fetch_challenge(board, did)
            print(json.dumps({"did": did, "nonce": nonce, "signature": sign_hex(key, nonce)}, separators=(",", ":")))
            return 0
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
