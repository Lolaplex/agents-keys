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
from .store import did_from_path, key_path, load, mint, sign_b64url, sign_hex


_SIG_TOKEN = re.compile(r"[A-Za-z0-9_-]{86}")
_VERIFY_FLAGS = {"--stdin", "--help-json", "-h", "--help"}


def _message_arg(value: str | None, use_stdin: bool) -> str:
    """Resolve a message positional: '-' or --stdin reads stdin verbatim."""
    if use_stdin or value == "-":
        return sys.stdin.read()
    if value is None:
        raise ValueError("message required (pass it positionally, '-', or --stdin)")
    return value


def help_json() -> dict:
    return {
        "name": "agents-keys",
        "version": __version__,
        "commands": {
            "mint": {
                "usage": "agents-keys mint <slug>",
                "description": "Write <host>/keys/<slug>.ed25519. Print did:key only.",
                "side_effects": "mutating",
                "effects": ["writes <host>/keys/<slug>.ed25519"],
            },
            "ensure": {
                "usage": "agents-keys ensure <slug>",
                "description": "Print did:key; mint <host>/keys/<slug>.ed25519 on first call.",
                "side_effects": "mutating",
                "effects": ["writes <host>/keys/<slug>.ed25519 if missing"],
            },
            "import": {
                "usage": "agents-keys import <slug> <path>",
                "description": "Import unencrypted OpenSSH or sodium secret; print did:key only.",
                "side_effects": "mutating",
                "effects": ["writes <host>/keys/<slug>.ed25519"],
            },
            "did": {
                "usage": "agents-keys did <slug>",
                "description": "Derive did:key from the key file.",
                "side_effects": "read-only",
                "effects": [],
            },
            "ssh-pubkey": {
                "usage": "agents-keys ssh-pubkey <slug>",
                "description": "Print one ssh-ed25519 public line for the slug key.",
                "side_effects": "read-only",
                "effects": [],
            },
            "sign": {
                "usage": "agents-keys sign <slug> [<nonce>|-|--stdin] [--b64url]",
                "description": "Ed25519 signature over the message. Hex by default; --b64url emits the verify-compatible form.",
                "side_effects": "read-only",
                "effects": [],
            },
            "verify": {
                "usage": "agents-keys verify <did> [<message>|-|--stdin] <sig>",
                "description": "Verify an 86-char unpadded base64url Ed25519 signature made by did:key.",
                "side_effects": "read-only",
                "effects": [],
            },
            "prove": {
                "usage": "agents-keys prove <slug> <board-url> [--verb VERB] [--handle HANDLE] [--successor-did DID]",
                "description": "Challenge the board and print {did, nonce, signature, event_signature?}.",
                "side_effects": "mutating",
                "effects": ["network fetch"],
            },
            "resolve": {
                "usage": "agents-keys resolve <locator>",
                "description": "Fetch did.json / mailto home doc; print keys JSON. Exit 3 when a pinned locator serves a different did:key.",
                "side_effects": "read-only",
                "effects": ["network fetch"],
            },
            "pin": {
                "usage": "agents-keys pin <locator>",
                "description": "Resolve locator and TOFU-pin did:key to <host>/keys/known-dids.jsonl.",
                "side_effects": "mutating",
                "effects": ["network fetch", "writes <host>/keys/known-dids.jsonl"],
            },
        },
        "flags": ["--help-json", "--stdin", "--b64url"],
        "env": ["AGENTS_KEYS_DIR", "AGENTS_KNOWN_DIDS_FILE", "AGENTS_USERS_FILE"],
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
    sign_p.add_argument("nonce", nargs="?", help="message to sign ('-' or --stdin reads stdin)")
    sign_p.add_argument("--stdin", action="store_true", help="read the message from stdin")
    sign_p.add_argument("--b64url", action="store_true", help="print base64url signature (verify-compatible)")
    ver_p = sub.add_parser("verify", help="Verify a did:key signature (base64url) over a message")
    ver_p.add_argument("did")
    ver_p.add_argument("message", nargs="?", help="message that was signed ('-' or --stdin reads stdin)")
    ver_p.add_argument("sig", nargs="?", help="86-char unpadded base64url signature")
    ver_p.add_argument("--stdin", action="store_true", help="read the message from stdin")
    ens_p = sub.add_parser("ensure", help="Print did:key, minting the key once if missing")
    ens_p.add_argument("slug")
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
    argv = list(sys.argv[1:] if argv is None else argv)
    rescued_sig: str | None = None
    if argv[:1] == ["verify"]:
        # The sig is the last positional; argparse misroutes it when it starts
        # with '-' or trails a flag (nargs='?' eats the match). Rescue only
        # those: '-'-leading non-flag tokens (malformed ones included, so
        # verify_did exits 1 instead of argparse 2) and a sig-shaped token
        # orphaned after a flag. An 86-char message stays the message.
        for i in range(len(argv) - 1, 0, -1):
            tok = argv[i]
            dash_leading = (
                len(tok) > 1
                and tok.startswith("-")
                and tok not in _VERIFY_FLAGS
            )
            flag_orphaned = argv[i - 1] in _VERIFY_FLAGS and _SIG_TOKEN.fullmatch(tok)
            if dash_leading or flag_orphaned:
                rescued_sig = argv.pop(i)
                break
    args = parser.parse_args(argv)
    if rescued_sig is not None:
        if args.sig is not None:
            print("verify takes one signature", file=sys.stderr)
            return 2
        args.sig = rescued_sig
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
        if args.command == "ensure":
            try:
                out = mint(args.slug)
                print(f"wrote {out['path']} (secret, 0600).", file=sys.stderr)
            except FileExistsError:
                _key, did, _path = load(args.slug)
                out = {"did": did}
            print(out["did"])
            return 0
        if args.command == "sign":
            key, _did, _path = load(args.slug)
            try:
                message = _message_arg(args.nonce, args.stdin)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 2
            if args.b64url:
                print(sign_b64url(key, message.encode("utf-8")))
            else:
                print(sign_hex(key, message))
            return 0
        if args.command == "verify":
            from .store import verify_did
            sig = args.sig
            message_arg = args.message
            if args.stdin and sig is None and message_arg is not None:
                # `verify <did> --stdin <sig>`: single positional is the sig.
                sig, message_arg = message_arg, None
            try:
                message = _message_arg(message_arg, args.stdin)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 2
            if sig is None:
                print("verify needs a signature argument", file=sys.stderr)
                return 2
            try:
                verify_did(args.did, message.encode("utf-8"), sig)
            except ValueError as e:
                print(f"invalid: {e}", file=sys.stderr)
                return 1
            print("valid")
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
