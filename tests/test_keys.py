"""Ed25519 did:key mint/sign (libsodium file format)."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from nacl.signing import SigningKey

from agents_keys.pins import PinMismatchError, load_pins, pin_locator, pins_path
from agents_keys.resolve import extract_ed25519_dids, resolve_locator
from agents_keys.ssh import ssh_ed25519_pubkey_line
from agents_keys.store import (
    _b58_encode,
    did_key_from_signing_key,
    load,
    mint,
    sign_hex,
    signing_key_from_file,
    sodium_secret_bytes,
)

GOLDEN_SEED = "1111111111111111111111111111111111111111111111111111111111111111"
GOLDEN_DID = "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S"
GOLDEN_MESSAGE = "board-login:golden"
GOLDEN_SIG = (
    "b19584f1413e30cc6e573c3f98346dd9be319400f57d49be6f24a57f1b7fdacc"
    "840bdf957acf61ddde57fb80875e87d0be430ab3ef47d69907a2d4c5514ed00e"
)
GOLDEN_SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4UgozLJd4c3 agents-keys"
ROOT = Path(__file__).resolve().parents[1]


def _golden_key() -> SigningKey:
    return SigningKey(bytes.fromhex(GOLDEN_SEED))


class TestStore(unittest.TestCase):
    def test_golden_did_and_signature(self):
        key = _golden_key()
        self.assertEqual(did_key_from_signing_key(key), GOLDEN_DID)
        self.assertEqual(sign_hex(key, GOLDEN_MESSAGE), GOLDEN_SIG)

    def test_golden_ssh_pubkey_line(self):
        line = ssh_ed25519_pubkey_line(_golden_key(), comment="agents-keys")
        self.assertEqual(line, GOLDEN_SSH)

    def test_load_64_byte_sodium_secret(self):
        key = _golden_key()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "probe.ed25519"
        path.write_bytes(sodium_secret_bytes(key))
        loaded = signing_key_from_file(path)
        self.assertEqual(did_key_from_signing_key(loaded), GOLDEN_DID)

    def test_load_64_byte_secret_with_trailing_crlf(self):
        key = SigningKey.generate()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "probe.ed25519"
        blob = sodium_secret_bytes(key)
        while blob[-1] in (0x0A, 0x0D):
            key = SigningKey.generate()
            blob = sodium_secret_bytes(key)
        path.write_bytes(blob + b"\r\n")
        loaded = signing_key_from_file(path)
        self.assertEqual(did_key_from_signing_key(loaded), did_key_from_signing_key(key))

    def test_mint_refuses_overwrite(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            first = mint("probe")
            self.assertTrue(first["did"].startswith("did:key:z6Mk"))
            self.assertEqual(load("probe")[1], first["did"])
            with self.assertRaises(FileExistsError):
                mint("probe")


class TestResolve(unittest.TestCase):
    def test_extract_ed25519_from_doc(self):
        pub = bytes(_golden_key().verify_key)
        prefixed = b"\xed\x01" + pub
        mb = "z" + _b58_encode(prefixed)
        doc = {
            "id": "did:web:corp.example",
            "alsoKnownAs": ["mailto:alice@corp.example", GOLDEN_DID],
            "verificationMethod": [
                {
                    "id": "did:web:corp.example#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:corp.example",
                    "publicKeyMultibase": mb,
                }
            ],
        }
        keys = extract_ed25519_dids(doc)
        self.assertIn(GOLDEN_DID, keys)

    def test_resolve_mailto_mocked(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pub = bytes(_golden_key().verify_key)
        mb = "z" + _b58_encode(b"\xed\x01" + pub)
        doc = {
            "id": "did:web:corp.example",
            "alsoKnownAs": ["mailto:alice@corp.example"],
            "verificationMethod": [{"publicKeyMultibase": mb, "type": "Ed25519VerificationKey2020"}],
        }

        def fake_get(url: str) -> str:
            self.assertIn("corp.example", url)
            return json.dumps(doc)

        with patch.dict(os.environ, {"AGENTS_KNOWN_DIDS": str(Path(tmp.name) / "pins.jsonl")}):
            with patch("agents_keys.resolve._fetch_json", return_value=doc):
                result = resolve_locator("mailto:alice@corp.example")
        self.assertEqual(result.did, GOLDEN_DID)
        self.assertTrue(result.match)


class TestPins(unittest.TestCase):
    def test_pin_tofu_then_mismatch(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        with patch.dict(os.environ, {"AGENTS_KNOWN_DIDS": str(pin_file)}):
            pin_locator(GOLDEN_DID, ["mailto:alice@corp.example"])
            self.assertEqual(len(load_pins()), 1)
            with self.assertRaises(PinMismatchError):
                pin_locator("did:key:z6MkOTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROt", ["mailto:alice@corp.example"])


class TestCli(unittest.TestCase):
    def _run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = dict(os.environ)
        merged["PYTHONPATH"] = str(ROOT / "src")
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, "-m", "agents_keys", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=merged,
        )

    def test_help_json(self):
        proc = self._run("--help-json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["name"], "agents-keys")
        self.assertIn("mint", data["commands"])
        self.assertIn("pin", data["commands"])
        self.assertIn("resolve", data["commands"])

    def test_mint_did_sign_roundtrip(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = {"AGENTS_KEYS_DIR": tmp.name}
        minted = self._run("mint", "cli-bot", env=env)
        self.assertEqual(minted.returncode, 0, minted.stderr)
        did = minted.stdout.strip()
        self.assertTrue(did.startswith("did:key:z6Mk"))
        self.assertNotIn("private", minted.stdout.lower())
        shown = self._run("did", "cli-bot", env=env)
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertEqual(shown.stdout.strip(), did)
        nonce = "board-login:cli"
        signed = self._run("sign", "cli-bot", nonce, env=env)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            key, _, _ = load("cli-bot")
            self.assertEqual(signed.stdout.strip(), sign_hex(key, nonce))

    def test_ssh_pubkey_command(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = {"AGENTS_KEYS_DIR": tmp.name}
        self._run("mint", "ssh-bot", env=env)
        proc = self._run("ssh-pubkey", "ssh-bot", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.strip().startswith("ssh-ed25519 "))

    def test_prove_prints_json(self):
        from agents_keys.cli import main

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            minted = mint("prove-bot")
            out = io.StringIO()
            err = io.StringIO()
            with patch("agents_keys.cli.fetch_challenge", return_value={"nonce": "board-login:n"}):
                with redirect_stdout(out), redirect_stderr(err):
                    rc = main(["prove", "prove-bot", "https://board.example"])
            self.assertEqual(rc, 0, err.getvalue())
            body = json.loads(out.getvalue())
            self.assertEqual(body["did"], minted["did"])
            self.assertEqual(body["nonce"], "board-login:n")
            key, _, _ = load("prove-bot")
            self.assertEqual(body["signature"], sign_hex(key, "board-login:n"))


if __name__ == "__main__":
    unittest.main()
