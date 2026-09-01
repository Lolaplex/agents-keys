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

from agents_keys.store import (
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
ROOT = Path(__file__).resolve().parents[1]


class TestStore(unittest.TestCase):
    def test_golden_did_and_signature(self):
        key = SigningKey(bytes.fromhex(GOLDEN_SEED))
        self.assertEqual(did_key_from_signing_key(key), GOLDEN_DID)
        self.assertEqual(sign_hex(key, GOLDEN_MESSAGE), GOLDEN_SIG)

    def test_load_64_byte_sodium_secret(self):
        key = SigningKey(bytes.fromhex(GOLDEN_SEED))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "probe.ed25519"
        path.write_bytes(sodium_secret_bytes(key))
        loaded = signing_key_from_file(path)
        self.assertEqual(did_key_from_signing_key(loaded), GOLDEN_DID)

    def test_mint_refuses_overwrite(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            first = mint("probe")
            self.assertTrue(first["did"].startswith("did:key:z6Mk"))
            self.assertEqual(load("probe")[1], first["did"])
            with self.assertRaises(FileExistsError):
                mint("probe")


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
        self.assertIn("prove", data["commands"])

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

    def test_prove_prints_json(self):
        from agents_keys.cli import main

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            minted = mint("prove-bot")
            out = io.StringIO()
            err = io.StringIO()
            with patch("agents_keys.cli.fetch_challenge", return_value="board-login:n"):
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
