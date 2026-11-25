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

from agents_keys.frames import canonical_frame_bytes, sign_frame, verify_frame
from agents_keys.pins import (
    PinMismatchError,
    PinRecord,
    check_keys_match_pin,
    find_pin_by_locator,
    find_pins_by_locators,
    load_pins,
    pin_locator,
    pins_path,
)
from agents_keys.resolve import extract_ed25519_dids, resolve_locator
from agents_keys.ssh import ssh_ed25519_pubkey_line
from agents_keys.store import (
    _b58_encode,
    did_key_from_signing_key,
    load,
    mint,
    sign_b64url,
    sign_hex,
    signing_key_from_file,
    sodium_secret_bytes,
    verify_did,
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

    def test_locator_lookup_finds_pin(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        with patch.dict(os.environ, {"AGENTS_KNOWN_DIDS_FILE": str(pin_file)}):
            pin_locator(GOLDEN_DID, ["mailto:alice@corp.example", "did:web:corp.example"])
            rec = find_pin_by_locator(["did:web:corp.example"])
            self.assertIsNotNone(rec)
            self.assertEqual(rec.did, GOLDEN_DID)
            self.assertIsNone(find_pin_by_locator(["mailto:nobody@else.example"]))


class TestTofuLocatorSwap(unittest.TestCase):
    """A pinned locator serving a different did:key is a TOFU break, not a pass."""

    def _doc_for(self, did_key, locator):
        pub = bytes(did_key.verify_key)
        return {
            "id": "did:web:corp.example",
            "alsoKnownAs": [locator],
            "verificationMethod": [
                {
                    "type": "Ed25519VerificationKey2020",
                    "publicKeyMultibase": "z" + _b58_encode(b"\xed\x01" + pub),
                }
            ],
        }

    def test_check_keys_match_pin_blocks_swapped_did(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        locator = "mailto:alice@corp.example"
        rogue_did = did_key_from_signing_key(SigningKey.generate())
        env = {"AGENTS_KNOWN_DIDS_FILE": str(pin_file)}
        with patch.dict(os.environ, env):
            pin_locator(GOLDEN_DID, [locator])
            match, pinned = check_keys_match_pin([rogue_did], None, locators=[locator])
            self.assertFalse(match)
            self.assertEqual(pinned, GOLDEN_DID)
            # the pinned did itself still matches
            match, pinned = check_keys_match_pin([GOLDEN_DID], None, locators=[locator])
            self.assertTrue(match)
            self.assertEqual(pinned, GOLDEN_DID)

    def test_check_keys_match_pin_unpinned_locator_passes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        with patch.dict(os.environ, {"AGENTS_KNOWN_DIDS_FILE": str(pin_file)}):
            match, pinned = check_keys_match_pin(
                [GOLDEN_DID], None, locators=["mailto:nobody@else.example"]
            )
        self.assertTrue(match)
        self.assertIsNone(pinned)

    def test_check_keys_match_pin_locator_conflict_beats_did_pin(self):
        """corp.example compromised: serves did M under a locator pinned to did A."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        did_m = did_key_from_signing_key(SigningKey.generate())
        env = {"AGENTS_KNOWN_DIDS_FILE": str(pin_file)}
        with patch.dict(os.environ, env):
            pin_locator(GOLDEN_DID, ["mailto:alice@corp.example"])
            pin_locator(did_m, ["mailto:mallory@evil.example"])
            match, pinned = check_keys_match_pin(
                [did_m], did_m, locators=["mailto:Alice@corp.example"]
            )
        self.assertFalse(match)
        self.assertEqual(pinned, GOLDEN_DID)

    def test_check_keys_match_pin_explicit_pinned_did(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        did_m = did_key_from_signing_key(SigningKey.generate())
        with patch.dict(os.environ, {"AGENTS_KNOWN_DIDS_FILE": str(pin_file)}):
            match, pinned = check_keys_match_pin([did_m], did_m, pinned_did=GOLDEN_DID)
            self.assertFalse(match)
            self.assertEqual(pinned, GOLDEN_DID)
            match, _ = check_keys_match_pin([did_m], did_m, pinned_did=did_m)
            self.assertTrue(match)

    def test_find_pins_by_locators_all_records_case_insensitive(self):
        records = [
            PinRecord(did="did:key:zA", locators=["mailto:alice@corp.example"]),
            PinRecord(did="did:key:zB", locators=["mailto:mallory@evil.example"]),
        ]
        hits = find_pins_by_locators(
            [" MAILTO:ALICE@CORP.EXAMPLE ", "mailto:Mallory@EVIL.example"], records
        )
        self.assertEqual([r.did for r in hits], ["did:key:zA", "did:key:zB"])
        self.assertEqual(find_pins_by_locators(["nobody@x.example"], records), [])

    def test_resolve_locator_reports_mismatch(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        locator = "mailto:alice@corp.example"
        rogue_key = SigningKey.generate()
        doc = self._doc_for(rogue_key, locator)
        with patch.dict(os.environ, {"AGENTS_KNOWN_DIDS_FILE": str(pin_file)}):
            pin_locator(GOLDEN_DID, [locator])
            with patch("agents_keys.resolve._fetch_json", return_value=doc):
                result = resolve_locator(locator)
        self.assertFalse(result.match)
        self.assertTrue(result.pinned)

    def test_resolve_cli_exit_3_on_swapped_did(self):
        from agents_keys.cli import main

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pin_file = Path(tmp.name) / "pins.jsonl"
        locator = "mailto:alice@corp.example"
        rogue_key = SigningKey.generate()
        doc = self._doc_for(rogue_key, locator)
        err = io.StringIO()
        with patch.dict(os.environ, {"AGENTS_KNOWN_DIDS_FILE": str(pin_file)}):
            pin_locator(GOLDEN_DID, [locator])
            with patch("agents_keys.resolve._fetch_json", return_value=doc):
                with redirect_stderr(err):
                    rc = main(["resolve", locator])
        self.assertEqual(rc, 3)


class TestSignVerifyEncoding(unittest.TestCase):
    def test_sign_b64url_roundtrip(self):
        key = _golden_key()
        sig = sign_b64url(key, GOLDEN_MESSAGE.encode("utf-8"))
        self.assertEqual(len(sig), 86)
        self.assertNotIn("=", sig)
        verify_did(GOLDEN_DID, GOLDEN_MESSAGE.encode("utf-8"), sig)

    def test_verify_did_rejects_non_base64url(self):
        msg = b"hello"
        bad_sigs = [
            "",
            "!!!",
            "a" * 85,
            "a" * 87,
            "a" * 84 + "==",  # padding is not accepted
            GOLDEN_SIG,       # 128-char hex is not base64url
            "A" * 85 + "+",
            "A" * 85 + "/",
        ]
        for bad in bad_sigs:
            with self.assertRaises(ValueError, msg=f"sig accepted: {bad!r}"):
                verify_did(GOLDEN_DID, msg, bad)

    def test_verify_did_rejects_wrong_signature(self):
        key = _golden_key()
        sig = sign_b64url(key, b"other message")
        with self.assertRaises(ValueError):
            verify_did(GOLDEN_DID, GOLDEN_MESSAGE.encode("utf-8"), sig)


class TestFrames(unittest.TestCase):
    def test_canonical_bytes_domain_tag_and_sig_strip(self):
        payload = {
            "kind": "ws:announce",
            "did": "did:key:zX",
            "sig": "deadbeef",
            "signature": "cafe",
            "b": 2,
            "a": 1,
        }
        raw = canonical_frame_bytes("ws:announce", payload)
        self.assertTrue(raw.startswith(b"ws-frame/1\nws:announce\n"))
        body = raw.split(b"\n", 2)[2]
        self.assertNotIn(b"sig", body)
        self.assertEqual(body, b'{"a":1,"b":2,"did":"did:key:zX","kind":"ws:announce"}')

    def test_canonical_bytes_rejects_nan(self):
        with self.assertRaises(ValueError):
            canonical_frame_bytes("ws:announce", {"x": float("nan")})

    def test_sign_verify_frame_roundtrip_and_tamper(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            did = mint("frame-bot")["did"]
            frame = sign_frame("frame-bot", "ws:announce", {"endpoint": "wss://x.example", "seq": 1})
            self.assertEqual(frame["did"], did)
            self.assertEqual(frame["kind"], "ws:announce")
            self.assertEqual(len(frame["sig"]), 86)
            verify_frame(did, "ws:announce", frame)
            # tampered payload fails
            with self.assertRaises(ValueError):
                verify_frame(did, "ws:announce", dict(frame, seq=2))
            # wrong kind fails
            with self.assertRaises(ValueError):
                verify_frame(did, "ws:revoke", frame)
            # wrong did fails
            with self.assertRaises(ValueError):
                verify_frame(GOLDEN_DID, "ws:announce", frame)
            # missing sig fails
            unsigned = {k: v for k, v in frame.items() if k != "sig"}
            with self.assertRaises(ValueError):
                verify_frame(did, "ws:announce", unsigned)

    def test_frame_kind_rejects_crlf_and_empty(self):
        for bad in ("a\nb", "a\rb", ""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                canonical_frame_bytes(bad, {})

    def test_canonical_bytes_rejects_non_dict_payload(self):
        with self.assertRaises(ValueError):
            canonical_frame_bytes("ws:announce", "not-a-dict")

    def test_sign_frame_rejects_newline_kind(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            mint("frame-bot")
            with self.assertRaises(ValueError):
                sign_frame("frame-bot", "a\nb", {"seq": 1})

    def test_verify_frame_rejects_non_dict(self):
        for bad in ("not-a-dict", ["did", GOLDEN_DID], None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                verify_frame(GOLDEN_DID, "ws:announce", bad)


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
        self.assertIn("verify", data["commands"])
        self.assertIn("ensure", data["commands"])
        for name, spec in data["commands"].items():
            self.assertIn("side_effects", spec, name)

    def test_help_json_side_effects_enum(self):
        proc = self._run("--help-json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        for name in ("did", "ssh-pubkey", "sign", "verify", "resolve"):
            self.assertEqual(
                data["commands"][name]["side_effects"], "read-only", name
            )
        for name in ("mint", "ensure", "import", "pin", "prove"):
            self.assertEqual(
                data["commands"][name]["side_effects"], "mutating", name
            )

    def test_ensure_mints_once_and_prints_did(self):
        from agents_keys.cli import main

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            out1, err1 = io.StringIO(), io.StringIO()
            with redirect_stdout(out1), redirect_stderr(err1):
                rc1 = main(["ensure", "e-bot"])
            out2, err2 = io.StringIO(), io.StringIO()
            with redirect_stdout(out2), redirect_stderr(err2):
                rc2 = main(["ensure", "e-bot"])
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        did = out1.getvalue().strip()
        self.assertTrue(did.startswith("did:key:z6Mk"))
        self.assertEqual(out2.getvalue().strip(), did)
        self.assertIn("wrote", err1.getvalue())
        self.assertNotIn("wrote", err2.getvalue())

    def test_sign_stdin_b64url_then_verify_stdin(self):
        from agents_keys.cli import main

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"AGENTS_KEYS_DIR": tmp.name}):
            did = mint("io-bot")["did"]
            key, _, _ = load("io-bot")
            payload = '{"frame":"ws:announce","n":1}'
            out = io.StringIO()
            with patch("sys.stdin", io.StringIO(payload)):
                with redirect_stdout(out):
                    rc = main(["sign", "io-bot", "--stdin", "--b64url"])
            self.assertEqual(rc, 0)
            sig = out.getvalue().strip()
            self.assertEqual(sig, sign_b64url(key, payload.encode("utf-8")))
            # sign `-` reads stdin the same way
            out = io.StringIO()
            with patch("sys.stdin", io.StringIO(payload)):
                with redirect_stdout(out):
                    rc = main(["sign", "io-bot", "-", "--b64url"])
            self.assertEqual(rc, 0)
            self.assertEqual(out.getvalue().strip(), sig)
            # verify did --stdin <sig>
            out = io.StringIO()
            with patch("sys.stdin", io.StringIO(payload)):
                with redirect_stdout(out):
                    rc = main(["verify", did, "--stdin", sig])
            self.assertEqual(rc, 0)
            self.assertIn("valid", out.getvalue())
            # verify did - <sig>
            out = io.StringIO()
            with patch("sys.stdin", io.StringIO(payload)):
                with redirect_stdout(out):
                    rc = main(["verify", did, "-", sig])
            self.assertEqual(rc, 0)
            # tampered message fails
            err = io.StringIO()
            with patch("sys.stdin", io.StringIO(payload + "x")):
                with redirect_stderr(err):
                    rc = main(["verify", did, "--stdin", sig])
            self.assertEqual(rc, 1)
            self.assertIn("invalid", err.getvalue())
            # non-base64url sig rejected by the CLI
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main(["verify", did, "m", "!!!"])
            self.assertEqual(rc, 1)
            self.assertIn("invalid", err.getvalue())

    def test_verify_sig_leading_dash_not_eaten_by_argparse(self):
        from agents_keys.cli import main

        # '-'-leading base64url sigs must reach verify_did, not argparse.
        dash_sig = "-" + "A" * 85
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["verify", GOLDEN_DID, "m", dash_sig])
        self.assertEqual(rc, 1)
        self.assertIn("signature does not verify", err.getvalue())

    def test_verify_message_looking_like_sig_is_not_rescued(self):
        from agents_keys.cli import main

        # an 86-char message must not be popped as the sig; args stay put
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["verify", GOLDEN_DID, "A" * 86, "invalid_sig"])
        self.assertEqual(rc, 1)
        self.assertIn("not base64url", err.getvalue())

    def test_verify_dash_leading_short_sig_exits_1(self):
        from agents_keys.cli import main

        # '-'-leading malformed sig reaches verify_did, not argparse exit 2
        err = io.StringIO()
        with redirect_stderr(err):
            rc = main(["verify", GOLDEN_DID, "msg", "-" + "A" * 84])
        self.assertEqual(rc, 1)
        self.assertIn("not base64url", err.getvalue())

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


def test_host_scoped_paths(tmp_path, monkeypatch):
    import agents_keys.store as store
    import agents_keys.pins as pins
    host = tmp_path / "host"
    monkeypatch.setenv("AGENTS_HOST_DIR", str(host))
    monkeypatch.delenv("AGENTS_KEYS_DIR", raising=False)
    monkeypatch.delenv("AGENTS_KNOWN_DIDS", raising=False)
    monkeypatch.delenv("AGENTS_KNOWN_DIDS_FILE", raising=False)
    assert store.keys_dir() == host / "keys"
    assert pins.pins_path() == host / "keys" / "known-dids.jsonl"


def test_known_dids_file_env(tmp_path, monkeypatch):
    import agents_keys.pins as pins
    monkeypatch.setenv("AGENTS_KNOWN_DIDS_FILE", str(tmp_path / "pins.jsonl"))
    assert pins.pins_path() == tmp_path / "pins.jsonl"


def test_users_file_and_migration(tmp_path, monkeypatch):
    from agents_keys import users
    host = tmp_path / "host"
    monkeypatch.setenv("AGENTS_HOST_DIR", str(host))
    monkeypatch.delenv("AGENTS_USERS_FILE", raising=False)
    monkeypatch.delenv("AGENTS_IDENTITY_PATH", raising=False)
    assert users.users_file() == host / "users.json"
    # legacy identity.json lifts once
    legacy = host / "identity.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"users": {"felix": {"did": "did:key:zABC"}}}', encoding="utf-8")
    moved = users.migrate_identity()
    assert moved == host / "users.json"
    assert users.lookup_did("felix") == "did:key:zABC"
    # second call is a no-op
    assert users.migrate_identity() is None
    uid = users.bind_did("telegram:42", "did:key:zDEF")
    assert uid.startswith("u_") and len(uid) == 14
    assert users.lookup_did("telegram:42") == "did:key:zDEF"
    assert users.lookup_did(uid) == "did:key:zDEF"


def test_bind_did_canonical_schema_and_legacy_upgrade(tmp_path, monkeypatch):
    import re
    from agents_keys import users

    host = tmp_path / "host"
    monkeypatch.setenv("AGENTS_HOST_DIR", str(host))
    monkeypatch.delenv("AGENTS_USERS_FILE", raising=False)
    monkeypatch.delenv("AGENTS_IDENTITY_PATH", raising=False)

    # Fresh binding creates canonical u_<12hex> record
    uid = users.bind_did("telegram:42", "did:key:zDEF")
    assert re.match(r"^u_[0-9a-f]{12}$", uid)
    disk = json.loads((host / "users.json").read_text(encoding="utf-8"))
    assert disk["users"][uid] == {
        "id": uid,
        "aliases": ["telegram:42"],
        "did": "did:key:zDEF",
    }

    # Re-binding same alias updates DID in place without minting a second user
    uid_same = users.bind_did("telegram:42", "did:key:zDEF2")
    assert uid_same == uid
    assert users.lookup_did("telegram:42") == "did:key:zDEF2"

    # Binding second alias with explicit user_id attaches to same record
    uid_explicit = users.bind_did("repl:local", "did:key:zDEF3", user_id=uid)
    assert uid_explicit == uid
    disk = json.loads((host / "users.json").read_text(encoding="utf-8"))
    assert disk["users"][uid]["aliases"] == ["telegram:42", "repl:local"]
    assert disk["users"][uid]["did"] == "did:key:zDEF3"
    assert users.lookup_did("repl:local") == "did:key:zDEF3"

    # Legacy alias-keyed row upgrades cleanly to canonical u_<12hex> and pops old key
    legacy_path = tmp_path / "legacy_users.json"
    legacy_path.write_text(
        json.dumps({"users": {"felix": {"did": "did:key:zOLD", "aliases": ["felix", "tg:1"]}}}),
        encoding="utf-8",
    )
    assert users.lookup_did("felix", users_path=legacy_path) == "did:key:zOLD"
    upgraded_uid = users.bind_did("felix", "did:key:zNEW", users_path=legacy_path)
    assert re.match(r"^u_[0-9a-f]{12}$", upgraded_uid)
    upgraded_disk = json.loads(legacy_path.read_text(encoding="utf-8"))
    assert "felix" not in upgraded_disk["users"]
    assert upgraded_disk["users"][upgraded_uid] == {
        "id": upgraded_uid,
        "aliases": ["felix", "tg:1"],
        "did": "did:key:zNEW",
    }


def test_users_file_standalone_fallback(tmp_path, monkeypatch):
    from agents_keys import users

    host = tmp_path / "host"
    monkeypatch.setenv("AGENTS_HOST_DIR", str(host))
    monkeypatch.delenv("AGENTS_USERS_FILE", raising=False)
    monkeypatch.delenv("AGENTS_IDENTITY_PATH", raising=False)
    monkeypatch.setitem(sys.modules, "agents_workspace", None)

    assert users.users_file() == host.resolve() / "users.json"
    custom = tmp_path / "custom_users.json"
    monkeypatch.setenv("AGENTS_USERS_FILE", str(custom))
    assert users.users_file() == custom.resolve()


def test_bind_did_interoperates_with_traces_and_workspace_members(tmp_path, monkeypatch):
    import pytest
    from agents_workspace import Host
    from agents_workspace.members import migrate_members
    from agents_keys import users

    traces_identity = pytest.importorskip("agents_traces.identity")

    host_dir = tmp_path / "host"
    monkeypatch.setenv("AGENTS_HOST_DIR", str(host_dir))
    monkeypatch.delenv("AGENTS_USERS_FILE", raising=False)
    monkeypatch.delenv("AGENTS_IDENTITY_PATH", raising=False)

    host = Host.open(host_dir)
    ws = host.create("demo")
    uid = users.bind_did("telegram:42", "did:key:zDEF")

    # agents_traces.identity.IdentityStore resolves same user id and keeps did
    istore = traces_identity.IdentityStore(workspace=ws)
    resolved = istore.resolve(channel="telegram", user="42")
    assert resolved.user.id == uid
    assert resolved.user.did == "did:key:zDEF"
    assert "telegram:42" in resolved.user.aliases

    # agents_workspace.members.migrate_members accepts the user record
    rows = migrate_members(ws)
    assert rows == [{"id": uid, "role": "owner", "did": "did:key:zDEF"}]


def test_store_and_pins_standalone_fallback(tmp_path, monkeypatch):
    import agents_keys.pins as pins
    import agents_keys.store as store

    host = tmp_path / "host"
    monkeypatch.setenv("AGENTS_HOST_DIR", str(host))
    for k in ("AGENTS_KEYS_DIR", "AGENTS_KNOWN_DIDS", "AGENTS_KNOWN_DIDS_FILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setitem(sys.modules, "agents_workspace", None)

    assert store.keys_dir() == host / "keys"
    assert pins.pins_path() == host / "keys" / "known-dids.jsonl"
    did = store.mint("standalone_bot")["did"]
    _, loaded_did, _ = store.load("standalone_bot")
    assert did.startswith("did:key:z")
    assert loaded_did == did

