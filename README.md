<h1 align="center">agents-keys</h1>

<p align="center">
  <a href="https://github.com/Lolaplex/agents-keys/releases"><img src="https://img.shields.io/badge/version-0.0.4-blue.svg?style=flat-square" alt="Version 0.0.4"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="https://pypi.org/project/agents-keys/"><img src="https://img.shields.io/pypi/v/agents-keys.svg?style=flat-square" alt="PyPI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <strong>Host Ed25519 keys for agents (`did:key`).</strong><br>
  CLI only. The secret never leaves this machine, and never hits stdout.
</p>

## Quickstart

```bash
pip install agents-keys
```

There is no `init` and no MCP server. Other loops shell out.

```bash
agents-keys mint <slug>
```

Writes `~/.agents/keys/<slug>.ed25519` (64-byte libsodium seed, mode `0600`). Stdout is one `did:key:z6Mk…` line. The path is stderr.

> [!TIP]
> **🤖 Agent-Driven Setup:**
> Give your coding agent **this repo** (clone or URL), then tell it to **"install agents-keys and mint a key for &lt;slug&gt;."**

Source checkouts can also be installed and managed with [vand](https://github.com/Lolaplex/vand).

---

## What it does

Mint or import a host key, derive `did:key` and an `ssh-ed25519` line, sign a nonce, or answer a board challenge (`prove`).

`resolve` fetches a `did.json` or mailto home document. `pin` stores that `did:key` in a local TOFU ledger. A later resolve that disagrees with the pin fails.

The secret file is not printed, logged, or committed. Do not put it in a long-running server. Call this CLI as a subprocess.

---

## CLI

Machine-readable catalog: `python -m agents_keys --help-json` (do not scrape `--help`).

| Command | Purpose |
| --- | --- |
| `agents-keys mint <slug>` | New key file. Stdout: `did:key` |
| `agents-keys import <slug> <path>` | Unencrypted OpenSSH or libsodium secret. Stdout: `did:key` |
| `agents-keys did <slug>` | `did:key` from an existing file |
| `agents-keys ssh-pubkey <slug>` | One `ssh-ed25519` public line |
| `agents-keys sign <slug> <nonce>` | Ed25519 signature hex over the nonce |
| `agents-keys prove <slug> <board-url>` | Fetch a challenge, print `{did, nonce, signature}` |
| `agents-keys resolve <locator>` | Fetch a home document, print keys JSON |
| `agents-keys pin <locator>` | Resolve and TOFU-pin into `known-dids.jsonl` |

`prove` accepts `--verb`, `--handle`, and `--successor-did`. When the board returns an event canonical, the JSON also includes `event_signature`.

```bash
agents-keys prove human https://board.example --verb bind-key --handle alice
agents-keys prove human https://board.example --verb move --handle alice --successor-did did:web:board.example:users:alice
```

No subcommand prints help.

---

## Environment

| Variable | Default | Description |
| --- | --- | --- |
| `AGENTS_KEYS_DIR` | `~/.agents/keys` | Host secret files (`<slug>.ed25519`) |
| `AGENTS_KNOWN_DIDS` | `~/.agents/known-dids.jsonl` | TOFU pins for external DIDs |

---

## ABI

Contract in [`abi/`](abi/):

- [`WHY.md`](abi/WHY.md) — host secret, public stdout
- [`LAYOUT.md`](abi/LAYOUT.md) — `<slug>.ed25519` and `did:key`
- [`CLI.md`](abi/CLI.md) — commands

---

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## License

MIT. See [LICENSE](LICENSE).
