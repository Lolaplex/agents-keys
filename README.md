# agents-keys

<p align="left">
  <a href="https://github.com/Lolaplex/agents-keys/releases"><img src="https://img.shields.io/badge/version-0.1.0-blue.svg?style=flat-square" alt="Version 0.1.0"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="https://pypi.org/project/agents-keys/"><img src="https://img.shields.io/pypi/v/agents-keys.svg?style=flat-square" alt="PyPI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License"></a>
</p>

**Mint and sign agent Ed25519 keys (`did:key`) as a secure local host file.**  
CLI only (`python -m agents_keys`). Pure Python + PyNaCl, zero MCP, zero database dependencies.

The secret key stays safely in `~/.agents/keys/<slug>.ed25519` (64-byte libsodium seed, mode 0600). The CLI never prints, echoes, or logs secret keys.

---

## Quickstart

### 1-Step Setup

```bash
pip install agents-keys
```

### 2. Agent-Driven Setup (Zero Friction)

> [!TIP]
> **🤖 Agent-Driven Setup (Zero Friction):**  
> Simply tell your coding agent: **"Mint an agent key for <slug>."**  
> The agent installs the package, generates the key pair, and outputs the public `did:key` identifier.

*Source checkouts can also be installed and managed using [vand](https://github.com/Lolaplex/vand).*

---

## Why `agents-keys`?

Modern autonomous coding agents require verifiable cryptographic identities without the overhead of heavy decentralized identity (DID) frameworks or cloud KMS dependencies.

**`agents-keys` applies the Lolaplex philosophy:**
- **Zero Heavy Frameworks**: Pure standard library CLI + minimal PyNaCl Ed25519 bindings.
- **Local Secret Isolation**: Private keys live strictly on the host file system (`~/.agents/keys/<slug>.ed25519`) with mode `0600`. Secrets are never stored in databases, committed to git, or leaked into chat transcripts.
- **Standard W3C Identifiers**: Generates compliant `did:key:z6Mk...` multi-codec identifiers compatible with modern cryptography standards.
- **Challenge-Response Proofs**: Built-in verification for challenge nonces, binding agent public keys to boards, gateways, and peer nodes.

---

## Architecture & Flow

```text
 ┌─────────────────────────────────────────────────────────────┐
 │                     CODING AGENT / HOST                     │
 │          agents-harness · CLI Scripts · Board Boot          │
 └──────────────────────────────┬──────────────────────────────┘
                                │  CLI Verbs (mint / sign / prove)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                         AGENTS-KEYS                         │
 │     Ed25519 Signer · did:key Multi-codec · Nonce Prover     │
 └──────────────┬───────────────────────────────┬──────────────┘
                │                               │
                ▼                               ▼
 ┌─────────────────────────────┐ ┌─────────────────────────────┐
 │       HOST SECRET KEY       │ │       PUBLIC did:key        │
 │  ~/.agents/keys/<slug>.key  │ │     did:key:z6Mku...        │
 │  (mode 0600, never leaked)  │ │   Deterministic public ID   │
 └─────────────────────────────┘ └─────────────────────────────┘
```

---

## CLI Reference

Machine catalog: `python -m agents_keys --help-json`

| Command | Purpose |
|---------|---------|
| `agents-keys mint <slug>` | Writes a new key file. Stdout is one `did:key:z6Mk…` line |
| `agents-keys import <slug> <path>` | Imports an unencrypted OpenSSH or libsodium secret |
| `agents-keys did <slug>` | Derives the `did:key` from an existing key file |
| `agents-keys ssh-pubkey <slug>` | Outputs the public key in standard `ssh-ed25519` format |
| `agents-keys sign <slug> <nonce>` | Generates an Ed25519 signature hex string over a nonce |
| `agents-keys prove <slug> <board-url>` | Resolves a board challenge and prints `{did, nonce, signature}` |
| `agents-keys resolve <locator>` | Fetches `did.json` / mailto home document and prints keys JSON |
| `agents-keys pin <locator>` | Resolves and TOFU-pins `did:key` in `known-dids.jsonl` |

### Scoped Lifecycle Examples

```bash
agents-keys prove human https://board.example --verb bind-key --handle alice
agents-keys prove human https://board.example --verb move --handle alice --successor-did did:web:board.example:users:alice
```

---

## Environment & Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTS_KEYS_DIR` | `~/.agents/keys` | Directory holding host secret key files |
| `AGENTS_KNOWN_DIDS` | `~/.agents/known-dids.jsonl` | Local TOFU pin ledger for verified external DIDs |

---

## Constraints

- **No MCP**: Designed strictly as a host CLI. Other agent loops invoke `agents-keys` as an isolated subprocess rather than embedding private key operations in long-running servers.
- **Never Store Secrets Remotely**: Private keys remain host-bound.

---

## Testing & Verification

Run the test suite:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
