# agents-keys ABI

Version: see [`VERSION`](VERSION).

Host Ed25519 keys and `did:key` proofs. No MCP server. The Python package in this repository is the reference implementation.

| Doc | Contract |
| --- | --- |
| [`WHY.md`](WHY.md) | Secret stays on the host |
| [`LAYOUT.md`](LAYOUT.md) | Key file bytes and `did:key` |
| [`CLI.md`](CLI.md) | mint, import, did, ssh-pubkey, sign, prove, resolve, pin |

Machine-readable command list: `python -m agents_keys --help-json`.
