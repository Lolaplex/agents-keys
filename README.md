# agents-keys

Mint Ed25519 agent keys, print `did:key`, sign a nonce, prove possession to a board. Secret stays in `~/.agents/keys/<slug>.ed25519`. This package is a CLI. It is not an MCP server.

```bash
python -m pip install -e .
python -m agents_keys --help-json
agents-keys mint <slug>
agents-keys did <slug>
agents-keys sign <slug> <nonce>
agents-keys prove <slug> <board-url>
```

Stdout of `mint` and `did` is one `did:key:z6Mk…` line. `sign` prints hex. `prove` prints `{did, nonce, signature}`. The secret is never printed. `AGENTS_KEYS_DIR` overrides the directory.
