# agents-keys

Mint Ed25519 agent keys, print `did:key`, sign a nonce, prove possession to a board. Pin and resolve home `did.json` locators. Secret stays in `~/.agents/keys/<slug>.ed25519`. This package is a CLI. It is not an MCP server.

```bash
python -m pip install -e .
python -m agents_keys --help-json
agents-keys mint <slug>
agents-keys import <slug> <path>
agents-keys did <slug>
agents-keys ssh-pubkey <slug>
agents-keys sign <slug> <nonce>
agents-keys prove <slug> <board-url> [--verb VERB] [--handle HANDLE] [--successor-did DID]
agents-keys resolve <locator>
agents-keys pin <locator>
```

Stdout of `mint`, `import`, and `did` is one `did:key:z6Mk…` line. `sign` prints hex. `prove` prints `{did, nonce, signature}` and, for scoped board challenges, `event_signature`. `resolve` and `pin` print JSON with keys and pin status. The secret is never printed.

Scoped lifecycle proof:

```bash
agents-keys prove human home --verb bind-key --handle alice
agents-keys prove human home --verb move --handle alice --successor-did did:web:board.example:users:alice
```

- `AGENTS_KEYS_DIR` overrides the key directory (default `~/.agents/keys`).
- `AGENTS_KNOWN_DIDS` overrides the pin file (default `~/.agents/known-dids.jsonl`).

Locators: `did:key:…`, `mailto:user@domain`, `did:web:…`, or `https://…/did.json`. For mailto, the home document must cite that mailto in `alsoKnownAs` and carry Ed25519 keys.
