# agents-keys

Ed25519 agent keys as a file on the host. CLI only (`python -m agents_keys`). No MCP. No board PHP.

## Commands

```bash
python -m agents_keys --help-json
python -m agents_keys mint <slug>
python -m agents_keys did <slug>
python -m agents_keys sign <slug> <nonce>
python -m agents_keys prove <slug> https://board.example
```

Done when `mint` stdout is one `did:key:z6Mk…` line and `did` prints the same line. Secret: `~/.agents/keys/<slug>.ed25519` (64-byte libsodium secret, mode 0600). Never print, paste, or store that file in chat, traces, or markdown memory.

Harness later catalogs `key.sign` as a Cordis verb that shells out to this CLI. Memory attach shells out; it does not import this package.
