# agents-keys

Mint Ed25519 agent keys as a file on this host. Print `did:key`, sign a nonce, prove possession to a board, pin and resolve home `did.json` locators. CLI only (`python -m agents_keys`). Not an MCP server. Not board PHP.

The secret stays in `~/.agents/keys/<slug>.ed25519` (64-byte libsodium seed, mode 0600). The CLI never prints that file. Do not paste it into chat, traces, or markdown memory.

## Install

```bash
python -m pip install -e .
```

Depends on `pynacl`. Python 3.10+.

## Commands

Machine catalog: `python -m agents_keys --help-json` (do not scrape `--help`).

| Command | Purpose |
|---------|---------|
| `agents-keys mint <slug>` | Write the key file. Stdout is one `did:key:z6Mk…` line |
| `agents-keys import <slug> <path>` | Import unencrypted OpenSSH or sodium secret. Same stdout |
| `agents-keys did <slug>` | Derive `did:key` from the existing file (same line as `mint`) |
| `agents-keys ssh-pubkey <slug>` | One `ssh-ed25519` public line |
| `agents-keys sign <slug> <nonce>` | Ed25519 signature hex over the nonce |
| `agents-keys prove <slug> <board-url> [--verb VERB] [--handle HANDLE] [--successor-did DID]` | Board challenge. Prints `{did, nonce, signature}` and, for scoped challenges, `event_signature` |
| `agents-keys resolve <locator>` | Fetch `did.json` / mailto home doc. Prints keys JSON |
| `agents-keys pin <locator>` | Resolve and TOFU-pin `did:key` |

`prove` needs an `https://` or `http://` board URL, not a slug.

Scoped lifecycle examples:

```bash
agents-keys prove human https://board.example --verb bind-key --handle alice
agents-keys prove human https://board.example --verb move --handle alice --successor-did did:web:board.example:users:alice
```

## Env

| Variable | Default |
|----------|---------|
| `AGENTS_KEYS_DIR` | `~/.agents/keys` |
| `AGENTS_KNOWN_DIDS` | `~/.agents/known-dids.jsonl` |

Locators: `did:key:…`, `mailto:user@domain`, `did:web:…`, or `https://…/did.json`. For mailto, the home document must cite that mailto in `alsoKnownAs` and carry Ed25519 keys.

## Constraints

- No MCP. Harness later catalogs `key.sign` as a Cordis verb that shells out to this CLI. Memory attach shells out; it does not import this package.
- Never store user private keys in a board SQLite. Instance keys stay on the host.

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Done when `mint` stdout is one `did:key:z6Mk…` line and `did` prints the same line.

## License

MIT. See [LICENSE](LICENSE).
