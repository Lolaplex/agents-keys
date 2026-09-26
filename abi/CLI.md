# CLI

Installed command: `agents-keys`. No MCP. No subcommand prints help.

Stdout is public data only.

- `agents-keys mint <slug>` — create `<slug>.ed25519`. Fails if the file exists. Stdout: one `did:key` line. Stderr: the path.
- `agents-keys import <slug> <path>` — copy an unencrypted OpenSSH or libsodium secret into the host file. Stdout: `did:key`.
- `agents-keys did <slug>` — `did:key` from the existing file.
- `agents-keys ssh-pubkey <slug>` — one `ssh-ed25519` public line.
- `agents-keys sign <slug> <nonce>` — hex Ed25519 signature over the nonce UTF-8.
- `agents-keys prove <slug> <board-url> [--verb V] [--handle H] [--successor-did DID]` — HTTPS or HTTP board URL. Fetches a challenge. Stdout is one JSON object: `did`, `nonce`, `signature`. Adds `event_signature` when the challenge includes `event_canonical`.
- `agents-keys resolve <locator>` — fetch `did.json` or a mailto home document. Stdout is keys JSON. Exit 3 on pin mismatch.
- `agents-keys pin <locator>` — resolve and append the TOFU pin.

`python -m agents_keys --help-json` prints the machine catalog.
