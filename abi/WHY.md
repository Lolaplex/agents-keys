# Why agents-keys exists

Version: see [`VERSION`](VERSION).

Agents need a stable public id (`did:key`) and a way to sign a board nonce. They do not need a KMS, a DID wallet, or a server that holds the seed.

The secret file stays in `AGENTS_KEYS_DIR` (default `~/.agents/keys`). Stdout is the public id or a signature. The path, when printed, goes to stderr. Do not embed this package in a long-running process. Shell out.
