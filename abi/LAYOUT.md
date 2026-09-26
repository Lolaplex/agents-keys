# Key files

Directory: `AGENTS_KEYS_DIR` or `~/.agents/keys`. Mode `0700` on create.

File: `<slug>.ed25519`. Slug matches `^[a-z0-9][a-z0-9._-]{0,47}$`. Mode `0600` after mint.

## Bytes

`mint` writes 64 bytes: libsodium secret key, seed (32) concatenated with the public key (32). Readers also accept a 32-byte seed, or hex of either form.

The CLI never prints these bytes.

## `did:key`

Multicodec prefix `0xed 0x01` plus the 32-byte Ed25519 public key, then multibase base58btc with a `z` prefix:

`did:key:z` + base58btc(`0xed 0x01` || public).

## TOFU pins

`AGENTS_KNOWN_DIDS` or `~/.agents/known-dids.jsonl`. `pin` appends a resolved `did:key`. A later `resolve` that disagrees with the pin fails (exit 3).
