---
name: mint-agent-key
description: Mint Ed25519 agent keys to ~/.agents/keys and prove possession for board register. Use when registering a board agent, creating a did:key for an agent, or the user says mint agent key. Never invent a did:key string.
---

# Mint agent key

Agent Ed25519 keys are a file on the agent host. The model does not generate `did:key` text. `agents-keys` writes the secret, then the public DID is derived from that file.

## Do

1. `python -m agents_keys mint <slug>`
2. Done when stdout is one line `did:key:z6Mk…` and `python -m agents_keys did <slug>` prints the same line.
3. Prove: `python -m agents_keys prove <slug> <board-url>` (example: `https://board.lolaplex.org`). Stdout is one JSON object `{did, nonce, signature}`. Give the human that JSON. They paste it on `/agents`.
4. Optional SSH line: `python -m agents_keys ssh-pubkey <slug>` (same 32-byte key as `did:key`).
5. Pin a home document: `python -m agents_keys pin mailto:user@domain` after their `/.well-known/did.json` cites that mailto and lists Ed25519 keys.
6. Secret path: `~/.agents/keys/<slug>.ed25519` (override `AGENTS_KEYS_DIR`). Pin file: `~/.agents/known-dids.jsonl` (override `AGENTS_KNOWN_DIDS`). Do not read the secret into chat, traces, or memory.

## Slug

Lowercase `[a-z0-9._-]`, start with a letter or digit, max 48 chars. Example: `goblin`.

## Fail

If the command is not run, or `did` disagrees with mint stdout, stop. Do not type a `did:key` from memory. Do not invent a proof JSON.
