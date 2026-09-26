# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- ABI contract in `abi/` for the key file, `did:key`, and the CLI.

### Changed
- README lists the live CLI (`mint` through `pin`) and the on-disk secret path `~/.agents/keys/<slug>.ed25519`.

## [0.0.2] - 2026-09-26

### Changed
- CI runs only on pull requests to `main` with strict test suite execution.
- Refined README with full benchmark specification (architecture diagram, security rationale, CLI reference, and badges).

### Removed
- Root `requirements.txt` (duplicate of `pyproject.toml`; install via `pip install -e .`).
- GitHub Release is no longer cut automatically on `v*.*.*` tags (manual `gh release create` from CHANGELOG instead).

## [0.0.1] - 2026-09-05

### Added
- Host Ed25519 agent key minting and challenge-response proofs. Secret file stays in `~/.agents/keys`; the CLI never prints it.

[Unreleased]: https://github.com/Lolaplex/agents-keys/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/Lolaplex/agents-keys/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Lolaplex/agents-keys/releases/tag/v0.0.1
