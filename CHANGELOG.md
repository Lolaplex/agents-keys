# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- CI runs only on pull requests to `main`.
- README now documents install, the real CLI (`--help-json` plus each subcommand), env, and the verify command.

### Removed
- Root `requirements.txt` (duplicate of `pyproject.toml`; install via `pip install -e .`).
- GitHub Release is no longer cut automatically on `v*.*.*` tags (manual `gh release create` from CHANGELOG instead).

## [0.0.1] - 2026-09-05

### Added
- Host Ed25519 agent key minting and challenge-response proofs. Secret file stays in `~/.agents/keys`; the CLI never prints it.

[Unreleased]: https://github.com/Lolaplex/agents-keys/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/Lolaplex/agents-keys/releases/tag/v0.0.1
