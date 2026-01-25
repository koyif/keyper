# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Keyper password manager
- End-to-end encryption with client-side encryption
- gRPC server with HTTP gateway
- CLI client with offline-first functionality
- Cross-platform support (Linux, macOS, Windows)
- SQLite local storage for offline access
- PostgreSQL backend for server
- Synchronization between client and server
- Terminal UI (TUI) for interactive usage
- Support for multiple secret types: credentials, text notes, credit cards, binary data
- Device management
- GoReleaser configuration for automated releases
- GitHub Actions CI/CD workflows
- Installation scripts for all platforms

### Security
- Argon2id key derivation with RFC 9106 parameters
- AES-256-GCM encryption
- Encryption key verifier for password validation
- All encryption happens client-side
- Server never has access to unencrypted secrets or encryption keys

## [0.1.0] - TBD

Initial release.

[Unreleased]: https://github.com/koyif/keyper/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/koyif/keyper/releases/tag/v0.1.0
