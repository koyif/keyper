# Release Process

This document describes the release process for Keyper.

## Prerequisites

- **GoReleaser** installed: `make install-goreleaser` or `go install github.com/goreleaser/goreleaser/v2@latest`
- **GPG key** configured for signing releases (optional but recommended)
- **GitHub token** with repository write access (for automated releases)

## Version Numbering

Keyper follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backwards-compatible manner
- **PATCH** version for backwards-compatible bug fixes

Format: `vMAJOR.MINOR.PATCH` (e.g., `v1.2.3`)

## Local Testing

Before creating a release, test the build locally:

```bash
# Build binaries with version injection
make build

# Test version information
./bin/keyper-client version
./bin/keyper-server -version

# Create a snapshot release (local testing only)
make release-snapshot

# Or with goreleaser directly
goreleaser release --snapshot --clean --skip=sign
```

The snapshot build creates:
- Cross-platform binaries in `dist/`
- Archives (tar.gz for Linux/macOS, zip for Windows)
- Checksums file
- No publishing or signing

## Creating a Release

### 1. Update Version Information

Update the following files before creating a release:

- [ ] `CHANGELOG.md` - Document all changes in the new version
- [ ] `README.md` - Update version references if needed
- [ ] `docs/` - Update any version-specific documentation

### 2. Run Tests

Ensure all tests pass:

```bash
# Run all tests
make test

# Run tests with coverage
make coverage

# Run linter
make lint
```

### 3. Create and Push Git Tag

```bash
# Create an annotated tag
git tag -a v1.2.3 -m "Release v1.2.3"

# Push the tag to trigger the release workflow
git push origin v1.2.3
```

### 4. Automated Release Process

Once the tag is pushed, GitHub Actions will automatically:

1. **Run CI Tests** - Execute full test suite with PostgreSQL integration tests
2. **Check Coverage** - Ensure code coverage meets the 70% threshold
3. **Build Binaries** - Create binaries for all supported platforms:
   - Linux: amd64, arm64
   - macOS: amd64 (Intel), arm64 (Apple Silicon)
   - Windows: amd64
4. **Create Archives** - Package binaries with README and CHANGELOG
5. **Generate Checksums** - SHA256 checksums for all artifacts
6. **Sign Artifacts** - GPG signature for checksums (if GPG key configured)
7. **Create GitHub Release** - Publish release with all artifacts
8. **Upload Assets** - Attach all binaries, archives, and checksums

### 5. Verify Release

After the automated release completes:

1. Visit https://github.com/koyif/keyper/releases
2. Verify all artifacts are present
3. Test installation using the install scripts:
   ```bash
   # Linux/macOS
   curl -sSL https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.sh | bash

   # Windows (PowerShell)
   iwr https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.ps1 -useb | iex
   ```
4. Verify version information: `keyper version`

## Manual Release (Emergency)

If automated release fails, you can release manually:

```bash
# Ensure you're on the correct commit/tag
git checkout v1.2.3

# Set GitHub token
export GITHUB_TOKEN="your_github_token"

# Run GoReleaser
goreleaser release --clean
```

## Configuring GPG Signing

To enable GPG signing of releases:

### 1. Generate GPG Key (if you don't have one)

```bash
gpg --full-generate-key
# Choose RSA and RSA, 4096 bits, no expiration
```

### 2. Export GPG Key

```bash
# List keys
gpg --list-secret-keys --keyid-format=long

# Export private key
gpg --armor --export-secret-keys YOUR_KEY_ID > private-key.asc

# Get key fingerprint
gpg --fingerprint YOUR_KEY_ID
```

### 3. Add to GitHub Secrets

In your GitHub repository settings (Settings > Secrets and variables > Actions):

- `GPG_PRIVATE_KEY` - Contents of `private-key.asc`
- `GPG_PASSPHRASE` - Your GPG key passphrase
- `GPG_FINGERPRINT` - Your GPG key fingerprint

### 4. Test Signing

```bash
# Test locally with your GPG key
goreleaser release --snapshot --clean

# The checksums file should have a .sig signature file
ls dist/*.sig
```

## Supported Platforms

### Client Binary (`keyper`)

- **Linux**
  - amd64 (x86_64)
  - arm64 (aarch64)
- **macOS**
  - amd64 (Intel)
  - arm64 (Apple Silicon)
- **Windows**
  - amd64 (x86_64)

### Server Binary (`keyper-server`)

- Same platforms as client

## Build Artifacts

Each release includes:

1. **Source Archives**
   - Automatically created by GitHub

2. **Binary Archives**
   - `keyper_VERSION_Linux_x86_64.tar.gz`
   - `keyper_VERSION_Linux_arm64.tar.gz`
   - `keyper_VERSION_Darwin_x86_64.tar.gz`
   - `keyper_VERSION_Darwin_arm64.tar.gz`
   - `keyper_VERSION_Windows_x86_64.zip`

3. **Checksums**
   - `keyper_VERSION_checksums.txt` - SHA256 checksums for all artifacts
   - `keyper_VERSION_checksums.txt.sig` - GPG signature (if configured)

## Rollback Process

If a release has critical issues:

### 1. Delete the Release

```bash
# Delete the tag locally
git tag -d v1.2.3

# Delete the tag on GitHub
git push origin :refs/tags/v1.2.3

# Delete the GitHub release manually via web interface
```

### 2. Fix the Issue

```bash
# Make necessary fixes
git commit -m "Fix critical issue in v1.2.3"
```

### 3. Create New Release

```bash
# Create new patch version
git tag -a v1.2.4 -m "Release v1.2.4 - Hotfix for v1.2.3"
git push origin v1.2.4
```

## Troubleshooting

### Build Fails

- Check that all tests pass: `make test`
- Verify linting passes: `make lint`
- Check GoReleaser config: `goreleaser check`

### Missing Artifacts

- Ensure `.goreleaser.yml` is properly configured
- Check GitHub Actions logs for errors
- Verify GitHub token has correct permissions

### GPG Signing Fails

- Verify GPG secrets are correctly set in GitHub
- Test signing locally: `echo "test" | gpg --clearsign`
- Check GPG key hasn't expired: `gpg --list-keys`

### Coverage Check Fails

- Run `make coverage` locally to see current coverage
- Add tests to increase coverage above 70%
- Update coverage threshold in `.github/workflows/ci.yml` if needed

## Release Checklist

- [ ] All tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Coverage meets threshold (`make coverage`)
- [ ] CHANGELOG.md updated
- [ ] Version bumped appropriately
- [ ] Snapshot build tested (`make release-snapshot`)
- [ ] Git tag created and pushed
- [ ] GitHub Actions workflow completed successfully
- [ ] Release verified on GitHub
- [ ] Installation scripts tested
- [ ] Announcement prepared (if applicable)

## Resources

- [GoReleaser Documentation](https://goreleaser.com/)
- [Semantic Versioning](https://semver.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GPG Signing Guide](https://docs.github.com/en/authentication/managing-commit-signature-verification)