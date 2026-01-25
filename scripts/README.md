# Installation Scripts

This directory contains installation scripts for Keyper on different platforms.

## Linux & macOS

### Quick Installation

```bash
curl -sSL https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.sh | bash
```

### Custom Installation Directory

```bash
INSTALL_DIR=$HOME/.local/bin curl -sSL https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.sh | bash
```

### Manual Installation

```bash
# Download the script
curl -sSL https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.sh -o install.sh

# Make it executable
chmod +x install.sh

# Run it
./install.sh
```

## Windows

### Quick Installation (PowerShell)

```powershell
iwr https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.ps1 -useb | iex
```

### Manual Installation

```powershell
# Download the script
Invoke-WebRequest -Uri https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.ps1 -OutFile install.ps1

# Run it
.\install.ps1
```

## Features

### install.sh (Linux/macOS)

- Automatically detects OS and architecture
- Downloads the latest release from GitHub
- Verifies checksums using SHA256
- Installs to `/usr/local/bin` by default (configurable via `INSTALL_DIR`)
- Uses `sudo` automatically when needed
- Verifies installation after completion

### install.ps1 (Windows)

- Automatically detects architecture
- Downloads the latest release from GitHub
- Verifies checksums using SHA256
- Installs to `%LOCALAPPDATA%\Programs\Keyper` by default
- Prompts to add installation directory to PATH
- Interactive installation with user confirmations

## Supported Platforms

- **Linux**: x86_64 (amd64), ARM64 (aarch64)
- **macOS**: x86_64 (Intel), ARM64 (Apple Silicon)
- **Windows**: x86_64 (amd64)

## Manual Binary Download

If you prefer to download binaries manually, visit the [releases page](https://github.com/koyif/keyper/releases) and download the appropriate archive for your platform:

1. Download the archive for your platform
2. Download the checksums file
3. Verify the checksum:
   ```bash
   # Linux/macOS
   sha256sum -c keyper_*_checksums.txt --ignore-missing

   # Windows (PowerShell)
   (Get-FileHash keyper_*.zip -Algorithm SHA256).Hash
   ```
4. Extract the archive
5. Move the binary to a directory in your PATH

## Verifying Releases

All releases are signed with GPG. To verify a release:

```bash
# Import the GPG key (first time only)
gpg --keyserver keyserver.ubuntu.com --recv-keys <GPG_KEY_ID>

# Verify the signature
gpg --verify keyper_*_checksums.txt.sig keyper_*_checksums.txt
```

## Updating Keyper

To update to the latest version, simply run the installation script again. It will download and install the latest release.

## Uninstalling

### Linux/macOS

```bash
# If installed to /usr/local/bin
sudo rm /usr/local/bin/keyper

# If installed to custom directory
rm $INSTALL_DIR/keyper
```

### Windows

```powershell
# Remove binary
Remove-Item "$env:LOCALAPPDATA\Programs\Keyper\keyper.exe"

# Remove from PATH (manual step)
# Edit environment variables through System Properties
```

## Troubleshooting

### Permission Denied (Linux/macOS)

If you get a permission error, ensure the script is executable:

```bash
chmod +x install.sh
```

### Command Not Found After Installation

Ensure the installation directory is in your PATH:

```bash
# Linux/macOS
echo $PATH

# Windows (PowerShell)
$env:Path
```

If not, add it:

```bash
# Linux/macOS (add to ~/.bashrc or ~/.zshrc)
export PATH="$PATH:/usr/local/bin"

# Windows (PowerShell as Administrator)
[Environment]::SetEnvironmentVariable("Path", "$env:Path;$env:LOCALAPPDATA\Programs\Keyper", "User")
```

### Checksum Verification Failed

This usually means the download was corrupted. Try running the installation script again.

### Unsupported Platform

If you get an "unsupported platform" error, your OS or architecture may not be supported. Check the [releases page](https://github.com/koyif/keyper/releases) for available platforms or [build from source](../README.md#building-from-source).

## Support

For issues with installation scripts, please [open an issue](https://github.com/koyif/keyper/issues) on GitHub.