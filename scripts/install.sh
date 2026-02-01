#!/usr/bin/env bash
#
# Keyper installation script for Linux and macOS
# Usage: curl -sSL https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.sh | bash
#

set -e

# Configuration
GITHUB_REPO="koyif/keyper"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="keyper"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux*)
            OS="Linux"
            ;;
        Darwin*)
            OS="Darwin"
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    log_info "Detected platform: $OS/$ARCH"
}

# Get the latest release version
get_latest_version() {
    log_info "Fetching latest release version..."

    VERSION=$(curl -sL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$VERSION" ]; then
        log_error "Failed to fetch latest version"
        exit 1
    fi

    log_info "Latest version: $VERSION"
}

# Download and verify the binary
download_binary() {
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/keyper_${VERSION#v}_${OS}_${ARCH}.tar.gz"
    CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/keyper_${VERSION#v}_checksums.txt"

    TEMP_DIR=$(mktemp -d)
    ARCHIVE_FILE="${TEMP_DIR}/keyper.tar.gz"
    CHECKSUM_FILE="${TEMP_DIR}/checksums.txt"

    log_info "Downloading from: $DOWNLOAD_URL"

    if ! curl -sL "$DOWNLOAD_URL" -o "$ARCHIVE_FILE"; then
        log_error "Failed to download binary"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    log_info "Downloading checksums..."
    if ! curl -sL "$CHECKSUM_URL" -o "$CHECKSUM_FILE"; then
        log_warn "Failed to download checksums, skipping verification"
    else
        log_info "Verifying checksum..."
        ARCHIVE_NAME="keyper_${VERSION#v}_${OS}_${ARCH}.tar.gz"

        # Extract the checksum for this specific archive
        EXPECTED_CHECKSUM=$(grep "$ARCHIVE_NAME" "$CHECKSUM_FILE" | awk '{print $1}')

        if [ -z "$EXPECTED_CHECKSUM" ]; then
            log_warn "Checksum not found for $ARCHIVE_NAME, skipping verification"
        else
            # Calculate actual checksum
            if command -v sha256sum >/dev/null 2>&1; then
                ACTUAL_CHECKSUM=$(sha256sum "$ARCHIVE_FILE" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then
                ACTUAL_CHECKSUM=$(shasum -a 256 "$ARCHIVE_FILE" | awk '{print $1}')
            else
                log_warn "sha256sum or shasum not found, skipping verification"
                ACTUAL_CHECKSUM=""
            fi

            if [ -n "$ACTUAL_CHECKSUM" ] && [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
                log_error "Checksum verification failed!"
                log_error "Expected: $EXPECTED_CHECKSUM"
                log_error "Actual:   $ACTUAL_CHECKSUM"
                rm -rf "$TEMP_DIR"
                exit 1
            fi

            log_info "Checksum verified successfully"
        fi
    fi

    log_info "Extracting archive..."
    tar -xzf "$ARCHIVE_FILE" -C "$TEMP_DIR"

    BINARY_PATH="${TEMP_DIR}/${BINARY_NAME}"

    if [ ! -f "$BINARY_PATH" ]; then
        log_error "Binary not found in archive"
        rm -rf "$TEMP_DIR"
        exit 1
    fi
}

# Install the binary
install_binary() {
    log_info "Installing to $INSTALL_DIR..."

    # Check if we need sudo
    if [ ! -w "$INSTALL_DIR" ]; then
        log_warn "Installation directory requires elevated privileges"
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            log_error "sudo not found, cannot install to $INSTALL_DIR"
            log_info "Please run this script with elevated privileges or set INSTALL_DIR to a writable location"
            rm -rf "$TEMP_DIR"
            exit 1
        fi
    else
        SUDO=""
    fi

    # Create install directory if it doesn't exist
    $SUDO mkdir -p "$INSTALL_DIR"

    # Install the binary
    $SUDO cp "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
    $SUDO chmod +x "$INSTALL_DIR/$BINARY_NAME"

    # Clean up
    rm -rf "$TEMP_DIR"

    log_info "Installation complete!"
}

# Verify installation
verify_installation() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        log_info "Keyper installed successfully!"
        echo ""
        "$BINARY_NAME" version
        echo ""
        log_info "Run 'keyper --help' to get started"
    else
        log_warn "Installation successful, but $BINARY_NAME is not in PATH"
        log_info "Add $INSTALL_DIR to your PATH to use keyper"
        log_info "Or run: export PATH=\"\$PATH:$INSTALL_DIR\""
    fi
}

# Main installation flow
main() {
    echo ""
    log_info "Installing Keyper - Secure Password Manager"
    echo ""

    detect_platform
    get_latest_version
    download_binary
    install_binary
    verify_installation

    echo ""
    log_info "Thank you for installing Keyper!"
}

# Run main function
main