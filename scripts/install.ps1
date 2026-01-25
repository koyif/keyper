# Keyper installation script for Windows PowerShell
# Usage: iwr https://raw.githubusercontent.com/koyif/keyper/main/scripts/install.ps1 -useb | iex

$ErrorActionPreference = 'Stop'

# Configuration
$GitHubRepo = "koyif/keyper"
$BinaryName = "keyper.exe"
$DefaultInstallDir = "$env:LOCALAPPDATA\Programs\Keyper"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )

    switch ($Type) {
        "Info" { Write-Host "[INFO] $Message" -ForegroundColor Green }
        "Warn" { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        "Error" { Write-Host "[ERROR] $Message" -ForegroundColor Red }
    }
}

# Detect architecture
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE

    if ($arch -eq "AMD64") {
        return "x86_64"
    } elseif ($arch -eq "ARM64") {
        return "arm64"
    } else {
        Write-ColorOutput "Unsupported architecture: $arch" "Error"
        exit 1
    }
}

# Get latest release version
function Get-LatestVersion {
    Write-ColorOutput "Fetching latest release version..."

    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest"
        $version = $response.tag_name

        if ([string]::IsNullOrEmpty($version)) {
            throw "Version tag is empty"
        }

        Write-ColorOutput "Latest version: $version"
        return $version
    } catch {
        Write-ColorOutput "Failed to fetch latest version: $_" "Error"
        exit 1
    }
}

# Download and verify binary
function Download-Binary {
    param(
        [string]$Version,
        [string]$Arch
    )

    $versionWithoutV = $Version.TrimStart('v')
    $downloadUrl = "https://github.com/$GitHubRepo/releases/download/$Version/keyper_${versionWithoutV}_Windows_${Arch}.zip"
    $checksumUrl = "https://github.com/$GitHubRepo/releases/download/$Version/keyper_${versionWithoutV}_checksums.txt"

    $tempDir = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid().ToString()
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    $archiveFile = Join-Path $tempDir "keyper.zip"
    $checksumFile = Join-Path $tempDir "checksums.txt"

    Write-ColorOutput "Downloading from: $downloadUrl"

    try {
        # Download archive
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archiveFile -UseBasicParsing

        # Download checksums
        Write-ColorOutput "Downloading checksums..."
        try {
            Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumFile -UseBasicParsing

            # Verify checksum
            Write-ColorOutput "Verifying checksum..."
            $archiveName = "keyper_${versionWithoutV}_Windows_${Arch}.zip"
            $checksumContent = Get-Content $checksumFile
            $expectedChecksum = ($checksumContent | Select-String -Pattern $archiveName | ForEach-Object { $_.Line.Split(' ')[0] })

            if ([string]::IsNullOrEmpty($expectedChecksum)) {
                Write-ColorOutput "Checksum not found for $archiveName, skipping verification" "Warn"
            } else {
                $actualChecksum = (Get-FileHash -Path $archiveFile -Algorithm SHA256).Hash.ToLower()

                if ($expectedChecksum -ne $actualChecksum) {
                    Write-ColorOutput "Checksum verification failed!" "Error"
                    Write-ColorOutput "Expected: $expectedChecksum" "Error"
                    Write-ColorOutput "Actual:   $actualChecksum" "Error"
                    Remove-Item -Path $tempDir -Recurse -Force
                    exit 1
                }

                Write-ColorOutput "Checksum verified successfully"
            }
        } catch {
            Write-ColorOutput "Failed to download checksums, skipping verification: $_" "Warn"
        }

        # Extract archive
        Write-ColorOutput "Extracting archive..."
        Expand-Archive -Path $archiveFile -DestinationPath $tempDir -Force

        $binaryPath = Join-Path $tempDir $BinaryName

        if (-not (Test-Path $binaryPath)) {
            Write-ColorOutput "Binary not found in archive" "Error"
            Remove-Item -Path $tempDir -Recurse -Force
            exit 1
        }

        return @{
            TempDir = $tempDir
            BinaryPath = $binaryPath
        }
    } catch {
        Write-ColorOutput "Failed to download binary: $_" "Error"
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
        exit 1
    }
}

# Install binary
function Install-Binary {
    param(
        [string]$SourcePath,
        [string]$InstallDir
    )

    Write-ColorOutput "Installing to $InstallDir..."

    # Create install directory if it doesn't exist
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Copy binary
    $destPath = Join-Path $InstallDir $BinaryName
    Copy-Item -Path $SourcePath -Destination $destPath -Force

    Write-ColorOutput "Installation complete!"
    return $destPath
}

# Add to PATH
function Add-ToPath {
    param(
        [string]$InstallDir
    )

    # Get current user PATH
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")

    # Check if already in PATH
    if ($userPath -like "*$InstallDir*") {
        Write-ColorOutput "Installation directory is already in PATH"
        return
    }

    # Add to PATH
    Write-ColorOutput "Adding $InstallDir to PATH..."
    $newPath = "$userPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")

    # Update current session PATH
    $env:Path = "$env:Path;$InstallDir"

    Write-ColorOutput "Added to PATH. You may need to restart your terminal for changes to take effect."
}

# Verify installation
function Test-Installation {
    param(
        [string]$BinaryPath
    )

    Write-ColorOutput "Verifying installation..."

    try {
        & $BinaryPath version
        Write-Host ""
        Write-ColorOutput "Keyper installed successfully!"
        Write-ColorOutput "Run 'keyper --help' to get started"
    } catch {
        Write-ColorOutput "Installation verification failed: $_" "Warn"
    }
}

# Main installation flow
function Main {
    Write-Host ""
    Write-ColorOutput "Installing Keyper - Secure Password Manager"
    Write-Host ""

    # Detect platform
    $arch = Get-Architecture
    Write-ColorOutput "Detected architecture: $arch"

    # Get latest version
    $version = Get-LatestVersion

    # Download binary
    $download = Download-Binary -Version $version -Arch $arch

    # Prompt for install directory
    $installDir = Read-Host "Install directory (press Enter for default: $DefaultInstallDir)"
    if ([string]::IsNullOrWhiteSpace($installDir)) {
        $installDir = $DefaultInstallDir
    }

    # Install binary
    $installedPath = Install-Binary -SourcePath $download.BinaryPath -InstallDir $installDir

    # Clean up temp directory
    Remove-Item -Path $download.TempDir -Recurse -Force

    # Add to PATH
    $addToPath = Read-Host "Add to PATH? (Y/n)"
    if ([string]::IsNullOrWhiteSpace($addToPath) -or $addToPath -eq "Y" -or $addToPath -eq "y") {
        Add-ToPath -InstallDir $installDir
    } else {
        Write-ColorOutput "Skipped adding to PATH. You can manually add $installDir to your PATH." "Warn"
    }

    # Verify installation
    Test-Installation -BinaryPath $installedPath

    Write-Host ""
    Write-ColorOutput "Thank you for installing Keyper!"
    Write-Host ""
}

# Run main function
Main