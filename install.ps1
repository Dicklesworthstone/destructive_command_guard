# dcg PowerShell installer
#
# Usage:
#   irm https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.ps1 | iex
#
# Options:
#   -Version vX.Y.Z   Install specific version (default: latest)
#   -Dest DIR         Install to DIR (default: ~/.local/bin)
#   -EasyMode         Auto-add to PATH
#   -Verify           Run self-test after install
#
Param(
  [string]$Version = "",
  [string]$Dest = "$HOME\.local\bin",
  [string]$Owner = "Dicklesworthstone",
  [string]$Repo = "destructive_command_guard",
  [string]$Checksum = "",
  [string]$ChecksumUrl = "",
  [string]$SigstoreBundleUrl = "",
  [string]$CosignIdentityRegex = "",
  [string]$CosignOidcIssuer = "",
  [string]$ArtifactUrl = "",
  [switch]$EasyMode,
  [switch]$Verify
)

$ErrorActionPreference = "Stop"
$FallbackVersion = "v0.1.0"

function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

# Resolve latest version if not specified
if (-not $Version) {
  Write-Info "Resolving latest version..."
  try {
    # Try GitHub API first
    $apiUrl = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{"Accept"="application/vnd.github.v3+json"} -ErrorAction Stop
    $Version = $release.tag_name
    Write-Info "Resolved latest version: $Version"
  } catch {
    # Fallback: try redirect-based resolution
    try {
      $redirectUrl = "https://github.com/$Owner/$Repo/releases/latest"
      $response = Invoke-WebRequest -Uri $redirectUrl -MaximumRedirection 0 -ErrorAction Stop
    } catch {
      if ($_.Exception.Response.Headers.Location) {
        $location = $_.Exception.Response.Headers.Location.ToString()
        $extracted = $location -replace ".*/tag/", ""
        # Validate: must start with 'v' and not contain URL chars
        if ($extracted -match "^v[0-9]" -and $extracted -notmatch "/") {
          $Version = $extracted
          Write-Info "Resolved latest version via redirect: $Version"
        }
      }
    }
    if (-not $Version) {
      $Version = $FallbackVersion
      Write-Warn "Could not resolve latest version; defaulting to $Version"
    }
  }
}

# Determine target
if (-not [Environment]::Is64BitProcess) {
  Write-Err "32-bit Windows is not supported. Please use a 64-bit system."
  exit 1
}
$target = "x86_64-pc-windows-msvc"
$zip = "dcg-$target.zip"

if (-not $CosignIdentityRegex) {
  $CosignIdentityRegex = "^https://github.com/$Owner/$Repo/.github/workflows/dist.yml@refs/tags/.*$"
}
if (-not $CosignOidcIssuer) {
  $CosignOidcIssuer = "https://token.actions.githubusercontent.com"
}

if ($ArtifactUrl) {
  $url = $ArtifactUrl
} else {
  $url = "https://github.com/$Owner/$Repo/releases/download/$Version/$zip"
}

# Create temp directory
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "dcg_install"
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zipFile = Join-Path $tmp $zip

Write-Info "Downloading $url"
try {
  Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
} catch {
  Write-Err "Failed to download artifact: $_"
  exit 1
}

# Verify checksum
$checksumToUse = $Checksum
if (-not $checksumToUse) {
  if (-not $ChecksumUrl) { $ChecksumUrl = "$url.sha256" }
  Write-Info "Fetching checksum from $ChecksumUrl"
  try {
    $checksumToUse = (Invoke-WebRequest -Uri $ChecksumUrl -UseBasicParsing).Content.Trim().Split(' ')[0]
  } catch {
    Write-Err "Checksum file not found or invalid; refusing to install."
    exit 1
  }
}

$hash = Get-FileHash $zipFile -Algorithm SHA256
if ($hash.Hash.ToLower() -ne $checksumToUse.ToLower()) {
  Write-Err "Checksum mismatch!"
  Write-Err "Expected: $checksumToUse"
  Write-Err "Got:      $($hash.Hash.ToLower())"
  exit 1
}
Write-Ok "Checksum verified"

# Verify Sigstore/cosign bundle (best-effort)
if (Get-Command cosign -ErrorAction SilentlyContinue) {
  if (-not $SigstoreBundleUrl) { $SigstoreBundleUrl = "$url.sigstore.json" }
  $bundleFile = Join-Path $tmp ([System.IO.Path]::GetFileName($SigstoreBundleUrl))
  Write-Info "Fetching sigstore bundle from $SigstoreBundleUrl"
  try {
    Invoke-WebRequest -Uri $SigstoreBundleUrl -OutFile $bundleFile -UseBasicParsing
    & cosign verify-blob --bundle $bundleFile --certificate-identity-regexp $CosignIdentityRegex --certificate-oidc-issuer $CosignOidcIssuer $zipFile | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Err "Signature verification failed"
      exit 1
    }
    Write-Ok "Signature verified (cosign)"
  } catch {
    Write-Warn "Sigstore bundle not found; skipping signature verification"
  }
} else {
  Write-Warn "cosign not found; skipping signature verification (install cosign for stronger authenticity checks)"
}

# Extract
Write-Info "Extracting..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
$extractDir = Join-Path $tmp "extract"
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $extractDir)

# Find binary
$bin = Get-ChildItem -Path $extractDir -Recurse -Filter "dcg.exe" | Select-Object -First 1
if (-not $bin) {
  Write-Err "Binary not found in zip"
  exit 1
}

# Install
if (-not (Test-Path $Dest)) {
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
}
Copy-Item $bin.FullName (Join-Path $Dest "dcg.exe") -Force
Write-Ok "Installed to $Dest\dcg.exe"

# PATH management
$path = [Environment]::GetEnvironmentVariable("PATH", "User")
if (-not $path.Contains($Dest)) {
  if ($EasyMode) {
    [Environment]::SetEnvironmentVariable("PATH", "$path;$Dest", "User")
    Write-Ok "Added $Dest to PATH (User)"
  } else {
    Write-Warn "Add $Dest to PATH to use dcg"
  }
}

# Cleanup
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

# Verify
if ($Verify) {
  Write-Info "Running self-test..."
  $testInput = '{"tool_name":"Bash","tool_input":{"command":"git status"}}'
  $result = $testInput | & "$Dest\dcg.exe"
  Write-Ok "Self-test complete"
}

Write-Ok "Done. Binary at: $Dest\dcg.exe"
Write-Host ""
Write-Info "To configure Claude Code, add to your settings.json:"
# Escape backslashes for JSON output (double them for JSON string)
$jsonPath = ($Dest -replace '\\', '\\\\') + "\\\\dcg.exe"
Write-Host @"
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$jsonPath"
          }
        ]
      }
    ]
  }
}
"@
