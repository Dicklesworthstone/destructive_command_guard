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

function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

function Get-DcgCommandName {
  param([string]$Command)

  if ([string]::IsNullOrWhiteSpace($Command)) { return "" }

  $trimmed = $Command.Trim()
  if ($trimmed.StartsWith('"')) {
    $end = $trimmed.IndexOf('"', 1)
    if ($end -gt 0) {
      $program = $trimmed.Substring(1, $end - 1)
    } else {
      $program = $trimmed.Trim('"')
    }
  } elseif ($trimmed.StartsWith("'")) {
    $end = $trimmed.IndexOf("'", 1)
    if ($end -gt 0) {
      $program = $trimmed.Substring(1, $end - 1)
    } else {
      $program = $trimmed.Trim("'")
    }
  } else {
    $program = ($trimmed -split '\s+', 2)[0]
  }

  (($program -replace '\\', '/') -split '/')[-1].ToLowerInvariant()
}

function Test-DcgHookCommand {
  param([object]$Hook)

  if ($null -eq $Hook) { return $false }
  $prop = $Hook.PSObject.Properties["command"]
  if ($null -eq $prop) { return $false }

  $name = Get-DcgCommandName ([string]$prop.Value)
  $name -eq "dcg" -or $name -eq "dcg.exe"
}

function Get-ObjectPropertyValue {
  param([object]$Object, [string]$Name)

  if ($null -eq $Object) { return $null }
  $prop = $Object.PSObject.Properties[$Name]
  if ($null -eq $prop) { return $null }
  # PowerShell unwraps single-element arrays when they leave a function via the
  # output stream, which silently turns a one-entry JSON array into a scalar
  # PSCustomObject. Callers downstream then fail Test-JsonArray and throw
  # "PreToolUse must contain a list" on a perfectly valid hooks.json with a
  # single PreToolUse entry. Preserve array-ness with the unary comma operator.
  if ($prop.Value -is [array]) { return ,$prop.Value }
  $prop.Value
}

function Test-ObjectPropertyExists {
  param([object]$Object, [string]$Name)

  $null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]
}

function Set-ObjectPropertyValue {
  param([object]$Object, [string]$Name, [object]$Value)

  if ($null -eq $Object.PSObject.Properties[$Name]) {
    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
  } else {
    $Object.$Name = $Value
  }
}

function Get-JsonArray {
  param([object]$Value)

  if ($null -eq $Value) { return @() }
  if ($Value -is [array]) { return @($Value) }
  @($Value)
}

function Test-JsonArray {
  param([object]$Value)

  $Value -is [array]
}

function Test-JsonObject {
  param([object]$Value)

  $null -ne $Value -and $Value.GetType() -eq [System.Management.Automation.PSCustomObject]
}

function Test-UserPathContains {
  param([string]$PathValue, [string]$PathToFind)

  if ([string]::IsNullOrWhiteSpace($PathToFind)) { return $false }

  $target = $PathToFind.TrimEnd([char[]]@('\', '/'))
  if ([string]::IsNullOrWhiteSpace($target)) { return $false }

  if ([string]::IsNullOrEmpty($PathValue)) { return $false }
  foreach ($part in ($PathValue -split ';')) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    if ($part.TrimEnd([char[]]@('\', '/')) -ieq $target) {
      return $true
    }
  }

  $false
}

function Test-CodexHookAlreadyCurrent {
  param([object]$Config, [string]$DcgPath)

  $hooks = Get-ObjectPropertyValue $Config "hooks"
  if ($null -eq $hooks) { return $false }

  $dcgCommands = @()
  $firstBashHookCommand = $null
  $firstBashMatcherSeen = $false
  foreach ($entry in (Get-JsonArray (Get-ObjectPropertyValue $hooks "PreToolUse"))) {
    if ((Get-ObjectPropertyValue $entry "matcher") -ne "Bash") { continue }
    $entryHooks = Get-JsonArray (Get-ObjectPropertyValue $entry "hooks")
    if (-not $firstBashMatcherSeen) {
      $firstBashMatcherSeen = $true
      if ($entryHooks.Count -gt 0) {
        $firstBashHookCommand = [string](Get-ObjectPropertyValue $entryHooks[0] "command")
      }
    }
    foreach ($hook in $entryHooks) {
      if (Test-DcgHookCommand $hook) {
        $dcgCommands += [string](Get-ObjectPropertyValue $hook "command")
      }
    }
  }

  $dcgCommands.Count -eq 1 -and
    $dcgCommands[0] -eq $DcgPath -and
    $firstBashHookCommand -eq $DcgPath
}

function Configure-CodexHook {
  param([string]$DcgPath)

  $codexDir = Join-Path $HOME ".codex"
  $hooksFile = Join-Path $codexDir "hooks.json"
  $codexInstalled = (Test-Path $codexDir -PathType Container) -or
    ($null -ne (Get-Command codex -ErrorAction SilentlyContinue)) -or
    ($null -ne (Get-Command codex.exe -ErrorAction SilentlyContinue))

  if (-not $codexInstalled) { return "skipped" }

  if (-not (Test-Path $codexDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $codexDir | Out-Null
  }

  $dcgHook = [pscustomobject][ordered]@{
    type = "command"
    command = $DcgPath
  }

  if (-not (Test-Path $hooksFile -PathType Leaf)) {
    $config = [pscustomobject][ordered]@{
      hooks = [pscustomobject][ordered]@{
        PreToolUse = @(
          [pscustomobject][ordered]@{
            matcher = "Bash"
            hooks = @($dcgHook)
          }
        )
      }
    }
    # Write UTF-8 without BOM: Codex's JSON parser rejects the BOM byte sequence
    # at offset 0 ("expected value at line 1 column 1"). Use the .NET API directly
    # because Windows PowerShell 5.1 lacks `-Encoding UTF8NoBOM` (PS 6+ only). (#125)
    [System.IO.File]::WriteAllText(
        $hooksFile,
        ($config | ConvertTo-Json -Depth 20),
        (New-Object System.Text.UTF8Encoding $false)
    )
    return "created"
  }

  try {
    $config = Get-Content -Raw -Path $hooksFile | ConvertFrom-Json
  } catch {
    throw "Codex hooks.json is invalid JSON; leaving it unchanged: $hooksFile"
  }

  if (-not (Test-JsonObject $config)) {
    throw "Codex hooks.json must contain a JSON object; leaving it unchanged: $hooksFile"
  }

  $hooksExists = Test-ObjectPropertyExists $config "hooks"
  $hooks = Get-ObjectPropertyValue $config "hooks"
  if ($hooksExists -and -not (Test-JsonObject $hooks)) {
    throw "Codex hooks.json hooks must contain a JSON object; leaving it unchanged: $hooksFile"
  }

  if ($hooksExists) {
    $preToolUseExists = Test-ObjectPropertyExists $hooks "PreToolUse"
    $preToolUse = Get-ObjectPropertyValue $hooks "PreToolUse"
    if ($preToolUseExists -and -not (Test-JsonArray $preToolUse)) {
      throw "Codex hooks.json PreToolUse must contain a list; leaving it unchanged: $hooksFile"
    }
  }

  if (Test-CodexHookAlreadyCurrent $config $DcgPath) {
    return "already"
  }

  if (-not $hooksExists) {
    $hooks = [pscustomobject][ordered]@{}
    Set-ObjectPropertyValue $config "hooks" $hooks
  }

  $bashHooks = @()
  $newPreToolUse = @()

  foreach ($entry in (Get-JsonArray (Get-ObjectPropertyValue $hooks "PreToolUse"))) {
    if ((Get-ObjectPropertyValue $entry "matcher") -eq "Bash") {
      $entryHooks = Get-ObjectPropertyValue $entry "hooks"
      if ($null -ne $entryHooks -and -not (Test-JsonArray $entryHooks)) {
        throw "Codex hooks.json Bash matcher hooks must contain a list; leaving it unchanged: $hooksFile"
      }
      foreach ($hook in (Get-JsonArray $entryHooks)) {
        if (-not (Test-DcgHookCommand $hook)) {
          $bashHooks += $hook
        }
      }
    } else {
      $newPreToolUse += $entry
    }
  }

  $bashEntry = [pscustomobject][ordered]@{
    matcher = "Bash"
    hooks = @($dcgHook) + $bashHooks
  }
  $newPreToolUse = @($bashEntry) + $newPreToolUse

  Set-ObjectPropertyValue $hooks "PreToolUse" $newPreToolUse
  # UTF-8 without BOM — see comment above where this file is first created. (#125)
  [System.IO.File]::WriteAllText(
    $hooksFile,
    ($config | ConvertTo-Json -Depth 20),
    (New-Object System.Text.UTF8Encoding $false)
  )
  "merged"
}

# Resolve latest version if not specified
if ((-not $Version) -and (-not $ArtifactUrl)) {
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
      Write-Err "Could not resolve latest release. Re-run with -Version vX.Y.Z or provide -ArtifactUrl."
      exit 1
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

# Create a unique temp directory so concurrent installers cannot collide.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_install_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
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
if (-not (Test-UserPathContains -PathValue $path -PathToFind $Dest)) {
  if ($EasyMode) {
    if ([string]::IsNullOrEmpty($path)) {
      [Environment]::SetEnvironmentVariable("PATH", $Dest, "User")
    } else {
      [Environment]::SetEnvironmentVariable("PATH", "$path;$Dest", "User")
    }
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

Write-Host ""
try {
  $codexStatus = Configure-CodexHook -DcgPath (Join-Path $Dest "dcg.exe")
  switch ($codexStatus) {
    "created" { Write-Ok "Created Codex CLI hook at $HOME\.codex\hooks.json" }
    "merged" { Write-Ok "Added Codex CLI hook to $HOME\.codex\hooks.json" }
    "already" { Write-Ok "Codex CLI hook already configured" }
    "skipped" { Write-Info "Codex CLI not detected; skipped Codex hook configuration" }
    default { Write-Warn "Codex CLI hook status: $codexStatus" }
  }
} catch {
  Write-Warn "Codex CLI auto-configuration failed: $_"
}
