# dcg PowerShell uninstaller
#
# Usage:
#   irm https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/uninstall.ps1 | iex
#
# Options:
#   -Dest DIR       Binary install directory (default: ~/.local/bin)
#   -Yes            Skip confirmation prompt
#   -KeepConfig     Preserve ~/.config/dcg
#   -KeepHistory    Preserve ~/.local/share/dcg
#   -KeepPath       Preserve PATH entry for -Dest
#   -Purge          Remove config and history even if keep flags are set
#   -Quiet          Suppress non-error output
#

Param(
  [string]$Dest = "$HOME\.local\bin",
  [switch]$Yes,
  [switch]$KeepConfig,
  [switch]$KeepHistory,
  [switch]$KeepPath,
  [switch]$Purge,
  [switch]$Quiet
)

$ErrorActionPreference = "Stop"

function Write-Info { param($msg) if (-not $Quiet) { Write-Host "[*] $msg" -ForegroundColor Cyan } }
function Write-Ok { param($msg) if (-not $Quiet) { Write-Host "[+] $msg" -ForegroundColor Green } }
function Write-Warn { param($msg) if (-not $Quiet) { Write-Host "[!] $msg" -ForegroundColor Yellow } }
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
  # PSCustomObject. Callers downstream then fail Test-JsonArray, and the
  # uninstaller bails out without stripping the dcg hook from a hooks.json
  # that has only one Bash matcher / one inner hook. Preserve array-ness with
  # the unary comma operator.
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

function Remove-ObjectPropertyValue {
  param([object]$Object, [string]$Name)

  if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) {
    $Object.PSObject.Properties.Remove($Name)
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

function Test-EmptyObject {
  param([object]$Object)

  $null -eq $Object -or @($Object.PSObject.Properties).Count -eq 0
}

function Remove-DcgHooksFromJsonFile {
  param([string]$Path, [switch]$DeleteEmptyFile)

  if (-not (Test-Path $Path -PathType Leaf)) { return $false }

  try {
    $config = Get-Content -Raw -Path $Path | ConvertFrom-Json
  } catch {
    Write-Warn "Could not parse $Path; leaving it unchanged"
    return $false
  }

  if ($null -eq $config -or $config -isnot [psobject]) { return $false }

  $hooks = Get-ObjectPropertyValue $config "hooks"
  if ($null -eq $hooks -or $hooks -isnot [psobject]) { return $false }

  if (-not (Test-ObjectPropertyExists $hooks "PreToolUse")) { return $false }
  $preToolUse = Get-ObjectPropertyValue $hooks "PreToolUse"
  if (-not (Test-JsonArray $preToolUse)) { return $false }

  $newPreToolUse = @()
  $removed = $false

  foreach ($entry in (Get-JsonArray $preToolUse)) {
    if ((Get-ObjectPropertyValue $entry "matcher") -ne "Bash") {
      $newPreToolUse += $entry
      continue
    }

    $inner = Get-ObjectPropertyValue $entry "hooks"
    if ($null -eq $inner) {
      $newPreToolUse += $entry
      continue
    }
    if (-not (Test-JsonArray $inner)) {
      return $false
    }

    $filtered = @()
    foreach ($hook in (Get-JsonArray $inner)) {
      if (Test-DcgHookCommand $hook) {
        $removed = $true
      } else {
        $filtered += $hook
      }
    }

    if ($filtered.Count -gt 0) {
      Set-ObjectPropertyValue $entry "hooks" $filtered
      $newPreToolUse += $entry
    }
  }

  if (-not $removed) { return $false }

  if ($newPreToolUse.Count -gt 0) {
    Set-ObjectPropertyValue $hooks "PreToolUse" $newPreToolUse
  } else {
    Remove-ObjectPropertyValue $hooks "PreToolUse"
  }

  if (Test-EmptyObject $hooks) {
    Remove-ObjectPropertyValue $config "hooks"
  }

  if ((Test-EmptyObject $config) -and $DeleteEmptyFile) {
    Remove-Item -Force -Path $Path
  } else {
    # Write UTF-8 without BOM: Codex's JSON parser rejects the BOM byte sequence
    # at offset 0 ("expected value at line 1 column 1"), and `Set-Content -Encoding UTF8`
    # on Windows PowerShell 5.1 writes a BOM. Use the .NET API directly because
    # `-Encoding UTF8NoBOM` is PowerShell 6+ only. Mirrors the install.ps1 fix. (#125)
    [System.IO.File]::WriteAllText(
      $Path,
      ($config | ConvertTo-Json -Depth 20),
      (New-Object System.Text.UTF8Encoding $false)
    )
  }

  $true
}

function Remove-DcgFromUserPath {
  param([string]$PathToRemove)

  $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
  if ([string]::IsNullOrWhiteSpace($userPath)) { return $false }

  $target = $PathToRemove.TrimEnd([char[]]@('\', '/'))
  $parts = @()
  $removed = $false

  foreach ($part in ($userPath -split ';')) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    if ($part.TrimEnd([char[]]@('\', '/')) -ieq $target) {
      $removed = $true
      continue
    }
    $parts += $part
  }

  if ($removed) {
    [Environment]::SetEnvironmentVariable("PATH", ($parts -join ';'), "User")
  }

  $removed
}

if ($Purge) {
  $KeepConfig = $false
  $KeepHistory = $false
}

if (-not $Yes) {
  Write-Warn "This will remove dcg hooks and the installed dcg.exe binary."
  $answer = Read-Host "Continue? [y/N]"
  if ($answer -notmatch '^[Yy]$') {
    Write-Info "Cancelled"
    exit 0
  }
}

$binary = Join-Path $Dest "dcg.exe"

$claudeSettings = Join-Path (Join-Path $HOME ".claude") "settings.json"
if (Remove-DcgHooksFromJsonFile -Path $claudeSettings) {
  Write-Ok "Removed Claude Code hook"
}

$codexHooks = Join-Path (Join-Path $HOME ".codex") "hooks.json"
if (Remove-DcgHooksFromJsonFile -Path $codexHooks -DeleteEmptyFile) {
  Write-Ok "Removed Codex CLI hook"
}

if (Test-Path $binary -PathType Leaf) {
  Remove-Item -Force -Path $binary
  Write-Ok "Removed $binary"
}

if (-not $KeepPath) {
  if (Remove-DcgFromUserPath -PathToRemove $Dest) {
    Write-Ok "Removed $Dest from User PATH"
  }
}

$configDir = Join-Path $HOME ".config\dcg"
if (-not $KeepConfig -and (Test-Path $configDir)) {
  Remove-Item -Recurse -Force -Path $configDir
  Write-Ok "Removed $configDir"
}

$historyDir = Join-Path $HOME ".local\share\dcg"
if (-not $KeepHistory -and (Test-Path $historyDir)) {
  Remove-Item -Recurse -Force -Path $historyDir
  Write-Ok "Removed $historyDir"
}

Write-Ok "Uninstall complete"
