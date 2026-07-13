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
  [switch]$Quiet,
  # Testing hook: dot-source (`. ./uninstall.ps1 -LoadFunctionsOnly`) to load the
  # functions WITHOUT running the uninstall body (see tests/installer/*.ps1).
  [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = "Stop"

function Write-Info { param($msg) if (-not $Quiet) { Write-Host "[*] $msg" -ForegroundColor Cyan } }
function Write-Ok { param($msg) if (-not $Quiet) { Write-Host "[+] $msg" -ForegroundColor Green } }
function Write-Warn { param($msg) if (-not $Quiet) { Write-Host "[!] $msg" -ForegroundColor Yellow } }
function Write-Err { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

function Test-CommandTokenLooksLikePath {
  param([string]$Token)

  if ([string]::IsNullOrEmpty($Token)) { return $false }
  ($Token -match '^[A-Za-z]:[\\/]' -or
    $Token.StartsWith('\') -or
    $Token.StartsWith('/') -or
    $Token -match '[\\/]')
}

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
    # A BARE (unquoted) value may be a path that itself contains spaces (e.g. an
    # install under `C:\Users\John Doe\.local\bin\dcg.exe`). Splitting on
    # whitespace and keeping token 0 would yield `C:\Users\John` -> wrong basename.
    # Mirror install.ps1: if token 0 looks like a path, take the trailing
    # `/\`-segment's first token as the program, UNLESS some other executable
    # (`*.exe/.cmd/.bat/.ps1 `) appears before it (then dcg is just an argument).
    $program = ($trimmed -split '\s+', 2)[0]
    if (Test-CommandTokenLooksLikePath $program) {
      $normalizedTrimmed = $trimmed -replace '\\', '/'
      $leafFromFullPath = ($normalizedTrimmed -split '/')[-1]
      $leafCommand = (($leafFromFullPath -split '\s+', 2)[0]).Trim('"').Trim("'")
      $prefixBeforeLeaf = $normalizedTrimmed.Substring(0, $normalizedTrimmed.Length - $leafFromFullPath.Length)
      if ((($leafCommand -eq "dcg") -or ($leafCommand -eq "dcg.exe")) -and
          ($prefixBeforeLeaf -notmatch '(?i)\.(?:exe|cmd|bat|ps1)\s')) {
        $program = $leafCommand
      }
    }
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
  # Strip dcg's hook from a Claude-Code-style hooks file. Defaults to
  # PreToolUse/Bash (Claude + Codex); pass -EventName/-Matcher for Gemini
  # (BeforeTool/run_shell_command). Removes ONLY dcg-owned inner hooks, preserves
  # coexisting hooks/matchers, prunes emptied containers. UTF-8 no BOM.
  param(
    [string]$Path,
    [switch]$DeleteEmptyFile,
    [string]$EventName = "PreToolUse",
    [string]$Matcher = "Bash"
  )

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

  if (-not (Test-ObjectPropertyExists $hooks $EventName)) { return $false }
  $preToolUse = Get-ObjectPropertyValue $hooks $EventName
  if (-not (Test-JsonArray $preToolUse)) { return $false }

  $newPreToolUse = @()
  $removed = $false

  foreach ($entry in (Get-JsonArray $preToolUse)) {
    if ((Get-ObjectPropertyValue $entry "matcher") -ne $Matcher) {
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
    Set-ObjectPropertyValue $hooks $EventName $newPreToolUse
  } else {
    Remove-ObjectPropertyValue $hooks $EventName
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

function Unconfigure-CursorHook {
  # Remove dcg from ~/.cursor/hooks.json (beforeShellExecution[]) and delete our
  # marker-guarded bridge script. Preserves coexisting hooks. Returns $true if any
  # dcg artifact was removed.
  param([string]$HomeDir = $HOME)
  $removed = $false
  $cursorDir = Join-Path $HomeDir ".cursor"
  $bridge = Join-Path (Join-Path $cursorDir "hooks") "dcg-pre-shell.ps1"
  if ((Test-Path $bridge -PathType Leaf) -and
      ((Get-Content -Raw -LiteralPath $bridge) -match 'dcg-cursor-hook')) {
    Remove-Item -Force -LiteralPath $bridge -ErrorAction SilentlyContinue
    $removed = $true
  }
  $hooksFile = Join-Path $cursorDir "hooks.json"
  if (-not (Test-Path $hooksFile -PathType Leaf)) { return $removed }
  try { $config = Get-Content -Raw -LiteralPath $hooksFile | ConvertFrom-Json }
  catch { Write-Warn "Could not parse $hooksFile; leaving it unchanged"; return $removed }
  if ($null -eq $config -or $config -isnot [psobject]) { return $removed }
  $hooks = Get-ObjectPropertyValue $config "hooks"
  if ($null -eq $hooks -or $hooks -isnot [psobject]) { return $removed }
  if (-not (Test-ObjectPropertyExists $hooks "beforeShellExecution")) { return $removed }
  $entries = Get-JsonArray (Get-ObjectPropertyValue $hooks "beforeShellExecution")
  $kept = @()
  foreach ($e in $entries) {
    $cmd = [string](Get-ObjectPropertyValue $e "command")
    if (($cmd -match 'dcg-pre-shell') -or ((Get-DcgCommandName $cmd) -in @('dcg', 'dcg.exe'))) {
      $removed = $true; continue
    }
    $kept += $e
  }
  if (-not $removed) { return $false }
  if ($kept.Count -gt 0) { Set-ObjectPropertyValue $hooks "beforeShellExecution" $kept }
  else { Remove-ObjectPropertyValue $hooks "beforeShellExecution" }
  if (Test-EmptyObject $hooks) { Remove-ObjectPropertyValue $config "hooks" }
  $remainingKeys = @($config.PSObject.Properties.Name | Where-Object { $_ -ne 'version' })
  if ($remainingKeys.Count -eq 0) {
    Remove-Item -Force -LiteralPath $hooksFile  # dcg-created file; nothing left but version
  } else {
    [System.IO.File]::WriteAllText($hooksFile, ($config | ConvertTo-Json -Depth 20),
      (New-Object System.Text.UTF8Encoding $false))
  }
  $true
}

function Unconfigure-CopilotHook {
  # Remove dcg from the user-level hook by default. -RepoRoot selects the
  # legacy repo-local path written by dcg <= 0.6.5 so uninstall can clean both.
  # strip the dcg bash/powershell fields, drop an entry only if it has no other
  # platform field, preserve coexisting hooks. Returns $true if removed.
  param([string]$CopilotHome, [string]$RepoRoot)
  if (-not [string]::IsNullOrEmpty($RepoRoot)) {
    $hookFile = Join-Path (Join-Path (Join-Path $RepoRoot ".github") "hooks") "dcg.json"
  } else {
    if ([string]::IsNullOrEmpty($CopilotHome)) {
      if (-not [string]::IsNullOrWhiteSpace($env:COPILOT_HOME)) {
        $CopilotHome = $env:COPILOT_HOME
      } else {
        $CopilotHome = Join-Path $HOME ".copilot"
      }
    }
    $hookFile = Join-Path (Join-Path $CopilotHome "hooks") "dcg.json"
  }
  if (-not (Test-Path $hookFile -PathType Leaf)) { return $false }
  try { $config = Get-Content -Raw -LiteralPath $hookFile | ConvertFrom-Json } catch { return $false }
  if ($null -eq $config -or $config -isnot [psobject]) { return $false }
  $hooks = Get-ObjectPropertyValue $config "hooks"
  if ($null -eq $hooks -or $hooks -isnot [psobject]) { return $false }
  if (-not (Test-ObjectPropertyExists $hooks "preToolUse")) { return $false }
  $entries = Get-JsonArray (Get-ObjectPropertyValue $hooks "preToolUse")
  $kept = @()
  $removed = $false
  foreach ($e in $entries) {
    if ($e -isnot [psobject]) { $kept += $e; continue }
    foreach ($field in @("bash", "powershell")) {
      $val = Get-ObjectPropertyValue $e $field
      if ($null -ne $val -and ((Get-DcgCommandName ([string]$val)) -in @('dcg', 'dcg.exe'))) {
        Remove-ObjectPropertyValue $e $field
        $removed = $true
      }
    }
    $hasPlatform = (Test-ObjectPropertyExists $e "bash") -or (Test-ObjectPropertyExists $e "powershell")
    if ($hasPlatform) { $kept += $e }  # else: drop the now-empty dcg entry
  }
  if (-not $removed) { return $false }
  if ($kept.Count -gt 0) { Set-ObjectPropertyValue $hooks "preToolUse" $kept }
  else { Remove-ObjectPropertyValue $hooks "preToolUse" }
  if (Test-EmptyObject $hooks) { Remove-ObjectPropertyValue $config "hooks" }
  $remainingKeys = @($config.PSObject.Properties.Name | Where-Object { $_ -ne 'version' })
  if ($remainingKeys.Count -eq 0) {
    Remove-Item -Force -LiteralPath $hookFile
  } else {
    [System.IO.File]::WriteAllText($hookFile, ($config | ConvertTo-Json -Depth 20),
      (New-Object System.Text.UTF8Encoding $false))
  }
  $true
}

function Unconfigure-HermesHook {
  # Remove dcg from ~/.hermes/config.yaml. With powershell-yaml: strip the dcg
  # pre_tool_call entry (leave hooks_auto_accept, which other hooks may rely on).
  # Without the module: never edit arbitrary YAML — warn the user to remove it.
  # Returns $true if removed.
  param([string]$HomeDir = $HOME)
  $cfg = Join-Path (Join-Path $HomeDir ".hermes") "config.yaml"
  if (-not (Test-Path $cfg -PathType Leaf)) { return $false }
  if ($null -eq (Get-Module -ListAvailable -Name powershell-yaml -ErrorAction SilentlyContinue)) {
    Write-Warn "powershell-yaml not installed; remove the dcg entry from $cfg manually."
    return $false
  }
  Import-Module powershell-yaml -ErrorAction SilentlyContinue
  try { $doc = (Get-Content -Raw -LiteralPath $cfg | ConvertFrom-Yaml) } catch { return $false }
  if ($doc -isnot [System.Collections.IDictionary]) { return $false }
  $hooks = $doc["hooks"]
  if ($hooks -isnot [System.Collections.IDictionary]) { return $false }
  $list = $hooks["pre_tool_call"]
  if ($null -eq $list) { return $false }
  $kept = @(@($list) | Where-Object {
      -not (($_ -is [System.Collections.IDictionary]) -and
            ((Get-DcgCommandName ([string]$_["command"])) -in @('dcg', 'dcg.exe')))
    })
  if ($kept.Count -eq @($list).Count) { return $false }
  if ($kept.Count -gt 0) { $hooks["pre_tool_call"] = $kept } else { $hooks.Remove("pre_tool_call") }
  [System.IO.File]::WriteAllText($cfg, (ConvertTo-Yaml $doc), (New-Object System.Text.UTF8Encoding $false))
  $true
}

# Testing entrypoint: when dot-sourced with -LoadFunctionsOnly, stop here so the
# functions above are available without running the uninstall body below.
if ($LoadFunctionsOnly) { return }

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

# Gemini CLI (BeforeTool / run_shell_command).
$geminiSettings = Join-Path (Join-Path $HOME ".gemini") "settings.json"
if (Remove-DcgHooksFromJsonFile -Path $geminiSettings -EventName "BeforeTool" -Matcher "run_shell_command" -DeleteEmptyFile) {
  Write-Ok "Removed Gemini CLI hook"
}

# Cursor IDE (hooks.json + PowerShell bridge).
if (Unconfigure-CursorHook) { Write-Ok "Removed Cursor IDE hook + bridge" }

# GitHub Copilot CLI: user-level hook plus the legacy repo-local hook, if the
# uninstaller is running inside a repository that still has one.
if (Unconfigure-CopilotHook) { Write-Ok "Removed user-level GitHub Copilot CLI hook" }
if (Get-Command git -ErrorAction SilentlyContinue) {
  $legacyRepo = (& git rev-parse --show-toplevel 2>$null)
  if (-not [string]::IsNullOrWhiteSpace($legacyRepo) -and
      (Unconfigure-CopilotHook -RepoRoot ($legacyRepo.Trim()))) {
    Write-Ok "Removed legacy repo-local GitHub Copilot CLI hook"
  }
}

# Hermes Agent (~/.hermes/config.yaml).
if (Unconfigure-HermesHook) { Write-Ok "Removed Hermes hook" }

# Grok (xAI): ~/.grok/hooks/dcg.json is a dcg-OWNED file — delete it outright
# (user-level and any project-local copy).
foreach ($grokHook in @((Join-Path (Join-Path (Join-Path $HOME ".grok") "hooks") "dcg.json"),
                        (Join-Path (Join-Path (Join-Path (Get-Location) ".grok") "hooks") "dcg.json"))) {
  if (Test-Path $grokHook -PathType Leaf) {
    Remove-Item -Force -LiteralPath $grokHook -ErrorAction SilentlyContinue
    Write-Ok "Removed Grok hook ($grokHook)"
  }
}

# Antigravity (agy): ~/.gemini/config/hooks.json uses the PreToolUse/Bash shape;
# strip the dcg entry, preserving any coexisting hooks.
$agyHooks = Join-Path (Join-Path (Join-Path $HOME ".gemini") "config") "hooks.json"
if (Remove-DcgHooksFromJsonFile -Path $agyHooks -DeleteEmptyFile) {
  Write-Ok "Removed Antigravity (agy) hook"
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
