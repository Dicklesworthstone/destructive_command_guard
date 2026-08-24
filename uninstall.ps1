# dcg PowerShell uninstaller
#
# Usage:
#   irm https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/uninstall.ps1 | iex
#
# Options:
#   -Dest DIR       Binary install directory (default: ~/.local/bin)
#   -Yes            Skip confirmation prompt
#   -KeepConfig     Preserve config in native and legacy dcg state roots
#   -KeepHistory    Preserve history.db, backups, and local history data
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

function Get-QuotedCommandProgram {
  param([string]$Text)

  if ([string]::IsNullOrEmpty($Text) -or $Text.Length -lt 2) { return "" }
  $quote = $Text[0]
  if ($quote -ne "'" -and $quote -ne '"') { return "" }

  $program = New-Object System.Text.StringBuilder
  $index = 1
  while ($index -lt $Text.Length) {
    $character = $Text[$index]
    if ($character -eq $quote) {
      if ($quote -eq "'" -and
          $index + 1 -lt $Text.Length -and
          $Text[$index + 1] -eq "'") {
        [void]$program.Append("'")
        $index += 2
        continue
      }
      return $program.ToString()
    }
    if ($quote -eq '"' -and
        $character -eq [char]96 -and
        $index + 1 -lt $Text.Length) {
      [void]$program.Append($Text[$index + 1])
      $index += 2
      continue
    }
    [void]$program.Append($character)
    $index += 1
  }
  ""
}

function Get-DcgCommandName {
  param([string]$Command)

  if ([string]::IsNullOrWhiteSpace($Command)) { return "" }

  $trimmed = $Command.Trim()
  if ($trimmed.StartsWith('&')) {
    $trimmed = $trimmed.Substring(1).TrimStart()
  }
  if ($trimmed.StartsWith('"') -or $trimmed.StartsWith("'")) {
    $program = Get-QuotedCommandProgram $trimmed
    if ([string]::IsNullOrEmpty($program)) { return "" }
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
  if ($Hook -is [System.Collections.IDictionary]) {
    if (-not $Hook.Contains("command")) { return $false }
    $command = $Hook["command"]
  } else {
    $prop = $Hook.PSObject.Properties["command"]
    if ($null -eq $prop) { return $false }
    $command = $prop.Value
  }

  $name = Get-DcgCommandName ([string]$command)
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
  # Strip dcg's hook from every matcher entry under a Claude-Code-style event.
  # Looking across all matchers repairs historical misinstallations where dcg
  # was executable but attached to a matcher the agent never invoked. Removes
  # ONLY dcg-owned inner hooks, preserves coexisting hooks/matchers, prunes
  # emptied containers. UTF-8 no BOM.
  param(
    [string]$Path,
    [switch]$DeleteEmptyFile,
    [string]$EventName = "PreToolUse"
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
    $inner = Get-ObjectPropertyValue $entry "hooks"
    if ($null -eq $inner) {
      $newPreToolUse += $entry
      continue
    }
    if (-not (Test-JsonArray $inner)) {
      return $false
    }

    $entryRemoved = $false
    $filtered = @()
    foreach ($hook in (Get-JsonArray $inner)) {
      if (Test-DcgHookCommand $hook) {
        $removed = $true
        $entryRemoved = $true
      } else {
        $filtered += $hook
      }
    }

    if ($entryRemoved) {
      # Drop the group only when removing dcg's hooks EMPTIED it. A matcher
      # group the user wrote with an originally-empty "hooks": [] — or one
      # that keeps non-dcg hooks — survives untouched (matches uninstall.sh:
      # bash prunes only `inner and not filtered` groups).
      if ($filtered.Count -eq 0) { continue }
      Set-ObjectPropertyValue $entry "hooks" $filtered
    }
    $newPreToolUse += $entry
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

function Remove-DcgStateDirectories {
  # history.db currently lives beside config.toml in $ConfigDir. Treat it and
  # SQLite's live sidecars as history so -KeepConfig and -KeepHistory remain
  # independent. Backups also share the native Windows config root because
  # dirs::data_dir() resolves to roaming AppData. $DataDir contains local logs.
  param(
    [string]$ConfigDir,
    [string]$DataDir,
    [switch]$KeepConfig,
    [switch]$KeepHistory
  )

  $historyNames = @(
    "history.db",
    "history.db-wal",
    "history.db-shm",
    "backups",
    "blocked.log"
  )
  $sameStateRoot = (
    [System.IO.Path]::GetFullPath($ConfigDir) -ieq
    [System.IO.Path]::GetFullPath($DataDir)
  )

  if (Test-Path $ConfigDir -PathType Container) {
    if (-not $KeepConfig -and -not $KeepHistory) {
      Remove-Item -Recurse -Force -LiteralPath $ConfigDir
      Write-Ok "Removed $ConfigDir"
    } elseif (-not $KeepConfig) {
      foreach ($item in @(Get-ChildItem -Force -LiteralPath $ConfigDir)) {
        if ($item.Name -notin $historyNames) {
          Remove-Item -Recurse -Force -LiteralPath $item.FullName
        }
      }
      Write-Ok "Removed configuration from $ConfigDir (preserved history)"
    } elseif (-not $KeepHistory) {
      foreach ($name in $historyNames) {
        $historyPath = Join-Path $ConfigDir $name
        if (Test-Path -LiteralPath $historyPath) {
          Remove-Item -Recurse -Force -LiteralPath $historyPath
        }
      }
      Write-Ok "Removed history database from $ConfigDir"
    }
  }

  if (-not $sameStateRoot -and -not $KeepHistory -and
      (Test-Path $DataDir -PathType Container)) {
    Remove-Item -Recurse -Force -LiteralPath $DataDir
    Write-Ok "Removed $DataDir"
  }
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
  # Match the event key explicitly and case-insensitively: Copilot's schema is
  # camelCase `preToolUse`, but historical dcg releases could leave a
  # PascalCase `PreToolUse` entry behind; clean every matching spelling (#253).
  $preProps = @($hooks.PSObject.Properties | Where-Object { $_.Name.ToLowerInvariant() -eq 'pretooluse' })
  if ($preProps.Count -eq 0) { return $false }
  $removed = $false
  foreach ($prop in $preProps) {
    $preKey = $prop.Name
    $entries = Get-JsonArray $prop.Value
    $kept = @()
    $keyRemoved = $false
    foreach ($e in $entries) {
      if ($e -isnot [psobject]) { $kept += $e; continue }
      foreach ($field in @("bash", "powershell")) {
        $val = Get-ObjectPropertyValue $e $field
        if ($null -ne $val -and ((Get-DcgCommandName ([string]$val)) -in @('dcg', 'dcg.exe'))) {
          Remove-ObjectPropertyValue $e $field
          $keyRemoved = $true
        }
      }
      $hasPlatform = (Test-ObjectPropertyExists $e "bash") -or (Test-ObjectPropertyExists $e "powershell")
      if ($hasPlatform) { $kept += $e }  # else: drop the now-empty dcg entry
    }
    if (-not $keyRemoved) { continue }
    $removed = $true
    if ($kept.Count -gt 0) { Set-ObjectPropertyValue $hooks $preKey $kept }
    else { Remove-ObjectPropertyValue $hooks $preKey }
  }
  if (-not $removed) { return $false }
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

function Get-HermesConfigDir {
  # The directory whose config.yaml Hermes Agent actually reads (mirror of the
  # resolver in install.ps1): HERMES_HOME when set, else %LOCALAPPDATA%\hermes
  # on native Windows, else ~/.hermes (Linux/macOS pwsh).
  param([string]$HomeDir = $HOME)
  if (-not [string]::IsNullOrWhiteSpace($env:HERMES_HOME)) { return $env:HERMES_HOME }
  if ($env:OS -eq 'Windows_NT') {
    $base = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($base)) {
      try {
        $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
      } catch { $base = $null }
    }
    if (-not [string]::IsNullOrWhiteSpace($base)) { return (Join-Path $base 'hermes') }
  }
  Join-Path $HomeDir '.hermes'
}

function Unconfigure-HermesHook {
  # Remove dcg from Hermes' config.yaml. Native Windows Hermes reads
  # HERMES_HOME (default %LOCALAPPDATA%\hermes); pre-#270 dcg installers wrote
  # to ~/.hermes — so clean BOTH locations. With powershell-yaml: strip the dcg
  # pre_tool_call entry (leave hooks_auto_accept, which other hooks may rely on).
  # Without the module: never edit arbitrary YAML — warn the user to remove it.
  # Returns $true if any dcg entry was removed.
  param([string]$HomeDir = $HOME)
  $dirs = @((Get-HermesConfigDir -HomeDir $HomeDir), (Join-Path $HomeDir ".hermes")) |
    Select-Object -Unique
  $removedAny = $false
  foreach ($dir in $dirs) {
    $cfg = Join-Path $dir "config.yaml"
    if (-not (Test-Path $cfg -PathType Leaf)) { continue }
    if ($null -eq (Get-Module -ListAvailable -Name powershell-yaml -ErrorAction SilentlyContinue)) {
      Write-Warn "powershell-yaml not installed; remove the dcg entry from $cfg manually."
      continue
    }
    Import-Module powershell-yaml -ErrorAction SilentlyContinue
    try { $doc = (Get-Content -Raw -LiteralPath $cfg | ConvertFrom-Yaml) } catch { continue }
    if ($doc -isnot [System.Collections.IDictionary]) { continue }
    $hooks = $doc["hooks"]
    if ($hooks -isnot [System.Collections.IDictionary]) { continue }
    $list = $hooks["pre_tool_call"]
    if ($null -eq $list) { continue }
    $kept = @(@($list) | Where-Object {
        -not (($_ -is [System.Collections.IDictionary]) -and
              ((Get-DcgCommandName ([string]$_["command"])) -in @('dcg', 'dcg.exe')))
      })
    if ($kept.Count -eq @($list).Count) { continue }
    if ($kept.Count -gt 0) { $hooks["pre_tool_call"] = $kept } else { $hooks.Remove("pre_tool_call") }
    [System.IO.File]::WriteAllText($cfg, (ConvertTo-Yaml $doc), (New-Object System.Text.UTF8Encoding $false))
    $removedAny = $true
  }
  $removedAny
}

function Get-DcgRepositoryRoot {
  param([string]$StartDir = (Get-Location).Path)
  try {
    $current = Get-Item -LiteralPath $StartDir -ErrorAction Stop
    while ($null -ne $current) {
      if (Test-Path (Join-Path $current.FullName '.git')) { return $current.FullName }
      $current = $current.Parent
    }
    return [System.IO.Path]::GetFullPath($StartDir)
  } catch {
    return $StartDir
  }
}

function Get-OmpConfigRoot {
  param([string]$HomeDir = $HOME)
  $configName = if ([string]::IsNullOrEmpty($env:PI_CONFIG_DIR)) { '.omp' } else { $env:PI_CONFIG_DIR }
  $configName = $configName.TrimStart([char[]]@('\', '/'))
  Join-Path $HomeDir $configName
}

function Get-OmpAgentDir {
  # Mirror OMP's active-profile directory resolution closely enough for safe,
  # marker-owned extension cleanup.
  param([string]$HomeDir = $HOME)
  $configRoot = Get-OmpConfigRoot -HomeDir $HomeDir

  $profile = $null
  if (Test-Path Env:OMP_PROFILE) { $profile = $env:OMP_PROFILE }
  elseif (Test-Path Env:PI_PROFILE) { $profile = $env:PI_PROFILE }
  if ($null -ne $profile) { $profile = $profile.Trim() }
  $validProfile = (-not [string]::IsNullOrEmpty($profile)) -and
    ($profile -ne 'default') -and ($profile.Length -le 64) -and
    ($profile -match '^[a-z0-9][a-z0-9._-]*$') -and (-not $profile.EndsWith('.')) -and
    ($profile -notmatch '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)')
  if ($validProfile) {
    return (Join-Path (Join-Path (Join-Path $configRoot 'profiles') $profile) 'agent')
  }
  if (-not [string]::IsNullOrEmpty($env:PI_CODING_AGENT_DIR)) {
    return $env:PI_CODING_AGENT_DIR
  }
  Join-Path $configRoot 'agent'
}

function Unconfigure-OmpExtension {
  # Remove only marker-owned dcg-guard.ts files; preserve user-authored files.
  # Sweep all profiles under the default/current config roots so changing
  # profiles after installation cannot leave a live extension behind.
  param([string]$HomeDir = $HOME, [string]$RepoRoot = '')
  if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Get-DcgRepositoryRoot
  }
  $configRoots = @(
    (Join-Path $HomeDir '.omp'),
    (Get-OmpConfigRoot -HomeDir $HomeDir)
  ) | Select-Object -Unique
  $paths = @(
    (Join-Path (Join-Path (Get-OmpAgentDir -HomeDir $HomeDir) 'extensions') 'dcg-guard.ts'),
    (Join-Path (Join-Path (Join-Path $RepoRoot '.omp') 'extensions') 'dcg-guard.ts')
  )
  if (-not [string]::IsNullOrEmpty($env:PI_CODING_AGENT_DIR)) {
    $paths += Join-Path (Join-Path $env:PI_CODING_AGENT_DIR 'extensions') 'dcg-guard.ts'
  }
  foreach ($configRoot in $configRoots) {
    $paths += Join-Path (Join-Path (Join-Path $configRoot 'agent') 'extensions') 'dcg-guard.ts'
    $profilesRoot = Join-Path $configRoot 'profiles'
    if (-not (Test-Path $profilesRoot -PathType Container)) { continue }
    foreach ($profileDir in Get-ChildItem -LiteralPath $profilesRoot -Directory -ErrorAction SilentlyContinue) {
      $paths += Join-Path (Join-Path (Join-Path $profileDir.FullName 'agent') 'extensions') 'dcg-guard.ts'
    }
  }
  $paths = @($paths | Select-Object -Unique)
  $removed = $false
  foreach ($extension in $paths) {
    if (-not (Test-Path $extension -PathType Leaf)) { continue }
    if ((Get-Content -Raw -LiteralPath $extension) -notmatch 'dcg-omp-extension') { continue }
    Remove-Item -Force -LiteralPath $extension -ErrorAction SilentlyContinue
    $removed = $true
  }
  $removed
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
if (Remove-DcgHooksFromJsonFile -Path $geminiSettings -EventName "BeforeTool" -DeleteEmptyFile) {
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

# Hermes Agent (HERMES_HOME / %LOCALAPPDATA%\hermes / ~/.hermes config.yaml).
if (Unconfigure-HermesHook) { Write-Ok "Removed Hermes hook" }

# Posit Assistant (~/.posit/assistant/settings.json): Claude-Code-shaped hooks,
# so the generic remover applies. Deliberately NO -DeleteEmptyFile — Posit
# Assistant keeps unrelated settings (model, permissions, ...) in this file.
$positAssistantSettings = Join-Path (Join-Path (Join-Path $HOME ".posit") "assistant") "settings.json"
if (Remove-DcgHooksFromJsonFile -Path $positAssistantSettings) {
  Write-Ok "Removed Posit Assistant hook"
}

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

if (Unconfigure-OmpExtension) { Write-Ok "Removed Oh My Pi extension" }

if (Test-Path $binary -PathType Leaf) {
  Remove-Item -Force -Path $binary
  Write-Ok "Removed $binary"
}

if (-not $KeepPath) {
  if (Remove-DcgFromUserPath -PathToRemove $Dest) {
    Write-Ok "Removed $Dest from User PATH"
  }
}

$nativeConfigDir = $null
$nativeConfigBase = $env:APPDATA
if ([string]::IsNullOrWhiteSpace($nativeConfigBase)) {
  $nativeConfigBase = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ApplicationData
  )
}
$nativeDataBase = $env:LOCALAPPDATA
if ([string]::IsNullOrWhiteSpace($nativeDataBase)) {
  $nativeDataBase = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
  )
}

if (-not [string]::IsNullOrWhiteSpace($nativeConfigBase)) {
  $nativeConfigDir = Join-Path $nativeConfigBase "dcg"
  $nativeDataDir = if ([string]::IsNullOrWhiteSpace($nativeDataBase)) {
    Join-Path $HOME ".local\share\dcg"
  } else {
    Join-Path $nativeDataBase "dcg"
  }
  Remove-DcgStateDirectories -ConfigDir $nativeConfigDir -DataDir $nativeDataDir `
    -KeepConfig:$KeepConfig -KeepHistory:$KeepHistory
}

# dcg continues to honor its historical XDG-style paths on Windows. Clean them
# as a separate root unless they resolve to the same directory as native
# roaming/local AppData.
$legacyConfigDir = Join-Path $HOME ".config\dcg"
$legacyDataDir = Join-Path $HOME ".local\share\dcg"
$nativeConfigResolved = if ($null -ne $nativeConfigDir) {
  [System.IO.Path]::GetFullPath($nativeConfigDir)
} else {
  ""
}
$legacyConfigResolved = [System.IO.Path]::GetFullPath($legacyConfigDir)
if ($legacyConfigResolved -ine $nativeConfigResolved) {
  Remove-DcgStateDirectories -ConfigDir $legacyConfigDir -DataDir $legacyDataDir `
    -KeepConfig:$KeepConfig -KeepHistory:$KeepHistory
}

Write-Ok "Uninstall complete"
