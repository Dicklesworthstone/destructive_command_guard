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
#   -Force            Configure agent hooks even if the agent CLI isn't detected
#   -NoConfigure      Install the binary only; skip all agent hook configuration
#   -Quiet            Suppress informational output (keep warnings/errors/success)
#   -Help             Print this help and exit
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
  [switch]$Verify,
  # Force agent (re)configuration even when an agent CLI is not detected (the
  # per-agent analog of what -EasyMode already does for Claude/Gemini).
  [switch]$Force,
  # Install the binary (and, under -EasyMode, set PATH) but skip ALL agent
  # hook auto-configuration and migration/profile helper setup.
  [switch]$NoConfigure,
  # Suppress informational ([*]) chatter; warnings, errors, and success ([+])
  # messages still print.
  [switch]$Quiet,
  # Print usage and exit.
  [switch]$Help,
  # Testing hook: dot-source the script (`. ./install.ps1 -LoadFunctionsOnly`) to
  # load its functions WITHOUT running the install body, so the hook-config merge
  # functions can be unit-tested (see tests/installer/*.ps1).
  [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = "Stop"

# Ensure TLS 1.2+ for GitHub downloads. Windows PowerShell 5.1 can still default
# to TLS 1.0/1.1, which GitHub rejects; harmless on PowerShell 7 (already modern).
try {
  [Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
  # Older/newer runtimes may not expose this; ignore.
}

function Write-Info { param($msg) if ($script:Quiet) { return }; Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
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

# Generic: true when the config already has exactly one dcg hook under a Bash
# Generic: true when the config already has exactly one dcg hook under the given
# $Event/$Matcher, equal to $DcgPath and first. Shared by Codex/Claude (PreToolUse
# /Bash) and Gemini (BeforeTool/run_shell_command).
function Test-AgentHookCurrent {
  param([object]$Config, [string]$DcgPath, [string]$Event, [string]$Matcher)

  $hooks = Get-ObjectPropertyValue $Config "hooks"
  if ($null -eq $hooks) { return $false }

  $dcgCommands = @()
  $firstHookCommand = $null
  $firstMatcherSeen = $false
  foreach ($entry in (Get-JsonArray (Get-ObjectPropertyValue $hooks $Event))) {
    if ((Get-ObjectPropertyValue $entry "matcher") -ne $Matcher) { continue }
    $entryHooks = Get-JsonArray (Get-ObjectPropertyValue $entry "hooks")
    if (-not $firstMatcherSeen) {
      $firstMatcherSeen = $true
      if ($entryHooks.Count -gt 0) {
        $firstHookCommand = [string](Get-ObjectPropertyValue $entryHooks[0] "command")
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
    $firstHookCommand -eq $DcgPath
}

# Atomically write $Object as JSON to $Path as UTF-8 WITHOUT a BOM. The BOM is
# omitted because strict JSON parsers (e.g. Codex) reject the leading EF BB BF
# ("expected value at line 1 column 1" — #125), and Windows PowerShell 5.1 lacks
# `-Encoding UTF8NoBOM`. The write is atomic (temp file in the same directory +
# Move-Item -Force) so a concurrent reader (an agent reading its settings) never
# sees a half-written file.
function Write-JsonFileNoBom {
  param([string]$Path, [object]$Object)

  $json = $Object | ConvertTo-Json -Depth 20
  $dir = Split-Path -Parent $Path
  $tmp = Join-Path $dir (".dcg-tmp-" + [System.Guid]::NewGuid().ToString("N"))
  [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding $false))
  Move-Item -Force -Path $tmp -Destination $Path
}

# Shared create-or-merge for a Claude-Code-style hooks file. Ensures
# `hooks.<Event>` has an entry with `matcher: <Matcher>` containing exactly one
# dcg hook ($DcgHook, whose command is $DcgPath), hoisted first, with any other
# hooks/entries preserved. Idempotent. Refuses to touch invalid JSON / malformed
# shapes (throws with $Label). Used by Codex/Claude (PreToolUse/Bash) and Gemini
# (BeforeTool/run_shell_command). Returns "created" | "already" | "merged".
function Merge-AgentHookFile {
  param(
    [string]$HooksFile,
    [object]$DcgHook,
    [string]$DcgPath,
    [string]$Event,
    [string]$Matcher,
    [string]$Label
  )

  if (-not (Test-Path $HooksFile -PathType Leaf)) {
    $innerHooks = [pscustomobject][ordered]@{}
    Set-ObjectPropertyValue $innerHooks $Event @(
      [pscustomobject][ordered]@{ matcher = $Matcher; hooks = @($DcgHook) }
    )
    $config = [pscustomobject][ordered]@{ hooks = $innerHooks }
    Write-JsonFileNoBom -Path $HooksFile -Object $config
    return "created"
  }

  try {
    $config = Get-Content -Raw -Path $HooksFile | ConvertFrom-Json
  } catch {
    throw "$Label is invalid JSON; leaving it unchanged: $HooksFile"
  }

  if (-not (Test-JsonObject $config)) {
    throw "$Label must contain a JSON object; leaving it unchanged: $HooksFile"
  }

  $hooksExists = Test-ObjectPropertyExists $config "hooks"
  $hooks = Get-ObjectPropertyValue $config "hooks"
  if ($hooksExists -and -not (Test-JsonObject $hooks)) {
    throw "$Label hooks must contain a JSON object; leaving it unchanged: $HooksFile"
  }

  if ($hooksExists) {
    $eventExists = Test-ObjectPropertyExists $hooks $Event
    $eventValue = Get-ObjectPropertyValue $hooks $Event
    if ($eventExists -and -not (Test-JsonArray $eventValue)) {
      throw "$Label $Event must contain a list; leaving it unchanged: $HooksFile"
    }
  }

  if (Test-AgentHookCurrent $config $DcgPath $Event $Matcher) {
    return "already"
  }

  if (-not $hooksExists) {
    $hooks = [pscustomobject][ordered]@{}
    Set-ObjectPropertyValue $config "hooks" $hooks
  }

  $matchedHooks = @()
  $newEventEntries = @()

  foreach ($entry in (Get-JsonArray (Get-ObjectPropertyValue $hooks $Event))) {
    if ((Get-ObjectPropertyValue $entry "matcher") -eq $Matcher) {
      $entryHooks = Get-ObjectPropertyValue $entry "hooks"
      if ($null -ne $entryHooks -and -not (Test-JsonArray $entryHooks)) {
        throw "$Label $Matcher matcher hooks must contain a list; leaving it unchanged: $HooksFile"
      }
      foreach ($hook in (Get-JsonArray $entryHooks)) {
        if (-not (Test-DcgHookCommand $hook)) {
          $matchedHooks += $hook
        }
      }
    } else {
      $newEventEntries += $entry
    }
  }

  $dcgEntry = [pscustomobject][ordered]@{
    matcher = $Matcher
    hooks = @($DcgHook) + $matchedHooks
  }
  $newEventEntries = @($dcgEntry) + $newEventEntries

  Set-ObjectPropertyValue $hooks $Event $newEventEntries
  Write-JsonFileNoBom -Path $HooksFile -Object $config
  "merged"
}

function Configure-CodexHook {
  param([string]$DcgPath, [string]$HomeDir = $HOME)

  $codexDir = Join-Path $HomeDir ".codex"
  $hooksFile = Join-Path $codexDir "hooks.json"
  $codexInstalled = (Test-Path $codexDir -PathType Container) -or
    ($null -ne (Get-Command codex -ErrorAction SilentlyContinue)) -or
    ($null -ne (Get-Command codex.exe -ErrorAction SilentlyContinue))

  if (-not $codexInstalled) { return "skipped" }

  if (-not (Test-Path $codexDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $codexDir | Out-Null
  }

  $dcgHook = [pscustomobject][ordered]@{ type = "command"; command = $DcgPath }
  Merge-AgentHookFile -HooksFile $hooksFile -DcgHook $dcgHook -DcgPath $DcgPath -Event "PreToolUse" -Matcher "Bash" -Label "Codex hooks.json"
}

# Configure Claude Code's PreToolUse/Bash hook in ~/.claude/settings.json. Claude
# Code uses the same hook shape as Codex, so this reuses Merge-PreToolUseBashHookFile.
# Configures when ~/.claude exists or `claude` is on PATH (or always under -Force,
# used by -EasyMode). Returns "created" | "already" | "merged" | "skipped".
function Configure-ClaudeHook {
  param([string]$DcgPath, [switch]$Force, [string]$HomeDir = $HOME)

  $claudeDir = Join-Path $HomeDir ".claude"
  $settingsFile = Join-Path $claudeDir "settings.json"
  $claudeInstalled = (Test-Path $claudeDir -PathType Container) -or
    ($null -ne (Get-Command claude -ErrorAction SilentlyContinue))

  if (-not $claudeInstalled -and -not $Force) { return "skipped" }

  if (-not (Test-Path $claudeDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null
  }

  $dcgHook = [pscustomobject][ordered]@{ type = "command"; command = $DcgPath }
  Merge-AgentHookFile -HooksFile $settingsFile -DcgHook $dcgHook -DcgPath $DcgPath -Event "PreToolUse" -Matcher "Bash" -Label "Claude settings.json"
}

# Configure Gemini CLI's BeforeTool / run_shell_command hook in
# ~/.gemini/settings.json. Gemini's hook entry carries `name` + `timeout` fields
# in addition to type/command. NOTE: this is ~/.gemini/settings.json — distinct
# from agy's ~/.gemini/config/hooks.json (configured by `dcg install --agy`).
# Returns "created" | "already" | "merged" | "skipped".
function Configure-GeminiHook {
  param([string]$DcgPath, [switch]$Force, [string]$HomeDir = $HOME)

  $geminiDir = Join-Path $HomeDir ".gemini"
  $settingsFile = Join-Path $geminiDir "settings.json"
  $geminiInstalled = (Test-Path $geminiDir -PathType Container) -or
    ($null -ne (Get-Command gemini -ErrorAction SilentlyContinue))

  if (-not $geminiInstalled -and -not $Force) { return "skipped" }

  if (-not (Test-Path $geminiDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $geminiDir | Out-Null
  }

  $dcgHook = [pscustomobject][ordered]@{
    name = "dcg"
    type = "command"
    command = $DcgPath
    timeout = 5000
  }
  Merge-AgentHookFile -HooksFile $settingsFile -DcgHook $dcgHook -DcgPath $DcgPath -Event "BeforeTool" -Matcher "run_shell_command" -Label "Gemini settings.json"
}

# Defend against zip-slip / path traversal BEFORE extracting: reject any entry
# whose path is absolute, has a drive letter, or contains a `..` traversal
# segment, and require the archive to be non-empty and to contain dcg.exe. Throws
# on any violation so a malicious/corrupt archive can never write outside the
# extraction directory or ship without the expected binary.
function Assert-ZipLayoutSafe {
  param([string]$ZipPath)

  Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
  $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
  try {
    $entryCount = 0
    $hasDcg = $false
    foreach ($entry in $zip.Entries) {
      $name = $entry.FullName
      if ([string]::IsNullOrEmpty($name)) { continue }
      $entryCount++

      $normalized = $name -replace '\\', '/'
      if ($normalized.StartsWith('/') -or $normalized.StartsWith('//') -or $normalized -match '^[A-Za-z]:') {
        throw "Refusing to extract: archive entry has an absolute path: '$name'"
      }
      foreach ($seg in ($normalized -split '/')) {
        if ($seg -eq '..') {
          throw "Refusing to extract: archive entry contains a '..' traversal segment: '$name'"
        }
      }
      if ($entry.Name -ieq 'dcg.exe') { $hasDcg = $true }
    }
    if ($entryCount -eq 0) { throw "Refusing to extract: archive is empty" }
    if (-not $hasDcg) { throw "Refusing to extract: archive does not contain dcg.exe" }
  } finally {
    $zip.Dispose()
  }
}

# True when a hook entry's command references the legacy Python predecessor.
function Test-PredecessorHookCommand {
  param([object]$Hook)
  if ($null -eq $Hook) { return $false }
  $prop = $Hook.PSObject.Properties["command"]
  if ($null -eq $prop) { return $false }
  ([string]$prop.Value) -match 'git_safety_guard'
}

# Remove the legacy `git_safety_guard` Python predecessor: strip ONLY its hook
# entries from ~/.claude/settings.json (preserving the modern dcg hook and any
# coexisting hooks) and delete its script under ~/.claude/hooks. Returns $true if
# anything was removed. Safe to call before Configure-ClaudeHook so a migrating
# user never runs both the old and new hooks.
function Remove-DcgPredecessor {
  param([string]$HomeDir = $HOME)

  $removed = $false
  $claudeDir = Join-Path $HomeDir ".claude"
  $settingsFile = Join-Path $claudeDir "settings.json"

  if (Test-Path $settingsFile -PathType Leaf) {
    $config = $null
    try { $config = Get-Content -Raw -Path $settingsFile | ConvertFrom-Json } catch { $config = $null }
    if ($null -ne $config) {
      $hooks = Get-ObjectPropertyValue $config "hooks"
      if ($null -ne $hooks) {
        $newPre = @()
        foreach ($entry in (Get-JsonArray (Get-ObjectPropertyValue $hooks "PreToolUse"))) {
          $entryHooks = Get-JsonArray (Get-ObjectPropertyValue $entry "hooks")
          $kept = @()
          foreach ($h in $entryHooks) {
            if (Test-PredecessorHookCommand $h) { $removed = $true } else { $kept += $h }
          }
          if ($kept.Count -gt 0) {
            Set-ObjectPropertyValue $entry "hooks" $kept
            $newPre += $entry
          } elseif ($entryHooks.Count -eq 0) {
            $newPre += $entry
          }
          # else: every hook in this entry was the predecessor -> drop the entry.
        }
        if ($removed) {
          Set-ObjectPropertyValue $hooks "PreToolUse" $newPre
          Write-JsonFileNoBom -Path $settingsFile -Object $config
        }
      }
    }
  }

  $predScript = Join-Path (Join-Path $claudeDir "hooks") "git_safety_guard.py"
  if (Test-Path $predScript -PathType Leaf) {
    Remove-Item -Force $predScript -ErrorAction SilentlyContinue
    $removed = $true
    $hookDir = Split-Path -Parent $predScript
    if ((Test-Path $hookDir) -and -not (Get-ChildItem -Path $hookDir -Force)) {
      Remove-Item -Force $hookDir -ErrorAction SilentlyContinue
    }
  }

  $removed
}

# Append a guarded check to the user's PowerShell profile that warns, on each new
# session, if the dcg PreToolUse hook has gone missing from ~/.claude/settings.json
# (Claude Code can silently drop it when it rewrites settings). Idempotent
# (marker-guarded). The PowerShell analog of `dcg setup`'s Unix shell-RC check.
# Returns "added" | "already" | "failed".
function Add-DcgProfileCheck {
  param([string]$ProfilePath = $PROFILE.CurrentUserAllHosts)

  $marker = "# dcg: warn if the Claude Code hook was silently removed"
  try {
    if (Test-Path $ProfilePath -PathType Leaf) {
      $content = Get-Content -Raw -Path $ProfilePath
      if ($content -and $content.Contains($marker)) { return "already" }
    } else {
      $dir = Split-Path -Parent $ProfilePath
      if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    }

    # Single-quoted here-string: written verbatim into the profile (no expansion now).
    $block = @'
if ((Get-Command dcg -ErrorAction SilentlyContinue) -and (Test-Path "$HOME\.claude\settings.json")) {
  try {
    $dcgCfg = Get-Content -Raw "$HOME\.claude\settings.json" | ConvertFrom-Json
    $dcgHas = $false
    foreach ($dcgE in @($dcgCfg.hooks.PreToolUse)) {
      foreach ($dcgH in @($dcgE.hooks)) {
        if (((([string]$dcgH.command) -split '[\\/]')[-1]) -replace '\.exe$','' -ieq 'dcg') { $dcgHas = $true }
      }
    }
    if (-not $dcgHas) { Write-Host '[dcg] Hook missing from ~/.claude/settings.json - run: dcg install' -ForegroundColor Yellow }
  } catch { }
}
'@

    Add-Content -Path $ProfilePath -Value ("`n" + $marker + "`n" + $block)
    return "added"
  } catch {
    return "failed"
  }
}

# True when a Copilot platform-field command string invokes dcg.
function Test-DcgPlatformCommand {
  param([object]$Command)
  if ($null -eq $Command) { return $false }
  $s = [string]$Command
  if ([string]::IsNullOrWhiteSpace($s)) { return $false }
  $name = Get-DcgCommandName $s   # last path segment, lowercased
  ($name -eq "dcg") -or ($name -eq "dcg.exe")
}

# Configure GitHub Copilot CLI's user-level hook at
# $COPILOT_HOME/hooks/dcg.json (or ~/.copilot/hooks/dcg.json).
# Copilot hooks are NOT matcher-based: hooks.preToolUse[] entries carry platform-
# keyed `bash` + `powershell` command fields (the `powershell` field is what makes
# this work on Windows). Strips dcg from any existing entry's bash/powershell
# fields (preserving an entry that still has a non-dcg platform field) and prepends
# the canonical dcg entry. -CopilotHome is for tests; production honors the
# documented COPILOT_HOME override and otherwise uses ~/.copilot.
# Returns "created" | "already" | "merged".
function Configure-CopilotHook {
  param([string]$DcgPath, [string]$CopilotHome)

  if ([string]::IsNullOrEmpty($CopilotHome)) {
    if (-not [string]::IsNullOrWhiteSpace($env:COPILOT_HOME)) {
      $CopilotHome = $env:COPILOT_HOME
    } else {
      $CopilotHome = Join-Path $HOME ".copilot"
    }
  }

  $hookDir = Join-Path $CopilotHome "hooks"
  $hookFile = Join-Path $hookDir "dcg.json"
  if (-not (Test-Path $hookDir)) { New-Item -ItemType Directory -Force -Path $hookDir | Out-Null }

  $desired = [pscustomobject][ordered]@{
    type = "command"
    bash = $DcgPath
    powershell = $DcgPath
    cwd = "."
    timeoutSec = 30
  }

  if (-not (Test-Path $hookFile -PathType Leaf)) {
    $config = [pscustomobject][ordered]@{
      version = 1
      hooks = [pscustomobject][ordered]@{ preToolUse = @($desired) }
    }
    Write-JsonFileNoBom -Path $hookFile -Object $config
    return "created"
  }

  $originalJson = Get-Content -Raw -Path $hookFile
  try { $config = $originalJson | ConvertFrom-Json } catch {
    throw "Copilot hook file is invalid JSON; leaving it unchanged: $hookFile"
  }
  if (-not (Test-JsonObject $config)) {
    throw "Copilot hook file must contain a JSON object; leaving it unchanged: $hookFile"
  }

  $hooksExists = Test-ObjectPropertyExists $config "hooks"
  $hooks = Get-ObjectPropertyValue $config "hooks"
  if ($hooksExists -and -not (Test-JsonObject $hooks)) {
    throw "Copilot hook file hooks must contain a JSON object; leaving it unchanged: $hookFile"
  }
  if (-not $hooksExists) {
    $hooks = [pscustomobject][ordered]@{}
    Set-ObjectPropertyValue $config "hooks" $hooks
  }
  $pre = Get-ObjectPropertyValue $hooks "preToolUse"
  if ($null -ne $pre -and -not (Test-JsonArray $pre)) {
    throw "Copilot hook file preToolUse must contain a list; leaving it unchanged: $hookFile"
  }

  $preserved = @()
  foreach ($entry in (Get-JsonArray $pre)) {
    if (-not (Test-JsonObject $entry)) { $preserved += $entry; continue }
    $bashIsDcg = Test-DcgPlatformCommand (Get-ObjectPropertyValue $entry "bash")
    $psIsDcg = Test-DcgPlatformCommand (Get-ObjectPropertyValue $entry "powershell")
    if (-not $bashIsDcg -and -not $psIsDcg) { $preserved += $entry; continue }
    # Rebuild the entry without the dcg-invoking platform field(s).
    $cleaned = [pscustomobject][ordered]@{}
    foreach ($p in $entry.PSObject.Properties) {
      if (($p.Name -eq "bash" -and $bashIsDcg) -or ($p.Name -eq "powershell" -and $psIsDcg)) { continue }
      Set-ObjectPropertyValue $cleaned $p.Name $p.Value
    }
    $stillBash = $null -ne (Get-ObjectPropertyValue $cleaned "bash")
    $stillPs = $null -ne (Get-ObjectPropertyValue $cleaned "powershell")
    if ($stillBash -or $stillPs) { $preserved += $cleaned }
    # else: the entry only carried dcg platform fields -> drop it entirely.
  }

  Set-ObjectPropertyValue $config "version" 1
  Set-ObjectPropertyValue $hooks "preToolUse" (@($desired) + $preserved)

  $newJson = $config | ConvertTo-Json -Depth 20
  $origNorm = ($originalJson | ConvertFrom-Json) | ConvertTo-Json -Depth 20
  if ($newJson -eq $origNorm) { return "already" }

  Write-JsonFileNoBom -Path $hookFile -Object $config
  "merged"
}

function Get-CursorBridgeContent {
  # The PowerShell bridge that Cursor's beforeShellExecution hook invokes. It
  # translates Cursor's {command, cwd} payload into dcg's Bash-hook shape, pipes
  # it to dcg.exe, and maps dcg's permissionDecision back to Cursor's
  # {permission, continue, userMessage, ...} response. Pure PowerShell — no Python
  # bridge (which is fragile on Windows). Fail-open (allow) on any error.
  param([string]$DcgPath)
  $escaped = $DcgPath.Replace("'", "''")
  $header = "# dcg-cursor-hook: generated by dcg installer (pure PowerShell bridge; no interpreter dependency)`n`$DcgBinFallback = '$escaped'`n"
  $body = @'
$ErrorActionPreference = 'SilentlyContinue'
$DcgBin = $env:DCG_BIN
if ([string]::IsNullOrEmpty($DcgBin)) { $DcgBin = $DcgBinFallback }
function Write-CursorOut($o) { [Console]::Out.Write(($o | ConvertTo-Json -Compress)) }
function Send-Allow {
  Write-CursorOut @{ permission = 'allow'; continue = $true; userMessage = ''; agentMessage = ''; user_message = ''; agent_message = '' }
}
function Send-Deny($r) {
  Write-CursorOut @{ permission = 'deny'; continue = $false; userMessage = $r; agentMessage = $r; user_message = $r; agent_message = $r }
}
try { $raw = [Console]::In.ReadToEnd() } catch { Send-Allow; exit 0 }
if ([string]::IsNullOrWhiteSpace($raw)) { Send-Allow; exit 0 }
try { $payload = $raw | ConvertFrom-Json } catch { Send-Allow; exit 0 }
$command = [string]$payload.command
if ([string]::IsNullOrEmpty($command)) { Send-Allow; exit 0 }
if ($payload.cwd) { Set-Location -LiteralPath $payload.cwd -ErrorAction SilentlyContinue }
$hookInput = @{ tool_name = 'Bash'; tool_input = @{ command = $command } } | ConvertTo-Json -Compress
$env:CURSOR_IDE = '1'
try { $out = ($hookInput | & $DcgBin 2>$null | Out-String).Trim() } catch { Send-Allow; exit 0 }
if ([string]::IsNullOrEmpty($out)) { Send-Allow; exit 0 }
try { $dcg = $out | ConvertFrom-Json } catch { Send-Allow; exit 0 }
$decision = $dcg.hookSpecificOutput.permissionDecision
$reason = $dcg.hookSpecificOutput.permissionDecisionReason
if ([string]::IsNullOrEmpty($reason)) { $reason = 'Blocked by dcg' }
if ($decision -eq 'deny') { Send-Deny $reason } else { Send-Allow }
exit 0
'@
  $header + $body
}

function Configure-CursorHook {
  # Configure Cursor IDE: write the PowerShell bridge to
  # ~/.cursor/hooks/dcg-pre-shell.ps1 and merge ~/.cursor/hooks.json so dcg is
  # FIRST in beforeShellExecution[], collapsing duplicate dcg entries and
  # preserving coexisting hooks. Idempotent; UTF-8 no BOM; refuses invalid JSON.
  # Returns skipped | conflict | invalid | created | already | merged.
  param([string]$DcgPath, [string]$HomeDir = $HOME, [switch]$Force)

  $cursorDir = Join-Path $HomeDir ".cursor"
  $detected = (Test-Path $cursorDir -PathType Container) -or
    ($null -ne (Get-Command cursor -ErrorAction SilentlyContinue))
  if (-not $detected -and -not $Force) { return "skipped" }

  $hookDir = Join-Path $cursorDir "hooks"
  $bridge = Join-Path $hookDir "dcg-pre-shell.ps1"
  $hooksFile = Join-Path $cursorDir "hooks.json"
  $marker = "dcg-cursor-hook"

  # Refuse to clobber a pre-existing non-dcg script at the bridge path.
  if ((Test-Path $bridge -PathType Leaf) -and
      -not ((Get-Content -Raw -LiteralPath $bridge) -match $marker)) {
    return "conflict"
  }

  if (-not (Test-Path $hookDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $hookDir | Out-Null
  }
  $bridgeContent = Get-CursorBridgeContent -DcgPath $DcgPath
  [System.IO.File]::WriteAllText($bridge, $bridgeContent, (New-Object System.Text.UTF8Encoding $false))

  # The hooks.json command line that launches the bridge. Windows PowerShell
  # (powershell.exe) is always present; -ExecutionPolicy Bypass lets the unsigned
  # bridge run; -NoProfile keeps it fast and hermetic.
  $hookCmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$bridge`""

  if (-not (Test-Path $hooksFile -PathType Leaf)) {
    $config = [pscustomobject][ordered]@{
      version = 1
      hooks = [pscustomobject][ordered]@{
        beforeShellExecution = @([pscustomobject][ordered]@{ command = $hookCmd })
      }
    }
    Write-JsonFileNoBom -Path $hooksFile -Object $config
    return "created"
  }

  try {
    $config = Get-Content -Raw -LiteralPath $hooksFile | ConvertFrom-Json
  } catch {
    return "invalid"
  }
  if (-not (Test-JsonObject $config)) { return "invalid" }

  $hooks = Get-ObjectPropertyValue $config "hooks"
  if ($null -eq $hooks) { $hooks = [pscustomobject][ordered]@{} }
  if (-not (Test-JsonObject $hooks)) { return "invalid" }

  $entries = Get-JsonArray (Get-ObjectPropertyValue $hooks "beforeShellExecution")
  $isDcg = { param($e) (Test-JsonObject $e) -and ($e.command -eq $hookCmd) }
  $matching = @($entries | Where-Object { & $isDcg $_ })
  $first = if ($entries.Count -gt 0 -and (Test-JsonObject $entries[0])) { $entries[0].command } else { $null }
  if ($matching.Count -eq 1 -and $first -eq $hookCmd) { return "already" }

  $preserved = @($entries | Where-Object { -not (& $isDcg $_) })
  $newEntries = @([pscustomobject][ordered]@{ command = $hookCmd }) + $preserved
  Set-ObjectPropertyValue $config "version" 1
  Set-ObjectPropertyValue $hooks "beforeShellExecution" $newEntries
  Set-ObjectPropertyValue $config "hooks" $hooks
  Write-JsonFileNoBom -Path $hooksFile -Object $config
  "merged"
}

function Get-HermesYamlBlock {
  # Minimal Hermes config.yaml block. dcg first in hooks.pre_tool_call (matcher
  # 'terminal'; Hermes' payload deserializes straight into dcg's HookInput), and
  # hooks_auto_accept so shell hooks register in non-TTY contexts. The path is a
  # single-quoted YAML scalar so Windows backslashes stay literal.
  param([string]$DcgPath)
  $q = $DcgPath.Replace("'", "''")
  @"
hooks_auto_accept: true
hooks:
  pre_tool_call:
    - matcher: terminal
      command: '$q'
      timeout: 30
"@
}

function Test-HermesIsDcgCommand {
  param([string]$Cmd)
  if ([string]::IsNullOrWhiteSpace($Cmd)) { return $false }
  $name = (Get-DcgCommandName $Cmd) -replace '(?i)\.exe$', ''
  $name -ieq "dcg"
}

function Configure-HermesHook {
  # Configure Hermes Agent (~/.hermes/config.yaml, hooks.pre_tool_call[]). Pure
  # PowerShell, no PyYAML. Strategy (never corrupts an existing config):
  #   - no config.yaml yet -> emit a fresh minimal YAML (we own the whole file).
  #   - config exists + powershell-yaml module present -> full-fidelity merge.
  #   - config exists + no module -> 'manual' (caller prints exact instructions);
  #     round-tripping arbitrary YAML in pure PS is too risky to fake.
  # Returns skipped | created | already | merged | manual | invalid.
  param([string]$DcgPath, [string]$HomeDir = $HOME, [switch]$Force)

  $hermesDir = Join-Path $HomeDir ".hermes"
  $detected = (Test-Path $hermesDir -PathType Container) -or
    ($null -ne (Get-Command hermes -ErrorAction SilentlyContinue))
  if (-not $detected -and -not $Force) { return "skipped" }

  $cfgFile = Join-Path $hermesDir "config.yaml"
  if (-not (Test-Path $hermesDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $hermesDir | Out-Null
  }

  if (-not (Test-Path $cfgFile -PathType Leaf)) {
    [System.IO.File]::WriteAllText($cfgFile, (Get-HermesYamlBlock -DcgPath $DcgPath),
      (New-Object System.Text.UTF8Encoding $false))
    return "created"
  }

  # Idempotency WITHOUT the YAML module: a read-only scan for an existing dcg
  # `command:` line. If dcg is already wired in AT THIS path, return "already"
  # rather than re-prompting a manual edit of a config dcg itself wrote (a
  # reinstall no-op). A STALE dcg path (e.g. a reinstall to a different -Dest)
  # is deliberately NOT treated as "already" — it falls through so the user is
  # told to update it, instead of silently leaving a hook on a deleted binary.
  $existingText = Get-Content -Raw -LiteralPath $cfgFile -ErrorAction SilentlyContinue
  if ($existingText) {
    foreach ($line in ($existingText -split "`r?`n")) {
      if ($line -match '^\s*command:\s*(.+?)\s*$') {
        $val = $Matches[1].Trim().Trim('"').Trim("'")
        if ((Test-HermesIsDcgCommand $val) -and ($val -eq $DcgPath)) { return "already" }
      }
    }
  }

  $hasYaml = $null -ne (Get-Module -ListAvailable -Name powershell-yaml -ErrorAction SilentlyContinue)
  if (-not $hasYaml) { return "manual" }

  Import-Module powershell-yaml -ErrorAction Stop
  try { $doc = (Get-Content -Raw -LiteralPath $cfgFile | ConvertFrom-Yaml) } catch { return "invalid" }
  if ($null -eq $doc) { $doc = @{} }
  if ($doc -isnot [System.Collections.IDictionary]) { return "invalid" }

  $hooks = $doc["hooks"]
  if ($null -eq $hooks) { $hooks = @{}; $doc["hooks"] = $hooks }
  if ($hooks -isnot [System.Collections.IDictionary]) { return "invalid" }
  $list = $hooks["pre_tool_call"]
  if ($null -eq $list) { $list = @() }
  if ($list -isnot [System.Collections.IEnumerable] -or $list -is [string]) { return "invalid" }

  $existing = @($list)
  $dcgCmds = @($existing | Where-Object { ($_ -is [System.Collections.IDictionary]) -and (Test-HermesIsDcgCommand $_["command"]) } | ForEach-Object { $_["command"] })
  $firstCmd = if ($existing.Count -gt 0 -and ($existing[0] -is [System.Collections.IDictionary])) { $existing[0]["command"] } else { $null }
  if ($dcgCmds.Count -eq 1 -and $dcgCmds[0] -eq $DcgPath -and $firstCmd -eq $DcgPath -and $doc.Contains("hooks_auto_accept")) {
    return "already"
  }

  $preserved = @($existing | Where-Object { -not (($_ -is [System.Collections.IDictionary]) -and (Test-HermesIsDcgCommand $_["command"])) })
  $dcgEntry = [ordered]@{ matcher = "terminal"; command = $DcgPath; timeout = 30 }
  $hooks["pre_tool_call"] = @($dcgEntry) + $preserved
  if (-not $doc.Contains("hooks_auto_accept")) { $doc["hooks_auto_accept"] = $true }

  $yaml = ConvertTo-Yaml $doc
  [System.IO.File]::WriteAllText($cfgFile, $yaml, (New-Object System.Text.UTF8Encoding $false))
  "merged"
}

function Resolve-LocalSourcePath {
  # If $Source names a local artifact (a `file://` URI or an existing local path,
  # absolute or relative), return its filesystem path; otherwise return $null,
  # meaning "treat as an HTTP(S) URL and fetch over the network". This is what
  # lets -ArtifactUrl/-ChecksumUrl/-SigstoreBundleUrl point at a local file for
  # hermetic, network-free installs and CI smoke tests.
  param([string]$Source)
  if ([string]::IsNullOrWhiteSpace($Source)) { return $null }
  # A URI scheme (http://, https://, file://, ...). A bare Windows path like
  # C:\x or C:/x is NOT a scheme (it has ':\'/':/' not '://'), so it falls through.
  if ($Source -match '^[A-Za-z][A-Za-z0-9+.-]*://') {
    if ($Source -match '^(?i)file://') {
      try { return ([System.Uri]$Source).LocalPath } catch { return $null }
    }
    return $null
  }
  if (Test-Path -LiteralPath $Source -PathType Leaf) {
    return (Resolve-Path -LiteralPath $Source).Path
  }
  return $null
}

function Copy-OrDownloadToFile {
  # Copy a local/`file://` source to $OutFile, or download an HTTP(S) source.
  param([string]$Source, [string]$OutFile)
  $local = Resolve-LocalSourcePath -Source $Source
  if ($local) {
    if (-not (Test-Path -LiteralPath $local -PathType Leaf)) { throw "Local source not found: $local" }
    Copy-Item -LiteralPath $local -Destination $OutFile -Force
  } else {
    Invoke-WebRequest -Uri $Source -OutFile $OutFile -UseBasicParsing
  }
}

function Convert-ContentToText {
  param($Content)
  if ($Content -is [byte[]]) {
    return [System.Text.Encoding]::UTF8.GetString($Content)
  }
  if (($Content -is [System.Array]) -and ($Content.Count -gt 0) -and ($Content[0] -is [byte])) {
    return [System.Text.Encoding]::UTF8.GetString([byte[]]$Content)
  }
  [string]$Content
}

function Read-OrDownloadText {
  # Return the text content of a local/`file://` source, or fetch it over HTTP(S).
  param([string]$Source)
  $local = Resolve-LocalSourcePath -Source $Source
  if ($local) {
    if (-not (Test-Path -LiteralPath $local -PathType Leaf)) { throw "Local source not found: $local" }
    return (Get-Content -LiteralPath $local -Raw)
  }
  return (Convert-ContentToText -Content (Invoke-WebRequest -Uri $Source -UseBasicParsing).Content)
}

function Test-Sha256Token {
  # A SHA-256 hex digest is exactly 64 hex characters — nothing else.
  param([string]$Token)
  ($null -ne $Token) -and ($Token -match '^[0-9a-fA-F]{64}$')
}

function ConvertTo-WindowsTarget {
  # Map a host-architecture string to the Rust target triple. ARM64 -> native
  # aarch64; everything else -> x64 (ARM64 Windows can also run the x64 build under
  # emulation, which is the fallback when no native aarch64 artifact exists).
  param([string]$Arch)
  if ($Arch -match '(?i)arm64|aarch64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
}

function Get-WindowsTarget {
  $arch = $null
  try { $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch { }
  if ([string]::IsNullOrEmpty($arch)) { $arch = $env:PROCESSOR_ARCHITECTURE }
  ConvertTo-WindowsTarget -Arch $arch
}

function Get-PathLeaf {
  # Last path segment, splitting on BOTH separators (so it is correct for URLs,
  # file:// paths, and Windows paths on any platform). Strips a query/fragment.
  param([string]$PathOrUrl)
  $clean = $PathOrUrl -replace '[?#].*$', ''
  @($clean -split '[\\/]' | Where-Object { $_ })[-1]
}

function Get-SiblingUrl {
  # Replace the last path segment of $Url with $Leaf. Handles http(s)/file:// URIs
  # (via UriBuilder) and bare local paths.
  param([string]$Url, [string]$Leaf)
  if ($Url -match '^[A-Za-z][A-Za-z0-9+.-]*://') {
    $b = New-Object System.UriBuilder ([System.Uri]$Url)
    $p = $b.Path
    $idx = $p.LastIndexOf('/')
    $b.Path = if ($idx -ge 0) { $p.Substring(0, $idx + 1) + $Leaf } else { $Leaf }
    return $b.Uri.AbsoluteUri
  }
  $idx = $Url.LastIndexOfAny([char[]]@('\', '/'))
  if ($idx -ge 0) { return $Url.Substring(0, $idx + 1) + $Leaf }
  $Leaf
}

function Resolve-ChecksumToken {
  # Resolve a validated 64-hex SHA-256 for $ArtifactUrl. Order: (1) the per-file
  # `.sha256` (first whitespace token); (2) sibling `SHA256SUMS.txt`; (3) sibling
  # `SHA256SUMS` — parsing `<hash>  [*]<file>` rows and selecting the one whose
  # filename matches the artifact. Every candidate is 64-hex validated; throws if
  # none yields a valid token (so junk content never installs).
  param([string]$ArtifactUrl, [string]$PerFileUrl)

  if ($PerFileUrl) {
    try {
      $tok = @((Read-OrDownloadText -Source $PerFileUrl).Trim() -split '\s+' | Where-Object { $_ })[0]
      if (Test-Sha256Token $tok) { return $tok }
    } catch { }
  }

  $artifactLeaf = Get-PathLeaf $ArtifactUrl
  foreach ($manifest in @('SHA256SUMS.txt', 'SHA256SUMS')) {
    $murl = Get-SiblingUrl -Url $ArtifactUrl -Leaf $manifest
    $text = $null
    try { $text = Read-OrDownloadText -Source $murl } catch { continue }
    foreach ($line in ($text -split "`r?`n")) {
      $l = $line.Trim()
      if (-not $l -or $l.StartsWith('#')) { continue }
      $parts = @($l -split '\s+' | Where-Object { $_ })
      if ($parts.Count -lt 2) { continue }
      $hash = $parts[0]
      $file = ($parts[-1]).TrimStart('*')  # coreutils marks binary mode with '*'
      if ((Test-Sha256Token $hash) -and ((Get-PathLeaf $file) -eq $artifactLeaf)) { return $hash }
    }
  }
  throw "no valid SHA-256 found for $artifactLeaf (per-file .sha256, SHA256SUMS.txt, SHA256SUMS all failed)"
}

function Detect-Agents {
  # Probe for installed coding agents (config dir under $HomeDir, or the agent's
  # CLI on PATH). Returns an [ordered] map of
  # agent display-name -> [bool] detected, in the order we configure them. Used to
  # print a "detected / will configure" summary (install.sh parity) and to decide
  # which optional agents (Grok/agy) to wire via the dcg binary under -EasyMode.
  # RepoRoot is accepted for caller/test parity but intentionally does not make
  # Copilot "detected".
  param([string]$HomeDir = $HOME, [string]$RepoRoot = "")
  $null = $RepoRoot
  function _has([string]$cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
  function _dir([string]$name) { Test-Path (Join-Path $HomeDir $name) -PathType Container }
  [ordered]@{
    'Claude'  = ((_dir '.claude')  -or (_has 'claude'))
    'Codex'   = ((_dir '.codex')   -or (_has 'codex'))
    'Gemini'  = ((_dir '.gemini')  -or (_has 'gemini'))
    'Cursor'  = ((_dir '.cursor')  -or (_has 'cursor'))
    'Copilot' = ((_dir '.copilot') -or
      (-not [string]::IsNullOrWhiteSpace($env:COPILOT_HOME) -and
        (Test-Path $env:COPILOT_HOME -PathType Container)) -or
      (_has 'copilot') -or (_has 'gh-copilot'))
    'Grok'    = ((_dir '.grok')    -or (-not [string]::IsNullOrEmpty($env:GROK_SESSION_ID)))
    'Agy'     = (_has 'agy')
    'Hermes'  = (_dir '.hermes')
  }
}

function Get-DetectedAgentNames {
  # The display-names of agents Detect-Agents flagged as present, in order.
  param($Agents)
  @($Agents.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
}

# Testing entrypoint: when dot-sourced with -LoadFunctionsOnly, stop here so the
# functions above are available without running the install body below.
if ($LoadFunctionsOnly) { return }

if ($Help) {
  Write-Host @'
dcg PowerShell installer

Usage:
  irm https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.ps1 | iex
  & ([scriptblock]::Create((irm "<install.ps1 URL>"))) -EasyMode -Verify

Options:
  -Version vX.Y.Z   Install a specific version (default: latest GitHub release)
  -Dest DIR         Install to DIR (default: ~/.local/bin)
  -EasyMode         Add the install dir to PATH and force agent configuration
  -Verify           Run a self-test after install
  -Force            Configure agent hooks even if the agent CLI isn't detected
  -NoConfigure      Install the binary only; skip all agent hook configuration
  -Quiet            Suppress informational output (keep warnings/errors/success)
  -Help             Print this help and exit

Configured agents (when detected, or with -Force/-EasyMode):
  Claude Code  (~/.claude/settings.json)      Codex CLI   (~/.codex/hooks.json)
  Gemini CLI   (~/.gemini/settings.json)      Copilot CLI (~/.copilot/hooks/dcg.json)
  Cursor IDE   (~/.cursor/hooks.json)         Hermes      (~/.hermes/config.yaml)
  Grok / agy   via dcg install --grok / --agy under -EasyMode when detected
'@
  exit 0
}

# -Force is the per-agent analog of -EasyMode's config-forcing; OR them together
# so callers can force agent (re)configuration without also touching PATH.
$forceConfig = $EasyMode -or $Force

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
$target = Get-WindowsTarget
$zip = "dcg-$target.zip"
Write-Info "Host architecture target: $target"

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

# Wrap download/verify/extract/install in try/finally so the temp directory is
# ALWAYS removed — including the `exit 1` failure paths (PowerShell runs `finally`
# on `exit`), not just on success. (Body left at its original indentation to keep
# the diff minimal.)
try {
$zipFile = Join-Path $tmp $zip

if (Resolve-LocalSourcePath -Source $url) {
  Write-Info "Using local artifact $url"
} else {
  Write-Info "Downloading $url"
}
try {
  Copy-OrDownloadToFile -Source $url -OutFile $zipFile
} catch {
  # ARM64 emulation fallback: if a native aarch64 artifact isn't published (e.g.
  # this release predates ARM64 builds), retry with the x64 build, which runs on
  # Windows-on-ARM under emulation. Only when we auto-derived the URL (no override).
  if ($target -eq "aarch64-pc-windows-msvc" -and -not $ArtifactUrl) {
    Write-Warn "No native ARM64 artifact found; falling back to the x64 build (runs under emulation)."
    $target = "x86_64-pc-windows-msvc"
    $zip = "dcg-$target.zip"
    $url = "https://github.com/$Owner/$Repo/releases/download/$Version/$zip"
    # The checksum / sigstore URLs are derived from $url below, so they now point
    # at the x64 artifact automatically (unless the user passed explicit overrides).
    try {
      Copy-OrDownloadToFile -Source $url -OutFile $zipFile
    } catch {
      Write-Err "Failed to obtain artifact (ARM64 and x64 fallback both failed): $_"
      exit 1
    }
  } else {
    Write-Err "Failed to obtain artifact: $_"
    exit 1
  }
}

# Verify checksum
$checksumToUse = $Checksum
if (-not $checksumToUse) {
  $perFile = if ($ChecksumUrl) { $ChecksumUrl } else { "$url.sha256" }
  Write-Info "Resolving checksum (per-file .sha256, then SHA256SUMS.txt / SHA256SUMS)"
  try {
    $checksumToUse = Resolve-ChecksumToken -ArtifactUrl $url -PerFileUrl $perFile
  } catch {
    Write-Err "No valid SHA-256 checksum found; refusing to install. ($_)"
    exit 1
  }
} elseif (-not (Test-Sha256Token $checksumToUse)) {
  Write-Err "Provided -Checksum is not a valid 64-hex SHA-256; refusing to install."
  exit 1
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
    Copy-OrDownloadToFile -Source $SigstoreBundleUrl -OutFile $bundleFile
  } catch {
    Write-Warn "Sigstore bundle not found; skipping signature verification"
    $bundleFile = $null
  }
  if ($bundleFile) {
    # --new-bundle-format: the release ships the modern Sigstore protobuf
    # bundle (v0.3, cert under verificationMaterial.certificate) produced by
    # cosign v3.x in dist.yml. cosign can only parse that --bundle shape when
    # --new-bundle-format is passed; the flag was introduced in cosign v2.4.0
    # (sigstore/cosign#3796). An older cosign on PATH dies with
    # "unknown flag: --new-bundle-format" (exit 1) and cannot verify a v0.3
    # bundle at all even without the flag (it would fall back to the legacy
    # shape and fail with "bundle does not contain cert for verification,
    # please provide public key" -- issue #140).
    #
    # Signature verification is best-effort (the SHA256 checksum is already
    # verified and required above; the cosign-not-found and bundle-not-found
    # branches warn-and-skip rather than abort). So probe whether this cosign
    # supports the flag: if not, warn and skip instead of aborting the install
    # on an honest old client. A cosign that supports the flag is the only one
    # that can meaningfully verify the bundle, and for it a non-zero exit is a
    # real verification failure we still abort on.
    $cosignHelp = (& cosign verify-blob --help 2>&1 | Out-String)
    if ($cosignHelp -notmatch '--new-bundle-format') {
      Write-Warn "cosign is too old to verify the modern Sigstore bundle (needs >= 2.4.0 for --new-bundle-format); skipping signature verification (checksum already verified)"
    } else {
      & cosign verify-blob --new-bundle-format --bundle $bundleFile --certificate-identity-regexp $CosignIdentityRegex --certificate-oidc-issuer $CosignOidcIssuer $zipFile | Out-Null
      if ($LASTEXITCODE -ne 0) {
        Write-Err "Signature verification failed"
        exit 1
      }
      Write-Ok "Signature verified (cosign)"
    }
  }
} else {
  Write-Warn "cosign not found; skipping signature verification (install cosign for stronger authenticity checks)"
}

# Extract
Write-Info "Extracting..."
Assert-ZipLayoutSafe -ZipPath $zipFile
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
$installedExe = Join-Path $Dest "dcg.exe"
Copy-Item $bin.FullName $installedExe -Force
# Strip Mark-of-the-Web (Zone.Identifier) so the freshly-installed binary does not
# trip SmartScreen / "publisher could not be verified". Done only AFTER the
# checksum + cosign verification above, so an unverified binary is never unblocked.
# Wrapped in try/catch because Unblock-File is present-but-unsupported on non-Windows
# PowerShell (it throws "does not support Linux", which -ErrorAction can't suppress);
# on Windows it works normally. Keeps the installer body hermetically testable.
if (Get-Command Unblock-File -ErrorAction SilentlyContinue) {
  try { Unblock-File -Path $installedExe -ErrorAction SilentlyContinue } catch { }
}
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
    # The persisted User PATH (via SetEnvironmentVariable, which also broadcasts
    # WM_SETTINGCHANGE to new processes) only affects NEW shells. Also update THIS
    # session's PATH so `dcg` resolves immediately without opening a new terminal.
    if (-not (Test-UserPathContains -PathValue $env:PATH -PathToFind $Dest)) {
      $env:PATH = "$env:PATH;$Dest"
    }
    Write-Ok "Added $Dest to PATH (User) - available now in this window; other open terminals need a restart"
  } else {
    Write-Warn "Add $Dest to PATH to use dcg"
  }
}

}
finally {
  # Always clean up the temp dir (success, throw, or exit).
  if ($tmp -and (Test-Path $tmp)) {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

# Verify
if ($Verify) {
  Write-Info "Running self-test..."
  $testInput = '{"tool_name":"Bash","tool_input":{"command":"git status"}}'
  $result = $testInput | & "$Dest\dcg.exe"
  Write-Ok "Self-test complete"
}

Write-Ok "Done. Binary at: $Dest\dcg.exe"
Write-Host ""

$dcgExe = Join-Path $Dest "dcg.exe"

# Detect installed agents and print a concise summary (install.sh parity).
$detectedAgents = Detect-Agents
$detectedNames = Get-DetectedAgentNames $detectedAgents
if ($detectedNames.Count -gt 0) {
  Write-Info ("Detected agents: " + ($detectedNames -join ', '))
} else {
  Write-Info "No coding agents detected; will configure any that appear under standard paths."
}

# -NoConfigure: the binary is installed (and, under -EasyMode, on PATH); skip ALL
# agent hook auto-configuration. Mirrors the install.sh --no-configure contract.
if ($NoConfigure) {
  Write-Info "Skipping agent hook auto-configuration (-NoConfigure)."
  Write-Info "Configure manually later, or re-run without -NoConfigure."
  return
}

# Remove the legacy git_safety_guard Python predecessor (settings entry + script)
# before configuring Claude, so a migrating user never runs both hooks.
try {
  if (Remove-DcgPredecessor) {
    Write-Ok "Removed legacy git_safety_guard predecessor from Claude Code"
  }
} catch {
  Write-Warn "Could not remove legacy predecessor: $_"
}

# Configure Claude Code by merging into ~/.claude/settings.json. Under -EasyMode,
# force-configure even if ~/.claude does not exist yet; otherwise only when Claude
# Code is detected.
try {
  $claudeStatus = Configure-ClaudeHook -DcgPath $dcgExe -Force:$forceConfig
  switch ($claudeStatus) {
    "created" { Write-Ok "Created Claude Code hook at $HOME\.claude\settings.json" }
    "merged" { Write-Ok "Added Claude Code hook to $HOME\.claude\settings.json" }
    "already" { Write-Ok "Claude Code hook already configured" }
    "skipped" { Write-Info "Claude Code not detected; re-run with -EasyMode to configure it anyway" }
    default { Write-Warn "Claude Code hook status: $claudeStatus" }
  }
} catch {
  Write-Warn "Claude Code auto-configuration failed: $_"
}

Write-Host ""
try {
  $codexStatus = Configure-CodexHook -DcgPath $dcgExe
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

Write-Host ""
try {
  $geminiStatus = Configure-GeminiHook -DcgPath $dcgExe -Force:$forceConfig
  switch ($geminiStatus) {
    "created" { Write-Ok "Created Gemini CLI hook at $HOME\.gemini\settings.json" }
    "merged" { Write-Ok "Added Gemini CLI hook to $HOME\.gemini\settings.json" }
    "already" { Write-Ok "Gemini CLI hook already configured" }
    "skipped" { Write-Info "Gemini CLI not detected; re-run with -EasyMode to configure it anyway" }
    default { Write-Warn "Gemini CLI hook status: $geminiStatus" }
  }
} catch {
  Write-Warn "Gemini CLI auto-configuration failed: $_"
}

# Configure GitHub Copilot CLI's user-level hook. This protects every workspace
# and honors COPILOT_HOME when set (#182).
if ($detectedAgents['Copilot'] -or $forceConfig) {
  Write-Host ""
  try {
    $copilotStatus = Configure-CopilotHook -DcgPath $dcgExe
    switch ($copilotStatus) {
      "created" { Write-Ok "Created user-level GitHub Copilot CLI hook" }
      "merged" { Write-Ok "Added user-level GitHub Copilot CLI hook" }
      "already" { Write-Ok "User-level GitHub Copilot CLI hook already configured" }
      default { Write-Warn "GitHub Copilot CLI hook status: $copilotStatus" }
    }
  } catch {
    Write-Warn "GitHub Copilot CLI auto-configuration failed: $_"
  }
} else {
  Write-Info "GitHub Copilot CLI not detected; re-run with -EasyMode to configure its user-level hook anyway"
}

# Configure Cursor IDE (~/.cursor/hooks.json + a PowerShell bridge) when detected
# (or always under -EasyMode). No Python dependency.
if ($detectedAgents['Cursor'] -or $forceConfig) {
  Write-Host ""
  try {
    switch (Configure-CursorHook -DcgPath $dcgExe -Force:$forceConfig) {
      "created" { Write-Ok "Created Cursor IDE hook at $HOME\.cursor\hooks.json (PowerShell bridge)" }
      "merged" { Write-Ok "Added Cursor IDE hook to $HOME\.cursor\hooks.json (PowerShell bridge)" }
      "already" { Write-Ok "Cursor IDE hook already configured" }
      "conflict" { Write-Warn "A non-dcg script already occupies ~/.cursor/hooks/dcg-pre-shell.ps1; left unchanged" }
      "invalid" { Write-Warn "Cursor hooks.json is invalid JSON; left unchanged" }
      "skipped" { Write-Info "Cursor not detected; re-run with -EasyMode to configure it anyway" }
      default { Write-Warn "Cursor IDE hook status unknown" }
    }
  } catch {
    Write-Warn "Cursor IDE auto-configuration failed: $_"
  }
}

# Configure Hermes Agent (~/.hermes/config.yaml) when detected (or -EasyMode).
# Pure-PowerShell; never corrupts an existing config (prints manual steps instead).
if ($detectedAgents['Hermes'] -or $forceConfig) {
  Write-Host ""
  try {
    switch (Configure-HermesHook -DcgPath $dcgExe -Force:$forceConfig) {
      "created" { Write-Ok "Created Hermes hook at $HOME\.hermes\config.yaml" }
      "merged" { Write-Ok "Added Hermes hook to $HOME\.hermes\config.yaml" }
      "already" { Write-Ok "Hermes hook already configured" }
      "invalid" { Write-Warn "Hermes config.yaml is invalid YAML; left unchanged" }
      "skipped" { Write-Info "Hermes not detected; re-run with -EasyMode to configure it anyway" }
      "manual" {
        Write-Warn "Hermes config.yaml exists and the powershell-yaml module is not installed."
        Write-Info "To avoid corrupting it, add this to $HOME\.hermes\config.yaml manually:"
        Write-Host (Get-HermesYamlBlock -DcgPath $dcgExe)
        Write-Info "(Or install the YAML module first:  Install-Module powershell-yaml -Scope CurrentUser  then re-run.)"
      }
      default { Write-Warn "Hermes hook status unknown" }
    }
  } catch {
    Write-Warn "Hermes auto-configuration failed: $_"
  }
}

# Grok (xAI) and Antigravity (agy): configured via the dcg binary itself rather
# than hand-rolled JSON. `dcg install --grok` / `--agy` are pure-Rust and use
# current_exe(), so they produce the correct hook on Windows and stay the single
# source of truth for those hook shapes. This is an intentional Windows
# enhancement beyond install.sh (which does not configure Grok/agy); only when
# the agent is detected and under -EasyMode.
if ($EasyMode -and $detectedAgents['Grok']) {
  Write-Host ""
  try {
    & $dcgExe install --grok | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "Configured Grok (xAI) hook via 'dcg install --grok'" }
    else { Write-Warn "'dcg install --grok' exited with code $LASTEXITCODE" }
  } catch {
    Write-Warn "Grok hook configuration failed: $_"
  }
}
if ($EasyMode -and $detectedAgents['Agy']) {
  try {
    & $dcgExe install --agy | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "Configured Antigravity (agy) hook via 'dcg install --agy'" }
    else { Write-Warn "'dcg install --agy' exited with code $LASTEXITCODE" }
  } catch {
    Write-Warn "Antigravity (agy) hook configuration failed: $_"
  }
}

# Under -EasyMode, add a PowerShell-profile startup check that warns if Claude
# Code ever silently drops the dcg hook (the PS analog of `dcg setup`).
if ($EasyMode) {
  try {
    switch (Add-DcgProfileCheck) {
      "added" { Write-Ok "Added a PowerShell `$PROFILE check that warns if the Claude hook goes missing" }
      "already" { Write-Info "PowerShell `$PROFILE hook-check already present" }
      default { Write-Warn "Could not add the PowerShell `$PROFILE hook-check" }
    }
  } catch {
    Write-Warn "PowerShell profile check setup failed: $_"
  }
}
