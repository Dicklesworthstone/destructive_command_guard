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
#   -RequireMinisign  Require a valid release .minisig and the minisign tool
#   -MinisignSignatureUrl <url|file://> Override the adjacent .minisig source
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
  [string]$MinisignSignatureUrl = "",
  [switch]$RequireMinisign,
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

# Embedded release trust roots. New releases use the DSR-managed key. The
# retired key remains valid only for v0.6.7, the sole historical release whose
# installable archives were signed with it.
$script:DcgMinisignPublicKey = "RWSoYi6NXJWzaRs1mJmOwwXrZfPWcq6MXnQlNMLBYKzlIQTLwuVQG6uO"
$script:DcgMinisignKeyId = "69B3955C8D2E62A8"
$script:DcgLegacyMinisignPublicKey = "RWTQoKUb0Ue4NsqTpPWnABCrIU0+m25zsMlbv6UcRClQ7jmRP3A7NmTB"
$script:DcgLegacyMinisignKeyId = "36B847D11BA5A0D0"
# Pinned self-managed cosign key for DSR/manual releases. GitHub Actions OIDC
# remains a separately accepted trust path for workflow-built releases.
$script:DcgCosignReleasePublicKey = @"
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExiRXKgfQ5rG9l5Bxd4CEefEwmhxA
5QzBI7X6X3RC4HWHwk5hRC9eVUkC8JEqV1eYxY5G3rHaxDs3yJ01IjUY5g==
-----END PUBLIC KEY-----
"@

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

# Windows Defender Application Control/AppLocker can force Windows PowerShell
# into ConstrainedLanguage mode.  Cmdlets and core primitive types still work,
# but arbitrary .NET constructors/method calls do not.  Keep installer I/O on
# cmdlets in that mode while preserving strict UTF-8-without-BOM JSON/YAML.
function ConvertTo-Utf8NoBomBytes {
  param([string]$Text)

  [byte[]]$bytes = @(
    for ($i = 0; $i -lt $Text.Length; $i++) {
      $codePoint = [int][char]$Text[$i]
      if ($codePoint -ge 0xD800 -and $codePoint -le 0xDBFF) {
        if (($i + 1) -ge $Text.Length) { throw "Invalid UTF-16: unpaired high surrogate" }
        $low = [int][char]$Text[$i + 1]
        if ($low -lt 0xDC00 -or $low -gt 0xDFFF) { throw "Invalid UTF-16: unpaired high surrogate" }
        $codePoint = 0x10000 + (($codePoint - 0xD800) * 0x400) + ($low - 0xDC00)
        $i++
      } elseif ($codePoint -ge 0xDC00 -and $codePoint -le 0xDFFF) {
        throw "Invalid UTF-16: unpaired low surrogate"
      }

      if ($codePoint -le 0x7F) {
        [byte]$codePoint
      } elseif ($codePoint -le 0x7FF) {
        [byte](0xC0 -bor ($codePoint -shr 6))
        [byte](0x80 -bor ($codePoint -band 0x3F))
      } elseif ($codePoint -le 0xFFFF) {
        [byte](0xE0 -bor ($codePoint -shr 12))
        [byte](0x80 -bor (($codePoint -shr 6) -band 0x3F))
        [byte](0x80 -bor ($codePoint -band 0x3F))
      } else {
        [byte](0xF0 -bor ($codePoint -shr 18))
        [byte](0x80 -bor (($codePoint -shr 12) -band 0x3F))
        [byte](0x80 -bor (($codePoint -shr 6) -band 0x3F))
        [byte](0x80 -bor ($codePoint -band 0x3F))
      }
    }
  )
  return ,$bytes
}

function Write-Utf8NoBomText {
  param([string]$Path, [string]$Text)

  if ($PSVersionTable.PSVersion.Major -ge 6) {
    Set-Content -LiteralPath $Path -Value $Text -Encoding utf8NoBOM -NoNewline
    return
  }
  if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
    [byte[]]$bytes = ConvertTo-Utf8NoBomBytes -Text $Text
    Set-Content -LiteralPath $Path -Value $bytes -Encoding Byte
    return
  }
  [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding $false))
}

function Get-DcgFileSha256 {
  param([string]$Path)

  try {
    $token = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    if (Test-Sha256Token $token) { return $token.ToLowerInvariant() }
  } catch { }

  # Get-FileHash currently instantiates SHA256CryptoServiceProvider and is
  # rejected by WDAC ConstrainedLanguage. certutil.exe is a signed Windows
  # inbox binary and remains usable under that policy.
  $lines = @(& certutil.exe -hashfile $Path SHA256 2>&1)
  if ($LASTEXITCODE -eq 0) {
    foreach ($line in $lines) {
      $token = ([string]$line).Trim()
      if (Test-Sha256Token $token) { return $token.ToLowerInvariant() }
    }
  }
  throw "Unable to compute SHA-256 for $Path with Get-FileHash or certutil.exe"
}

function Get-DcgTempRoot {
  foreach ($candidate in @($env:TEMP, $env:TMP)) {
    if (-not [string]::IsNullOrWhiteSpace($candidate)) { return $candidate }
  }
  throw "TEMP and TMP are unset; cannot create a private installer directory"
}

function Get-DcgUserPath {
  try { return [Environment]::GetEnvironmentVariable("PATH", "User") } catch { }
  try { return [string](Get-ItemPropertyValue -LiteralPath "HKCU:\Environment" -Name Path -ErrorAction Stop) } catch { return "" }
}

function Set-DcgUserPath {
  param([string]$Value)

  try {
    [Environment]::SetEnvironmentVariable("PATH", $Value, "User")
    return
  } catch { }
  if (-not (Test-Path -LiteralPath "HKCU:\Environment")) {
    New-Item -Path "HKCU:\Environment" -Force | Out-Null
  }
  New-ItemProperty -LiteralPath "HKCU:\Environment" -Name Path -Value $Value -PropertyType ExpandString -Force | Out-Null
}

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

# Generic: true when the config already has exactly one dcg hook anywhere under
# the given $Event, installed under $Matcher, equal to $DcgHook, and first.
# $OwnedMatchers identifies legacy matcher entries whose malformed hook arrays
# must be rejected during migrations.
function Test-HookMatchesDesired {
  param([object]$Actual, [object]$Desired)

  if (-not (Test-JsonObject $Actual) -or -not (Test-JsonObject $Desired)) { return $false }
  if (@($Actual.PSObject.Properties).Count -ne @($Desired.PSObject.Properties).Count) {
    return $false
  }
  foreach ($prop in $Desired.PSObject.Properties) {
    $actualProp = $Actual.PSObject.Properties[$prop.Name]
    if ($null -eq $actualProp -or $actualProp.Value -ne $prop.Value) {
      return $false
    }
  }
  $true
}

function Test-AgentHookCurrent {
  param(
    [object]$Config,
    [object]$DcgHook,
    [string]$Event,
    [string]$Matcher,
    [string[]]$OwnedMatchers = @($Matcher)
  )

  $hooks = Get-ObjectPropertyValue $Config "hooks"
  if ($null -eq $hooks) { return $false }

  $eventValue = Get-ObjectPropertyValue $hooks $Event
  if (-not (Test-JsonArray $eventValue)) { return $false }
  $entries = @(Get-JsonArray $eventValue)
  if ($entries.Count -eq 0) { return $false }

  $dcgHooks = @()
  foreach ($entry in $entries) {
    $entryMatcher = Get-ObjectPropertyValue $entry "matcher"
    $entryHooksValue = Get-ObjectPropertyValue $entry "hooks"
    if (-not (Test-JsonArray $entryHooksValue)) {
      if ($entryMatcher -in $OwnedMatchers) { return $false }
      continue
    }
    $entryHooks = @(Get-JsonArray $entryHooksValue)
    foreach ($hook in $entryHooks) {
      if (Test-DcgHookCommand $hook) {
        $dcgHooks += $hook
      }
    }
  }

  $firstEntry = $entries[0]
  $firstEntryHooksValue = Get-ObjectPropertyValue $firstEntry "hooks"
  if (-not (Test-JsonArray $firstEntryHooksValue)) { return $false }
  $firstEntryHooks = @(Get-JsonArray $firstEntryHooksValue)
  $dcgHooks.Count -eq 1 -and
    (Get-ObjectPropertyValue $firstEntry "matcher") -eq $Matcher -and
    $firstEntryHooks.Count -gt 0 -and
    (Test-HookMatchesDesired $firstEntryHooks[0] $DcgHook)
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
  Write-Utf8NoBomText -Path $tmp -Text $json
  Move-Item -Force -Path $tmp -Destination $Path
}

# Shared create-or-merge for a Claude-Code-style hooks file. Ensures
# `hooks.<Event>` has an entry with `matcher: <Matcher>` containing exactly one
# dcg hook ($DcgHook), hoisted first, with any other hooks/entries preserved.
# Stale dcg hooks are removed from every matcher entry so an earlier
# misinstallation cannot leave an executable but ineffective duplicate.
# $OwnedMatchers identifies legacy matcher values whose malformed hook arrays
# must be rejected. Coexisting hooks are never widened. Idempotent. Refuses to
# touch invalid JSON / malformed owned shapes (throws with $Label).
# Returns "created" | "already" | "merged".
function Merge-AgentHookFile {
  param(
    [string]$HooksFile,
    [object]$DcgHook,
    [string]$Event,
    [string]$Matcher,
    [string]$Label,
    [string[]]$OwnedMatchers = @($Matcher)
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

  if (Test-AgentHookCurrent $config $DcgHook $Event $Matcher $OwnedMatchers) {
    return "already"
  }

  if (-not $hooksExists) {
    $hooks = [pscustomobject][ordered]@{}
    Set-ObjectPropertyValue $config "hooks" $hooks
  }

  $canonicalEntry = $null
  $newEventEntries = @()

  foreach ($entry in (Get-JsonArray (Get-ObjectPropertyValue $hooks $Event))) {
    $entryMatcher = Get-ObjectPropertyValue $entry "matcher"
    if ($entryMatcher -eq $Matcher) {
      $entryHooks = Get-ObjectPropertyValue $entry "hooks"
      if ($null -ne $entryHooks -and -not (Test-JsonArray $entryHooks)) {
        throw "$Label $Matcher matcher hooks must contain a list; leaving it unchanged: $HooksFile"
      }
      $filtered = @()
      foreach ($hook in (Get-JsonArray $entryHooks)) {
        if (-not (Test-DcgHookCommand $hook)) {
          $filtered += $hook
        }
      }
      if ($null -eq $canonicalEntry) {
        $canonicalEntry = $entry
        Set-ObjectPropertyValue $canonicalEntry "hooks" $filtered
      } elseif ($filtered.Count -gt 0 -or (Get-JsonArray $entryHooks).Count -eq 0) {
        Set-ObjectPropertyValue $entry "hooks" $filtered
        $newEventEntries += $entry
      }
    } else {
      $entryHooks = Get-ObjectPropertyValue $entry "hooks"
      if ($null -eq $entryHooks) {
        $newEventEntries += $entry
        continue
      }
      if (-not (Test-JsonArray $entryHooks)) {
        if ($entryMatcher -in $OwnedMatchers) {
          throw "$Label $entryMatcher matcher hooks must contain a list; leaving it unchanged: $HooksFile"
        }
        $newEventEntries += $entry
        continue
      }
      $filtered = @()
      $removedDcg = $false
      foreach ($hook in (Get-JsonArray $entryHooks)) {
        if (Test-DcgHookCommand $hook) {
          $removedDcg = $true
        } else {
          $filtered += $hook
        }
      }
      if (-not $removedDcg -or $filtered.Count -gt 0) {
        if ($removedDcg) {
          Set-ObjectPropertyValue $entry "hooks" $filtered
        }
        $newEventEntries += $entry
      }
    }
  }

  if ($null -eq $canonicalEntry) {
    $canonicalEntry = [pscustomobject][ordered]@{
      matcher = $Matcher
      hooks = @()
    }
  }
  $canonicalHooks = @($DcgHook) + @(Get-JsonArray (Get-ObjectPropertyValue $canonicalEntry "hooks"))
  Set-ObjectPropertyValue $canonicalEntry "hooks" $canonicalHooks
  $newEventEntries = @($canonicalEntry) + $newEventEntries

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
  Merge-AgentHookFile -HooksFile $hooksFile -DcgHook $dcgHook -Event "PreToolUse" -Matcher "Bash" -Label "Codex hooks.json"
}

# Configure Claude Code's PreToolUse hook for both native shell tools in
# ~/.claude/settings.json. The hook itself runs in PowerShell so an absolute
# Windows path is not reinterpreted by Git Bash (#232).
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

  $escapedDcgPath = $DcgPath.Replace("'", "''")
  $dcgHook = [pscustomobject][ordered]@{
    type = "command"
    command = "& '$escapedDcgPath'"
    shell = "powershell"
  }
  Merge-AgentHookFile -HooksFile $settingsFile -DcgHook $dcgHook -Event "PreToolUse" -Matcher "Bash|PowerShell" -Label "Claude settings.json" -OwnedMatchers @("Bash", "Bash|PowerShell")
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
  Merge-AgentHookFile -HooksFile $settingsFile -DcgHook $dcgHook -Event "BeforeTool" -Matcher "run_shell_command" -Label "Gemini settings.json"
}

# Defend against zip-slip, ambiguous layouts, and non-file entries BEFORE
# extracting. A release ZIP has one valid shape: exactly one root-level regular
# Resolve the tar to use for archive inspection/extraction. Prefer the
# trusted Windows inbox bsdtar (System32) explicitly: PATH-first resolution
# can select an MSYS/Git-for-Windows tar whose colon handling treats
# "C:\..." as a remote host ("Cannot connect to C:") and which is not the
# trusted binary this guard intends. Fall back to PATH only when the inbox
# copy is absent (non-Windows test hosts).
function Get-TrustedTarCommand {
  if ($env:SystemRoot) {
    $inboxTar = Join-Path $env:SystemRoot "System32\tar.exe"
    if (Test-Path -LiteralPath $inboxTar) {
      return @(Get-Command $inboxTar -CommandType Application -ErrorAction SilentlyContinue)[0]
    }
  }
  return @(Get-Command tar.exe -CommandType Application -ErrorAction SilentlyContinue)[0]
}

# file named `dcg.exe`. Rejecting nested and extra members also makes the later
# install path deterministic instead of searching attacker-controlled trees.
function Assert-ZipLayoutSafe {
  param([string]$ZipPath)

  $tar = Get-TrustedTarCommand
  if ($null -eq $tar) {
    if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
      throw "Refusing to extract: trusted Windows tar.exe is unavailable"
    }
    # Non-Windows test/development hosts do not have the Windows inbox bsdtar.
    # Retain the full-language .NET inspection path there; WDAC never reaches
    # this branch because supported Windows 10/11 hosts ship tar.exe.
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
      $entries = @($archive.Entries)
      if ($entries.Count -ne 1) {
        throw "Refusing to extract: release archive must contain exactly one member"
      }
      $entryName = [string]$entries[0].FullName
      $attributes = [int]$entries[0].ExternalAttributes
      $unixType = (($attributes -shr 16) -band 0xF000)
      $isDirectory = (($attributes -band 0x10) -ne 0) -or $entryName.EndsWith('/') -or $entryName.EndsWith('\')
      $isRegular = (-not $isDirectory) -and (($unixType -eq 0) -or ($unixType -eq 0x8000))
    } finally {
      $archive.Dispose()
    }
  } else {
    $entries = @(& $tar.Source -tf $ZipPath 2>&1)
    if ($LASTEXITCODE -ne 0) {
      throw "Refusing to extract: tar.exe could not inspect the archive"
    }
    $entries = @($entries | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($entries.Count -ne 1) {
      throw "Refusing to extract: release archive must contain exactly one member"
    }
    $entryName = [string]$entries[0]
    $details = @(& $tar.Source -tvf $ZipPath 2>&1)
    if ($LASTEXITCODE -ne 0 -or $details.Count -ne 1) {
      throw "Refusing to extract: tar.exe could not inspect the archive member type"
    }
    $isRegular = ([string]$details[0]).TrimStart().StartsWith('-')
  }

  $normalized = $entryName -replace '\\', '/'
  if ($normalized -cne 'dcg.exe') {
    throw "Refusing to extract: sole archive member must be the root-level file 'dcg.exe'"
  }
  if (-not $isRegular) {
    throw "Refusing to extract: archive member 'dcg.exe' is not a regular file"
  }
}

function Expand-DcgArchive {
  param([string]$ZipPath, [string]$DestinationPath)

  if ($ExecutionContext.SessionState.LanguageMode -ne "ConstrainedLanguage") {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $DestinationPath -Force
    return
  }

  $tar = Get-TrustedTarCommand
  if ($null -eq $tar) {
    throw "Cannot extract under ConstrainedLanguage: trusted Windows tar.exe is unavailable"
  }
  New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
  & $tar.Source -xf $ZipPath -C $DestinationPath
  if ($LASTEXITCODE -ne 0) {
    throw "tar.exe failed to extract the verified archive"
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

# The startup-check block written into PowerShell profiles. Single-quoted
# here-string: written verbatim into the profile (no expansion at install time).
# Detection must accept every command shape the installers write: bare `dcg`,
# an absolute Unix or Windows path, and the PowerShell quoted-invocation form
# `& 'C:\...\dcg.exe' [args]` (issue #282: naively splitting that on [\\/]
# leaves a trailing quote + args, so the hook looked missing every session).
$script:DcgProfileCheckMarker = "# dcg: warn if the Claude Code hook was silently removed"
$script:DcgProfileCheckBlock = @'
if ((Get-Command dcg -ErrorAction SilentlyContinue) -and (Test-Path "$HOME\.claude\settings.json")) {
  try {
    $dcgCfg = Get-Content -Raw "$HOME\.claude\settings.json" | ConvertFrom-Json
    $dcgHas = $false
    foreach ($dcgE in @($dcgCfg.hooks.PreToolUse)) {
      foreach ($dcgH in @($dcgE.hooks)) {
        $dcgCmd = ([string]$dcgH.command).Trim()
        if ($dcgCmd -match '^&\s*[''"](.+?)[''"]') { $dcgExe = $Matches[1] }
        else { $dcgExe = (($dcgCmd -split '\s+')[0]).Trim('"').Trim("'") }
        if ((($dcgExe -split '[\\/]')[-1]) -replace '\.exe$','' -ieq 'dcg') { $dcgHas = $true }
      }
    }
    if (-not $dcgHas) { Write-Host '[dcg] Hook missing from ~/.claude/settings.json - run: dcg install' -ForegroundColor Yellow }
  } catch { }
}
'@

# Replace a stale dcg startup-check block (marker line through the first
# column-0 closing brace) in $Content with the current marker + block.
# Returns the updated content, or $null if the managed region could not be
# located (hand-mangled block).
function Repair-DcgProfileCheckContent {
  param([string]$Content)
  $pattern = '(?ms)^[ \t]*' + [regex]::Escape($script:DcgProfileCheckMarker) + '[ \t]*\r?\n.*?^\}[ \t]*(\r?\n|\z)'
  $rx = [regex]$pattern
  if (-not $rx.IsMatch($Content)) { return $null }
  # Escape '$' in the replacement so block text like $dcgCfg is inserted verbatim.
  $repl = ($script:DcgProfileCheckMarker + "`n" + $script:DcgProfileCheckBlock + "`n").Replace('$', '$$')
  $rx.Replace($Content, $repl, 1)
}

# Append a guarded check to the user's PowerShell profile that warns, on each new
# session, if the dcg PreToolUse hook has gone missing from ~/.claude/settings.json
# (Claude Code can silently drop it when it rewrites settings). Idempotent
# (marker-guarded), and self-repairing: a marker whose block text differs from
# the current one (e.g. the pre-#282 naive path split that warned on every
# session) is rewritten in place — re-running the installer really does fix a
# stale check. Also repairs stale blocks in the *other* host's profile
# (Windows PowerShell 5.1 and pwsh 7 keep separate profile.ps1 files), since
# the warning may fire in a different host than the one running the installer.
# The PowerShell analog of `dcg setup`'s Unix shell-RC check.
# Returns "added" | "already" | "updated" | "failed".
function Add-DcgProfileCheck {
  param(
    [string]$ProfilePath = $PROFILE.CurrentUserAllHosts,
    [string[]]$AlsoRepairPaths = $null
  )

  $marker = $script:DcgProfileCheckMarker
  $block = $script:DcgProfileCheckBlock
  # Line-ending-insensitive "is the current block already present" test: the
  # block's own newlines depend on how this script was fetched (LF via irm,
  # CRLF via a CRLF checkout) and profiles get re-saved by editors either way.
  # Without normalization a current block that differs only in EOLs would be
  # rewritten on every run.
  $normBlock = $block.Replace("`r`n", "`n")
  try {
    if ($null -eq $AlsoRepairPaths) {
      # Both hosts' CurrentUserAllHosts profiles, wherever Documents lives
      # (OneDrive redirection included). Non-existent paths are skipped below.
      $AlsoRepairPaths = @()
      $docs = [Environment]::GetFolderPath('MyDocuments')
      if ($docs) {
        $AlsoRepairPaths = @(
          (Join-Path $docs 'WindowsPowerShell\profile.ps1'),
          (Join-Path $docs 'PowerShell\profile.ps1')
        )
      }
    }

    $status = $null
    if (Test-Path $ProfilePath -PathType Leaf) {
      $content = Get-Content -Raw -Path $ProfilePath
      if ($content -and $content.Contains($marker)) {
        if ($content.Replace("`r`n", "`n").Contains($normBlock)) {
          $status = "already"
        } else {
          $repaired = Repair-DcgProfileCheckContent -Content $content
          if ($null -ne $repaired) {
            Set-Content -Path $ProfilePath -Value $repaired -NoNewline
          } else {
            # Marker present but the block boundary is unrecognizable; append a
            # fresh block so at least the current check runs.
            Add-Content -Path $ProfilePath -Value ("`n" + $marker + "`n" + $block)
          }
          $status = "updated"
        }
      }
    } else {
      $dir = Split-Path -Parent $ProfilePath
      if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    }

    if ($null -eq $status) {
      Add-Content -Path $ProfilePath -Value ("`n" + $marker + "`n" + $block)
      $status = "added"
    }

    # Best-effort repair of stale blocks in other profiles (never adds new ones).
    foreach ($other in $AlsoRepairPaths) {
      if (-not $other) { continue }
      try {
        $otherFull = [System.IO.Path]::GetFullPath($other)
        $mainFull = [System.IO.Path]::GetFullPath($ProfilePath)
        if ($otherFull -eq $mainFull) { continue }
        if (-not (Test-Path $other -PathType Leaf)) { continue }
        $otherContent = Get-Content -Raw -Path $other
        if (-not ($otherContent -and $otherContent.Contains($marker))) { continue }
        if ($otherContent.Replace("`r`n", "`n").Contains($normBlock)) { continue }
        $repaired = Repair-DcgProfileCheckContent -Content $otherContent
        if ($null -ne $repaired) {
          Set-Content -Path $other -Value $repaired -NoNewline
          if ($status -eq "already") { $status = "updated" }
        }
      } catch { }
    }

    return $status
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

  # Quote the binary path: shell-form hooks word-split an unquoted spaced
  # profile path (C:\Users\John Doe\...) at execution, the same failure the
  # Unix installer fixed for spaced DEST dirs. Get-DcgCommandName already
  # recognizes both quoted and legacy-unquoted forms for dedupe/uninstall.
  $quotedDcgPath = '"' + $DcgPath + '"'
  $desired = [pscustomobject][ordered]@{
    type = "command"
    bash = $quotedDcgPath
    powershell = $quotedDcgPath
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
  # Copilot's published hooks schema names the event camelCase `preToolUse`,
  # but historical dcg releases could leave a PascalCase `PreToolUse` behind.
  # Resolve the actual property name explicitly and case-insensitively rather
  # than leaning on PSObject's case-insensitive member lookup, adopt the
  # file's existing spelling, and repair a duplicate casing pair into the one
  # canonical camelCase key (#253).
  $preProps = @($hooks.PSObject.Properties | Where-Object { $_.Name.ToLowerInvariant() -eq 'pretooluse' })
  foreach ($p in $preProps) {
    if ($null -ne $p.Value -and -not (Test-JsonArray $p.Value)) {
      throw "Copilot hook file $($p.Name) must contain a list; leaving it unchanged: $hookFile"
    }
  }
  if ($preProps.Count -eq 0) {
    $preKey = 'preToolUse'
    $pre = $null
  } elseif ($preProps.Count -eq 1) {
    $preKey = $preProps[0].Name
    $pre = $preProps[0].Value
  } else {
    # Both casings present: merge every entry into one canonical key so no
    # non-dcg hook is dropped; dcg-owned entries are stripped below.
    $preKey = 'preToolUse'
    $pre = @()
    foreach ($p in $preProps) { $pre += (Get-JsonArray $p.Value) }
    foreach ($p in $preProps) { $hooks.PSObject.Properties.Remove($p.Name) }
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
  Set-ObjectPropertyValue $hooks $preKey (@($desired) + $preserved)

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
  Write-Utf8NoBomText -Path $bridge -Text $bridgeContent

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

function Get-HermesConfigDir {
  # The directory whose config.yaml Hermes Agent actually reads. Hermes
  # resolves its data root as (hermes-agent windows-native.md):
  #   1. HERMES_HOME when set — the native-Windows Hermes installer itself sets
  #      HERMES_HOME=%LOCALAPPDATA%\hermes, and users may repoint it (e.g. at
  #      %USERPROFILE%\.hermes to keep a Linux/WSL layout).
  #   2. %LOCALAPPDATA%\hermes on native Windows.
  #   3. ~/.hermes on Linux/macOS (the layout install.sh configures).
  # Writing to ~/.hermes on native Windows produces a config Hermes never
  # reads, so the hook silently never fires (issue #270).
  param([string]$HomeDir = $HOME)
  if (-not [string]::IsNullOrWhiteSpace($env:HERMES_HOME)) { return $env:HERMES_HOME }
  if ($env:OS -eq 'Windows_NT') {
    $base = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($base)) {
      # LOCALAPPDATA is set on any normal Windows session; the known-folder API
      # is a fallback for stripped environments. ConstrainedLanguage mode can
      # reject .NET static calls — fall through to ~/.hermes in that case.
      try {
        $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
      } catch { $base = $null }
    }
    if (-not [string]::IsNullOrWhiteSpace($base)) { return (Join-Path $base 'hermes') }
  }
  Join-Path $HomeDir '.hermes'
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
  # Configure Hermes Agent (config.yaml, hooks.pre_tool_call[]) at the path
  # Hermes actually reads — Get-HermesConfigDir: HERMES_HOME, else
  # %LOCALAPPDATA%\hermes on native Windows, else ~/.hermes. Pure
  # PowerShell, no PyYAML. Strategy (never corrupts an existing config):
  #   - no config.yaml yet -> emit a fresh minimal YAML (we own the whole file).
  #   - config exists + powershell-yaml module present -> full-fidelity merge.
  #   - config exists + no module -> 'manual' (caller prints exact instructions);
  #     round-tripping arbitrary YAML in pure PS is too risky to fake.
  # Returns skipped | created | already | merged | manual | invalid.
  param([string]$DcgPath, [string]$HomeDir = $HOME, [switch]$Force)

  $hermesDir = Get-HermesConfigDir -HomeDir $HomeDir
  # A legacy/WSL-style ~/.hermes still counts as "Hermes is installed here",
  # but the hook is always WRITTEN to the resolved native path above.
  $detected = (Test-Path $hermesDir -PathType Container) -or
    (Test-Path (Join-Path $HomeDir ".hermes") -PathType Container) -or
    ($null -ne (Get-Command hermes -ErrorAction SilentlyContinue))
  if (-not $detected -and -not $Force) { return "skipped" }

  $cfgFile = Join-Path $hermesDir "config.yaml"
  if (-not (Test-Path $hermesDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $hermesDir | Out-Null
  }

  if (-not (Test-Path $cfgFile -PathType Leaf)) {
    Write-Utf8NoBomText -Path $cfgFile -Text (Get-HermesYamlBlock -DcgPath $DcgPath)
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
  Write-Utf8NoBomText -Path $cfgFile -Text $yaml
  "merged"
}

# Configure Posit Assistant's PreToolUse hook in ~/.posit/assistant/settings.json.
# One entry in the global file covers the Positron/RStudio extension, the
# standalone server, and the `pa` terminal client — they all read this file.
#
# The wire contract is Claude-Code-compatible (snake_case PreToolUse stdin,
# exit code 2 blocks with stderr as the reason, and
# hookSpecificOutput.permissionDecision is read on exit 0), so dcg answers with
# its existing ClaudeCompatible protocol and only the config entry differs from
# Configure-ClaudeHook:
#
#   1. The matcher is lowercase "bash|powershell". A simple matcher string is
#      an EXACT match (with "|"/"," separating alternatives) against the tool
#      name, so Claude's "Bash|PowerShell" would match neither shell tool.
#   2. Only documented handler fields are emitted: type, command, timeout. In
#      particular there is NO `shell` field (which the Claude entry uses); the
#      command path is quoted instead — shell-form hooks run through cmd.exe on
#      Windows, and quoting keeps an install path with spaces resolvable.
#   3. `timeout` is in seconds and bounds a wedged hook.
#
# Returns "created" | "already" | "merged" | "skipped".
function Configure-PositAssistantHook {
  param([string]$DcgPath, [switch]$Force, [string]$HomeDir = $HOME)

  $positDir = Join-Path (Join-Path $HomeDir ".posit") "assistant"
  $settingsFile = Join-Path $positDir "settings.json"
  # ~/.posit/assistant is created lazily on first run, so also accept the
  # legacy config dir and the `pa` terminal client on PATH. A bare ~/.posit is
  # deliberately NOT enough — other Posit tools use that directory too.
  $positInstalled = (Test-Path $positDir -PathType Container) -or
    (Test-Path (Join-Path $HomeDir ".positai") -PathType Container) -or
    ($null -ne (Get-Command pa -ErrorAction SilentlyContinue))

  if (-not $positInstalled -and -not $Force) { return "skipped" }

  if (-not (Test-Path $positDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $positDir | Out-Null
  }

  $dcgHook = [pscustomobject][ordered]@{
    type = "command"
    command = '"' + $DcgPath + '"'
    timeout = 10
  }
  Merge-AgentHookFile -HooksFile $settingsFile -DcgHook $dcgHook -Event "PreToolUse" -Matcher "bash|powershell" -Label "Posit Assistant settings.json"
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

function Invoke-DcgMinisignVerification {
  # Fetch and verify the adjacent long-lived minisign signature. By default a
  # missing sidecar or missing verifier warns and continues after SHA256; a
  # present-but-invalid signature is always fatal. -Require makes every missing
  # prerequisite fatal as well. SignatureSource supports local paths/file:// for
  # hermetic installer E2E tests.
  param(
    [string]$ArtifactPath,
    [string]$ArtifactSource,
    [string]$SignatureSource,
    [string]$TempDirectory,
    [string]$ReleaseVersion = "",
    [switch]$Require
  )

  $minisignPublicKey = $script:DcgMinisignPublicKey
  $minisignKeyId = $script:DcgMinisignKeyId
  if ($ReleaseVersion -in @("v0.6.7", "0.6.7")) {
    $minisignPublicKey = $script:DcgLegacyMinisignPublicKey
    $minisignKeyId = $script:DcgLegacyMinisignKeyId
  }

  if ([string]::IsNullOrWhiteSpace($SignatureSource)) {
    $SignatureSource = "$ArtifactSource.minisig"
  }
  $signatureFile = Join-Path $TempDirectory "artifact.minisig"
  Write-Info "Fetching minisign signature from $SignatureSource"
  try {
    Copy-OrDownloadToFile -Source $SignatureSource -OutFile $signatureFile
  } catch {
    if ($Require) {
      throw "Required minisign signature could not be fetched from ${SignatureSource}: $($_.Exception.Message)"
    }
    Write-Warn "Minisign signature not found; continuing after mandatory checksum verification"
    return
  }

  # Require an external executable. A PowerShell function/alias/script shim can
  # otherwise claim success without doing any cryptographic verification.
  $minisign = Get-Command minisign -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if (-not $minisign) {
    if ($Require) { throw "minisign is required but was not found on PATH" }
    Write-Warn "minisign not found; signature is present but cannot be verified"
    return
  }

  try {
    & $minisign -Vm $ArtifactPath -x $signatureFile -P $minisignPublicKey
    $verificationSucceeded = $?
    $verificationExitCode = $LASTEXITCODE
    if ((-not $verificationSucceeded) -or ($verificationExitCode -ne 0)) {
      throw "minisign exited with status $verificationExitCode"
    }
  } catch {
    throw "Minisign verification failed (expected key ID ${minisignKeyId}): $($_.Exception.Message)"
  }

  Write-Ok "Signature verified (minisign key $minisignKeyId)"
}

function Test-DcgPatchedCosignVersion {
  # CVE-2026-22703 is repaired in 2.6.2 and 3.0.4. Reject unknown/development
  # version strings rather than trusting a potentially vulnerable verifier.
  param([string]$VersionJson)

  if ($VersionJson -notmatch '"gitVersion"\s*:\s*"v([0-9]+)\.([0-9]+)\.([0-9]+)"') {
    return $false
  }
  $major = [int]$Matches[1]
  $minor = [int]$Matches[2]
  $patch = [int]$Matches[3]

  if ($major -gt 3) { return $true }
  if ($major -eq 3) {
    return (($minor -gt 0) -or (($minor -eq 0) -and ($patch -ge 4)))
  }
  if ($major -eq 2) {
    return (($minor -gt 6) -or (($minor -eq 6) -and ($patch -ge 2)))
  }
  return $false
}

function Invoke-DcgSigstoreVerification {
  # Verify either a DSR/manual key-signed bundle or a GitHub Actions OIDC
  # bundle. A missing bundle/tool remains best-effort; a present bundle that
  # fails both pinned trust paths is fatal.
  param(
    [string]$ArtifactPath,
    [string]$BundleSource,
    [string]$TempDirectory,
    [string]$IdentityRegex,
    [string]$OidcIssuer
  )

  $cosign = Get-Command cosign -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if (-not $cosign) {
    Write-Warn "cosign not found; skipping signature verification (install cosign for stronger authenticity checks)"
    return
  }

  $bundleFile = Join-Path $TempDirectory (Get-PathLeaf $BundleSource)
  Write-Info "Fetching sigstore bundle from $BundleSource"
  try {
    Copy-OrDownloadToFile -Source $BundleSource -OutFile $bundleFile
  } catch {
    Write-Warn "Sigstore bundle not found; skipping signature verification"
    return
  }

  $versionJson = (& $cosign.Source version --json 2>&1 | Out-String)
  if (($LASTEXITCODE -ne 0) -or (-not (Test-DcgPatchedCosignVersion -VersionJson $versionJson))) {
    Write-Warn "cosign is missing required bundle-verification security fixes (need >=2.6.2 or >=3.0.4); skipping signature verification (checksum already verified)"
    return
  }

  $cosignHelp = (& $cosign.Source verify-blob --help 2>&1 | Out-String)
  $bundleFormatArgs = @()
  if ($cosignHelp -match '--new-bundle-format') {
    $bundleFormatArgs += '--new-bundle-format'
  }

  $publicKeyFile = Join-Path $TempDirectory "dcg-cosign-release.pub"
  Write-Utf8NoBomText -Path $publicKeyFile -Text ($script:DcgCosignReleasePublicKey.Trim() + "`n")

  $localKeyArgs = @("verify-blob") + $bundleFormatArgs + @(
    "--bundle", $bundleFile,
    "--key", $publicKeyFile,
    $ArtifactPath
  )
  # Windows PowerShell 5.1 turns native stderr into ErrorRecord objects when
  # streams are merged. Cosign writes "Verified OK" to stderr even on success,
  # so temporarily make those records non-terminating and trust the native exit
  # code. The captured text remains available for a genuine failure diagnostic.
  $savedErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $localKeyOutput = (& $cosign.Source @localKeyArgs 2>&1 | Out-String)
    $localKeyExitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $savedErrorActionPreference
  }
  if ($localKeyExitCode -eq 0) {
    Write-Ok "Signature verified (cosign local release key)"
    return
  }

  $oidcArgs = @("verify-blob") + $bundleFormatArgs + @(
    "--bundle", $bundleFile,
    "--certificate-identity-regexp", $IdentityRegex,
    "--certificate-oidc-issuer", $OidcIssuer,
    $ArtifactPath
  )
  try {
    $ErrorActionPreference = "Continue"
    $oidcOutput = (& $cosign.Source @oidcArgs 2>&1 | Out-String)
    $oidcExitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $savedErrorActionPreference
  }
  if ($oidcExitCode -ne 0) {
    $details = (($localKeyOutput.Trim(), $oidcOutput.Trim()) |
      Where-Object { $_ } | Select-Object -First 2) -join " | "
    throw "Sigstore bundle failed verification under both pinned release trust roots: $details"
  }

  Write-Ok "Signature verified (cosign GitHub Actions identity)"
}

function Convert-ContentToText {
  param($Content)
  if ($Content -is [byte[]]) {
    $bytes = [byte[]]$Content
  } elseif (($Content -is [System.Array]) -and ($Content.Count -gt 0) -and ($Content[0] -is [byte])) {
    $bytes = [byte[]]$Content
  } else {
    return [string]$Content
  }

  # Release checksum manifests are deliberately ASCII. Decode that narrow
  # authenticated-input grammar without invoking Encoding methods, which WDAC
  # ConstrainedLanguage rejects.
  $chars = foreach ($byte in $bytes) {
    if ($byte -gt 0x7F) { throw "Checksum response is not ASCII" }
    [char]$byte
  }
  return (-join $chars)
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
  # Under WOW64/emulation PROCESSOR_ARCHITEW6432 reports the native host while
  # PROCESSOR_ARCHITECTURE reports the current process. Prefer that explicit
  # native value so x64 PowerShell on Windows ARM64 selects the ARM64 artifact.
  $arch = $env:PROCESSOR_ARCHITEW6432
  if ([string]::IsNullOrWhiteSpace($arch)) {
    try { $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch { }
  }
  if ([string]::IsNullOrWhiteSpace($arch)) { $arch = $env:PROCESSOR_ARCHITECTURE }
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
  # and bare local paths without UriBuilder (blocked in ConstrainedLanguage).
  param([string]$Url, [string]$Leaf)

  $base = $Url
  $suffix = ""
  if ($Url -match '^([^?#]*)([?#].*)$') {
    $base = $Matches[1]
    $suffix = $Matches[2]
  }
  $idx = $base.LastIndexOfAny([char[]]@('\', '/'))
  if ($idx -ge 0) { return $base.Substring(0, $idx + 1) + $Leaf + $suffix }
  $Leaf + $suffix
}

function Test-Dcg64BitWindows {
  $arch = $env:PROCESSOR_ARCHITEW6432
  if ([string]::IsNullOrWhiteSpace($arch)) { $arch = $env:PROCESSOR_ARCHITECTURE }
  $arch -match '(?i)amd64|x86_64|arm64|aarch64'
}

function Normalize-DcgVersionTag {
  param([string]$Value)

  $trimmed = $Value.Trim()
  $pattern = '^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$'
  if ($trimmed -notmatch $pattern) {
    throw "Invalid version '$Value': expected SemVer such as v1.2.3"
  }

  $withoutV = $trimmed -replace '^v', ''
  $withoutBuild = ($withoutV -split '\+', 2)[0]
  if ($withoutBuild.Contains('-')) {
    $prerelease = ($withoutBuild -split '-', 2)[1]
    foreach ($identifier in ($prerelease -split '\.')) {
      if (($identifier -match '^[0-9]+$') -and $identifier.Length -gt 1 -and $identifier.StartsWith('0')) {
        throw "Invalid version '$Value': numeric prerelease identifiers cannot have leading zeroes"
      }
    }
  }

  "v$withoutV"
}

function Get-DcgReportedVersion {
  param([string]$Path)

  # Windows PowerShell 5.1 promotes any native stderr output to a
  # NativeCommandError when the installer's script-wide preference is Stop.
  # dcg intentionally sends its human banner to stderr even though --version
  # succeeds and prints the machine-readable version on stdout. Capture both
  # streams under a narrowly scoped non-terminating preference, then judge the
  # native invocation by its exit code and restore the caller's preference.
  $savedErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = @(& $Path --version 2>&1)
    $status = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $savedErrorActionPreference
  }
  if ($null -eq $status) {
    throw "Installed dcg did not report a native process exit code"
  }
  if ($status -ne 0) {
    throw "Installed dcg failed --version with exit code $status"
  }

  foreach ($rawLine in $output) {
    $candidate = ([string]$rawLine).Trim()
    $candidate = $candidate -replace '^dcg\s+', ''
    try { return (Normalize-DcgVersionTag -Value $candidate) } catch { }
  }
  throw "Installed dcg --version output did not contain a valid SemVer"
}

function Assert-DcgInstalledVersion {
  param([string]$Path, [string]$ExpectedVersion = "")

  $reported = Get-DcgReportedVersion -Path $Path
  if ($ExpectedVersion) {
    $expected = Normalize-DcgVersionTag -Value $ExpectedVersion
    if ($reported -cne $expected) {
      throw "Installed dcg version mismatch: expected $expected, got $reported"
    }
  }
  Write-Ok "Installed version verified: $($reported.Substring(1))"
}

function Invoke-DcgInstallSelfTest {
  param([string]$Path, [string]$ProbeRoot)

  $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  $savedHome = $env:HOME
  $savedUserProfile = $env:USERPROFILE
  $savedXdgConfig = $env:XDG_CONFIG_HOME
  $savedAppData = $env:APPDATA
  $savedLocalAppData = $env:LOCALAPPDATA
  $savedNativePreference = $PSNativeCommandUseErrorActionPreference
  $probeHome = Join-Path $ProbeRoot 'selftest-home'
  New-Item -ItemType Directory -Force -Path $probeHome | Out-Null

  try {
    $env:HOME = $probeHome
    $env:USERPROFILE = $probeHome
    $env:XDG_CONFIG_HOME = Join-Path $probeHome '.config'
    $env:APPDATA = Join-Path $probeHome 'AppData\Roaming'
    $env:LOCALAPPDATA = Join-Path $probeHome 'AppData\Local'
    $PSNativeCommandUseErrorActionPreference = $false
    Push-Location $ProbeRoot
    try {
      $savedErrorActionPreference = $ErrorActionPreference
      try {
        $ErrorActionPreference = 'Continue'
        $allowOutput = @(& $resolvedPath test --format json 'git status' 2>&1)
        $allowStatus = $LASTEXITCODE
      } finally {
        $ErrorActionPreference = $savedErrorActionPreference
      }
      $allowText = $allowOutput -join "`n"
      if ($allowStatus -ne 0 -or $allowText -notmatch '"decision"\s*:\s*"allow"') {
        throw "Self-test did not allow the safe probe (exit $allowStatus)"
      }

      # `dcg test` evaluates this string; it never executes it. Require both
      # exit 1 and structured deny output so a crash cannot masquerade as a pass.
      $savedErrorActionPreference = $ErrorActionPreference
      try {
        $ErrorActionPreference = 'Continue'
        $denyOutput = @(& $resolvedPath test --format json 'rm -rf /' 2>&1)
        $denyStatus = $LASTEXITCODE
      } finally {
        $ErrorActionPreference = $savedErrorActionPreference
      }
      $denyText = $denyOutput -join "`n"
      if ($denyStatus -ne 1 -or $denyText -notmatch '"decision"\s*:\s*"deny"') {
        throw "Self-test did not deny the destructive probe (exit $denyStatus)"
      }
    } finally {
      Pop-Location
    }
  } finally {
    $env:HOME = $savedHome
    $env:USERPROFILE = $savedUserProfile
    $env:XDG_CONFIG_HOME = $savedXdgConfig
    $env:APPDATA = $savedAppData
    $env:LOCALAPPDATA = $savedLocalAppData
    $PSNativeCommandUseErrorActionPreference = $savedNativePreference
  }

  Write-Ok "Self-test complete"
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
    'Hermes'  = ((_dir '.hermes') -or (_has 'hermes') -or
      (Test-Path (Get-HermesConfigDir -HomeDir $HomeDir) -PathType Container))
    # A bare ~/.posit is not enough — other Posit tools share that directory.
    'Posit'   = ((Test-Path (Join-Path (Join-Path $HomeDir '.posit') 'assistant') -PathType Container) -or
      (_dir '.positai') -or (_has 'pa'))
    'Omp'     = ((_dir '.omp') -or (_has 'omp'))
  }
}

function Get-DetectedAgentNames {
  # The display-names of agents Detect-Agents flagged as present, in order.
  param($Agents)
  @(
    foreach ($name in @('Claude', 'Codex', 'Gemini', 'Cursor', 'Copilot', 'Grok', 'Agy', 'Hermes', 'Posit', 'Omp')) {
      if ($Agents[$name]) { $name }
    }
  )
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
  -RequireMinisign  Require a valid .minisig and the minisign verifier
  -MinisignSignatureUrl <url|file://>  Override the adjacent .minisig source
  -Force            Configure agent hooks even if the agent CLI isn't detected
  -NoConfigure      Install the binary only; skip all agent hook configuration
  -Quiet            Suppress informational output (keep warnings/errors/success)
  -Help             Print this help and exit

Configured agents (when detected, or with -Force/-EasyMode):
  Claude Code  (~/.claude/settings.json)      Codex CLI   (~/.codex/hooks.json)
  Gemini CLI   (~/.gemini/settings.json)      Copilot CLI (~/.copilot/hooks/dcg.json)
  Cursor IDE   (~/.cursor/hooks.json)         Hermes      (HERMES_HOME, else %LOCALAPPDATA%\hermes\config.yaml)
  Posit Assistant (~/.posit/assistant/settings.json)
  Oh My Pi     (~/.omp/agent/extensions/dcg-guard.ts via dcg install --omp)
  Grok / agy   via dcg install --grok / --agy under -EasyMode when detected
'@
  exit 0
}

# -Force is the per-agent analog of -EasyMode's config-forcing; OR them together
# so callers can force agent (re)configuration without also touching PATH.
$forceConfig = $EasyMode -or $Force

if ($Version) {
  try {
    $Version = Normalize-DcgVersionTag -Value $Version
  } catch {
    Write-Err $_.Exception.Message
    exit 2
  }
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

if ($Version) {
  try {
    $Version = Normalize-DcgVersionTag -Value $Version
  } catch {
    Write-Err "Resolved release version is invalid: $($_.Exception.Message)"
    exit 1
  }
}

# Determine target
if (-not (Test-Dcg64BitWindows)) {
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
$tmp = Join-Path (Get-DcgTempRoot) ("dcg_install_" + [System.Guid]::NewGuid().ToString("N"))
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

$hash = Get-DcgFileSha256 -Path $zipFile
if ($hash -ne $checksumToUse.ToLower()) {
  Write-Err "Checksum mismatch!"
  Write-Err "Expected: $checksumToUse"
  Write-Err "Got:      $hash"
  exit 1
}
Write-Ok "Checksum verified"

try {
  Invoke-DcgMinisignVerification `
    -ArtifactPath $zipFile `
    -ArtifactSource $url `
    -SignatureSource $MinisignSignatureUrl `
    -TempDirectory $tmp `
    -ReleaseVersion $Version `
    -Require:$RequireMinisign
} catch {
  Write-Err $_.Exception.Message
  exit 1
}

# Verify Sigstore/cosign bundle (best-effort)
if (-not $SigstoreBundleUrl) { $SigstoreBundleUrl = "$url.sigstore.json" }
try {
  Invoke-DcgSigstoreVerification `
    -ArtifactPath $zipFile `
    -BundleSource $SigstoreBundleUrl `
    -TempDirectory $tmp `
    -IdentityRegex $CosignIdentityRegex `
    -OidcIssuer $CosignOidcIssuer
} catch {
  Write-Err $_.Exception.Message
  exit 1
}

# Extract
Write-Info "Extracting..."
Assert-ZipLayoutSafe -ZipPath $zipFile
$extractDir = Join-Path $tmp "extract"
Expand-DcgArchive -ZipPath $zipFile -DestinationPath $extractDir

# The validated release layout has one deterministic root-level binary.
$binPath = Join-Path $extractDir "dcg.exe"
if (-not (Test-Path -LiteralPath $binPath -PathType Leaf)) {
  Write-Err "Binary not found in zip"
  exit 1
}

# Install
if (-not (Test-Path $Dest)) {
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
}
$installedExe = Join-Path $Dest "dcg.exe"
Copy-Item $binPath $installedExe -Force
# Strip Mark-of-the-Web (Zone.Identifier) so the freshly-installed binary does not
# trip SmartScreen / "publisher could not be verified". Done only AFTER the
# required checksum and, when a bundle and compatible cosign are available,
# signature verification above, so unchecked bytes are never unblocked.
# Wrapped in try/catch because Unblock-File is present-but-unsupported on non-Windows
# PowerShell (it throws "does not support Linux", which -ErrorAction can't suppress);
# on Windows it works normally. Keeps the installer body hermetically testable.
if (Get-Command Unblock-File -ErrorAction SilentlyContinue) {
  try { Unblock-File -Path $installedExe -ErrorAction SilentlyContinue } catch { }
}
Write-Ok "Installed to $Dest\dcg.exe"

# PATH management
$path = Get-DcgUserPath
if (-not (Test-UserPathContains -PathValue $path -PathToFind $Dest)) {
  if ($EasyMode) {
    if ([string]::IsNullOrEmpty($path)) {
      Set-DcgUserPath -Value $Dest
    } else {
      Set-DcgUserPath -Value "$path;$Dest"
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

try {
  Assert-DcgInstalledVersion -Path $installedExe -ExpectedVersion $Version
  if ($Verify) {
    Write-Info "Running self-test..."
    Invoke-DcgInstallSelfTest -Path $installedExe -ProbeRoot $tmp
  }
} catch {
  Write-Err $_.Exception.Message
  exit 1
}

}
finally {
  # Always clean up the temp dir (success, throw, or exit).
  if ($tmp -and (Test-Path $tmp)) {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

Write-Ok "Done. Binary at: $Dest\dcg.exe"
Write-Host ""

$dcgExe = Join-Path $Dest "dcg.exe"

# -NoConfigure: the binary is installed (and, under -EasyMode, on PATH); skip ALL
# agent hook auto-configuration. Mirrors the install.sh --no-configure contract.
if ($NoConfigure) {
  Write-Info "Skipping agent hook auto-configuration (-NoConfigure)."
  Write-Info "Configure manually later, or re-run without -NoConfigure."
  return
}

# Detect installed agents and print a concise summary (install.sh parity).
$detectedAgents = Detect-Agents
$detectedNames = Get-DetectedAgentNames $detectedAgents
if ($detectedNames.Count -gt 0) {
  Write-Info ("Detected agents: " + ($detectedNames -join ', '))
} else {
  Write-Info "No coding agents detected; will configure any that appear under standard paths."
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

# Configure Hermes Agent (HERMES_HOME, else %LOCALAPPDATA%\hermes\config.yaml on
# native Windows, else ~/.hermes/config.yaml) when detected (or -EasyMode).
# Pure-PowerShell; never corrupts an existing config (prints manual steps instead).
if ($detectedAgents['Hermes'] -or $forceConfig) {
  Write-Host ""
  $hermesCfgPath = Join-Path (Get-HermesConfigDir) 'config.yaml'
  try {
    switch (Configure-HermesHook -DcgPath $dcgExe -Force:$forceConfig) {
      "created" { Write-Ok "Created Hermes hook at $hermesCfgPath" }
      "merged" { Write-Ok "Added Hermes hook to $hermesCfgPath" }
      "already" { Write-Ok "Hermes hook already configured" }
      "invalid" { Write-Warn "Hermes config.yaml is invalid YAML; left unchanged" }
      "skipped" { Write-Info "Hermes not detected; re-run with -EasyMode to configure it anyway" }
      "manual" {
        Write-Warn "Hermes config.yaml exists and the powershell-yaml module is not installed."
        Write-Info "To avoid corrupting it, add this to $hermesCfgPath manually:"
        Write-Host (Get-HermesYamlBlock -DcgPath $dcgExe)
        Write-Info "(Or install the YAML module first:  Install-Module powershell-yaml -Scope CurrentUser  then re-run.)"
      }
      default { Write-Warn "Hermes hook status unknown" }
    }
  } catch {
    Write-Warn "Hermes auto-configuration failed: $_"
  }
}

# Configure Posit Assistant (~/.posit/assistant/settings.json) when detected (or
# -EasyMode). The single global entry covers the Positron/RStudio extension, the
# standalone server, and the `pa` terminal client — they all read this file.
if ($detectedAgents['Posit'] -or $forceConfig) {
  Write-Host ""
  try {
    switch (Configure-PositAssistantHook -DcgPath $dcgExe -Force:$forceConfig) {
      "created" { Write-Ok "Created Posit Assistant hook at $HOME\.posit\assistant\settings.json" }
      "merged" { Write-Ok "Added Posit Assistant hook to $HOME\.posit\assistant\settings.json" }
      "already" { Write-Ok "Posit Assistant hook already configured" }
      "skipped" { Write-Info "Posit Assistant not detected; re-run with -EasyMode to configure it anyway" }
      default { Write-Warn "Posit Assistant hook status unknown" }
    }
  } catch {
    Write-Warn "Posit Assistant auto-configuration failed: $_"
  }
}

# Configure Oh My Pi through dcg's generated native ExtensionAPI module. The
# Rust installer is the single source of truth for active-profile resolution,
# marker ownership, and the embedded absolute dcg.exe path.
if ($detectedAgents['Omp'] -or $forceConfig) {
  Write-Host ""
  try {
    & $dcgExe install --omp --force | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "Configured Oh My Pi extension via 'dcg install --omp'" }
    else { Write-Warn "'dcg install --omp' exited with code $LASTEXITCODE" }
  } catch {
    Write-Warn "Oh My Pi extension configuration failed: $_"
  }
} else {
  Write-Info "Oh My Pi not detected; re-run with -EasyMode to configure its extension anyway"
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
      "updated" { Write-Ok "Replaced a stale PowerShell `$PROFILE hook-check with the current version" }
      "already" { Write-Info "PowerShell `$PROFILE hook-check already present" }
      default { Write-Warn "Could not add the PowerShell `$PROFILE hook-check" }
    }
  } catch {
    Write-Warn "PowerShell profile check setup failed: $_"
  }
}
