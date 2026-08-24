#!/usr/bin/env pwsh
# Tests Configure-PositAssistantHook from install.ps1 by dot-sourcing it with
# -LoadFunctionsOnly (so the install body does not run). Runnable on any OS with
# PowerShell. Covers: create, idempotency, UTF-8 no BOM, merge that preserves
# unrelated settings/groups/events, stale-path repair, lookalike preservation,
# refuse-invalid-JSON, skip-when-absent, legacy-dir detection, and Detect-Agents
# wiring. The function takes -HomeDir so a temp home can be injected ($HOME is
# read-only in PowerShell).
#
# Three Posit-specific invariants are asserted deliberately, because getting any
# of them wrong produces a hook that sits in the file but never fires (or breaks
# on an install path with spaces):
#   - the matcher is lowercase "bash|powershell" (a simple matcher string is an
#     exact match against the tool name; both shell-tool names are covered);
#   - only documented handler fields are emitted, so there is NO `shell` field
#     (the Claude entry uses one) and the command is quoted for cmd.exe instead;
#   - `timeout` is present and expressed in seconds.

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_posit_test_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}
function Test-NoBom([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}
function New-PositDir([string]$homeDir) {
    $d = Join-Path (Join-Path $homeDir '.posit') 'assistant'
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    $d
}

$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'
$expectedCommand = '"' + $dcgPath + '"'

$ompSelectorNames = @('OMP_PROFILE', 'PI_PROFILE', 'PI_CONFIG_DIR', 'PI_CODING_AGENT_DIR')
$savedOmpSelectors = @{}
foreach ($name in $ompSelectorNames) {
    $savedOmpSelectors[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    # Detect-Agents is exercised below, so make its OMP isolation assertion
    # non-vacuous even when the host starts with no OMP variables configured.
    [Environment]::SetEnvironmentVariable($name, "dcg-test-ambient-$name", 'Process')
}
foreach ($name in $ompSelectorNames) {
    [Environment]::SetEnvironmentVariable($name, $null, 'Process')
}

try {
    $unclearedOmpSelectors = @($ompSelectorNames | Where-Object {
        Test-Path -LiteralPath "Env:$_"
    })
    if ($unclearedOmpSelectors.Count -ne 0) {
        throw "OMP test selector fence failed: $($unclearedOmpSelectors -join ', ')"
    }
    Check $true "OMP path/profile selectors are scrubbed before loading installer functions"

    . (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

# --- Test 1: create + idempotent + no BOM + wire shape ---
Write-Host "Test 1: create / idempotent / no-BOM / wire shape"
$h1 = New-TempHome
try {
    $status = Configure-PositAssistantHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status -eq 'created') "first run returns 'created' (got '$status')"
    $settings = Join-Path (Join-Path (Join-Path $h1 '.posit') 'assistant') 'settings.json'
    Check (Test-Path $settings) "settings.json created"
    Check (Test-NoBom $settings) "file has no UTF-8 BOM"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $hook = $p.hooks.PreToolUse[0].hooks[0]
    Check ($p.hooks.PreToolUse[0].matcher -eq 'bash|powershell') "matcher is lowercase and covers both shell tools"
    Check ($hook.command -eq $expectedCommand) "dcg command is quoted so a path with spaces survives cmd.exe"
    Check ($hook.type -eq 'command') "hook type is 'command'"
    Check ($hook.timeout -eq 10) "timeout is 10 (seconds)"
    Check ($null -eq $hook.PSObject.Properties['shell']) "hook carries no 'shell' field (not a documented handler field)"
    Check (Test-DcgHookCommand $hook) "quoted command is recognized as dcg"
    $status2 = Configure-PositAssistantHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status2 -eq 'already') "second run returns 'already' (got '$status2')"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

# --- Test 2: merge preserves unrelated settings, groups, and events ---
Write-Host "Test 2: merge preserves unrelated settings and groups"
$h2 = New-TempHome
try {
    $pdir = New-PositDir $h2
    $settings = Join-Path $pdir 'settings.json'
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @([ordered]@{ matcher = 'bash,edit'; hooks = @([ordered]@{ type = 'command'; command = 'audit-log' }) })
            SessionStart = @([ordered]@{ hooks = @([ordered]@{ type = 'command'; command = 'greet' }) })
        }
        model = 'keep-me'
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
    $status = Configure-PositAssistantHook -DcgPath $dcgPath -Force -HomeDir $h2
    Check ($status -eq 'merged') "returns 'merged' (got '$status')"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    Check ($p.hooks.PreToolUse[0].matcher -eq 'bash|powershell') "dcg group is hoisted first"
    Check ($p.hooks.PreToolUse[0].hooks[0].command -eq $expectedCommand) "dcg is the first hook in its group"
    $userGroup = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'bash,edit' })[0]
    Check ($null -ne $userGroup) "user's comma-list matcher group is preserved verbatim"
    Check ($userGroup.hooks[0].command -eq 'audit-log') "user's hook is preserved"
    Check ($p.hooks.SessionStart[0].hooks[0].command -eq 'greet') "unrelated event preserved"
    Check ($p.model -eq 'keep-me') "unrelated root setting preserved"
    Check (Test-NoBom $settings) "merged file has no BOM"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

# --- Test 3: a stale dcg path is repaired, not duplicated ---
Write-Host "Test 3: repair stale dcg path"
$h3 = New-TempHome
try {
    $pdir = New-PositDir $h3
    $settings = Join-Path $pdir 'settings.json'
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @([ordered]@{
                matcher = 'bash|powershell'
                hooks = @(
                    [ordered]@{ type = 'command'; command = '"C:\old\dcg.exe"'; timeout = 10 },
                    [ordered]@{ type = 'command'; command = 'keep-sibling' }
                )
            })
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
    $status = Configure-PositAssistantHook -DcgPath $dcgPath -Force -HomeDir $h3
    Check ($status -eq 'merged') "stale path returns 'merged' (got '$status')"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $allDcg = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | Where-Object { Test-DcgHookCommand $_ })
    Check ($allDcg.Count -eq 1) "exactly one dcg hook remains"
    Check ($allDcg[0].command -eq $expectedCommand) "the remaining dcg hook points at the new path"
    $cmds = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
    Check ($cmds -contains 'keep-sibling') "sibling hook in the same group is preserved"
    $status2 = Configure-PositAssistantHook -DcgPath $dcgPath -Force -HomeDir $h3
    Check ($status2 -eq 'already') "repair is idempotent"
} finally { Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }

# --- Test 4: a lookalike tool whose basename merely contains "dcg" survives ---
Write-Host "Test 4: preserve lookalike non-dcg tooling"
$h4 = New-TempHome
try {
    $pdir = New-PositDir $h4
    $settings = Join-Path $pdir 'settings.json'
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @([ordered]@{
                matcher = 'bash'
                hooks = @([ordered]@{ type = 'command'; command = 'C:\tools\dcgworkflow.exe --scan' })
            })
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
    Configure-PositAssistantHook -DcgPath $dcgPath -Force -HomeDir $h4 | Out-Null
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $cmds = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
    Check ($cmds -contains 'C:\tools\dcgworkflow.exe --scan') "unrelated tool containing 'dcg' is not removed"
} finally { Remove-Item -Recurse -Force $h4 -ErrorAction SilentlyContinue }

# --- Test 5: refuse invalid JSON (leave untouched) ---
Write-Host "Test 5: refuse invalid JSON"
$h5 = New-TempHome
try {
    $pdir = New-PositDir $h5
    $settings = Join-Path $pdir 'settings.json'
    Set-Content -Path $settings -Value '{ not valid json'
    $threw = $false
    try { Configure-PositAssistantHook -DcgPath $dcgPath -Force -HomeDir $h5 } catch { $threw = $true }
    Check $threw "throws on invalid JSON"
    Check ((Get-Content -Raw $settings).Trim() -eq '{ not valid json') "invalid JSON left unchanged"
} finally { Remove-Item -Recurse -Force $h5 -ErrorAction SilentlyContinue }

# --- Test 6: skip when not detected and not forced ---
# PATH is cleared so `pa` is not discoverable; with ~/.posit/assistant absent
# and no -Force the result must be 'skipped' and nothing may be written.
Write-Host "Test 6: skip when ~/.posit/assistant absent and not -Force"
$h6 = New-TempHome
$savedPath = $env:PATH
try {
    $env:PATH = ''
    $status = Configure-PositAssistantHook -DcgPath $dcgPath -HomeDir $h6
    Check ($status -eq 'skipped') "returns 'skipped' (got '$status')"
    Check (-not (Test-Path (Join-Path $h6 '.posit'))) "no config directory is created when skipping"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h6 -ErrorAction SilentlyContinue }

# --- Test 7: detection via the legacy config dir ---
Write-Host "Test 7: detect via legacy ~/.positai"
$h7 = New-TempHome
$savedPath = $env:PATH
try {
    $env:PATH = ''
    New-Item -ItemType Directory -Force -Path (Join-Path $h7 '.positai') | Out-Null
    $status = Configure-PositAssistantHook -DcgPath $dcgPath -HomeDir $h7
    Check ($status -eq 'created') "legacy dir counts as detected (got '$status')"
    $settings = Join-Path (Join-Path (Join-Path $h7 '.posit') 'assistant') 'settings.json'
    Check (Test-Path $settings) "hook lands in the CURRENT location, not the legacy one"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h7 -ErrorAction SilentlyContinue }

# --- Test 8: Detect-Agents / Get-DetectedAgentNames wiring ---
Write-Host "Test 8: Detect-Agents reports Posit"
$h8 = New-TempHome
$savedPath = $env:PATH
try {
    $env:PATH = ''
    New-PositDir $h8 | Out-Null
    $agents = Detect-Agents -HomeDir $h8
    Check ([bool]$agents['Posit']) "Detect-Agents flags Posit when ~/.posit/assistant exists"
    Check ((Get-DetectedAgentNames $agents) -contains 'Posit') "Get-DetectedAgentNames includes Posit"
    Check (-not [bool]$agents['Omp']) "ambient OMP selectors cannot inject Omp into the Posit fixture"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h8 -ErrorAction SilentlyContinue }
} finally {
    foreach ($name in $ompSelectorNames) {
        [Environment]::SetEnvironmentVariable($name, $savedOmpSelectors[$name], 'Process')
    }
}

if ($script:failures -gt 0) {
    Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red
    exit 1
}
Write-Host "All Configure-PositAssistantHook tests passed." -ForegroundColor Green
