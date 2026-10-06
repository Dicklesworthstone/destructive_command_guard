#!/usr/bin/env pwsh
# Tests Configure-ClaudeHook (and the shared matcher-aware hook merge) from
# install.ps1 by dot-sourcing it with -LoadFunctionsOnly (so the install body
# does not run). Runnable on any OS with PowerShell. Covers: create, merge with a
# coexisting Bash-only hook, legacy/wrong-matcher migration, idempotency,
# UTF-8-no-BOM, refuse-invalid-JSON, and skip. The functions take a -HomeDir
# param so a temp home can be injected ($HOME is read-only in PowerShell).

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installPs1 = Join-Path $repoRoot 'install.ps1'
. $installPs1 -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_claude_test_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}
function Test-NoBom([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}

$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

# --- Test 1: create + idempotent + no BOM ---
Write-Host "Test 1: create / idempotent / no-BOM"
$h1 = New-TempHome
try {
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status -eq 'created') "first run returns 'created' (got '$status')"
    $settings = Join-Path $h1 '.claude/settings.json'
    Check (Test-Path $settings) "settings.json created"
    Check (Test-NoBom $settings) "file has no UTF-8 BOM"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    Check ($p.hooks.PreToolUse[0].matcher -eq 'Bash|PowerShell|Monitor') "matcher covers Bash, PowerShell, and Monitor scripts"
    Check ($p.hooks.PreToolUse[0].hooks[0].command -eq "& '$dcgPath'") "dcg command uses a PowerShell-safe absolute path"
    Check ($p.hooks.PreToolUse[0].hooks[0].shell -eq 'powershell') "hook shell is explicitly PowerShell"
    Check (Test-DcgHookCommand $p.hooks.PreToolUse[0].hooks[0]) "wrapped command is recognized as dcg"
    $before = Get-Content -Raw $settings
    $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status2 -eq 'already') "second run returns 'already' (got '$status2')"
    Check ((Get-Content -Raw $settings) -eq $before) "current settings stay byte-for-byte unchanged"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

# --- Test 2: preserve a coexisting Bash-only hook without widening it ---
Write-Host "Test 2: preserve coexisting Bash-only hooks"
$h2 = New-TempHome
try {
    $cdir = Join-Path $h2 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse  = @([ordered]@{ matcher = 'Bash'; hooks = @([ordered]@{ type = 'command'; command = 'other-tool' }) })
            PostToolUse = @([ordered]@{ matcher = 'Write'; hooks = @([ordered]@{ type = 'command'; command = 'formatter' }) })
        }
        otherSetting = 'keep-me'
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h2
    Check ($status -eq 'merged') "returns 'merged' (got '$status')"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    $shells = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'Bash|PowerShell|Monitor' })[0]
    $bash = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'Bash' })[0]
    Check ($shells.hooks[0].command -eq "& '$dcgPath'") "dcg hoisted first in combined shell matcher"
    Check ((@($bash.hooks | ForEach-Object { $_.command })) -contains 'other-tool') "coexisting Bash hook preserved under Bash only"
    Check (-not ((@($shells.hooks | ForEach-Object { $_.command })) -contains 'other-tool')) "Bash-only hook was not widened to PowerShell or Monitor"
    Check ($p.hooks.PostToolUse[0].hooks[0].command -eq 'formatter') "PostToolUse preserved"
    Check ($p.otherSetting -eq 'keep-me') "unrelated root setting preserved"
    Check (Test-NoBom (Join-Path $cdir 'settings.json')) "merged file has no BOM"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

# --- Test 3: migrate legacy dcg entry without duplicating or losing siblings ---
Write-Host "Test 3: migrate both legacy shell matchers (#226, #529)"
foreach ($legacyMatcher in @('Bash', 'Bash|PowerShell')) {
    $h3 = New-TempHome
    try {
        $cdir = Join-Path $h3 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
        $settings = Join-Path $cdir 'settings.json'
        $existing = [ordered]@{
            hooks = [ordered]@{
                PreToolUse = @([ordered]@{
                    matcher = $legacyMatcher
                    hooks = @(
                        [ordered]@{ type = 'command'; command = $dcgPath },
                        [ordered]@{ type = 'command'; command = 'keep-original-scope'; timeout = 7 }
                    )
                    customField = 'keep-metadata'
                })
            }
        }
        $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
        $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h3
        Check ($status -eq 'merged') "$legacyMatcher install returns 'merged' (got '$status')"
        $p = Get-Content -Raw $settings | ConvertFrom-Json
        $allDcg = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | Where-Object { Test-DcgHookCommand $_ })
        $legacy = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq $legacyMatcher })[0]
        Check ($allDcg.Count -eq 1) "exactly one dcg hook remains after $legacyMatcher migration"
        Check ($p.hooks.PreToolUse[0].matcher -eq 'Bash|PowerShell|Monitor') "migrated matcher includes Monitor"
        Check ($legacy.hooks[0].command -eq 'keep-original-scope') "legacy sibling stays under $legacyMatcher"
        Check ($legacy.hooks[0].timeout -eq 7) "legacy sibling hook metadata preserved"
        Check ($legacy.customField -eq 'keep-metadata') "legacy entry metadata preserved"
        $before = Get-Content -Raw $settings
        $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h3
        Check ($status2 -eq 'already') "migrated $legacyMatcher registration is idempotent"
        Check ((Get-Content -Raw $settings) -eq $before) "migrated settings stay byte-for-byte unchanged"
    } finally { Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }
}

# --- Test 4: refuse invalid JSON (leave untouched) ---
Write-Host "Test 4: refuse invalid JSON"
$h4 = New-TempHome
try {
    $cdir = Join-Path $h4 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    Set-Content -Path (Join-Path $cdir 'settings.json') -Value '{ not valid json'
    $threw = $false
    try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h4 } catch { $threw = $true }
    Check $threw "throws on invalid JSON"
    Check ((Get-Content -Raw (Join-Path $cdir 'settings.json')).Trim() -eq '{ not valid json') "invalid JSON left unchanged"
} finally { Remove-Item -Recurse -Force $h4 -ErrorAction SilentlyContinue }

# --- Test 5: skip when not detected and not forced ---
# Clear PATH so `claude` is not discoverable (this CI/dev box may have it on PATH);
# with ~/.claude absent and no -Force the result must be 'skipped'.
Write-Host "Test 5: skip when ~/.claude absent and not -Force"
$h5 = New-TempHome
$savedPath = $env:PATH
try {
    $env:PATH = ''
    $status = Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h5
    Check ($status -eq 'skipped') "returns 'skipped' (got '$status')"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h5 -ErrorAction SilentlyContinue }

# --- Test 6: escaped apostrophes round-trip and extra async metadata is repaired ---
Write-Host "Test 6: escaped apostrophe path / reject async hook"
$h6 = New-TempHome
try {
    $apostrophePath = "C:\Users\O'Brien\.local\bin\dcg.exe"
    $escapedPath = $apostrophePath.Replace("'", "''")
    $cdir = Join-Path $h6 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @([ordered]@{
                matcher = 'Bash|PowerShell|Monitor'
                hooks = @([ordered]@{
                    type = 'command'
                    command = "& '$escapedPath'"
                    shell = 'powershell'
                    async = $true
                })
            })
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    Check (Test-DcgHookCommand $existing.hooks.PreToolUse[0].hooks[0]) "escaped apostrophe command is recognized"
    $status = Configure-ClaudeHook -DcgPath $apostrophePath -Force -HomeDir $h6
    Check ($status -eq 'merged') "async dcg hook is replaced instead of accepted as current"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    $hook = $p.hooks.PreToolUse[0].hooks[0]
    Check ($hook.command -eq "& '$escapedPath'") "escaped path survives JSON round-trip"
    Check ($null -eq $hook.PSObject.Properties['async']) "blocking hook has no async metadata"
    $status2 = Configure-ClaudeHook -DcgPath $apostrophePath -Force -HomeDir $h6
    Check ($status2 -eq 'already') "repaired escaped-path hook is idempotent"
} finally { Remove-Item -Recurse -Force $h6 -ErrorAction SilentlyContinue }

# --- Test 7: malformed scalar inner hooks are rejected without mutation ---
Write-Host "Test 7: reject scalar inner hooks"
$h7 = New-TempHome
try {
    $cdir = Join-Path $h7 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $settings = Join-Path $cdir 'settings.json'
    $original = '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell","hooks":{"type":"command","command":"dcg"}}]}}'
    Set-Content -Path $settings -Value $original -NoNewline
    $threw = $false
    try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h7 } catch { $threw = $true }
    Check $threw "throws on scalar matcher hooks"
    Check ((Get-Content -Raw $settings) -eq $original) "malformed settings are left byte-for-byte unchanged"
} finally { Remove-Item -Recurse -Force $h7 -ErrorAction SilentlyContinue }

# --- Test 8: repair dcg installed beneath an unrelated matcher ---
Write-Host "Test 8: repair wrong-matcher dcg hook"
$h8 = New-TempHome
try {
    $cdir = Join-Path $h8 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $settings = Join-Path $cdir 'settings.json'
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @(
                [ordered]@{
                    matcher = 'Write'
                    hooks = @(
                        [ordered]@{ type = 'command'; command = $dcgPath },
                        [ordered]@{ type = 'command'; command = 'keep-write-hook' }
                    )
                }
            )
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h8
    Check ($status -eq 'merged') "wrong-matcher install returns 'merged' (got '$status')"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $allDcg = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | Where-Object { Test-DcgHookCommand $_ })
    $write = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'Write' })[0]
    Check ($allDcg.Count -eq 1) "exactly one dcg hook remains after wrong-matcher repair"
    Check ($p.hooks.PreToolUse[0].matcher -eq 'Bash|PowerShell|Monitor') "repaired hook uses canonical matcher"
    Check ($write.hooks[0].command -eq 'keep-write-hook') "coexisting wrong-matcher hook preserved"
    $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h8
    Check ($status2 -eq 'already') "wrong-matcher repair is idempotent"
} finally { Remove-Item -Recurse -Force $h8 -ErrorAction SilentlyContinue }

# --- Test 9: one current hook replaces duplicates under both legacy matchers ---
Write-Host "Test 9: collapse mixed current and legacy dcg registrations (#529)"
$h9 = New-TempHome
try {
    $cdir = Join-Path $h9 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $settings = Join-Path $cdir 'settings.json'
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @(
                [ordered]@{
                    matcher = 'Bash|PowerShell|Monitor'
                    hooks = @([ordered]@{ type = 'command'; command = "& '$dcgPath'"; shell = 'powershell' })
                },
                [ordered]@{
                    matcher = 'Bash|PowerShell'
                    customField = 'keep-shells-metadata'
                    hooks = @(
                        [ordered]@{ type = 'command'; command = 'C:\old\dcg.exe' },
                        [ordered]@{ type = 'command'; command = 'keep-shells' }
                    )
                },
                [ordered]@{
                    matcher = 'Bash'
                    hooks = @([ordered]@{ type = 'command'; command = $dcgPath })
                },
                [ordered]@{
                    matcher = 'Monitor'
                    customField = 'keep-monitor-metadata'
                    hooks = @([ordered]@{ type = 'command'; command = 'monitor-audit' })
                }
            )
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h9
    Check ($status -eq 'merged') "duplicates prevent a false 'already' result"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $entries = @($p.hooks.PreToolUse)
    $allDcg = @($entries | ForEach-Object { $_.hooks } | Where-Object { Test-DcgHookCommand $_ })
    Check ($allDcg.Count -eq 1) "exactly one dcg hook remains across all matcher generations"
    Check ($entries.Count -eq 3) "emptied legacy matcher is removed"
    Check ($entries[0].matcher -eq 'Bash|PowerShell|Monitor') "canonical entry stays first"
    Check ($entries[0].hooks[0].command -eq "& '$dcgPath'") "canonical hook uses the current path"
    Check ($entries[1].matcher -eq 'Bash|PowerShell') "legacy sibling scope is preserved"
    Check ($entries[1].hooks[0].command -eq 'keep-shells') "legacy sibling command is preserved"
    Check ($entries[1].customField -eq 'keep-shells-metadata') "legacy sibling entry metadata is preserved"
    Check ($entries[2].matcher -eq 'Monitor') "unrelated Monitor-only hook is not widened"
    Check ($entries[2].hooks[0].command -eq 'monitor-audit') "unrelated Monitor-only hook is preserved"
    Check ($entries[2].customField -eq 'keep-monitor-metadata') "Monitor-only entry metadata is preserved"
    $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h9
    Check ($status2 -eq 'already') "mixed matcher migration is idempotent"
} finally { Remove-Item -Recurse -Force $h9 -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) {
    Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red
    exit 1
}
Write-Host "All Configure-ClaudeHook tests passed." -ForegroundColor Green
