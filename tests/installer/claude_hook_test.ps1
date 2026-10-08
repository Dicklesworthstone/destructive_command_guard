#!/usr/bin/env pwsh
# Tests Configure-ClaudeHook (and the shared matcher-aware hook merge) from
# install.ps1 by dot-sourcing it with -LoadFunctionsOnly (so the install body
# does not run). Runnable on any OS with PowerShell. Covers: create, merge with a
# coexisting Bash-only hook, legacy/wrong-matcher migration, idempotency,
# UTF-8-no-BOM, refuse-invalid-JSON, skip, and CLAUDE_CONFIG_DIR install/uninstall
# and predecessor migration. The functions take a -HomeDir
# param so a temp home can be injected ($HOME is read-only in PowerShell).

$ErrorActionPreference = 'Stop'
$savedClaudeConfigDir = $env:CLAUDE_CONFIG_DIR
$env:CLAUDE_CONFIG_DIR = $null

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
try {
    $env:CLAUDE_CONFIG_DIR = $null

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

# Active configuration overrides HomeDir's default and preserves settings.
$activeHome = New-TempHome
Push-Location $activeHome
try {
    foreach ($form in @('absolute', 'relative', 'tilde', 'home', 'empty')) {
        switch ($form) {
            'absolute' { $env:CLAUDE_CONFIG_DIR = Join-Path $activeHome 'absolute config'; $expected = $env:CLAUDE_CONFIG_DIR }
            'relative' { $env:CLAUDE_CONFIG_DIR = 'relative config'; $expected = Join-Path (Get-Location).Path 'relative config' }
            'tilde' { $env:CLAUDE_CONFIG_DIR = '~/alternate config'; $expected = Join-Path $activeHome 'alternate config' }
            'home' { $env:CLAUDE_CONFIG_DIR = '~'; $expected = $activeHome }
            'empty' { $env:CLAUDE_CONFIG_DIR = ''; $expected = Join-Path $activeHome '.claude' }
        }
        Check ((Get-ClaudeConfigDir -HomeDir $activeHome) -eq $expected) "resolver: $form"
        New-Item -ItemType Directory -Force $expected | Out-Null
        $settings = Join-Path $expected 'settings.json'
        [System.IO.File]::WriteAllText($settings, '{"theme":"dark"}')
        $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $activeHome
        Check ($status -eq 'merged') "active configuration installed: $form"
        $value = Get-Content -Raw $settings | ConvertFrom-Json
        Check ($value.theme -eq 'dark') "settings preserved: $form"
        Check (@($value.hooks.PreToolUse).Count -eq 1) "hook present: $form"
    }
} finally { Pop-Location; $env:CLAUDE_CONFIG_DIR = $savedClaudeConfigDir }

# --- Test 10: every supported selector applies to installation and removal ---
foreach ($selection in @('unset', 'empty', 'absolute', 'tilde', 'tilde-backslash', 'home', 'relative')) {
    Write-Host "Test 10: CLAUDE_CONFIG_DIR $selection install / migration / uninstall"
    $h10 = New-TempHome
    Push-Location $h10
    try {
        $defaultDir = Join-Path $h10 '.claude'
        $defaultSettings = Join-Path $defaultDir 'settings.json'
        New-Item -ItemType Directory -Path $defaultDir | Out-Null
        $defaultConfig = '{"model":"default-model","hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell|Monitor","hooks":[{"type":"command","command":"dcg"}]}]}}'
        Set-Content -LiteralPath $defaultSettings -Value $defaultConfig -NoNewline
        switch ($selection) {
            'unset' { $env:CLAUDE_CONFIG_DIR = $null; $expectedDir = $defaultDir }
            'empty' { $env:CLAUDE_CONFIG_DIR = ''; $expectedDir = $defaultDir }
            'absolute' { $expectedDir = Join-Path $h10 'active config [work]'; $env:CLAUDE_CONFIG_DIR = $expectedDir }
            'tilde' { $env:CLAUDE_CONFIG_DIR = '~/active config'; $expectedDir = Join-Path $h10 'active config' }
            'tilde-backslash' { $env:CLAUDE_CONFIG_DIR = '~\active config'; $expectedDir = Join-Path $h10 'active config' }
            'home' { $env:CLAUDE_CONFIG_DIR = '~'; $expectedDir = $h10 }
            'relative' { $env:CLAUDE_CONFIG_DIR = 'active config'; $expectedDir = Join-Path $h10 'active config' }
        }
        $settings = Join-Path $expectedDir 'settings.json'
        Check ((Get-ClaudeConfigDir -HomeDir $h10) -eq $expectedDir) "$selection resolves the active directory"
        New-Item -ItemType Directory -Force -Path $expectedDir | Out-Null
        @{
            model = 'active-model'
            permissions = @{ allow = @('Read') }
            hooks = @{
                PreToolUse = @(@{ matcher = 'Bash'; hooks = @(
                    @{ type = 'command'; command = 'keep-active-hook' },
                    @{ type = 'command'; command = 'python3 legacy/git_safety_guard.py' }
                ) })
                PostToolUse = @(@{ matcher = 'Write'; hooks = @(@{ type = 'command'; command = 'keep-after-hook' }) })
            }
        } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $settings
        Check (Remove-DcgPredecessor -HomeDir $h10) "$selection migrates the active predecessor"
        $migrated = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json
        $migratedCommands = @($migrated.hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
        Check (-not ($migratedCommands -match 'git_safety_guard')) "$selection removes the active predecessor only"
        $status = Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h10
        Check ($status -eq 'merged') "$selection installs in the selected settings"
        $p = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json
        Check ($p.model -eq 'active-model') "$selection preserves the active model"
        Check ($p.permissions.allow[0] -eq 'Read') "$selection preserves permissions"
        $commands = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
        Check ($commands -contains 'keep-active-hook') "$selection preserves the third-party hook"
        Check ($p.hooks.PostToolUse[0].hooks[0].command -eq 'keep-after-hook') "$selection preserves other hook events"
        Check (Test-NoBom $settings) "$selection writes valid UTF-8 without a BOM"
        $installed = Get-Content -Raw -LiteralPath $settings
        Check ((Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h10) -eq 'already') "$selection installation is idempotent"
        Check ((Get-Content -Raw -LiteralPath $settings) -eq $installed) "$selection second install leaves bytes unchanged"
        if ($settings -ne $defaultSettings) {
            Check ((Get-Content -Raw -LiteralPath $defaultSettings) -eq $defaultConfig) "$selection install and migration preserve the default settings byte-for-byte"
        }

        # Load the uninstaller in its own scope to exercise its independently
        # shipped resolver without replacing the installer functions above.
        $removed = & {
            . (Join-Path $repoRoot 'uninstall.ps1') -LoadFunctionsOnly
            Check ((Get-ClaudeConfigDir -HomeDir $h10) -eq $expectedDir) "$selection uninstall resolves the same directory"
            Unconfigure-ClaudeHook -HomeDir $h10
        }
        Check ($removed -eq $true) "$selection uninstall removes the active hook"
        $after = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json
        $remaining = @($after.hooks.PreToolUse | ForEach-Object { $_.hooks })
        Check (@($remaining | Where-Object { Test-DcgHookCommand $_ }).Count -eq 0) "$selection uninstall removes all active dcg entries"
        Check ($remaining[0].command -eq 'keep-active-hook') "$selection uninstall preserves the third-party hook"
        Check ($after.model -eq 'active-model') "$selection uninstall preserves other settings"
        if ($settings -ne $defaultSettings) {
            Check ((Get-Content -Raw -LiteralPath $defaultSettings) -eq $defaultConfig) "$selection uninstall leaves the default protected settings unchanged"
        }
    } finally {
        Pop-Location
        Remove-Item -Recurse -Force -LiteralPath $h10 -ErrorAction SilentlyContinue
    }
}

Write-Host 'Test 11: an explicit directory creates a fresh installation with an empty PATH and without -Force'
$h11 = New-TempHome
$savedPath11 = $env:PATH
try {
    $env:PATH = ''
    $env:CLAUDE_CONFIG_DIR = Join-Path $h11 'new/active config'
    $freshSettings = Join-Path $env:CLAUDE_CONFIG_DIR 'settings.json'
    Check ((Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h11) -eq 'created') 'fresh selected config is installed automatically'
    Check (Test-Path -LiteralPath $freshSettings) 'selected directory and settings are created'
    Check (-not (Test-Path -LiteralPath (Join-Path $h11 '.claude'))) 'default directory is not created'
} finally {
    $env:PATH = $savedPath11
    Remove-Item -Recurse -Force -LiteralPath $h11 -ErrorAction SilentlyContinue
}

} finally { $env:CLAUDE_CONFIG_DIR = $savedClaudeConfigDir }

if ($script:failures -gt 0) {
    Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red
    exit 1
}
Write-Host "All Configure-ClaudeHook tests passed." -ForegroundColor Green
