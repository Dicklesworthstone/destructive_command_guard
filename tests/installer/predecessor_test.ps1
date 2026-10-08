#!/usr/bin/env pwsh
# Tests Remove-DcgPredecessor from install.ps1: strips ONLY the legacy
# git_safety_guard hook entries from ~/.claude/settings.json (preserving the
# modern dcg hook + coexisting hooks) and removes the predecessor script.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_pred_test_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}

$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'
$savedClaudeConfigDir = $env:CLAUDE_CONFIG_DIR
try {
    $env:CLAUDE_CONFIG_DIR = $null

Write-Host "Test 1: removes ONLY the predecessor hook, keeps dcg + coexisting"
$h1 = New-TempHome
try {
    $cdir = Join-Path $h1 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @([ordered]@{ matcher = 'Bash'; hooks = @(
                [ordered]@{ type = 'command'; command = 'python3 ~/.claude/hooks/git_safety_guard.py' },
                [ordered]@{ type = 'command'; command = $dcgPath },
                [ordered]@{ type = 'command'; command = 'other-tool' }
            )})
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    $removed = Remove-DcgPredecessor -HomeDir $h1
    Check ($removed -eq $true) "returns true when predecessor present"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    $cmds = @($p.hooks.PreToolUse[0].hooks | ForEach-Object { $_.command })
    Check (-not ($cmds | Where-Object { $_ -match 'git_safety_guard' })) "git_safety_guard hook removed"
    Check ($cmds -contains $dcgPath) "modern dcg hook preserved"
    Check ($cmds -contains 'other-tool') "coexisting hook preserved"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

Write-Host "Test 2: no predecessor -> returns false, unchanged"
$h2 = New-TempHome
try {
    $cdir = Join-Path $h2 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{ hooks = [ordered]@{ PreToolUse = @([ordered]@{ matcher = 'Bash'; hooks = @([ordered]@{ type = 'command'; command = $dcgPath }) }) } }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    $removed = Remove-DcgPredecessor -HomeDir $h2
    Check ($removed -eq $false) "returns false when no predecessor"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    Check ($p.hooks.PreToolUse[0].hooks[0].command -eq $dcgPath) "dcg hook untouched"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

Write-Host "Test 3: removes the predecessor script file + empty hooks dir"
$h3 = New-TempHome
try {
    $hookDir = Join-Path (Join-Path $h3 '.claude') 'hooks'
    New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
    Set-Content -Path (Join-Path $hookDir 'git_safety_guard.py') -Value '# legacy'
    $removed = Remove-DcgPredecessor -HomeDir $h3
    Check ($removed -eq $true) "returns true when predecessor script present"
    Check (-not (Test-Path (Join-Path $hookDir 'git_safety_guard.py'))) "predecessor script deleted"
    Check (-not (Test-Path $hookDir)) "empty hooks dir removed"
} finally { Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }

foreach ($cwdScope in @('home', 'project')) {
    Write-Host "Test 4: selected predecessor migration preserves inactive files from $cwdScope"
    $h4 = New-TempHome
    $defaultDir = Join-Path $h4 '.claude'
    $defaultHooks = Join-Path $defaultDir 'hooks'
    New-Item -ItemType Directory -Force -Path $defaultHooks | Out-Null
    $defaultScript = Join-Path $defaultHooks 'git_safety_guard.py'
    $defaultSettings = Join-Path $defaultDir 'settings.json'
    $defaultScriptContent = '# inactive default predecessor'
    $defaultSettingsContent = '{"model":"default-model","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"python3 ~/.claude/hooks/git_safety_guard.py"}]}]}}'
    Set-Content -LiteralPath $defaultScript -Value $defaultScriptContent -NoNewline
    Set-Content -LiteralPath $defaultSettings -Value $defaultSettingsContent -NoNewline
    $workDir = $h4
    if ($cwdScope -eq 'project') {
        $workDir = Join-Path $h4 'distinct-project'
        $projectHooks = Join-Path $workDir '.claude/hooks'
        New-Item -ItemType Directory -Force -Path $projectHooks | Out-Null
        $projectScript = Join-Path $projectHooks 'git_safety_guard.py'
        $projectSettings = Join-Path $workDir '.claude/settings.json'
        Set-Content -LiteralPath $projectScript -Value '# project predecessor' -NoNewline
        Set-Content -LiteralPath $projectSettings -Value $defaultSettingsContent -NoNewline
    }
    $env:CLAUDE_CONFIG_DIR = Join-Path $h4 'active-profile'
    Push-Location $workDir
    try {
        Check (-not (Remove-DcgPredecessor -HomeDir $h4)) "$cwdScope does not mistake an inactive predecessor for the selected installation"

        $activeHooks = Join-Path $env:CLAUDE_CONFIG_DIR 'hooks'
        New-Item -ItemType Directory -Force -Path $activeHooks | Out-Null
        $activeScript = Join-Path $activeHooks 'git_safety_guard.py'
        $activeSettings = Join-Path $env:CLAUDE_CONFIG_DIR 'settings.json'
        Set-Content -LiteralPath $activeScript -Value '# selected predecessor'
        Set-Content -LiteralPath $activeSettings -Value '{"model":"active-model","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"python3 hooks/git_safety_guard.py"},{"type":"command","command":"keep-active-hook"}]}]}}'
        Check (Remove-DcgPredecessor -HomeDir $h4) "$cwdScope migrates the selected predecessor"
        Check (-not (Test-Path -LiteralPath $activeScript)) "$cwdScope removes the selected predecessor script"
        $activeAfter = Get-Content -Raw -LiteralPath $activeSettings | ConvertFrom-Json
        Check ($activeAfter.model -eq 'active-model') "$cwdScope preserves unrelated selected settings"
        $activeCommands = @($activeAfter.hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
        Check (($activeCommands.Count -eq 1) -and ($activeCommands[0] -eq 'keep-active-hook')) "$cwdScope removes only the selected predecessor hook"
        Check ((Get-Content -Raw -LiteralPath $defaultScript) -eq $defaultScriptContent) "$cwdScope leaves the inactive default script byte-for-byte unchanged"
        Check ((Get-Content -Raw -LiteralPath $defaultSettings) -eq $defaultSettingsContent) "$cwdScope leaves inactive default settings byte-for-byte unchanged"
        if ($cwdScope -eq 'project') {
            # The native PowerShell installer has never scanned project-local
            # predecessors; preserve that scope while shell installers retain
            # their existing project migration behavior.
            Check ((Get-Content -Raw -LiteralPath $projectScript) -eq '# project predecessor') 'distinct project predecessor script stays unchanged'
            Check ((Get-Content -Raw -LiteralPath $projectSettings) -eq $defaultSettingsContent) 'distinct project settings stay unchanged'
        }
    } finally {
        Pop-Location
        $env:CLAUDE_CONFIG_DIR = $null
        Remove-Item -Recurse -Force -LiteralPath $h4 -ErrorAction SilentlyContinue
    }
}

} finally { $env:CLAUDE_CONFIG_DIR = $savedClaudeConfigDir }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Remove-DcgPredecessor tests passed." -ForegroundColor Green
