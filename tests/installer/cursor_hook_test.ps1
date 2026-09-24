#!/usr/bin/env pwsh
# Tests Configure-CursorHook from install.ps1: PowerShell bridge (no Python) +
# ~/.cursor/hooks.json merge (dcg first in beforeShellExecution, dup-collapse,
# coexisting-preserve, idempotent, UTF-8 no BOM, refuse-invalid). Also runs the
# generated bridge end-to-end against the real dcg binary to confirm it translates
# Cursor's {command,cwd} payload and maps deny/allow correctly.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_cursor_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $h ".cursor") -Force | Out-Null  # make Cursor "detected"
    $h
}
function Test-NoBom([string]$p) {
    $b = [System.IO.File]::ReadAllBytes($p)
    -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}
$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

Write-Host "Test 1: create bridge + hooks.json, idempotent"
$h1 = New-TempHome
try {
    $s = Configure-CursorHook -DcgPath $dcgPath -HomeDir $h1
    Check ($s -eq 'created') "create returns 'created' (got '$s')"
    $bridge = Join-Path $h1 '.cursor/hooks/dcg-pre-shell.ps1'
    Check (Test-Path $bridge) "bridge dcg-pre-shell.ps1 created"
    Check (Test-NoBom $bridge) "bridge has no UTF-8 BOM"
    Check ((Get-Content -Raw $bridge) -match 'dcg-cursor-hook') "bridge has marker"
    Check ((Get-Content -Raw $bridge) -notmatch 'python') "bridge is PowerShell (no python)"
    $hooksFile = Join-Path $h1 '.cursor/hooks.json'
    Check (Test-Path $hooksFile) "hooks.json created"
    Check (Test-NoBom $hooksFile) "hooks.json has no UTF-8 BOM"
    $cfg = Get-Content -Raw $hooksFile | ConvertFrom-Json
    Check ($cfg.version -eq 1) "version = 1"
    Check ($cfg.hooks.beforeShellExecution[0].command -match 'dcg-pre-shell\.ps1') "dcg bridge is first in beforeShellExecution"
    Check ($cfg.hooks.beforeShellExecution[0].command -match 'powershell -NoProfile') "uses powershell -NoProfile launcher"
    $s2 = Configure-CursorHook -DcgPath $dcgPath -HomeDir $h1
    Check ($s2 -eq 'already') "idempotent returns 'already' (got '$s2')"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

Write-Host "Test 2: merge preserves a coexisting hook + hoists dcg first, collapses dup"
$h2 = New-TempHome
try {
    $cursorDir = Join-Path $h2 '.cursor'
    $existing = [ordered]@{
        version = 1
        hooks = [ordered]@{
            beforeShellExecution = @(
                [ordered]@{ command = 'other-tool --check' },
                [ordered]@{ command = 'powershell -NoProfile -ExecutionPolicy Bypass -File "stale"' }
            )
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cursorDir 'hooks.json')
    $s = Configure-CursorHook -DcgPath $dcgPath -HomeDir $h2
    Check ($s -eq 'merged') "returns 'merged' (got '$s')"
    $cfg = Get-Content -Raw (Join-Path $cursorDir 'hooks.json') | ConvertFrom-Json
    Check ($cfg.hooks.beforeShellExecution[0].command -match 'dcg-pre-shell\.ps1') "dcg hoisted first"
    $cmds = @($cfg.hooks.beforeShellExecution | ForEach-Object { $_.command })
    Check ($cmds -contains 'other-tool --check') "coexisting non-dcg hook preserved"
    Check ((@($cmds | Where-Object { $_ -match 'dcg-pre-shell' })).Count -eq 1) "exactly one dcg entry (dup collapsed)"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

Write-Host "Test 3: conflict (foreign script at bridge path) + invalid JSON"
$h3 = New-TempHome
try {
    $hookDir = Join-Path $h3 '.cursor/hooks'; New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
    Set-Content -Path (Join-Path $hookDir 'dcg-pre-shell.ps1') -Value '# someone-elses script'
    Check ((Configure-CursorHook -DcgPath $dcgPath -HomeDir $h3) -eq 'conflict') "foreign bridge -> conflict"
} finally { Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }
$h3b = New-TempHome
try {
    Set-Content -Path (Join-Path $h3b '.cursor/hooks.json') -Value '{ not json'
    Check ((Configure-CursorHook -DcgPath $dcgPath -HomeDir $h3b) -eq 'invalid') "invalid hooks.json -> invalid"
} finally { Remove-Item -Recurse -Force $h3b -ErrorAction SilentlyContinue }

Write-Host "Test 4: skipped when Cursor absent and not -Force"
$h4 = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_cursor_none_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $h4 | Out-Null
$savedPath = $env:PATH
try {
    $env:PATH = ''
    Check ((Configure-CursorHook -DcgPath $dcgPath -HomeDir $h4) -eq 'skipped') "no ~/.cursor + no cursor on PATH -> skipped"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h4 -ErrorAction SilentlyContinue }

Write-Host "Test 5: generated bridge translates Cursor payload + maps deny/allow (real binary)"
$bin = if (Test-Path (Join-Path $repoRoot 'target/debug/dcg')) { Join-Path $repoRoot 'target/debug/dcg' }
       elseif (Test-Path (Join-Path $repoRoot 'target/release/dcg')) { Join-Path $repoRoot 'target/release/dcg' }
       else { $null }
if (-not $bin) { Write-Host "  (skip: no dcg binary built)" -ForegroundColor Yellow }
else {
    $h5 = New-TempHome
    try {
        [void](Configure-CursorHook -DcgPath $bin -HomeDir $h5)
        $bridge = Join-Path $h5 '.cursor/hooks/dcg-pre-shell.ps1'
        $deny = (@{ command = 'git reset --hard'; cwd = $h5 } | ConvertTo-Json -Compress | pwsh -NoProfile -File $bridge | Out-String)
        $d = $deny | ConvertFrom-Json
        Check ($d.permission -eq 'deny') "destructive command -> Cursor permission=deny (got '$($d.permission)')"
        Check ($d.continue -eq $false) "deny sets continue=false"
        Check (-not [string]::IsNullOrWhiteSpace($d.userMessage)) "deny carries a userMessage"
        $allow = (@{ command = 'git status'; cwd = $h5 } | ConvertTo-Json -Compress | pwsh -NoProfile -File $bridge | Out-String)
        $a = $allow | ConvertFrom-Json
        Check ($a.permission -eq 'allow') "safe command -> Cursor permission=allow (got '$($a.permission)')"
        # A command over max_command_bytes is unverified: dcg answers ask, and
        # the bridge must pass that through rather than allow it.
        $long = 'echo ' + ('x' * 71680)
        $askOut = (@{ command = $long; cwd = $h5 } | ConvertTo-Json -Compress | pwsh -NoProfile -File $bridge | Out-String)
        $k = $askOut | ConvertFrom-Json
        Check ($k.permission -eq 'ask') "unverified command -> Cursor permission=ask (got '$($k.permission)')"
    } finally { Remove-Item -Recurse -Force $h5 -ErrorAction SilentlyContinue }
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Configure-CursorHook tests passed." -ForegroundColor Green
