#!/usr/bin/env pwsh
# Tests Configure-CopilotHook from install.ps1: user-level hooks/dcg.json
# with preToolUse[] entries carrying bash+powershell platform fields. Verifies
# create/idempotent/merge, field-level dedup (preserves a coexisting platform
# hook sharing an entry with dcg), and COPILOT_HOME behavior.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempRepo {
    $r = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_copilot_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $r | Out-Null
    $r
}
$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'

Write-Host "Test 1: create (bash+powershell+cwd+timeoutSec) + idempotent"
$r1 = New-TempRepo
try {
    $s = Configure-CopilotHook -DcgPath $dcgPath -CopilotHome $r1
    Check ($s -eq 'created') "create returns 'created' (got '$s')"
    $f = Join-Path $r1 'hooks/dcg.json'
    Check (Test-Path $f) "user-level hooks/dcg.json created"
    $p = Get-Content -Raw $f | ConvertFrom-Json
    Check ($p.version -eq 1) "version=1"
    $e = $p.hooks.preToolUse[0]
    Check ($e.bash -eq $dcgPath) "bash field = dcg path"
    Check ($e.powershell -eq $dcgPath) "powershell field = dcg path (Windows support)"
    Check ($e.cwd -eq '.') "cwd = ."
    Check ($e.timeoutSec -eq 30) "timeoutSec = 30"
    $s2 = Configure-CopilotHook -DcgPath $dcgPath -CopilotHome $r1
    Check ($s2 -eq 'already') "idempotent returns 'already' (got '$s2')"
} finally { Remove-Item -Recurse -Force $r1 -ErrorAction SilentlyContinue }

Write-Host "Test 2: merge - field-level dedup preserves a coexisting platform hook"
$r2 = New-TempRepo
try {
    $hookDir = Join-Path $r2 'hooks'; New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
    $existing = [ordered]@{
        version = 1
        hooks = [ordered]@{
            preToolUse = @(
                [ordered]@{ type = 'command'; bash = '/old/bin/dcg'; powershell = 'my-formatter' },
                [ordered]@{ type = 'command'; bash = 'linter'; powershell = 'linter.exe' }
            )
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $hookDir 'dcg.json')
    $s = Configure-CopilotHook -DcgPath $dcgPath -CopilotHome $r2
    Check ($s -eq 'merged') "returns 'merged' (got '$s')"
    $p = Get-Content -Raw (Join-Path $hookDir 'dcg.json') | ConvertFrom-Json
    Check ($p.hooks.preToolUse[0].bash -eq $dcgPath) "canonical dcg entry prepended (first)"
    # the entry that had bash=dcg + powershell=my-formatter: bash stripped, powershell kept
    $kept = @($p.hooks.preToolUse | Where-Object { $_.powershell -eq 'my-formatter' })[0]
    Check ($null -ne $kept) "entry with non-dcg powershell preserved"
    Check ($null -eq $kept.PSObject.Properties['bash']) "the dcg 'bash' field was stripped from that entry"
    # the fully-coexisting linter entry preserved intact
    $linter = @($p.hooks.preToolUse | Where-Object { $_.powershell -eq 'linter.exe' })[0]
    Check (($null -ne $linter) -and ($linter.bash -eq 'linter')) "coexisting non-dcg entry preserved intact"
} finally { Remove-Item -Recurse -Force $r2 -ErrorAction SilentlyContinue }

Write-Host "Test 3: COPILOT_HOME works outside a git repository"
$r3 = New-TempRepo
$savedHome = $env:COPILOT_HOME
try {
    $env:COPILOT_HOME = $r3
    $s = Configure-CopilotHook -DcgPath $dcgPath
    Check ($s -eq 'created') "creates user-level hook without git (got '$s')"
    Check (Test-Path (Join-Path $r3 'hooks/dcg.json')) "honors COPILOT_HOME"
} finally {
    $env:COPILOT_HOME = $savedHome
    Remove-Item -Recurse -Force $r3 -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Configure-CopilotHook tests passed." -ForegroundColor Green
