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
$bin = $null
if ($env:DCG_TEST_BIN -and (Test-Path -LiteralPath $env:DCG_TEST_BIN)) { $bin = $env:DCG_TEST_BIN }
foreach ($candidate in @('target/debug/dcg.exe', 'target/debug/dcg', 'target/release/dcg.exe', 'target/release/dcg')) {
    if (-not $bin -and (Test-Path (Join-Path $repoRoot $candidate) -PathType Leaf)) { $bin = Join-Path $repoRoot $candidate }
}
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

Write-Host "Test 6: the bridge fails closed (#517): BOM payloads, unreadable payloads, dcg without a verdict"
# Feed the bridge raw bytes, the way cursor-agent does, under every PowerShell
# present: Windows PowerShell 5.1 (what hooks.json launches) decodes
# [Console]::In with the OEM code page, which is how a UTF-8 BOM broke the JSON.
function Invoke-Bridge([string]$Shell, [string]$Bridge, [byte[]]$Bytes, [hashtable]$Env = @{}) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Shell
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Bridge`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding $false
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $p.StandardInput.BaseStream.Write($Bytes, 0, $Bytes.Length)
    $p.StandardInput.Close()
    $p.WaitForExit()
    [pscustomobject]@{ Out = $outTask.Result; Err = $errTask.Result; Code = $p.ExitCode }
}
function Get-Permission($result) {
    try { ($result.Out | ConvertFrom-Json).permission } catch { "unparsable: $($result.Out)" }
}
$utf8 = New-Object System.Text.UTF8Encoding $false
$bom = [byte[]](0xEF, 0xBB, 0xBF)
$shells = @()
foreach ($name in @('powershell', 'pwsh')) {
    $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { $shells += $cmd.Source }
}
$h6 = New-TempHome
try {
    # Stand-ins for a dcg that ran but gave no verdict, one that denied and then
    # exited non-zero, and one that records the bytes it was sent.
    $fakes = Join-Path $h6 'fakes'
    New-Item -ItemType Directory -Path $fakes -Force | Out-Null
    $denyJson = '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"fake deny reason"}}'
    $fakeBodies = if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        @{
            'exit-nonzero.cmd' = "@exit /b 3"
            'exit-zero-silent.cmd' = "@exit /b 0"
            'exit-zero-garbage.cmd' = "@echo not a verdict"
            'deny-then-exit-nonzero.cmd' = "@echo $denyJson`r`n@exit /b 2"
            'capture.cmd' = "@findstr `"^`" > `"%DCG_FAKE_CAPTURE%`"`r`n@exit /b 3"
        }
    } else {
        @{
            'exit-nonzero' = "#!/bin/sh`ncat >/dev/null`nexit 3`n"
            'exit-zero-silent' = "#!/bin/sh`ncat >/dev/null`nexit 0`n"
            'exit-zero-garbage' = "#!/bin/sh`ncat >/dev/null`necho 'not a verdict'`n"
            'deny-then-exit-nonzero' = "#!/bin/sh`ncat >/dev/null`nprintf '%s\n' '$denyJson'`nexit 2`n"
            'capture' = "#!/bin/sh`ncat > `"`$DCG_FAKE_CAPTURE`"`nexit 3`n"
        }
    }
    foreach ($name in $fakeBodies.Keys) {
        $path = Join-Path $fakes $name
        [System.IO.File]::WriteAllText($path, $fakeBodies[$name])
        if (-not ($IsWindows -or $env:OS -eq 'Windows_NT')) { & chmod 755 $path }
    }
    $fake = { param($n) $p = Join-Path $fakes $n; if (Test-Path "$p.cmd") { "$p.cmd" } else { $p } }

    [void](Configure-CursorHook -DcgPath (& $fake 'exit-zero-silent') -HomeDir $h6)
    $bridge = Join-Path $h6 '.cursor/hooks/dcg-pre-shell.ps1'
    $safe = $utf8.GetBytes((@{ command = 'git status'; cwd = $h6 } | ConvertTo-Json -Compress))

    foreach ($shell in $shells) {
        $label = Split-Path -Leaf $shell
        foreach ($name in @('exit-nonzero', 'exit-zero-silent', 'exit-zero-garbage')) {
            $r = Invoke-Bridge $shell $bridge $safe @{ DCG_BIN = (& $fake $name) }
            Check ((Get-Permission $r) -eq 'deny') "[$label] dcg without a verdict ($name) -> deny (got '$(Get-Permission $r)')"
            Check ($r.Out -match 'could not be verified') "[$label] the block says why ($name)"
            $r = Invoke-Bridge $shell $bridge $safe @{ DCG_BIN = (& $fake $name); DCG_BRIDGE_CRASH_DECISION = ' Allow ' }
            Check ((Get-Permission $r) -eq 'allow') "[$label] DCG_BRIDGE_CRASH_DECISION=allow lets $name through"
        }
        $r = Invoke-Bridge $shell $bridge $safe @{ DCG_BIN = (& $fake 'deny-then-exit-nonzero'); DCG_BRIDGE_CRASH_DECISION = 'allow' }
        Check ((Get-Permission $r) -eq 'deny' -and $r.Out -match 'fake deny reason') "[$label] a deny survives a non-zero exit and the crash opt-out"

        foreach ($payload in @(
            @{ name = 'not JSON'; bytes = $utf8.GetBytes('{ not json') },
            @{ name = 'a JSON string'; bytes = $utf8.GetBytes('"git reset --hard"') },
            @{ name = 'a JSON array'; bytes = $utf8.GetBytes('[{"command":"git reset --hard"}]') },
            @{ name = 'empty'; bytes = [byte[]]@() }
        )) {
            $r = Invoke-Bridge $shell $bridge $payload.bytes @{ DCG_BIN = (& $fake 'exit-zero-silent') }
            Check ((Get-Permission $r) -eq 'deny') "[$label] an unreadable payload ($($payload.name)) -> deny (got '$(Get-Permission $r)')"
        }

        $r = Invoke-Bridge $shell $bridge $safe @{ DCG_BIN = (Join-Path $h6 'no-such-dcg.exe') }
        Check ((Get-Permission $r) -eq 'allow') "[$label] a dcg that cannot start fails open"
        Check ($r.Err -match 'could not run dcg') "[$label] and says so on stderr"

        # The bytes dcg receives: UTF-8, BOM stripped, non-ASCII intact.
        $capture = Join-Path $h6 "capture-$label.json"
        $accented = $utf8.GetBytes((@{ command = "echo caf$([char]0xE9)"; cwd = $h6 } | ConvertTo-Json -Compress))
        $r = Invoke-Bridge $shell $bridge ($bom + $accented) @{ DCG_BIN = (& $fake 'capture'); DCG_FAKE_CAPTURE = $capture }
        $sent = if (Test-Path $capture) { [System.IO.File]::ReadAllBytes($capture) } else { [byte[]]@() }
        $sentText = $utf8.GetString($sent)
        Check ($sentText -match "caf$([char]0xE9)") "[$label] dcg receives the command as UTF-8 (got '$sentText')"
        Check ($sentText -match '"dcg_explicit_verdict":\s*true') "[$label] the bridge asks dcg for an explicit verdict"
    }

    if ($bin) {
        [void](Configure-CursorHook -DcgPath $bin -HomeDir $h6 -Force)
        foreach ($shell in $shells) {
            $label = Split-Path -Leaf $shell
            $destructive = $utf8.GetBytes((@{ command = 'git stash clear'; cwd = $h6 } | ConvertTo-Json -Compress))
            $r = Invoke-Bridge $shell $bridge ($bom + $destructive) @{ HOME = $h6; USERPROFILE = $h6; DCG_NO_SELF_HEAL = '1' }
            Check ((Get-Permission $r) -eq 'deny') "[$label] a BOM-prefixed destructive payload -> deny with the real dcg (got '$(Get-Permission $r)')"
            $r = Invoke-Bridge $shell $bridge ($bom + $safe) @{ HOME = $h6; USERPROFILE = $h6; DCG_NO_SELF_HEAL = '1' }
            Check ((Get-Permission $r) -eq 'allow') "[$label] a BOM-prefixed safe payload -> allow with the real dcg (got '$(Get-Permission $r)')"
        }
    } else { Write-Host "  (skip real-dcg BOM cases: no dcg binary built)" -ForegroundColor Yellow }
} finally { Remove-Item -Recurse -Force $h6 -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Configure-CursorHook tests passed." -ForegroundColor Green
