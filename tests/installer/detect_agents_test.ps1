#!/usr/bin/env pwsh
# Tests install.ps1 Detect-Agents / Get-DetectedAgentNames: agent detection by
# config dir (under -HomeDir), order of the summary, and the empty case. PATH is
# cleared so on-PATH CLI probing (claude/codex/gemini/copilot/gh-copilot/agy) does not
# leak the host's real tools into the result.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_detect_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}

$savedPath = $env:PATH
$savedGrok = $env:GROK_SESSION_ID
$savedHermesHome = $env:HERMES_HOME
$savedLocalAppData = $env:LOCALAPPDATA
$savedOs = $env:OS
$ompSelectorNames = @('OMP_PROFILE', 'PI_PROFILE', 'PI_CONFIG_DIR', 'PI_CODING_AGENT_DIR')
$savedOmpSelectors = @{}
foreach ($name in $ompSelectorNames) {
    $savedOmpSelectors[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    # Seed a non-vacuous ambient value before proving the fixture fence clears
    # it. This catches a missing scrub even on otherwise clean CI hosts.
    Microsoft.PowerShell.Management\Set-Item -LiteralPath "Env:$name" -Value "dcg-test-ambient-$name"
}
foreach ($name in $ompSelectorNames) {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
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

    $env:PATH = ''                 # no CLI probing leaks
    $env:GROK_SESSION_ID = $null
    $env:HERMES_HOME = $null       # no Hermes home-resolution leaks (issue #270)
    $env:LOCALAPPDATA = $null
    $env:OS = $null
    $env:PI_CONFIG_DIR = $null
    $env:CRUSH_GLOBAL_CONFIG = $null  # no Crush config-path override leaks (#388)
    $env:XDG_CONFIG_HOME = $null

    Write-Host "Test 1: detects only the agents whose config dir is present"
    $h1 = New-TempHome
    New-Item -ItemType Directory -Path (Join-Path $h1 '.claude') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $h1 '.gemini') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $h1 '.grok')   | Out-Null
    $a = Detect-Agents -HomeDir $h1
    Check ($a['Claude'] -eq $true) "Claude detected (~/.claude present)"
    Check ($a['Gemini'] -eq $true) "Gemini detected (~/.gemini present)"
    Check ($a['Grok'] -eq $true) "Grok detected (~/.grok present)"
    Check ($a['Codex'] -eq $false) "Codex NOT detected (no ~/.codex, no codex on PATH)"
    Check ($a['Cursor'] -eq $false) "Cursor NOT detected"
    Check ($a['Copilot'] -eq $false) "Copilot NOT detected (no ~/.copilot, no copilot CLI)"
    Check ($a['Agy'] -eq $false) "Agy NOT detected (no agy on PATH)"
    Check ($a['Hermes'] -eq $false) "Hermes NOT detected"
    Check ($a['Posit'] -eq $false) "Posit Assistant NOT detected"
    Check ($a['Omp'] -eq $false) "Oh My Pi NOT detected"
    Check ($a['Crush'] -eq $false) "Crush NOT detected (no ~/.config/crush, no crush on PATH)"
    $names = Get-DetectedAgentNames $a
    Check (($names -join ',') -eq 'Claude,Gemini,Grok') "summary lists detected agents in config order (got '$($names -join ',')')"
    Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue

    Write-Host "Test 1b: Posit Assistant detected from ~/.posit/assistant"
    $h1b = New-TempHome
    New-Item -ItemType Directory -Force -Path (Join-Path (Join-Path $h1b '.posit') 'assistant') | Out-Null
    $a1b = Detect-Agents -HomeDir $h1b
    Check ($a1b['Posit'] -eq $true) "Posit detected (~/.posit/assistant present)"
    $names1b = Get-DetectedAgentNames $a1b
    Check (($names1b -join ',') -eq 'Posit') "summary lists only Posit (got '$($names1b -join ',')')"
    Remove-Item -Recurse -Force $h1b -ErrorAction SilentlyContinue

    Write-Host "Test 1c: a bare ~/.posit directory is not enough"
    $h1c = New-TempHome
    New-Item -ItemType Directory -Force -Path (Join-Path $h1c '.posit') | Out-Null
    $a1c = Detect-Agents -HomeDir $h1c
    Check ($a1c['Posit'] -eq $false) "Posit NOT detected from ~/.posit alone (other Posit tools share it)"
    Remove-Item -Recurse -Force $h1c -ErrorAction SilentlyContinue

    Write-Host "Test 1d: legacy ~/.positai counts as Posit Assistant"
    $h1d = New-TempHome
    New-Item -ItemType Directory -Force -Path (Join-Path $h1d '.positai') | Out-Null
    $a1d = Detect-Agents -HomeDir $h1d
    Check ($a1d['Posit'] -eq $true) "Posit detected via legacy ~/.positai"
    Remove-Item -Recurse -Force $h1d -ErrorAction SilentlyContinue

    Write-Host "Test 1e: Oh My Pi detected from ~/.omp"
    $h1e = New-TempHome
    New-Item -ItemType Directory -Force -Path (Join-Path $h1e '.omp') | Out-Null
    $a1e = Detect-Agents -HomeDir $h1e
    Check ($a1e['Omp'] -eq $true) "Oh My Pi detected via ~/.omp"
    $names1e = Get-DetectedAgentNames $a1e
    Check (($names1e -join ',') -eq 'Omp') "summary lists only Omp (got '$($names1e -join ',')')"
    Remove-Item -Recurse -Force $h1e -ErrorAction SilentlyContinue

    Write-Host "Test 1g: Crush detected from ~/.config/crush"
    $h1g = New-TempHome
    New-Item -ItemType Directory -Force -Path (Join-Path (Join-Path $h1g '.config') 'crush') | Out-Null
    $a1g = Detect-Agents -HomeDir $h1g
    Check ($a1g['Crush'] -eq $true) "Crush detected via ~/.config/crush"
    $names1g = Get-DetectedAgentNames $a1g
    Check (($names1g -join ',') -eq 'Crush') "summary lists only Crush (got '$($names1g -join ',')')"
    Remove-Item -Recurse -Force $h1g -ErrorAction SilentlyContinue

    Write-Host "Test 1h: Crush detected from the CRUSH_GLOBAL_CONFIG directory override"
    $h1h = New-TempHome
    $crushOverride = Join-Path $h1h 'crush-global'
    New-Item -ItemType Directory -Force -Path $crushOverride | Out-Null
    $env:CRUSH_GLOBAL_CONFIG = $crushOverride
    $a1h = Detect-Agents -HomeDir $h1h
    Check ($a1h['Crush'] -eq $true) "Crush detected via CRUSH_GLOBAL_CONFIG"
    $env:CRUSH_GLOBAL_CONFIG = $null
    Remove-Item -Recurse -Force $h1h -ErrorAction SilentlyContinue

    Write-Host "Test 1f: Oh My Pi detected from PI_CONFIG_DIR"
    $h1f = New-TempHome
    $env:PI_CONFIG_DIR = '.custom-omp'
    New-Item -ItemType Directory -Force -Path (Join-Path $h1f '.custom-omp') | Out-Null
    $a1f = Detect-Agents -HomeDir $h1f
    Check ($a1f['Omp'] -eq $true) "Oh My Pi detected via PI_CONFIG_DIR"
    $env:PI_CONFIG_DIR = $null
    Remove-Item -Recurse -Force $h1f -ErrorAction SilentlyContinue

    Write-Host "Test 1g: Oh My Pi detection treats wildcard characters in HOME literally"
    $h1g = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_detect_[omp]_" + [Guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory((Join-Path $h1g '.omp'))
    $a1g = Detect-Agents -HomeDir $h1g
    Check ($a1g['Omp'] -eq $true) "Oh My Pi detected when HOME contains brackets"

    Write-Host "Test 1h: Windows drive-qualified PI_CONFIG_DIR cannot escape HOME"
    $env:PI_CONFIG_DIR = 'C:\omp-outside-home'
    Check ($null -eq (Get-OmpConfigRootForDetection -HomeDir $h1g -WindowsSemantics $true)) "drive-qualified OMP config root rejected for Windows detection"

    Write-Host "Test 1i: OMP detection config root follows native Node path joining"
    $nativeWindows = [System.IO.Path]::DirectorySeparatorChar -eq '\'
    $oracleHome = if ($nativeWindows) { 'C:\Users\u' } else { '/home/u' }
    $env:PI_CONFIG_DIR = 'outer/../normalized-omp'
    $normalizedRoot = Get-OmpConfigRootForDetection -HomeDir $oracleHome -WindowsSemantics $nativeWindows
    $expectedNormalizedRoot = if ($nativeWindows) { 'C:\Users\u\normalized-omp' } else { '/home/u/normalized-omp' }
    Check ([string]::Equals($normalizedRoot, $expectedNormalizedRoot, [System.StringComparison]::Ordinal)) "detection normalizes dot and parent components"
    $env:PI_CONFIG_DIR = '../../../../../../../../../../../../x'
    $clampedRoot = Get-OmpConfigRootForDetection -HomeDir $oracleHome -WindowsSemantics $nativeWindows
    $expectedClampedRoot = if ($nativeWindows) { 'C:\x' } else { '/x' }
    Check ([string]::Equals($clampedRoot, $expectedClampedRoot, [System.StringComparison]::Ordinal)) "detection clamps excess parent components at the filesystem root"
    if (-not $nativeWindows) {
        $env:PI_CONFIG_DIR = '\.literal-backslash'
        $backslashRoot = Get-OmpConfigRootForDetection -HomeDir $oracleHome -WindowsSemantics $false
        Check ([string]::Equals($backslashRoot, '/home/u/\.literal-backslash', [System.StringComparison]::Ordinal)) "POSIX detection preserves leading backslash literally (got '$backslashRoot')"

        $backslashHome = New-TempHome
        try {
            $literalConfigRoot = [System.IO.Path]::Combine($backslashHome, '\.literal-backslash')
            $normalizedDecoyRoot = [System.IO.Path]::Combine($backslashHome, '.literal-backslash')
            [void][System.IO.Directory]::CreateDirectory($literalConfigRoot)
            $literalAgents = Detect-Agents -HomeDir $backslashHome
            Check ($literalAgents['Omp'] -eq $true) "POSIX detection finds the literal-backslash config root"

            [System.IO.Directory]::Delete($literalConfigRoot, $true)
            [void][System.IO.Directory]::CreateDirectory($normalizedDecoyRoot)
            $decoyAgents = Detect-Agents -HomeDir $backslashHome
            Check ($decoyAgents['Omp'] -eq $false) "POSIX detection does not probe a separator-normalized decoy"
        } finally {
            if ([System.IO.Directory]::Exists($backslashHome)) {
                [System.IO.Directory]::Delete($backslashHome, $true)
            }
        }
    }
    $env:PI_CONFIG_DIR = $null
    $names1g = Get-DetectedAgentNames $a1g
    Check (($names1g -join ',') -eq 'Omp') "bracketed HOME summary lists only Omp (got '$($names1g -join ',')')"
    Remove-Item -LiteralPath $h1g -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Test 2: empty home -> nothing detected"
    $h2 = New-TempHome
    $a2 = Detect-Agents -HomeDir $h2
    $names2 = Get-DetectedAgentNames $a2
    Check ($names2.Count -eq 0) "no agents detected in an empty home (got '$($names2 -join ',')')"
    Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue

    Write-Host "Test 3: repo root alone does not make Copilot detected"
    $h3 = New-TempHome
    $a3 = Detect-Agents -HomeDir $h3 -RepoRoot $h3
    Check ($a3['Copilot'] -eq $false) "Copilot not detected from repo root alone"
    New-Item -ItemType Directory -Path (Join-Path $h3 '.copilot') | Out-Null
    $a3WithCopilot = Detect-Agents -HomeDir $h3 -RepoRoot $h3
    Check ($a3WithCopilot['Copilot'] -eq $true) "Copilot detected from ~/.copilot"
    Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue

    Write-Host "Test 4: GROK_SESSION_ID env triggers Grok detection without ~/.grok"
    $h4 = New-TempHome
    $env:GROK_SESSION_ID = 'sess-123'
    $a4 = Detect-Agents -HomeDir $h4
    Check ($a4['Grok'] -eq $true) "Grok detected via GROK_SESSION_ID env"
    $env:GROK_SESSION_ID = $null
    Remove-Item -Recurse -Force $h4 -ErrorAction SilentlyContinue

    Write-Host "Test 5: native-Windows Hermes (%LOCALAPPDATA%\hermes) detected without ~/.hermes (issue #270)"
    $h5 = New-TempHome
    $lad5 = Join-Path $h5 'AppData/Local'
    New-Item -ItemType Directory -Force -Path (Join-Path $lad5 'hermes') | Out-Null
    $env:OS = 'Windows_NT'
    $env:LOCALAPPDATA = $lad5
    $a5 = Detect-Agents -HomeDir $h5
    Check ($a5['Hermes'] -eq $true) "Hermes detected via LOCALAPPDATA\hermes"
    $env:OS = $null
    $env:LOCALAPPDATA = $null
    $a5b = Detect-Agents -HomeDir $h5
    Check ($a5b['Hermes'] -eq $false) "Hermes NOT detected once the native dir is out of scope"
    Remove-Item -Recurse -Force $h5 -ErrorAction SilentlyContinue
} finally {
    $env:PATH = $savedPath
    $env:GROK_SESSION_ID = $savedGrok
    $env:HERMES_HOME = $savedHermesHome
    $env:LOCALAPPDATA = $savedLocalAppData
    $env:OS = $savedOs
    foreach ($name in $ompSelectorNames) {
        if ($null -eq $savedOmpSelectors[$name]) {
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        } else {
            Microsoft.PowerShell.Management\Set-Item -LiteralPath "Env:$name" -Value $savedOmpSelectors[$name]
        }
    }
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Detect-Agents tests passed." -ForegroundColor Green
