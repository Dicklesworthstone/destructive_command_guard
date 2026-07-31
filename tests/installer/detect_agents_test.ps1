#!/usr/bin/env pwsh
# Tests install.ps1 Detect-Agents / Get-DetectedAgentNames: agent detection by
# config dir (under -HomeDir), order of the summary, and the empty case. PATH is
# cleared so on-PATH CLI probing (claude/codex/gemini/copilot/gh-copilot/agy) does not
# leak the host's real tools into the result.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

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
try {
    $env:PATH = ''                 # no CLI probing leaks
    $env:GROK_SESSION_ID = $null

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
    Check ($a1c['Posit'] -eq $false) "Posit NOT detected from ~/.posit alone (other Posit tools use it too)"
    Remove-Item -Recurse -Force $h1c -ErrorAction SilentlyContinue

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
} finally {
    $env:PATH = $savedPath
    $env:GROK_SESSION_ID = $savedGrok
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Detect-Agents tests passed." -ForegroundColor Green
