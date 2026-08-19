#!/usr/bin/env pwsh
# Tests Add-DcgProfileCheck from install.ps1: appends a marker-guarded,
# syntactically-valid warning block to a PowerShell profile, idempotently.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_profile_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $profilePath = Join-Path $tmp 'sub\Microsoft.PowerShell_profile.ps1'  # parent dir must be created

    $s1 = Add-DcgProfileCheck -ProfilePath $profilePath
    Check ($s1 -eq 'added') "first run returns 'added' (got '$s1')"
    Check (Test-Path $profilePath) "profile created (incl. parent dir)"

    $content = Get-Content -Raw $profilePath
    Check ($content.Contains('# dcg: warn if the Claude Code hook')) "marker present"
    Check ($content.Contains('Hook missing from ~/.claude/settings.json')) "warning text present"

    $perr = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$perr)
    Check (($null -eq $perr) -or ($perr.Count -eq 0)) "appended profile parses as valid PowerShell"

    # --- Detection-expression coverage (issue #282) ---
    # The profile block must recognize every command shape dcg's installers
    # write, including the PowerShell quoted-invocation form `& '...' [args]`.
    # $detect mirrors the block's detection lines verbatim; the Contains checks
    # below pin the shipped block to this copy so they cannot drift apart.
    $detect = {
        param([string]$command)
        $dcgCmd = $command.Trim()
        if ($dcgCmd -match '^&\s*[''"](.+?)[''"]') { $dcgExe = $Matches[1] }
        else { $dcgExe = (($dcgCmd -split '\s+')[0]).Trim('"').Trim("'") }
        ((($dcgExe -split '[\\/]')[-1]) -replace '\.exe$','' -ieq 'dcg')
    }
    Check ($content.Contains('if ($dcgCmd -match ''^&\s*[''''"](.+?)[''''"]'') { $dcgExe = $Matches[1] }')) "profile block contains quoted-invocation branch"
    Check ($content.Contains('else { $dcgExe = (($dcgCmd -split ''\s+'')[0]).Trim(''"'').Trim("''") }')) "profile block contains bare-token branch"
    Check ($content.Contains('if ((($dcgExe -split ''[\\/]'')[-1]) -replace ''\.exe$'','''' -ieq ''dcg'') { $dcgHas = $true }')) "profile block contains leaf comparison"

    foreach ($case in @(
        "& 'C:\Users\x\.local\bin\dcg.exe' hook",
        "& 'C:\Users\x\.local\bin\dcg.exe'",
        '& "C:\Users\x\.local\bin\dcg.exe" hook',
        'C:\Users\x\.local\bin\dcg.exe',
        '/home/u/.local/bin/dcg',
        '"/home/u/.local/bin/dcg"',
        'dcg',
        'dcg.exe',
        'DCG.EXE'
    )) {
        Check (& $detect $case) "detects dcg hook command: $case"
    }
    foreach ($case in @(
        "& 'C:\tools\other.exe' hook",
        'notdcg.exe',
        '/usr/bin/notdcg',
        ''
    )) {
        Check (-not (& $detect $case)) "rejects non-dcg command: $case"
    }

    $s2 = Add-DcgProfileCheck -ProfilePath $profilePath
    Check ($s2 -eq 'already') "second run returns 'already' (got '$s2')"

    $count = ([regex]::Matches((Get-Content -Raw $profilePath), [regex]::Escape('# dcg: warn if the Claude Code hook'))).Count
    Check ($count -eq 1) "marker appears exactly once (idempotent)"

    # --- Stale-block replacement (issue #282 follow-up) ---
    # A profile carrying the pre-#282 block (same marker, naive path split) must
    # be repaired in place by a re-run, not skipped as "already".
    $staleBlock = @'
# dcg: warn if the Claude Code hook was silently removed
if ((Get-Command dcg -ErrorAction SilentlyContinue) -and (Test-Path "$HOME\.claude\settings.json")) {
  try {
    $dcgCfg = Get-Content -Raw "$HOME\.claude\settings.json" | ConvertFrom-Json
    $dcgHas = $false
    foreach ($dcgE in @($dcgCfg.hooks.PreToolUse)) {
      foreach ($dcgH in @($dcgE.hooks)) {
        if (((([string]$dcgH.command) -split '[\\/]')[-1]) -replace '\.exe$','' -ieq 'dcg') { $dcgHas = $true }
      }
    }
    if (-not $dcgHas) { Write-Host '[dcg] Hook missing from ~/.claude/settings.json - run: dcg install' -ForegroundColor Yellow }
  } catch { }
}
'@
    $stalePath = Join-Path $tmp 'stale_profile.ps1'
    Set-Content -Path $stalePath -Value ("# user stuff before`n" + $staleBlock + "`n# user stuff after")

    $s3 = Add-DcgProfileCheck -ProfilePath $stalePath
    Check ($s3 -eq 'updated') "stale pre-#282 block is replaced, returns 'updated' (got '$s3')"

    $staleContent = Get-Content -Raw $stalePath
    Check ($staleContent.Contains('if ($dcgCmd -match ''^&\s*[''''"](.+?)[''''"]'') { $dcgExe = $Matches[1] }')) "repaired profile contains current quoted-invocation branch"
    Check (-not $staleContent.Contains("if (((([string]`$dcgH.command) -split '[\\/]')[-1])")) "naive pre-#282 detection line removed"
    Check ($staleContent.Contains('# user stuff before')) "content before the block preserved"
    Check ($staleContent.Contains('# user stuff after')) "content after the block preserved"
    $staleCount = ([regex]::Matches($staleContent, [regex]::Escape('# dcg: warn if the Claude Code hook'))).Count
    Check ($staleCount -eq 1) "repaired profile has marker exactly once"
    $perr2 = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($staleContent, [ref]$null, [ref]$perr2)
    Check (($null -eq $perr2) -or ($perr2.Count -eq 0)) "repaired profile parses as valid PowerShell"

    $s4 = Add-DcgProfileCheck -ProfilePath $stalePath
    Check ($s4 -eq 'already') "repaired profile is stable on the next run (got '$s4')"

    # --- Cross-host repair ---
    # A stale block in the OTHER host's profile (e.g. WindowsPowerShell 5.1's
    # profile.ps1 while installing under pwsh 7) is repaired, but a profile
    # without the marker is never created or touched.
    $otherStale = Join-Path $tmp 'other_host_profile.ps1'
    Set-Content -Path $otherStale -Value $staleBlock
    $missingOther = Join-Path $tmp 'no_such_profile.ps1'
    $mainPath2 = Join-Path $tmp 'main_profile2.ps1'
    $s5 = Add-DcgProfileCheck -ProfilePath $mainPath2 -AlsoRepairPaths @($otherStale, $missingOther)
    Check ($s5 -eq 'added') "main profile added while repairing other host (got '$s5')"
    $otherContent = Get-Content -Raw $otherStale
    Check ($otherContent.Contains('if ($dcgCmd -match ''^&\s*[''''"](.+?)[''''"]'') { $dcgExe = $Matches[1] }')) "other host's stale block repaired"
    Check (-not (Test-Path $missingOther)) "non-existent other profile is not created"
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Add-DcgProfileCheck tests passed." -ForegroundColor Green
