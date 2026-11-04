#!/usr/bin/env pwsh
# Tests Assert-ZipLayoutSafe from install.ps1 (zip-slip / path-traversal defense).
# Dot-sources install.ps1 -LoadFunctionsOnly and feeds it crafted archives.

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_zipslip_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

function New-TestZip([string[]]$EntryNames) {
    $path = Join-Path $tmp ("z_" + [Guid]::NewGuid().ToString('N') + ".zip")
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
    $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $EntryNames) {
            $e = $zip.CreateEntry($name)
            $w = New-Object System.IO.StreamWriter($e.Open())
            $w.Write("x"); $w.Dispose()
        }
    } finally { $zip.Dispose(); $fs.Dispose() }
    $path
}
function New-SymlinkZip {
    $path = Join-Path $tmp ("z_" + [Guid]::NewGuid().ToString('N') + ".zip")
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
    $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $e = $zip.CreateEntry('dcg.exe')
        # Unix mode 0120777 in the upper 16 bits marks this ZIP entry as a symlink.
        $e.ExternalAttributes = -1577123840
        $w = New-Object System.IO.StreamWriter($e.Open())
        $w.Write('target.exe'); $w.Dispose()
    } finally { $zip.Dispose(); $fs.Dispose() }
    # ZipArchive writes a Windows "version made by" host byte even when Unix
    # mode bits are supplied. Windows tar.exe therefore treats the fixture as a
    # regular file unless the central-directory creator is made authentically
    # Unix (host 3). Patch only that metadata byte in this one-entry test ZIP.
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($path)
    $patchedCreator = $false
    for ($i = 0; $i -le ($bytes.Length - 6); $i++) {
        if ($bytes[$i] -eq 0x50 -and $bytes[$i + 1] -eq 0x4B -and
            $bytes[$i + 2] -eq 0x01 -and $bytes[$i + 3] -eq 0x02) {
            $bytes[$i + 5] = 3
            $patchedCreator = $true
            break
        }
    }
    if (-not $patchedCreator) { throw 'test ZIP central directory was not found' }
    [System.IO.File]::WriteAllBytes($path, $bytes)
    $path
}
function ShouldThrow([string]$zip, [string]$why) {
    $threw = $false
    try { Assert-ZipLayoutSafe -ZipPath $zip } catch { $threw = $true }
    Check $threw $why
}
function ShouldPass([string]$zip, [string]$why) {
    $ok = $true
    try { Assert-ZipLayoutSafe -ZipPath $zip } catch { $ok = $false; Write-Host "    (threw: $_)" }
    Check $ok $why
}

function New-TarApplicationMock {
    if ($env:OS -eq 'Windows_NT') {
        $path = Join-Path $tmp 'tar-scope.cmd'
        $body = @'
@echo off
if "%~1"=="-tf" goto list
if "%~1"=="-tvf" goto details
if "%~1"=="-xf" goto extract
exit /b 64
:list
echo dcg.exe
exit /b %DCG_MOCK_TAR_LIST_EXIT%
:details
echo -rw-r--r-- root/root 1 2026-01-01 00:00 dcg.exe
exit /b %DCG_MOCK_TAR_DETAILS_EXIT%
:extract
echo extracted
exit /b %DCG_MOCK_TAR_EXTRACT_EXIT%
'@
    } else {
        $path = Join-Path $tmp 'tar-scope'
        $body = @'
#!/bin/sh
case "$1" in
  -tf) printf '%s\n' 'dcg.exe'; exit "$DCG_MOCK_TAR_LIST_EXIT" ;;
  -tvf) printf '%s\n' '-rw-r--r-- root/root 1 2026-01-01 00:00 dcg.exe'; exit "$DCG_MOCK_TAR_DETAILS_EXIT" ;;
  -xf) printf '%s\n' 'extracted'; exit "$DCG_MOCK_TAR_EXTRACT_EXIT" ;;
  *) exit 64 ;;
esac
'@
    }
    Set-Content -LiteralPath $path -Value ($body -replace "`r`n", "`n") -Encoding ascii
    if ($env:OS -ne 'Windows_NT') {
        & chmod +x $path
        if ($global:LASTEXITCODE -ne 0) { throw 'could not make mock tar executable' }
    }
    return $path
}

function Invoke-ArchiveInspectionFromFunction([int]$LocalExit, [int]$PreviousExit) {
    # Only replace trusted-command lookup; listing still runs a native process.
    function Get-TrustedTarCommand { Get-Command $tarMock -CommandType Application -ErrorAction Stop }
    $LASTEXITCODE = $LocalExit
    $global:LASTEXITCODE = $PreviousExit
    $failure = $null
    try { Assert-ZipLayoutSafe -ZipPath $scopeZip } catch { $failure = $_.Exception.Message }
    [pscustomobject]@{ Failure = $failure }
}

try {
    ShouldPass  (New-TestZip @('dcg.exe'))                              "flat archive with dcg.exe is accepted"
    ShouldThrow (New-TestZip @('dcg-x86_64-pc-windows-msvc/dcg.exe'))   "rejects a nested dcg.exe"
    ShouldThrow (New-TestZip @('dcg.exe', 'README.txt'))                "rejects extra archive members"
    ShouldThrow (New-TestZip @('dcg.exe/'))                             "rejects a directory named dcg.exe"
    ShouldThrow (New-SymlinkZip)                                        "rejects a symlink named dcg.exe"
    ShouldThrow (New-TestZip @('DCG.EXE'))                              "requires the canonical member name"
    ShouldThrow (New-TestZip @('../evil.exe', 'dcg.exe'))               "rejects a '..' traversal entry"
    ShouldThrow (New-TestZip @('sub/../../evil', 'dcg.exe'))            "rejects an embedded '..' segment"
    ShouldThrow (New-TestZip @('/etc/cron.d/evil', 'dcg.exe'))          "rejects an absolute (/) path"
    ShouldThrow (New-TestZip @('C:\Windows\System32\evil.exe', 'dcg.exe')) "rejects a drive-letter path"
    ShouldThrow (New-TestZip @())                                       "rejects an empty archive"
    ShouldThrow (New-TestZip @('README.txt'))                           "rejects an archive missing dcg.exe"

    Write-Host 'Native tar scope checks: plausible output never overrides a failed process'
    $scopeZip = New-TestZip @('dcg.exe')
    $tarMock = New-TarApplicationMock
    $env:DCG_MOCK_TAR_LIST_EXIT = '0'
    $env:DCG_MOCK_TAR_DETAILS_EXIT = '0'
    $scopeSuccess = Invoke-ArchiveInspectionFromFunction -LocalExit -1 -PreviousExit 37
    Check (-not $scopeSuccess.Failure) 'successful native inspection ignores caller-local/stale failure statuses'
    $env:DCG_MOCK_TAR_LIST_EXIT = '19'
    $listFailure = Invoke-ArchiveInspectionFromFunction -LocalExit 0 -PreviousExit 0
    Check ($listFailure.Failure -ceq 'Refusing to extract: tar.exe could not inspect the archive') `
        'dcg.exe listing from native exit 19 is rejected despite caller-local/stale success'
    $env:DCG_MOCK_TAR_LIST_EXIT = '0'
    $env:DCG_MOCK_TAR_DETAILS_EXIT = '23'
    $detailsFailure = Invoke-ArchiveInspectionFromFunction -LocalExit 0 -PreviousExit 0
    Check ($detailsFailure.Failure -ceq 'Refusing to extract: tar.exe could not inspect the archive member type') `
        'regular-file details from native exit 23 are rejected despite caller-local/stale success'

    # ConstrainedLanguage is intentionally isolated in a child host so this
    # tests the actual extraction branch on both Windows and PowerShell Core.
    $tarProbe = Join-Path $tmp 'tar-extraction-scope.ps1'
    @'
param([string]$InstallPath, [string]$TarPath, [string]$ZipPath, [string]$DestinationPath)
$ErrorActionPreference = 'Stop'
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
. $InstallPath -LoadFunctionsOnly
function Get-TrustedTarCommand { Get-Command $TarPath -CommandType Application -ErrorAction Stop }
function Invoke-ScopedExtraction([int]$LocalExit, [bool]$ShouldFail) {
    $LASTEXITCODE = $LocalExit
    $global:LASTEXITCODE = 37
    $failure = $null
    try { Expand-DcgArchive -ZipPath $ZipPath -DestinationPath $DestinationPath | Out-Null }
    catch { $failure = $_.Exception.Message }
    if ($ShouldFail) {
        if ($failure -cne 'tar.exe failed to extract the verified archive') {
            throw "unexpected native extraction result: $failure"
        }
    } elseif ($failure) {
        throw "successful extraction was rejected: $failure"
    }
}
$env:DCG_MOCK_TAR_EXTRACT_EXIT = '0'
Invoke-ScopedExtraction -LocalExit -1 -ShouldFail $false
'extract-success'
$env:DCG_MOCK_TAR_EXTRACT_EXIT = '19'
Invoke-ScopedExtraction -LocalExit 0 -ShouldFail $true
'extract-failure'
'@ | Set-Content -LiteralPath $tarProbe -Encoding UTF8
    $currentPowerShell = (Get-Process -Id $PID).Path
    $global:LASTEXITCODE = -1
    $extractionResults = @(& $currentPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tarProbe `
        -InstallPath (Join-Path $repoRoot 'install.ps1') -TarPath $tarMock -ZipPath $scopeZip `
        -DestinationPath (Join-Path $tmp 'tar-extract'))
    $extractionProbeExit = $global:LASTEXITCODE
    Check (($extractionProbeExit -eq 0) -and ($extractionResults -contains 'extract-success')) `
        'ConstrainedLanguage extraction accepts native success despite a caller-local failure status'
    Check (($extractionProbeExit -eq 0) -and ($extractionResults -contains 'extract-failure')) `
        'ConstrainedLanguage extraction rejects native failure despite a caller-local success status'

    $windowsPowerShell = Get-Command powershell.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($windowsPowerShell) {
        Write-Host "ConstrainedLanguage integration: inspect, extract, UTF-8 write, and SHA-256"
        $validZip = New-TestZip @('dcg.exe')
        $probeOut = Join-Path $tmp 'constrained-output'
        $probeScript = Join-Path $tmp 'constrained-probe.ps1'
        $versionMock = Join-Path $tmp 'dcg-version.cmd'
        $versionFailureMock = Join-Path $tmp 'dcg-version-failure.cmd'
        $selfTestMock = Join-Path $tmp 'dcg-self-test.cmd'
        @'
@echo off
echo 9.8.7
echo dcg v9.8.7 diagnostic banner 1>&2
exit /b 0
'@ | Set-Content -LiteralPath $versionMock -Encoding ASCII
        @'
@echo off
echo dcg version probe failed 1>&2
exit /b 23
'@ | Set-Content -LiteralPath $versionFailureMock -Encoding ASCII
        @'
@echo off
if "%~4"=="git status" goto allow
if "%~4"=="rm -rf /" goto deny
echo unexpected self-test arguments 1>&2
exit /b 64
:allow
echo {"decision":"allow"}
echo dcg safe diagnostic banner 1>&2
exit /b 0
:deny
echo {"decision":"deny"}
echo dcg deny diagnostic banner 1>&2
exit /b 1
'@ | Set-Content -LiteralPath $selfTestMock -Encoding ASCII
        @'
param(
    [string]$InstallPath,
    [string]$ZipPath,
    [string]$OutputPath,
    [string]$VersionCommand,
    [string]$VersionFailureCommand,
    [string]$SelfTestCommand
)
$ErrorActionPreference = 'Stop'
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
. $InstallPath -LoadFunctionsOnly
Assert-ZipLayoutSafe -ZipPath $ZipPath
$extract = Join-Path $OutputPath 'extract'
Expand-DcgArchive -ZipPath $ZipPath -DestinationPath $extract
if (-not (Test-Path -LiteralPath (Join-Path $extract 'dcg.exe'))) {
    throw 'verified archive did not extract dcg.exe'
}
$utf8 = Join-Path $OutputPath 'utf8.txt'
$text = 'snowman ' + [char]0x2603 + '; rocket ' + [char]0xD83D + [char]0xDE80
Write-Utf8NoBomText -Path $utf8 -Text $text
[byte[]]$bytes = @(Get-Content -LiteralPath $utf8 -Encoding Byte)
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    throw 'UTF-8 helper emitted a BOM'
}
if (-not (Test-Sha256Token (Get-DcgFileSha256 -Path $utf8))) {
    throw 'SHA-256 fallback returned an invalid digest'
}
if ((Get-DcgReportedVersion -Path $VersionCommand) -cne 'v9.8.7') {
    throw 'native stdout/stderr version capture failed under ErrorActionPreference Stop'
}
if ($ErrorActionPreference -cne 'Stop') {
    throw 'Get-DcgReportedVersion did not restore ErrorActionPreference after success'
}
$versionFailure = $null
try {
    Get-DcgReportedVersion -Path $VersionFailureCommand | Out-Null
} catch {
    $versionFailure = $_.Exception.Message
}
if ($versionFailure -cne 'Installed dcg failed --version with exit code 23') {
    throw "unexpected nonzero native exit result: $versionFailure"
}
if ($ErrorActionPreference -cne 'Stop') {
    throw 'Get-DcgReportedVersion did not restore ErrorActionPreference after failure'
}
Invoke-DcgInstallSelfTest -Path $SelfTestCommand -ProbeRoot $OutputPath
if ($ErrorActionPreference -cne 'Stop') {
    throw 'Invoke-DcgInstallSelfTest did not restore ErrorActionPreference'
}
'ok'
'@ | Set-Content -LiteralPath $probeScript -Encoding UTF8
        New-Item -ItemType Directory -Path $probeOut | Out-Null
        $probeResult = & $windowsPowerShell.Source -NoLogo -NoProfile -ExecutionPolicy Bypass -File $probeScript `
            -InstallPath (Join-Path $repoRoot 'install.ps1') -ZipPath $validZip -OutputPath $probeOut `
            -VersionCommand $versionMock -VersionFailureCommand $versionFailureMock `
            -SelfTestCommand $selfTestMock
        Check (($LASTEXITCODE -eq 0) -and ($probeResult -contains 'ok')) `
            "Windows PowerShell 5.1 ConstrainedLanguage installer primitives and native stream capture work end to end"
    } else {
        Write-Host "  skip: Windows PowerShell 5.1 is unavailable on this host"
    }
} finally {
    Remove-Item Env:DCG_MOCK_TAR_LIST_EXIT, Env:DCG_MOCK_TAR_DETAILS_EXIT, Env:DCG_MOCK_TAR_EXTRACT_EXIT -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All Assert-ZipLayoutSafe tests passed." -ForegroundColor Green
