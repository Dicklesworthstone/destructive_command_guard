#!/usr/bin/env pwsh
# Tests install.ps1 checksum hardening (.4.4): Test-Sha256Token (64-hex),
# Get-SiblingUrl, Resolve-ChecksumToken (per-file .sha256 -> SHA256SUMS.txt ->
# SHA256SUMS fallback, filename row match, junk rejection), and the minisign
# release-trust path. Uses local files.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function Set-MinisignApplicationMock([string]$Directory, [int]$ExitCode, [switch]$WriteStderr) {
    if ($env:OS -eq 'Windows_NT') {
        $path = Join-Path $Directory 'minisign.cmd'
        $diagnostic = if ($WriteStderr) { "echo Signature verified 1>&2`r`n" } else { '' }
        $body = "@echo off`r`necho %* > `"%DCG_MINISIGN_ARGS_FILE%`"`r`n${diagnostic}exit /b $ExitCode`r`n"
        Set-Content -LiteralPath $path -Value $body -Encoding ascii -NoNewline
    } else {
        $path = Join-Path $Directory 'minisign'
        $diagnostic = if ($WriteStderr) { "printf 'Signature verified\n' >&2`n" } else { '' }
        $body = "#!/bin/sh`nprintf '%s\n' `"`$*`" > `"`$DCG_MINISIGN_ARGS_FILE`"`n${diagnostic}exit $ExitCode`n"
        Set-Content -LiteralPath $path -Value $body -Encoding ascii -NoNewline
        & chmod +x $path
        if ($global:LASTEXITCODE -ne 0) { throw "could not make mock minisign executable" }
    }
    return $path
}

function Invoke-MinisignFromFunction([int]$LocalExit, [int]$PreviousExit) {
    # Deliberately shadow the global automatic variable as in GH #641.
    $LASTEXITCODE = $LocalExit
    $global:LASTEXITCODE = $PreviousExit
    $failure = $null
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp -Require
    } catch { $failure = $_.Exception.Message }
    [pscustomobject]@{
        Failure = $failure
        Preference = $ErrorActionPreference
        LocalExit = $LASTEXITCODE
    }
}

function Set-CosignApplicationMock([string]$Directory) {
    if ($env:OS -eq 'Windows_NT') {
        $path = Join-Path $Directory 'cosign.cmd'
        $body = @'
@echo off
if "%~1"=="version" (
  echo {"gitVersion":"v3.1.3"}
  exit /b 0
)
if "%~2"=="--help" (
  echo Usage: cosign verify-blob --bundle FILE --key FILE
  exit /b 0
)
echo %* >> "%DCG_COSIGN_ARGS_FILE%"
echo Verification diagnostic 1>&2
if "%~4"=="--key" exit /b %DCG_MOCK_COSIGN_LOCAL_EXIT%
exit /b %DCG_MOCK_COSIGN_OIDC_EXIT%
'@
        Set-Content -LiteralPath $path -Value $body -Encoding ascii
    } else {
        $path = Join-Path $Directory 'cosign'
        $body = @'
#!/bin/sh
if [ "$1" = 'version' ]; then
  printf '%s\n' '{"gitVersion":"v3.1.3"}'
  exit 0
fi
if [ "$2" = '--help' ]; then
  printf '%s\n' 'Usage: cosign verify-blob --bundle FILE --key FILE'
  if [ "$DCG_MOCK_COSIGN_BREAK_AFTER_HELP" = '1' ]; then /bin/chmod -x "$0"; fi
  exit 0
fi
printf '%s\n' "$*" >> "$DCG_COSIGN_ARGS_FILE"
printf '%s\n' 'Verification diagnostic' >&2
if [ "$4" = '--key' ]; then exit "$DCG_MOCK_COSIGN_LOCAL_EXIT"; fi
exit "$DCG_MOCK_COSIGN_OIDC_EXIT"
'@
        Set-Content -LiteralPath $path -Value ($body -replace "`r`n", "`n") -Encoding ascii
        & chmod +x $path
        if ($global:LASTEXITCODE -ne 0) { throw 'could not make mock cosign executable' }
    }
}

function Invoke-CosignFromFunction([int]$LocalExit, [int]$PreviousExit) {
    $LASTEXITCODE = $LocalExit
    $global:LASTEXITCODE = $PreviousExit
    $failure = $null
    try {
        Invoke-DcgSigstoreVerification -ArtifactPath $zip -BundleSource $scopeBundle `
            -TempDirectory $tmp -IdentityRegex 'pinned-test-identity' -OidcIssuer 'pinned-test-issuer'
    } catch { $failure = $_.Exception.Message }
    [pscustomobject]@{
        Failure = $failure
        Preference = $ErrorActionPreference
        NativeExit = $global:LASTEXITCODE
    }
}

function Set-DcgApplicationMock([string]$Directory) {
    if ($env:OS -eq 'Windows_NT') {
        $path = Join-Path $Directory 'dcg.cmd'
        $body = @'
@echo off
if "%~1"=="--version" (
  echo dcg 0.16.0
  echo version diagnostic 1>&2
  exit /b %DCG_MOCK_VERSION_EXIT%
)
if "%~4"=="git status" (
  echo {"decision":"allow"}
  echo safe diagnostic 1>&2
  exit /b %DCG_MOCK_ALLOW_EXIT%
)
if "%~4"=="rm -rf /" (
  echo {"decision":"deny"}
  echo deny diagnostic 1>&2
  exit /b %DCG_MOCK_DENY_EXIT%
)
exit /b 64
'@
        Set-Content -LiteralPath $path -Value $body -Encoding ascii
    } else {
        $path = Join-Path $Directory 'dcg'
        $body = @'
#!/bin/sh
if [ "$1" = '--version' ]; then
  printf '%s\n' 'dcg 0.16.0'
  printf '%s\n' 'version diagnostic' >&2
  exit "$DCG_MOCK_VERSION_EXIT"
fi
if [ "$4" = 'git status' ]; then
  printf '%s\n' '{"decision":"allow"}'
  printf '%s\n' 'safe diagnostic' >&2
  exit "$DCG_MOCK_ALLOW_EXIT"
fi
if [ "$4" = 'rm -rf /' ]; then
  printf '%s\n' '{"decision":"deny"}'
  printf '%s\n' 'deny diagnostic' >&2
  exit "$DCG_MOCK_DENY_EXIT"
fi
exit 64
'@
        Set-Content -LiteralPath $path -Value ($body -replace "`r`n", "`n") -Encoding ascii
        & chmod +x $path
        if ($global:LASTEXITCODE -ne 0) { throw 'could not make mock dcg executable' }
    }
    return $path
}

function Invoke-QualificationFromFunction([int]$LocalExit, [int]$PreviousExit, [switch]$SelfTest) {
    $LASTEXITCODE = $LocalExit
    $global:LASTEXITCODE = $PreviousExit
    $failure = $null
    $reported = $null
    try {
        if ($SelfTest) {
            Invoke-DcgInstallSelfTest -Path $qualifier -ProbeRoot $qualifierDir
        } else {
            $reported = Get-DcgReportedVersion -Path $qualifier
        }
    } catch { $failure = $_.Exception.Message }
    [pscustomobject]@{ Failure = $failure; ReportedVersion = $reported; Preference = $ErrorActionPreference }
}

function Set-CertutilApplicationMock([string]$Directory) {
    if ($env:OS -eq 'Windows_NT') {
        $path = Join-Path $Directory 'certutil.cmd'
        $body = @'
@echo off
echo %DCG_MOCK_HASH%
echo hash diagnostic 1>&2
exit /b %DCG_MOCK_HASH_EXIT%
'@
    } else {
        $path = Join-Path $Directory 'certutil'
        $body = @'
#!/bin/sh
printf '%s\n' "$DCG_MOCK_HASH"
printf '%s\n' 'hash diagnostic' >&2
exit "$DCG_MOCK_HASH_EXIT"
'@
    }
    Set-Content -LiteralPath $path -Value ($body -replace "`r`n", "`n") -Encoding ascii
    if ($env:OS -ne 'Windows_NT') {
        & chmod +x $path
        if ($global:LASTEXITCODE -ne 0) { throw 'could not make mock certutil executable' }
    }
    return $path
}

function Invoke-HashFromFunction([int]$LocalExit, [int]$PreviousExit) {
    # Force only the fallback boundary; certutil itself is a native process.
    function Get-FileHash { throw 'exercise the certutil fallback' }
    Set-Alias -Name certutil.exe -Value $hashMock -Scope Local
    $LASTEXITCODE = $LocalExit
    $global:LASTEXITCODE = $PreviousExit
    $failure = $null
    $digest = $null
    try { $digest = Get-DcgFileSha256 -Path $zip } catch { $failure = $_.Exception.Message }
    [pscustomobject]@{ Failure = $failure; Digest = $digest; Preference = $ErrorActionPreference }
}
$HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 64 hex
$OTHER = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

Write-Host "Test 1: Test-Sha256Token"
Check (Test-Sha256Token $HASH) "accepts a 64-hex token"
Check (Test-Sha256Token ($HASH.ToUpper())) "accepts upper-case hex"
Check (-not (Test-Sha256Token "deadbeef")) "rejects too-short"
Check (-not (Test-Sha256Token ($HASH + "0"))) "rejects too-long (65)"
Check (-not (Test-Sha256Token ($HASH.Substring(0,63) + "g"))) "rejects non-hex char"
Check (-not (Test-Sha256Token "")) "rejects empty"

Write-Host "Test 2: Convert-ContentToText decodes byte-array sidecars"
$bytes = [System.Text.Encoding]::UTF8.GetBytes("$HASH  dcg-x86_64-pc-windows-msvc.zip`n")
$decoded = (Convert-ContentToText -Content $bytes).Trim().Split(' ')[0]
Check ($decoded -eq $HASH) "decodes GitHub release .sha256 byte[] content"

Write-Host "Test 3: Get-SiblingUrl (http + file:// + local path)"
Check ((Get-SiblingUrl -Url "https://h/a/b/dcg.zip" -Leaf "SHA256SUMS.txt") -eq "https://h/a/b/SHA256SUMS.txt") "http sibling"
Check ((Get-SiblingUrl -Url "file:///x/y/dcg.zip" -Leaf "SHA256SUMS") -eq "file:///x/y/SHA256SUMS") "file:// sibling"
Check ((Get-SiblingUrl -Url "/x/y/dcg.zip" -Leaf "S") -eq "/x/y/S") "local-path sibling"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_csum_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$savedPath = $env:PATH
try {
    $zip = Join-Path $tmp "dcg-x86_64-pc-windows-msvc.zip"
    Set-Content -LiteralPath $zip -Value "ZIP" -NoNewline

    Write-Host "Test 4: per-file .sha256 is the primary path"
    Set-Content -LiteralPath "$zip.sha256" -Value "$HASH  dcg-x86_64-pc-windows-msvc.zip" -NoNewline
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "resolves from per-file .sha256"
    Remove-Item -LiteralPath "$zip.sha256" -Force

    Write-Host "Test 5: fallback to SHA256SUMS.txt, selecting the matching filename row"
    $manifest = @(
        "$OTHER  some-other-file.tar.xz",
        "$HASH *dcg-x86_64-pc-windows-msvc.zip",   # coreutils binary marker '*'
        "deadbeef  malformed-line"
    ) -join "`n"
    Set-Content -LiteralPath (Join-Path $tmp "SHA256SUMS.txt") -Value $manifest
    # per-file absent -> falls through to the manifest
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "picks the matching row from SHA256SUMS.txt"
    Remove-Item -LiteralPath (Join-Path $tmp "SHA256SUMS.txt") -Force

    Write-Host "Test 6: fallback to bare SHA256SUMS"
    Set-Content -LiteralPath (Join-Path $tmp "SHA256SUMS") -Value "$HASH  dcg-x86_64-pc-windows-msvc.zip"
    Check ((Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256") -eq $HASH) "picks row from bare SHA256SUMS"
    Remove-Item -LiteralPath (Join-Path $tmp "SHA256SUMS") -Force

    Write-Host "Test 7: junk per-file content is rejected (no valid token -> throws)"
    Set-Content -LiteralPath "$zip.sha256" -Value "not-a-real-hash" -NoNewline
    $threw = $false
    try { Resolve-ChecksumToken -ArtifactUrl $zip -PerFileUrl "$zip.sha256" | Out-Null } catch { $threw = $true }
    Check $threw "junk .sha256 with no manifest fallback throws"

    Write-Host "Test 8: missing minisign sidecar is optional unless explicitly required"
    $missingSignature = Join-Path $tmp "missing.minisig"
    $optionalThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $missingSignature -TempDirectory $tmp
    } catch { $optionalThrew = $true }
    Check (-not $optionalThrew) "optional missing signature warns and continues"
    $requiredThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $missingSignature -TempDirectory $tmp -Require
    } catch { $requiredThrew = $true }
    Check $requiredThrew "required missing signature is fatal"

    Write-Host "Test 9: present signature invokes an external minisign with the embedded public key"
    $signature = Join-Path $tmp "release.minisig"
    Set-Content -LiteralPath $signature -Value "signature" -NoNewline
    $mockBin = Join-Path $tmp "mock-bin"
    New-Item -ItemType Directory -Path $mockBin | Out-Null
    $env:DCG_MINISIGN_ARGS_FILE = Join-Path $tmp "minisign.args"
    Set-MinisignApplicationMock -Directory $mockBin -ExitCode 0 | Out-Null
    $env:PATH = "$mockBin$([System.IO.Path]::PathSeparator)$savedPath"
    $global:DcgMinisignFunctionWasCalled = $false
    function global:minisign { $global:DcgMinisignFunctionWasCalled = $true }
    $verifyThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp -Require
    } catch { $verifyThrew = $true }
    Check (-not $verifyThrew) "external mock minisign verifier succeeds"
    Check (-not $global:DcgMinisignFunctionWasCalled) "ignores a PowerShell function shim"
    $minisignArgs = Get-Content -Raw -LiteralPath $env:DCG_MINISIGN_ARGS_FILE
    Check ($minisignArgs -match '(?:^|\s)-Vm(?:\s|$)') "passes verify-message mode"
    Check ($minisignArgs -match '(?:^|\s)-P(?:\s|$)') "passes an explicit public key"
    Check ($minisignArgs -match 'RWSoYi6NXJWzaRs1mJmOwwXrZfPWcq6MXnQlNMLBYKzlIQTLwuVQG6uO') `
        "uses the embedded release key"

    Write-Host "Test 9a: native success ignores caller-local and stale exit codes (GH #641)"
    Set-MinisignApplicationMock -Directory $mockBin -ExitCode 0 -WriteStderr | Out-Null
    $scopedSuccess = Invoke-MinisignFromFunction -LocalExit -1 -PreviousExit 37
    Check (-not $scopedSuccess.Failure) "successful native verifier with stderr is accepted"
    Check ($scopedSuccess.LocalExit -eq -1) "caller-local LASTEXITCODE is unchanged"
    Check ($scopedSuccess.Preference -eq 'Stop') "success restores ErrorActionPreference"

    Write-Host "Test 10: the retired minisign key is scoped to v0.6.7"
    $legacyThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp -ReleaseVersion "v0.6.7" -Require
    } catch { $legacyThrew = $true }
    Check (-not $legacyThrew) "legacy release verification succeeds"
    $legacyArgs = Get-Content -Raw -LiteralPath $env:DCG_MINISIGN_ARGS_FILE
    Check ($legacyArgs -match 'RWTQoKUb0Ue4NsqTpPWnABCrIU0\+m25zsMlbv6UcRClQ7jmRP3A7NmTB') `
        "uses the retired key only for v0.6.7"

    Write-Host "Test 11: patched cosign version floors reject vulnerable builds"
    $cosignCases = @(
        @('v2.6.1', $false, 'rejects cosign 2.6.1'),
        @('v2.6.2', $true, 'accepts cosign 2.6.2'),
        @('v3.0.3', $false, 'rejects cosign 3.0.3'),
        @('v3.0.4', $true, 'accepts cosign 3.0.4'),
        @('v3.1.2', $true, 'accepts newer cosign 3.x'),
        @('v3.0.4-rc.1', $false, 'rejects prerelease builds at the patched floor'),
        @('v2.6.2-rc.1', $false, 'rejects a 2.x prerelease at the patched floor'),
        @('devel', $false, 'rejects unknown development builds'),
        @('v3.1.3+dirty', $true, 'accepts distro build metadata above the floor (GH #505)'),
        @('v3.0.4+dirty', $true, 'build metadata does not lower the floor release'),
        @('v3.0.3+dirty', $false, 'build metadata does not raise a vulnerable release'),
        @('3.1.3', $true, 'accepts a version without the v prefix'),
        @('v3.1.3-dirty', $true, 'accepts a git-describe dirty suffix above the floor'),
        @('v3.0.4-dirty', $false, 'rejects a dirty suffix at the floor'),
        @('v3.0.4-3-gabc1234', $false, 'rejects git-describe builds at the floor'),
        @('v3.1.0-rc.1+build.5', $true, 'accepts a prerelease whose core is above the floor'),
        @('v2.6.10', $true, 'compares numerically, not lexically'),
        @('v4.0.0-rc.1', $true, 'accepts a future major prerelease'),
        @('v1.13.9', $false, 'rejects cosign 1.x'),
        @('v3.1', $false, 'rejects a truncated version'),
        @('v3.1.3 junk', $false, 'rejects trailing junk')
    )
    foreach ($case in $cosignCases) {
        $json = '{"gitVersion":"' + $case[0] + '"}'
        Check ((Test-DcgPatchedCosignVersion -VersionOutput $json) -eq $case[1]) "$($case[2]) [$($case[0])]"
    }
    $prettyJson = "{`n  ""gitVersion"": ""v3.1.3+dirty"",`n  ""gitTreeState"": ""dirty""`n}"
    Check (Test-DcgPatchedCosignVersion -VersionOutput $prettyJson) "reads pretty-printed JSON"
    $textOutput = "  ______   ______.   _______.`nGitVersion:    v3.1.3+dirty`nGitCommit:     11926fa`n"
    Check (Test-DcgPatchedCosignVersion -VersionOutput $textOutput) "reads the plain-text GitVersion line"
    Check (-not (Test-DcgPatchedCosignVersion -VersionOutput "")) "rejects empty output"

    Write-Host "Test 12: a present invalid minisign signature is always fatal"
    Set-MinisignApplicationMock -Directory $mockBin -ExitCode 1 | Out-Null
    $invalidThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp
    } catch { $invalidThrew = $true }
    Check $invalidThrew "invalid signature fails even without -RequireMinisign"

    Write-Host "Test 12a: caller-local success cannot hide native verification failure"
    $scopedFailure = Invoke-MinisignFromFunction -LocalExit 0 -PreviousExit 0
    Check ($scopedFailure.Failure -like '*Minisign verification failed*status 1*') `
        "native failure wins over local and stale global success"
    Check ($scopedFailure.Preference -eq 'Stop') "failure restores ErrorActionPreference"

    Write-Host "Test 12b: a verifier that cannot launch never inherits a stale success"
    $brokenBin = Join-Path $tmp 'broken-minisign'
    New-Item -ItemType Directory -Path $brokenBin | Out-Null
    if ($env:OS -eq 'Windows_NT') {
        $brokenVerifier = Join-Path $brokenBin 'minisign.exe'
        Set-Content -LiteralPath $brokenVerifier -Value 'not a Windows executable' -Encoding ascii
    } else {
        $brokenVerifier = Join-Path $brokenBin 'minisign'
        Set-Content -LiteralPath $brokenVerifier -Value "#!/nonexistent/dcg-test-interpreter`n" -Encoding ascii -NoNewline
        & chmod +x $brokenVerifier
        if ($global:LASTEXITCODE -ne 0) { throw 'could not make broken verifier executable' }
    }
    $env:PATH = $brokenBin
    Check ([bool](Get-Command minisign -CommandType Application -ErrorAction SilentlyContinue)) `
        "broken verifier is discovered as an application before its launch fails"
    $launchFailure = Invoke-MinisignFromFunction -LocalExit 0 -PreviousExit 0
    Check ($launchFailure.Failure -like '*Minisign verification failed*') "failed native launch is fatal"
    Check ($launchFailure.Preference -eq 'Stop') "failed launch restores ErrorActionPreference"

    Write-Host "Test 13: strict mode rejects a function shim when no external verifier exists"
    $emptyPath = Join-Path $tmp "empty-path"
    New-Item -ItemType Directory -Path $emptyPath | Out-Null
    $env:PATH = $emptyPath
    $shimThrew = $false
    try {
        Invoke-DcgMinisignVerification -ArtifactPath $zip -ArtifactSource $zip `
            -SignatureSource $signature -TempDirectory $tmp -Require
    } catch { $shimThrew = $true }
    Check $shimThrew "function shim cannot satisfy -RequireMinisign"

    Write-Host "Test 14: a distro cosign build is used for bundle verification (GH #505)"
    if ($env:OS -eq 'Windows_NT') {
        Write-Host "  skip: the mock cosign is a POSIX shell script"
    } else {
        $env:PATH = $savedPath
        $cosignBin = Join-Path $tmp "cosign-bin"
        New-Item -ItemType Directory -Path $cosignBin | Out-Null
        $cosignMock = Join-Path $cosignBin 'cosign'
        $cosignBody = @'
#!/bin/sh
if [ "$1" = version ]; then
  if [ "$2" = --json ]; then
    [ "$DCG_MOCK_COSIGN_JSON" = 0 ] && exit 1
    printf '{\n  "gitVersion": "%s",\n  "gitTreeState": "dirty"\n}\n' "$DCG_MOCK_COSIGN_VERSION"
  else
    printf 'GitVersion:    %s\nGitTreeState:  dirty\n' "$DCG_MOCK_COSIGN_VERSION"
  fi
  exit 0
fi
if [ "$1" = verify-blob ] && [ "$2" = --help ]; then
  echo 'Usage: cosign verify-blob --bundle FILE --key FILE'
  exit 0
fi
printf '%s\n' "$*" > "$DCG_COSIGN_ARGS_FILE"
case " $* " in
  *" --key "*) exit 0 ;;
  *) exit 1 ;;
esac
'@
        Set-Content -LiteralPath $cosignMock -Value ($cosignBody -replace "`r`n", "`n") -Encoding ascii -NoNewline
        & chmod +x $cosignMock
        # The bundle is copied into -TempDirectory, so it must live elsewhere.
        $bundle = Join-Path $cosignBin "release.sigstore.json"
        Set-Content -LiteralPath $bundle -Value "{}" -NoNewline
        $env:PATH = "$cosignBin$([System.IO.Path]::PathSeparator)$savedPath"
        $env:DCG_COSIGN_ARGS_FILE = Join-Path $tmp "cosign.args"
        $sigstoreCases = @(
            @('v3.1.3+dirty', '1', $true, 'JSON gitVersion with build metadata is verified'),
            @('v3.1.3+dirty', '0', $true, 'plain-text GitVersion fallback is verified'),
            @('v3.0.3+dirty', '1', $false, 'a vulnerable release with build metadata is still skipped')
        )
        foreach ($case in $sigstoreCases) {
            Remove-Item -LiteralPath $env:DCG_COSIGN_ARGS_FILE -Force -ErrorAction SilentlyContinue
            $env:DCG_MOCK_COSIGN_VERSION = $case[0]
            $env:DCG_MOCK_COSIGN_JSON = $case[1]
            Invoke-DcgSigstoreVerification -ArtifactPath $zip -BundleSource $bundle -TempDirectory $tmp `
                -IdentityRegex 'unused' -OidcIssuer 'unused'
            $ran = Test-Path -LiteralPath $env:DCG_COSIGN_ARGS_FILE
            Check ($ran -eq $case[2]) "$($case[3]) [$($case[0])]"
            if ($case[2] -and $ran) {
                Check ((Get-Content -Raw -LiteralPath $env:DCG_COSIGN_ARGS_FILE) -match '--key') `
                    "verifies against the pinned release key [$($case[0])]"
            }
        }
        Remove-Item Env:DCG_MOCK_COSIGN_VERSION, Env:DCG_MOCK_COSIGN_JSON, Env:DCG_COSIGN_ARGS_FILE -ErrorAction SilentlyContinue
    }

    Write-Host "Test 15: cosign trust paths use native status despite function-local shadows"
    $scopeCosignBin = Join-Path $tmp 'scope-cosign-bin'
    New-Item -ItemType Directory -Path $scopeCosignBin | Out-Null
    Set-CosignApplicationMock -Directory $scopeCosignBin
    $scopeBundle = Join-Path $scopeCosignBin 'scope.sigstore.json'
    Set-Content -LiteralPath $scopeBundle -Value '{}' -Encoding ascii
    $env:PATH = "$scopeCosignBin$([System.IO.Path]::PathSeparator)$savedPath"
    $env:DCG_COSIGN_ARGS_FILE = Join-Path $tmp 'scope-cosign.args'
    $env:DCG_MOCK_COSIGN_LOCAL_EXIT = '0'
    $env:DCG_MOCK_COSIGN_OIDC_EXIT = '9'
    $cosignSuccess = Invoke-CosignFromFunction -LocalExit -1 -PreviousExit 37
    Check (-not $cosignSuccess.Failure) 'local-key success is accepted with stderr and stale/local failure'
    Check ((Test-Path -LiteralPath $env:DCG_COSIGN_ARGS_FILE) -and `
        ((Get-Content -Raw -LiteralPath $env:DCG_COSIGN_ARGS_FILE) -match '--key')) `
        'scope shadow does not skip cosign verification as an unknown version'
    Check ($cosignSuccess.Preference -eq 'Stop') 'cosign success restores ErrorActionPreference'

    $env:DCG_MOCK_COSIGN_LOCAL_EXIT = '7'
    $env:DCG_MOCK_COSIGN_OIDC_EXIT = '8'
    $cosignFailure = Invoke-CosignFromFunction -LocalExit 0 -PreviousExit 0
    Check ($cosignFailure.Failure -like '*failed verification under both pinned release trust roots*') `
        'both trust failures are fatal despite local and stale global success'
    Check ($cosignFailure.Preference -eq 'Stop') 'cosign failure restores ErrorActionPreference'

    $env:DCG_MOCK_COSIGN_OIDC_EXIT = '0'
    $cosignFallback = Invoke-CosignFromFunction -LocalExit -1 -PreviousExit 0
    Check (-not $cosignFallback.Failure) 'native OIDC success is accepted after local-key failure'
    Check ((Test-Path -LiteralPath $env:DCG_COSIGN_ARGS_FILE) -and `
        ((Get-Content -Raw -LiteralPath $env:DCG_COSIGN_ARGS_FILE) -match '--certificate-oidc-issuer pinned-test-issuer')) `
        'OIDC fallback still receives its pinned trust identity'

    Write-Host "Test 15a: cosign launch failure after successful version/help cannot reuse exit zero"
    if ($env:OS -eq 'Windows_NT') {
        Write-Host '  skip: revoking executable permission between invocations requires POSIX chmod'
    } else {
        $env:DCG_MOCK_COSIGN_BREAK_AFTER_HELP = '1'
        $cosignLaunchFailure = Invoke-CosignFromFunction -LocalExit 0 -PreviousExit 0
        # PowerShell 7 can classify a no-longer-executable file as a document
        # and reject it before creating a process; other hosts fail at launch.
        Check ($cosignLaunchFailure.Failure -match '(?i)(cannot run a document|failed to run|failed verification under both pinned release trust roots)') `
            'a failed verification launch is fatal despite successful version/help and stale exit zero'
        Check ($cosignLaunchFailure.NativeExit -eq -1) 'failed launch retains the failure sentinel instead of prior success'
        Check ($cosignLaunchFailure.Preference -eq 'Stop') 'cosign failed launch restores ErrorActionPreference'
    }

    Write-Host 'Test 16: installed version qualification uses the actual native exit code'
    $env:PATH = $savedPath
    $qualifierDir = Join-Path $tmp 'qualification'
    New-Item -ItemType Directory -Path $qualifierDir | Out-Null
    $qualifier = Set-DcgApplicationMock -Directory $qualifierDir
    $env:DCG_MOCK_VERSION_EXIT = '0'
    $versionSuccess = Invoke-QualificationFromFunction -LocalExit -1 -PreviousExit 37
    Check (-not $versionSuccess.Failure -and $versionSuccess.ReportedVersion -ceq 'v0.16.0') `
        'native version success survives stderr and local/stale failure codes'
    Check ($versionSuccess.Preference -eq 'Stop') 'version success restores ErrorActionPreference'
    $env:DCG_MOCK_VERSION_EXIT = '23'
    $versionFailure = Invoke-QualificationFromFunction -LocalExit 0 -PreviousExit 0
    Check ($versionFailure.Failure -ceq 'Installed dcg failed --version with exit code 23') `
        'a version-shaped response with native exit 23 is rejected despite local/stale success'

    Write-Host 'Test 17: self-test accepts native allow/deny statuses inside a caller function'
    $env:DCG_MOCK_ALLOW_EXIT = '0'
    $env:DCG_MOCK_DENY_EXIT = '1'
    foreach ($shadow in @(0, -1)) {
        $selfTestSuccess = Invoke-QualificationFromFunction -LocalExit $shadow -PreviousExit 37 -SelfTest
        Check (-not $selfTestSuccess.Failure) "self-test accepts allow=0 and deny=1 despite local exit $shadow"
        Check ($selfTestSuccess.Preference -eq 'Stop') "self-test restores ErrorActionPreference with local exit $shadow"
    }
    $env:DCG_MOCK_DENY_EXIT = '0'
    $selfTestFailure = Invoke-QualificationFromFunction -LocalExit 1 -PreviousExit 1 -SelfTest
    Check ($selfTestFailure.Failure -ceq 'Self-test did not deny the destructive probe (exit 0)') `
        'deny-shaped output with the wrong native exit remains a qualification failure'

    Write-Host 'Test 18: certutil fallback requires successful native hashing despite caller shadows'
    $hashMock = Set-CertutilApplicationMock -Directory $qualifierDir
    $env:DCG_MOCK_HASH = $HASH.ToUpperInvariant()
    $env:DCG_MOCK_HASH_EXIT = '0'
    $hashSuccess = Invoke-HashFromFunction -LocalExit -1 -PreviousExit 37
    Check ((-not $hashSuccess.Failure) -and ($hashSuccess.Digest -ceq $HASH)) `
        'successful native checksum survives stderr and local/stale failure statuses'
    Check ($hashSuccess.Preference -eq 'Stop') 'native hashing success restores ErrorActionPreference'
    $env:DCG_MOCK_HASH_EXIT = '19'
    $hashFailure = Invoke-HashFromFunction -LocalExit 0 -PreviousExit 0
    Check ($hashFailure.Failure -like 'Unable to compute SHA-256*') `
        'valid-looking digest from native exit 19 is rejected despite local/stale success'
    Check (-not $hashFailure.Digest) 'failed native hashing returns no trusted digest'
    Check ($hashFailure.Preference -eq 'Stop') 'native hashing failure restores ErrorActionPreference'
} finally {
    $env:PATH = $savedPath
    Remove-Item Env:DCG_MOCK_COSIGN_LOCAL_EXIT, Env:DCG_MOCK_COSIGN_OIDC_EXIT, Env:DCG_MOCK_COSIGN_BREAK_AFTER_HELP, Env:DCG_COSIGN_ARGS_FILE -ErrorAction SilentlyContinue
    Remove-Item Env:DCG_MOCK_VERSION_EXIT, Env:DCG_MOCK_ALLOW_EXIT, Env:DCG_MOCK_DENY_EXIT -ErrorAction SilentlyContinue
    Remove-Item Env:DCG_MOCK_HASH, Env:DCG_MOCK_HASH_EXIT -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All checksum-resolution tests passed." -ForegroundColor Green
