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
function Set-MinisignApplicationMock([string]$Directory, [int]$ExitCode) {
    if ($env:OS -eq 'Windows_NT') {
        $path = Join-Path $Directory 'minisign.cmd'
        $body = "@echo off`r`necho %* > `"%DCG_MINISIGN_ARGS_FILE%`"`r`nexit /b $ExitCode`r`n"
        Set-Content -LiteralPath $path -Value $body -Encoding ascii -NoNewline
    } else {
        $path = Join-Path $Directory 'minisign'
        $body = "#!/bin/sh`nprintf '%s\n' `"`$*`" > `"`$DCG_MINISIGN_ARGS_FILE`"`nexit $ExitCode`n"
        Set-Content -LiteralPath $path -Value $body -Encoding ascii -NoNewline
        & chmod +x $path
        if ($LASTEXITCODE -ne 0) { throw "could not make mock minisign executable" }
    }
    return $path
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
} finally {
    $env:PATH = $savedPath
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All checksum-resolution tests passed." -ForegroundColor Green
