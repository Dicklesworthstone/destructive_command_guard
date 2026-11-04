#!/usr/bin/env pwsh
# Tests install.ps1 local-artifact support: Resolve-LocalSourcePath /
# Copy-OrDownloadToFile / Read-OrDownloadText. These let -ArtifactUrl /
# -ChecksumUrl / -SigstoreBundleUrl point at a local file (or file:// URI) so
# the installer runs with no network (hermetic CI smoke / offline install).
# Also exercises transactional installation using real native fixture binaries
# in local ZIPs: rejected candidates must never replace a working guard.

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'install.ps1') -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}

function New-NativeDcgFixture([string]$Path, [string]$Version, [int]$DenyExit = 1) {
    if ($env:OS -eq 'Windows_NT') {
        # Windows PowerShell ships the .NET Framework compiler. A real PE
        # executable exercises CreateProcess even when this suite uses pwsh.
        $compiler = @(
            (Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
            (Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $compiler) { throw 'native fixture tests require the Windows .NET Framework csc.exe' }
        $source = @'
using System;
using System.IO;
using System.Reflection;
public static class DcgFixture {
    public static int Main(string[] args) {
        string log = Environment.GetEnvironmentVariable("DCG_TEST_INSTALL_PROBE_LOG");
        if (!String.IsNullOrEmpty(log)) File.AppendAllText(log, Assembly.GetExecutingAssembly().Location + "\n");
        if (args.Length == 1 && args[0] == "--version") {
            Console.WriteLine("dcg __VERSION__"); return 0;
        }
        if (args.Length == 4 && args[0] == "test" && args[3] == "git status") {
            Console.WriteLine("{\"decision\":\"allow\"}"); return 0;
        }
        if (args.Length == 4 && args[0] == "test" && args[3] == "rm -rf /") {
            Console.WriteLine("{\"decision\":\"deny\"}"); return __DENY_EXIT__;
        }
        return 64;
    }
}
'@
        $source = $source.Replace('__VERSION__', $Version).Replace('__DENY_EXIT__', [string]$DenyExit)
        $sourceFile = $Path + '.cs'
        Set-Content -LiteralPath $sourceFile -Value $source -Encoding ASCII
        & $compiler /nologo /target:exe "/out:$Path" $sourceFile
        if ($global:LASTEXITCODE -ne 0) { throw "native fixture compilation failed: $Path" }
    } else {
        $source = @'
#!/bin/sh
if [ -n "$DCG_TEST_INSTALL_PROBE_LOG" ]; then printf '%s\n' "$0" >> "$DCG_TEST_INSTALL_PROBE_LOG"; fi
if [ "$1" = '--version' ]; then printf '%s\n' 'dcg __VERSION__'; exit 0; fi
if [ "$4" = 'git status' ]; then printf '%s\n' '{"decision":"allow"}'; exit 0; fi
if [ "$4" = 'rm -rf /' ]; then printf '%s\n' '{"decision":"deny"}'; exit __DENY_EXIT__; fi
exit 64
'@
        $source = $source.Replace('__VERSION__', $Version).Replace('__DENY_EXIT__', [string]$DenyExit)
        Set-Content -LiteralPath $Path -Value ($source -replace "`r`n", "`n") -Encoding ASCII
        & chmod 755 $Path
        if ($global:LASTEXITCODE -ne 0) { throw 'could not make native fixture executable' }
    }
}

function New-FixtureZip([string]$BinaryPath, [string]$ZipPath) {
    $stream = [System.IO.File]::Open($ZipPath, [System.IO.FileMode]::CreateNew)
    $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $archive.CreateEntry('dcg.exe')
        $entry.ExternalAttributes = -2115174400 # Unix regular file, mode 0755.
        $entryStream = $entry.Open()
        $inputStream = [System.IO.File]::OpenRead($BinaryPath)
        try { $inputStream.CopyTo($entryStream) } finally { $inputStream.Dispose(); $entryStream.Dispose() }
    } finally { $archive.Dispose(); $stream.Dispose() }
    # Preserve executable mode when running the exact installer on Unix. The
    # central directory must identify the supplied mode bits as Unix metadata.
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($ZipPath)
    for ($i = 0; $i -le ($bytes.Length - 6); $i++) {
        if ($bytes[$i] -eq 0x50 -and $bytes[$i + 1] -eq 0x4B -and
            $bytes[$i + 2] -eq 0x01 -and $bytes[$i + 3] -eq 0x02) {
            $bytes[$i + 5] = 3
            [System.IO.File]::WriteAllBytes($ZipPath, $bytes)
            return
        }
    }
    throw 'fixture ZIP central directory was not found'
}

function Invoke-FixtureInstall([string]$ZipPath, [string]$Destination, [string]$ProbeLog) {
    $savedPreference = $ErrorActionPreference
    $savedProbeLog = $env:DCG_TEST_INSTALL_PROBE_LOG
    try {
        $ErrorActionPreference = 'Continue'
        $env:DCG_TEST_INSTALL_PROBE_LOG = $ProbeLog
        $global:LASTEXITCODE = -1
        $messages = @(& $currentPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $installPs1 `
            -ArtifactUrl $ZipPath -Checksum (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash `
            -Dest $Destination -Version 'v0.16.0' -Verify -NoConfigure 2>&1)
        $code = $global:LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
        $env:DCG_TEST_INSTALL_PROBE_LOG = $savedProbeLog
    }
    [pscustomobject]@{ Code = $code; Output = $messages -join "`n" }
}

$installPs1 = Join-Path $repoRoot 'install.ps1'
$currentPowerShell = (Get-Process -Id $PID).Path
$savedTemp = $env:TEMP
$savedTmp = $env:TMP
$savedArchitecture = $env:PROCESSOR_ARCHITECTURE
$savedNativePreference = $PSNativeCommandUseErrorActionPreference

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_localsrc_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp 'dcg-x86_64-pc-windows-msvc.zip'
    [System.IO.File]::WriteAllBytes($zip, [byte[]](0x50, 0x4B, 0x03, 0x04, 0x01, 0x02, 0x03))
    $sha = Join-Path $tmp 'dcg-x86_64-pc-windows-msvc.zip.sha256'
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
    Set-Content -LiteralPath $sha -Value "$hash  dcg-x86_64-pc-windows-msvc.zip" -NoNewline
    # A correctly-formed file:// URI for this path.
    $fileUri = ([System.Uri]("file://" + $zip)).AbsoluteUri

    Write-Host "Test 1: Resolve-LocalSourcePath"
    Check ((Resolve-LocalSourcePath -Source $zip) -eq $zip) "bare existing path resolves to itself"
    Check ((Resolve-LocalSourcePath -Source $fileUri) -eq $zip) "file:// URI resolves to its local path"
    Check ($null -eq (Resolve-LocalSourcePath -Source 'https://example.com/x.zip')) "https:// -> null (remote)"
    Check ($null -eq (Resolve-LocalSourcePath -Source 'http://example.com/x.zip')) "http:// -> null (remote)"
    Check ($null -eq (Resolve-LocalSourcePath -Source ($zip + '.nope'))) "nonexistent path -> null"
    Check ($null -eq (Resolve-LocalSourcePath -Source '')) "empty -> null"

    Write-Host "Test 2: Copy-OrDownloadToFile copies a local/file:// source byte-for-byte"
    $out1 = Join-Path $tmp 'out1.zip'
    Copy-OrDownloadToFile -Source $zip -OutFile $out1
    Check (Test-Path $out1) "bare path: output file created"
    $a = [System.IO.File]::ReadAllBytes($zip); $b = [System.IO.File]::ReadAllBytes($out1)
    Check (($a.Length -eq $b.Length) -and (-not (Compare-Object $a $b))) "bare path: bytes identical"
    $out2 = Join-Path $tmp 'out2.zip'
    Copy-OrDownloadToFile -Source $fileUri -OutFile $out2
    $c = [System.IO.File]::ReadAllBytes($out2)
    Check (($a.Length -eq $c.Length) -and (-not (Compare-Object $a $c))) "file:// URI: bytes identical"
    $threw = $false
    try { Copy-OrDownloadToFile -Source ($zip + '.missing') -OutFile (Join-Path $tmp 'x') } catch { $threw = $true }
    Check $threw "missing local source throws (not a silent empty file)"

    Write-Host "Test 3: Read-OrDownloadText reads a local/file:// checksum file"
    $txt = (Read-OrDownloadText -Source $sha).Trim().Split(' ')[0]
    Check ($txt -eq $hash) "bare path: checksum text read + parses to the hash"
    $txt2 = (Read-OrDownloadText -Source (([System.Uri]("file://" + $sha)).AbsoluteUri)).Trim().Split(' ')[0]
    Check ($txt2 -eq $hash) "file:// URI: checksum text read"
    $threw2 = $false
    try { Read-OrDownloadText -Source ($sha + '.missing') | Out-Null } catch { $threw2 = $true }
    Check $threw2 "missing checksum source throws"

    Write-Host "Test 4: default ChecksumUrl convention (`$url.sha256`) resolves locally"
    # The install body sets `$ChecksumUrl = "$url.sha256"` when -Checksum is absent;
    # for a local zip that must point at the co-located .sha256.
    $derived = "$zip.sha256"
    Check ((Resolve-LocalSourcePath -Source $derived) -eq $sha) "<zip>.sha256 resolves to the sidecar checksum"

    Write-Host 'Test 5: the full installer qualifies a native candidate before replacing the guard'
    Add-Type -AssemblyName System.IO.Compression | Out-Null
    $env:TEMP = $tmp
    $env:TMP = $tmp
    $env:PROCESSOR_ARCHITECTURE = 'AMD64'
    $PSNativeCommandUseErrorActionPreference = $false
    $oldBinary = Join-Path $tmp 'old.exe'
    $goodBinary = Join-Path $tmp 'good.exe'
    $wrongVersion = Join-Path $tmp 'wrong-version.exe'
    $badSelfTest = Join-Path $tmp 'bad-selftest.exe'
    $badLaunch = Join-Path $tmp 'bad-launch.exe'
    New-NativeDcgFixture -Path $oldBinary -Version '0.15.0'
    New-NativeDcgFixture -Path $goodBinary -Version '0.16.0'
    New-NativeDcgFixture -Path $wrongVersion -Version '0.14.0'
    New-NativeDcgFixture -Path $badSelfTest -Version '0.16.0' -DenyExit 0
    Set-Content -LiteralPath $badLaunch -Value "#!/dcg-nonexistent-interpreter`nexit 0" -Encoding ASCII

    foreach ($case in @(
        @{ Name = 'wrong-version'; Binary = $wrongVersion; Success = $false },
        @{ Name = 'bad-selftest'; Binary = $badSelfTest; Success = $false },
        @{ Name = 'failed-launch'; Binary = $badLaunch; Success = $false },
        @{ Name = 'valid'; Binary = $goodBinary; Success = $true }
    )) {
        $caseRoot = Join-Path $tmp $case.Name
        $destination = Join-Path $caseRoot 'bin with spaces [literal]'
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        $liveBinary = Join-Path $destination 'dcg.exe'
        Copy-Item -LiteralPath $oldBinary -Destination $liveBinary
        if ($env:OS -eq 'Windows_NT') {
            $acl = New-Object System.Security.AccessControl.FileSecurity
            $acl.SetAccessRuleProtection($true, $false)
            $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $liveBinary -AclObject $acl
            $beforePermissions = (Get-Acl -LiteralPath $liveBinary).Sddl
        } else {
            & chmod 700 $liveBinary
            $beforePermissions = [System.IO.File]::GetUnixFileMode($liveBinary)
        }
        $beforeHash = (Get-FileHash -LiteralPath $liveBinary -Algorithm SHA256).Hash
        $archivePath = Join-Path $caseRoot 'dcg.zip'
        New-FixtureZip -BinaryPath $case.Binary -ZipPath $archivePath
        $probeLog = Join-Path $caseRoot 'native-probes.log'
        $result = Invoke-FixtureInstall -ZipPath $archivePath -Destination $destination -ProbeLog $probeLog
        Check (($result.Code -eq 0) -eq $case.Success) "$($case.Name): installer reports the native qualification outcome"
        $expectedHash = if ($case.Success) { (Get-FileHash -LiteralPath $goodBinary -Algorithm SHA256).Hash } else { $beforeHash }
        Check ((Get-FileHash -LiteralPath $liveBinary -Algorithm SHA256).Hash -ceq $expectedHash) `
            "$($case.Name): only a qualified candidate can replace the incumbent bytes"
        $afterPermissions = if ($env:OS -eq 'Windows_NT') { (Get-Acl -LiteralPath $liveBinary).Sddl } else { [System.IO.File]::GetUnixFileMode($liveBinary) }
        Check ($afterPermissions -ceq $beforePermissions) "$($case.Name): incumbent access controls are preserved"
        if ($case.Name -ne 'failed-launch') {
            $probes = @(Get-Content -LiteralPath $probeLog)
            Check (($probes.Count -gt 0) -and @($probes | Where-Object {
                (Split-Path -Parent $_) -cne $destination -or (Split-Path -Leaf $_) -notlike '.dcg-install-*.exe'
            }).Count -eq 0) "$($case.Name): real native qualification ran only on the destination stage"
        }
        Check (@(Get-ChildItem -LiteralPath $destination -Force | Where-Object { $_.Name -like '.dcg-install-*' -or $_.Name -like 'dcg.exe.bak.*' }).Count -eq 0) `
            "$($case.Name): no transient executable or rollback copy remains"
    }

    Write-Host 'Test 6: directory targets cannot absorb the staged executable'
    $collisionRoot = Join-Path $tmp 'directory-collision'
    $collisionTarget = Join-Path $collisionRoot 'dcg.exe'
    New-Item -ItemType Directory -Path $collisionTarget -Force | Out-Null
    $sentinel = Join-Path $collisionTarget 'keep.txt'
    Set-Content -LiteralPath $sentinel -Value 'existing directory contents' -NoNewline
    $goodZip = Join-Path $tmp 'good.zip'
    New-FixtureZip -BinaryPath $goodBinary -ZipPath $goodZip
    $collisionResult = Invoke-FixtureInstall -ZipPath $goodZip -Destination $collisionRoot -ProbeLog (Join-Path $tmp 'collision-probes.log')
    Check ($collisionResult.Code -ne 0) 'an executable destination that is a directory is rejected'
    Check ((Get-Content -LiteralPath $sentinel -Raw) -ceq 'existing directory contents') 'directory contents remain unchanged'
    Check (-not (Test-Path -LiteralPath (Join-Path $collisionTarget 'dcg.exe'))) 'no executable is nested inside the directory target'
    $linkedRoot = Join-Path $tmp 'linked-directory'
    New-Item -ItemType Directory -Path $linkedRoot | Out-Null
    $linkedTarget = Join-Path $linkedRoot 'dcg.exe'
    $linkType = if ($env:OS -eq 'Windows_NT') { 'Junction' } else { 'SymbolicLink' }
    New-Item -ItemType $linkType -Path $linkedTarget -Value $collisionTarget | Out-Null
    $linkedResult = Invoke-FixtureInstall -ZipPath $goodZip -Destination $linkedRoot -ProbeLog (Join-Path $tmp 'linked-probes.log')
    Check ($linkedResult.Code -ne 0) 'an executable destination linked to a directory is rejected'
    Check (((Get-Item -LiteralPath $linkedTarget -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) `
        'the existing directory link is retained'
    Check (-not (Test-Path -LiteralPath (Join-Path $collisionTarget 'dcg.exe'))) 'a linked directory receives no executable'

    Write-Host 'Test 7: failed native promotion preserves and recovers the incumbent'
    $missingRoot = Join-Path $tmp 'missing-source'
    New-Item -ItemType Directory -Path $missingRoot | Out-Null
    $missingTarget = Join-Path $missingRoot 'dcg.exe'
    Copy-Item -LiteralPath $oldBinary -Destination $missingTarget
    $beforeHash = (Get-FileHash -LiteralPath $missingTarget -Algorithm SHA256).Hash
    $threw = $false
    try { Install-DcgBinary -SourcePath (Join-Path $missingRoot 'unavailable.exe') -DestinationPath $missingTarget -ExpectedVersion 'v0.16.0' -ProbeRoot $missingRoot }
    catch { $threw = $true }
    Check $threw 'a candidate that disappears before staging reports failure'
    Check ((Get-FileHash -LiteralPath $missingTarget -Algorithm SHA256).Hash -ceq $beforeHash) `
        'failed staging leaves incumbent bytes unchanged'
    $savedVersionCheck = (Get-Command Assert-DcgInstalledVersion).ScriptBlock
    foreach ($failureMode in @('replace', 'recover')) {
        $failureRoot = Join-Path $tmp $failureMode
        New-Item -ItemType Directory -Path $failureRoot | Out-Null
        $failureTarget = Join-Path $failureRoot 'dcg.exe'
        Copy-Item -LiteralPath $oldBinary -Destination $failureTarget
        $beforeHash = (Get-FileHash -LiteralPath $failureTarget -Algorithm SHA256).Hash
        function Assert-DcgInstalledVersion {
            param([string]$Path, [string]$ExpectedVersion)
            & $savedVersionCheck -Path $Path -ExpectedVersion $ExpectedVersion
            # Withhold the qualified stage so the actual native replacement
            # fails. Also model ReplaceFile moving the incumbent aside before
            # failure to exercise its recovery path, without mocking Replace.
            Rename-Item -LiteralPath $Path -NewName ((Split-Path -Leaf $Path) + '.withheld')
            if ($failureMode -eq 'recover') {
                Move-Item -LiteralPath $failureTarget -Destination $backup
            }
        }
        try {
            $threw = $false
            try { Install-DcgBinary -SourcePath $goodBinary -DestinationPath $failureTarget -ExpectedVersion 'v0.16.0' -ProbeRoot $failureRoot }
            catch { $threw = $true }
            Check $threw "${failureMode}: promotion failure is reported"
            $preserved = Test-Path -LiteralPath $failureTarget -PathType Leaf
            Check ($preserved -and (Get-FileHash -LiteralPath $failureTarget -Algorithm SHA256).Hash -ceq $beforeHash) `
                "${failureMode}: the previous executable is intact at its original path"
        } finally {
            Set-Item -LiteralPath Function:Assert-DcgInstalledVersion -Value $savedVersionCheck
        }
    }

    Write-Host 'Test 8: ConstrainedLanguage preserves an existing guard and supports fresh installation'
    $clProbe = Join-Path $tmp 'constrained-install.ps1'
    @'
param([string]$Installer, [string]$Source, [string]$Destination, [string]$ProbeRoot)
$ErrorActionPreference = 'Stop'
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'
. $Installer -LoadFunctionsOnly
try {
    Install-DcgBinary -SourcePath $Source -DestinationPath $Destination -ExpectedVersion 'v0.16.0' -ProbeRoot $ProbeRoot -Verify
} catch {
    Write-Output $_.Exception.Message
    exit 1
}
'@ | Set-Content -LiteralPath $clProbe -Encoding UTF8
    $clRoot = Join-Path $tmp 'constrained'
    New-Item -ItemType Directory -Path $clRoot | Out-Null
    $clExisting = Join-Path $clRoot 'existing.exe'
    $clFresh = Join-Path $clRoot 'fresh.exe'
    Copy-Item -LiteralPath $oldBinary -Destination $clExisting
    $beforeHash = (Get-FileHash -LiteralPath $clExisting -Algorithm SHA256).Hash
    $refusal = @(& $currentPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $clProbe `
        -Installer $installPs1 -Source $goodBinary -Destination $clExisting -ProbeRoot $clRoot)
    Check ($global:LASTEXITCODE -ne 0 -and ($refusal -match 'Cannot atomically replace.*ConstrainedLanguage')) `
        'ConstrainedLanguage explicitly refuses an unsafe existing-file replacement'
    Check ((Get-FileHash -LiteralPath $clExisting -Algorithm SHA256).Hash -ceq $beforeHash) `
        'ConstrainedLanguage refusal leaves incumbent bytes unchanged'
    & $currentPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $clProbe `
        -Installer $installPs1 -Source $goodBinary -Destination $clFresh -ProbeRoot $clRoot
    Check ($global:LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $clFresh -PathType Leaf)) `
        'ConstrainedLanguage still qualifies and installs a fresh executable'
    Check ((Get-FileHash -LiteralPath $clFresh -Algorithm SHA256).Hash -ceq (Get-FileHash -LiteralPath $goodBinary -Algorithm SHA256).Hash) `
        'fresh constrained installation contains exactly the qualified candidate'
} finally {
    $env:TEMP = $savedTemp
    $env:TMP = $savedTmp
    $env:PROCESSOR_ARCHITECTURE = $savedArchitecture
    $PSNativeCommandUseErrorActionPreference = $savedNativePreference
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red; exit 1 }
Write-Host "All local-source tests passed." -ForegroundColor Green
