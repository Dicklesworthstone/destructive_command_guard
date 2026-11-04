"""Execute the documented installer bootstrap against real Minisign signatures.

Run with Python 3 and minisign on PATH:
    python3 -m unittest discover -s tests/install -p test_verified_bootstrap.py -v

DCG_TEST_MINISIGN may name a verifier installed outside PATH. Optional
DCG_TEST_RELEASE_ASSETS points at downloaded v0.16.0 assets for an additional
real-release authentication check; the published script's execution boundary is
intercepted in that check. DCG_TEST_POWERSHELL adds an engine outside PATH;
available pwsh and Windows PowerShell are both exercised. DCG_TEST_WINDOWS_DOC
selects another documentation snapshot for regression/mutation checks.

Only DCG_TEST_NATIVE_WINDOWS_INSTALL=1 on native Windows enables a real public
v0.16.0 install, into a retained scratch destination with -NoConfigure and no
self-healing. This opt-in test leaves the documented trust root and download
path intact, and adds only isolation arguments at the child-process boundary.

The documentation's actual shell code, cryptographic verifier, SHA-256 checks,
and child PowerShell processes run. Test fixtures replace fixed trust literals
and downloads. Windows tests keep the real ACL/Unblock-File operations; Unix
tests explicitly omit that unsupported platform boundary and do not qualify it.
Fixtures and logs are retained under the printed temporary directory, including
fresh TEST-ONLY signing keys; no project release private key is used or needed.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERSION = "v0.16.0"
PUBLIC_KEY = "RWSoYi6NXJWzaRs1mJmOwwXrZfPWcq6MXnQlNMLBYKzlIQTLwuVQG6uO"
INSTALLER_SHA256 = "072462974ad790008e8a3aadb1a9eecf2d9b6bd0ef7b469f69f0fb0fa3b51c7c"
POWERSHELL_SHA256 = "f662ac7d34d2b7545a0e3ad7d5c7baff561fb6ccf96e75ee31d7f8b37fce7696"
BASE_URL = (
    "https://github.com/Dicklesworthstone/destructive_command_guard"
    f"/releases/download/{VERSION}"
)
BEGIN = "<!-- verified-release-install:begin -->"
END = "<!-- verified-release-install:end -->"
MARKER_SCRIPT = b'''#!/usr/bin/env bash
printf '%s\\n' "$@" >> "$DCG_TEST_MARKER"
'''


def documented_shell(path: Path) -> str:
    """Take the runnable block verbatim, so documentation is the code under test."""
    text = path.read_text(encoding="utf-8")
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise AssertionError(f"{path.name}: expected one marked installation recipe")
    section = text.split(BEGIN, 1)[1].split(END, 1)[0]
    blocks = re.findall(r"```bash\n(.*?)\n```", section, re.DOTALL)
    if len(blocks) != 1:
        raise AssertionError(f"{path.name}: expected one Bash block between markers")
    return blocks[0]


def documented_powershell(path: Path | None = None) -> str:
    path = path or Path(os.environ.get("DCG_TEST_WINDOWS_DOC", ROOT / "docs/windows.md"))
    text = path.read_text(encoding="utf-8")
    begin = "<!-- verified-release-install-powershell:begin -->"
    end = "<!-- verified-release-install-powershell:end -->"
    if text.count(begin) != 1 or text.count(end) != 1:
        raise AssertionError(f"{path.name}: expected one marked installation recipe")
    section = text.split(begin, 1)[1].split(end, 1)[0]
    blocks = re.findall(r"```powershell\n(.*?)\n```", section, re.DOTALL)
    if len(blocks) != 1:
        raise AssertionError(f"{path.name}: expected one PowerShell block between markers")
    return blocks[0]


def verifier_path() -> str:
    requested = os.environ.get("DCG_TEST_MINISIGN", "minisign")
    binary = shutil.which(requested)
    if not binary:
        raise RuntimeError("Install minisign or set DCG_TEST_MINISIGN; cryptographic tests require it")
    return str(Path(binary).resolve())


def fleet_probe_template(delimiter: str) -> str:
    """Read a quoted probe template without running the fleet driver or SSH."""
    script = (ROOT / "scripts/e2e_fleet_install.sh").read_text()
    marker = f"cat <<'{delimiter}'\n"
    if script.count(marker) != 1:
        raise AssertionError(f"Expected exactly one {delimiter} fleet probe template")
    return script.split(marker, 1)[1].split(f"\n{delimiter}\n", 1)[0]


class DocumentationContractTests(unittest.TestCase):
    def test_recipe_parses_in_available_bash_installations(self):
        recipe = documented_shell(ROOT / "SKILL.md")
        shells = {str(Path(shell).resolve()) for shell in (shutil.which("bash"), "/bin/bash")
                  if shell and os.access(shell, os.X_OK)}
        self.assertTrue(shells, "Bash is required to validate the installation recipe")
        for shell in sorted(shells):
            with self.subTest(shell=shell):
                result = subprocess.run([shell, "-n"], input=recipe, capture_output=True,
                                        text=True, check=False, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_readme_and_skill_execute_the_same_recipe(self):
        self.assertEqual(documented_shell(ROOT / "SKILL.md"), documented_shell(ROOT / "README.md"))

    def test_trust_root_and_release_identity_are_explicit(self):
        recipe = documented_shell(ROOT / "SKILL.md")
        self.assertIn(VERSION, recipe)
        self.assertEqual(recipe.count(PUBLIC_KEY), 1)
        self.assertEqual(recipe.count(INSTALLER_SHA256), 1)
        self.assertEqual((ROOT / "release/minisign.pub").read_text().splitlines()[1], PUBLIC_KEY)
        self.assertIn(f'"{PUBLIC_KEY}"', (ROOT / "install.sh").read_text())

    def test_prominent_entrypoints_do_not_offer_mutable_script_downloads(self):
        paths = (
            "README.md", "SKILL.md", "docs/windows.md", "docs/scan-precommit-guide.md",
            "docs/pi-integration.md", "install.sh", "install.ps1", "uninstall.sh", "uninstall.ps1",
        )
        unsafe = re.compile(
            r"https://raw\.githubusercontent\.com/Dicklesworthstone/destructive_command_guard/"
            r"(?:main|master)/(?:install|uninstall)\.(?:sh|ps1)"
            r"|https://github\.com/Dicklesworthstone/destructive_command_guard/"
            r"releases/latest/download/(?:install|uninstall)\.(?:sh|ps1)"
        )
        for name in paths:
            with self.subTest(path=name):
                self.assertIsNone(unsafe.search((ROOT / name).read_text()), name)

    def test_windows_recipe_has_the_same_pinned_trust_boundary(self):
        # A source contract check, not a substitute for native PowerShell/ACL
        # execution. The actual published PS1 signature is verified separately.
        recipe = documented_powershell(ROOT / "docs/windows.md")
        for pin in (VERSION, PUBLIC_KEY, POWERSHELL_SHA256):
            self.assertEqual(recipe.count(pin), 1)
        self.assertNotRegex(recipe, r"(?i)Invoke-Expression|ScriptBlock\s*\]::Create|\biex\b")
        self.assertRegex(recipe, r"Get-Command\s+minisign\s+-CommandType\s+Application")
        signature_call = recipe.index("-Vm $installer -x $signature -P $key")
        signature_guard = recipe.index("if ($signatureExit -ne 0) { throw")
        hash_check = recipe.index("Get-FileHash -LiteralPath $installer -Algorithm SHA256")
        hash_guard = recipe.index("if ($actualHash.ToLowerInvariant() -cne $expectedHash)")
        execute = recipe.index("$installProcess = Start-Process")
        self.assertLess(signature_call, signature_guard)
        self.assertLess(signature_guard, hash_check)
        self.assertLess(hash_check, hash_guard)
        self.assertLess(hash_guard, recipe.index("throw ", hash_guard))
        self.assertLess(recipe.index("throw ", hash_guard), execute)
        self.assertIn("'-Version', $tag, '-RequireMinisign', '-Verify'", recipe[:execute])
        self.assertIn("$global:LASTEXITCODE = -1", recipe[:signature_call])
        self.assertIn("$signatureExit = $global:LASTEXITCODE", recipe[signature_call:signature_guard])
        self.assertIn("-Wait -PassThru -NoNewWindow -ErrorAction Stop", recipe[execute:])
        self.assertIn("$null -eq $installProcess.ExitCode -or $installProcess.ExitCode -ne 0", recipe[execute:])

    def test_windows_fleet_probe_authenticates_before_execution_and_requires_a_receipt(self):
        # Structural checks only: native PowerShell and Windows ACL execution
        # still belong to the native release-host verification lane.
        probe = fleet_probe_template("PSEOF")
        self.assertEqual(probe.count(PUBLIC_KEY), 1)
        self.assertNotIn("$RepoRaw", probe)
        verify = probe.index("-Vm $installerPath -x $installerSignaturePath -P $minisignPublicKey")
        signature_guard = probe.index("if ($signatureExit -ne 0) { throw 'invalid installer signature' }")
        identity_guard = probe.index("$signatureLines.Count -ne 4 -or")
        receipt = probe.index("Emit 'installer_signature_verified' 'PASS'")
        unblock = probe.index("Unblock-File -LiteralPath $installerPath")
        execute = probe.index("$installerProcess = Start-Process")
        self.assertLess(verify, signature_guard)
        self.assertLess(signature_guard, identity_guard)
        self.assertLess(identity_guard, receipt)
        self.assertLess(receipt, unblock)
        self.assertLess(unblock, execute)
        self.assertIn("$global:LASTEXITCODE = -1", probe[:verify])
        self.assertIn("$signatureExit = $global:LASTEXITCODE", probe[verify:signature_guard])
        self.assertNotRegex(probe, r"(?im)^\s*\$LASTEXITCODE\s*=")
        self.assertIn("-RequireMinisign', '-Verify', '-NoConfigure'", probe[:execute])
        self.assertIn("$null -eq $installerProcess.ExitCode -or $installerProcess.ExitCode -ne 0", probe)
        self.assertIn(
            'trusted comment: dsr-built destructive_command_guard $Version additional $actualInstallerSha',
            probe[:receipt],
        )
        self.assertIn(
            'trusted comment: dsr strict release destructive_command_guard $Version additional $actualInstallerSha',
            probe[:receipt],
        )
        self.assertIn(
            '$signatureLines[2] -cne $expectedIdentity -and $signatureLines[2] -cne $strictIdentity',
            probe[identity_guard:receipt],
        )
        driver = (ROOT / "scripts/e2e_fleet_install.sh").read_text()
        cases = re.search(r"EXPECTED_CASES=\((.*?)\)", driver, re.DOTALL)
        self.assertIsNotNone(cases)
        self.assertIn("installer_signature_verified", cases.group(1).split())


class PowerShellBootstrapTestCase(unittest.TestCase):
    """Shared engines and fresh test signing key; contains no test cases."""

    @classmethod
    def setUpClass(cls):
        candidates = (os.environ.get("DCG_TEST_POWERSHELL"), shutil.which("pwsh"),
                      shutil.which("powershell"))
        cls.shells = sorted({str(Path(path).resolve()) for path in candidates if path})
        if not cls.shells:
            if os.environ.get("DCG_TEST_NATIVE_WINDOWS_INSTALL") == "1":
                raise RuntimeError("Requested native Windows qualification requires PowerShell")
            raise unittest.SkipTest("PowerShell unavailable; native Windows qualification is still required")
        cls.minisign = verifier_path()
        cls.work = Path(tempfile.mkdtemp(prefix=f"dcg-{cls.__name__}-"))
        print(f"\nRetained PowerShell fixtures: {cls.work}", file=sys.stderr)
        cls.key = cls.work / "test-only.key"
        public = cls.work / "test-only.pub"
        subprocess.run([cls.minisign, "-G", "-W", "-p", str(public), "-s", str(cls.key)],
                       check=True, capture_output=True, timeout=15)
        cls.key.chmod(0o600)
        cls.public_key = public.read_text().splitlines()[1]
        cls.sequence = 0

    @staticmethod
    def quote(value):
        return "'" + str(value).replace("'", "''") + "'"


class FleetPowerShellExitTests(PowerShellBootstrapTestCase):
    """Execute fleet blocks with real signatures and child PowerShell processes.

    Windows ACL setup and downloads are outside these isolated blocks. Actual
    Minisign, native process launches, and child PowerShell run; the fixtures
    use a fresh test key and never contact a release server.
    """

    def run_probe(self, shell, *, scenario="valid", scope="function", installer_body=None,
                  stale_exit=0):
        type(self).sequence += 1
        directory = self.work / f"{type(self).sequence:03d}-{scenario}-{scope}"
        directory.mkdir()
        installer = directory / "install.ps1"
        installer.write_text(
            "param([string]$Version, [string]$Dest, [switch]$RequireMinisign, "
            "[switch]$Verify, [switch]$NoConfigure)\n" +
            (installer_body if installer_body is not None else
             "if ($Version -ne 'v0.16.0' -or -not $RequireMinisign -or "
             "-not $Verify -or -not $NoConfigure) { throw 'missing strict install arguments' }\n"
             "Set-Content -LiteralPath (Join-Path $PSScriptRoot 'installer-ran') -Value 'yes'\n"),
            encoding="utf-8",
        )
        digest = hashlib.sha256(installer.read_bytes()).hexdigest()
        signature = directory / "install.ps1.minisig"
        comment = f"dsr-built destructive_command_guard {VERSION} additional {digest}"
        subprocess.run([self.minisign, "-S", "-s", str(self.key), "-m", str(installer),
                        "-x", str(signature), "-t", comment],
                       check=True, capture_output=True, timeout=15)
        if scenario == "invalid-signature":
            installer.write_text(installer.read_text() + "# modified after signing\n")
            digest = hashlib.sha256(installer.read_bytes()).hexdigest()
        verifier = self.minisign
        if scenario == "failed-launch":
            verifier = str(directory / "missing-minisign.exe")

        probe = fleet_probe_template("PSEOF")
        signature_url = '-Uri "$RepoRelease/$Version/install.ps1.minisig"'
        begin = probe.rfind("try {\n", 0, probe.index(signature_url))
        end = probe.index("$logText = ''")
        self.assertGreaterEqual(begin, 0)
        body = probe[begin:end]
        self.assertIn("Emit 'installer_signature_verified' 'PASS'", body)
        self.assertIn("Emit 'install' 'PASS'", body)
        # Invoke-WebRequest does no work: fixture bytes already exist. Unblock
        # is a Windows-only boundary, not a cryptographic test substitution.
        prelude = (
            "$ErrorActionPreference = 'Continue'\n"
            "function Emit([string]$name, [string]$status, [string]$detail = '') {\n"
            "  Write-Output \"RESULT:${name}:${status}:${detail}\"\n}\n"
            "function Invoke-WebRequest { param([switch]$UseBasicParsing, $TimeoutSec, $UserAgent, "
            "$Uri, $OutFile, $ErrorAction) }\n"
            "function Unblock-File { param($LiteralPath, $ErrorAction) }\n"
            f"$work = {self.quote(directory)}\n"
            f"$installerPath = {self.quote(installer)}\n"
            f"$installerSignaturePath = {self.quote(signature)}\n"
            f"$minisign = {self.quote(verifier)}\n"
            f"$minisignPublicKey = {self.quote(self.public_key)}\n"
            f"$Version = {self.quote(VERSION)}\n"
            f"$actualInstallerSha = {self.quote(digest)}\n"
            "$RepoRelease = 'https://invalid.example/never-contacted'\n"
            "$dest = Join-Path $work 'bin with spaces'\n"
            f"$global:LASTEXITCODE = {stale_exit}\n"
        )
        if scope == "function":
            code = prelude + "function Invoke-Probe {\n$LASTEXITCODE = 71\n" + body + "\n}\nInvoke-Probe\n"
        else:
            code = prelude + body
        harness = directory / "probe.ps1"
        harness.write_text(code, encoding="utf-8-sig")
        result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
                                cwd=directory, capture_output=True, text=True, check=False, timeout=40)
        (directory / "stdout.log").write_text(result.stdout)
        (directory / "stderr.log").write_text(result.stderr)
        return result, directory

    def test_valid_signature_in_script_and_shadowing_function_scopes(self):
        for shell in self.shells:
            for scope in ("script", "function"):
                for stale_exit in (0, 37):
                    with self.subTest(shell=shell, scope=scope, stale_exit=stale_exit):
                        result, directory = self.run_probe(shell, scope=scope, stale_exit=stale_exit)
                        self.assertIn("RESULT:installer_signature_verified:PASS", result.stdout)
                        self.assertIn("RESULT:install:PASS", result.stdout, result.stdout + result.stderr)
                        self.assertTrue((directory / "installer-ran").exists())

    def test_invalid_signature_and_failed_launch_ignore_stale_success(self):
        for shell in self.shells:
            for scenario in ("invalid-signature", "failed-launch"):
                for scope in ("script", "function"):
                    with self.subTest(shell=shell, scenario=scenario, scope=scope):
                        result, directory = self.run_probe(shell, scenario=scenario, scope=scope)
                        self.assertIn("RESULT:installer_signature_verified:FAIL", result.stdout)
                        self.assertNotIn("RESULT:installer_signature_verified:PASS", result.stdout)
                        self.assertNotIn("RESULT:install:PASS", result.stdout)
                        self.assertFalse((directory / "installer-ran").exists())

    def test_child_installer_exit_and_exception_are_failures(self):
        for shell in self.shells:
            for installer_body in ("exit 23\n", "throw 'fixture installer failure'\n"):
                with self.subTest(shell=shell, installer_body=installer_body):
                    result, _ = self.run_probe(shell, installer_body=installer_body)
                    self.assertIn("RESULT:installer_signature_verified:PASS", result.stdout)
                    self.assertIn("RESULT:install:FAIL", result.stdout, result.stdout + result.stderr)
                    self.assertNotIn("RESULT:install:PASS", result.stdout)

    def test_successful_script_does_not_inherit_a_native_exit_code(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                body = (
                    "if ($env:OS -eq 'Windows_NT') { & $env:ComSpec /c exit 17 } "
                    "else { & /bin/sh -c 'exit 17' }\n"
                    "Set-Content -LiteralPath (Join-Path $PSScriptRoot 'installer-ran') -Value 'yes'\n"
                )
                result, directory = self.run_probe(shell, installer_body=body)
                self.assertIn("RESULT:install:PASS", result.stdout, result.stdout + result.stderr)
                self.assertTrue((directory / "installer-ran").exists())


class DocumentedPowerShellTests(PowerShellBootstrapTestCase):
    """Execute the complete marked Install-DcgRelease function, not a copy."""

    def run_documented_recipe(self, shell, *, scenario="valid", mode="Normal", stale_exit=0,
                              nested=False, installer_body="", published=False, native=False):
        type(self).sequence += 1
        directory = self.work / f"{type(self).sequence:03d}-{scenario}"
        directory.mkdir()
        server = directory / "release"
        server.mkdir()
        installer = server / "install.ps1"
        signature = server / "install.ps1.minisig"
        marker = directory / "installer-ran.json"
        launch = directory / "launch.json"
        download_log = directory / "downloads.log"
        recipe = documented_powershell()
        for pin in (VERSION, PUBLIC_KEY, POWERSHELL_SHA256):
            self.assertEqual(recipe.count(pin), 1)

        if published:
            assets = Path(os.environ["DCG_TEST_RELEASE_ASSETS"])
            for name in ("install.ps1", "install.ps1.minisig"):
                shutil.copy2(assets / name, server / name)
        elif not native:
            installer.write_text(
                "param([string]$Version, [switch]$RequireMinisign, [switch]$Verify, [switch]$EasyMode)\n"
                "[ordered]@{Version=$Version; RequireMinisign=[bool]$RequireMinisign; "
                "Verify=[bool]$Verify; EasyMode=[bool]$EasyMode} | ConvertTo-Json -Compress | "
                f"Set-Content -LiteralPath {self.quote(marker)} -Encoding UTF8\n" + installer_body,
                encoding="utf-8-sig",
            )
            signed = installer
            if scenario == "invalid-signature":
                signed = directory / "different-installer.ps1"
                signed.write_bytes(installer.read_bytes() + b"# another signed script\n")
            if scenario != "missing-signature":
                subprocess.run([self.minisign, "-S", "-s", str(self.key), "-m", str(signed),
                                "-x", str(signature), "-t", f"test-only release {VERSION}"],
                               check=True, capture_output=True, timeout=15)
            if scenario == "tampered":
                installer.write_bytes(installer.read_bytes() + b"# modified after signing\n")
            digest = hashlib.sha256(installer.read_bytes()).hexdigest()
            if scenario == "wrong-digest":
                digest = "0" * 64
            # Only the fixed test trust literals change; no production override
            # for key, digest, tag, verifier result, or download URL is added.
            recipe = recipe.replace(PUBLIC_KEY, self.public_key).replace(POWERSHELL_SHA256, digest)

        binaries = directory / "bin"
        binaries.mkdir()
        verifier = binaries / ("minisign.exe" if os.name == "nt" else "minisign")
        if scenario == "failed-verifier-launch":
            verifier.write_bytes(b"#!/dcg-nonexistent-interpreter\nexit 0\n")
            verifier.chmod(0o700)
        elif scenario == "success-stderr":
            if os.name == "nt":
                (binaries / "minisign.cmd").write_text(
                    f'@echo off\n>&2 echo ordinary native diagnostic\n"{self.minisign}" %*\nexit /b %ERRORLEVEL%\n',
                    encoding="ascii",
                )
            else:
                verifier.write_text("#!/bin/sh\nprintf '%s\\n' 'ordinary native diagnostic' >&2\n"
                                    f"exec {shlex.quote(self.minisign)} \"$@\"\n")
                verifier.chmod(0o700)
        elif scenario != "missing-verifier":
            shutil.copy2(self.minisign, verifier)
            verifier.chmod(0o700)

        prelude = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
        if not native:
            prelude += (
                "function Invoke-WebRequest {\n"
                "  [CmdletBinding()]\n"
                "  param([switch]$UseBasicParsing, [int]$TimeoutSec, [string]$UserAgent, "
                "[string]$Uri, [string]$OutFile)\n"
                f"  if ($Uri -cne {self.quote(BASE_URL + '/install.ps1')} -and "
                f"$Uri -cne {self.quote(BASE_URL + '/install.ps1.minisig')}) {{ throw 'unexpected download URL' }}\n"
                f"  Add-Content -LiteralPath {self.quote(download_log)} -Value $Uri -Encoding UTF8\n"
                "  $leaf = $Uri.Substring($Uri.LastIndexOf('/') + 1)\n"
            )
            if scenario == "missing-installer":
                prelude += "  if ($leaf -eq 'install.ps1') { throw 'fixture installer unavailable' }\n"
            prelude += (
                f"  Copy-Item -LiteralPath (Join-Path {self.quote(server)} $leaf) "
                "-Destination $OutFile -ErrorAction Stop\n"
            )
            if scenario == "failed-download":
                prelude += "  throw 'fixture download failed after writing bytes'\n"
            prelude += "}\n"

        if os.name != "nt":
            # Keep every authentication/execution statement intact. Only the
            # explicitly Windows-only ACL region is omitted on Unix; native
            # Windows runs the exact original ACL operations and Unblock-File.
            acl_begin = recipe.index("    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User\n")
            acl_end = recipe.index('    Write-Host "Installer verification files: $work"', acl_begin)
            self.assertIn("Set-Acl -LiteralPath $work -AclObject $acl -ErrorAction Stop", recipe[acl_begin:acl_end])
            recipe = recipe[:acl_begin] + "    # Unix test: Windows ACL boundary not executed.\n" + recipe[acl_end:]
            prelude += "function Unblock-File { param($LiteralPath, $ErrorAction) }\n"
            prelude += "Write-Host 'TEST-PLATFORM: Unix; Windows ACL/Unblock-File not qualified'\n"

        if published or native or scenario in ("failed-installer-launch", "missing-installer-status"):
            # Refuse a recipe with an execution path that our interception
            # would miss. Published bytes must never run in the auth-only test.
            self.assertEqual(recipe.count("Start-Process"), 1)
            self.assertNotRegex(recipe, r"[&.]\s+\$installer\b")
            prelude += (
                "function Start-Process {\n"
                "  [CmdletBinding()]\n"
                "  param([string]$FilePath, [string[]]$ArgumentList, [switch]$Wait, "
                "[switch]$PassThru, [switch]$NoNewWindow)\n"
                "  if (-not $Wait -or -not $PassThru -or -not $NoNewWindow) { throw 'missing process acceptance flags' }\n"
                "  [ordered]@{file=$FilePath; arguments=$ArgumentList} | ConvertTo-Json -Compress | "
                f"Set-Content -LiteralPath {self.quote(launch)} -Encoding UTF8\n"
            )
            if native:
                destination = directory / "native install bin"
                prelude += (
                    f"  $isolatedArguments = @($ArgumentList) + @('-Dest', {self.quote(chr(34) + str(destination) + chr(34))}, '-NoConfigure')\n"
                    "  Microsoft.PowerShell.Management\\Start-Process -FilePath $FilePath "
                    "-ArgumentList $isolatedArguments -Wait -PassThru -NoNewWindow -ErrorAction Stop\n"
                )
            elif published:
                prelude += ("  Write-Host 'PUBLISHED-AUTHENTICATION-ONLY: installer execution intercepted'\n"
                            "  [pscustomobject]@{ExitCode=0}\n")
            elif scenario == "failed-installer-launch":
                prelude += "  throw 'fixture child process failed to launch'\n"
            else:
                prelude += "  [pscustomobject]@{ExitCode=$null}\n"
            prelude += "}\n"

        invoke = f"Install-DcgRelease -Mode {mode}\n"
        if nested:
            invoke = ("function Invoke-NestedCaller {\n  $LASTEXITCODE = 71\n  " + invoke +
                      "}\n$LASTEXITCODE = 83\nInvoke-NestedCaller\n")
        code = prelude + recipe + f"\n$global:LASTEXITCODE = {stale_exit}\ntry {{\n" + invoke
        if native:
            installed = directory / "native install bin" / "dcg.exe"
            code += (
                f"if (-not (Test-Path -LiteralPath {self.quote(installed)})) {{ throw 'native binary missing' }}\n"
                "$ErrorActionPreference = 'Continue'\n$global:LASTEXITCODE = -1\n"
                f"$versionOutput = @(& {self.quote(installed)} --version 2>&1) -join ' '\n"
                "$versionExit = $global:LASTEXITCODE\n$ErrorActionPreference = 'Stop'\n"
                "if ($versionExit -ne 0 -or $versionOutput -notmatch '0[.]16[.]0') { throw 'installed release version mismatch' }\n"
                "Write-Host \"NATIVE-INSTALL:PASS $versionOutput\"\n"
            )
        code += "Write-Host 'DOCUMENTED-BOOTSTRAP:PASS'\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n"
        harness = directory / "documented-recipe.ps1"
        harness.write_text(code, encoding="utf-8-sig")
        env = {key: value for key, value in os.environ.items() if not key.startswith("DCG_")}
        env["PATH"] = str(binaries) + (os.pathsep + os.environ.get("PATH", "") if native else "")
        # These remain inherited by the optional real installer BEFORE its
        # self-test. In particular, never let the test repair the user's hooks.
        env["DCG_SELF_HEAL_HOOK"] = "0"
        env["DCG_HISTORY_DISABLED"] = "1"
        for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_DATA_HOME", "TEMP", "TMP"):
            isolated = directory / ("application data" if name in ("LOCALAPPDATA", "XDG_DATA_HOME") else name.lower())
            isolated.mkdir(exist_ok=True)
            env[name] = str(isolated)
        result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
                                cwd=directory, env=env, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", check=False,
                                timeout=300 if native else 45)
        (directory / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (directory / "stderr.log").write_text(result.stderr, encoding="utf-8")
        return result, directory

    def assert_documented_refusal(self, result, directory):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("DOCUMENTED-BOOTSTRAP:PASS", result.stdout)
        self.assertFalse((directory / "installer-ran.json").exists(), "Unauthenticated installer executed")

    def test_verified_normal_and_easy_modes_survive_stale_codes_and_caller_scopes(self):
        for shell in self.shells:
            for mode in ("Normal", "Easy"):
                for stale_exit, nested in ((0, False), (37, True)):
                    with self.subTest(shell=shell, mode=mode, stale_exit=stale_exit, nested=nested):
                        result, directory = self.run_documented_recipe(
                            shell, mode=mode, stale_exit=stale_exit, nested=nested)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn("DOCUMENTED-BOOTSTRAP:PASS", result.stdout)
                        receipt = json.loads((directory / "installer-ran.json").read_text(encoding="utf-8-sig"))
                        self.assertEqual(receipt, {"Version": VERSION, "RequireMinisign": True,
                                                   "Verify": True, "EasyMode": mode == "Easy"})
                        self.assertEqual((directory / "downloads.log").read_text(encoding="utf-8-sig").splitlines(),
                                         [BASE_URL + "/install.ps1", BASE_URL + "/install.ps1.minisig"])

    def test_authentication_failures_never_execute_the_downloaded_script(self):
        for shell in self.shells:
            for scenario in ("invalid-signature", "tampered", "wrong-digest", "missing-installer",
                             "missing-signature", "missing-verifier", "failed-verifier-launch", "failed-download"):
                with self.subTest(shell=shell, scenario=scenario):
                    result, directory = self.run_documented_recipe(shell, scenario=scenario, nested=True)
                    self.assert_documented_refusal(result, directory)
                    if scenario == "missing-verifier":
                        self.assertFalse((directory / "downloads.log").exists())
                    if scenario in ("invalid-signature", "tampered"):
                        self.assertIn("Installer signature verification failed", result.stderr)
                    if scenario == "failed-verifier-launch":
                        # A native loader exception may terminate the call
                        # before the explicit exit-code guard is reached.
                        self.assertEqual(len((directory / "downloads.log").read_text(encoding="utf-8-sig").splitlines()), 2)
                    if scenario == "wrong-digest":
                        self.assertIn("does not match the pinned release", result.stderr)

    def test_successful_native_stderr_is_not_a_signature_failure(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, directory = self.run_documented_recipe(shell, scenario="success-stderr", nested=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((directory / "installer-ran.json").exists())

    def test_installer_exit_and_exception_are_reported_as_failures(self):
        for shell in self.shells:
            for body in ("exit 23\n", "throw 'fixture installer failure'\n"):
                with self.subTest(shell=shell, body=body):
                    result, directory = self.run_documented_recipe(shell, installer_body=body, nested=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((directory / "installer-ran.json").exists())
                    self.assertIn("Installer failed with exit code", result.stderr)
                    self.assertNotIn("DOCUMENTED-BOOTSTRAP:PASS", result.stdout)

    def test_failed_child_launch_and_unknown_exit_status_fail_closed(self):
        for shell in self.shells:
            for scenario in ("failed-installer-launch", "missing-installer-status"):
                with self.subTest(shell=shell, scenario=scenario):
                    result, directory = self.run_documented_recipe(shell, scenario=scenario)
                    self.assert_documented_refusal(result, directory)
                    self.assertTrue((directory / "launch.json").exists())

    def test_successful_installer_with_expected_native_denial_is_accepted(self):
        body = ("if ($env:OS -eq 'Windows_NT') { & $env:ComSpec /c exit 1 } "
                "else { & /bin/sh -c 'exit 1' }\n"
                "Write-Output 'self-test: expected native denial accepted'\n")
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, directory = self.run_documented_recipe(shell, installer_body=body, nested=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((directory / "installer-ran.json").exists())

    @unittest.skipUnless(os.environ.get("DCG_TEST_RELEASE_ASSETS"), "Optional published release assets not supplied")
    def test_published_v0160_documented_authentication_without_executing_the_installer(self):
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, directory = self.run_documented_recipe(shell, published=True, nested=True, stale_exit=37)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PUBLISHED-AUTHENTICATION-ONLY: installer execution intercepted", result.stdout)
                self.assertFalse((directory / "installer-ran.json").exists())
                receipt = json.loads((directory / "launch.json").read_text(encoding="utf-8-sig"))
                self.assertEqual(receipt["arguments"][-4:], ["-Version", VERSION, "-RequireMinisign", "-Verify"])

    @unittest.skipUnless(os.environ.get("DCG_TEST_NATIVE_WINDOWS_INSTALL") == "1",
                         "Opt-in native Windows installation: set DCG_TEST_NATIVE_WINDOWS_INSTALL=1")
    def test_native_public_v0160_install_in_scratch_without_hook_changes(self):
        self.assertEqual(os.name, "nt", "Requested native installation must run on a Windows host")
        for shell in self.shells:
            with self.subTest(shell=shell):
                result, _ = self.run_documented_recipe(shell, native=True, mode="Normal", nested=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("NATIVE-INSTALL:PASS", result.stdout)
                self.assertIn("Signature verified (minisign key ", result.stdout)


class VerifiedBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.minisign = verifier_path()
        cls.bash = shutil.which("bash")
        if not cls.bash:
            raise RuntimeError("The documented Bash recipe requires bash")
        cls.work = Path(tempfile.mkdtemp(prefix="dcg-verified-bootstrap-tests-"))
        print(f"\nRetained bootstrap fixtures: {cls.work}", file=sys.stderr)
        cls.keys = cls.work / "test-only-keys"
        cls.keys.mkdir(mode=0o700)
        for name in ("trusted", "untrusted"):
            subprocess.run(
                [cls.minisign, "-G", "-W", "-p", str(cls.keys / f"{name}.pub"),
                 "-s", str(cls.keys / f"{name}.key")],
                check=True, capture_output=True, timeout=15,
            )
            (cls.keys / f"{name}.key").chmod(0o600)
        cls.fixture_key = (cls.keys / "trusted.pub").read_text().splitlines()[1]
        cls.fixture_digest = hashlib.sha256(MARKER_SCRIPT).hexdigest()
        cls.sequence = 0

    def run_recipe(
        self, *, mode: str = "", payload: bytes = MARKER_SCRIPT, signature: str = "valid",
        missing: str = "", curl_failure: str = "", no_verifier: bool = False,
        hash_tool: str = "sha256sum", hash_failure: bool = False, trusted_digest: str | None = None,
        conditional: bool = False, extra_args: tuple[str, ...] = (), prelude: str = "",
        ambient: dict[str, str] | None = None,
    ):
        type(self).sequence += 1
        directory = self.work / f"{type(self).sequence:03d}-{self._testMethodName}"
        directory.mkdir(mode=0o700)
        server = directory / "release"
        server.mkdir()
        script = server / "install.sh"
        script.write_bytes(payload)
        sigpath = server / "install.sh.minisig"
        signed = script
        if signature == "other-payload":
            signed = directory / "other-script.sh"
            signed.write_bytes(MARKER_SCRIPT + b"# Different signed installer.\n")
        signer = "untrusted" if signature == "untrusted-key" else "trusted"
        if signature != "missing":
            subprocess.run(
                [self.minisign, "-S", "-s", str(self.keys / f"{signer}.key"),
                 "-m", str(signed), "-x", str(sigpath), "-t", f"test-only release {VERSION}"],
                check=True, capture_output=True, timeout=15,
            )
        if signature == "modified-installer":
            script.write_bytes(payload + b"# Modified after signing.\n")
        if signature == "empty":
            sigpath.write_bytes(b"")

        binaries = directory / "bin"
        binaries.mkdir()
        for command in ("bash", "mktemp", "chmod", "mkdir", "cat", "cut", "awk", "sed"):
            binary = shutil.which(command)
            if binary:
                (binaries / command).symlink_to(binary)
        if hash_tool:
            binary = shutil.which(hash_tool)
            if not binary:
                self.skipTest(f"{hash_tool} is unavailable on this host")
            if hash_failure:
                failing_hash = binaries / hash_tool
                failing_hash.write_text(f"#!{sys.executable}\n" +
                                       f"print({self.fixture_digest!r} + '  installer.sh')\n"
                                       "raise SystemExit(1)\n")
                failing_hash.chmod(0o700)
            else:
                (binaries / hash_tool).symlink_to(binary)
        if not no_verifier:
            (binaries / "minisign").symlink_to(self.minisign)

        # Fail-closed, local-only transport: an unexpected host, tag, or path
        # cannot accidentally reach the network or return a fallback fixture.
        curl = binaries / "curl"
        curl.write_text(f"#!{sys.executable}\n" + '''import json, os, pathlib, sys
args = sys.argv[1:]
urls = [arg for arg in args if arg.startswith("https://")]
if len(urls) != 1:
    sys.exit(98)
url = urls[0]
with open(os.environ["DCG_TEST_DOWNLOAD_LOG"], "a") as log:
    log.write(json.dumps({"url": url, "args": args}) + "\\n")
base = os.environ["DCG_TEST_BASE"]
allowed = [base + "/install.sh", base + "/install.sh.minisig"]
if url not in allowed:
    sys.exit(98)
name = url.rsplit("/", 1)[1]
dest = None
for index, arg in enumerate(args):
    if arg in ("-o", "--output"):
        dest = pathlib.Path(args[index + 1])
if dest is None:
    sys.exit(98)
source = pathlib.Path(os.environ["DCG_TEST_SERVER"]) / name
if name == os.environ.get("DCG_TEST_MISSING") or not source.is_file():
    sys.exit(22)
dest.write_bytes(source.read_bytes())
if name == os.environ.get("DCG_TEST_CURL_FAILURE"):
    sys.exit(22)
''')
        curl.chmod(0o700)
        sudo = binaries / "sudo"
        sudo.write_text(f"#!{sys.executable}\n" + '''import os, sys
with open(os.environ["DCG_TEST_SUDO_LOG"], "a") as log:
    log.write("sudo invoked\\n")
args = sys.argv[1:]
if args and args[0] == "--":
    args.pop(0)
os.execvp(args[0], args)
''')
        sudo.chmod(0o700)
        for name in ("home", "downloads"):
            (directory / name).mkdir(mode=0o700)
        env = {
            "PATH": str(binaries), "HOME": str(directory / "home"),
            "TMPDIR": str(directory / "downloads"), "LC_ALL": "C",
            "DCG_TEST_MARKER": str(directory / "installer-ran"),
            "DCG_TEST_SUDO_LOG": str(directory / "sudo-ran"),
            "DCG_TEST_DOWNLOAD_LOG": str(directory / "downloads.jsonl"),
            "DCG_TEST_SERVER": str(server), "DCG_TEST_BASE": BASE_URL,
            "DCG_TEST_MISSING": missing, "DCG_TEST_CURL_FAILURE": curl_failure,
        }
        env.update(ambient or {})
        recipe = documented_shell(ROOT / "SKILL.md")
        self.assertEqual(recipe.count(PUBLIC_KEY), 1)
        self.assertEqual(recipe.count(INSTALLER_SHA256), 1)
        # Substitute only fixed trust literals in the in-memory TEST copy. The
        # production recipe exposes no test key, URL, or digest override.
        recipe = recipe.replace(PUBLIC_KEY, self.fixture_key).replace(
            INSTALLER_SHA256, trusted_digest or self.fixture_digest,
        )
        args = ([mode] if mode else []) + list(extra_args)
        invocation = "dcg_install" + "".join(" " + shlex.quote(arg) for arg in args)
        if conditional:
            invocation = f"if {invocation}; then exit 0; else exit $?; fi"
        result = subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", prelude + "\n" + recipe + "\n" + invocation],
            env=env, cwd=directory, capture_output=True, text=True, check=False, timeout=20,
        )
        (directory / "stdout.log").write_text(result.stdout)
        (directory / "stderr.log").write_text(result.stderr)
        return result, directory

    def assert_refused(self, result, directory):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((directory / "installer-ran").exists(), "Unverified installer executed")
        self.assertFalse((directory / "sudo-ran").exists(), "Elevated command ran before verification")

    def test_valid_release_preserves_normal_easy_and_system_modes(self):
        for mode in ("", "--easy-mode", "--system"):
            with self.subTest(mode=mode):
                result, directory = self.run_recipe(mode=mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                args = (directory / "installer-ran").read_text().splitlines()
                self.assertEqual(args, ["--version", VERSION, "--require-minisign"] + ([mode] if mode else []))
                self.assertEqual((directory / "sudo-ran").exists(), mode == "--system")
                if mode == "--system":
                    self.assertEqual((directory / "sudo-ran").read_text(), "sudo invoked\n")
                downloads = [json.loads(line) for line in (directory / "downloads.jsonl").read_text().splitlines()]
                self.assertEqual([item["url"] for item in downloads],
                                 [BASE_URL + "/install.sh", BASE_URL + "/install.sh.minisig"])
                for downloaded in (directory / "downloads").glob("*/install.sh"):
                    self.assertEqual(stat.S_IMODE(downloaded.parent.stat().st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE(downloaded.stat().st_mode), 0o600)

    def test_modified_installer_fails_even_with_matching_digest(self):
        modified = MARKER_SCRIPT + b"# Modified after signing.\n"
        for mode in ("", "--easy-mode", "--system"):
            with self.subTest(mode=mode):
                self.assert_refused(*self.run_recipe(
                    mode=mode, signature="modified-installer",
                    trusted_digest=hashlib.sha256(modified).hexdigest(), conditional=True,
                ))

    def test_mismatched_and_untrusted_signatures_fail_before_sudo(self):
        for signature in ("other-payload", "untrusted-key", "empty"):
            with self.subTest(signature=signature):
                self.assert_refused(*self.run_recipe(mode="--system", signature=signature, conditional=True))

    def test_authentic_other_installer_cannot_replace_pinned_release(self):
        self.assert_refused(*self.run_recipe(
            mode="--system", payload=MARKER_SCRIPT + b"# Another authentic release.\n", conditional=True,
        ))

    def test_missing_downloads_refuse_installation_and_elevation(self):
        for missing in ("install.sh", "install.sh.minisig"):
            for mode in ("", "--easy-mode", "--system"):
                with self.subTest(missing=missing, mode=mode):
                    self.assert_refused(*self.run_recipe(mode=mode, missing=missing, conditional=True))

    def test_download_failure_refuses_even_when_valid_bytes_were_written(self):
        for asset in ("install.sh", "install.sh.minisig"):
            with self.subTest(asset=asset):
                self.assert_refused(*self.run_recipe(mode="--system", curl_failure=asset, conditional=True))

    def test_missing_verifier_fails_without_download_or_sudo(self):
        result, directory = self.run_recipe(mode="--system", no_verifier=True, conditional=True)
        self.assert_refused(result, directory)
        self.assertFalse((directory / "downloads.jsonl").exists())

    def test_missing_hash_tool_fails_closed(self):
        self.assert_refused(*self.run_recipe(mode="--system", hash_tool="", conditional=True))

    def test_hash_command_failure_refuses_even_with_expected_digest_on_stdout(self):
        self.assert_refused(*self.run_recipe(mode="--system", hash_failure=True, conditional=True))

    def test_macos_shasum_fallback_verifies_and_refuses_wrong_digest(self):
        result, directory = self.run_recipe(hash_tool="shasum")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((directory / "installer-ran").exists())
        self.assert_refused(*self.run_recipe(
            mode="--system", hash_tool="shasum", trusted_digest="0" * 64, conditional=True,
        ))

    def test_unsafe_or_conflicting_flags_are_rejected(self):
        for args in (("--no-verify",), ("--from-source",), ("--version", "main"),
                     ("--system", "--easy-mode")):
            with self.subTest(args=args):
                result, directory = self.run_recipe(extra_args=args, conditional=True)
                self.assert_refused(result, directory)
                self.assertFalse((directory / "downloads.jsonl").exists())

    def test_ambient_trust_overrides_do_not_change_release_or_key(self):
        ambient = {
            "VERSION": "main", "TAG": "latest", "OWNER": "attacker", "REPO": "payload",
            "MINISIGN_PUBLIC_KEY": (self.keys / "untrusted.pub").read_text().splitlines()[1],
            "CHECKSUM": "0" * 64, "ARTIFACT_URL": "https://attacker.invalid/payload",
        }
        self.assert_refused(*self.run_recipe(
            mode="--system", signature="untrusted-key", ambient=ambient, conditional=True,
        ))

    def test_shell_function_cannot_impersonate_verifier(self):
        self.assert_refused(*self.run_recipe(
            mode="--system", signature="untrusted-key", conditional=True,
            prelude="minisign() { return 0; }\nexport -f minisign",
        ))

    def run_fleet_authentication(self, scenario: str, comment_prefix: str = "dsr-built"):
        """Exercise only the real probe's authentication prefix, never install."""
        type(self).sequence += 1
        directory = self.work / f"{type(self).sequence:03d}-fleet-{scenario}"
        directory.mkdir(mode=0o700)
        server = directory / "release"
        server.mkdir()
        signed = directory / "signed-input.sh"
        signed.write_bytes(MARKER_SCRIPT)
        digest = self.fixture_digest
        comment_tag = "v0.16.1" if scenario == "wrong-tag" else VERSION
        comment_project = "another_project" if scenario == "wrong-project" else "destructive_command_guard"
        comment_digest = "0" * 64 if scenario == "wrong-digest" else digest
        comment_role = "aggregate" if scenario == "wrong-role" else "additional"
        comment = f"{comment_prefix} {comment_project} {comment_tag} {comment_role} {comment_digest}"
        if scenario == "generic-comment":
            comment = f"{comment_prefix} timestamp:123"
        if scenario == "mismatched-signature":
            signed.write_bytes(MARKER_SCRIPT + b"# A different signed script.\n")
        signer = "untrusted" if scenario == "untrusted-key" else "trusted"
        signature = directory / "fixture.minisig"
        subprocess.run(
            [self.minisign, "-S", "-s", str(self.keys / f"{signer}.key"),
             "-m", str(signed), "-x", str(signature), "-t", comment],
            check=True, capture_output=True, timeout=15,
        )
        payload = MARKER_SCRIPT
        if scenario == "rehashed":
            payload += b"# Modified after signing; matching SHA256 sidecar supplied.\n"
        if scenario != "missing-installer":
            (server / "install.sh").write_bytes(payload)
        if scenario != "missing-checksum":
            (server / "install.sh.sha256").write_text(
                hashlib.sha256(payload).hexdigest() + "  install.sh\n",
            )
        if scenario != "missing-signature":
            (server / "install.sh.minisig").write_bytes(signature.read_bytes())

        binaries = directory / "bin"
        binaries.mkdir()
        for name in ("env", "sed", "mktemp", "mkdir", "uname", "awk", "tr", "sha256sum"):
            binary = shutil.which(name)
            if not binary:
                self.skipTest(f"{name} is required by the Unix fleet probe")
            (binaries / name).symlink_to(binary)
        if scenario != "missing-verifier":
            (binaries / "minisign").symlink_to(self.minisign)
        curl = binaries / "curl"
        # Embed test fixture paths: the real probe deliberately removes every
        # DCG_* environment variable before authenticating its download.
        curl.write_text(
            f"#!{sys.executable}\nimport pathlib, sys\n"
            f"server = pathlib.Path({str(server)!r})\n"
            f"base = {BASE_URL!r}\n"
            "args = sys.argv[1:]\n"
            "urls = [arg for arg in args if arg.startswith('https://')]\n"
            "if len(urls) != 1:\n    sys.exit(98)\n"
            "url = urls[0]\n"
            "allowed = [base + '/' + name for name in "
            "('install.sh', 'install.sh.sha256', 'install.sh.minisig')]\n"
            "if url not in allowed:\n    sys.exit(98)\n"
            "dest = None\n"
            "for index, arg in enumerate(args):\n"
            "    if arg in ('-o', '--output'):\n        dest = pathlib.Path(args[index + 1])\n"
            "source = server / url.rsplit('/', 1)[1]\n"
            "if dest is None or not source.is_file():\n    sys.exit(22)\n"
            "dest.write_bytes(source.read_bytes())\n",
        )
        curl.chmod(0o700)
        downloads = directory / "downloads"
        downloads.mkdir(mode=0o700)
        home = directory / "home"
        home.mkdir(mode=0o700)
        probe = fleet_probe_template("PROBE")
        self.assertEqual(probe.count("# 3. Install"), 1, "Never execute a probe without its install boundary")
        prefix = probe.split("# 3. Install", 1)[0]
        self.assertIn("installer_signature_verified", prefix)
        self.assertEqual(prefix.count(PUBLIC_KEY), 1)
        prefix = prefix.replace(PUBLIC_KEY, self.fixture_key)
        marker = directory / "authentication-passed"
        sentinel = f"\nprintf '%s\\n' authenticated > {shlex.quote(str(marker))}\n"
        result = subprocess.run(
            [self.bash, "--noprofile", "--norc", "-c", prefix + sentinel, "fleet-auth-test",
             VERSION, BASE_URL.rsplit("/", 1)[0]],
            env={"PATH": str(binaries), "HOME": str(home), "TMPDIR": str(downloads), "LC_ALL": "C"},
            cwd=directory, capture_output=True, text=True, check=False, timeout=20,
        )
        (directory / "stdout.log").write_text(result.stdout)
        (directory / "stderr.log").write_text(result.stderr)
        return result, marker

    def test_fleet_probe_accepts_an_authenticated_release_before_its_install_boundary(self):
        for prefix in ("dsr-built", "dsr strict release"):
            with self.subTest(prefix=prefix):
                result, marker = self.run_fleet_authentication("valid", prefix)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(marker.exists())
                self.assertIn("RESULT:installer_checksum_verified:PASS", result.stdout)
                self.assertIn("RESULT:installer_signature_verified:PASS", result.stdout)

    def test_fleet_probe_refuses_unverified_or_wrong_release_before_install_boundary(self):
        cases = [(scenario, "dsr-built") for scenario in (
            "rehashed", "mismatched-signature", "untrusted-key", "missing-installer",
            "missing-checksum", "missing-signature", "missing-verifier",
        )]
        cases += [(scenario, prefix) for prefix in ("dsr-built", "dsr strict release")
                  for scenario in ("wrong-tag", "wrong-digest", "wrong-project", "wrong-role", "generic-comment")]
        cases.append(("valid", "dsr-unknown-format"))
        for scenario, prefix in cases:
            with self.subTest(scenario=scenario, prefix=prefix):
                result, marker = self.run_fleet_authentication(scenario, prefix)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(marker.exists(), f"{scenario}: authentication failure reached installation")
                self.assertNotIn("RESULT:installer_signature_verified:PASS", result.stdout)
                if scenario.startswith("wrong-") or scenario in ("generic-comment", "valid"):
                    self.assertIn("does not authenticate the exact project, release, and digest", result.stdout)
                elif scenario in ("rehashed", "mismatched-signature", "untrusted-key"):
                    self.assertIn("invalid installer signature", result.stdout)


@unittest.skipUnless(os.environ.get("DCG_TEST_RELEASE_ASSETS"), "Optional published release assets not supplied")
class PublishedReleaseTests(unittest.TestCase):
    def test_actual_release_installer_identity_and_signature_without_execution(self):
        directory = Path(os.environ["DCG_TEST_RELEASE_ASSETS"])
        for name, digest in (("install.sh", INSTALLER_SHA256), ("install.ps1", POWERSHELL_SHA256)):
            with self.subTest(asset=name):
                installer = directory / name
                self.assertEqual(hashlib.sha256(installer.read_bytes()).hexdigest(), digest)
                result = subprocess.run(
                    [verifier_path(), "-Vm", str(installer), "-x", str(directory / f"{name}.minisig"),
                     "-P", PUBLIC_KEY],
                    capture_output=True, text=True, check=False, timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
