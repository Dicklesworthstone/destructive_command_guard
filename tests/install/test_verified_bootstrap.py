"""Execute the documented installer bootstrap against real Minisign signatures.

Run with Python 3 and minisign on PATH:
    python3 -m unittest discover -s tests/install -p test_verified_bootstrap.py -v

DCG_TEST_MINISIGN may name a verifier installed outside PATH. Optional
DCG_TEST_RELEASE_ASSETS points at downloaded v0.16.0 assets for an additional
real-release verification check; those published scripts are NEVER executed.

Only the download boundary and sudo are replaced. The documentation's actual
shell code, the cryptographic verifier, and both SHA-256 implementations run.
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


def verifier_path() -> str:
    requested = os.environ.get("DCG_TEST_MINISIGN", "minisign")
    binary = shutil.which(requested)
    if not binary:
        raise RuntimeError("Install minisign or set DCG_TEST_MINISIGN; cryptographic tests require it")
    return str(Path(binary).resolve())


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
        text = (ROOT / "docs/windows.md").read_text()
        begin = "<!-- verified-release-install-powershell:begin -->"
        end = "<!-- verified-release-install-powershell:end -->"
        self.assertEqual(text.count(begin), 1)
        self.assertEqual(text.count(end), 1)
        section = text.split(begin, 1)[1].split(end, 1)[0]
        blocks = re.findall(r"```powershell\n(.*?)\n```", section, re.DOTALL)
        self.assertEqual(len(blocks), 1)
        recipe = blocks[0]
        for pin in (VERSION, PUBLIC_KEY, POWERSHELL_SHA256):
            self.assertEqual(recipe.count(pin), 1)
        self.assertNotRegex(recipe, r"(?i)Invoke-Expression|ScriptBlock\s*\]::Create|\biex\b")
        self.assertRegex(recipe, r"Get-Command\s+minisign\s+-CommandType\s+Application")
        signature_call = recipe.index("-Vm $installer -x $signature -P $key")
        signature_guard = recipe.index("if ($signatureExit -ne 0) { throw")
        hash_check = recipe.index("Get-FileHash -LiteralPath $installer -Algorithm SHA256")
        hash_guard = recipe.index("if ($actualHash.ToLowerInvariant() -cne $expectedHash)")
        execute = recipe.index("& $installer @installArgs")
        self.assertLess(signature_call, signature_guard)
        self.assertLess(signature_guard, hash_check)
        self.assertLess(hash_check, hash_guard)
        self.assertLess(hash_guard, recipe.index("throw ", hash_guard))
        self.assertLess(recipe.index("throw ", hash_guard), execute)
        self.assertIn("Version = $tag; RequireMinisign = $true", recipe[:execute])


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
