"""The #442 gate must fail on a detected defect, not just on SIGSEGV.

Run with: python3 -m unittest discover -s scripts -p test_check_scanner_safety.py -v
The sanitizer control compiles a deliberately faulty *temporary fixture*, not
repository source. It verifies the actual compiler/runner path; mocks alone
cannot prove that sanitizer diagnostics make the gate fail.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch

import check_scanner_safety as safety


class ScannerSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.results = self.root / "results"
        self.results.mkdir()
        self.vendor = self.root / "vendor"
        self.vendor.mkdir()
        for name, value in [("ROOT", self.root), ("RESULTS", self.results),
                            ("VENDOR", self.vendor)]:
            self.enterContext(patch.object(safety, name, value))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def successful_native(self, source, name, flags, expected=0):
        (self.results / f"{name}.log").write_text("PASS\n")
        return 0

    def test_checked_in_vendor_always_gets_domain_and_fatal_sanitizer_checks(self):
        with patch.object(safety, "native", side_effect=self.successful_native) as native:
            with patch.object(safety.urllib.request, "urlopen") as download:
                safety.prepare()
                download.assert_not_called()
        self.assertEqual(native.call_args_list, [
            call(self.vendor, "patched-domain", ["-DCHECK_CTYPE_DOMAIN"]),
            call(self.vendor, "patched-native", []),
            call(self.vendor, "patched-sanitized", safety.SANITIZER_FLAGS),
        ])
        self.assertIn("-fno-sanitize-recover=all", safety.SANITIZER_FLAGS)

    def test_domain_violation_cannot_be_masked_by_later_native_passes(self):
        with patch.object(safety, "native", side_effect=RuntimeError("exit 86")) as native:
            with self.assertRaisesRegex(RuntimeError, "exit 86"):
                safety.prepare()
        native.assert_called_once_with(self.vendor, "patched-domain", ["-DCHECK_CTYPE_DOMAIN"])

    def test_sanitizer_failure_is_not_swallowed(self):
        with patch.object(safety, "native", side_effect=[0, 0, RuntimeError("UBSan")]):
            with self.assertRaisesRegex(RuntimeError, "UBSan"):
                safety.prepare()

    def test_real_undefined_behavior_fails_even_with_inherited_recovery_options(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "scanner_brace_probe.c").write_text(
            "#include <limits.h>\n"
            "int main(void) { volatile int value = INT_MAX; value += 1; return 0; }\n"
        )
        # With the old recoverable flags this program printed a diagnostic but
        # exited zero. The new native path must fail, without mutating os.environ.
        inherited = {"ASAN_OPTIONS": "halt_on_error=0:exitcode=0",
                     "UBSAN_OPTIONS": "halt_on_error=0:exitcode=0"}
        with patch.dict(os.environ, inherited):
            # Any nonzero status: Linux honours exitcode=1, while macOS's UBSan
            # runtime aborts under -fno-sanitize-recover (SIGABRT, -6). Both
            # fail the gate, which is the property under test.
            with self.assertRaisesRegex(RuntimeError, r"exited (?!0,)-?\d+, expected 0"):
                safety.native(self.vendor, "overflow-control", safety.SANITIZER_FLAGS)
            for name, value in inherited.items():
                self.assertEqual(os.environ[name], value)
        log = (self.results / "overflow-control.log").read_text()
        self.assertIn("runtime error: signed integer overflow", log)

    def test_safe_native_control_still_passes(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "scanner_brace_probe.c").write_text("int main(void) { return 0; }\n")
        self.assertEqual(safety.native(self.vendor, "safe-control", safety.SANITIZER_FLAGS), 0)

    def test_repeat_retains_failure_after_subsequent_successes(self):
        with patch.object(safety, "run", side_effect=[0, 101, 0, 0, 0, 0]) as run:
            with self.assertRaisesRegex(RuntimeError, "1/6 --lib runs failed"):
                safety.repeat(2)
        records = json.loads((self.results / "lib-runs.json").read_text())
        self.assertEqual([row["exit"] for row in records], [0, 101, 0, 0, 0, 0])
        self.assertEqual(run.call_count, 6)
        self.assertEqual([row["mode"] for row in records],
                         ["default"] * 2 + ["threads-128"] * 2 + ["serial"] * 2)
        self.assertEqual([entry.args[0] for entry in run.call_args_list], [
            ["cargo", "test", "--locked", "--lib"],
            ["cargo", "test", "--locked", "--lib"],
            ["cargo", "test", "--locked", "--lib", "--", "--test-threads=128"],
            ["cargo", "test", "--locked", "--lib", "--", "--test-threads=128"],
            ["cargo", "test", "--locked", "--lib", "--", "--test-threads=1"],
            ["cargo", "test", "--locked", "--lib", "--", "--test-threads=1"],
        ])

    def test_repeat_retains_timeouts_as_failures(self):
        with patch.object(safety, "run", side_effect=[
            subprocess.TimeoutExpired(["cargo"], 300), 0, 0,
        ]):
            with self.assertRaisesRegex(RuntimeError, "1/3 --lib runs failed"):
                safety.repeat(1)
        records = json.loads((self.results / "lib-runs.json").read_text())
        self.assertEqual([row["exit"] for row in records], ["timeout", 0, 0])


if __name__ == "__main__":
    unittest.main()
