#!/usr/bin/env python3
"""Reproduce #442 against the real C scanner and validate the narrow repair.

prepare: validate the checked-in scanner (bootstrap the pinned copy if absent).
repeat:  run the complete --lib gate repeatedly; retain every failure and log.
publish-tree: stage ONLY the candidate Git objects, never update any Git ref.

The publish command is a bootstrap aid for environments without a local Rust
host. It requires an explicitly supplied GitHub token with contents permission.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "target" / "scanner-safety"
VERSION = "0.25.1"
CHECKSUM = "9e5ec769279cc91b561d3df0d8a5deb26b0ad40d183127f409494d6d8fc53062"
VENDOR = ROOT / "vendor" / "tree-sitter-bash"
PATCHES = ROOT / "vendor" / "patches"
SANITIZER_FLAGS = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-fno-omit-frame-pointer"]
# Do not let inherited recovery/exitcode/suppression options turn a diagnostic
# into a successful gate. These overrides apply only to the native child.
SANITIZER_ENV = {"ASAN_OPTIONS": "halt_on_error=1:exitcode=1",
                 "UBSAN_OPTIONS": "halt_on_error=1:exitcode=1:print_stacktrace=1"}


def run(command: list[str], log_name: str, expected: int | None = 0,
        timeout: int = 300, *, env: dict[str, str] | None = None) -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    log = RESULTS / log_name
    print("+", " ".join(command), flush=True)
    with log.open("wb") as output:
        try:
            process = subprocess.Popen(command, cwd=ROOT, stdout=output,
                                       stderr=subprocess.STDOUT, env=env,
                                       start_new_session=os.name == "posix")
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Cargo has a test-binary child: terminate our entire process group
            # so a timed-out run cannot contaminate the next trial.
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait()
            output.write(b"\nSCANNER-SAFETY: process timed out; not a pass.\n")
            raise
    print(f"exit={status}; log={log}", flush=True)
    if expected is not None and status != expected:
        print(log.read_text(errors="replace")[-24000:], flush=True)
        raise RuntimeError(f"{command[0]} exited {status}, expected {expected}")
    return status


def native(source: Path, name: str, flags: list[str], expected: int | None = 0) -> int:
    binary = RESULTS / name
    run([os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g", *flags,
         "-I", str(source / "src"), str(ROOT / "scripts/scanner_brace_probe.c"),
         "-o", str(binary)], name + "-build.log")
    environment = None
    if any(flag.startswith("-fsanitize=") for flag in flags):
        environment = {**os.environ, **SANITIZER_ENV}
    return run([str(binary)], name + ".log", expected, env=environment)


def prepare() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    if not VENDOR.exists():
        url = f"https://static.crates.io/crates/tree-sitter-bash/tree-sitter-bash-{VERSION}.crate"
        with urllib.request.urlopen(url, timeout=60) as response:
            archive = response.read(16 * 1024 * 1024 + 1)
        if len(archive) > 16 * 1024 * 1024:
            raise RuntimeError("unexpectedly large source archive")
        if hashlib.sha256(archive).hexdigest() != CHECKSUM:
            raise RuntimeError("tree-sitter-bash release checksum mismatch")
        upstream = RESULTS / "upstream"
        upstream.mkdir(exist_ok=False)
        prefix = f"tree-sitter-bash-{VERSION}"
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            members = bundle.getmembers()
            if sum(member.size for member in members) > 64 * 1024 * 1024:
                raise RuntimeError("unexpectedly large expanded source archive")
            for member in members:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or not path.parts
                        or path.parts[0] != prefix
                        or not (member.isfile() or member.isdir())):
                    raise RuntimeError(f"unsafe source archive entry: {member.name}")
            bundle.extractall(upstream, members=members, filter="data")
        source = upstream / prefix
        # Exit 86 is an explicit precondition violation, not a timing-based
        # expectation that undefined behavior must always deliver SIGSEGV.
        native(source, "upstream-domain", ["-DCHECK_CTYPE_DOMAIN"], 86)
        raw_exit = native(source, "upstream-native", [], None)
        (RESULTS / "upstream.json").write_text(json.dumps({
            "version": VERSION, "checksum": CHECKSUM,
            "domain_guard_exit": 86, "uninstrumented_exit": raw_exit,
        }, indent=2) + "\n")
        shutil.copytree(source, VENDOR)
        for patch, directory in [
            (PATCHES / "tree-sitter-bash-0.25.1-unicode.patch", "vendor/tree-sitter-bash"),
            (PATCHES / "dcg-bash-scanner-wiring.patch", None),
        ]:
            arguments = ["git", "apply"]
            if directory:
                arguments.append(f"--directory={directory}")
            run([*arguments, "--check", str(patch)], patch.stem + "-check.log")
            run([*arguments, str(patch)], patch.stem + "-apply.log")
    # Always check the ctype precondition, including on the normal vendored
    # path. A mapped libc table overread need not fault or trip ASAN/UBSAN.
    native(VENDOR, "patched-domain", ["-DCHECK_CTYPE_DOMAIN"])
    native(VENDOR, "patched-native", [])
    native(VENDOR, "patched-sanitized", SANITIZER_FLAGS)
    for name in ["patched-domain", "patched-native", "patched-sanitized"]:
        print((RESULTS / f"{name}.log").read_text(), flush=True)


def repeat(runs: int) -> None:
    if runs < 1 or runs > 100:
        raise ValueError("--runs must be between 1 and 100")
    records: list[dict[str, object]] = []
    # No filter, no skip, no retry-until-green: every nonzero status fails.
    for mode, args, count in [
        ("default", [], runs),
        ("threads-128", ["--", "--test-threads=128"], runs),
        ("serial", ["--", "--test-threads=1"], min(runs, 3)),
    ]:
        for index in range(1, count + 1):
            command = ["cargo", "test", "--locked", "--lib", *args]
            started = time.monotonic()
            try:
                status = run(command, f"lib-{mode}-{index:02}.log", None)
            except subprocess.TimeoutExpired:
                status = "timeout"
            records.append({"mode": mode, "run": index, "exit": status,
                            "seconds": round(time.monotonic() - started, 3)})
            (RESULTS / "lib-runs.json").write_text(json.dumps(records, indent=2) + "\n")
    failures = [record for record in records if record["exit"] != 0]
    print(json.dumps({"runs": len(records), "failures": failures}, indent=2), flush=True)
    if failures:
        raise RuntimeError(f"{len(failures)}/{len(records)} --lib runs failed")


def publish_tree() -> None:
    token = os.environ["GH_TOKEN"]
    repository = os.environ["GITHUB_REPOSITORY"]
    if repository != "Dicklesworthstone/destructive_command_guard":
        raise RuntimeError("candidate upload is scoped to the #442 repository")
    parent = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if parent != os.environ["GITHUB_SHA"]:
        raise RuntimeError("checkout does not match the triggering commit")

    def request(path: str, payload: dict[str, object] | None = None) -> dict[str, object]:
        body = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/{path}", data=body,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "Content-Type": "application/json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(req, timeout=120) as response:
            return json.load(response)

    paths = set()
    for arguments in [["diff", "--name-only", "-z"],
                      ["ls-files", "--others", "--exclude-standard", "-z"]]:
        output = subprocess.check_output(["git", *arguments], cwd=ROOT)
        paths.update(path.decode() for path in output.split(b"\0") if path)
    # src/lib.rs is deliberately absent: the scanner_regression_tests module is
    # declared on main, not by the wiring patch, so the tests run with or without
    # the vendored repair. The candidate is Cargo wiring plus the vendored source.
    if not {"Cargo.toml", "Cargo.lock"}.issubset(paths):
        raise RuntimeError("candidate wiring is absent; refusing to stage an incomplete fix")
    entries = []
    for name in sorted(paths):
        if name not in {"Cargo.toml", "Cargo.lock"} and not name.startswith("vendor/tree-sitter-bash/"):
            raise RuntimeError(f"unexpected candidate change: {name}")
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"candidate must contain only regular files: {name}")
        blob = request("git/blobs", {"content": base64.b64encode(path.read_bytes()).decode(),
                                     "encoding": "base64"})
        entries.append({"path": name, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    commit = request(f"git/commits/{parent}")
    tree = request("git/trees", {"base_tree": commit["tree"]["sha"], "tree": entries})
    result = {"parent": parent, "tree": tree["sha"], "entries": entries,
              "note": "Git objects only: no commit, branch, tag, PR, or ref was created or updated."}
    (RESULTS / "candidate-tree.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "repeat", "publish-tree"])
    parser.add_argument("--runs", type=int, default=12)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    elif args.command == "repeat":
        repeat(args.runs)
    else:
        publish_tree()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"scanner-safety: {error}", file=sys.stderr)
        sys.exit(1)
