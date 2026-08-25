#!/usr/bin/env python3
"""Generate a perf baseline JSON artifact for dcg.

This script measures process-per-invocation latency for representative commands
and records p50/p95/p99/mean/throughput with basic build metadata.

Usage:
  ./scripts/perf_baseline.py --bin ./target/release/dcg --output perf/baselines/latest.json
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, TextIO, Tuple


PROCESS_BACKSTOP_SECONDS = 30.0
TAIL_COVERAGE_PCT = 95
TAIL_CONFIDENCE_PCT = 95
MIN_TOLERANCE_SAMPLES = 59
PERF_ARTIFACT_SCHEMA_VERSION = 4
PERF_HOOK_AGENT = "claude-code"
REQUIRED_ABSOLUTE_GATE_CASE_IDS = (
    "quick_reject",
    "safe_keyword",
    "destructive_keyword",
    "heredoc_inline",
    "full_eval_redirect",
    "full_eval_copy",
    "posix_test_probe",
    "xargs_fixed_template",
    "multi_construct_245",
)

# Populated immediately after argument parsing so an unexpected exception can
# still leave a self-contained ERROR certificate for an explicitly requested
# gate. It deliberately contains only CLI values, never measured state.
_UNCAUGHT_GATE_CONTEXT: Dict[str, Any] = {
    "requested": False,
    "output_path": None,
    "supplied_budget_ms": None,
    "margin_pct": 50,
}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def capture_host_context() -> Dict[str, Any]:
    """Capture coarse host/load context without claiming benchmark control."""
    try:
        load_average = list(os.getloadavg())
    except (AttributeError, OSError):
        load_average = None
    return {
        "node": platform.node(),
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "processor": platform.processor() or None,
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "load_average_1m_5m_15m": load_average,
    }


def run_one(
    bin_path: str,
    command: str,
    env: Dict[str, str],
    working_directory: str,
    expected_decision: str,
) -> float:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    start = time.perf_counter_ns()
    result = subprocess.run(
        [bin_path, "--agent", PERF_HOOK_AGENT],
        input=payload,
        capture_output=True,
        check=False,
        env=env,
        cwd=working_directory,
        timeout=PROCESS_BACKSTOP_SECONDS,
    )
    end = time.perf_counter_ns()
    inspect_hook_result(result, expected_decision, "timed hook invocation")
    return (end - start) / 1_000_000.0


def measure_max_rss_kb(
    bin_path: str,
    command: str,
    env: Dict[str, str],
    working_directory: str,
) -> Optional[int]:
    """Measure max RSS in KB using /usr/bin/time -v."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    try:
        result = subprocess.run(
            ["/usr/bin/time", "-v", bin_path, "--agent", PERF_HOOK_AGENT],
            input=payload,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
            cwd=working_directory,
            timeout=PROCESS_BACKSTOP_SECONDS,
        )
        if result.returncode != 0:
            return None
        # Parse "Maximum resident set size (kbytes): NNNN" from stderr
        for line in result.stderr.decode(errors="replace").splitlines():
            if "Maximum resident set size" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    return int(parts[1].strip())
        return None
    except subprocess.TimeoutExpired:
        raise
    except Exception:
        return None


def percentile(sorted_values: List[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = int(round((pct / 100.0) * (len(sorted_values) - 1)))
    idx = max(0, min(idx, len(sorted_values) - 1))
    return sorted_values[idx]


def inspect_hook_result(
    result: subprocess.CompletedProcess[bytes],
    expected_decision: str,
    context: str,
) -> Dict[str, Any]:
    """Validate one completed hook process and summarize its wire result."""
    if result.returncode != 0:
        raise RuntimeError(
            f"{context} exited {result.returncode}, expected hook exit 0; "
            f"stderr={result.stderr.decode(errors='replace')[:240]!r}"
        )

    observed_decision: str
    if not result.stdout:
        observed_decision = "allow"
        if result.stderr:
            raise RuntimeError(
                f"{context} allow result polluted stderr; refusing to credit a "
                "non-conformant hook result"
            )
    else:
        try:
            parsed = json.loads(result.stdout)
            observed_decision = parsed["hookSpecificOutput"]["permissionDecision"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError(
                f"{context} emitted non-hook stdout; refusing to credit it: "
                f"{result.stdout[:240]!r}"
            ) from exc
        if observed_decision != "deny":
            raise RuntimeError(
                f"{context} emitted unexpected decision {observed_decision!r}"
            )
        if not result.stderr:
            raise RuntimeError(f"{context} deny result lost its stderr warning")

    if observed_decision != expected_decision:
        raise RuntimeError(
            f"{context} observed {observed_decision!r}, "
            f"expected {expected_decision!r}"
        )

    return {
        "expected_decision": expected_decision,
        "observed_decision": observed_decision,
        "returncode": result.returncode,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }


def validate_hook_case(
    bin_path: str,
    command: str,
    env: Dict[str, str],
    working_directory: str,
    expected_decision: str,
) -> Dict[str, Any]:
    """Prove that a timing candidate reached the intended hook outcome."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    result = subprocess.run(
        [bin_path, "--agent", PERF_HOOK_AGENT],
        input=payload,
        capture_output=True,
        check=False,
        env=env,
        cwd=working_directory,
        timeout=PROCESS_BACKSTOP_SECONDS,
    )
    return inspect_hook_result(result, expected_decision, "semantic control")


def summarize_timings(timings: List[float]) -> Dict[str, Any]:
    timings_sorted = sorted(timings)
    mean_ms = sum(timings_sorted) / len(timings_sorted)
    return {
        "p50_ms": statistics.median(timings_sorted),
        "p95_ms": percentile(timings_sorted, 95),
        "p99_ms": percentile(timings_sorted, 99),
        "mean_ms": mean_ms,
        "throughput_per_s": 1000.0 / mean_ms if mean_ms > 0 else 0.0,
        "sample_count": len(timings_sorted),
    }


def summarize_paired_deltas(deltas: List[float]) -> Dict[str, Any]:
    summary = summarize_timings(deltas)
    # A signed paired delta is not a throughput measurement. Negative samples
    # are retained as host-noise evidence rather than silently clamped away.
    summary.pop("throughput_per_s")
    summary["negative_sample_count"] = sum(value < 0 for value in deltas)
    summary["min_ms"] = min(deltas)
    summary["max_ms"] = max(deltas)
    return summary


def run_case(
    bin_path: str,
    command: str,
    env: Dict[str, str],
    working_directory: str,
    expected_decision: str,
    warmup: int,
    runs: int,
    paired_bypass: bool,
    measure_rss: bool = True,
) -> Dict[str, Any]:
    control_before = validate_hook_case(
        bin_path, command, env, working_directory, expected_decision
    )
    bypass_env = env.copy()
    bypass_env["DCG_BYPASS"] = "1"
    bypass_control_before = None
    if paired_bypass:
        bypass_control_before = validate_hook_case(
            bin_path, command, bypass_env, working_directory, "allow"
        )

    def measure_pair(index: int) -> Tuple[float, Optional[float]]:
        if not paired_bypass:
            return (
                run_one(
                    bin_path,
                    command,
                    env,
                    working_directory,
                    expected_decision,
                ),
                None,
            )
        if index % 2 == 0:
            full_ms = run_one(
                bin_path, command, env, working_directory, expected_decision
            )
            bypass_ms = run_one(
                bin_path, command, bypass_env, working_directory, "allow"
            )
        else:
            bypass_ms = run_one(
                bin_path, command, bypass_env, working_directory, "allow"
            )
            full_ms = run_one(
                bin_path, command, env, working_directory, expected_decision
            )
        return full_ms, bypass_ms

    for index in range(warmup):
        measure_pair(index)

    timings: List[float] = []
    bypass_timings: List[float] = []
    paired_deltas: List[float] = []
    for index in range(runs):
        full_ms, bypass_ms = measure_pair(index)
        timings.append(full_ms)
        if bypass_ms is not None:
            bypass_timings.append(bypass_ms)
            paired_deltas.append(full_ms - bypass_ms)

    # Measure max RSS (single measurement after warmup)
    max_rss_kb = None
    if measure_rss:
        max_rss_kb = measure_max_rss_kb(
            bin_path, command, env, working_directory
        )

    metrics = summarize_timings(timings)
    metrics["max_rss_kb"] = max_rss_kb
    metrics["samples_ms"] = timings
    result = {
        "metrics": metrics,
        "semantic_controls": {
            "before": control_before,
            "after": validate_hook_case(
                bin_path, command, env, working_directory, expected_decision
            ),
        },
    }
    if paired_bypass:
        bypass_metrics = summarize_timings(bypass_timings)
        bypass_metrics["samples_ms"] = bypass_timings
        result["bypass_metrics"] = bypass_metrics
        result["bypass_semantic_controls"] = {
            "before": bypass_control_before,
            "after": validate_hook_case(
                bin_path, command, bypass_env, working_directory, "allow"
            ),
        }
        evaluator_delta_metrics = summarize_paired_deltas(paired_deltas)
        evaluator_delta_metrics["samples_ms"] = paired_deltas
        result["evaluator_delta_metrics"] = evaluator_delta_metrics
    return result


def capture_version_output(
    bin_path: str, env: Dict[str, str], working_directory: str
) -> str:
    result = subprocess.run(
        [bin_path, "--version"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        cwd=working_directory,
        timeout=PROCESS_BACKSTOP_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(f"dcg --version exited {result.returncode}")
    return (result.stdout + result.stderr).strip()


def create_toolchain_probe_environment(
    host_environment: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Preserve host rustup discovery without contaminating measured children."""
    source = os.environ if host_environment is None else host_environment
    env = {
        key: value
        for key, value in source.items()
        if not key.startswith("DCG_")
    }
    identity_keys = (
        "CARGO_HOME",
        "HOME",
        "PATH",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "USERPROFILE",
    )
    return env, {
        "scope": (
            "host build-toolchain probe only; this environment is never passed "
            "to measured dcg children"
        ),
        "host_home_preserved_for_rustup_proxy": True,
        "ambient_dcg_keys_scrubbed": sorted(
            key for key in source if key.startswith("DCG_")
        ),
        "identity_environment_value_sha256": {
            key: hashlib.sha256(env[key].encode()).hexdigest()
            for key in identity_keys
            if key in env
        },
    }


def capture_rustc_version(
    env: Dict[str, str], working_directory: str
) -> Dict[str, Any]:
    executable = shutil.which("rustc", path=env.get("PATH"))
    canonical_executable = os.path.realpath(executable) if executable else None
    executable_sha256 = None
    if canonical_executable and os.path.isfile(canonical_executable):
        try:
            executable_sha256 = sha256_file(canonical_executable)
        except OSError:
            pass
    executable_identity = {
        "path": executable,
        "canonical_path": canonical_executable,
        "canonical_sha256": executable_sha256,
    }
    try:
        result = subprocess.run(
            [executable or "rustc", "-vV"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            cwd=working_directory,
            timeout=PROCESS_BACKSTOP_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "error": str(exc),
            "executable": executable_identity,
        }

    output = result.stdout.strip()
    parsed: Dict[str, str] = {}
    duplicate_fields = []
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in parsed:
            duplicate_fields.append(key)
        parsed[key] = value.strip()
    required = ("release", "commit-hash", "commit-date", "host")
    missing = [key for key in required if not parsed.get(key)]
    status = (
        "ok"
        if result.returncode == 0 and not missing and not duplicate_fields
        else "error"
    )
    return {
        "status": status,
        "returncode": result.returncode,
        "version_output": output,
        "stderr": result.stderr.strip(),
        "release": parsed.get("release"),
        "commit_hash": parsed.get("commit-hash"),
        "commit_date": parsed.get("commit-date"),
        "host": parsed.get("host"),
        "missing_fields": missing,
        "duplicate_fields": sorted(set(duplicate_fields)),
        "executable": executable_identity,
    }


def capture_git_sha(repo_root: str, env: Dict[str, str]) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            cwd=repo_root,
            timeout=PROCESS_BACKSTOP_SECONDS,
        )
        if result.returncode != 0:
            return None
        sha = result.stdout.strip()
        return sha if sha else None
    except Exception:
        return None


def capture_git_describe(repo_root: str, env: Dict[str, str]) -> Optional[str]:
    """Capture the same tagged, dirty-aware description embedded by vergen-gix."""
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--dirty"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            cwd=repo_root,
            timeout=PROCESS_BACKSTOP_SECONDS,
        )
        if result.returncode != 0:
            return None
        describe = result.stdout.strip()
        return describe if describe else None
    except Exception:
        return None


def extract_embedded_git_describe(version_output: str) -> Optional[str]:
    """Extract the vergen Git description printed by ``dcg --version``."""
    ansi_escape = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    for raw_line in version_output.splitlines():
        line = ansi_escape.sub("", raw_line)
        if "Commit:" not in line:
            continue
        value = line.split("Commit:", 1)[1].split("│", 1)[0].strip()
        if value and value != "VERGEN_IDEMPOTENT_OUTPUT":
            return value
    return None


def extract_embedded_git_sha(version_output: str) -> Optional[str]:
    """Extract the full vergen Git object id printed by ``dcg --version``."""
    ansi_escape = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    for raw_line in version_output.splitlines():
        line = ansi_escape.sub("", raw_line).strip()
        if not line.startswith("Git SHA:"):
            continue
        value = line.split("Git SHA:", 1)[1].strip()
        if value and value != "VERGEN_IDEMPOTENT_OUTPUT":
            return value
    return None


def extract_embedded_rustc_toolchain(version_output: str) -> Dict[str, Optional[str]]:
    """Extract the compiler identity embedded in the measured binary."""
    ansi_escape = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    labels = {
        "Rustc release:": "release",
        "Rustc commit:": "commit_hash",
        "Rustc date:": "commit_date",
        "Rustc host:": "host",
    }
    values: Dict[str, Optional[str]] = {key: None for key in labels.values()}
    for raw_line in version_output.splitlines():
        line = ansi_escape.sub("", raw_line).strip()
        for label, key in labels.items():
            if line.startswith(label):
                value = line.split(label, 1)[1].strip()
                if value and value != "VERGEN_IDEMPOTENT_OUTPUT":
                    values[key] = value
                break
    return values


def invalid_rustc_identity_fields(identity: Dict[str, Any]) -> Dict[str, str]:
    """Return malformed compiler fields that cannot serve as an identity."""
    invalid: Dict[str, str] = {}
    release = identity.get("release")
    commit_hash = identity.get("commit_hash")
    commit_date = identity.get("commit_date")
    host = identity.get("host")

    if release and not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", release
    ):
        invalid["release"] = "expected a rustc semantic release identifier"
    if commit_hash and not re.fullmatch(r"[0-9a-fA-F]{40}", commit_hash):
        invalid["commit_hash"] = "expected a full 40-hex rustc commit hash"
    if commit_date:
        try:
            parsed_date = time.strptime(commit_date, "%Y-%m-%d")
            if time.strftime("%Y-%m-%d", parsed_date) != commit_date:
                raise ValueError("non-canonical date")
        except (ValueError, OverflowError):
            invalid["commit_date"] = "expected a real ISO calendar date"
    if host and not re.fullmatch(
        r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_.]+){2,}", host
    ):
        invalid["host"] = "expected a Rust host target triple"
    return invalid


def classify_toolchain_binding(
    embedded: Dict[str, Optional[str]], observed: Dict[str, Any]
) -> Dict[str, Any]:
    """Bind the binary's build compiler to the currently observed rustc."""
    fields = ("release", "commit_hash", "commit_date", "host")
    missing_binary = [field for field in fields if not embedded.get(field)]
    missing_observed = [field for field in fields if not observed.get(field)]
    invalid_binary = invalid_rustc_identity_fields(embedded)
    invalid_observed = invalid_rustc_identity_fields(observed)
    mismatches = {
        field: {"binary": embedded.get(field), "observed": observed.get(field)}
        for field in fields
        if embedded.get(field)
        and observed.get(field)
        and embedded[field] != observed[field]
    }
    if missing_binary:
        status = "unverified_missing_binary_toolchain"
        reason = f"dcg --version omitted compiler fields: {missing_binary}"
    elif invalid_binary:
        status = "unverified_malformed_binary_toolchain"
        reason = f"dcg --version exposed malformed compiler fields: {invalid_binary}"
    elif observed.get("status") != "ok" or missing_observed:
        status = "unverified_missing_observed_toolchain"
        reason = (
            "rustc -vV could not provide one unambiguous compiler identity: "
            f"status={observed.get('status')!r}, "
            f"returncode={observed.get('returncode')!r}, "
            f"missing={missing_observed}, "
            f"duplicates={observed.get('duplicate_fields', [])}, "
            f"error={observed.get('error')!r}"
        )
    elif invalid_observed:
        status = "unverified_malformed_observed_toolchain"
        reason = f"rustc -vV exposed malformed compiler fields: {invalid_observed}"
    elif mismatches:
        status = "mismatch"
        reason = f"binary build compiler differs from observed rustc: {mismatches}"
    else:
        status = "verified_exact_rustc_vv"
        reason = "binary and observed rustc identities match exactly"
    return {
        "method": "exact release/commit-hash/commit-date/host equality",
        "status": status,
        "verified": status == "verified_exact_rustc_vv",
        "reason": reason,
        "binary": embedded,
        "observed": {field: observed.get(field) for field in fields},
        "invalid_binary_fields": invalid_binary,
        "invalid_observed_fields": invalid_observed,
        "mismatches": mismatches,
    }


def classify_source_binding(
    embedded_git_sha: Optional[str],
    repository_git_sha: Optional[str],
    embedded_git_describe: Optional[str],
    repository_git_describe: Optional[str],
    repository_state: Dict[str, Any],
) -> Dict[str, Any]:
    """Classify whether the measured binary is provably from this checkout."""
    if repository_state["dirty"]:
        status = "unverified_dirty_worktree"
        reason = (
            "the checkout is dirty, so Git metadata cannot bind the binary to "
            "the current source bytes"
        )
    elif embedded_git_sha is None:
        status = "unverified_missing_binary_provenance"
        reason = "dcg --version did not expose an embedded full Git SHA"
    elif repository_git_sha is None:
        status = "unverified_missing_repository_provenance"
        reason = "git rev-parse could not identify the checked-out source"
    elif embedded_git_sha != repository_git_sha:
        status = "mismatch"
        reason = (
            "the binary and checkout full Git SHAs differ: "
            f"{embedded_git_sha!r} != {repository_git_sha!r}"
        )
    else:
        status = "verified_exact_git_sha"
        reason = (
            "the clean checkout and measured binary expose the same full "
            "Git object id"
        )
    return {
        "method": "full Git SHA equality on a clean checkout",
        "status": status,
        "verified": status == "verified_exact_git_sha",
        "reason": reason,
        "binary_git_sha": embedded_git_sha,
        "repository_git_sha": repository_git_sha,
        "binary_git_describe": embedded_git_describe,
        "repository_git_describe": repository_git_describe,
        "git_describe_matches": (
            embedded_git_describe is not None
            and embedded_git_describe == repository_git_describe
        ),
    }


def capture_git_state(repo_root: str, env: Dict[str, str]) -> Dict[str, Any]:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        capture_output=True,
        check=False,
        env=env,
        cwd=repo_root,
        timeout=PROCESS_BACKSTOP_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git status exited {result.returncode}; "
            f"stderr={result.stderr.decode(errors='replace')[:240]!r}"
        )
    status_text = result.stdout.decode(errors="replace")
    return {
        "dirty": bool(status_text),
        "porcelain_v1": status_text.splitlines(),
        "porcelain_v1_sha256": hashlib.sha256(result.stdout).hexdigest(),
    }


def capture_build_input_manifest(repo_root: str) -> Dict[str, Any]:
    relative_paths = []
    for path in (
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "rust-toolchain.toml",
        ".cargo/config.toml",
    ):
        if os.path.isfile(os.path.join(repo_root, path)):
            relative_paths.append(path)
    source_root = os.path.join(repo_root, "src")
    for current_root, directories, filenames in os.walk(source_root):
        directories.sort()
        for filename in sorted(filenames):
            absolute_path = os.path.join(current_root, filename)
            if os.path.isfile(absolute_path):
                relative_paths.append(os.path.relpath(absolute_path, repo_root))

    entries = []
    aggregate = hashlib.sha256()
    for relative_path in sorted(relative_paths):
        absolute_path = os.path.join(repo_root, relative_path)
        file_hash = sha256_file(absolute_path)
        size_bytes = os.path.getsize(absolute_path)
        entries.append(
            {
                "path": relative_path,
                "size_bytes": size_bytes,
                "sha256": file_hash,
            }
        )
        aggregate.update(
            f"{relative_path}\0{size_bytes}\0{file_hash}\n".encode("utf-8")
        )
    return {
        "algorithm": "sha256(path\\0size\\0sha256\\n)",
        "aggregate_sha256": aggregate.hexdigest(),
        "file_count": len(entries),
        "files": entries,
    }


def capture_harness_manifest(repo_root: str) -> Dict[str, Any]:
    entries = []
    for relative_path in (
        "scripts/perf_baseline.py",
        "AGENTS.md",
        ".github/workflows/ci.yml",
    ):
        absolute_path = os.path.join(repo_root, relative_path)
        entries.append(
            {
                "path": relative_path,
                "size_bytes": os.path.getsize(absolute_path),
                "sha256": sha256_file(absolute_path),
            }
        )
    return {"files": entries}


def capture_shipped_budget(repo_root: str) -> Dict[str, Any]:
    source_path = os.path.join(repo_root, "src", "perf.rs")
    with open(source_path, "r", encoding="utf-8") as handle:
        source = handle.read()
    matches = re.findall(
        r"pub const HOOK_EVALUATION_BUDGET_MS:\s*u64\s*=\s*([0-9_]+)\s*;",
        source,
    )
    if len(matches) != 1:
        raise RuntimeError(
            "expected exactly one HOOK_EVALUATION_BUDGET_MS constant in "
            f"{source_path}, found {len(matches)}"
        )
    return {
        "path": os.path.relpath(source_path, repo_root),
        "sha256": sha256_file(source_path),
        "hook_evaluation_budget_ms": int(matches[0].replace("_", "")),
    }


def capture_trace(
    bin_path: str,
    command: str,
    env: Dict[str, str],
    working_directory: str,
) -> Dict[str, Any]:
    """Run command with trace logging and capture the output."""
    trace_env = env.copy()
    trace_env["DCG_TRACE"] = "1"

    try:
        result = subprocess.run(
            [
                bin_path,
                "--agent",
                PERF_HOOK_AGENT,
                "explain",
                command,
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=trace_env,
            cwd=working_directory,
            timeout=PROCESS_BACKSTOP_SECONDS,
        )
        if result.returncode != 0:
            return {
                "status": "failed",
                "returncode": result.returncode,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            }

        try:
            payload = json.loads(result.stdout)
            if "trace" not in payload:
                return {
                    "status": "missing",
                    "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                }
            return {"status": "ok", "trace": payload["trace"]}
        except json.JSONDecodeError:
            return {
                "status": "invalid_json",
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            }

    except subprocess.TimeoutExpired:
        return {"status": "timed_out", "timeout_seconds": PROCESS_BACKSTOP_SECONDS}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}


def build_cases() -> List[Dict[str, Any]]:
    return [
        {
            "id": "quick_reject",
            "description": "No pack keywords (fast allow)",
            "command": "ls -la",
            "env": {},
            "expected_decision": "allow",
        },
        {
            "id": "safe_keyword",
            "description": "Keyword present, safe path",
            "command": "git status",
            "env": {},
            "expected_decision": "allow",
        },
        {
            "id": "destructive_keyword",
            "description": "Keyword present, destructive match",
            "command": "git reset --hard",
            "env": {},
            "expected_decision": "deny",
        },
        {
            "id": "heredoc_inline",
            "description": "Inline script trigger",
            "command": "python -c \"import os; os.system('rm -rf /')\"",
            "env": {},
            "expected_decision": "deny",
        },
        {
            "id": "bypass",
            "description": "Bypass hook via DCG_BYPASS",
            "command": "git reset --hard",
            "env": {"DCG_BYPASS": "1"},
            "expected_decision": "allow",
        },
        # Cold-process classes added after #245/#248: the historical case set
        # above never exercised the full-evaluation path that a keyword hit
        # without an early semantic decision takes, so per-invocation pattern
        # compilation cost was invisible to this tool.
        {
            "id": "full_eval_redirect",
            "description": "Redirect keyword forces full evaluation (#245 case C)",
            "command": "echo hi 2>/dev/null",
            "env": {},
            "expected_decision": "allow",
        },
        {
            "id": "full_eval_copy",
            "description": "cp keyword forces full evaluation without a match",
            "command": "cp report.txt backup.txt",
            "env": {},
            "expected_decision": "allow",
        },
        {
            "id": "posix_test_probe",
            "description": "POSIX test builtin probe (#246 measured 491ms on 0.7.8)",
            "command": '[ -f x ]',
            "env": {},
            "expected_decision": "allow",
        },
        {
            "id": "xargs_fixed_template",
            "description": "Pipeline consumer with fixed -I template (recursive evaluation)",
            "command": "cat repos.txt | xargs -P12 -I{} sh -c 'cd {} && git status'",
            "env": {},
            "expected_decision": "allow",
        },
        {
            "id": "multi_construct_245",
            "description": "The #245 deterministic-abort reproducer shape",
            "command": (
                'd=/tmp/gt2\nmkdir -p "$d"; cd "$d"\n'
                "git init -q . 2>/dev/null; git config user.email t@t.t\n"
                "echo hi > a.txt; git add a.txt; git commit -qm init 2>&1 | head -2\n"
                "am guard install gt2 \"$d\" 2>&1 | head -20\n"
                'ls -la .git/hooks/ | grep -vE "sample"'
            ),
            "env": {},
            "expected_decision": "allow",
        },
    ]


def create_isolated_environment() -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Create retained HOME/config/work state and scrub all ambient DCG_* keys."""
    isolation_root = tempfile.mkdtemp(prefix="dcg-perf-baseline-")
    home = os.path.join(isolation_root, "home")
    config_home = os.path.join(home, ".config")
    data_home = os.path.join(home, ".local", "share")
    working_directory = os.path.join(isolation_root, "work")
    temp_directory = os.path.join(isolation_root, "tmp")
    for path in (home, config_home, data_home, working_directory, temp_directory):
        os.makedirs(path, exist_ok=True)

    inherited_allowlist = (
        "CARGO_HOME",
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "RUSTUP_HOME",
        "SystemRoot",
        "SYSTEMROOT",
        "TZ",
        "WINDIR",
    )
    env = {
        key: os.environ[key]
        for key in inherited_allowlist
        if key in os.environ
    }
    env.setdefault("PATH", os.defpath)
    explicit_env = {
        "DCG_ALLOWLIST_SYSTEM_PATH": "",
        "DCG_HISTORY_DISABLED": "1",
        "DCG_SELF_HEAL_HOOK": "0",
        "HOME": home,
        "USERPROFILE": home,
        "XDG_CONFIG_HOME": config_home,
        "XDG_DATA_HOME": data_home,
        "TMPDIR": temp_directory,
        "TEMP": temp_directory,
        "TMP": temp_directory,
    }
    env.update(explicit_env)
    inherited_fingerprints = {
        key: hashlib.sha256(value.encode()).hexdigest()
        for key, value in env.items()
        if key not in explicit_env
    }
    return env, {
        "root": isolation_root,
        "home": home,
        "config_home": config_home,
        "data_home": data_home,
        "working_directory": working_directory,
        "temp_directory": temp_directory,
        "ambient_keys_excluded": sorted(set(os.environ) - set(inherited_allowlist)),
        "ambient_dcg_keys_scrubbed": sorted(
            key for key in os.environ if key.startswith("DCG_")
        ),
        "inherited_environment_value_sha256": inherited_fingerprints,
        "explicit_environment": explicit_env,
        "retained": True,
    }


def probe_effective_budget(
    bin_path: str, env: Dict[str, str], working_directory: str
) -> Dict[str, Any]:
    result = subprocess.run(
        [
            bin_path,
            "--agent",
            PERF_HOOK_AGENT,
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        env=env,
        cwd=working_directory,
        timeout=PROCESS_BACKSTOP_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"config probe exited {result.returncode}; "
            f"stderr={result.stderr.decode(errors='replace')[:240]!r}"
        )
    if result.stderr:
        raise RuntimeError(
            "config probe polluted stderr; refusing to certify a run with "
            f"diagnostics={result.stderr.decode(errors='replace')[:240]!r}"
        )
    try:
        payload = json.loads(result.stdout)
        general = payload["general"]
        source = general["hook_timeout_source"]
        resolved = general["hook_timeout_ms"]
        config_sources = payload["config_sources"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError(
            f"config probe emitted an invalid payload: {result.stdout[:240]!r}"
        ) from exc
    if not isinstance(resolved, int) or not isinstance(source, str):
        raise RuntimeError(
            "config probe returned invalid hook_timeout_ms/hook_timeout_source types"
        )
    if not isinstance(config_sources, list) or not all(
        isinstance(item, dict) and isinstance(item.get("status"), str)
        for item in config_sources
    ):
        raise RuntimeError("config probe returned invalid config_sources")
    disallowed_sources = [
        item
        for item in config_sources
        if item["status"] in {"loaded", "invalid", "rejected"}
    ]
    if disallowed_sources:
        raise RuntimeError(
            "isolated run encountered loaded/invalid/rejected config source(s): "
            f"{disallowed_sources}"
        )
    return {
        "returncode": result.returncode,
        "hook_timeout_ms": resolved,
        "hook_timeout_source": source,
        "config_sources": config_sources,
        "effective_config": payload,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }


def max_allowed_tail_exceedances(sample_count: int) -> int:
    """Return the 95/95 one-sided binomial tolerance allowance."""
    if sample_count < MIN_TOLERANCE_SAMPLES:
        return -1

    exceedance_probability = 1.0 - (TAIL_COVERAGE_PCT / 100.0)
    alpha = 1.0 - (TAIL_CONFIDENCE_PCT / 100.0)
    non_exceedance_probability = 1.0 - exceedance_probability
    log_probability = sample_count * math.log(non_exceedance_probability)
    log_cumulative = log_probability
    log_alpha = math.log(alpha)
    allowed = 0 if log_cumulative <= log_alpha else -1

    for exceedances in range(1, sample_count + 1):
        log_probability += (
            math.log(sample_count - exceedances + 1)
            - math.log(exceedances)
            + math.log(exceedance_probability)
            - math.log(non_exceedance_probability)
        )
        larger = max(log_cumulative, log_probability)
        smaller = min(log_cumulative, log_probability)
        log_cumulative = larger + math.log1p(math.exp(smaller - larger))
        if log_cumulative > log_alpha:
            break
        allowed = exceedances
    return allowed


def run_internal_self_tests() -> None:
    """Exercise certificate invariants that previously admitted false greens."""

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise RuntimeError(message)

    clean = {"dirty": False}
    same_description = "v1.2.3"
    different_sha = classify_source_binding(
        "a" * 40,
        "b" * 40,
        same_description,
        same_description,
        clean,
    )
    require(
        not different_sha["verified"] and different_sha["status"] == "mismatch",
        "equal tag descriptions must not hide different full Git SHAs",
    )
    exact_sha = classify_source_binding(
        "a" * 40,
        "a" * 40,
        same_description,
        same_description,
        clean,
    )
    require(
        exact_sha["verified"] and exact_sha["status"] == "verified_exact_git_sha",
        "equal full Git SHAs on a clean checkout must verify",
    )

    embedded_toolchain = {
        "release": "1.98.0-nightly",
        "commit_hash": "c" * 40,
        "commit_date": "2026-06-05",
        "host": "x86_64-unknown-linux-gnu",
    }
    observed_toolchain: Dict[str, Any] = {
        "status": "ok",
        **embedded_toolchain,
    }
    exact_toolchain = classify_toolchain_binding(
        embedded_toolchain, observed_toolchain
    )
    require(
        exact_toolchain["verified"],
        "identical embedded and observed compiler identities must verify",
    )
    observed_toolchain["commit_hash"] = "d" * 40
    mismatched_toolchain = classify_toolchain_binding(
        embedded_toolchain, observed_toolchain
    )
    require(
        not mismatched_toolchain["verified"]
        and mismatched_toolchain["status"] == "mismatch",
        "a stale binary built by another compiler must not verify",
    )
    for field, malformed_value in (
        ("release", "unknown"),
        ("commit_hash", "abc"),
        ("commit_date", "yesterday"),
        ("host", "unknown"),
    ):
        malformed_binary = dict(embedded_toolchain)
        malformed_observed = {"status": "ok", **embedded_toolchain}
        malformed_binary[field] = malformed_value
        malformed_observed[field] = malformed_value
        malformed_binding = classify_toolchain_binding(
            malformed_binary, malformed_observed
        )
        require(
            not malformed_binding["verified"]
            and "malformed" in malformed_binding["status"],
            f"equal malformed rustc {field} values must not verify",
        )

    synthetic_host_env = {
        "HOME": "/host/home",
        "PATH": "/host/home/.cargo/bin:/usr/bin",
        "DCG_HOOK_TIMEOUT_MS": "5000",
    }
    compiler_env, compiler_env_evidence = create_toolchain_probe_environment(
        synthetic_host_env
    )
    require(
        compiler_env.get("HOME") == "/host/home"
        and compiler_env.get("PATH") == "/host/home/.cargo/bin:/usr/bin",
        "compiler probe must preserve the host HOME/PATH used by a rustup proxy",
    )
    require(
        "DCG_HOOK_TIMEOUT_MS" not in compiler_env
        and compiler_env_evidence["ambient_dcg_keys_scrubbed"]
        == ["DCG_HOOK_TIMEOUT_MS"],
        "compiler probe must still scrub unrelated ambient DCG_* settings",
    )

    expected_tail_allowances = {58: -1, 59: 0, 100: 1}
    for sample_count, expected in expected_tail_allowances.items():
        observed = max_allowed_tail_exceedances(sample_count)
        require(
            observed == expected,
            f"tail allowance for {sample_count} samples was {observed}, expected {expected}",
        )
    large_allowance = max_allowed_tail_exceedances(15_000)
    require(
        0 <= large_allowance < 15_000,
        "large-sample binomial tolerance calculation underflowed",
    )

    empty_gate = build_latency_gate(True, 1_000, 1_000, 1_000, 50, [], [], [])
    require(
        empty_gate["overall_result"] == "ERROR"
        and empty_gate["evaluated_case_count"] == 0,
        "an empty absolute case set must not pass vacuously",
    )
    bypass_only_gate = build_latency_gate(
        True,
        1_000,
        1_000,
        1_000,
        50,
        [{"id": "bypass"}],
        [{"id": "bypass"}],
        [],
    )
    require(
        bypass_only_gate["overall_result"] == "ERROR",
        "a bypass-only absolute case set must not pass vacuously",
    )

    saved_context = dict(_UNCAUGHT_GATE_CONTEXT)
    recorded_aborts: List[Dict[str, Any]] = []
    try:
        _UNCAUGHT_GATE_CONTEXT.update(
            {
                "requested": True,
                "output_path": "/outside/repository/certificate.json",
                "supplied_budget_ms": 1_000,
                "margin_pct": 50,
            }
        )

        def explode() -> int:
            raise RuntimeError("synthetic uncaught failure")

        def record_abort(**kwargs: Any) -> None:
            recorded_aborts.append(kwargs)

        guarded_status = run_guarded_entrypoint(
            explode, record_abort, io.StringIO()
        )
    finally:
        _UNCAUGHT_GATE_CONTEXT.clear()
        _UNCAUGHT_GATE_CONTEXT.update(saved_context)
    require(
        guarded_status == 1
        and len(recorded_aborts) == 1
        and "synthetic uncaught failure" in recorded_aborts[0]["reason"],
        "an uncaught gate exception must emit one ERROR certificate and fail",
    )


def write_json_payload(payload: Dict[str, Any], output_path: Optional[str]) -> None:
    """Write one canonical JSON payload to the requested artifact destination."""
    output_json = json.dumps(payload, indent=2, sort_keys=True)
    if output_path:
        output_path = os.path.abspath(output_path)
        output_directory = os.path.dirname(output_path)
        output_basename = os.path.basename(output_path)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_directory,
            prefix=f".{output_basename}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(output_json)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary_path = handle.name
        os.replace(temporary_path, output_path)
    else:
        print(output_json)


def emit_gate_abort(
    output_path: Optional[str],
    reason: str,
    supplied_budget_ms: Optional[int],
    margin_pct: int,
    shipped_budget_ms: Optional[int] = None,
    effective_budget_ms: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit a self-contained error certificate for a gate preflight abort."""
    limit_ms = (
        shipped_budget_ms * margin_pct / 100.0
        if shipped_budget_ms is not None and margin_pct > 0
        else None
    )
    gate = {
        "enabled": True,
        "preflight_abort": True,
        "supplied_budget_ms": supplied_budget_ms,
        "shipped_budget_ms": shipped_budget_ms,
        "effective_budget_ms": effective_budget_ms,
        "margin_pct": margin_pct,
        "limit_ms": limit_ms,
        "estimand": "paired full hook wall time minus matched DCG_BYPASS wall time",
        "tail_rule": {
            "kind": "one-sided exact binomial tolerance bound",
            "confidence_pct": TAIL_CONFIDENCE_PCT,
            "coverage_pct": TAIL_COVERAGE_PCT,
            "minimum_sample_count": MIN_TOLERANCE_SAMPLES,
        },
        "excluded_case_ids": ["bypass"],
        "expected_case_count": 0,
        "evaluated_case_count": 0,
        "cases": [],
        "violations": [],
        "errors": [reason],
        "overall_result": "ERROR",
    }
    payload = {
        "schema_version": PERF_ARTIFACT_SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "preflight": details or {},
        "cases": [],
        "errors": [reason],
        "latency_gate": gate,
    }
    try:
        write_json_payload(payload, output_path)
    except OSError as exc:
        print(
            f"error: could not write latency-gate abort certificate: {exc}",
            file=sys.stderr,
        )


def build_latency_gate(
    enabled: bool,
    supplied_budget_ms: Optional[int],
    shipped_budget_ms: int,
    effective_budget_ms: int,
    margin_pct: int,
    case_specs: List[Dict[str, Any]],
    results: List[Dict[str, Any]],
    errors: List[str],
) -> Dict[str, Any]:
    """Build the authoritative gate verdict serialized into the JSON artifact."""
    spec_ids = [case["id"] for case in case_specs]
    result_ids = [case["id"] for case in results]
    contract_errors: List[str] = []
    duplicate_spec_ids = sorted(
        case_id for case_id in set(spec_ids) if spec_ids.count(case_id) > 1
    )
    duplicate_result_ids = sorted(
        case_id for case_id in set(result_ids) if result_ids.count(case_id) > 1
    )
    if duplicate_spec_ids:
        contract_errors.append(
            f"duplicate performance case ids: {duplicate_spec_ids}"
        )
    if duplicate_result_ids:
        contract_errors.append(
            f"duplicate performance result ids: {duplicate_result_ids}"
        )
    unexpected_result_ids = sorted(set(result_ids) - set(spec_ids))
    if unexpected_result_ids:
        contract_errors.append(
            f"unexpected performance result ids: {unexpected_result_ids}"
        )
    if not errors and set(result_ids) != set(spec_ids):
        missing_result_ids = sorted(set(spec_ids) - set(result_ids))
        contract_errors.append(
            "successful measurement set is incomplete; missing result ids: "
            f"{missing_result_ids}"
        )
    if enabled:
        missing_required_case_ids = sorted(
            set(REQUIRED_ABSOLUTE_GATE_CASE_IDS) - set(spec_ids)
        )
        if missing_required_case_ids:
            contract_errors.append(
                "absolute gate case contract is missing required ids: "
                f"{missing_required_case_ids}"
            )

    limit_ms = shipped_budget_ms * margin_pct / 100.0 if enabled else None
    result_by_id = {case["id"]: case for case in results}
    per_case: List[Dict[str, Any]] = []
    violations: List[str] = []

    if enabled:
        for spec in case_specs:
            case_id = spec["id"]
            if case_id == "bypass":
                continue
            case = result_by_id.get(case_id)
            if case is None:
                per_case.append(
                    {
                        "case": case_id,
                        "status": "ERROR",
                        "error": "measurement unavailable; see top-level errors",
                    }
                )
                continue

            signed_p95 = case["evaluator_delta_metrics"]["p95_ms"]
            budget_consumption_p95 = max(0.0, signed_p95)
            delta_samples = case["evaluator_delta_metrics"]["samples_ms"]
            over_limit_sample_count = sum(
                max(0.0, sample) > limit_ms for sample in delta_samples
            )
            allowed_over_limit_sample_count = max_allowed_tail_exceedances(
                len(delta_samples)
            )
            status = (
                "PASS"
                if budget_consumption_p95 <= limit_ms
                and over_limit_sample_count <= allowed_over_limit_sample_count
                else "FAIL"
            )
            per_case.append(
                {
                    "case": case_id,
                    "full_process_p95_ms": case["metrics"]["p95_ms"],
                    "bypass_process_p95_ms": case["bypass_metrics"]["p95_ms"],
                    "evaluator_delta_p50_ms": case["evaluator_delta_metrics"][
                        "p50_ms"
                    ],
                    "evaluator_delta_p95_ms": signed_p95,
                    "budget_consumption_p95_ms": budget_consumption_p95,
                    "limit_ms": limit_ms,
                    "over_limit_sample_count": over_limit_sample_count,
                    "allowed_over_limit_sample_count": (
                        allowed_over_limit_sample_count
                    ),
                    "status": status,
                }
            )
            if budget_consumption_p95 > limit_ms:
                violations.append(
                    f"{case_id}: paired evaluator p95 "
                    f"{budget_consumption_p95:.1f}ms exceeds "
                    f"{limit_ms:.0f}ms ({margin_pct}% of the "
                    f"{shipped_budget_ms}ms hook budget)"
                )
            if over_limit_sample_count > allowed_over_limit_sample_count:
                violations.append(
                    f"{case_id}: {over_limit_sample_count} of {len(delta_samples)} "
                    "paired evaluator samples exceed the limit; the "
                    f"{TAIL_CONFIDENCE_PCT}/{TAIL_COVERAGE_PCT} one-sided "
                    "binomial tolerance rule allows at most "
                    f"{allowed_over_limit_sample_count}"
                )

    expected_case_count = sum(spec["id"] != "bypass" for spec in case_specs)
    evaluated_case_count = sum(case["status"] != "ERROR" for case in per_case)
    if enabled and expected_case_count <= 0:
        contract_errors.append("absolute gate has no evaluable cases")
    if enabled and evaluated_case_count != expected_case_count:
        contract_errors.append(
            "absolute gate evaluated case count does not match its contract: "
            f"{evaluated_case_count} != {expected_case_count}"
        )
    all_errors = [*errors, *contract_errors]

    if all_errors:
        overall_result = "ERROR"
    elif not enabled:
        overall_result = "NOT_RUN"
    elif violations:
        overall_result = "FAIL"
    else:
        overall_result = "PASS"

    return {
        "enabled": enabled,
        "supplied_budget_ms": supplied_budget_ms,
        "shipped_budget_ms": shipped_budget_ms,
        "effective_budget_ms": effective_budget_ms,
        "margin_pct": margin_pct,
        "limit_ms": limit_ms,
        "estimand": (
            "paired full hook wall time minus matched DCG_BYPASS wall time"
            if enabled
            else None
        ),
        "tail_rule": (
            {
                "kind": "one-sided exact binomial tolerance bound",
                "confidence_pct": TAIL_CONFIDENCE_PCT,
                "coverage_pct": TAIL_COVERAGE_PCT,
                "minimum_sample_count": MIN_TOLERANCE_SAMPLES,
            }
            if enabled
            else None
        ),
        "excluded_case_ids": ["bypass"] if enabled else [],
        "expected_case_count": expected_case_count if enabled else 0,
        "evaluated_case_count": evaluated_case_count,
        "cases": per_case,
        "violations": violations,
        "errors": all_errors,
        "overall_result": overall_result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate dcg perf baseline JSON")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run mutation-sensitive certificate invariant checks and exit",
    )
    parser.add_argument("--bin", default="./target/release/dcg", help="Path to dcg binary")
    parser.add_argument("--output", help="Write JSON output to this file")
    parser.add_argument("--warmup", type=int, default=30, help="Warmup iterations per case")
    parser.add_argument("--runs", type=int, default=300, help="Measured iterations per case")
    parser.add_argument("--skip-trace", action="store_true", help="Skip explain trace capture")
    parser.add_argument(
        "--assert-budget-ms",
        type=int,
        default=None,
        help=(
            "Absolute evaluator-cost gate: pair every full hook invocation "
            "with DCG_BYPASS, subtract the matched process floor, and fail "
            "(exit 3) unless paired-delta p95 fits within this budget after "
            "applying --assert-margin-pct. The supplied value must exactly "
            "match the positive HOOK_EVALUATION_BUDGET_MS parsed from "
            "src/perf.rs. Omitting this option leaves gate mode disabled; "
            "supplying zero is an error rather than a disable sentinel."
        ),
    )
    parser.add_argument(
        "--assert-margin-pct",
        type=int,
        default=50,
        help=(
            "Percentage of --assert-budget-ms that paired evaluator p95 may "
            "consume (default 50; values above 60 are rejected). Gate mode "
            "also applies a 95/95 one-sided binomial tolerance rule and "
            f"requires at least {MIN_TOLERANCE_SAMPLES} measured samples."
        ),
    )
    args = parser.parse_args()
    if args.self_test:
        try:
            run_internal_self_tests()
        except RuntimeError as exc:
            print(f"perf baseline self-test failed: {exc}", file=sys.stderr)
            return 1
        print("perf baseline self-test passed")
        return 0
    gate_enabled = args.assert_budget_ms is not None
    _UNCAUGHT_GATE_CONTEXT.update(
        {
            "requested": gate_enabled,
            "output_path": args.output,
            "supplied_budget_ms": args.assert_budget_ms,
            "margin_pct": args.assert_margin_pct,
        }
    )

    repo_root = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
    if gate_enabled and args.output:
        output_path = os.path.realpath(os.path.abspath(args.output))
        try:
            output_inside_repo = os.path.commonpath([repo_root, output_path]) == repo_root
        except ValueError:
            output_inside_repo = False
        if output_inside_repo:
            reason = (
                "gate output must be outside the repository so writing the "
                "certificate cannot invalidate the measured source snapshot"
            )
            emit_gate_abort(
                None,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                details={"rejected_output_path": output_path},
            )
            print(f"error: {reason}: {output_path}", file=sys.stderr)
            return 1
    bin_path = os.path.realpath(os.path.abspath(args.bin))
    if not os.path.isfile(bin_path):
        reason = f"binary not found: {bin_path}"
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                details={"binary_path": bin_path},
            )
        print(f"error: {reason}", file=sys.stderr)
        return 1
    if not os.access(bin_path, os.X_OK):
        reason = f"binary is not executable: {bin_path}"
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                details={"binary_path": bin_path},
            )
        print(f"error: {reason}", file=sys.stderr)
        return 1
    if args.warmup < 0 or args.runs <= 0:
        reason = "--warmup must be >= 0 and --runs must be > 0"
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                details={"warmup": args.warmup, "runs": args.runs},
            )
        print(f"error: {reason}", file=sys.stderr)
        return 1
    if gate_enabled and args.assert_budget_ms <= 0:
        reason = "--assert-budget-ms must be > 0 when supplied"
        emit_gate_abort(
            args.output,
            reason,
            args.assert_budget_ms,
            args.assert_margin_pct,
        )
        print(f"error: {reason}", file=sys.stderr)
        return 1
    if gate_enabled:
        if not 0 < args.assert_margin_pct <= 60:
            reason = "--assert-margin-pct must be in the range 1..=60"
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
            )
            print(f"error: {reason}", file=sys.stderr)
            return 1
        if args.runs < MIN_TOLERANCE_SAMPLES:
            reason = (
                "latency gate requires --runs >= "
                f"{MIN_TOLERANCE_SAMPLES} for its {TAIL_CONFIDENCE_PCT}/"
                f"{TAIL_COVERAGE_PCT} one-sided binomial tolerance rule"
            )
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                details={"runs": args.runs},
            )
            print(f"error: {reason}", file=sys.stderr)
            return 1
    elif args.assert_margin_pct <= 0:
        print("error: --assert-margin-pct must be > 0", file=sys.stderr)
        return 1

    try:
        source_budget_start = capture_shipped_budget(repo_root)
    except Exception as exc:  # noqa: BLE001
        reason = f"could not derive shipped hook budget: {exc}"
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
            )
        print(f"error: {reason}", file=sys.stderr)
        return 1
    shipped_budget_ms = source_budget_start["hook_evaluation_budget_ms"]
    if gate_enabled and args.assert_budget_ms != shipped_budget_ms:
        reason = (
            "--assert-budget-ms "
            f"({args.assert_budget_ms}) does not match the shipped "
            f"HOOK_EVALUATION_BUDGET_MS ({shipped_budget_ms}) parsed from "
            f"{source_budget_start['path']}"
        )
        emit_gate_abort(
            args.output,
            reason,
            args.assert_budget_ms,
            args.assert_margin_pct,
            shipped_budget_ms=shipped_budget_ms,
            details={"budget_source": source_budget_start},
        )
        print(f"LATENCY GATE ABORTED: {reason}", file=sys.stderr)
        return 3

    toolchain_probe_env, toolchain_probe_environment = (
        create_toolchain_probe_environment()
    )
    rustc_observation_start = capture_rustc_version(
        toolchain_probe_env, repo_root
    )
    host_context_start = capture_host_context()
    base_env, isolation = create_isolated_environment()
    working_directory = isolation["working_directory"]
    binary_sha_start = sha256_file(bin_path)
    binary_size = os.path.getsize(bin_path)
    git_sha_start = capture_git_sha(repo_root, base_env)
    git_describe_start = capture_git_describe(repo_root, base_env)
    git_state_start = capture_git_state(repo_root, base_env)
    build_input_manifest_start = capture_build_input_manifest(repo_root)
    harness_manifest_start = capture_harness_manifest(repo_root)
    try:
        version_output = capture_version_output(bin_path, base_env, working_directory)
    except Exception as exc:  # noqa: BLE001
        reason = f"could not capture binary version: {exc}"
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                shipped_budget_ms=shipped_budget_ms,
                details={
                    "binary_path": bin_path,
                    "binary_sha256": binary_sha_start,
                },
            )
        print(f"error: {reason}", file=sys.stderr)
        return 1
    embedded_git_sha = extract_embedded_git_sha(version_output)
    embedded_git_describe = extract_embedded_git_describe(version_output)
    source_binding_start = classify_source_binding(
        embedded_git_sha,
        git_sha_start,
        embedded_git_describe,
        git_describe_start,
        git_state_start,
    )
    source_binding_start["required_for_latency_gate"] = gate_enabled
    if gate_enabled and not source_binding_start["verified"]:
        reason = (
            "measured binary is not provably bound to "
            f"this checkout ({source_binding_start['status']}): "
            f"{source_binding_start['reason']}"
        )
        emit_gate_abort(
            args.output,
            reason,
            args.assert_budget_ms,
            args.assert_margin_pct,
            shipped_budget_ms=shipped_budget_ms,
            details={
                "binary_path": bin_path,
                "binary_sha256": binary_sha_start,
                "repository_git_sha": git_sha_start,
                "source_binding": source_binding_start,
            },
        )
        print(f"LATENCY GATE ABORTED: {reason}", file=sys.stderr)
        return 3
    embedded_rustc_toolchain = extract_embedded_rustc_toolchain(version_output)
    toolchain_binding_start = classify_toolchain_binding(
        embedded_rustc_toolchain, rustc_observation_start
    )
    toolchain_binding_start["required_for_latency_gate"] = gate_enabled
    if gate_enabled and not toolchain_binding_start["verified"]:
        reason = (
            "measured binary is not provably bound to the observed compiler "
            f"({toolchain_binding_start['status']}): "
            f"{toolchain_binding_start['reason']}"
        )
        emit_gate_abort(
            args.output,
            reason,
            args.assert_budget_ms,
            args.assert_margin_pct,
            shipped_budget_ms=shipped_budget_ms,
            details={
                "source_binding": source_binding_start,
                "toolchain_binding": toolchain_binding_start,
                "rustc_observation": rustc_observation_start,
            },
        )
        print(f"LATENCY GATE ABORTED: {reason}", file=sys.stderr)
        return 3

    try:
        config_probe = probe_effective_budget(bin_path, base_env, working_directory)
    except Exception as exc:  # noqa: BLE001
        reason = f"could not verify effective hook budget: {exc}"
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                shipped_budget_ms=shipped_budget_ms,
                details={"source_binding": source_binding_start},
            )
        print(f"error: {reason}", file=sys.stderr)
        return 3 if gate_enabled else 1
    if config_probe["hook_timeout_source"] != "default":
        reason = (
            "isolated config probe resolved a non-default "
            f"hook timeout source ({config_probe['hook_timeout_source']!r}); "
            "measurements would not represent shipped defaults"
        )
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                shipped_budget_ms=shipped_budget_ms,
                effective_budget_ms=config_probe["hook_timeout_ms"],
                details={
                    "source_binding": source_binding_start,
                    "effective_budget_probe": config_probe,
                },
            )
        print(f"LATENCY RUN ABORTED: {reason}", file=sys.stderr)
        return 3 if gate_enabled else 1
    if config_probe["hook_timeout_ms"] != shipped_budget_ms:
        reason = (
            "isolated binary resolved "
            f"{config_probe['hook_timeout_ms']}ms but src/perf.rs declares "
            f"{shipped_budget_ms}ms"
        )
        if gate_enabled:
            emit_gate_abort(
                args.output,
                reason,
                args.assert_budget_ms,
                args.assert_margin_pct,
                shipped_budget_ms=shipped_budget_ms,
                effective_budget_ms=config_probe["hook_timeout_ms"],
                details={
                    "source_binding": source_binding_start,
                    "effective_budget_probe": config_probe,
                },
            )
        print(f"LATENCY RUN ABORTED: {reason}", file=sys.stderr)
        return 3 if gate_enabled else 1

    case_specs = build_cases()
    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for case in case_specs:
        env = base_env.copy()
        env.update(case.get("env", {}))
        try:
            case_result = run_case(
                bin_path,
                case["command"],
                env,
                working_directory,
                case["expected_decision"],
                args.warmup,
                args.runs,
                paired_bypass=gate_enabled and case["id"] != "bypass",
            )
            trace = {"status": "skipped"}
            if not args.skip_trace:
                trace = capture_trace(
                    bin_path, case["command"], env, working_directory
                )
            case_record = {
                "id": case["id"],
                "description": case["description"],
                "command": case["command"],
                "expected_decision": case["expected_decision"],
                "env": case.get("env", {}),
                "trace": trace,
            }
            case_record.update(case_result)
            results.append(case_record)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{case['id']}: {exc}")

    binary_sha_end = sha256_file(bin_path)
    git_sha_end = capture_git_sha(repo_root, base_env)
    git_describe_end = capture_git_describe(repo_root, base_env)
    git_state_end = capture_git_state(repo_root, base_env)
    build_input_manifest_end = capture_build_input_manifest(repo_root)
    harness_manifest_end = capture_harness_manifest(repo_root)
    try:
        source_budget_end = capture_shipped_budget(repo_root)
    except Exception as exc:  # noqa: BLE001
        source_budget_end = {"error": str(exc)}
        errors.append("could not re-read src/perf.rs after the run")
    try:
        config_probe_end = probe_effective_budget(
            bin_path, base_env, working_directory
        )
    except Exception as exc:  # noqa: BLE001
        config_probe_end = {"error": str(exc)}
        errors.append("could not repeat the effective hook budget probe after the run")
    source_binding_end = classify_source_binding(
        extract_embedded_git_sha(version_output),
        git_sha_end,
        extract_embedded_git_describe(version_output),
        git_describe_end,
        git_state_end,
    )
    source_binding_end["required_for_latency_gate"] = gate_enabled
    rustc_observation_end = capture_rustc_version(toolchain_probe_env, repo_root)
    host_context_end = capture_host_context()
    toolchain_binding_end = classify_toolchain_binding(
        embedded_rustc_toolchain, rustc_observation_end
    )
    toolchain_binding_end["required_for_latency_gate"] = gate_enabled
    if binary_sha_end != binary_sha_start:
        errors.append("measured binary changed during the run")
    if git_sha_end != git_sha_start:
        errors.append("repository HEAD changed during the run")
    if git_describe_end != git_describe_start:
        errors.append("repository Git description changed during the run")
    if git_state_end != git_state_start:
        errors.append("repository worktree state changed during the run")
    if build_input_manifest_end != build_input_manifest_start:
        errors.append("Rust/Cargo build inputs changed during the run")
    if harness_manifest_end != harness_manifest_start:
        errors.append("performance harness bytes changed during the run")
    if source_budget_end != source_budget_start:
        errors.append("src/perf.rs or its shipped budget changed during the run")
    if config_probe_end != config_probe:
        errors.append("effective configuration changed during the run")
    if source_binding_end != source_binding_start:
        errors.append("binary/source provenance binding changed during the run")
    if rustc_observation_end != rustc_observation_start:
        errors.append("observed rustc toolchain changed during the run")
    if toolchain_binding_end != toolchain_binding_start:
        errors.append("binary/toolchain provenance binding changed during the run")

    latency_gate = build_latency_gate(
        gate_enabled,
        args.assert_budget_ms,
        shipped_budget_ms,
        config_probe["hook_timeout_ms"],
        args.assert_margin_pct,
        case_specs,
        results,
        errors,
    )

    payload = {
        "schema_version": PERF_ARTIFACT_SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary": {
            "path": bin_path,
            "version_output": version_output,
            "size_bytes": binary_size,
            "sha256": binary_sha_start,
            "sha256_end": binary_sha_end,
            "stable_during_run": binary_sha_end == binary_sha_start,
        },
        "source": {
            "repository_root": repo_root,
            "repository_git_sha": git_sha_start,
            "repository_git_sha_end": git_sha_end,
            "repository_git_describe": git_describe_start,
            "repository_git_describe_end": git_describe_end,
            "repository_state": git_state_start,
            "repository_state_end": git_state_end,
            "binary_source_binding": source_binding_start,
            "binary_source_binding_end": source_binding_end,
            "build_input_manifest": build_input_manifest_start,
            "build_input_manifest_end": build_input_manifest_end,
            "harness_manifest": harness_manifest_start,
            "harness_manifest_end": harness_manifest_end,
            "perf_budget_source": source_budget_start,
            "perf_budget_source_end": source_budget_end,
        },
        "toolchain": {
            "binary": embedded_rustc_toolchain,
            "probe_environment": toolchain_probe_environment,
            "observation": rustc_observation_start,
            "observation_end": rustc_observation_end,
            "binding": toolchain_binding_start,
            "binding_end": toolchain_binding_end,
        },
        "host": {
            "start": host_context_start,
            "end": host_context_end,
            "controlled": False,
            "note": (
                "host load and power state are observational; compare retained "
                "raw samples and load context before attributing small deltas"
            ),
        },
        "environment_isolation": isolation,
        "effective_budget_probe": config_probe,
        "effective_budget_probe_end": config_probe_end,
        "method": {
            "mode": "process-per-invocation",
            "explicit_agent_profile": PERF_HOOK_AGENT,
            "hook_argv_suffix": ["--agent", PERF_HOOK_AGENT],
            "warmup": args.warmup,
            "runs": args.runs,
            "timer": "perf_counter_ns",
            "parent_process_backstop_seconds": PROCESS_BACKSTOP_SECONDS,
            "parent_process_backstop_scope": (
                "subprocess liveness only; distinct from the shipped in-process "
                "hook evaluation budget"
            ),
            "rss_method": "/usr/bin/time -v",
            "raw_estimand": "dcg process wall time, including process spawn",
            "budget_estimand": (
                "paired full hook wall time minus matched DCG_BYPASS wall time"
                if gate_enabled
                else None
            ),
            "pair_order": "alternating AB/BA by sample index" if gate_enabled else None,
            "timed_sample_semantics": (
                "every timed child result is captured and validated after the "
                "timer stops; wrong decisions and malformed wire output fail the run"
            ),
            "self_heal_coverage": (
                "excluded for host safety: DCG_SELF_HEAL_HOOK=0; this certificate "
                "does not measure default hook self-healing work"
            ),
            "toolchain_binding_scope": (
                "native-build certificate: the running host rustc identity must "
                "exactly match the compiler embedded in the binary; cross-compiled "
                "artifacts require separate build attestation"
            ),
            "protocol_scope": (
                "generic Bash hook JSON path; OMP compact bridge bytes are checked "
                "by e2e_harness_matrix.sh, while the full Bun ExtensionAPI callback "
                "requires separate end-to-end latency evidence"
            ),
            "notes": (
                "Raw samples are retained. max_rss_kb is measured separately via "
                "/usr/bin/time -v. Only paired evaluator deltas are compared with "
                "the in-process hook evaluation budget."
            ),
        },
        "cases": results,
        "errors": latency_gate["errors"],
        "latency_gate": latency_gate,
    }

    write_json_payload(payload, args.output)

    if gate_enabled:
        print(
            json.dumps(
                {
                    "event": "latency_gate_env",
                    "effective_budget_ms": config_probe["hook_timeout_ms"],
                    "budget_source": config_probe["hook_timeout_source"],
                    "budget_source_path": source_budget_start["path"],
                    "budget_source_sha256": source_budget_start["sha256"],
                    "isolated_home": isolation["home"],
                    "working_directory": working_directory,
                    "source_binding": source_binding_start,
                    "toolchain_binding": toolchain_binding_start,
                }
            ),
            file=sys.stderr,
        )
        for case_gate in latency_gate["cases"]:
            print(
                json.dumps(
                    {
                        "event": "latency_gate_case",
                        **case_gate,
                        "budget_ms": latency_gate["shipped_budget_ms"],
                    }
                ),
                file=sys.stderr,
            )
        if latency_gate["overall_result"] == "FAIL":
            print(
                "LATENCY GATE FAILED — evaluator cost is eating the "
                "fail-closed hook deadline (#245 regression class):",
                file=sys.stderr,
            )
            for violation in latency_gate["violations"]:
                print(f"  {violation}", file=sys.stderr)
            return 3
        if latency_gate["overall_result"] == "PASS":
            print(
                "LATENCY GATE PASSED: "
                f"{latency_gate['evaluated_case_count']} paired cases, evaluator "
                f"p95 within {latency_gate['margin_pct']}% of the "
                f"{latency_gate['shipped_budget_ms']}ms budget",
                file=sys.stderr,
            )

    if latency_gate["overall_result"] == "ERROR":
        gate_errors = latency_gate["errors"]
        print(
            f"error: latency gate could not certify this run: {gate_errors}",
            file=sys.stderr,
        )
        return 1

    return 0


def run_guarded_entrypoint(
    entrypoint: Callable[[], int],
    abort_emitter: Callable[..., None] = emit_gate_abort,
    error_stream: TextIO = sys.stderr,
) -> int:
    """Turn an unexpected gate exception into retained ERROR evidence."""
    try:
        return entrypoint()
    except Exception as exc:  # noqa: BLE001
        reason = f"uncaught perf harness error: {type(exc).__name__}: {exc}"
        context = dict(_UNCAUGHT_GATE_CONTEXT)
        if context["requested"]:
            try:
                abort_emitter(
                    output_path=context["output_path"],
                    reason=reason,
                    supplied_budget_ms=context["supplied_budget_ms"],
                    margin_pct=context["margin_pct"],
                    details={
                        "exception_type": type(exc).__name__,
                        "exception_message": str(exc),
                    },
                )
            except Exception as certificate_exc:  # noqa: BLE001
                print(
                    "error: emergency latency-gate certificate emission also "
                    f"failed: {certificate_exc}",
                    file=error_stream,
                )
        print(f"error: {reason}", file=error_stream)
        return 1


if __name__ == "__main__":
    raise SystemExit(run_guarded_entrypoint(main))
