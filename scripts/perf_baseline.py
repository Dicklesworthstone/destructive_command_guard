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
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple


PROCESS_BACKSTOP_SECONDS = 30.0


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run_one(
    bin_path: str,
    command: str,
    env: Dict[str, str],
    working_directory: str,
) -> float:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    start = time.perf_counter_ns()
    result = subprocess.run(
        [bin_path],
        input=payload,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=env,
        cwd=working_directory,
        timeout=PROCESS_BACKSTOP_SECONDS,
    )
    end = time.perf_counter_ns()
    if result.returncode != 0:
        raise RuntimeError(
            f"dcg exited {result.returncode} during timed hook invocation; "
            "refusing to credit a failed process as latency evidence"
        )
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
            ["/usr/bin/time", "-v", bin_path],
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
        [bin_path],
        input=payload,
        capture_output=True,
        check=False,
        env=env,
        cwd=working_directory,
        timeout=PROCESS_BACKSTOP_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"semantic control exited {result.returncode}, expected hook exit 0; "
            f"stderr={result.stderr.decode(errors='replace')[:240]!r}"
        )

    observed_decision: str
    if not result.stdout:
        observed_decision = "allow"
        if result.stderr:
            raise RuntimeError(
                "semantic allow control polluted stderr; refusing to time a "
                "non-conformant hook outcome"
            )
    else:
        try:
            parsed = json.loads(result.stdout)
            observed_decision = parsed["hookSpecificOutput"]["permissionDecision"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError(
                "semantic control emitted non-hook stdout; refusing to time it: "
                f"{result.stdout[:240]!r}"
            ) from exc
        if observed_decision != "deny":
            raise RuntimeError(
                f"semantic control emitted unexpected decision {observed_decision!r}"
            )
        if not result.stderr:
            raise RuntimeError("semantic deny control lost its stderr warning")

    if observed_decision != expected_decision:
        raise RuntimeError(
            f"semantic control observed {observed_decision!r}, "
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
            return run_one(bin_path, command, env, working_directory), None
        if index % 2 == 0:
            full_ms = run_one(bin_path, command, env, working_directory)
            bypass_ms = run_one(bin_path, command, bypass_env, working_directory)
        else:
            bypass_ms = run_one(bin_path, command, bypass_env, working_directory)
            full_ms = run_one(bin_path, command, env, working_directory)
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


def capture_rustc_version(
    env: Dict[str, str], working_directory: str
) -> Tuple[str, Optional[str]]:
    try:
        result = subprocess.run(
            ["rustc", "-vV"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            cwd=working_directory,
            timeout=PROCESS_BACKSTOP_SECONDS,
        )
        output = result.stdout.strip()
        host = None
        for line in output.splitlines():
            if line.startswith("host:"):
                host = line.split(":", 1)[1].strip()
        return output, host
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}", None


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
            [bin_path, "explain", command, "--format", "json"],
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
        [bin_path, "config", "--format", "json"],
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate dcg perf baseline JSON")
    parser.add_argument("--bin", default="./target/release/dcg", help="Path to dcg binary")
    parser.add_argument("--output", help="Write JSON output to this file")
    parser.add_argument("--warmup", type=int, default=30, help="Warmup iterations per case")
    parser.add_argument("--runs", type=int, default=300, help="Measured iterations per case")
    parser.add_argument("--skip-trace", action="store_true", help="Skip explain trace capture")
    parser.add_argument(
        "--assert-budget-ms",
        type=int,
        default=0,
        help=(
            "Absolute evaluator-cost gate: pair every full hook invocation "
            "with DCG_BYPASS, subtract the matched process floor, and fail "
            "(exit 3) unless paired-delta p95 fits within this budget after "
            "applying --assert-margin-pct. The supplied value must exactly "
            "match HOOK_EVALUATION_BUDGET_MS parsed from src/perf.rs."
        ),
    )
    parser.add_argument(
        "--assert-margin-pct",
        type=int,
        default=50,
        help=(
            "Percentage of --assert-budget-ms that paired evaluator p95 may "
            "consume (default 50; values above 60 are rejected)"
        ),
    )
    args = parser.parse_args()

    repo_root = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
    bin_path = os.path.realpath(os.path.abspath(args.bin))
    if not os.path.isfile(bin_path):
        print(f"error: binary not found: {bin_path}", file=sys.stderr)
        return 1
    if not os.access(bin_path, os.X_OK):
        print(f"error: binary is not executable: {bin_path}", file=sys.stderr)
        return 1
    if args.warmup < 0 or args.runs <= 0:
        print("error: --warmup must be >= 0 and --runs must be > 0", file=sys.stderr)
        return 1
    if args.assert_budget_ms < 0:
        print("error: --assert-budget-ms must be >= 0", file=sys.stderr)
        return 1
    gate_enabled = args.assert_budget_ms > 0
    if gate_enabled:
        if not 0 < args.assert_margin_pct <= 60:
            print("error: --assert-margin-pct must be in the range 1..=60", file=sys.stderr)
            return 1
    elif args.assert_margin_pct <= 0:
        print("error: --assert-margin-pct must be > 0", file=sys.stderr)
        return 1

    try:
        source_budget_start = capture_shipped_budget(repo_root)
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not derive shipped hook budget: {exc}", file=sys.stderr)
        return 1
    shipped_budget_ms = source_budget_start["hook_evaluation_budget_ms"]
    if gate_enabled and args.assert_budget_ms != shipped_budget_ms:
        print(
            "LATENCY GATE ABORTED: --assert-budget-ms "
            f"({args.assert_budget_ms}) does not match the shipped "
            f"HOOK_EVALUATION_BUDGET_MS ({shipped_budget_ms}) parsed from "
            f"{source_budget_start['path']}",
            file=sys.stderr,
        )
        return 3

    base_env, isolation = create_isolated_environment()
    working_directory = isolation["working_directory"]
    binary_sha_start = sha256_file(bin_path)
    binary_size = os.path.getsize(bin_path)
    git_sha_start = capture_git_sha(repo_root, base_env)
    git_state_start = capture_git_state(repo_root, base_env)
    build_input_manifest_start = capture_build_input_manifest(repo_root)
    harness_manifest_start = capture_harness_manifest(repo_root)
    try:
        version_output = capture_version_output(bin_path, base_env, working_directory)
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not capture binary version: {exc}", file=sys.stderr)
        return 1
    rustc_output, rustc_host = capture_rustc_version(base_env, repo_root)

    try:
        config_probe = probe_effective_budget(bin_path, base_env, working_directory)
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not verify effective hook budget: {exc}", file=sys.stderr)
        return 3 if gate_enabled else 1
    if config_probe["hook_timeout_source"] != "default":
        print(
            "LATENCY RUN ABORTED: isolated config probe resolved a non-default "
            f"hook timeout source ({config_probe['hook_timeout_source']!r}); "
            "measurements would not represent shipped defaults",
            file=sys.stderr,
        )
        return 3 if gate_enabled else 1
    if config_probe["hook_timeout_ms"] != shipped_budget_ms:
        print(
            "LATENCY RUN ABORTED: isolated binary resolved "
            f"{config_probe['hook_timeout_ms']}ms but src/perf.rs declares "
            f"{shipped_budget_ms}ms",
            file=sys.stderr,
        )
        return 3 if gate_enabled else 1

    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for case in build_cases():
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
    git_state_end = capture_git_state(repo_root, base_env)
    build_input_manifest_end = capture_build_input_manifest(repo_root)
    harness_manifest_end = capture_harness_manifest(repo_root)
    try:
        source_budget_end = capture_shipped_budget(repo_root)
    except Exception as exc:  # noqa: BLE001
        source_budget_end = {"error": str(exc)}
        errors.append("could not re-read src/perf.rs after the run")
    if binary_sha_end != binary_sha_start:
        errors.append("measured binary changed during the run")
    if git_sha_end != git_sha_start:
        errors.append("repository HEAD changed during the run")
    if git_state_end != git_state_start:
        errors.append("repository worktree state changed during the run")
    if build_input_manifest_end != build_input_manifest_start:
        errors.append("Rust/Cargo build inputs changed during the run")
    if harness_manifest_end != harness_manifest_start:
        errors.append("performance harness bytes changed during the run")
    if source_budget_end != source_budget_start:
        errors.append("src/perf.rs or its shipped budget changed during the run")

    payload = {
        "schema_version": 2,
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
            "repository_state": git_state_start,
            "repository_state_end": git_state_end,
            "build_input_manifest": build_input_manifest_start,
            "build_input_manifest_end": build_input_manifest_end,
            "harness_manifest": harness_manifest_start,
            "harness_manifest_end": harness_manifest_end,
            "perf_budget_source": source_budget_start,
            "perf_budget_source_end": source_budget_end,
        },
        "toolchain_observation": {
            "version_output": rustc_output,
            "host": rustc_host,
        },
        "host": {
            "node": platform.node(),
            "os": platform.system(),
            "release": platform.release(),
            "arch": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "environment_isolation": isolation,
        "effective_budget_probe": config_probe,
        "method": {
            "mode": "process-per-invocation",
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
            "notes": (
                "Raw samples are retained. max_rss_kb is measured separately via "
                "/usr/bin/time -v. Only paired evaluator deltas are compared with "
                "the in-process hook evaluation budget."
            ),
        },
        "cases": results,
        "errors": errors,
    }

    output_json = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output_json)
            handle.write("\n")
    else:
        print(output_json)

    if errors:
        print(f"error: {len(errors)} case(s) failed to run: {errors}", file=sys.stderr)
        return 1

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
                }
            ),
            file=sys.stderr,
        )

        # Process spawn is outside the evaluator deadline. Compare only paired
        # full-minus-bypass deltas while retaining raw end-to-end timings.
        limit_ms = shipped_budget_ms * args.assert_margin_pct / 100.0
        violations = []
        gated_cases = 0
        for case in results:
            if case["id"] == "bypass":
                continue
            gated_cases += 1
            signed_p95 = case["evaluator_delta_metrics"]["p95_ms"]
            budget_consumption_p95 = max(0.0, signed_p95)
            status = "ok" if budget_consumption_p95 <= limit_ms else "OVER"
            print(
                json.dumps(
                    {
                        "event": "latency_gate_case",
                        "case": case["id"],
                        "full_process_p95_ms": round(case["metrics"]["p95_ms"], 3),
                        "bypass_process_p95_ms": round(
                            case["bypass_metrics"]["p95_ms"], 3
                        ),
                        "evaluator_delta_p50_ms": round(
                            case["evaluator_delta_metrics"]["p50_ms"], 3
                        ),
                        "evaluator_delta_p95_ms": round(signed_p95, 3),
                        "budget_consumption_p95_ms": round(
                            budget_consumption_p95, 3
                        ),
                        "limit_ms": limit_ms,
                        "budget_ms": shipped_budget_ms,
                        "status": status,
                    }
                ),
                file=sys.stderr,
            )
            if budget_consumption_p95 > limit_ms:
                violations.append(
                    f"{case['id']}: paired evaluator p95 "
                    f"{budget_consumption_p95:.1f}ms exceeds "
                    f"{limit_ms:.0f}ms ({args.assert_margin_pct}% of the "
                    f"{shipped_budget_ms}ms hook budget)"
                )
        if violations:
            print(
                "LATENCY GATE FAILED — evaluator cost is eating the "
                "fail-closed hook deadline (#245 regression class):",
                file=sys.stderr,
            )
            for violation in violations:
                print(f"  {violation}", file=sys.stderr)
            return 3
        print(
            f"LATENCY GATE PASSED: {gated_cases} paired cases, evaluator p95 "
            f"within {args.assert_margin_pct}% of the {shipped_budget_ms}ms budget",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
