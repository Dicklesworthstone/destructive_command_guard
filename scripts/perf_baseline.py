#!/usr/bin/env python3
"""Generate a perf baseline JSON artifact for dcg.

This script measures process-per-invocation latency for representative commands
and records p50/p95/p99/mean/throughput with basic build metadata.

Usage:
  ./scripts/perf_baseline.py --bin ./target/release/dcg --output perf/baselines/latest.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


def run_one(bin_path: str, command: str, env: Optional[Dict[str, str]] = None) -> float:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    start = time.perf_counter_ns()
    subprocess.run(
        [bin_path],
        input=payload,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=env,
    )
    end = time.perf_counter_ns()
    return (end - start) / 1_000_000.0


def percentile(sorted_values: List[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = int(round((pct / 100.0) * (len(sorted_values) - 1)))
    idx = max(0, min(idx, len(sorted_values) - 1))
    return sorted_values[idx]


def run_case(
    bin_path: str,
    command: str,
    env: Optional[Dict[str, str]],
    warmup: int,
    runs: int,
) -> Dict[str, Any]:
    for _ in range(warmup):
        run_one(bin_path, command, env)

    timings = [run_one(bin_path, command, env) for _ in range(runs)]
    timings_sorted = sorted(timings)

    mean_ms = sum(timings_sorted) / len(timings_sorted)
    throughput = 1000.0 / mean_ms if mean_ms > 0 else 0.0

    return {
        "p50_ms": statistics.median(timings_sorted),
        "p95_ms": percentile(timings_sorted, 95),
        "p99_ms": percentile(timings_sorted, 99),
        "mean_ms": mean_ms,
        "throughput_per_s": throughput,
        "sample_count": len(timings_sorted),
    }


def capture_version_output(bin_path: str) -> str:
    try:
        result = subprocess.run(
            [bin_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = (result.stdout + result.stderr).strip()
        return output
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


def capture_rustc_version() -> Tuple[str, Optional[str]]:
    try:
        result = subprocess.run(
            ["rustc", "-vV"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout.strip()
        host = None
        for line in output.splitlines():
            if line.startswith("host:"):
                host = line.split(":", 1)[1].strip()
        return output, host
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}", None


def capture_git_sha() -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        sha = result.stdout.strip()
        return sha if sha else None
    except Exception:
        return None


def capture_trace(bin_path: str, command: str) -> Optional[Dict[str, Any]]:
    """Run command with trace logging and capture the output."""
    env = os.environ.copy()
    env["DCG_TRACE"] = "1"
    
    try:
        result = subprocess.run(
            [bin_path, "explain", command, "--format", "json"],
            capture_output=True,
            text=True,
            check=False,
            env=env
        )
        if result.returncode != 0:
            return None
            
        try:
            payload = json.loads(result.stdout)
            return payload.get("trace")
        except json.JSONDecodeError:
            return None
            
    except Exception:
        return None


def build_cases() -> List[Dict[str, Any]]:
    return [
        {
            "id": "quick_reject",
            "description": "No pack keywords (fast allow)",
            "command": "ls -la",
            "env": {},
        },
        {
            "id": "safe_keyword",
            "description": "Keyword present, safe path",
            "command": "git status",
            "env": {},
        },
        {
            "id": "destructive_keyword",
            "description": "Keyword present, destructive match",
            "command": "git reset --hard",
            "env": {},
        },
        {
            "id": "heredoc_inline",
            "description": "Inline script trigger",
            "command": "python -c \"import os; os.system('rm -rf /')\"",
            "env": {},
        },
        {
            "id": "bypass",
            "description": "Bypass hook via DCG_BYPASS",
            "command": "git reset --hard",
            "env": {"DCG_BYPASS": "1"},
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate dcg perf baseline JSON")
    parser.add_argument("--bin", default="./target/release/dcg", help="Path to dcg binary")
    parser.add_argument("--output", help="Write JSON output to this file")
    parser.add_argument("--warmup", type=int, default=30, help="Warmup iterations per case")
    parser.add_argument("--runs", type=int, default=300, help="Measured iterations per case")
    parser.add_argument("--skip-trace", action="store_true", help="Skip explain trace capture")
    args = parser.parse_args()

    if not os.path.isfile(args.bin):
        print(f"error: binary not found: {args.bin}", file=sys.stderr)
        return 1

    version_output = capture_version_output(args.bin)
    rustc_output, rustc_host = capture_rustc_version()
    git_sha = capture_git_sha()

    base_env = dict(os.environ)

    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for case in build_cases():
        env = base_env.copy()
        env.update(case.get("env", {}))
        try:
            metrics = run_case(args.bin, case["command"], env, args.warmup, args.runs)
            trace = None
            if not args.skip_trace:
                trace = capture_trace(args.bin, case["command"])
            results.append(
                {
                    "id": case["id"],
                    "description": case["description"],
                    "command": case["command"],
                    "env": case.get("env", {}),
                    "metrics": metrics,
                    "trace": trace,
                }
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{case['id']}: {exc}")

    payload = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary": {
            "path": args.bin,
            "version_output": version_output,
            "git_sha": git_sha,
        },
        "rustc": {
            "version_output": rustc_output,
            "host": rustc_host,
        },
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "arch": platform.machine(),
        },
        "method": {
            "mode": "process",
            "warmup": args.warmup,
            "runs": args.runs,
            "timer": "perf_counter_ns",
            "rss_method": "none",
            "notes": "Process-per-invocation timing. Stage timings populated if trace output includes steps.",
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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
