#!/bin/bash
# Scan mode regression test
# Compares current scan output against golden expected output

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DCG="${DCG_SCAN_REGRESSION_BIN:-${PROJECT_DIR}/target/release/dcg}"
FIXTURES_DIR="${PROJECT_DIR}/tests/fixtures/scan"
EXPECTED="${FIXTURES_DIR}/expected_output.json"
if [ -n "${DCG_SCAN_REGRESSION_ACTUAL:-}" ]; then
    ACTUAL="$DCG_SCAN_REGRESSION_ACTUAL"
else
    ACTUAL="$(mktemp "${TMPDIR:-/tmp}/dcg_scan_regression_actual.XXXXXX")"
fi

# Check prerequisites
if [ ! -f "$DCG" ]; then
    echo "Error: dcg binary not found at $DCG"
    echo "Run: cargo build --release"
    exit 1
fi

if [ ! -f "$EXPECTED" ]; then
    echo "Error: Expected output not found at $EXPECTED"
    exit 1
fi

echo "Running scan regression test..."
echo "Binary: $DCG"
echo "Fixtures: $FIXTURES_DIR"

# Run scan and capture output (stderr goes to /dev/null to avoid corrupting JSON)
# The golden intentionally exercises optional PostgreSQL and Docker rules in
# addition to the default core packs. Keep that scope explicit so the gate does
# not silently lose those findings when runtime defaults change.
"$DCG" scan --paths "$FIXTURES_DIR" --format json --top 0 \
    --with-packs database.postgresql,containers.docker > "$ACTUAL" 2>/dev/null || true

# Compare the complete deterministic scan contract. The scanner receives an
# absolute fixture path, while the checked-in golden uses repository-relative
# paths, so normalize only that prefix. Timing remains intentionally excluded.
echo ""
echo "Comparing outputs..."

if ! python3 - "$EXPECTED" "$ACTUAL" <<'PY'
import difflib
import json
import sys


def normalize_path(value):
    normalized = value.replace("\\", "/")
    marker = "/tests/fixtures/scan/"
    if marker in normalized:
        return "tests/fixtures/scan/" + normalized.split(marker, 1)[1]
    return normalized


def normalize(payload):
    summary = dict(payload["summary"])
    summary.pop("elapsed_ms", None)
    if "skipped" in summary:
        summary["skipped"] = [
            {**entry, "path": normalize_path(entry["path"])}
            for entry in summary["skipped"]
        ]

    findings = [
        {**finding, "file": normalize_path(finding["file"])}
        for finding in payload["findings"]
    ]
    return {
        "schema_version": payload["schema_version"],
        "summary": summary,
        "findings": findings,
    }


with open(sys.argv[1], encoding="utf-8") as handle:
    expected = normalize(json.load(handle))
with open(sys.argv[2], encoding="utf-8") as handle:
    actual = normalize(json.load(handle))

if expected != actual:
    expected_lines = json.dumps(expected, indent=2, sort_keys=True).splitlines()
    actual_lines = json.dumps(actual, indent=2, sort_keys=True).splitlines()
    print("FAIL: scan output differs from golden", file=sys.stderr)
    print(
        "\n".join(
            difflib.unified_diff(
                expected_lines,
                actual_lines,
                fromfile="expected",
                tofile="actual",
                lineterm="",
            )
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
then
    exit 1
fi

ACTUAL_FILES=$(python3 -c "import json; print(json.load(open('$ACTUAL'))['summary']['files_scanned'])")
ACTUAL_FINDINGS=$(python3 -c "import json; print(json.load(open('$ACTUAL'))['summary']['findings_total'])")

echo ""
echo "PASS: Scan regression test passed"
echo "  Files scanned: $ACTUAL_FILES"
echo "  Findings: $ACTUAL_FINDINGS"
echo "  Complete normalized golden matches"
