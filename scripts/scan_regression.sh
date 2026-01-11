#!/bin/bash
# Scan mode regression test
# Compares current scan output against golden expected output

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DCG="${PROJECT_DIR}/target/release/dcg"
FIXTURES_DIR="${PROJECT_DIR}/tests/fixtures/scan"
EXPECTED="${FIXTURES_DIR}/expected_output.json"
ACTUAL="/tmp/dcg_scan_regression_actual.json"

# Check prerequisites
if [ ! -f "$DCG" ]; then
    echo "Error: Release binary not found at $DCG"
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

# Run scan and capture output
"$DCG" scan --paths "$FIXTURES_DIR" --format json --top 0 > "$ACTUAL" 2>&1 || true

# Compare key fields (ignore timestamps and elapsed_ms which vary)
echo ""
echo "Comparing outputs..."

# Extract and compare findings count
EXPECTED_FINDINGS=$(python3 -c "import json; print(json.load(open('$EXPECTED'))['summary']['findings_total'])")
ACTUAL_FINDINGS=$(python3 -c "import json; print(json.load(open('$ACTUAL'))['summary']['findings_total'])")

if [ "$EXPECTED_FINDINGS" != "$ACTUAL_FINDINGS" ]; then
    echo "FAIL: Findings count mismatch"
    echo "  Expected: $EXPECTED_FINDINGS"
    echo "  Actual: $ACTUAL_FINDINGS"
    exit 1
fi

# Compare files scanned
EXPECTED_FILES=$(python3 -c "import json; print(json.load(open('$EXPECTED'))['summary']['files_scanned'])")
ACTUAL_FILES=$(python3 -c "import json; print(json.load(open('$ACTUAL'))['summary']['files_scanned'])")

if [ "$EXPECTED_FILES" != "$ACTUAL_FILES" ]; then
    echo "FAIL: Files scanned mismatch"
    echo "  Expected: $EXPECTED_FILES"
    echo "  Actual: $ACTUAL_FILES"
    exit 1
fi

# Compare rule IDs (semantic check)
EXPECTED_RULES=$(python3 -c "
import json
findings = json.load(open('$EXPECTED'))['findings']
rules = sorted([f.get('rule_id', '') for f in findings])
print('\n'.join(rules))
")

ACTUAL_RULES=$(python3 -c "
import json
findings = json.load(open('$ACTUAL'))['findings']
rules = sorted([f.get('rule_id', '') for f in findings])
print('\n'.join(rules))
")

if [ "$EXPECTED_RULES" != "$ACTUAL_RULES" ]; then
    echo "FAIL: Rule IDs mismatch"
    echo ""
    echo "Expected rules:"
    echo "$EXPECTED_RULES"
    echo ""
    echo "Actual rules:"
    echo "$ACTUAL_RULES"
    exit 1
fi

echo ""
echo "PASS: Scan regression test passed"
echo "  Files scanned: $ACTUAL_FILES"
echo "  Findings: $ACTUAL_FINDINGS"
echo "  All rule IDs match"
