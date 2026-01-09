#!/bin/bash
#
# Benchmark Budget Enforcement Script
#
# Runs Criterion benchmarks and checks results against performance budgets.
# Exit 0 if all benchmarks pass, exit 1 if any exceed panic thresholds.
#
# Usage:
#   ./scripts/check_benchmark_budgets.sh [--warn-only]
#
# Options:
#   --warn-only   Only warn on budget violations, don't fail
#
# Performance Budgets (from src/perf.rs):
#   | Operation              | Target   | Warning  | Panic    |
#   |------------------------|----------|----------|----------|
#   | Quick reject           | 1μs      | 5μs      | 50μs     |
#   | Fast path              | 50μs     | 100μs    | 500μs    |
#   | Pattern match          | 100μs    | 250μs    | 1ms      |
#   | Heredoc trigger        | 5μs      | 10μs     | 100μs    |
#   | Heredoc extract        | 200μs    | 500μs    | 2ms      |
#   | Language detect        | 20μs     | 50μs     | 200μs    |
#   | Full pipeline          | 5ms      | 15ms     | 50ms     |

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

WARN_ONLY=false
if [[ "${1:-}" == "--warn-only" ]]; then
    WARN_ONLY=true
fi

# Budget thresholds (in nanoseconds for easy comparison)
# Format: benchmark_pattern:warning_ns:panic_ns
declare -A BUDGETS=(
    # Tier 1: Trigger checks - budget 10μs/100μs
    ["tier1_triggers/check_triggers"]=10000:100000
    ["tier1_triggers/matched_triggers"]=10000:100000

    # Quick reject - budget 5μs/50μs
    ["pack_aware_quick_reject"]=5000:50000

    # Core pipeline (pattern match) - budget 250μs/1ms
    ["core_pipeline"]=250000:1000000

    # Tier 2: Heredoc extraction - budget 500μs/2ms
    ["tier2_extraction"]=500000:2000000

    # Shell extraction - budget 500μs/2ms
    ["shell_extraction"]=500000:2000000

    # Language detection - budget 50μs/200μs
    ["language_detection"]=50000:200000

    # Full pipeline - budget 15ms/50ms
    ["full_pipeline"]=15000000:50000000
)

echo -e "${BLUE}=== Performance Budget Check ===${NC}"
echo ""

# Create temp directory for benchmark output
BENCH_DIR=$(mktemp -d)
trap "rm -rf $BENCH_DIR" EXIT

echo -e "${BLUE}Running benchmarks...${NC}"

# Run benchmarks and save output
if ! cargo bench --bench heredoc_perf -- --noplot --save-baseline budget_check 2>&1 | tee "$BENCH_DIR/bench_output.txt"; then
    echo -e "${RED}Benchmark run failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Checking results against budgets...${NC}"
echo ""

# Parse benchmark results and check against budgets
VIOLATIONS=0
WARNINGS=0

# Extract timing from benchmark output
# Format: "time:   [113.74 ns 114.19 ns 114.74 ns]"
# We use the middle value (point estimate)
while IFS= read -r line; do
    # Look for benchmark name lines (they start with the benchmark group/name)
    if [[ "$line" =~ ^([a-z_]+/[a-z_/]+)$ ]]; then
        CURRENT_BENCH="$line"
        continue
    fi

    # Look for timing lines
    if [[ "$line" =~ time:.*\[([0-9.]+)\ (ns|µs|μs|ms|s)\ ([0-9.]+)\ (ns|µs|μs|ms|s)\ ([0-9.]+)\ (ns|µs|μs|ms|s)\] ]]; then
        # Extract middle value (point estimate)
        VALUE="${BASH_REMATCH[3]}"
        UNIT="${BASH_REMATCH[4]}"

        # Convert to nanoseconds
        case "$UNIT" in
            ns) VALUE_NS=$(echo "$VALUE" | awk '{printf "%.0f", $1}') ;;
            µs|μs) VALUE_NS=$(echo "$VALUE" | awk '{printf "%.0f", $1 * 1000}') ;;
            ms) VALUE_NS=$(echo "$VALUE" | awk '{printf "%.0f", $1 * 1000000}') ;;
            s) VALUE_NS=$(echo "$VALUE" | awk '{printf "%.0f", $1 * 1000000000}') ;;
        esac

        # Find matching budget
        for pattern in "${!BUDGETS[@]}"; do
            if [[ "$CURRENT_BENCH" == *"$pattern"* ]]; then
                IFS=: read -r WARNING_NS PANIC_NS <<< "${BUDGETS[$pattern]}"

                # Format value for display
                if [[ $VALUE_NS -ge 1000000 ]]; then
                    DISPLAY_VALUE="$(echo "$VALUE_NS" | awk '{printf "%.2fms", $1/1000000}')"
                elif [[ $VALUE_NS -ge 1000 ]]; then
                    DISPLAY_VALUE="$(echo "$VALUE_NS" | awk '{printf "%.2fμs", $1/1000}')"
                else
                    DISPLAY_VALUE="${VALUE_NS}ns"
                fi

                # Check against thresholds
                if [[ $VALUE_NS -gt $PANIC_NS ]]; then
                    echo -e "${RED}PANIC${NC} $CURRENT_BENCH: $DISPLAY_VALUE (budget: $(echo $PANIC_NS | awk '{printf "%.0fμs", $1/1000}'))"
                    ((VIOLATIONS++))
                elif [[ $VALUE_NS -gt $WARNING_NS ]]; then
                    echo -e "${YELLOW}WARN${NC}  $CURRENT_BENCH: $DISPLAY_VALUE (budget: $(echo $WARNING_NS | awk '{printf "%.0fμs", $1/1000}'))"
                    ((WARNINGS++))
                else
                    echo -e "${GREEN}OK${NC}    $CURRENT_BENCH: $DISPLAY_VALUE"
                fi
                break
            fi
        done
    fi
done < "$BENCH_DIR/bench_output.txt"

echo ""
echo -e "${BLUE}=== Summary ===${NC}"
echo -e "Violations (panic): $VIOLATIONS"
echo -e "Warnings: $WARNINGS"

if [[ $VIOLATIONS -gt 0 ]]; then
    if [[ "$WARN_ONLY" == "true" ]]; then
        echo -e "${YELLOW}Budget violations detected (warn-only mode)${NC}"
        exit 0
    else
        echo -e "${RED}Budget violations detected - failing CI${NC}"
        exit 1
    fi
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}Warnings detected but within panic threshold${NC}"
    exit 0
else
    echo -e "${GREEN}All benchmarks within budget${NC}"
    exit 0
fi
