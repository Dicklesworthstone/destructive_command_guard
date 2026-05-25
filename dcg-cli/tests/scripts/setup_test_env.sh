#!/usr/bin/env bash
# setup_test_env.sh - Test Environment Setup for DCG E2E Tests
# Part of bead [E0-T1] E2E test infrastructure
#
# This script prepares an isolated test environment for DCG E2E testing.
# It can create temp directories, mock git repos, and configure test fixtures.

set -euo pipefail

# === Configuration ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTS_DIR="$PROJECT_ROOT/tests"
FIXTURES_DIR="$TESTS_DIR/e2e/fixtures"

# Default test environment location
TEST_ENV_ROOT="${TEST_ENV_ROOT:-/tmp/dcg-e2e-tests}"
TEST_ENV_ID="${TEST_ENV_ID:-$(date +%Y%m%d_%H%M%S)_$$}"
TEST_ENV_DIR="$TEST_ENV_ROOT/$TEST_ENV_ID"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# === Logging ===
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# === Help ===
show_help() {
    cat << EOF
DCG Test Environment Setup

Usage: $(basename "$0") [OPTIONS] COMMAND

Commands:
    create              Create a new test environment
    destroy             Destroy a test environment
    list                List existing test environments
    clean               Remove all old test environments
    export-vars         Print environment variables for sourcing

Options:
    -h, --help          Show this help message
    -d, --dir DIR       Use DIR as test environment root
    -i, --id ID         Use specific environment ID
    --git-repo          Initialize a mock git repository
    --with-history N    Create N commits in mock repo
    --with-branches N   Create N feature branches
    --with-config FILE  Copy config fixture to environment
    --with-commands     Copy command fixtures to environment
    --verbose           Verbose output

Environment Variables:
    TEST_ENV_ROOT       Root directory for test environments
    TEST_ENV_ID         Specific test environment ID
    DCG_BINARY          Path to dcg binary

Examples:
    # Create environment with git repo and history
    $(basename "$0") create --git-repo --with-history 10

    # Create and export for current shell
    eval \$($(basename "$0") create --export-vars)

    # Clean up old environments (>24h old)
    $(basename "$0") clean

EOF
    exit 0
}

# === Create Test Environment ===
create_env() {
    log_info "Creating test environment: $TEST_ENV_DIR"

    # Create directory structure
    mkdir -p "$TEST_ENV_DIR"/{workspace,configs,tmp,reports}

    # Write environment metadata
    cat > "$TEST_ENV_DIR/.dcg-test-env" << EOF
{
    "id": "$TEST_ENV_ID",
    "created": "$(date -Iseconds)",
    "project_root": "$PROJECT_ROOT",
    "user": "${USER:-unknown}",
    "hostname": "${HOSTNAME:-unknown}"
}
EOF

    log_success "Created: $TEST_ENV_DIR"
}

# === Initialize Git Repository ===
init_git_repo() {
    local repo_dir="$TEST_ENV_DIR/workspace"
    local history_count="${1:-0}"
    local branch_count="${2:-0}"

    log_info "Initializing git repository in: $repo_dir"

    cd "$repo_dir"

    # Initialize git
    git init -q

    # Configure git for tests
    git config user.email "test@dcg-e2e.local"
    git config user.name "DCG E2E Test"

    # Create initial content
    cat > README.md << 'EOF'
# DCG Test Repository

This is a mock repository for DCG E2E testing.
EOF

    cat > .gitignore << 'EOF'
*.log
*.tmp
.dcg/
target/
node_modules/
EOF

    mkdir -p src
    cat > src/main.rs << 'EOF'
fn main() {
    println!("Hello from DCG test repo!");
}
EOF

    # Initial commit
    git add -A
    git commit -q -m "Initial commit"

    log_success "Git repo initialized"

    # Create history if requested
    if [[ "$history_count" -gt 0 ]]; then
        log_info "Creating $history_count commits..."

        for i in $(seq 1 "$history_count"); do
            echo "// Change $i" >> src/main.rs
            git add -A
            git commit -q -m "Commit $i: Test change"
        done

        log_success "Created $history_count commits"
    fi

    # Create branches if requested
    if [[ "$branch_count" -gt 0 ]]; then
        log_info "Creating $branch_count feature branches..."

        for i in $(seq 1 "$branch_count"); do
            git checkout -q -b "feature/test-$i"
            echo "// Feature $i" >> src/main.rs
            git add -A
            git commit -q -m "Feature $i: Implementation"
            git checkout -q main 2>/dev/null || git checkout -q master
        done

        log_success "Created $branch_count branches"
    fi

    cd - > /dev/null
}

# === Copy Config Fixtures ===
copy_config() {
    local config_name="$1"
    local config_source="$FIXTURES_DIR/configs/${config_name}.toml"
    local config_dest="$TEST_ENV_DIR/configs/${config_name}.toml"

    if [[ ! -f "$config_source" ]]; then
        log_error "Config fixture not found: $config_name"
        return 1
    fi

    cp "$config_source" "$config_dest"
    log_success "Copied config: $config_name"
}

# === Copy All Config Fixtures ===
copy_all_configs() {
    log_info "Copying all config fixtures..."

    mkdir -p "$TEST_ENV_DIR/configs"

    for config in "$FIXTURES_DIR/configs"/*.toml; do
        [[ -f "$config" ]] || continue
        cp "$config" "$TEST_ENV_DIR/configs/"
    done

    log_success "Copied $(ls "$TEST_ENV_DIR/configs"/*.toml 2>/dev/null | wc -l) configs"
}

# === Copy Command Fixtures ===
copy_commands() {
    log_info "Copying command fixtures..."

    mkdir -p "$TEST_ENV_DIR/commands"

    for cmd_file in "$FIXTURES_DIR/commands"/*.txt; do
        [[ -f "$cmd_file" ]] || continue
        cp "$cmd_file" "$TEST_ENV_DIR/commands/"
    done

    log_success "Copied $(ls "$TEST_ENV_DIR/commands"/*.txt 2>/dev/null | wc -l) command sets"
}

# === Build DCG Binary ===
build_dcg() {
    local release="${1:-false}"

    log_info "Building DCG..."

    cd "$PROJECT_ROOT"

    if [[ "$release" == "true" ]]; then
        cargo build --release -q
        DCG_BINARY="$PROJECT_ROOT/target/release/dcg"
    else
        cargo build -q
        DCG_BINARY="$PROJECT_ROOT/target/debug/dcg"
    fi

    if [[ ! -x "$DCG_BINARY" ]]; then
        log_error "Failed to build DCG"
        return 1
    fi

    # Symlink to test env
    ln -sf "$DCG_BINARY" "$TEST_ENV_DIR/dcg"

    log_success "Built: $DCG_BINARY"

    cd - > /dev/null
}

# === Export Environment Variables ===
export_vars() {
    cat << EOF
export TEST_ENV_DIR="$TEST_ENV_DIR"
export TEST_ENV_ID="$TEST_ENV_ID"
export DCG_TEST_WORKSPACE="$TEST_ENV_DIR/workspace"
export DCG_TEST_CONFIGS="$TEST_ENV_DIR/configs"
export DCG_TEST_COMMANDS="$TEST_ENV_DIR/commands"
export DCG_BINARY="${DCG_BINARY:-$TEST_ENV_DIR/dcg}"
export PATH="$TEST_ENV_DIR:\$PATH"
EOF
}

# === Destroy Test Environment ===
destroy_env() {
    local env_dir="${1:-$TEST_ENV_DIR}"

    if [[ ! -d "$env_dir" ]]; then
        log_warn "Environment not found: $env_dir"
        return 0
    fi

    # Safety check - ensure it's a DCG test env
    if [[ ! -f "$env_dir/.dcg-test-env" ]]; then
        log_error "Not a DCG test environment: $env_dir"
        return 1
    fi

    log_info "Destroying: $env_dir"
    rm -rf "$env_dir"
    log_success "Destroyed"
}

# === List Test Environments ===
list_envs() {
    log_info "Test environments in: $TEST_ENV_ROOT"
    echo ""

    if [[ ! -d "$TEST_ENV_ROOT" ]]; then
        echo "  (none)"
        return
    fi

    for env in "$TEST_ENV_ROOT"/*/; do
        [[ -d "$env" ]] || continue

        local env_name=$(basename "$env")
        local env_meta="$env/.dcg-test-env"

        if [[ -f "$env_meta" ]]; then
            local created=$(grep '"created"' "$env_meta" | cut -d'"' -f4)
            local size=$(du -sh "$env" 2>/dev/null | cut -f1)
            echo "  $env_name  ($created, $size)"
        else
            echo "  $env_name  (unknown)"
        fi
    done
}

# === Clean Old Environments ===
clean_envs() {
    local max_age_hours="${1:-24}"

    log_info "Cleaning environments older than ${max_age_hours}h..."

    if [[ ! -d "$TEST_ENV_ROOT" ]]; then
        log_info "No environments to clean"
        return
    fi

    local cleaned=0

    for env in "$TEST_ENV_ROOT"/*/; do
        [[ -d "$env" ]] || continue
        [[ -f "$env/.dcg-test-env" ]] || continue

        # Check age
        local env_age_mins=$(( ( $(date +%s) - $(stat -c %Y "$env") ) / 60 ))
        local env_age_hours=$(( env_age_mins / 60 ))

        if [[ $env_age_hours -ge $max_age_hours ]]; then
            destroy_env "$env"
            ((cleaned++))
        fi
    done

    log_success "Cleaned $cleaned environments"
}

# === Validate Environment ===
validate_env() {
    local env_dir="${1:-$TEST_ENV_DIR}"

    log_info "Validating environment: $env_dir"

    local valid=true

    # Check structure
    for dir in workspace configs tmp; do
        if [[ ! -d "$env_dir/$dir" ]]; then
            log_error "Missing directory: $dir"
            valid=false
        fi
    done

    # Check metadata
    if [[ ! -f "$env_dir/.dcg-test-env" ]]; then
        log_error "Missing environment metadata"
        valid=false
    fi

    # Check DCG binary
    if [[ -L "$env_dir/dcg" ]] && [[ -x "$env_dir/dcg" ]]; then
        local version=$("$env_dir/dcg" --version 2>/dev/null || echo "unknown")
        log_info "DCG: $version"
    else
        log_warn "DCG binary not linked"
    fi

    if [[ "$valid" == "true" ]]; then
        log_success "Environment valid"
        return 0
    else
        log_error "Environment invalid"
        return 1
    fi
}

# === Main ===
main() {
    local command=""
    local with_git=false
    local history_count=0
    local branch_count=0
    local config_name=""
    local with_commands=false
    local verbose=false
    local export_mode=false
    local release_build=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) show_help ;;
            -d|--dir) TEST_ENV_ROOT="$2"; shift 2 ;;
            -i|--id) TEST_ENV_ID="$2"; shift 2 ;;
            --git-repo) with_git=true; shift ;;
            --with-history) history_count="$2"; shift 2 ;;
            --with-branches) branch_count="$2"; shift 2 ;;
            --with-config) config_name="$2"; shift 2 ;;
            --with-commands) with_commands=true; shift ;;
            --verbose) verbose=true; shift ;;
            --export-vars) export_mode=true; shift ;;
            --release) release_build=true; shift ;;
            create|destroy|list|clean|validate|export-vars)
                command="$1"; shift ;;
            *)
                if [[ -z "$command" ]]; then
                    log_error "Unknown command: $1"
                    exit 1
                fi
                ;;
        esac
    done

    # Update TEST_ENV_DIR with potentially new values
    TEST_ENV_DIR="$TEST_ENV_ROOT/$TEST_ENV_ID"

    # Execute command
    case "$command" in
        create)
            create_env

            if [[ "$with_git" == "true" ]] || [[ $history_count -gt 0 ]] || [[ $branch_count -gt 0 ]]; then
                init_git_repo "$history_count" "$branch_count"
            fi

            if [[ -n "$config_name" ]]; then
                copy_config "$config_name"
            else
                copy_all_configs
            fi

            if [[ "$with_commands" == "true" ]]; then
                copy_commands
            fi

            # Build DCG
            build_dcg "$release_build"

            # Validate
            validate_env

            if [[ "$export_mode" == "true" ]]; then
                echo ""
                echo "# To use this environment, run:"
                echo "eval \$($(basename "$0") export-vars -i $TEST_ENV_ID)"
            fi
            ;;

        destroy)
            destroy_env
            ;;

        list)
            list_envs
            ;;

        clean)
            clean_envs 24
            ;;

        validate)
            validate_env
            ;;

        export-vars)
            export_vars
            ;;

        "")
            # No command - default to create if options suggest it
            if [[ "$with_git" == "true" ]] || [[ -n "$config_name" ]]; then
                create_env
                [[ "$with_git" == "true" ]] && init_git_repo "$history_count" "$branch_count"
                [[ -n "$config_name" ]] && copy_config "$config_name"
                [[ "$with_commands" == "true" ]] && copy_commands
                build_dcg "$release_build"
                validate_env
            else
                show_help
            fi
            ;;

        *)
            log_error "Unknown command: $command"
            exit 1
            ;;
    esac
}

main "$@"
