# Regression Corpus

This directory contains test cases for dcg's command evaluation. The corpus
tests run automatically via `cargo test --test regression_corpus`.

## Directory Structure

```
corpus/
  true_positives/           # Commands that MUST be blocked
    git_destructive.toml    # git reset --hard, git clean -fd, etc.
    rm_destructive.toml     # rm -rf outside temp dirs
    docker_destructive.toml # docker system prune, kubectl delete, etc.
  false_positives/          # Commands that MUST be allowed
    git_safe.toml           # git status, git log, git checkout -b, etc.
    rm_safe.toml            # rm -rf in /tmp, /var/tmp, $TMPDIR
    other_safe.toml         # ls, cat, cargo, npm, etc.
    substring_safe.toml     # "digit", "form" (contain git/rm as substring)
    non_execution.toml      # command -v git, which rm, --version, etc.
  bypass_attempts/          # Obfuscated dangerous commands (MUST be blocked)
    obfuscation.toml        # /usr/bin/git, backslash escaping
    wrappers.toml           # sudo/env/command/time/nohup prefixes
    heredoc_inline.toml     # python -c, bash -c, heredocs, eval
  edge_cases/               # Commands that must not crash
    boundaries.toml         # single char, empty subcommand, many flags
    quoting.toml            # single/double quotes, escaping, mixed
    multi_segment.toml      # pipes, &&, ||, ;, subshells, $()
    unicode.toml            # UTF-8 edge cases
    regex_worst_case.toml   # Potential ReDoS patterns
```

## File Format (TOML)

```toml
[[case]]
description = "Short description of what this tests"
command = "the command to evaluate"
expected = "deny"  # or "allow"
rule_id = "pack.id:pattern-name"  # optional, for validation

# Optional log expectations (for golden tests / shared E2E harness)
# These are ignored by the current regression_corpus test, but are part
# of the canonical schema for future harnesses.
[case.log]
decision = "deny"          # allow|deny|warn|log
mode = "deny"              # deny|warn|log
pack_id = "core.git"
pattern_name = "reset-hard"
rule_id = "core.git:reset-hard"
reason_contains = "destroys uncommitted changes"
```

## Adding New Test Cases

1. Choose the appropriate category directory
2. Add to an existing `.toml` file or create a new one
3. Run `cargo test --test regression_corpus` to verify

## Canonical Corpus (Golden + E2E)

The canonical, cross-harness corpus lives at:
- `tests/corpus/canonical.toml`

This file is intended to be directly consumed by golden tests and the
shared e2e harness. It includes explicit expected log fields so outputs
can be asserted deterministically.
Note: the canonical schema uses `expected_decision` and `expected_log`
keys (see the doc below); it is separate from the regression corpus
schema used by `regression_corpus.rs`.

Behavior invariants and schema details:
- `docs/canonical-corpus-invariants.md`

## Canonical Corpus Coverage (MUST remain stable)

The regression corpus provides the baseline command set for isomorphism and
behavior stability. The canonical corpus adds expected log outputs on top of
these commands for golden/e2e verification. Coverage matrix:

### Category: Git Commands
| Behavior | File | Examples |
|----------|------|----------|
| Safe (read-only) | `false_positives/git_safe.toml` | git status, git log, git diff |
| Safe (create) | `false_positives/git_safe.toml` | git checkout -b, git branch new |
| Destructive | `true_positives/git_destructive.toml` | git reset --hard, git clean -fd |

### Category: Filesystem Commands
| Behavior | File | Examples |
|----------|------|----------|
| rm in temp dirs | `false_positives/rm_safe.toml` | rm -rf /tmp/*, rm -rf $TMPDIR/* |
| rm elsewhere | `true_positives/rm_destructive.toml` | rm -rf /, rm -rf ~, rm -rf * |
| Non-recursive | `false_positives/rm_safe.toml` | rm file.txt, rm -f file.txt |

### Category: Command Prefixes & Wrappers
| Behavior | File | Examples |
|----------|------|----------|
| sudo prefix | `bypass_attempts/wrappers.toml` | sudo git reset --hard |
| env prefix | `bypass_attempts/wrappers.toml` | env git reset --hard |
| command prefix | `bypass_attempts/wrappers.toml` | command git reset --hard |
| time/nohup | `bypass_attempts/wrappers.toml` | time rm -rf /, nohup git reset |
| backslash escape | `bypass_attempts/obfuscation.toml` | \git reset --hard |
| full path | `bypass_attempts/obfuscation.toml` | /usr/bin/git reset --hard |

### Category: Heredocs & Inline Scripts
| Behavior | File | Examples |
|----------|------|----------|
| python -c | `bypass_attempts/heredoc_inline.toml` | python -c "import shutil; shutil.rmtree(...)" |
| bash -c | `bypass_attempts/heredoc_inline.toml` | bash -c 'rm -rf /' |
| node -e | `bypass_attempts/heredoc_inline.toml` | node -e "require('fs').rmSync(...)" |
| heredocs | `bypass_attempts/heredoc_inline.toml` | cat <<EOF\nrm -rf\nEOF |
| eval | `bypass_attempts/heredoc_inline.toml` | eval 'rm -rf /' |
| pipe to shell | `bypass_attempts/heredoc_inline.toml` | echo 'rm -rf' \| bash |

### Category: False Positives (Keyword Substring)
| Behavior | File | Examples |
|----------|------|----------|
| Substring git | `false_positives/substring_safe.toml` | digit, legitimate, fugitive |
| Substring rm | `false_positives/substring_safe.toml` | form, normal, terminal |
| In arguments | `false_positives/substring_safe.toml` | grep 'git reset' file |
| In commit msg | `false_positives/substring_safe.toml` | git commit -m 'fix rm behavior' |

### Category: Non-Execution Commands
| Behavior | File | Examples |
|----------|------|----------|
| command -v/-V | `false_positives/non_execution.toml` | command -v git |
| which/whereis | `false_positives/non_execution.toml` | which rm, whereis git |
| type | `false_positives/non_execution.toml` | type -t git |
| --version/--help | `false_positives/non_execution.toml` | git --version, rm --help |

### Category: Multi-Segment Commands
| Behavior | File | Examples |
|----------|------|----------|
| Pipes | `edge_cases/multi_segment.toml` | echo y \| rm -rf |
| AND chains | `edge_cases/multi_segment.toml` | ls && git reset --hard |
| OR chains | `edge_cases/multi_segment.toml` | test -f x \|\| rm -rf / |
| Semicolons | `edge_cases/multi_segment.toml` | echo; git reset --hard |
| Subshells | `edge_cases/multi_segment.toml` | (git reset --hard) |
| $()/backticks | `edge_cases/multi_segment.toml` | $(git reset --hard) |

### Category: Quoting Variations
| Behavior | File | Examples |
|----------|------|----------|
| Single quotes | `edge_cases/quoting.toml` | echo 'rm -rf' (safe, data) |
| Double quotes | `edge_cases/quoting.toml` | echo "git reset" (safe, data) |
| Escapes | `edge_cases/quoting.toml` | \git reset (blocked) |
| Mixed | `edge_cases/quoting.toml` | python -c "print('x')" |

## Non-Negotiable Behavior Invariants

These invariants must never change without an explicit design review:

### 1. Pack Evaluation Order
- Packs are evaluated in **deterministic tier order** (safe packs first, then by tier).
- Within a tier, packs are ordered **lexicographically by pack_id**.
- This ensures reproducible attribution (same input -> same pack/pattern match).

### 2. Safe-Before-Destructive Pattern Order
- For any command, **all safe patterns** across all enabled packs are checked first.
- Only if no safe pattern matches are **destructive patterns** checked.


### 3. Allowlist Bypass Scope
- Allowlists only bypass the **decision** (deny -> allow), not parsing/normalization.
- Allowlist matches are logged with `allowlist_override` field.
- Allowlist lookup happens **after** pattern matching, not before.

### 4. Fail-Open Semantics
- On **budget exhaustion**: allow (return early with `skipped_due_to_budget`).
- On **heredoc parse error**: allow (with warning log).
- On **heredoc timeout**: allow (with warning log).
- On **JSON parse error** (hook mode): allow (with warning log).
- **Never block due to internal errors.**

### 5. Word-Boundary Keyword Gating
- Keywords are matched at **word boundaries**, not substrings.
- `digit` does NOT trigger `git` keyword gate.
- `terminal` does NOT trigger `rm` keyword gate.
- Implemented via context classification in `SpanKind`.

### 6. Wrapper Stripping Behavior
- Known prefixes are stripped **before** pattern matching:
  - `sudo`, `env`, `command`, `builtin`, `exec`, `nohup`, `nice`, `time`
  - Full paths: `/usr/bin/git` -> `git`, `/bin/rm` -> `rm`
  - Backslash escapes: `\git` -> `git`
- Stripping is **deterministic** and happens in fixed order.
- Unknown prefixes are NOT stripped (conservative default).

### 7. Inline Code as Executable Context
- Heredocs (`<<EOF`) are parsed and bodies checked for destructive patterns.
- Inline execution (`python -c`, `bash -c`, `node -e`, etc.) bodies are checked.
- `eval 'cmd'` arguments are checked.
- Piped execution (`echo cmd | bash`) is checked.
- `SpanKind::InlineCode` and `SpanKind::HeredocBody` require pattern checks.

## Known Detection Gaps

The following cases are **not currently detected** but arguably should be.
They are commented out in the corpus files with `# NOTE:` markers.

### Flag Separation

These patterns use separated flags which current patterns don't handle:

- `rm -r -f /path` - Flags separated by space (only `-rf` combined works)
- `git clean -d -f` - Flags separated (only `-fd` combined works)

### Missing Patterns

These dangerous operations don't have patterns yet:

- `git checkout -f` / `git checkout --force` - Overwrites local changes
- `git checkout HEAD -- .` - Can overwrite working tree

### Partial Coverage

These have patterns but edge cases may slip through:

- `git push --force-with-lease` - Less destructive than `--force` but still risky
- `chmod -R 777` - Dangerous but not as immediately destructive as rm

## CI Integration

The corpus tests run as part of the standard test suite:

```bash
# Run just corpus tests
cargo test --test regression_corpus

# Run with verbose output
cargo test --test regression_corpus -- --nocapture
```

## Adding Regression Tests

When a bypass is found or a false positive is reported:

1. Add the command to the appropriate corpus file
2. If it's a gap, comment it out with `# NOTE:` and add to this README
3. Fix the pattern (if appropriate)
4. Uncomment the test case once the fix is verified
