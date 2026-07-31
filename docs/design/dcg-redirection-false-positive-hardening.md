# DCG redirection false-positive hardening

Status: design gate; no evaluator or policy code changed yet
Branch: `fix/shell-redirection-false-positives`
Date: 2026-07-31

## Problem statement

DCG must distinguish shell syntax from inert command data without weakening its protection against truncation. The observed incidents came from four superficially similar strings that have different semantics:

1. a real redirect whose target variable was assigned a fixed `/tmp` path earlier in the same command;
2. `>` bytes inside quoted JavaScript, TypeScript, `find -printf`, JSX, SQL, and heredoc bodies;
3. Docker's `run --rm` container-lifecycle option, which is not host-file deletion and is not `docker rm`;
4. real redirects to an unbound/dynamic target, which must continue to require approval.

The safety objective is not “permit more `>`”. It is to recognize the actual shell redirect token, classify its actual target, and make denials explain the exact token and approval scope.

## Current evidence

The installed binary is DCG 0.6.7. Upstream `main` and release 0.7.8 already include issue #225's quote-aware redirect handling in `src/evaluator.rs` and `tests/repro_redirect_quoted_data.rs`. The evaluator now finds an unquoted output redirect before applying `core.filesystem` redirect rules. Release 0.7.8 allows the previously blocked `find ... -printf '%f -> %l\n'` form while still denying a genuine redirect to `/etc/passwd`.

A release-binary differential probe produced this matrix:

| Case | 0.6.7 | 0.7.8 | Desired |
|---|---|---|---|
| literal `> /tmp/gcp-multi-poll.log` | allow | allow | allow |
| quoted `find -printf '%f -> %l'` | deny | allow | allow |
| quoted Node/TypeScript arrow data | allow in minimized probe | allow | allow |
| `docker run --rm ...` | allow | allow | allow |
| fixed relative evidence log | allow | allow | allow |
| `> "$RUN_DIR/evidence.log"` with unresolved variable | deny | deny | deny |
| `> /etc/passwd` | deny | deny | deny |
| `log=/tmp/gcp-multi-poll.log; : > "$log"` | deny | deny | allow after literal assignment proof |

This narrows the remaining code defect: quote handling and Docker `run --rm` are already correct upstream; simple prior-assignment constant propagation is absent. The 0.7.8 denial correctly reports `matched_span`, but robot output does not yet render the matched token or normalized target as human-readable fields.

The local Cargo 1.75 toolchain cannot compile this Rust 2024 repository, which pins `nightly-2026-06-06`. Design evidence therefore uses the checksum-verified 0.7.8 release binary. Implementation must not begin until the pinned toolchain is available and the source tests can run.

## Owner and impact surface

The rule owner is `core.filesystem`, with pattern definitions in `src/packs/core/filesystem.rs`. Shell-syntax ownership is in `src/evaluator.rs`, primarily `first_unquoted_output_redirect`, `filesystem_redirection_matching_view`, and `evaluate_core_filesystem_pack`. Existing public output ownership is in `src/hook.rs` and the JSON schemas.

The first PR should remain inside evaluator semantics and regression tests. It must not change IoA, agent hooks, local allowlists, Docker pack severities, or the installed `/usr/local/bin/dcg`. Approval-record schema and hook-output schema changes are separate follow-ups because they have different persistence and compatibility risks.

## Proposed first PR: literal redirect-target resolution

Add a narrow POSIX-shell resolver for redirects whose target is exactly `$NAME`, `${NAME}`, `"$NAME"`, or `"${NAME}"`. It may resolve a value only when all of these are true:

- a preceding top-level segment in the same submitted command assigns `NAME` once;
- the assignment value is one literal shell word after quote removal;
- the value contains no parameter expansion, command/process substitution, glob, brace expansion, tilde-user expansion, backslash-obfuscated traversal, `eval`, or control operator;
- no intervening segment mutates, exports dynamically, unsets, or indirectly references the variable;
- the redirect has no concatenated dynamic prefix or suffix in the first slice.

The resolved target must then pass the same sensitive-path classification as a direct literal redirect. `/etc`, root/home/system targets remain denied. Relative literals and literal `/tmp` or `/var/tmp` paths retain the existing direct-literal policy; this PR must not invent a broader writable-path allowlist.

For a path that already exists, the resolver should fail closed when `symlink_metadata` reports a symlink or a non-regular file. For a missing target, inspect the nearest existing parent without following a final target component and reject a symlinked parent chain. On Unix, an existing target must be owned by the invoking user. These checks reduce obvious symlink substitution but cannot eliminate the time-of-check/time-of-use race created by the shell's later `O_TRUNC`; documentation must state that a private `0700` run directory is stronger than a shared `/tmp` basename.

If any proof is missing, preserve today's `redirect-truncate-dynamic-path` denial. Do not guess from variable names such as `LOG`, and do not add a blanket `/tmp` bypass.

## Denial diagnostics follow-up

A subsequent output-focused PR should expose, without changing allow/deny behavior:

- the exact redirect operator span;
- the exact raw target token span;
- a normalized target only when statically provable;
- the unresolved feature that forced denial, such as `parameter-expansion`, `command-substitution`, `glob`, or `symlink`;
- the narrow approval scope accepted by the current command.

`matched_span` already provides a source-map foundation. New fields require updates to `src/hook.rs`, JSON schemas, robot/Codex protocol tests, and redaction review. They should not be mixed into the constant-propagation PR.

## Approval semantics follow-up

Current allow-once records bind to exact raw command plus cwd and expire after 24 hours. That is safer than a global bypass but does not yet bind a normalized redirect path, agent session, or shorter operator-selected timebox.

A separate design is required for an approval tuple such as:

```text
command_hash + cwd_realpath + rule_id + normalized_target + agent/session + expires_at + single_use
```

Redemption must re-resolve cwd and target, re-run no-follow/type/owner checks, and refuse changed symlink or path identity. The existing 24-hour record format must not be silently reinterpreted. No global `DCG_BYPASS`, permanent broad allowlist, or rule disablement is part of this work.

## Docker boundary

`docker run --rm` is already allowed and covered by `tests/containers_pack_comprehensive.rs`. `docker rm -f`, `docker volume rm`, Compose volume removal, and host filesystem deletion remain separate destructive rules. Add the observed Node `-e` diagnostic form to the existing Docker allow regression corpus only if it reproduces against source HEAD; do not weaken `containers.docker:rm-force` to solve a command-string parsing bug.

## Regression matrix for implementation

The first PR's red tests belong beside the existing redirect regressions and must cover:

### Must allow

- `log=/tmp/gcp-multi-poll.log; : > "$log"`
- assignment using single quotes and redirect using `${log}`
- a fixed repository-relative evidence path assigned before use
- quoted JavaScript arrows, JSX strings, SQL comparison operators, and `find -printf '%f -> %l'`
- `docker run --rm ... -e '... => ...'`

### Must deny

- unbound `$log`
- assignment from `$(...)`, backticks, another variable, glob, `eval`, or escaped traversal
- reassignment between proof and redirect
- literal assignment to `/etc/passwd`, `$HOME`, root, or another sensitive path
- existing symlink target and symlinked parent
- non-regular target
- genuine redirect outside quotes, including the anti-bypass `"git">/dev/null reset --hard`
- `docker rm -f`, `docker volume rm`, and Compose volume deletion

### Evidence gates

- focused redirect and container tests red before implementation and green after;
- `cargo test --test repro_redirect_quoted_data` plus the new focused regression;
- `cargo test`;
- `cargo check --all-targets`;
- `cargo clippy --all-targets -- -D warnings`;
- `cargo fmt --check`;
- differential checks against the installed 0.6.7 binary and checksum-verified 0.7.8 release;
- `git diff --check` and a clean feature branch before PR creation.

## Non-goals

- modifying IoA code or its feature branches;
- replacing the shell with a full interpreter;
- proving arbitrary shell dataflow across functions, loops, subshells, sourced files, or `eval`;
- globally trusting `/tmp`;
- allowing Docker removal operations because `docker run --rm` is safe;
- installing an unreleased DCG build into `/usr/local/bin` before upstream review and local acceptance.
