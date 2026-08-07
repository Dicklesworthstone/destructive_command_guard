# Canonical Command Corpus and Invariants

This document defines the canonical command corpus and the behavior
invariants that MUST NOT change. The corpus is designed to be consumed
directly by golden tests and the shared e2e harness.

## Canonical Corpus Location and Format

File: `tests/corpus/canonical.toml`

Schema (version 1):

- `schema_version` (int)
- `[[case]]` entries with:
  - `id` (string, stable identifier)
  - `category` (string)
  - `input_kind` (`command` or `hook_json`)
  - `command` (string, required when `input_kind = "command"`)
  - `raw_input` (string, required when `input_kind = "hook_json"`)
  - `expected_decision` (`allow` or `deny`)
  - `expected_log` (inline table of expected log/assertion fields)

`expected_log` is the stable set of fields that golden/e2e harnesses
must validate when present:

- `decision` (allow/deny)
- `pack_id`
- `pattern_name`
- `rule_id` (pack_id:pattern_name)
- `mode` (deny/ask/warn/log)
- `source` (pack, heredoc_ast, config_override, legacy_pattern)
- `reason_contains` (substring match)

For allow cases, `expected_log` may contain only `decision`.

## Corpus Coverage Requirements

The canonical corpus MUST include, at minimum, these categories:

- git safe (status/log/checkout -b/restore --staged)
- git destructive (reset --hard, clean -fd, push --force)
- rm safe in temp dirs (/tmp, /var/tmp, $TMPDIR)
- rm destructive elsewhere
- wrapper prefixes: sudo, env, command
- quoted command words
- substring false positives (echo/grep/rg)
- heredoc + inline code triggers (python -c, bash -c, etc.)
- malformed JSON in hook mode (empty/invalid JSON/non-string command)

The corpus MUST include edge cases:

- multi-segment commands (pipes, &&, ||, ;)
- command substitution $(...) and backticks
- command -v/-V (query mode; non-execution)
- backslash-escaped command words (\git)
- inline -c/-e code with mixed quoting

## Cross-Pack Replay Corpus

Directory: `tests/corpus/cross_pack_fp/`
Runner: `tests/cross_pack_corpus.rs`

The canonical corpus above and the per-category regression corpus both evaluate
against the default-enabled pack set, which is platform-dependent and excludes
opt-in packs. The cross-pack corpus is the complement: every case is replayed
with **all** registry packs force-enabled (`PackRegistry::all_pack_ids`,
including `windows.*` on non-Windows hosts) across the `posix`, `ps`, `cmd` and
`unknown` dialects.

Its schema is the regression schema plus `issue`, `dialects`, `known_failing`,
`known_failing_reason` and `known_failing_dialects`. It MUST contain, for every
fixed false-positive issue with an in-tree repro, the exact reported shape — so
that a fix landed in one pack is re-asked of every other pack.

`known_failing` marks a false positive this suite has found and that the owning
pack has not yet fixed. It is a bug record, never a licence to soften the case:
the recorded shape stays verbatim, the tolerance is scoped to the failing
dialects, and the suite fails if a marked case starts passing.

## Behavior Invariants (Must Never Change)

1) Pack ordering is deterministic and stable.
   - Packs are ordered by tier, then lexicographically by pack_id.
   - Tier ordering is fixed. `PackRegistry::pack_tier` in `src/packs/mod.rs` is
     the source of truth; as of this writing it runs safe, core/storage/remote,
     system, infrastructure, apigateway/cdn/cloud/dns/loadbalancer/platform,
     kubernetes, containers, backup/database/messaging/search, package_managers,
     strict_git, cicd/email/featureflags/secrets/monitoring/payment, windows,
     careful_company_running_windows, then unknown.

2) Safe-before-destructive evaluation is preserved.
   - Each enabled pack evaluates its safe patterns before its destructive
     patterns.
   - A safe match suppresses only that owning pack. It never prevents another
     enabled pack from enforcing a different security boundary.

3) Allowlist scope is precise.
   - A matched allowlist entry bypasses only the specific matched rule.
   - Allowlisting does not suppress evaluation of other packs/patterns.

4) Bounded-failure behavior is mandatory.
   - Malformed or oversized raw hook envelopes allow with an audit warning by
     default; `general.fail_closed = true` denies attacker-controlled parse
     failures. Transient stdin I/O errors always fail open.
   - An oversized extracted command or an exhausted evaluation deadline is
     indeterminate, never allow: review-capable clients ask and other clients
     block.
   - Heredoc extraction/AST errors run the bounded fallback by default unless
     strict settings explicitly require a block.

5) Word-boundary keyword gating is stable.
   - Quick-reject uses keyword detection over executable spans.
   - Substring false positives (e.g., "digit", ".gitignore", quoted data)
     must not trigger pack evaluation.

6) Hook output contract is stable.
   - Allow: no stdout JSON.
   - Deny: JSON to stdout and a warning box to stderr.
   - Warn/log modes: no stdout JSON deny.

Any change that violates these invariants requires an explicit design
review and a corpus update with documented rationale.
