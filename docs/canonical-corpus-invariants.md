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
- `mode` (deny/warn/log)
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

## Behavior Invariants (Must Never Change)

1) Pack ordering is deterministic and stable.
   - Packs are ordered by tier, then lexicographically by pack_id.
   - Tier ordering is fixed (safe, core, system, infrastructure, cloud,
     kubernetes, containers, database, package_managers, strict_git, cicd).

2) Safe-before-destructive evaluation is preserved.
   - All safe patterns across enabled packs are evaluated first.
   - Any safe match immediately allows the command.

3) Allowlist scope is precise.
   - A matched allowlist entry bypasses only the specific matched rule.
   - Allowlisting does not suppress evaluation of other packs/patterns.

4) Fail-open behavior is mandatory.
   - Hook input parse errors, oversized inputs, or exceeded deadlines must
     allow execution (no deny output).
   - Heredoc extraction/AST errors fail open by default unless strict
     settings explicitly override.

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
