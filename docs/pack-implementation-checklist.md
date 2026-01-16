# Pack Implementation Checklist

Use this checklist when adding a new pack to `destructive_command_guard`.

## 1. Analysis
- [ ] Identify the tool (e.g., `kubectl`, `aws`).
- [ ] List destructive commands (e.g., `delete`, `terminate`).
- [ ] List safe commands that might look similar.
- [ ] Identify the "quick reject" keywords (e.g., `kubectl`).

## 2. Implementation
- [ ] Create `src/packs/<category>/<tool>.rs`.
- [ ] Define the `Pack` struct with ID, name, description.
- [ ] Add keywords.
- [ ] Implement `destructive_patterns` (regex + reason).
- [ ] Implement `safe_patterns` (if needed for whitelist).

## 2a. Explanation Style Guide (for destructive patterns)

Explanations are optional but recommended for user-facing clarity. When present:

- Keep it short: 2-4 sentences, ~400 chars or less.
- Stay neutral and factual; avoid scaremongering or moralizing.
- Structure:
  1) What the command does.
  2) Why that is risky (data loss, downtime, security blast radius).
  3) Safer alternative and/or preview command.
- Use concrete nouns and commands (e.g., `git reset --soft`, `--dry-run`).
- Avoid absolutes unless accurate (prefer "often" or "can").
- Match the existing `reason` but add real detail (not repetition).

## 3. Unit Testing
- [ ] Copy `src/packs/test_template.rs` content to `src/packs/<category>/<tool>.rs` (mod tests).
- [ ] Update `test_pack_creation` to use `validate_pack`.
- [ ] Implement tests for all destructive patterns.
- [ ] Implement tests for safe patterns.
- [ ] Verify `cargo test packs::<category>::<tool>` passes.

## 4. E2E & Integration Testing
- [ ] Add known destructive commands to `tests/fixtures/destructive_commands.yaml`.
- [ ] Create `scripts/test_pack_<tool>.sh` using `scripts/templates/test_pack.sh`.
- [ ] Run the E2E script: `./scripts/test_pack_<tool>.sh --verbose`.
- [ ] Verify no regressions: `./scripts/e2e_test.sh`.

## 5. Registration
- [ ] Add module to `src/packs/<category>/mod.rs`.
- [ ] Register pack in `src/packs/mod.rs` (PACK_ENTRIES).

## 6. Documentation
- [ ] Add to `docs/packs/README.md` (or index).
- [ ] Verify `cargo run -- pack list` shows the new pack.
- [ ] (Optional) Add specific usage examples to docs.
