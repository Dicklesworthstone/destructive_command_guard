# Standard Pack Task Requirements Template

Purpose: define the required sections for every pack task. Use this when
creating or validating pack work items.

## Required Sections

### 1. Scope (Required)
Brief description of what tool/CLI/API this pack protects.

### 2. Destructive Patterns (Required)
List ALL destructive patterns with:
- Exact command or pattern
- Clear explanation of why it is dangerous
- Example of data loss or damage it could cause

### 3. Safe Patterns (Required)
List safe patterns that should NOT be blocked:
- Read-only operations
- Status/info commands
- Dry-run/preview modes

### 4. Implementation Notes (Required)
- Parent category bead ID
- Keywords to trigger pack evaluation
- Special considerations (aliases, API endpoints, etc.)
- Known overlaps with other packs

### 5. Testing Requirements (Required)
Standard checklist for ALL packs:
- [ ] Unit tests in `src/packs/<category>/<pack>.rs`
- [ ] E2E tests in `scripts/e2e_tests/<pack>.txt`
- [ ] E2E runs use the shared harness (git_safety_guard-ksk.1.4) with `--verbose` JSON logging
- [ ] Test coverage >= 90%
- [ ] All destructive patterns have test cases
- [ ] All safe patterns have test cases
- [ ] Edge cases tested (quotes, special chars)
- [ ] Performance benchmark < 500us

### 6. Acceptance Criteria (Required)
Specific, measurable criteria:
- [ ] Pattern X blocked
- [ ] Pattern Y allowed
- [ ] Documentation updated
- [ ] Completion checklist passed

## Example Structure

```markdown
# [PACK] category.name - Tool Name Pack

## Scope
Implement pattern matching for ToolName CLI operations.

## Destructive Patterns
- `tool delete X` - Permanently deletes X
- `tool remove --force` - Force removes without confirmation

## Safe Patterns
- `tool list`, `tool show`
- `tool status`

## Implementation Notes
- Parent category: category.* (git_safety_guard-XXX)
- Keywords: tool
- Note: Consider --dry-run flag

## Testing Requirements
[Standard checklist as above]

## Acceptance Criteria
- [ ] Delete operations blocked
- [ ] List/show operations allowed
- [ ] Completion checklist passed
```

## Validation
Use [CHECKLIST] Pack Implementation Completion Validation (git_safety_guard-ltou)
when signing off pack work.
