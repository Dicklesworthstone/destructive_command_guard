# GitHub Actions Extractor v1 Syntax Coverage

> Specification for `dcg scan` GitHub Actions workflow extractor. Version 1.0.
>
> This document defines the syntax coverage for the first-pass GitHub Actions extractor,
> ensuring explicit scope and serving as a test checklist for implementation.

---

## Overview

The GitHub Actions extractor analyzes workflow files to extract shell commands from
`run:` blocks within `steps:` arrays for security scanning. It operates conservatively:
**prefer silence over false positives**.

**Extractor ID:**
- `github_actions.steps.run` — Shell commands in `run:` steps

---

## File Detection

### Supported File Patterns

| Pattern | Example | Notes |
|---------|---------|-------|
| `.github/workflows/*.yml` | `.github/workflows/ci.yml` | Primary pattern |
| `.github/workflows/*.yaml` | `.github/workflows/deploy.yaml` | Alternate extension |
| `.github/workflows/**/*.yml` | `.github/workflows/sub/ci.yml` | Nested directories |

**Requirements:**
1. Path must contain `.github/workflows/` directory structure
2. File extension must be `.yml` or `.yaml` (case-insensitive)

### Not Matched

| Pattern | Reason |
|---------|--------|
| `workflows/ci.yml` | Missing `.github/` parent |
| `.github/workflow/ci.yml` | Wrong directory name (singular) |
| `.github/workflows/ci.json` | Wrong extension |
| `action.yml` | Composite action file (different structure) |
| `.github/actions/my-action/action.yml` | Composite action |

---

## GitHub Actions Workflow Structure

For context, a workflow file structure:

```yaml
name: CI
on: [push, pull_request]    # Triggers (not extracted)

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4       # uses: (not extracted)
      - name: Build                      # name: (not extracted)
        run: npm run build               # run: (EXTRACTED)
      - run: |                           # Block scalar (EXTRACTED)
          npm test
          npm run lint
```

**Key insight:** Only `run:` values within `steps:` arrays are extracted as shell commands.

---

## Supported Run Block Forms

### 1. Single-Line Run (Flow Scalar)

**Syntax:** `run: <command>`

```yaml
steps:
  - run: echo "Hello, World!"
  - run: npm install
  - run: git status
```

**Behavior:**
- Extracts the command text after `run:`
- Handles YAML quoting (double, single, unquoted)
- Strips leading/trailing whitespace

**Test Cases:**
- [x] `run: echo hello` → extracts `echo hello`
- [x] `run: "echo \"quoted\""` → extracts `echo "quoted"` (escape handling)
- [x] `run: 'rm -rf ./build'` → extracts `rm -rf ./build` (single quotes)
- [x] `- run: cmd` (list item with run) → extracts `cmd`

### 2. Block Scalar Run (Literal Block `|`)

**Syntax:** `run: |` followed by indented content

```yaml
steps:
  - run: |
      echo "First line"
      echo "Second line"
      npm run build
```

**Behavior:**
- Recognizes `|` (literal block scalar indicator)
- Captures all indented lines below as shell script
- Preserves newlines between commands
- Uses shell script extractor for command parsing

**Test Cases:**
- [x] Multi-line literal block extracts all commands
- [x] Comments within block handled by shell extractor
- [x] Empty lines within block preserved
- [x] Block ends when indentation returns to run: level

### 3. Block Scalar Run (Folded Block `>`)

**Syntax:** `run: >` followed by indented content

```yaml
steps:
  - run: >
      echo "This is a very long command
      that spans multiple lines
      and gets folded into one"
```

**Behavior:**
- Recognizes `>` (folded block scalar indicator)
- Newlines converted to spaces (standard YAML folding)
- Processes as single long command

**Test Cases:**
- [x] Folded block with `>` recognized
- [x] Line folding applied correctly

### 4. Quoted Scalars

**Syntax:** `run: "command"` or `run: 'command'`

```yaml
steps:
  - run: "echo \"nested quotes\""
  - run: 'single quoted: no escapes except '''
```

**Behavior:**
- Double quotes: handle `\n`, `\t`, `\"`, `\\` escapes
- Single quotes: only `''` escapes to single `'`
- Unquoted: used as-is after trimming

**Test Cases:**
- [x] Double-quoted with `\n` → newline in command
- [x] Double-quoted with `\"` → literal double quote
- [x] Single-quoted with `''` → single quote
- [x] Unquoted value extracted directly

---

## Context-Aware Extraction

### Steps Array Detection

The extractor tracks the `steps:` context:

```yaml
jobs:
  test:
    steps:           # <-- Enter steps context
      - run: cmd1    # Extracted
      - run: cmd2    # Extracted
    outputs:         # <-- Exit steps context
      result: ...
```

**Behavior:**
- Only `run:` within active `steps:` blocks are extracted
- `run:` at document root or outside `steps:` is ignored
- Indentation tracking determines context boundaries

### Skipped Blocks

Certain step properties are explicitly skipped:

| Property | Reason |
|----------|--------|
| `env:` | Environment variables (data, not commands) |
| `with:` | Action inputs (data, not commands) |
| `secrets:` | Sensitive data (never extract) |

```yaml
steps:
  - run: actual-command      # Extracted
    env:
      FOO: "rm -rf /"        # Skipped (data context)
    with:
      script: "rm -rf /"     # Skipped (action input)
```

**Test Cases:**
- [x] `env:` block values not extracted
- [x] `with:` block values not extracted
- [x] `secrets:` block values not extracted

---

## Lines Not Extracted

### Step Properties (Not Commands)

| Property | Example | Reason |
|----------|---------|--------|
| `name:` | `name: "rm -rf /"` | Display name, not command |
| `uses:` | `uses: actions/checkout@v4` | Action reference |
| `id:` | `id: build-step` | Step identifier |
| `if:` | `if: github.event_name == 'push'` | Condition expression |
| `working-directory:` | `working-directory: ./app` | Directory path |
| `continue-on-error:` | `continue-on-error: true` | Boolean flag |
| `timeout-minutes:` | `timeout-minutes: 10` | Numeric setting |

### Workflow Metadata

| Section | Reason |
|---------|--------|
| `name:` (workflow) | Display name |
| `on:` | Trigger configuration |
| `permissions:` | Permission settings |
| `concurrency:` | Concurrency settings |
| `defaults:` | Default settings |
| `env:` (workflow/job level) | Environment variables |

---

## Shell Override Handling

### v1 Behavior: Shell Agnostic

GitHub Actions supports `shell:` to specify command interpreter:

```yaml
steps:
  - run: Write-Host "Hello"
    shell: pwsh
  - run: python -c "print('hi')"
    shell: python
```

**Current Behavior:** The `shell:` property is NOT parsed. All `run:` blocks
are assumed to be shell (bash) commands.

**Implications:**
- PowerShell scripts extracted as if they were bash
- Python inline scripts extracted as shell commands
- May produce false positives for non-bash shells

**Test Cases:**
- [x] `run:` with `shell: bash` extracted normally
- [x] `run:` with `shell: pwsh` still extracted (v1 limitation)
- [x] `run:` with `shell: python` still extracted (v1 limitation)

---

## Unsupported Constructs (v1 Limitations)

The following are known limitations in v1. They may produce unexpected behavior
and should be addressed in future versions.

### 1. Reusable Workflows (`workflow_call`)

**Not Supported:**

```yaml
# .github/workflows/reusable.yml
on:
  workflow_call:
    inputs:
      command:
        type: string

jobs:
  build:
    steps:
      - run: ${{ inputs.command }}
```

**Current Behavior:** Template expressions (`${{ }}`) extracted literally.

**Impact:** Dynamic command values from workflow inputs won't be expanded.

### 2. Composite Actions

**Not Supported:**

```yaml
# action.yml (composite action)
runs:
  using: composite
  steps:
    - run: dangerous-command
      shell: bash
```

**Current Behavior:** Files named `action.yml` not matched by file detection.

**Impact:** Commands in composite actions not scanned.

### 3. Expression Substitution

**Not Supported:**

```yaml
steps:
  - run: ${{ github.event.inputs.command }}
  - run: echo "${{ secrets.SCRIPT }}"
```

**Current Behavior:** Expressions extracted literally as `${{ ... }}`.

**Impact:** Commands from inputs, secrets, or context not expanded.

### 4. Matrix Strategies

**Partially Supported:**

```yaml
jobs:
  test:
    strategy:
      matrix:
        cmd: ['cmd1', 'cmd2']
    steps:
      - run: ${{ matrix.cmd }}
```

**Current Behavior:** `run: ${{ matrix.cmd }}` extracted literally.

**Impact:** Matrix-expanded commands not individually scanned.

### 5. Shell Override Interpretation

**Not Supported:**

```yaml
steps:
  - run: |
      import os
      os.remove('/tmp/file')
    shell: python
```

**Current Behavior:** Python code extracted and scanned as bash.

**Impact:** Python-specific patterns (like `os.remove`) not matched by bash patterns.

### 6. Conditional Run Blocks

**Partially Supported:**

```yaml
steps:
  - run: dangerous-command
    if: github.ref == 'refs/heads/main'
```

**Current Behavior:** Command extracted regardless of `if:` condition.

**Impact:** Conditionally-skipped commands still flagged.

### 7. Multi-Job Workflows

**Supported:**

```yaml
jobs:
  job1:
    steps:
      - run: cmd1
  job2:
    steps:
      - run: cmd2
```

**Current Behavior:** All jobs' steps scanned.

**Note:** This is working correctly in v1.

---

## Implementation Details

### Steps Context Tracking

```
1. Find `steps:` key at job level
2. Track indentation of `steps:` line
3. Within steps block:
   - Look for list items (`- `) at appropriate indent
   - Check for `run:` key in each item
   - Skip `env:`, `with:`, `secrets:` sub-blocks
4. Exit steps context when indentation decreases
```

### Block Scalar Extraction

For `run: |` or `run: >`:

1. Note the indent level of `run:` line
2. Collect all following lines with greater indentation
3. Pass block to shell script extractor
4. Shell extractor handles comment stripping, etc.

### YAML Scalar Unquoting

```
Input: run: "echo \"hello\""
After unquoting: echo "hello"

Input: run: 'echo ''quoted'''
After unquoting: echo 'quoted'

Input: run: echo plain
After unquoting: echo plain
```

---

## Test Checklist

Use this checklist to verify implementation correctness:

### Path Detection
- [ ] `.github/workflows/ci.yml` matches
- [ ] `.github/workflows/ci.yaml` matches
- [ ] `.github/workflows/sub/ci.yml` matches (nested)
- [ ] `.GITHUB/WORKFLOWS/CI.YML` matches (case-insensitive)
- [ ] `.github/workflows/ci.json` does NOT match
- [ ] `workflows/ci.yml` does NOT match (missing .github)
- [ ] `.github/workflow/ci.yml` does NOT match (singular)
- [ ] `action.yml` does NOT match

### Single-Line Run
- [ ] `run: echo hello` extracts command
- [ ] `run: "quoted command"` handles double quotes
- [ ] `run: 'single quoted'` handles single quotes
- [ ] `- run: cmd` (list item) works
- [ ] Inline comment after run value (if any)

### Block Scalar Run
- [ ] `run: |` literal block extracts all lines
- [ ] `run: >` folded block recognized
- [ ] Multi-line content joined correctly
- [ ] Block ends at appropriate indentation

### Context Awareness
- [ ] `run:` inside `steps:` extracted
- [ ] `run:` outside `steps:` NOT extracted
- [ ] Multiple jobs' steps all scanned
- [ ] `env:` block values skipped
- [ ] `with:` block values skipped
- [ ] `secrets:` block values skipped

### Non-Run Properties
- [ ] `name: "cmd"` NOT extracted
- [ ] `uses: action@v1` NOT extracted
- [ ] `if: condition` NOT extracted
- [ ] `id: step-id` NOT extracted

### Quoting
- [ ] Double quotes with escape sequences
- [ ] Single quotes with `''` escape
- [ ] Unquoted values work

### Edge Cases
- [ ] Empty workflow returns no commands
- [ ] Workflow with only `uses:` steps returns no commands
- [ ] Keyword filter limits extraction
- [ ] Comments in block scalar handled

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-16 | Initial specification |

---

## Related Tasks

- **Blocks:** `git_safety_guard-0t5u` (Implement GitHub Actions workflow extractor)
- **Blocks:** `git_safety_guard-5rbb.8` (Unit tests for GitHub Actions extractor)
- **Parent:** `git_safety_guard-5rbb` (Scan Mode Extractors for CI/DevOps Files)
