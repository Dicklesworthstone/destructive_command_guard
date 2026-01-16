# Dockerfile Extractor v1 Syntax Coverage

> Specification for `dcg scan` Dockerfile extractor. Version 1.0.
>
> This document defines the syntax coverage for the first-pass Dockerfile extractor,
> ensuring explicit scope and serving as a test checklist for implementation.

---

## Overview

The Dockerfile extractor analyzes `RUN` instructions in Dockerfiles to extract
executable shell commands for security scanning. It operates conservatively:
**prefer silence over false positives**.

**Extractor IDs:**
- `dockerfile.run` — Shell-form RUN commands
- `dockerfile.run.exec` — Exec-form (JSON array) RUN commands

---

## File Detection

### Supported File Patterns

| Pattern | Example | Notes |
|---------|---------|-------|
| `Dockerfile` | `Dockerfile` | Case-insensitive |
| `*.dockerfile` | `app.dockerfile`, `build.dockerfile` | Suffix match |
| `Dockerfile.*` | `Dockerfile.dev`, `Dockerfile.prod` | Prefix match |

### Not Matched

| Pattern | Reason |
|---------|--------|
| `Dockerfile-backup` | Hyphen separator not recognized |
| `my-dockerfile` | Must end with `.dockerfile` suffix |
| `Containerfile` | Podman format (future work) |

---

## Supported RUN Forms

### 1. Shell Form (Single-Line)

**Syntax:** `RUN <command>`

```dockerfile
RUN apt-get update
RUN rm -rf /tmp/cache
RUN pip install requests
```

**Behavior:**
- Extracts the command portion after `RUN ` (space or tab delimiter)
- Strips trailing inline comments (e.g., `# comment`)
- Preserves internal command structure

**Test Cases:**
- [x] `RUN apt-get update` → extracts `apt-get update`
- [x] `RUN\tapt-get update` → extracts `apt-get update` (tab delimiter)
- [x] `RUN rm -rf ./tmp # cleanup` → extracts `rm -rf ./tmp`
- [x] `RUN echo "# not a comment"` → extracts `echo "# not a comment"`

### 2. Shell Form (Multiline with Backslash)

**Syntax:** `RUN <command> \` (continuation)

```dockerfile
RUN apt-get update \
    && apt-get install -y \
        curl \
        wget \
    && rm -rf /var/lib/apt/lists/*
```

**Behavior:**
- Joins lines ending with `\` (backslash continuation)
- Inserts single space between joined segments
- Respects limits: MAX_CONTINUATION_LINES=50, MAX_JOINED_CHARS=32KB
- Reports line number of first line (where RUN appears)

**Test Cases:**
- [x] Two-line continuation joins correctly with space
- [x] Deep nesting (10+ lines) joins correctly
- [x] Continuation within string quotes preserved
- [x] Bare `RUN` followed by continuation-only line

### 3. Exec Form (JSON Array)

**Syntax:** `RUN ["executable", "param1", "param2"]`

```dockerfile
RUN ["apt-get", "update"]
RUN ["sh", "-c", "echo hello && rm -rf /tmp"]
RUN ["/bin/bash", "-c", "complex command here"]
```

**Behavior:**
- Parses JSON array using `serde_json`
- Joins array elements with spaces for scanning
- Invalid JSON silently skipped (conservative)
- Extractor ID: `dockerfile.run.exec`

**Test Cases:**
- [x] `RUN ["apt-get", "update"]` → extracts `apt-get update`
- [x] `RUN ["sh", "-c", "rm -rf /tmp"]` → extracts `sh -c rm -rf /tmp`
- [x] Exec form with continuation across lines
- [x] Malformed JSON (missing bracket) → skipped, no error

### 4. Exec Form with Continuation

**Syntax:** JSON array spanning multiple lines

```dockerfile
RUN ["sh", "-c", \
  "rm -rf /tmp"]
```

**Behavior:**
- Joins continuation lines before JSON parsing
- Handles whitespace within JSON strings

**Test Cases:**
- [x] Split JSON array joins and parses correctly
- [x] Whitespace within quoted strings preserved

---

## Quoting and Escape Handling

### Shell Inline Comments

| Input | Extracted |
|-------|-----------|
| `rm -rf /tmp # cleanup` | `rm -rf /tmp` |
| `echo "# not a comment"` | `echo "# not a comment"` |
| `echo '# also not'` | `echo '# also not'` |

**Behavior:**
- `#` outside quotes treated as comment start
- Single and double quotes protect `#` characters
- Comment stripping uses quote-aware scanner

### Quoting Preservation

| Input | Extracted |
|-------|-----------|
| `echo "hello world"` | `echo "hello world"` (quotes preserved) |
| `bash -c 'rm -rf /tmp'` | `bash -c 'rm -rf /tmp'` |
| `FOO="value" cmd` | `FOO="value" cmd` |

**Behavior:**
- Quotes are preserved in extracted command
- Internal quote parsing for comment detection only
- No shell expansion or variable substitution

### Backslash Continuations

| Input | Extracted |
|-------|-----------|
| `apt-get update \`<br>`&& apt-get install` | `apt-get update && apt-get install` |
| `echo "line1\`<br>`line2"` | `echo "line1 line2"` |

**Behavior:**
- Trailing `\` triggers line continuation
- Joined with single space
- Backslash within quotes: **not currently special-cased** (v1 limitation)

---

## Instructions Not Extracted

The v1 extractor only processes `RUN` instructions. The following are explicitly
**not extracted** and will not trigger security scan matches:

### Dockerfile Instructions (Skipped)

| Instruction | Reason |
|-------------|--------|
| `FROM` | Base image, not executable |
| `COPY` | File copy, not shell command |
| `ADD` | File/URL add, not shell command |
| `ENV` | Environment variable, data context |
| `ARG` | Build argument, data context |
| `LABEL` | Metadata, not executable |
| `EXPOSE` | Port declaration, not executable |
| `WORKDIR` | Directory change, not shell command |
| `USER` | User switch, not shell command |
| `VOLUME` | Volume mount, not executable |
| `HEALTHCHECK` | Future work: contains CMD |
| `CMD` | Future work: container entry point |
| `ENTRYPOINT` | Future work: container entry point |
| `SHELL` | Future work: affects RUN behavior |
| `ONBUILD` | Future work: trigger instruction |
| `STOPSIGNAL` | Signal, not executable |
| `MAINTAINER` | Deprecated metadata |

### Comments

```dockerfile
# This is a comment, never extracted
# rm -rf / is safe in a comment
```

**Test Cases:**
- [x] `# rm -rf /` → not extracted
- [x] Comment after RUN stripped correctly
- [x] Inline comment with # in quotes preserved

---

## Unsupported Constructs (v1 Limitations)

The following are known limitations in v1. They may produce unexpected behavior
and should be addressed in future versions.

### 1. Heredocs in RUN (Docker BuildKit)

**Not Supported:**

```dockerfile
RUN <<EOF
apt-get update
apt-get install -y curl
rm -rf /tmp/cache
EOF
```

**Current Behavior:** Heredoc marker not recognized; subsequent lines not joined.

**Workaround:** Use continuation syntax or split into multiple RUN commands.

### 2. Variable Expansion

**Not Supported:**

```dockerfile
ARG CLEANUP_CMD="rm -rf /tmp"
RUN $CLEANUP_CMD
```

**Current Behavior:** Extracts literal `$CLEANUP_CMD`, not the expanded value.

**Impact:** Commands hidden behind variables won't trigger pattern matches.

### 3. SHELL Instruction Effects

**Not Supported:**

```dockerfile
SHELL ["/bin/bash", "-c"]
RUN echo hello
```

**Current Behavior:** SHELL instruction ignored; RUN parsing unchanged.

**Impact:** Non-default shells may affect command interpretation.

### 4. Escape Directive

**Not Supported:**

```dockerfile
# escape=`
RUN echo hello `
    && echo world
```

**Current Behavior:** Backtick escape not recognized; only `\` continuation.

**Impact:** Windows-style Dockerfiles with backtick escapes may not parse correctly.

### 5. Multi-Stage Build Awareness

**Limited:**

```dockerfile
FROM builder as build
RUN dangerous-command-here

FROM runtime
# No dangerous RUN here
```

**Current Behavior:** All stages scanned equally; no stage filtering.

**Impact:** Build-only dangerous commands flagged same as production images.

### 6. Nested Quotes in Exec Form

**Limited:**

```dockerfile
RUN ["sh", "-c", "echo \"nested quotes\" && rm -rf /tmp"]
```

**Current Behavior:** JSON parsing handles standard escapes; complex nesting untested.

---

## Implementation Limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_CONTINUATION_LINES` | 50 | Limit runaway continuation |
| `MAX_JOINED_CHARS` | 32,768 | Limit memory for joined command |

**Behavior when exceeded:**
- Stop joining at limit
- Return partial command up to limit
- No error; fail-open design

---

## Test Checklist

Use this checklist to verify implementation correctness:

### Path Detection
- [ ] `Dockerfile` matches (lowercase)
- [ ] `dockerfile` matches (case-insensitive)
- [ ] `Dockerfile.dev` matches (prefix variant)
- [ ] `app.dockerfile` matches (suffix variant)
- [ ] `Dockerfile-backup` does NOT match
- [ ] `Containerfile` does NOT match

### Shell Form
- [ ] Single-line RUN extracts command
- [ ] Tab delimiter (`RUN\tcmd`) works
- [ ] Inline comment stripped
- [ ] Comment with # in quotes preserved
- [ ] Empty RUN (just whitespace) skipped

### Continuation
- [ ] Two-line continuation joins
- [ ] Multi-line (5+) continuation joins
- [ ] Continuation limit (50 lines) stops
- [ ] Character limit (32KB) stops

### Exec Form
- [ ] Simple JSON array extracts
- [ ] JSON with spaces in args extracts
- [ ] Malformed JSON skipped silently
- [ ] Exec form with continuation

### Non-RUN Instructions
- [ ] FROM not extracted
- [ ] COPY not extracted
- [ ] ENV value not extracted (even if looks like command)
- [ ] LABEL not extracted
- [ ] Comments not extracted

### Edge Cases
- [ ] Empty file returns no commands
- [ ] File with only comments returns no commands
- [ ] Keyword filter: only extracts if keyword present
- [ ] Unicode in commands preserved

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-16 | Initial specification |

---

## Related Tasks

- **Blocks:** `git_safety_guard-0fv0` (Implement Dockerfile RUN command extractor)
- **Blocks:** `git_safety_guard-5rbb.6` (Unit tests for Dockerfile extractor)
- **Parent:** `git_safety_guard-5rbb` (Scan Mode Extractors for CI/DevOps Files)
