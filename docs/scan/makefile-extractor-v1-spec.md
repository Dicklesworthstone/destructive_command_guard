# Makefile Extractor v1 Syntax Coverage

> Specification for `dcg scan` Makefile extractor. Version 1.0.
>
> This document defines the syntax coverage for the first-pass Makefile extractor,
> ensuring explicit scope and serving as a test checklist for implementation.

---

## Overview

The Makefile extractor analyzes recipe lines (shell commands) in Makefiles to extract
executable commands for security scanning. It operates conservatively:
**prefer silence over false positives**.

**Extractor ID:**
- `makefile.recipe` — Recipe line commands

---

## File Detection

### Supported File Patterns

| Pattern | Example | Notes |
|---------|---------|-------|
| `Makefile` | `Makefile` | Case-insensitive |
| `makefile` | `makefile` | Lowercase variant |
| `MAKEFILE` | `MAKEFILE` | All-caps variant |

### Not Matched

| Pattern | Reason |
|---------|--------|
| `Makefile.backup` | Not exact filename |
| `build.mk` | `.mk` include files not yet supported |
| `GNUmakefile` | GNU variant not yet supported |
| `makefile.in` | Autoconf templates not supported |
| `Makefile.am` | Automake files not supported |

---

## Makefile Syntax Primer

For context, a Makefile consists of:

```makefile
# Comment
VARIABLE = value         # Variable assignment

target: prerequisites    # Rule definition
	command1             # Recipe line (starts with TAB)
	command2             # Another recipe line
```

**Key insight:** Only lines starting with a **literal TAB character** are recipe lines
containing shell commands to execute.

---

## Supported Recipe Formats

### 1. Simple Recipe Lines

**Syntax:** TAB followed by shell command

```makefile
all:
	echo "Building..."
	rm -rf ./build
	mkdir build
```

**Behavior:**
- Lines starting with `\t` (TAB character) are recipe lines
- Command is everything after the leading TAB
- Comments handled by shell script extractor (see below)

**Test Cases:**
- [x] `\tgit status` → extracts `git status`
- [x] `\trm -rf ./build` → extracts `rm -rf ./build`
- [x] Multiple recipe lines in same target extracted individually

### 2. Recipe Block Extraction

**Syntax:** Consecutive TAB-prefixed lines form a recipe block

```makefile
clean:
	rm -rf build
	rm -rf dist
	echo "Clean complete"

test:
	cargo test
```

**Behavior:**
- Recipe lines are grouped by consecutive TAB-prefixed lines
- Each target's recipe is processed as a shell script block
- Empty lines within recipes do NOT break the block (if continuation)
- Lines without TAB prefix (except continuations) end the block

**Test Cases:**
- [x] Consecutive recipe lines grouped correctly
- [x] Target boundary ends recipe block
- [x] Empty line without continuation ends block

### 3. Backslash Line Continuation

**Syntax:** Recipe line ending with `\` continues to next line

```makefile
build:
	gcc -Wall -Werror \
	    -O2 -g \
	    -o main main.c

deploy:
	rsync -avz \
		--exclude node_modules \
		--exclude .git \
		./ server:/app/
```

**Behavior:**
- Line ending with `\` (backslash) continues to next line
- Continuation line does NOT require leading TAB
- Lines are joined for command extraction
- Backslash and newline replaced with joining

**Test Cases:**
- [x] Two-line continuation joins correctly
- [x] Multi-line continuation (3+) joins correctly
- [x] Continuation without TAB on continuation line works
- [x] Nested continuation within quotes

### 4. Shell Comments in Recipes

**Syntax:** `#` in recipe line starts shell comment

```makefile
clean:
	rm -rf ./build   # Remove build directory
	# This entire line is a comment
	git status       # Check status
```

**Behavior:**
- Comments handled by underlying shell script extractor
- `#` outside quotes starts comment
- Comment portion stripped before pattern matching
- Entire comment-only lines produce no extraction

**Test Cases:**
- [x] Inline comment stripped: `rm -rf /tmp # cleanup` → `rm -rf /tmp`
- [x] Full comment line not extracted
- [x] `#` in quotes preserved: `echo "# header"` → `echo "# header"`

---

## Recipe vs Non-Recipe Lines

### Lines Extracted (Recipe Lines)

Lines starting with TAB that contain shell commands:

```makefile
all:
	@echo "Building"    # @ prefix still extracted as "echo Building"
	-rm -rf build       # - prefix still extracted as "rm -rf build"
	+make subdir        # + prefix still extracted as "make subdir"
```

**Recipe Line Prefixes:**
| Prefix | Meaning | Extraction Behavior |
|--------|---------|---------------------|
| (none) | Normal | Extract as-is |
| `@` | Silent (no echo) | Extract command after `@` |
| `-` | Ignore errors | Extract command after `-` |
| `+` | Run even in dry-run | Extract command after `+` |

**Note:** Prefix handling is delegated to shell script extractor.

### Lines Not Extracted

| Line Type | Example | Reason |
|-----------|---------|--------|
| Variable assignment | `CC = gcc` | Not executable context |
| Target definition | `all: build test` | Rule declaration, not command |
| Directive | `.PHONY: all clean` | Make directive, not command |
| Include | `include config.mk` | Make directive |
| Comment | `# Build configuration` | Not executable |
| Conditional | `ifeq ($(DEBUG),1)` | Make syntax, not shell |
| Blank line | (empty) | Nothing to extract |

---

## Variable Handling

### Variable Syntax in Make

Make variables can appear in recipes:

```makefile
CLEAN_CMD = rm -rf ./build

clean:
	$(CLEAN_CMD)
	${CLEAN_CMD}
	$$HOME/cleanup.sh    # Shell variable (doubled $$)
```

### v1 Behavior: No Substitution

**The v1 extractor does NOT expand variables.**

| Input | Extracted | Note |
|-------|-----------|------|
| `$(CC) -o main main.c` | `$(CC) -o main main.c` | Literal `$(CC)` |
| `${RM} -rf build` | `${RM} -rf build` | Literal `${RM}` |
| `$$HOME/script.sh` | `$$HOME/script.sh` | Literal `$$HOME` |
| `$(shell rm -rf /)` | `$(shell rm -rf /)` | Literal, not executed |

**Implications:**
- Patterns must match against literal variable syntax
- Dangerous commands hidden behind variables won't trigger
- This is a known v1 limitation (conservative approach)

**Test Cases:**
- [x] `$(VAR)` syntax preserved literally
- [x] `${VAR}` syntax preserved literally
- [x] `$$var` (shell variable) preserved literally
- [x] `$(shell cmd)` function not evaluated

---

## Unsupported Constructs (v1 Limitations)

The following are known limitations in v1. They may produce unexpected behavior
and should be addressed in future versions.

### 1. Variable Expansion

**Not Supported:**

```makefile
DANGER = rm -rf /
clean:
	$(DANGER)
```

**Current Behavior:** Extracts literal `$(DANGER)`, not the expanded value.

**Impact:** Commands hidden behind variables won't trigger pattern matches.

### 2. Make Functions

**Not Supported:**

```makefile
FILES := $(wildcard *.c)
clean:
	$(foreach f,$(FILES),rm $(f);)
	$(shell dangerous-command)
```

**Current Behavior:** Functions extracted literally, not evaluated.

**Impact:** Commands inside `$(shell ...)` won't be scanned as shell commands.

### 3. Conditional Directives

**Not Supported:**

```makefile
ifeq ($(DEBUG),1)
clean:
	rm -rf ./debug
else
clean:
	rm -rf ./release
endif
```

**Current Behavior:** `ifeq`/`else`/`endif` lines not parsed as directives;
recipe lines within conditionals ARE extracted.

**Impact:** Both branches' recipes may be extracted regardless of condition.

### 4. Pattern Rules

**Partially Supported:**

```makefile
%.o: %.c
	$(CC) -c $< -o $@
```

**Current Behavior:** Recipe lines extracted with literal `$<`, `$@`.

**Impact:** Automatic variables (`$@`, `$<`, `$^`, etc.) not expanded.

### 5. Include Directives

**Not Supported:**

```makefile
include common.mk
-include optional.mk
```

**Current Behavior:** Include files not followed or scanned.

**Impact:** Commands in included files not analyzed.

### 6. Multi-Line Variable Definitions

**Not Supported:**

```makefile
define SCRIPT
rm -rf /tmp
git reset --hard
endef

clean:
	$(SCRIPT)
```

**Current Behavior:** `define`/`endef` blocks not parsed; `$(SCRIPT)` extracted literally.

**Impact:** Multi-line variable content not scanned.

### 7. Alternative File Names

**Not Supported:**

| File Name | Status |
|-----------|--------|
| `GNUmakefile` | Not matched (future work) |
| `*.mk` | Not matched (include files) |
| `makefile.in` | Not matched (autoconf) |
| `Makefile.am` | Not matched (automake) |

---

## Implementation Details

### Recipe Block Processing

1. Scan for lines starting with TAB
2. Collect consecutive recipe lines into a block
3. Handle backslash continuations within block
4. Pass block to shell script extractor for command parsing
5. Return extracted commands with `makefile.recipe` extractor ID

### Shell Script Extractor Reuse

The Makefile extractor delegates to `extract_shell_script_with_offset_and_id()`:

- Comment stripping (`#` outside quotes)
- Quote-aware parsing
- Backslash continuation handling
- Keyword filtering

This ensures consistent behavior between `.sh` files and Makefile recipes.

---

## Test Checklist

Use this checklist to verify implementation correctness:

### Path Detection
- [ ] `Makefile` matches
- [ ] `makefile` matches (case-insensitive)
- [ ] `MAKEFILE` matches (case-insensitive)
- [ ] `Makefile.backup` does NOT match
- [ ] `build.mk` does NOT match
- [ ] `GNUmakefile` does NOT match

### Recipe Extraction
- [ ] TAB-prefixed line extracts command
- [ ] Non-TAB line not extracted
- [ ] Consecutive recipe lines form block
- [ ] Target definition line not extracted
- [ ] Variable assignment not extracted

### Backslash Continuation
- [ ] Two-line continuation joins correctly
- [ ] Multi-line continuation joins correctly
- [ ] Continuation line without TAB works
- [ ] Backslash at end of recipe line triggers continuation

### Comments
- [ ] Recipe line with `# comment` strips comment
- [ ] Full comment recipe line not extracted
- [ ] `#` in quotes preserved

### Variables
- [ ] `$(VAR)` syntax preserved literally
- [ ] `${VAR}` syntax preserved literally
- [ ] `$$var` shell variable preserved
- [ ] `$(shell ...)` not evaluated

### Recipe Prefixes
- [ ] `@echo hello` extracts (with or without `@`)
- [ ] `-rm -rf x` extracts (with or without `-`)
- [ ] `+make sub` extracts (with or without `+`)

### Edge Cases
- [ ] Empty Makefile returns no commands
- [ ] File with only variables returns no commands
- [ ] File with only comments returns no commands
- [ ] Keyword filter limits extraction

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-16 | Initial specification |

---

## Related Tasks

- **Blocks:** `git_safety_guard-dclh` (Implement Makefile recipe extractor)
- **Blocks:** `git_safety_guard-5rbb.7` (Unit tests for Makefile extractor)
- **Parent:** `git_safety_guard-5rbb` (Scan Mode Extractors for CI/DevOps Files)
