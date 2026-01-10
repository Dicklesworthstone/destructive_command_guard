# Design: Allow-Once Short-Code Exceptions

## Status: DRAFT
**Author:** ChartreuseForest  
**Date:** 2026-01-10  
**Bead:** git_safety_guard-oien.1  
**Reviewed:** Pending

---

## 1. Executive Summary

This design specifies a short-code "allow-once" exception flow that:
- Provides a time-limited escape hatch for false positives.
- Preserves safety guarantees (scoped to exact command + cwd).
- Is auditable, deterministic, and safe under concurrent hook execution.

The flow adds a pending-exceptions store that records short codes on deny
and allows users to grant temporary exceptions by code.

---

## 2. UX Overview

### 2.1 Deny Output (Hook)

On deny, print a short code at the very top of the message:

```
ALLOW-ONCE CODE: ab12
To allow once: dcg allow-once ab12
```

Notes:
- Code is always shown when a block occurs.
- Keep the first line short for TUI truncation.
- Code is lowercase hex.

### 2.2 CLI Commands

```
dcg allow-once <code>
dcg allow-once <code> --single-use
dcg allow-once <code> --show-raw
dcg allow-once <code> --hash <full_hash>
dcg allow-once <code> --index <n>
```

Behavior:
- Default is reusable until expiry (exact command + cwd match).
- `--single-use` marks the exception as consumed after the first allow.
- `--show-raw` reveals the raw command when resolving collisions.
- `--hash` or `--index` disambiguates collisions non-interactively.
- If the code maps to multiple pending entries, the CLI must disambiguate
  (see Section 5.3).

---

## 3. Short-Code Generation

### 3.1 Hash Input

Hash input string (exact formatting, including spaces):

```
"<timestamp> | <cwd> | <command_raw>"
```

Fields:
- `timestamp`: RFC3339 UTC format, seconds precision (e.g., `2026-01-10T06:30:00Z`).
  - Fallback: if RFC3339 formatting fails, use Unix epoch seconds as a decimal string.
- `cwd`: absolute current working directory string as observed by the hook (literal cwd, not repo root).
- `command_raw`: full raw command text as executed (no normalization; includes whitespace/newlines).

### 3.2 Hash Output

- `full_hash`: SHA-256 of the input string, lowercase hex.
- `short_code`: last 4 hex chars of `full_hash`.

Collision policy:
- Short code is for UI only.
- Store `full_hash` and all metadata per record.
- Multiple records may share a short code and must be disambiguated.

---

## 4. Storage Design

### 4.1 Location

Default path (user scope):
```
~/.config/dcg/pending_exceptions.jsonl
```

Notes:
- Use `dirs::config_dir()` and `dcg` subdir, consistent with allowlist.
- Add optional env override for tests:
  - `DCG_PENDING_EXCEPTIONS_PATH`

### 4.2 Format: JSONL

Rationale:
- Append-only, safe for concurrent writes.
- Deterministic field order via struct field order in serialization.

Each line is a JSON object with fixed field order:

```json
{
  "schema_version": 1,
  "short_code": "ab12",
  "full_hash": "0123abcd...ff",
  "created_at": "2026-01-10T06:30:00Z",
  "expires_at": "2026-01-11T06:30:00Z",
  "cwd": "/abs/path",
  "command_raw": "git reset --hard HEAD",
  "command_redacted": "git reset --hard ***",
  "reason": "Blocked by core.git:reset-hard",
  "single_use": false,
  "consumed_at": null
}
```

Rules:
- `schema_version` is required (current = 1).
- `expires_at` is computed at creation time (now + 24h).
- `consumed_at` is null unless consumed (single-use only).
- `command_redacted` is used for display and logs by default.

### 4.3 Deterministic Ordering

Ensure serialization uses a struct with fields in the exact order above.
Do not serialize maps with nondeterministic key ordering.

---

## 5. Record Lifecycle

### 5.1 Creation

On deny:
- Create a new record with the computed hash and metadata.
- Append to JSONL file as a single write (newline-terminated).
- Return the short code to the user.

### 5.2 Pruning

On load or every write:
- Drop entries where `expires_at` is in the past.
- Drop entries with `consumed_at` set (single-use only).
- Log pruned count (see Section 7).

### 5.3 Collision Handling

When `dcg allow-once <code>` is called:
- Load all active records matching `short_code`.
- If zero matches: return a clear error (code expired or unknown).
- If one match: grant exception.
- If multiple matches:
  - Show a table of redacted commands with index, created_at, cwd, and full_hash prefix.
  - Require `--hash <full_hash>` or `--index <n>` to disambiguate.
  - If TTY and no flag, prompt for selection (safe, local-only).

---

## 6. Concurrency & Integrity

### 6.1 Atomic Append

Use `OpenOptions::new().create(true).append(true)` and write each JSON line
with a single `write_all()` call. This preserves atomicity on POSIX.

### 6.2 Partial Corruption (Fail-Open)

Parsing strategy:
- Read file line-by-line.
- Parse each line independently.
- If a line fails to parse, skip it and continue.
- If the entire file is unreadable, treat as empty and continue (fail-open).

Rationale:
- The hook must not block or crash due to a corrupt store.
- Corruption should never prevent command execution.

---

## 7. Logging & Redaction

### 7.1 Redaction

Store both:
- `command_raw` for exact match + hashing.
- `command_redacted` for display/log output (default).

Redaction should:
- Remove obvious secrets (tokens, passwords, long hex strings).
- Mirror the logging redaction behavior where possible.

### 7.2 Logging Events

Log when:
- Entries are pruned (expired or consumed).
- A pending exception is consumed (single-use).

Log format should include:
- `short_code`, `full_hash`, `cwd`, `created_at`, `expires_at`, `consumed_at`.
- Use redacted command by default unless `--show-raw`.

---

## 8. Security & Scope

Scope enforcement:
- Exceptions are bound to exact `command_raw` and `cwd`.
- No canonicalization: matching uses the exact raw command text captured at deny time.
- Allow-once overrides pack denies, but not explicit config block overrides
  unless the CLI is invoked with `--force` (separate task).

Expiry:
- All records expire after 24 hours (non-configurable for MVP).

---

## 9. Testing Plan

Unit tests must cover:
- Hash input formatting and short code derivation.
- RFC3339 timestamp format parsing and expiry checks.
- Pruning expired and consumed entries.
- Collision disambiguation behavior.
- Redaction output vs raw command.
- Fail-open on corrupt lines or missing file.

E2E tests:
- Deny emits code on first line.
- `dcg allow-once <code>` allows the exact command + cwd.
- `--single-use` consumes after first allow.

---

## 10. Implementation Notes (Non-Normative)

- Reuse `chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")` for timestamp.
- Keep serialization simple with a `struct PendingException`.
- Avoid new deps if possible; if locking is required, prefer `fs2` (explicit version).
