# Upstream report for #442, ready to file

`vendor/tree-sitter-bash` exists only because this defect is unfixed upstream,
and every `tree-sitter-bash` bump has to re-apply two lines until it lands
there. The report below is written and checked so filing it is a copy-paste.

- **Where:** <https://github.com/tree-sitter/tree-sitter-bash/issues/new>
- **Checked 2026-09-19:** latest release is still `v0.25.1` (2025-12-02), and a
  search of that repo's issues for `isdigit` / `lookahead` returns nothing, so
  this is not a duplicate.
- **Delete this file** once the issue is filed; replace it with the issue URL in
  `vendor/README.md`, and drop the vendored copy entirely once a release
  carries the fix.

The patch to offer is `vendor/patches/tree-sitter-bash-0.25.1-unicode.patch`.

---

## Title

`isdigit(lexer->lookahead)` in the external scanner is undefined for non-ASCII input

## Body

### Summary

`src/scanner.c` passes `lexer->lookahead` to `isdigit()` in the brace-range
scanner. `TSLexer.lookahead` is a `int32_t` Unicode code point, while C defines
`isdigit()` only for `EOF` and values representable as `unsigned char`. Any
input whose code point exceeds 255 at that position is undefined behaviour, and
on glibc it is an out-of-bounds read of the locale classification table.

Two call sites, both in the `brace_start` block:

```c
while (isdigit(lexer->lookahead)) {   // src/scanner.c:1158
while (isdigit(lexer->lookahead)) {   // src/scanner.c:1172
```

### Why it is worth fixing rather than tolerating

The read usually lands on mapped memory and returns a value the loop discards,
so it is invisible most of the time. Whether it faults depends on where
`__ctype_b_loc()`'s table sits relative to an unmapped page, which moves with
thread count, stack size and allocation pattern — so it presents as an
intermittent, "concurrency-related" crash that is very hard to attribute.

We chased it as exactly that for a while: a test binary segfaulting in roughly
2 of 12 runs, with no Rust panic and no stack-overflow banner. `gdb` put the
fault at `scanner.c:1158`.

### Reproduction

A C harness that calls the external scanner directly, with
`symbols[BRACE_START] = true` and input `{` followed by a high code point:

```
U+0100, U+0130, U+07FF, U+FFFF, U+1D7D9, U+E01EF, U+10FFFF
```

Measured on Linux/glibc (GitHub Actions, `ubuntu-24.04`):

| build | result |
|---|---|
| unmodified `0.25.1`, with an `isdigit` domain assertion | exits 86 — `ctype-domain violation: isdigit(U+10FFFF)` |
| unmodified `0.25.1`, uninstrumented | exits `-11` (SIGSEGV) |
| patched | passes all 4,448,259 cases, plain and under ASAN+UBSAN |

No concurrency, parser cache or thread churn is needed; a single direct call
reproduces it.

On macOS the same input does **not** fault, because Darwin routes `isdigit`
through `__istype()`, which is range-safe above 255. That asymmetry is part of
why this is easy to miss.

### Suggested fix

Compare against the ASCII range directly at both sites:

```c
-        while (isdigit(lexer->lookahead)) {
+        while (lexer->lookahead >= '0' && lexer->lookahead <= '9') {
```

Two notes on the choice:

- **Not** an `unsigned char` cast. That would alias high code points onto ASCII
  digits — U+0130 would truncate to `0x30`, i.e. `'0'` — turning undefined
  behaviour into a wrong parse.
- `iswdigit()` would also be correct, and this file already uses it at lines 612
  and 631 for the same job, so the two narrow calls look like a slip rather than
  a convention. POSIX constrains the `digit` class to `0`–`9` in every locale,
  so the two agree on what they classify. The explicit comparison is offered
  because it removes the domain question at the call site rather than relying on
  a wider domain to contain it.

### Scope

- These are the only two narrow ctype calls in the file; the other 52 ctype
  calls are the wide `isw*` family, whose `wint_t` domain accepts a code point
  safely.
- Checked every other `tree-sitter-*` grammar scanner we had locally (13
  crates): `tree-sitter-bash` is the only one that calls a narrow ctype function
  at all. Core `tree-sitter`'s `subtree.c` calls `isprint(chr)` but guards it
  with `0 < chr && chr < 128`.
