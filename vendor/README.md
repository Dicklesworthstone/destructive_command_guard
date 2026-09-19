# Native parser safety patch (#442)

`tree-sitter-bash` is vendored from the exact 0.25.1 crates.io release:

- Archive SHA-256: `9e5ec769279cc91b561d3df0d8a5deb26b0ad40d183127f409494d6d8fc53062`
- Upstream Git revision: `a06c2e4415e9bc0346c6b86d401879ffb44058f7`
- Original scanner Git blob: `0c3430a7d562182e9e0f6657ffd07cad5392ce06`
- Patched scanner Git blob: `89f33c477e8060b91465fec105a1b911dfb4308c`

The upstream MIT license, generated grammar, Rust bindings and all other
release files are unchanged. The root `[patch.crates-io]` selects this copy
for ast-grep's transitive dependency; the root lockfile records it as a path
package. No shared Cargo registry files or process-global parser settings
are modified.

## Defect and repair

`patches/tree-sitter-bash-0.25.1-unicode.patch` changes only the two brace-range
digit loops. Tree-sitter's `TSLexer.lookahead` is a 32-bit Unicode code point;
C's `isdigit` accepts only EOF or a value representable as `unsigned char`.
A high code point can therefore index outside libc's classification table
with an entirely valid lexer pointer. Whether the read faults depends on
process memory layout. Concurrency is not required for this defect.

Use explicit ASCII comparisons, not an `unsigned char` cast (which aliases
Unicode code points to ASCII digits), and not input masking or AST fallback.
This preserves input bytes, source spans, ordinary brace parsing and command
matching. It does not attempt to repair unrelated environment mutation in
tests or claim that every intermittent suite failure has this cause.

## Reproduction and validation

`python3 scripts/check_scanner_safety.py prepare` validates the checked-in
scanner without downloads or source edits. It tests every Unicode scalar
in both digit loops, including continuation after an ASCII digit, normally
and under ASAN/UBSAN. The C-only sanitizer binary does not involve
`aws-lc-sys` or require instrumenting Rust's standard library.

`cargo test --locked --lib scanner_regression_tests` exercises actual
ast-grep, original UTF-8, destructive-command matching, cache reuse and
concurrent parsers. `python3 scripts/check_scanner_safety.py repeat --runs 12`
runs the complete `cargo test --locked --lib` gate 12 times at default
harness parallelism, 12 times with 128 test threads, and three times serially.
Logs and raw exit statuses are retained under `target/scanner-safety/`.
Any failed run makes the command fail; there is no retry-until-green behavior.

Both of those validate behaviour, and behaviour cannot tell a patched build
from an unpatched one: the out-of-domain read usually returns a value the loop
discards. `cargo test --locked --test repro_442_vendored_scanner_is_linked`
therefore asserts the wiring — that `Cargo.lock` resolves `tree-sitter-bash` to
this path package rather than a registry source, that no patch is recorded
unused, that the locked and vendored versions agree, and that the scanner here
still calls no narrow ctype function on a code point. Cargo reports a patch
that stopped applying only as a warning, so without that assertion a dependency
bump would restore the upstream defect with every gate green.

The Bash scanner safety workflow has read-only repository permissions.
Dependency, native-source and parser-boundary changes rerun the gate.

## Recorded native result

GitHub Actions run `35453962762`, commit
`2d83133bd4388692c7a85b570efdbee4f6ee2bfb`, reproduced the actual upstream
scanner's ctype-domain violation (exit 86) and an uninstrumented SIGSEGV
(exit -11). The two-loop patch then passed 4,448,259 actual-scanner cases
both normally and under AddressSanitizer plus UndefinedBehaviorSanitizer.
An independent local build from byte-identical upstream scanner and headers
reproduced both failures and both patched passes.

No concurrency, parser cache or environment mutation was needed to reproduce
this native defect. These are real upstream scanner executions, not a
reimplementation of the crashing function. The first workflow stopped at
rustfmt's requested wrapping of the new assertion; it did not compile Rust
or run the complete lib suite. The assertion was corrected in `46400e5`.
Consult subsequent workflow logs for Rust and complete-suite results; native
success alone is not a full-suite pass.

## Provenance of the initial import

The bootstrap in `check_scanner_safety.py` fetched the checksum-verified
archive, rejected unsafe tar entries, applied the two reviewed patches in an
isolated checkout, and staged Git blobs and a tree for explicit review.
It never committed, moved a ref, pushed a branch, or opened a PR. The imported
scanner hash above also matches the independently patched local source.
The workflow's temporary object-upload permission and step were removed
when the vendor copy was committed. The dormant bootstrap commands are
retained for reproducibility; normal validation uses the checked-in files.
