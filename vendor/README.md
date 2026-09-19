# Native parser safety patch (#442)

The candidate repair vendors the exact `tree-sitter-bash` 0.25.1 crates.io
release (SHA-256
`9e5ec769279cc91b561d3df0d8a5deb26b0ad40d183127f409494d6d8fc53062`).
The upstream MIT license and generated grammar are retained unchanged.

`patches/tree-sitter-bash-0.25.1-unicode.patch` changes only the two brace-range
digit loops. Tree-sitter's `TSLexer.lookahead` is a 32-bit Unicode code point;
C's `isdigit` accepts only EOF or a value representable as `unsigned char`.
A high code point can therefore index outside libc's classification table
with an entirely valid lexer pointer. Whether the read faults depends on
process memory layout. Concurrency is not required for the defect.

Use explicit ASCII comparisons, not an `unsigned char` cast (which aliases
Unicode code points to ASCII digits), and not input masking or AST fallback.
This preserves input bytes, source spans, ordinary brace parsing and command
matching. It does not attempt to repair unrelated environment mutation in
tests or claim to fix every possible cause of #442.

## Reproduction and validation

`python3 scripts/check_scanner_safety.py prepare` verifies the release checksum,
compiles the **actual** upstream scanner with an instrumented `isdigit`
precondition (exit 86 proves the bug without depending on a SIGSEGV), and runs
an uninstrumented reproduction too. It then applies the two reviewed patches
in this checkout, never in a shared Cargo registry cache. The patched scanner
is tested across every Unicode scalar in both loops, including continuation
after an ASCII digit, normally and under ASAN/UBSAN. The C-only sanitizer
binary does not involve `aws-lc-sys` or require instrumenting Rust's standard
library.

Once the vendored repair is present, the same command only validates it and
performs no download or source edit. `cargo test --locked --lib
scanner_regression_tests` exercises real ast-grep, UTF-8 preservation,
destructive-command matching, cache reuse and concurrent parsers.

`python3 scripts/check_scanner_safety.py repeat --runs 12` runs the entire
`cargo test --locked --lib` gate 12 times at default harness parallelism,
12 times with 128 test threads, and three times serially. Logs and raw exit
statuses are retained under `target/scanner-safety/`. Any failed run makes
the command fail; there is no retry-until-green behavior.

The bootstrap workflow may stage candidate Git blobs and a tree for review.
It never commits, moves a ref, pushes a branch, or opens a PR. A maintainer
must publish the reviewed tree explicitly. Remove its write permission after
the candidate has been published; routine regression checks need read access
only. No successful Rust or full-suite validation is implied by the presence
of these scripts: consult the logs for the exact tested revision and results.

## Recorded native result

GitHub Actions run `35453962762`, commit
`2d83133bd4388692c7a85b570efdbee4f6ee2bfb`, reproduced the actual upstream
scanner's ctype-domain violation (exit 86) and an uninstrumented SIGSEGV
(exit -11). The two-loop patch then passed 4,448,259 actual-scanner cases
both normally and under AddressSanitizer plus UndefinedBehaviorSanitizer.
No concurrency, parser cache or environment mutation was needed to reproduce
this native defect. The scanner and headers came from the checksum-verified
crates.io release, not a reimplementation of the crashing function.

That run stopped at rustfmt's requested wrapping of the new assertion; it
did not compile Rust or run the complete lib suite. The native result proves
this input-triggered defect, not that every intermittent suite failure has
the same cause. The bootstrap now exposes candidate objects immediately
after native validation so the full Rust validation and source review can
proceed independently. Candidate availability is still not a Rust pass.
