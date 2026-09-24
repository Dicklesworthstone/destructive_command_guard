//! #442 guard: the build must actually link the *patched* bash scanner.
//!
//! The repair for #442 is a two-line change to `tree-sitter-bash`'s C external
//! scanner, vendored under `vendor/tree-sitter-bash` and published as
//! `tree-sitter-bash-dcg`. dcg reaches the Bash grammar only through
//! `ast-grep-language`, so it depends on `ast-grep-language-dcg`
//! (`vendor/ast-grep-language`), which is ast-grep-language built against the
//! patched grammar. This replaced a `[patch.crates-io]`, which `cargo publish`
//! drops, so every crates.io build had silently compiled the unpatched scanner.
//! The same failure is still possible if the graph ever picks up a stock
//! `ast-grep-language` or `tree-sitter-bash` alongside, or instead of, the
//! forks. The build would succeed and link the unpatched scanner.
//!
//! Nothing else in the tree notices that. `scripts/check_scanner_safety.py`
//! compiles `vendor/tree-sitter-bash/src/scanner.c` directly with `cc`, so it
//! validates the file on disk rather than the one Cargo linked.
//! `src/scanner_regression_tests.rs` parses Unicode brace ranges through the
//! real ast-grep entry point, but its assertions — source bytes preserved, the
//! destructive command still matched — hold on an unpatched build too: the
//! out-of-domain `isdigit` read usually returns a value the loop discards, and
//! only faults when process memory layout happens to put libc's classification
//! table next to an unmapped page. A green suite is therefore not evidence that
//! the patched scanner is the one in the binary.
//!
//! That matters more than flakiness: a hook that dies on a signal writes
//! nothing to stdout, and the PreToolUse protocol reads empty stdout as
//! `allow`, so a fault in the guard's own parser fails open. This guard asserts
//! the wiring structurally instead. It lives under `tests/`, which Cargo
//! discovers automatically, so it cannot be orphaned the way
//! `src/scanner_regression_tests.rs` was.

use std::path::Path;

/// Narrow ctype classifiers: C defines these only for `EOF` and values
/// representable as `unsigned char`, so passing a Unicode code point is
/// undefined. The wide `isw*` family takes a `wint_t` and is safe; the same
/// scanner already uses `iswdigit` elsewhere.
const NARROW_CTYPE_FUNCTIONS: [&str; 14] = [
    "isalnum", "isalpha", "isblank", "iscntrl", "isdigit", "isgraph", "islower", "isprint",
    "ispunct", "isspace", "isupper", "isxdigit", "tolower", "toupper",
];

/// The two brace-range loops the repair rewrites, as they must read afterwards.
const ASCII_DIGIT_LOOP: &str = "lexer->lookahead >= '0' && lexer->lookahead <= '9'";

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Bodies of every table with this exact header, in file order.
///
/// Enough TOML for a `Cargo.lock`: a header line ends whatever table preceded
/// it, and the entries of a multi-line array are not headers.
fn tables<'a>(document: &'a str, header: &str) -> Vec<Vec<&'a str>> {
    let mut tables = Vec::new();
    let mut current: Option<Vec<&'a str>> = None;
    for line in document.lines().map(str::trim) {
        if line == header {
            tables.extend(current.replace(Vec::new()));
        } else if line.starts_with('[') && line.ends_with(']') {
            tables.extend(current.take());
        } else if let Some(body) = current.as_mut() {
            body.push(line);
        }
    }
    tables.extend(current);
    tables
}

/// The unquoted value of a `key = value` entry in a table body.
fn field<'a>(body: &[&'a str], key: &str) -> Option<&'a str> {
    body.iter().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim().trim_matches('"'))
    })
}

/// `line: text` for every call of a narrow ctype function in `source`.
///
/// `//` is the only comment form used around the patched loops. A narrow name
/// inside a block comment would fail this guard rather than slip past it, which
/// is the safe direction for a check whose whole job is to not miss one.
fn narrow_ctype_calls(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or(line);
        for name in NARROW_CTYPE_FUNCTIONS {
            let mut rest = code;
            while let Some(start) = rest.find(name) {
                let before = rest[..start].chars().next_back();
                let after = rest[start + name.len()..].trim_start().chars().next();
                // Reject a name embedded in a longer identifier (`my_isdigit`)
                // and a bare mention that is not a call.
                if !before.is_some_and(|c| c.is_alphanumeric() || c == '_') && after == Some('(') {
                    let text = line.trim();
                    found.push(format!("{}: {text}", index + 1));
                }
                rest = &rest[start + name.len()..];
            }
        }
    }
    found
}

#[test]
fn the_manifests_select_the_patched_grammar_crates() {
    let manifest = read("Cargo.toml");
    let dependency = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("ast-grep-language ="))
        .expect("Cargo.toml must depend on ast-grep-language");
    assert!(
        dependency.contains("package = \"ast-grep-language-dcg\""),
        "dcg must take ast-grep-language from the ast-grep-language-dcg fork — the stock crate \
         links the unpatched tree-sitter-bash scanner (#442): {dependency}"
    );
    assert!(
        tables(&manifest, "[patch.crates-io]").is_empty(),
        "a [patch.crates-io] is dropped by `cargo publish`; the grammar fix must travel through \
         the published -dcg crates instead"
    );

    let fork = read("vendor/ast-grep-language/Cargo.toml");
    let bash = tables(&fork, "[dependencies.tree-sitter-bash]");
    assert_eq!(
        bash.len(),
        1,
        "the fork must declare its tree-sitter-bash dependency"
    );
    assert_eq!(
        field(&bash[0], "package"),
        Some("tree-sitter-bash-dcg"),
        "ast-grep-language-dcg must build against the patched grammar crate"
    );
}

#[test]
fn the_lockfile_links_only_the_patched_grammar() {
    // The fuzz crate is its own workspace with its own lockfile. The old
    // `[patch.crates-io]` never reached it, so the fuzzers exercised the
    // unpatched scanner; it is held to the same rule now.
    for lock_path in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let lockfile = read(lock_path);
        let packages = tables(&lockfile, "[[package]]");
        let named = |name: &str| -> Vec<_> {
            packages
                .iter()
                .filter(|body| field(body, "name") == Some(name))
                .collect()
        };

        // Either stock crate in the graph means some path links the unpatched
        // scanner, however the rest of the graph is wired.
        for stock in ["tree-sitter-bash", "ast-grep-language"] {
            assert!(
                named(stock).is_empty(),
                "{lock_path} contains the stock `{stock}`, so the build links the unpatched \
                 tree-sitter-bash scanner (#442). Everything must go through the -dcg forks."
            );
        }

        let patched = named("tree-sitter-bash-dcg");
        assert_eq!(
            patched.len(),
            1,
            "expected exactly one tree-sitter-bash-dcg in {lock_path}, found {}",
            patched.len()
        );
        let vendored = read("vendor/tree-sitter-bash/Cargo.toml");
        let package = tables(&vendored, "[package]");
        assert_eq!(
            field(patched[0], "version"),
            field(&package[0], "version"),
            "the tree-sitter-bash-dcg version locked in {lock_path} and the vendored package \
             version disagree"
        );
    }
}

#[test]
fn the_lockfile_records_no_unused_patch() {
    let lockfile = read("Cargo.lock");
    let unused = tables(&lockfile, "[[patch.unused]]");
    let names: Vec<_> = unused
        .iter()
        .filter_map(|body| field(body, "name"))
        .collect();
    assert!(
        names.is_empty(),
        "Cargo.lock records unused patches {names:?}; a patch that stopped applying leaves the \
         unpatched crate in the build"
    );
}

#[test]
fn the_vendored_scanner_passes_no_code_point_to_a_narrow_ctype_function() {
    let scanner = read("vendor/tree-sitter-bash/src/scanner.c");
    let calls = narrow_ctype_calls(&scanner);
    assert!(
        calls.is_empty(),
        "vendor/tree-sitter-bash/src/scanner.c calls a narrow ctype function on a value that can \
         be a Unicode code point: {calls:#?}\n\
         TSLexer.lookahead is a 32-bit code point; C defines these classifiers only for EOF and \
         unsigned char. Use an explicit ASCII comparison, or the wide isw* form."
    );
}

#[test]
fn the_vendored_scanner_keeps_both_ascii_digit_loops() {
    let scanner = read("vendor/tree-sitter-bash/src/scanner.c");
    assert_eq!(
        scanner.matches(ASCII_DIGIT_LOOP).count(),
        2,
        "both brace-range digit loops must test the ASCII range directly: {ASCII_DIGIT_LOOP}"
    );
}

/// Negative controls. A guard whose matcher quietly broke would report "no
/// narrow ctype calls" and "patch in effect" forever, so both detectors are
/// exercised against inputs with known answers.
mod detection_is_not_vacuous {
    use super::{field, narrow_ctype_calls, tables};

    const REGISTRY_LOCK: &str = "\
[[package]]
name = \"tree-sitter-bash\"
version = \"0.26.0\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
checksum = \"deadbeef\"
dependencies = [
 \"cc\",
]

[[package]]
name = \"other\"
version = \"1.0.0\"

[[patch.unused]]
name = \"tree-sitter-bash\"
version = \"0.25.1\"
";

    #[test]
    fn separates_tables_and_reads_their_fields() {
        let packages = tables(REGISTRY_LOCK, "[[package]]");
        assert_eq!(packages.len(), 2, "a multi-line array is not a new table");
        assert_eq!(field(&packages[0], "name"), Some("tree-sitter-bash"));
        assert_eq!(field(&packages[0], "version"), Some("0.26.0"));
        assert_eq!(field(&packages[1], "name"), Some("other"));
        assert_eq!(
            field(&packages[1], "source"),
            None,
            "a missing field must read as absent, not as another table's value"
        );
    }

    #[test]
    fn detects_the_registry_fallback_this_guard_exists_to_catch() {
        let packages = tables(REGISTRY_LOCK, "[[package]]");
        assert!(
            field(&packages[0], "source").is_some(),
            "a registry-resolved tree-sitter-bash must be visible as a `source` field"
        );
        let unused = tables(REGISTRY_LOCK, "[[patch.unused]]");
        assert_eq!(unused.len(), 1, "an unused patch table must be found");
        assert_eq!(field(&unused[0], "name"), Some("tree-sitter-bash"));
    }

    #[test]
    fn flags_a_narrow_ctype_call_on_lookahead() {
        let calls = narrow_ctype_calls("        while (isdigit(lexer->lookahead)) {\n");
        assert_eq!(calls.len(), 1, "missed the #442 defect itself: {calls:?}");
        assert!(calls[0].starts_with("1: "), "expected a line number");
    }

    #[test]
    fn accepts_the_wide_form_and_the_ascii_comparison() {
        let source = "if (iswdigit(lexer->lookahead)) {\n\
                      while (lexer->lookahead >= '0' && lexer->lookahead <= '9') {\n";
        assert!(
            narrow_ctype_calls(source).is_empty(),
            "the wide isw* family and an explicit range comparison are both safe"
        );
    }

    #[test]
    fn ignores_comments_and_longer_identifiers() {
        let source = "// Passing it to libc isdigit can read outside its table.\n\
                      return my_isdigit(c) || towlower(c);\n\
                      const int isdigit_calls = 0;\n";
        assert!(
            narrow_ctype_calls(source).is_empty(),
            "a comment, a longer identifier and a bare mention are not calls"
        );
    }
}
