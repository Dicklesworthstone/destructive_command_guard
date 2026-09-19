//! #442 guard: every top-level `src/*.rs` must be reachable from the module tree.
//!
//! Rust does not auto-discover modules. A file sitting under `src/` with no
//! `mod` declaration is not part of the crate at all: it is never compiled,
//! never linted, and any `#[test]` function inside it never runs.
//!
//! `src/scanner_regression_tests.rs` shipped in exactly that state. Its
//! declaration lived only in `vendor/patches/dcg-bash-scanner-wiring.patch`, so
//! on `main` the file was inert. That went unnoticed because
//! `cargo test --lib <filter>` exits 0 when the filter matches nothing — so the
//! `scanner-safety` workflow step named "Compile and run the actual ast-grep
//! regressions" passed while running zero tests, and every heavy step gated on
//! its success ran on the strength of that vacuous pass.
//!
//! This guard lives under `tests/` deliberately: Cargo discovers every file in
//! that directory automatically, so the guard itself cannot be orphaned the same
//! way the thing it guards was. Both halves of it are covered below — the
//! matcher and the orphan detection are exercised against synthetic inputs, so a
//! guard that silently stopped detecting anything would fail rather than pass.

use std::collections::BTreeSet;
use std::path::Path;

/// Module names declared by `source`, ignoring commented-out declarations.
///
/// Matches `mod x;`, `pub mod x;` and `pub(crate) mod x;` without caring which,
/// since any of them is enough to pull the file into the crate. Multi-line and
/// inline (`mod x; mod y;`) forms are not used in this crate's roots.
fn declared_modules(source: &str) -> BTreeSet<&str> {
    source
        .lines()
        .filter_map(|line| {
            let code = line.split("//").next()?.trim();
            let without_semicolon = code.strip_suffix(';')?;
            let name = without_semicolon.rsplit_once("mod ")?.1.trim();
            // Reject `mod` embedded in a longer identifier: `pub mod x;` is a
            // declaration, `somemod x;` is not.
            let boundary_ok = without_semicolon
                .strip_suffix(name)?
                .trim_end()
                .strip_suffix("mod")
                .is_some_and(|before| before.is_empty() || before.ends_with(' '));
            (boundary_ok && !name.is_empty() && !name.contains(char::is_whitespace)).then_some(name)
        })
        .collect()
}

/// Stems of `*.rs` files directly under `dir`, excluding the crate roots, that
/// none of the roots declare. Sorted, so failure output is stable.
fn orphaned_modules(dir: &Path, declared: &BTreeSet<&str>) -> Vec<String> {
    let mut orphaned = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read the source directory") {
        let path = entry.expect("read a source directory entry").path();
        // A directory named `*.rs` is not a module file, so require a real file
        // rather than trusting the extension alone.
        if path.extension().is_none_or(|extension| extension != "rs") || !path.is_file() {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("utf-8 file stem");
        // The crate roots are build targets, not modules of one another.
        if stem == "lib" || stem == "main" {
            continue;
        }
        if !declared.contains(stem) {
            orphaned.push(stem.to_owned());
        }
    }
    orphaned.sort();
    orphaned
}

fn crate_root(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn every_top_level_source_file_is_declared_in_a_crate_root() {
    let lib = crate_root("lib.rs");
    let main = crate_root("main.rs");
    let mut declared = declared_modules(&lib);
    declared.extend(declared_modules(&main));

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let orphaned = orphaned_modules(&src, &declared);

    assert!(
        orphaned.is_empty(),
        "src/*.rs files with no `mod` declaration in src/lib.rs or src/main.rs: {orphaned:?}\n\
         An undeclared file is not part of the crate — it is not compiled, not linted, and its \
         tests never run. Add `mod <name>;` (with `#[cfg(test)]` if it is test-only) to a root."
    );
}

#[test]
fn the_scanner_regression_module_is_wired_in() {
    let lib = crate_root("lib.rs");
    assert!(
        declared_modules(&lib).contains("scanner_regression_tests"),
        "src/lib.rs must declare `mod scanner_regression_tests;` — the #442 bash-scanner \
         regressions only run if it does, and `cargo test --lib scanner_regression_tests` \
         exits 0 when the filter matches nothing, so its absence is silent."
    );
}

#[test]
fn the_wiring_patch_does_not_redeclare_the_module() {
    // The declaration lives on main, so the vendored-repair patch must not add a
    // second one: `git apply` would succeed and the crate would then fail to
    // compile with a duplicate module definition.
    let patch =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/patches/dcg-bash-scanner-wiring.patch");
    let text = std::fs::read_to_string(&patch).expect("read the wiring patch");
    let added_declaration = text
        .lines()
        .any(|line| line.starts_with('+') && line.contains("mod scanner_regression_tests;"));
    assert!(
        !added_declaration,
        "{} adds `mod scanner_regression_tests;`, which src/lib.rs already declares",
        patch.display()
    );
}

/// Negative controls. A guard whose detection quietly broke would report "no
/// orphans" forever, which is the failure mode this whole file exists to catch,
/// so the detection is exercised against inputs with known answers.
mod detection_is_not_vacuous {
    use super::{declared_modules, orphaned_modules};

    #[test]
    fn accepts_every_visibility_and_attribute_form() {
        let source = "pub mod alpha;\nmod beta;\npub(crate) mod gamma;\n#[cfg(test)]\nmod delta;\n";
        let found = declared_modules(source);
        for name in ["alpha", "beta", "gamma", "delta"] {
            assert!(found.contains(name), "missed {name} in {source:?}");
        }
    }

    #[test]
    fn ignores_commented_out_and_inline_module_bodies() {
        let found = declared_modules("// mod ghost;\nmod real;\nmod inline { }\n");
        assert!(found.contains("real"));
        assert!(
            !found.contains("ghost"),
            "a commented-out mod is not a declaration"
        );
        assert!(
            !found.contains("inline"),
            "an inline module body has no file"
        );
    }

    #[test]
    fn does_not_match_mod_inside_a_longer_identifier() {
        let found = declared_modules("let remod = 1;\nsomemod x;\n");
        assert!(found.is_empty(), "matched a non-declaration: {found:?}");
    }

    #[test]
    fn reports_an_undeclared_file_and_only_that_file() {
        let directory = tempfile::tempdir().expect("create a temporary source directory");
        let source = directory.path();
        for name in ["lib.rs", "main.rs", "declared.rs", "ghost.rs", "notes.txt"] {
            std::fs::write(source.join(name), "").expect("write a synthetic source file");
        }
        std::fs::create_dir(source.join("subdir.rs")).expect("create a look-alike directory");

        let roots = "pub mod declared;\n";
        let orphaned = orphaned_modules(source, &declared_modules(roots));

        assert_eq!(
            orphaned,
            vec!["ghost".to_owned()],
            "expected exactly the undeclared .rs file; crate roots, non-Rust files and \
             directories are not modules of their own"
        );
    }
}
