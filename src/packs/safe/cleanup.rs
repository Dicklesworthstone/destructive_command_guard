//! Safe cleanup pack - allows rm -rf on common build/cache directories.
//!
//! **This pack is DISABLED by default.** Enable it by adding `"safe.cleanup"` to
//! your `enabled_packs` configuration.
//!
//! # Allowed directories
//!
//! When enabled, this pack allows `rm -rf` on these relative paths:
//!
//! - `target/` - Rust build output
//! - `dist/` - Common frontend build output
//! - `build/` - Common build output (Gradle, general)
//! - `.next/` - Next.js cache
//! - `.turbo/` - Turborepo cache
//! - `.nuxt/` - Nuxt.js cache
//! - `.output/` - Nuxt 3 output
//! - `.svelte-kit/` - `SvelteKit` cache
//! - `node_modules/` - npm/yarn/pnpm dependencies
//! - `__pycache__/` - Python bytecode cache
//! - `.pytest_cache/` - pytest cache
//! - `.mypy_cache/` - mypy cache
//! - `.ruff_cache/` - ruff cache
//! - `.tox/` - tox environments
//! - `.eggs/` - setuptools cache
//! - `.gradle/` - Gradle cache
//! - `.maven/` - Maven cache
//! - `vendor/` - Vendored dependencies
//! - `coverage/` - Test coverage reports
//! - `.coverage/` - Coverage data
//! - `.nyc_output/` - NYC coverage output
//! - `.parcel-cache/` - Parcel bundler cache
//! - `.cache/` - Generic cache directory
//! - `.vite/` - Vite cache
//! - `.rollup.cache/` - Rollup cache
//! - `out/` - Common output directory
//!
//! # Safety constraints
//!
//! All patterns enforce:
//! - **Relative paths only**: No absolute paths (`/path`) or home paths (`~/path`)
//! - **No path traversal**: No `..` segments anywhere in the path
//! - **Explicit directory names**: Only exact matches at path start
//!
//! # Quoting Support
//!
//! Safe paths may be:
//! - Unquoted: `rm -rf target/`
//! - Double-quoted: `rm -rf "target/"`
//! - Single-quoted: `rm -rf 'target/'`
//!
//! Quoted paths may contain spaces if the underlying shell supports it (e.g., `rm -rf "build output"`),
//! but subpaths must not contain shell metacharacters like `$`, `;`, or `|` even inside quotes.
//!
//! # Examples
//!
//! **Allowed (when pack enabled):**
//! - `rm -rf target/`
//! - `rm -rf "target/"`
//! - `rm -rf 'dist/'`
//! - `rm -rf ./dist/`
//! - `rm -rf node_modules/`
//! - `rm -rf target/debug/`
//!
//! **Still blocked (even when pack enabled):**
//! - `rm -rf /target/` - absolute path
//! - `rm -rf ../target/` - path traversal
//! - `rm -rf foo/../target/` - embedded path traversal
//! - `rm -rf ~/target/` - home directory
//! - `rm -rf /home/user/target/` - absolute path

use crate::packs::{Pack, SafePattern};

/// Create the safe cleanup pack.
///
/// This pack is opt-in (disabled by default) and allows `rm -rf` on common
/// build/cache directories when the path is relative and contains no traversal.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "safe.cleanup".to_string(),
        name: "Safe Cleanup",
        description: "Allows rm -rf on common build/cache directories (target/, dist/, node_modules/, etc.)",
        keywords: &["rm"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: vec![], // This pack only adds safe patterns
        keyword_matcher: None,
    }
}

/// Generates safe patterns for a list of directory names.
///
/// Each directory gets patterns for both `rm -rf` and `rm -fr` flag orders,
/// as well as `./dir` prefix variants.
fn create_safe_patterns() -> Vec<SafePattern> {
    // Common build/cache directories that are safe to delete.
    // These are all relative-path-only and reject path traversal.
    let safe_dirs = [
        // Rust
        "target",
        // Frontend/JS
        "dist",
        "build",
        "node_modules",
        ".next",
        ".turbo",
        ".nuxt",
        ".output",
        ".svelte-kit",
        ".parcel-cache",
        ".cache",
        ".vite",
        ".rollup.cache",
        "out",
        // Python
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".eggs",
        // Java/JVM
        ".gradle",
        ".maven",
        // Go
        "vendor",
        // Coverage
        "coverage",
        ".coverage",
        ".nyc_output",
    ];

    let escaped_dirs: Vec<String> = safe_dirs.iter().map(|dir| regex_escape(dir)).collect();
    let dir_group = escaped_dirs.join("|");

    // Unquoted pattern (strict, no spaces)
    let unquoted_prefix = r"(?![^\s]*\.\.)(?:\./)?(?:";
    let unquoted_suffix = r")(?:/[^\s;&|$()`<>]+)*/?";
    let unquoted_pattern = format!("{}{}{}", unquoted_prefix, dir_group, unquoted_suffix);

    // Double-quoted pattern (allows spaces, no " inside)
    let dquote_prefix = r#""(?![^"]*\.\.)(?:\./)?(?:"#;
    let dquote_suffix = r#")(?:/[^";&|$()`<>]+)*/?""#;
    let dquote_pattern = format!("{}{}{}", dquote_prefix, dir_group, dquote_suffix);

    // Single-quoted pattern (allows spaces, no ' inside)
    let squote_prefix = r"'(?![^']*\.\.)(?:\./)?(?:";
    let squote_suffix = r")(?:/[^';&|$()`<>]+)*/?'";
    let squote_pattern = format!("{}{}{}", squote_prefix, dir_group, squote_suffix);

    // Combine all variants
    let safe_path_pattern = format!(
        "(?:{}|{}|{})",
        unquoted_pattern, dquote_pattern, squote_pattern
    );

    // One or more safe paths separated by whitespace.
    let safe_path_list = format!(r"{safe_path_pattern}(?:\s+{safe_path_pattern})*");

    let prefix = r"^\s*rm\s+";

    let rf_pattern =
        format!(r"{prefix}-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*(?:\s+--)?\s+{safe_path_list}\s*$");
    let fr_pattern =
        format!(r"{prefix}-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*(?:\s+--)?\s+{safe_path_list}\s*$");
    let separate_r_then_f = format!(
        r"{prefix}(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f(?:\s+--)?\s+{safe_path_list}\s*$"
    );
    let separate_f_then_r = format!(
        r"{prefix}(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR](?:\s+--)?\s+{safe_path_list}\s*$"
    );
    // Long flag patterns: only allow other flags (not directory arguments) between
    // --recursive and --force. This prevents commands like "rm --recursive foo --force target/"
    // from being allowed (where "foo" would also be deleted).
    //
    // - flags_before: zero or more flags each followed by whitespace (comes after prefix's \s+)
    // - flags_between_*: flags between the two key flags, using negative lookahead to avoid
    //   greedily consuming the terminating flag (which would cause the pattern to fail)
    let flags_before = r"(?:--?[a-zA-Z][-a-zA-Z0-9]*\s+)*";
    let flags_between_to_force = r"(?:\s+(?!--force\b)--?[a-zA-Z][-a-zA-Z0-9]*)*";
    let flags_between_to_recursive = r"(?:\s+(?!--recursive\b)--?[a-zA-Z][-a-zA-Z0-9]*)*";
    let recursive_force_pattern = format!(
        r"{prefix}{flags_before}--recursive{flags_between_to_force}\s+--force(?:\s+--)?\s+{safe_path_list}\s*$"
    );
    let force_recursive_pattern = format!(
        r"{prefix}{flags_before}--force{flags_between_to_recursive}\s+--recursive(?:\s+--)?\s+{safe_path_list}\s*$"
    );

    vec![
        make_safe_pattern("safe-cleanup-rf", rf_pattern),
        make_safe_pattern("safe-cleanup-fr", fr_pattern),
        make_safe_pattern("safe-cleanup-r-f", separate_r_then_f),
        make_safe_pattern("safe-cleanup-f-r", separate_f_then_r),
        make_safe_pattern("safe-cleanup-recursive-force", recursive_force_pattern),
        make_safe_pattern("safe-cleanup-force-recursive", force_recursive_pattern),
    ]
}

/// Escape regex special characters in a string.
fn regex_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\'
            | '-' => {
                escaped.push('\\');
                escaped.push(c);
            }
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Create a `SafePattern` from a name and regex string.
fn make_safe_pattern(name: &'static str, pattern: String) -> SafePattern {
    SafePattern {
        regex: crate::packs::regex_engine::LazyCompiledRegex::new_owned(pattern),
        name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack() -> Pack {
        create_pack()
    }

    // =========================================================================
    // Allowed commands (safe patterns should match)
    // =========================================================================

    #[test]
    fn allows_rm_rf_target() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf target/"),
            "rm -rf target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf target"),
            "rm -rf target should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./target/"),
            "rm -rf ./target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./target"),
            "rm -rf ./target should be allowed"
        );
    }

    #[test]
    fn allows_rm_fr_target() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -fr target/"),
            "rm -fr target/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_dist() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf dist/"),
            "rm -rf dist/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./dist/"),
            "rm -rf ./dist/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_node_modules() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf node_modules/"),
            "rm -rf node_modules/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -rf ./node_modules"),
            "rm -rf ./node_modules should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_build() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf build/"),
            "rm -rf build/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_pycache() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf __pycache__/"),
            "rm -rf __pycache__/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_next() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf .next/"),
            "rm -rf .next/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_with_subdirs() {
        let pack = pack();
        // Subdirectories of allowed dirs should also be allowed
        assert!(
            pack.matches_safe("rm -rf target/debug/"),
            "rm -rf target/debug/ should be allowed"
        );
    }

    #[test]
    fn allows_separate_flags() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -r -f target/"),
            "rm -r -f target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -f -r target/"),
            "rm -f -r target/ should be allowed"
        );
    }

    #[test]
    fn allows_long_flags() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm --recursive --force target/"),
            "rm --recursive --force target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm --force --recursive target/"),
            "rm --force --recursive target/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_cache() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf .cache/"),
            "rm -rf .cache/ should be allowed"
        );
    }

    #[test]
    fn allows_rm_rf_vendor() {
        let pack = pack();
        assert!(
            pack.matches_safe("rm -rf vendor/"),
            "rm -rf vendor/ should be allowed"
        );
    }

    // =========================================================================
    // Blocked commands (safe patterns should NOT match)
    // =========================================================================

    #[test]
    fn blocks_absolute_path() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf /target/"),
            "rm -rf /target/ (absolute) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf /home/user/target/"),
            "rm -rf /home/user/target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_home_path() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf ~/target/"),
            "rm -rf ~/target/ (home) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf ~user/target/"),
            "rm -rf ~user/target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_path_traversal_prefix() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf ../target/"),
            "rm -rf ../target/ (traversal) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf ../../target/"),
            "rm -rf ../../target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_embedded_path_traversal() {
        let pack = pack();
        assert!(
            !pack.matches_safe("rm -rf foo/../target/"),
            "rm -rf foo/../target/ (embedded traversal) should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf ./foo/../target/"),
            "rm -rf ./foo/../target/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_non_allowed_directories() {
        let pack = pack();
        // Random directories are NOT in the allowlist
        assert!(
            !pack.matches_safe("rm -rf src/"),
            "rm -rf src/ should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf data/"),
            "rm -rf data/ should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf important/"),
            "rm -rf important/ should NOT be allowed"
        );
    }

    #[test]
    fn blocks_target_as_suffix() {
        let pack = pack();
        // "target" as part of a larger directory name should NOT match
        assert!(
            !pack.matches_safe("rm -rf mytarget/"),
            "rm -rf mytarget/ should NOT be allowed"
        );
        assert!(
            !pack.matches_safe("rm -rf target-old/"),
            "rm -rf target-old/ should NOT be allowed (contains - after target)"
        );
    }

    #[test]
    fn blocks_plain_rm() {
        let pack = pack();
        // rm without -rf should not match (this pack is specifically for rm -rf)
        assert!(
            !pack.matches_safe("rm target/"),
            "rm target/ (no -rf) should NOT be allowed by this pack"
        );
        assert!(
            !pack.matches_safe("rm -r target/"),
            "rm -r target/ (no -f) should NOT be allowed by this pack"
        );
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn handles_case_sensitivity() {
        let pack = pack();
        // Directory names are case-sensitive
        assert!(
            !pack.matches_safe("rm -rf TARGET/"),
            "rm -rf TARGET/ should NOT be allowed (case sensitive)"
        );
        assert!(
            !pack.matches_safe("rm -rf Target/"),
            "rm -rf Target/ should NOT be allowed (case sensitive)"
        );
    }

    #[test]
    fn allows_uppercase_r_flag() {
        let pack = pack();
        // -R is equivalent to -r in rm
        assert!(
            pack.matches_safe("rm -Rf target/"),
            "rm -Rf target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -fR target/"),
            "rm -fR target/ should be allowed"
        );
    }

    #[test]
    fn pack_id_is_correct() {
        let pack = pack();
        assert_eq!(pack.id, "safe.cleanup");
    }

    #[test]
    fn pack_has_rm_keyword() {
        let pack = pack();
        assert!(
            pack.keywords.contains(&"rm"),
            "pack should have 'rm' keyword"
        );
    }

    #[test]
    fn pack_has_no_destructive_patterns() {
        let pack = pack();
        assert!(
            pack.destructive_patterns.is_empty(),
            "safe.cleanup should only have safe patterns, no destructive ones"
        );
    }

    #[test]
    fn allows_multiple_safe_dirs_in_one_command() {
        let pack = pack();
        // Multi-path commands are only allowed when ALL paths are in the allowlist.
        // This ensures "rm -rf target/ /etc" is blocked even though target/ is safe.
        assert!(
            pack.matches_safe("rm -rf target/ dist/"),
            "rm -rf target/ dist/ should be allowed (both dirs are in allowlist)"
        );
    }

    #[test]
    fn blocks_mixed_safe_and_unsafe_dirs() {
        let pack = pack();
        // If ANY path is not in the allowlist, the command should not match the safe pattern.
        assert!(
            !pack.matches_safe("rm -rf target/ src/"),
            "rm -rf target/ src/ should NOT be allowed (src/ not in allowlist)"
        );
        assert!(
            !pack.matches_safe("rm -rf target/ /etc/"),
            "rm -rf target/ /etc/ should NOT be allowed (absolute path)"
        );
    }

    #[test]
    fn blocks_trailing_path_traversal() {
        let pack = pack();
        // Trailing .. should be blocked (would delete parent directory)
        assert!(
            !pack.matches_safe("rm -rf target/.."),
            "rm -rf target/.. should NOT be allowed (path traversal)"
        );
        assert!(
            !pack.matches_safe("rm -rf target/../"),
            "rm -rf target/../ should NOT be allowed (path traversal)"
        );
        assert!(
            !pack.matches_safe("rm -rf target/../foo"),
            "rm -rf target/../foo should NOT be allowed (path traversal)"
        );
    }

    #[test]
    fn blocks_dirs_between_long_flags() {
        let pack = pack();
        // Security: directories between --recursive and --force must not be allowed,
        // as they would also be deleted. Only other flags are permitted between them.
        assert!(
            !pack.matches_safe("rm --recursive foo --force target/"),
            "rm --recursive foo --force target/ should NOT be allowed (foo between flags)"
        );
        assert!(
            !pack.matches_safe("rm --recursive /etc --force target/"),
            "rm --recursive /etc --force target/ should NOT be allowed (/etc between flags)"
        );
        assert!(
            !pack.matches_safe("rm --force src --recursive target/"),
            "rm --force src --recursive target/ should NOT be allowed (src between flags)"
        );
    }

    #[test]
    fn allows_flags_between_long_flags() {
        let pack = pack();
        // Other flags (not directories) between --recursive and --force are fine
        assert!(
            pack.matches_safe("rm --verbose --recursive --force target/"),
            "rm --verbose --recursive --force target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm --recursive --verbose --force target/"),
            "rm --recursive --verbose --force target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm --force --verbose --recursive target/"),
            "rm --force --verbose --recursive target/ should be allowed"
        );
        assert!(
            pack.matches_safe("rm -v --recursive --force target/"),
            "rm -v --recursive --force target/ should be allowed"
        );
    }

    #[test]
    fn blocks_shell_injection_in_path() {
        let pack = pack();
        // Security: Paths containing shell injection sequences must not be matched as safe subpaths.
        // If matched, the outer rm would be allowed, but the shell would execute the inner command first.

        // With spaces (already blocked by \s exclusion)
        assert!(
            !pack.matches_safe("rm -rf target/$(rm -rf /)"),
            "rm -rf target/$(rm -rf /) should NOT be allowed (command injection)"
        );

        // Without spaces (previously allowed!)
        assert!(
            !pack.matches_safe("rm -rf target/$(reboot)"),
            "rm -rf target/$(reboot) should NOT be allowed (command injection no spaces)"
        );
        assert!(
            !pack.matches_safe("rm -rf target/`reboot`"),
            "rm -rf target/`reboot` should NOT be allowed (command injection no spaces)"
        );
    }

    #[test]
    fn allows_quoted_paths() {
        let pack = pack();
        
        // Double quotes
        assert!(pack.matches_safe(r#"rm -rf "target""#));
        assert!(pack.matches_safe(r#"rm -rf "target/""#));
        assert!(pack.matches_safe(r#"rm -rf "target/debug""#));
        assert!(pack.matches_safe(r#"rm -rf "./target""#));
        
        // Single quotes
        assert!(pack.matches_safe(r"rm -rf 'target'"));
        assert!(pack.matches_safe(r"rm -rf 'target/'"));
        assert!(pack.matches_safe(r"rm -rf 'target/debug'"));
        assert!(pack.matches_safe(r"rm -rf './target'"));
        
        // Mixed quotes in one command (e.g. rm -rf "target" 'dist')
        assert!(pack.matches_safe(r#"rm -rf "target" 'dist'"#));
    }

    #[test]
    fn blocks_traversal_inside_quotes() {
        let pack = pack();
        
        // Double quotes
        assert!(!pack.matches_safe(r#"rm -rf "target/..""#));
        assert!(!pack.matches_safe(r#"rm -rf "target/../""#));
        assert!(!pack.matches_safe(r#"rm -rf "target/../foo""#));
        
        // Single quotes
        assert!(!pack.matches_safe(r"rm -rf 'target/..'"));
        assert!(!pack.matches_safe(r"rm -rf 'target/../'"));
        assert!(!pack.matches_safe(r"rm -rf 'target/../foo'"));
    }

    #[test]
    fn allows_spaces_inside_quotes() {
        let pack = pack();
        // Although standard build dirs don't have spaces, the regex allows subpaths with spaces if quoted
        assert!(pack.matches_safe(r#"rm -rf "target/foo bar""#));
        assert!(pack.matches_safe(r"rm -rf 'target/foo bar'"));
    }

    #[test]
    fn blocks_injection_inside_quotes() {
        let pack = pack();
        // Injection characters are blocked even inside quotes to be safe
        assert!(!pack.matches_safe(r#"rm -rf "target/$(reboot)""#));
        assert!(!pack.matches_safe(r"rm -rf 'target/$(reboot)'"));
        assert!(!pack.matches_safe(r#"rm -rf "target/foo;bar""#));
    }
}
