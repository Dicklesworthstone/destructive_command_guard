//! Cross-pack regression corpus (issue #289 part D).
//!
//! The per-rule corpus in `tests/corpus/{true,false}_positives/` evaluates
//! against the *default-enabled, platform-dependent* pack set. That leaves
//! three holes:
//!
//! 1. Opt-in packs are never exercised at all.
//! 2. `windows.*` cases never run on unix CI.
//! 3. Issue regressions live as inline unit tests next to the one rule that was
//!    patched, so a shape that false-positived under one rule is never re-asked
//!    of the others.
//!
//! The motivating example: `time foo` denied under `cdn.cloudflare_workers`
//! even after the #257 fix taught the *sanitizer* about `time` — nobody
//! re-asked the wrangler resolver (#283).
//!
//! This suite closes that. Every case in `tests/corpus/cross_pack_fp/` is
//! evaluated with **every registry pack force-enabled** (including `windows.*`
//! on unix) across every shell dialect the case permits.
//!
//! # Case format (TOML)
//!
//! ```toml
//! [[case]]
//! description = "chmod 600 then grep -rn: the -rn belongs to grep"
//! command = "chmod 600 /root/.ssh/x && grep -rn foo /etc/ssh/"
//! expected = "allow"              # or "deny" for a true-positive control
//! issue = 287                     # source issue (0 = no single issue)
//! rule_id = "core.git:reset-hard" # optional; asserted on deny cases
//! dialects = ["posix", "unknown"] # optional; default = all four
//! known_failing = true            # optional; reported but tolerated
//! known_failing_reason = "..."    # required when known_failing = true
//! known_failing_dialects = ["ps"] # optional; default = every dialect the
//!                                 # case runs under
//! ```
//!
//! `known_failing` exists because this suite is expected to *find* bugs: a
//! benign shape that still denies under some opt-in pack is a real false
//! positive owned by that pack, not something this corpus may weaken away. Such
//! cases are printed prominently and, if they ever start passing, the suite
//! fails so the marker gets removed. `known_failing_dialects` keeps the
//! tolerance as narrow as the bug: a shape that only false-positives under the
//! PowerShell dialect stays strictly asserted everywhere else.
//!
//! # Running
//!
//! ```bash
//! cargo test --test cross_pack_corpus
//! # dump every observed rule id (useful when adding controls):
//! DCG_CROSS_PACK_DUMP=1 cargo test --test cross_pack_corpus -- --nocapture
//! ```

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::packs::test_helpers::EvalSnapshot;
use destructive_command_guard::{Config, LayeredAllowlist};

/// All four dialects, in a stable order.
const ALL_DIALECTS: [(&str, ShellDialect); 4] = [
    ("posix", ShellDialect::Posix),
    ("ps", ShellDialect::PowerShell),
    ("cmd", ShellDialect::Cmd),
    ("unknown", ShellDialect::Unknown),
];

#[derive(Debug, Clone, serde::Deserialize)]
struct CrossPackCase {
    description: String,
    command: String,
    expected: String,
    #[serde(default)]
    issue: u32,
    #[serde(default)]
    rule_id: Option<String>,
    #[serde(default)]
    dialects: Option<Vec<String>>,
    #[serde(default)]
    known_failing: bool,
    #[serde(default)]
    known_failing_reason: Option<String>,
    #[serde(default)]
    known_failing_dialects: Option<Vec<String>>,
}

impl CrossPackCase {
    /// Whether a failure under `dialect_name` is a recorded, tolerated bug.
    fn tolerates(&self, dialect_name: &str) -> bool {
        self.known_failing
            && self
                .known_failing_dialects
                .as_ref()
                .is_none_or(|names| names.iter().any(|name| name == dialect_name))
    }
}

#[derive(Debug, serde::Deserialize)]
struct CrossPackFile {
    #[serde(rename = "case")]
    cases: Vec<CrossPackCase>,
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/cross_pack_fp")
}

fn load_cases() -> Vec<(String, CrossPackCase)> {
    let dir = corpus_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();

    let mut cases = Vec::new();
    for path in paths {
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let file: CrossPackFile = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        for case in file.cases {
            cases.push((name.clone(), case));
        }
    }
    cases
}

/// The dialects a case must be replayed under.
fn case_dialects(case: &CrossPackCase) -> Vec<(&'static str, ShellDialect)> {
    let Some(names) = case.dialects.as_ref() else {
        return ALL_DIALECTS.to_vec();
    };
    names
        .iter()
        .map(|name| {
            ALL_DIALECTS
                .iter()
                .find(|(label, _)| *label == name.as_str())
                .copied()
                .unwrap_or_else(|| {
                    panic!(
                        "unknown dialect {name:?} in cross-pack corpus (expected one of \
                         posix, ps, cmd, unknown)"
                    )
                })
        })
        .collect()
}

/// Evaluation context with **every** registry pack force-enabled.
///
/// This deliberately bypasses [`Config::enabled_pack_ids`]: the default set is
/// platform-dependent and omits opt-in packs, which is exactly the coverage
/// hole this suite exists to close.
struct AllPacks {
    keywords: Vec<&'static str>,
    ordered: Vec<String>,
    index: Option<destructive_command_guard::packs::EnabledKeywordIndex>,
    overrides: destructive_command_guard::config::CompiledOverrides,
    allowlists: LayeredAllowlist,
    heredoc: destructive_command_guard::config::HeredocSettings,
}

impl AllPacks {
    fn new() -> Self {
        let enabled: std::collections::HashSet<String> = REGISTRY
            .all_pack_ids()
            .into_iter()
            .map(str::to_string)
            .collect();
        let ordered = REGISTRY.expand_enabled_ordered(&enabled);
        let keywords = REGISTRY.collect_enabled_keywords(&enabled);
        let index = REGISTRY.build_enabled_keyword_index(&ordered);
        let config = Config::default();
        Self {
            keywords,
            ordered,
            index,
            overrides: config.overrides.compile(),
            allowlists: LayeredAllowlist::default(),
            heredoc: config.heredoc_settings(),
        }
    }

    fn eval(&self, command: &str, dialect: ShellDialect) -> EvalSnapshot {
        let result = evaluate_command_with_pack_order_at_path_in_dialect(
            command,
            &self.keywords,
            &self.ordered,
            self.index.as_ref(),
            &self.overrides,
            &self.allowlists,
            &self.heredoc,
            None,
            dialect,
        );
        EvalSnapshot::from_result(command, &result)
    }
}

/// Human-readable attribution for a failure message.
fn attribution(snapshot: &EvalSnapshot) -> String {
    snapshot
        .rule_id
        .clone()
        .unwrap_or_else(|| match (&snapshot.pack_id, &snapshot.pattern_name) {
            (Some(pack), None) => format!("{pack}:<unnamed>"),
            (None, Some(pattern)) => format!("<unknown pack>:{pattern}"),
            _ => "<no rule attribution>".to_string(),
        })
}

/// Check one case under one dialect. `Ok(())` means the case behaved.
fn check(
    all: &AllPacks,
    case: &CrossPackCase,
    dialect_name: &str,
    dialect: ShellDialect,
) -> Result<(), String> {
    let snapshot = all.eval(&case.command, dialect);

    if std::env::var_os("DCG_CROSS_PACK_DUMP").is_some() {
        println!(
            "[dump] {dialect_name:>7} {decision:>13} {rule:<48} {command:?}",
            decision = snapshot.decision,
            rule = attribution(&snapshot),
            command = case.command,
        );
    }

    match case.expected.as_str() {
        "allow" => {
            if snapshot.decision == "allow" {
                Ok(())
            } else {
                Err(format!(
                    "expected allow, got {decision} via {rule} (mode {mode:?}, reason {reason:?})",
                    decision = snapshot.decision,
                    rule = attribution(&snapshot),
                    mode = snapshot.effective_mode,
                    reason = snapshot.reason_preview,
                ))
            }
        }
        "deny" => {
            if snapshot.decision != "deny" {
                return Err(format!(
                    "expected deny, got {decision} (no pack claimed this command)",
                    decision = snapshot.decision,
                ));
            }
            match case.rule_id.as_deref() {
                Some(expected) if snapshot.rule_id.as_deref() != Some(expected) => Err(format!(
                    "denied as expected but attributed to {actual}, expected {expected}",
                    actual = attribution(&snapshot),
                )),
                _ => Ok(()),
            }
        }
        other => Err(format!(
            "invalid `expected` value {other:?} (must be \"allow\" or \"deny\")"
        )),
    }
}

// =============================================================================
// Tests
// =============================================================================

/// The corpus must stay well-formed: this is what keeps a typo from silently
/// deleting coverage.
#[test]
fn cross_pack_corpus_is_well_formed() {
    let cases = load_cases();
    assert!(
        cases.len() >= 50,
        "cross-pack corpus shrank unexpectedly ({} cases); every seeded issue \
         regression must stay in-tree",
        cases.len()
    );

    let mut seen = std::collections::HashSet::new();
    let mut issues = std::collections::BTreeSet::new();
    for (file, case) in &cases {
        assert!(
            matches!(case.expected.as_str(), "allow" | "deny"),
            "[{file}] {}: invalid expected {:?}",
            case.description,
            case.expected
        );
        assert!(
            !case.description.trim().is_empty(),
            "[{file}] case with empty description"
        );
        assert!(
            !case.known_failing || case.known_failing_reason.is_some(),
            "[{file}] {}: known_failing requires known_failing_reason",
            case.description
        );
        // Panics on an unknown dialect name.
        let dialects = case_dialects(case);
        if let Some(tolerated) = case.known_failing_dialects.as_ref() {
            assert!(
                case.known_failing,
                "[{file}] {}: known_failing_dialects without known_failing",
                case.description
            );
            for name in tolerated {
                assert!(
                    dialects.iter().any(|(label, _)| label == name),
                    "[{file}] {}: known_failing_dialects lists {name:?}, which the \
                     case never runs under",
                    case.description
                );
            }
        }
        assert!(
            seen.insert((case.command.clone(), case.expected.clone())),
            "[{file}] duplicate case command: {:?}",
            case.command
        );
        if case.issue != 0 {
            issues.insert(case.issue);
        }
    }

    // Every issue named in #289 §D that had an in-tree repro to copy from.
    for issue in [246, 273, 277, 279, 281, 283, 285, 287] {
        assert!(
            issues.contains(&issue),
            "cross-pack corpus lost its #{issue} coverage"
        );
    }

    println!(
        "cross-pack corpus: {} cases across {} issues",
        cases.len(),
        issues.len()
    );
}

/// The whole point: force-enable *every* pack, including opt-in and
/// `windows.*` packs that the default set omits on this platform.
#[test]
fn all_registry_packs_are_force_enabled() {
    let all = AllPacks::new();
    let registry_count = REGISTRY.all_pack_ids().len();
    assert_eq!(
        all.ordered.len(),
        registry_count,
        "every registry pack must be in the cross-pack evaluation order"
    );

    let default_enabled = Config::default().enabled_pack_ids();
    let default_ordered = REGISTRY.expand_enabled_ordered(&default_enabled);
    assert!(
        all.ordered.len() > default_ordered.len(),
        "the cross-pack pack set ({}) must be strictly larger than the default \
         set ({}) — otherwise this suite adds no coverage",
        all.ordered.len(),
        default_ordered.len()
    );

    assert!(
        all.ordered.iter().any(|id| id.starts_with("windows.")),
        "windows.* packs must be exercised even on non-Windows hosts"
    );

    println!(
        "cross-pack pack set: {} packs force-enabled (default set on this host: {})",
        all.ordered.len(),
        default_ordered.len()
    );
}

/// Replay every false-positive shape against every pack, in every dialect.
#[test]
fn cross_pack_false_positives_stay_allowed() {
    let all = AllPacks::new();
    let cases = load_cases();

    let mut checked = 0usize;
    let mut failures = Vec::new();
    let mut known_failures = Vec::new();
    let mut unexpectedly_passing = Vec::new();

    for (file, case) in &cases {
        if case.expected != "allow" {
            continue;
        }
        for (dialect_name, dialect) in case_dialects(case) {
            checked += 1;
            let outcome = check(&all, case, dialect_name, dialect);
            let label = format!(
                "[{file}] (#{issue}) {desc}\n    dialect: {dialect_name}\n    command: {command:?}",
                issue = case.issue,
                desc = case.description,
                command = case.command,
            );
            match (outcome, case.tolerates(dialect_name)) {
                (Err(msg), false) => failures.push(format!("{label}\n    {msg}")),
                (Err(msg), true) => known_failures.push(format!(
                    "{label}\n    {msg}\n    known_failing: {reason}",
                    reason = case.known_failing_reason.as_deref().unwrap_or("(none)"),
                )),
                (Ok(()), true) => unexpectedly_passing.push(label),
                (Ok(()), false) => {}
            }
        }
    }

    if !known_failures.is_empty() {
        println!(
            "\n=== KNOWN-FAILING cross-pack false positives ({}) ===",
            known_failures.len()
        );
        println!("These are real false-positive bugs owned by the matching pack.\n");
        for failure in &known_failures {
            println!("{failure}\n");
        }
    }

    let mut msg = String::new();
    if !failures.is_empty() {
        let _ = write!(
            msg,
            "\n{} of {checked} cross-pack false-positive check(s) denied:\n\n{}\n",
            failures.len(),
            failures.join("\n\n")
        );
    }
    if !unexpectedly_passing.is_empty() {
        let _ = write!(
            msg,
            "\n{} case(s) marked known_failing now pass — remove the marker:\n\n{}\n",
            unexpectedly_passing.len(),
            unexpectedly_passing.join("\n\n")
        );
    }
    assert!(msg.is_empty(), "{msg}");

    println!(
        "cross-pack false positives: {} of {checked} check(s) allowed under all packs \
         ({} known-failing)",
        checked - known_failures.len(),
        known_failures.len()
    );
}

/// The controls: without these, the false-positive suite would pass trivially
/// if every pack stopped matching anything.
#[test]
fn cross_pack_true_positive_controls_still_deny() {
    let all = AllPacks::new();
    let cases = load_cases();

    let mut checked = 0usize;
    let mut failures = Vec::new();
    let mut known_failures = Vec::new();

    for (file, case) in &cases {
        if case.expected != "deny" {
            continue;
        }
        for (dialect_name, dialect) in case_dialects(case) {
            checked += 1;
            let label = format!(
                "[{file}] (#{issue}) {desc}\n    dialect: {dialect_name}\n    command: {command:?}",
                issue = case.issue,
                desc = case.description,
                command = case.command,
            );
            if let Err(msg) = check(&all, case, dialect_name, dialect) {
                if case.tolerates(dialect_name) {
                    known_failures.push(format!("{label}\n    {msg}"));
                } else {
                    failures.push(format!("{label}\n    {msg}"));
                }
            }
        }
    }

    assert!(
        checked > 0,
        "cross-pack corpus lost its true-positive controls"
    );

    if !known_failures.is_empty() {
        println!(
            "\n=== KNOWN-FAILING cross-pack true-positive controls ({}) ===",
            known_failures.len()
        );
        for failure in &known_failures {
            println!("{failure}\n");
        }
    }

    assert!(
        failures.is_empty(),
        "\n{} of {checked} cross-pack true-positive control(s) failed:\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );

    println!("cross-pack true-positive controls: {checked} check(s) denied under all packs");
}
