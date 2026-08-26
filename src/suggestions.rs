//! Suggestions system for providing actionable guidance when commands are blocked.
//!
//! When DCG blocks a command, users need actionable guidance:
//! - What safer alternatives exist?
//! - How can they preview the effect first?
//! - How can they allowlist if intentional?
//!
//! This module provides:
//! - [`SuggestionKind`] enum categorizing types of suggestions
//! - [`Suggestion`] struct with actionable guidance
//! - [`SUGGESTION_REGISTRY`] static registry keyed by `rule_id`
//! - [`get_suggestions`] lookup function

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Type of suggestion to help the user.
///
/// Each kind represents a different strategy for helping users
/// work around blocked commands safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    /// "Run this first to preview the effect"
    /// e.g., "Run `git diff` before `git reset --hard`"
    PreviewFirst,

    /// "Use this safer alternative instead"
    /// e.g., "Use `git reset --soft` or `--mixed` instead of `--hard`"
    SaferAlternative,

    /// "Fix your workflow to avoid this situation"
    /// e.g., "Commit your changes before resetting"
    WorkflowFix,

    /// "Read the documentation for more context"
    /// e.g., "See: <https://git-scm.com/docs/git-reset>"
    Documentation,

    /// "How to allowlist this specific rule"
    /// e.g., "To allow: `dcg allow core.git:reset-hard --reason '...'`"
    AllowSafely,
}

impl SuggestionKind {
    /// Returns a human-readable label for this suggestion kind.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::PreviewFirst => "Preview first",
            Self::SaferAlternative => "Safer alternative",
            Self::WorkflowFix => "Workflow fix",
            Self::Documentation => "Documentation",
            Self::AllowSafely => "Allow safely",
        }
    }
}

/// A suggestion providing actionable guidance for a blocked command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestion {
    /// Type of suggestion
    pub kind: SuggestionKind,

    /// Human-readable suggestion text
    pub text: String,

    /// Optional command the user can copy/paste
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Optional URL for documentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl Suggestion {
    /// Create a new suggestion.
    #[must_use]
    pub fn new(kind: SuggestionKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            command: None,
            url: None,
        }
    }

    /// Add a command to copy/paste.
    #[must_use]
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Add a documentation URL.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

/// Registry of suggestions keyed by `rule_id` (e.g., `"core.git:reset-hard"`).
///
/// Rule IDs follow the format `{pack_id}:{pattern_name}`.
///
/// # Performance
///
/// - Lookup is O(1) via `HashMap`
/// - Returns static references (zero allocation on lookup)
/// - Initialized once on first access via `LazyLock`
pub static SUGGESTION_REGISTRY: LazyLock<HashMap<&'static str, Vec<Suggestion>>> =
    LazyLock::new(build_suggestion_registry);

/// Look up suggestions for a rule.
///
/// Returns `None` if no suggestions are registered for the given `rule_id`.
///
/// # Example
///
/// ```
/// use destructive_command_guard::suggestions::get_suggestions;
///
/// if let Some(suggestions) = get_suggestions("core.git:reset-hard") {
///     for s in suggestions {
///         println!("- {}", s.text);
///     }
/// }
/// ```
#[must_use]
pub fn get_suggestions(rule_id: &str) -> Option<&'static [Suggestion]> {
    SUGGESTION_REGISTRY.get(rule_id).map(Vec::as_slice)
}

/// Get the first suggestion of a specific kind for a rule.
#[must_use]
pub fn get_suggestion_by_kind(rule_id: &str, kind: SuggestionKind) -> Option<&'static Suggestion> {
    get_suggestions(rule_id).and_then(|suggestions| suggestions.iter().find(|s| s.kind == kind))
}

// ============================================================================
// Explanation Fallback System
// ============================================================================

/// Generate a fallback explanation when no explicit explanation is available.
///
/// The fallback is neutral, concise, and mentions:
/// - The matched pack and/or pattern name (when available)
/// - That the command matched a destructive pattern
/// - Points to `dcg explain` for details
///
/// # Arguments
///
/// * `pack_id` - The pack ID (e.g., "core.git")
/// * `pattern_name` - The pattern name (e.g., "reset-hard")
///
/// # Examples
///
/// ```
/// use destructive_command_guard::suggestions::fallback_explanation;
///
/// let exp = fallback_explanation(Some("core.git"), Some("reset-hard"));
/// assert!(exp.contains("core.git:reset-hard"));
/// assert!(exp.contains("dcg explain"));
/// ```
#[must_use]
pub fn fallback_explanation(pack_id: Option<&str>, pattern_name: Option<&str>) -> String {
    match (pack_id, pattern_name) {
        (Some(pack), Some(pattern)) => {
            format!(
                "This command matched the destructive pattern `{pack}:{pattern}`. \
                 Run `dcg explain` on this command for details and safer alternatives."
            )
        }
        (Some(pack), None) => {
            format!(
                "This command matched a destructive pattern in the `{pack}` pack. \
                 Run `dcg explain` on this command for details and safer alternatives."
            )
        }
        (None, Some(pattern)) => {
            format!(
                "This command matched the destructive pattern `{pattern}`. \
                 Run `dcg explain` on this command for details and safer alternatives."
            )
        }
        (None, None) => "This command matched a destructive pattern. \
             Run `dcg explain` on this command for details and safer alternatives."
            .to_string(),
    }
}

/// Get an explanation for a pattern, using the explicit explanation if available
/// or falling back to a generated explanation.
///
/// This function ensures no empty explanation sections in output.
///
/// # Arguments
///
/// * `explicit` - The explicit explanation from the pattern, if any
/// * `pack_id` - The pack ID for fallback generation
/// * `pattern_name` - The pattern name for fallback generation
///
/// # Examples
///
/// ```
/// use destructive_command_guard::suggestions::get_explanation;
///
/// // With explicit explanation
/// let exp = get_explanation(Some("Don't do this!"), Some("core.git"), Some("reset-hard"));
/// assert_eq!(exp, "Don't do this!");
///
/// // Without explicit explanation - uses fallback
/// let exp = get_explanation(None, Some("core.git"), Some("reset-hard"));
/// assert!(exp.contains("core.git:reset-hard"));
/// ```
#[must_use]
pub fn get_explanation(
    explicit: Option<&str>,
    pack_id: Option<&str>,
    pattern_name: Option<&str>,
) -> String {
    match explicit {
        Some(exp) if !exp.trim().is_empty() => exp.to_string(),
        _ => fallback_explanation(pack_id, pattern_name),
    }
}

/// Build the suggestion registry.
///
/// This function is called once by `LazyLock` to initialize the registry.
fn build_suggestion_registry() -> HashMap<&'static str, Vec<Suggestion>> {
    let mut m = HashMap::new();
    register_core_git_suggestions(&mut m);
    register_core_filesystem_suggestions(&mut m);
    register_heredoc_suggestions(&mut m);
    register_docker_suggestions(&mut m);
    register_kubernetes_suggestions(&mut m);
    register_database_suggestions(&mut m);
    register_system_permissions_suggestions(&mut m);
    m
}

/// Register suggestions for core.git pack rules.
#[allow(clippy::too_many_lines)]
fn register_core_git_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    m.insert(
        "core.git:reset-hard",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `git diff` and `git status` to see what would be lost",
            )
            .with_command("git diff && git status"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git reset --soft` or `--mixed` to preserve changes",
            )
            .with_command("git reset --soft HEAD~1"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Consider using `git stash` to save changes temporarily",
            )
            .with_command("git stash"),
            Suggestion::new(
                SuggestionKind::Documentation,
                "See Git documentation for reset options",
            )
            .with_url("https://git-scm.com/docs/git-reset"),
        ],
    );

    m.insert(
        "core.git:clean-force",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `git clean -n` to preview what would be deleted",
            )
            .with_command("git clean -n -fd"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git clean -i` for interactive mode to select files",
            )
            .with_command("git clean -i"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Add patterns to .gitignore instead of cleaning",
            ),
        ],
    );

    // Force push patterns (--force and -f variants)
    let force_push_suggestions = vec![
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use `git push --force-with-lease` to prevent overwriting others' work",
        )
        .with_command("git push --force-with-lease"),
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Run `git log origin/branch..HEAD` to see commits being pushed",
        ),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Coordinate with team before force pushing to shared branches",
        ),
    ];
    m.insert("core.git:push-force-long", force_push_suggestions.clone());
    m.insert("core.git:push-force-short", force_push_suggestions);

    // Checkout patterns that discard changes
    let checkout_discard_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Run `git status` and `git diff` to see uncommitted changes that would be lost",
        )
        .with_command("git status && git diff"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Commit or stash changes before discarding",
        )
        .with_command("git stash"),
    ];
    m.insert(
        "core.git:checkout-discard",
        checkout_discard_suggestions.clone(),
    );
    m.insert(
        "core.git:checkout-ref-discard",
        checkout_discard_suggestions,
    );

    m.insert(
        "core.git:branch-force-delete",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Review branch tips and upstream tracking state with `git branch -vv`",
            )
            .with_command("git branch -vv"),
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Compare Git's merged and unmerged branch classifications",
            )
            .with_command("git branch --merged && git branch --no-merged"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Ask the user for explicit approval before deleting or force-moving a branch ref",
            ),
        ],
    );

    m.insert(
        "core.git:branch-dynamic-token",
        vec![
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Resolve the dynamic value first, then pass the literal branch name — quoting \
                 keeps a *creation* safe, but a command that keeps a deletion/force flag like \
                 -D stays gated on its own merits",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "For a creation: quote the branch name so the expansion stays a single non-flag word",
            )
            .with_command("git branch \"backup-$(date +%s)\""),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "For a creation: add `--` to end option parsing so expanded output cannot become a flag",
            )
            .with_command("git branch -- <name>"),
        ],
    );

    m.insert(
        "core.git:git-alias-semantic-unverified",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Inspect the effective alias definition before invoking it",
            )
            .with_command("git config --show-origin --get-regexp '^alias\\.'"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Invoke the intended built-in Git subcommand directly after reviewing the alias expansion",
            ),
        ],
    );

    // restore worktree patterns
    let restore_worktree_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Run `git diff` to see uncommitted changes that would be lost",
        )
        .with_command("git diff"),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use `git stash` to save changes (retrievable later) instead of discarding",
        )
        .with_command("git stash"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Commit changes before discarding to preserve them in history",
        )
        .with_command("git commit -m 'WIP: saving changes'"),
    ];
    m.insert(
        "core.git:restore-worktree",
        restore_worktree_suggestions.clone(),
    );
    m.insert(
        "core.git:restore-worktree-explicit",
        restore_worktree_suggestions,
    );

    // reset --merge
    m.insert(
        "core.git:reset-merge",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `git status` to see uncommitted changes that could be lost",
            )
            .with_command("git status"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git merge --abort` to cleanly abort an in-progress merge",
            )
            .with_command("git merge --abort"),
        ],
    );

    // stash destruction
    m.insert(
        "core.git:stash-drop",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List stashes with `git stash list` and view contents with `git stash show -p`",
            )
            .with_command("git stash list"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Apply the stash first with `git stash apply` before dropping",
            )
            .with_command("git stash apply"),
        ],
    );

    m.insert(
        "core.git:stash-clear",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List all stashes with `git stash list` to review what would be deleted",
            )
            .with_command("git stash list"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Drop stashes individually with `git stash drop` for more control",
            )
            .with_command("git stash drop stash@{0}"),
        ],
    );
}

/// Recursive rm rules whose target is a root, home, or sensitive system path.
/// Their safer alternative must narrow the scope; repeating any recursive rm
/// here would merely restate the catastrophic operation.
const ROOT_HOME_RECURSIVE_RM_SUGGESTION_RULES: &[&str] = &[
    "core.filesystem:rm-rf-root-home",
    "core.filesystem:rm-r-f-separate-root-home",
    "core.filesystem:rm-recursive-force-root-home",
    "core.filesystem:rm-recursive-root-home",
];

/// Recursive rm rules for non-root targets. Their operand can still be a
/// regular file, so every command must accept either a file or a directory.
const GENERAL_RECURSIVE_RM_SUGGESTION_RULES: &[&str] = &[
    "core.filesystem:rm-rf-general",
    "core.filesystem:rm-r-f-separate",
    "core.filesystem:rm-recursive-force-long",
    "core.filesystem:rm-recursive-general",
];

/// A terminal `find -delete` preview must preserve the original expression and
/// its implicit depth-first traversal. Arbitrary boolean expressions have no
/// guaranteed exact mechanical rewrite.
const FIND_DELETE_SUGGESTION_RULES: &[&str] = &[
    "core.filesystem:find-delete-root-home",
    "core.filesystem:find-delete-general",
];

/// `tar --remove-files` should remain an archive operation while preserving
/// its sources, not be translated into a recursive rm workflow.
const TAR_REMOVE_FILES_SUGGESTION_RULES: &[&str] = &[
    "core.filesystem:tar-remove-files-root-home",
    "core.filesystem:tar-remove-files-general",
];

/// Rules that destroy or overwrite one file. Their preview must accept a file
/// operand; a directory-only `find path/ ...` command is incorrect here.
const SINGLE_FILE_SUGGESTION_RULES: &[&str] = &[
    "core.filesystem:unlink-root-home",
    "core.filesystem:unlink-general",
    "core.filesystem:truncate-zero-root-home",
    "core.filesystem:truncate-zero-general",
    "core.filesystem:shred-root-home",
    "core.filesystem:shred-general",
    "core.filesystem:dd-overwrite-root-home",
    "core.filesystem:dd-overwrite-general",
];

/// Move rules can target either a file or a directory, so their preview uses
/// `ls -ld` on the object itself and never assumes a tree.
const MOVED_PATH_SUGGESTION_RULES: &[&str] = &[
    "core.filesystem:mv-sensitive-source-root-home",
    "core.filesystem:mv-dynamic-path",
];

/// Register suggestions for core.filesystem pack rules.
fn register_core_filesystem_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    m.insert(
        "core.filesystem:sed-exec-unverified",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Render and inspect the exact shell command before passing it to GNU sed's `e` command or `s///e` flag",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use a non-executing sed substitution and run any reviewed shell command as a separate step",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Replace `&` and backreferences in an executable replacement with a literal, bounded command when execution is truly required",
            ),
        ],
    );

    // This registry feeds scan/trace output independently of the authored
    // PatternSuggestion guidance attached to hook denials. Root/home matches
    // must narrow the target instead of advertising another recursive delete.
    let root_home_recursive_rm_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Preview the target path with `find path -maxdepth 2 -print` before deleting",
        )
        .with_command("find path -maxdepth 2 -print"),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Copy one specific, explicitly reviewed file or directory to a backup; `reviewed-path` must be non-root, non-home, and non-sensitive, never the blocked root, home, or sensitive target, and the original is preserved",
        )
        .with_command("cp -a reviewed-path /tmp/reviewed-backup"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Verify the backup first and require separate approval for any cleanup; never substitute the blocked root, home, or sensitive path itself",
        ),
    ];
    for &rule_id in ROOT_HOME_RECURSIVE_RM_SUGGESTION_RULES {
        m.insert(rule_id, root_home_recursive_rm_suggestions.clone());
    }

    let general_recursive_rm_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Preview the target path with `find path -maxdepth 2 -print` before deleting",
        )
        .with_command("find path -maxdepth 2 -print"),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use `rm -ri` only from an interactive terminal; with stdin closed (as under an agent hook), it deletes nothing and exits 0",
        )
        .with_command("rm -ri path"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Move to trash with `trash-put path` on Linux (trash-cli), or `mv path ~/.Trash/` on macOS",
        ),
    ];
    for &rule_id in GENERAL_RECURSIVE_RM_SUGGESTION_RULES {
        m.insert(rule_id, general_recursive_rm_suggestions.clone());
    }

    // A terminal -delete can be transformed into a depth-first read-only
    // preview. Inside an arbitrary boolean expression, delete success can
    // affect evaluation, so there is no universally exact textual rewrite.
    let find_delete_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "For a terminal `-delete` action, preserve every original search root, option, and predicate, retain or add `-depth`, then replace that terminal action with `-print`",
        ),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "When `-delete` is inside an arbitrary boolean expression, there is no guaranteed exact mechanical rewrite; construct and inspect a read-only expression manually",
        ),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Constrain both the find roots and predicates to a literal temp subtree before any separately approved deletion",
        ),
    ];
    for &rule_id in FIND_DELETE_SUGGESTION_RULES {
        m.insert(rule_id, find_delete_suggestions.clone());
    }

    let tar_remove_files_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Inspect the exact source operands before archiving or removing anything",
        )
        .with_command("ls -la source"),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Create the archive without `--remove-files` so every source is preserved",
        )
        .with_command("tar -cf archive.tar source"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Verify the archive in a separate step before considering any separately approved source cleanup",
        )
        .with_command("tar -tf archive.tar"),
    ];
    for &rule_id in TAR_REMOVE_FILES_SUGGESTION_RULES {
        m.insert(rule_id, tar_remove_files_suggestions.clone());
    }

    m.insert(
        "core.filesystem:cp-sensitive-then-delete",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Inspect the exact sensitive source before copying it",
            )
            .with_command("ls -ld source"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Run the archive copy without chaining any deletion, then inspect the backup separately",
            )
            .with_command("cp -a source backup"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Verify source and backup in a separate step before considering cleanup",
            )
            .with_command("diff -r source backup"),
        ],
    );

    m.insert(
        "core.filesystem:ln-symlink-sensitive-then-delete",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Inspect where the link points before removing anything",
            )
            .with_command("readlink link"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Unlink only the symlink itself; never recursively remove the link target",
            )
            .with_command("unlink link"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Create, inspect, and clean up a symlink in separate commands without appending `/.` to it",
            ),
        ],
    );

    m.insert(
        "core.filesystem:rsync-sensitive-then-delete",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Preview a transfer to a fresh, non-existing backup destination without changing files or chaining deletion",
            )
            .with_command("rsync -a --dry-run --ignore-existing source fresh-backup/"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Copy to a fresh, non-existing backup destination without the later deletion; `--ignore-existing` prevents overwriting if that path unexpectedly exists",
            )
            .with_command("rsync -a --ignore-existing source fresh-backup/"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Verify source and the fresh backup in a separate step before considering cleanup",
            )
            .with_command("diff -r source fresh-backup"),
        ],
    );

    // A home-directory glob is a shell-selected file set, not necessarily a
    // directory tree. Preview the expansion itself instead of appending `/`.
    m.insert(
        "core.filesystem:rm-glob-home",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Preview the exact glob expansion with `ls -la path-pattern` before deleting",
            )
            .with_command("ls -la path-pattern"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Delete explicitly named files so the removal set is reviewable",
            )
            .with_command("rm path/file-one path/file-two"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Move reviewed matches with `trash-put` on Linux (trash-cli), or into `~/.Trash/` on macOS",
            ),
        ],
    );

    let single_file_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Inspect the file with `ls -la path` before deleting or overwriting it",
        )
        .with_command("ls -la path"),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Copy the file to a reviewed backup before unlinking or overwriting it",
        )
        .with_command("cp -p path path.bak"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Move a disposable file with `trash-put path` on Linux (trash-cli), or `mv path ~/.Trash/` on macOS",
        ),
    ];
    for &rule_id in SINGLE_FILE_SUGGESTION_RULES {
        m.insert(rule_id, single_file_suggestions.clone());
    }

    let moved_path_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Inspect the exact source and destination with `ls -ld path` before moving",
        )
        .with_command("ls -ld path"),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Copy to a literal backup path first, then verify the copy before any move",
        )
        .with_command("cp -a path path.bak"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Resolve dynamic paths to literal source and destination values in a separate review step",
        ),
    ];
    for &rule_id in MOVED_PATH_SUGGESTION_RULES {
        m.insert(rule_id, moved_path_suggestions.clone());
    }

    // The command word is assembled at runtime. Do not guess a platform or
    // repeat the unverified delete; make the executable and target reviewable.
    m.insert(
        "core.filesystem:rm-recursive-unverified",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Render and inspect the assembled executable, flags, and target as data before running it",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use a literal executable and literal target in a separate command so dcg can evaluate the exact operation",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Avoid a find -exec placeholder or PowerShell splat as the command word for recursive deletion",
            ),
        ],
    );

    // PowerShell guidance stays PowerShell-native and uses the runtime's own
    // cross-platform temp-directory resolver; never advertise Unix rm/trash.
    m.insert(
        "core.filesystem:powershell-remove-item-recursive",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List the item tree with `Get-ChildItem -Recurse path` before removing it",
            )
            .with_command("Get-ChildItem -Recurse path"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `Remove-Item -Recurse -WhatIf path` to preview without deleting",
            )
            .with_command("Remove-Item -Recurse -WhatIf path"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Move the tree aside with `Move-Item path (Join-Path ([IO.Path]::GetTempPath()) delete-me-reviewed)`",
            )
            .with_command(
                "Move-Item path (Join-Path ([IO.Path]::GetTempPath()) delete-me-reviewed)",
            ),
        ],
    );

    m.insert(
        "core.filesystem:rm-bare-glob",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List what the working-directory glob expands to before deleting anything",
            )
            .with_command("ls -la"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Delete explicitly named files so the removal set is reviewable",
            )
            .with_command("rm ./file-one ./file-two"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Constrain the glob to a reviewed shape such as `*.log` instead of every file",
            ),
        ],
    );
    m.insert(
        "core.filesystem:rm-bare-glob-root",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List the filesystem root before naming any one target",
            )
            .with_command("ls -la /"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Name one reviewed root-level file instead of the unbounded /* expansion",
            )
            .with_command("rm /specific-file"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Move one reviewed file aside first instead of deleting every root entry",
            )
            .with_command("mv /specific-file /tmp/delete-me-reviewed"),
        ],
    );

    // redirect-truncate-*: shell-syntax truncate-equivalent. These need
    // redirect-specific guidance; deletion suggestions read as a non sequitur
    // on a redirect denial (issues #316/#317).
    let redirect_truncate_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "Resolve and inspect the redirect target path before truncating it",
        ),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use append (`>>`) when preserving existing content is acceptable",
        ),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Redirect to a literal temp path instead of an expanded one",
        )
        .with_command("cmd > /tmp/scratch/out.log 2>&1"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Back up the target first if its current content matters: `cp target target.bak`",
        ),
    ];
    m.insert(
        "core.filesystem:redirect-truncate-root-home",
        redirect_truncate_suggestions.clone(),
    );
    m.insert(
        "core.filesystem:redirect-truncate-dynamic-path",
        redirect_truncate_suggestions,
    );
    m.insert(
        "core.filesystem:fork-bomb",
        vec![
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "There is no safe variant of a fork bomb; do not run it",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "To test process limits, use `ulimit -u` inside a disposable VM or container",
            ),
        ],
    );
}

/// Register suggestions for heredoc pattern rules.
///
/// Note: Rule IDs use the canonical `pack_id:pattern_name` format with colons,
/// matching the format used by `RuleId` in the allowlist module.
fn register_heredoc_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    m.insert(
        "heredoc.python:shutil_rmtree",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List directory contents with `os.listdir()` before removal",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `shutil.move()` to archive instead of delete",
            ),
        ],
    );

    m.insert(
        "heredoc.javascript:fs_rmsync",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Use `fs.readdirSync()` to list contents first",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Move files to a backup directory instead of deleting",
            ),
        ],
    );
}

/// Register suggestions for containers.docker pack rules.
#[allow(clippy::too_many_lines)]
fn register_docker_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    m.insert(
        "containers.docker:system-prune",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `docker system df` to see what would be affected",
            )
            .with_command("docker system df"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Prune specific resources: `docker container prune`, `docker image prune`",
            ),
        ],
    );

    m.insert(
        "containers.docker:volume-prune",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List volumes with `docker volume ls` to see what would be removed",
            )
            .with_command("docker volume ls"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Remove specific volumes with `docker volume rm <name>`",
            ),
        ],
    );

    m.insert(
        "containers.docker:network-prune",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List networks with `docker network ls` to see what would be removed",
            )
            .with_command("docker network ls"),
        ],
    );

    m.insert(
        "containers.docker:image-prune",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List dangling images with `docker images -f dangling=true`",
            )
            .with_command("docker images -f dangling=true"),
        ],
    );

    m.insert(
        "containers.docker:container-prune",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List stopped containers with `docker ps -a -f status=exited`",
            )
            .with_command("docker ps -a -f status=exited"),
        ],
    );

    m.insert(
        "containers.docker:rm-force",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Stop container first with `docker stop`, then `docker rm`",
            ),
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check container status with `docker ps -a`",
            )
            .with_command("docker ps -a"),
        ],
    );

    m.insert(
        "containers.docker:rmi-force",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check if image is in use with `docker ps -a --filter ancestor=<image>`",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Remove without force to see dependency errors first",
            ),
        ],
    );

    m.insert(
        "containers.docker:volume-rm",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Inspect volume with `docker volume inspect <name>` to verify contents",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up volume data before removing",
            ),
        ],
    );

    m.insert(
        "containers.docker:stop-all",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List running containers with `docker ps` to see what would be stopped",
            )
            .with_command("docker ps"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Stop specific containers by name instead of all",
            ),
        ],
    );
}

/// Register suggestions for kubernetes.kubectl pack rules.
#[allow(clippy::too_many_lines)]
fn register_kubernetes_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    m.insert(
        "kubernetes.kubectl:delete-namespace",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `kubectl get all -n <namespace>` to see all resources that would be deleted",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `kubectl delete <resource-type> --dry-run=client` to preview",
            )
            .with_command("kubectl delete namespace <name> --dry-run=client"),
        ],
    );

    m.insert(
        "kubernetes.kubectl:delete-all",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run with `--dry-run=client` to preview what would be deleted",
            )
            .with_command("kubectl delete <resource> --all --dry-run=client"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Delete specific resources by name instead of --all",
            ),
        ],
    );

    m.insert(
        "kubernetes.kubectl:delete-all-namespaces",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `kubectl get <resource> -A` to see what exists across namespaces",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Target a specific namespace with `-n <namespace>` instead of -A",
            ),
        ],
    );

    m.insert(
        "kubernetes.kubectl:drain-node",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List pods on node with `kubectl get pods --field-selector spec.nodeName=<node>`",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `kubectl cordon` first to prevent new pods, then drain",
            )
            .with_command("kubectl cordon <node>"),
        ],
    );

    m.insert(
        "kubernetes.kubectl:cordon-node",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check node status with `kubectl get node <node>`",
            ),
            Suggestion::new(
                SuggestionKind::Documentation,
                "Cordon marks node unschedulable; existing pods continue running",
            ),
        ],
    );

    m.insert(
        "kubernetes.kubectl:taint-noexecute",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List pods on node to see what would be evicted",
            )
            .with_command("kubectl get pods --field-selector spec.nodeName=<node>"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `NoSchedule` taint to prevent new pods without evicting existing ones",
            ),
        ],
    );

    m.insert(
        "kubernetes.kubectl:delete-workload",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Use `--dry-run=client` to preview the deletion",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Scale to 0 replicas first to gracefully stop pods",
            )
            .with_command("kubectl scale deployment <name> --replicas=0"),
        ],
    );

    m.insert(
        "kubernetes.kubectl:delete-pvc",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check PVC's reclaim policy with `kubectl get pv <pv-name> -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'`",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up data before deleting PVC if ReclaimPolicy is Delete",
            ),
        ],
    );

    m.insert(
        "kubernetes.kubectl:delete-pv",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check if PV is bound with `kubectl get pv <name>`",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Ensure data is backed up before deleting persistent volume",
            ),
        ],
    );

    m.insert(
        "kubernetes.kubectl:scale-to-zero",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check current replicas with `kubectl get deployment <name>`",
            ),
            Suggestion::new(
                SuggestionKind::Documentation,
                "Scaling to 0 stops all pods; use for maintenance or decommissioning",
            ),
        ],
    );

    m.insert(
        "kubernetes.kubectl:delete-force",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Remove --force --grace-period=0 to allow graceful termination",
            ),
            Suggestion::new(
                SuggestionKind::Documentation,
                "Force deletion skips graceful shutdown; use only for stuck resources",
            ),
        ],
    );
}

/// Register suggestions for database pack rules (`PostgreSQL`, `MongoDB`, `Redis`, `SQLite`).
#[allow(clippy::too_many_lines)]
fn register_database_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    // PostgreSQL suggestions
    m.insert(
        "database.postgresql:drop-database",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List databases with `\\l` in psql to verify target",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up with `pg_dump -Fc <database> > backup.dump` first",
            )
            .with_command("pg_dump -Fc <database> > backup.dump"),
        ],
    );

    m.insert(
        "database.postgresql:drop-table",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List tables with `\\dt` in psql to verify target",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up table with `pg_dump -t <table> <database>`",
            ),
        ],
    );

    m.insert(
        "database.postgresql:drop-schema",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List schema contents with `\\dn+` in psql",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up schema with `pg_dump -n <schema> <database>`",
            ),
        ],
    );

    m.insert(
        "database.postgresql:truncate-table",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check row count with `SELECT count(*) FROM <table>`",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up data with `COPY <table> TO '/tmp/backup.csv'` first",
            ),
        ],
    );

    m.insert(
        "database.postgresql:delete-without-where",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Add a WHERE clause to limit deletion scope",
            ),
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `SELECT count(*) FROM <table>` to see row count",
            ),
        ],
    );

    m.insert(
        "database.postgresql:dropdb-cli",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List databases with `psql -l` to verify target",
            )
            .with_command("psql -l"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up with `pg_dump` before dropping",
            ),
        ],
    );

    m.insert(
        "database.postgresql:pg-dump-clean",
        vec![
            Suggestion::new(
                SuggestionKind::Documentation,
                "The --clean flag drops objects before creating; be careful on restore",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Remove --clean flag to create without dropping existing objects",
            ),
        ],
    );

    // MongoDB suggestions
    m.insert(
        "database.mongodb:drop-database",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List databases with `show dbs` to verify target",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up with `mongodump --db <database>` first",
            )
            .with_command("mongodump --db <database>"),
        ],
    );

    m.insert(
        "database.mongodb:drop-collection",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List collections with `show collections` to verify target",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up with `mongoexport --collection <name>` first",
            ),
        ],
    );

    m.insert(
        "database.mongodb:delete-all",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check document count with `db.collection.countDocuments({})`",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Add filter criteria to `deleteMany()` to limit scope",
            ),
        ],
    );

    m.insert(
        "database.mongodb:mongorestore-drop",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Remove --drop flag to merge with existing data",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up existing data with `mongodump` before restoring with --drop",
            ),
        ],
    );

    m.insert(
        "database.mongodb:collection-drop",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check collection stats with `db.collection.stats()`",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Export collection with `mongoexport` before dropping",
            ),
        ],
    );

    // Redis suggestions
    m.insert(
        "database.redis:flushall",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check key counts per database with `INFO keyspace`",
            )
            .with_command("redis-cli INFO keyspace"),
            Suggestion::new(
                SuggestionKind::Documentation,
                "FLUSHALL deletes ALL keys in ALL databases; FLUSHDB affects only current database",
            ),
        ],
    );

    m.insert(
        "database.redis:flushdb",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check key count with `DBSIZE`",
            )
            .with_command("redis-cli DBSIZE"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Export keys with `redis-cli --scan` before flushing",
            ),
        ],
    );

    m.insert(
        "database.redis:debug-crash",
        vec![Suggestion::new(
            SuggestionKind::Documentation,
            "DEBUG SEGFAULT/CRASH will crash the Redis server; only use for testing",
        )],
    );

    m.insert(
        "database.redis:debug-sleep",
        vec![Suggestion::new(
            SuggestionKind::Documentation,
            "DEBUG SLEEP blocks the server; avoid in production",
        )],
    );

    m.insert(
        "database.redis:shutdown",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check connected clients with `CLIENT LIST`",
            )
            .with_command("redis-cli CLIENT LIST"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Use `BGSAVE` to persist data before shutdown",
            )
            .with_command("redis-cli BGSAVE"),
        ],
    );

    m.insert(
        "database.redis:config-dangerous",
        vec![Suggestion::new(
            SuggestionKind::Documentation,
            "CONFIG SET for dir/dbfilename can be exploited for arbitrary file writes",
        )],
    );

    // SQLite suggestions
    m.insert(
        "database.sqlite:drop-table",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List tables with `.tables` to verify target",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up database with `.backup <filename>` first",
            )
            .with_command(".backup backup.db"),
        ],
    );

    m.insert(
        "database.sqlite:delete-without-where",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Add a WHERE clause to limit deletion scope",
            ),
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check row count with `SELECT count(*) FROM <table>`",
            ),
        ],
    );

    m.insert(
        "database.sqlite:vacuum-into",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check if target file exists before VACUUM INTO",
            ),
            Suggestion::new(
                SuggestionKind::Documentation,
                "VACUUM INTO overwrites the target file if it exists",
            ),
        ],
    );

    m.insert(
        "database.sqlite:sqlite3-stdin",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Review the SQL file contents before executing",
            )
            .with_command("cat <file.sql>"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up database with `.backup` before running SQL from file",
            ),
        ],
    );

    // MySQL suggestions
    m.insert(
        "database.mysql:drop-database",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List databases with `SHOW DATABASES` to verify target",
            )
            .with_command("mysql -e 'SHOW DATABASES;'"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up with `mysqldump` before dropping",
            )
            .with_command("mysqldump -h host -u user -p <database> > backup.sql"),
        ],
    );

    m.insert(
        "database.mysql:drop-table",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List tables with `SHOW TABLES` to verify target",
            )
            .with_command("mysql -e 'SHOW TABLES FROM <database>;'"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up table with `mysqldump` before dropping",
            )
            .with_command("mysqldump -h host -u user -p <database> <table> > table_backup.sql"),
        ],
    );

    m.insert(
        "database.mysql:truncate-table",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check row count with `SELECT COUNT(*) FROM <table>`",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `DELETE FROM` for transactional safety (can be rolled back)",
            )
            .with_command("DELETE FROM <table>;  -- Slower but transactional"),
            Suggestion::new(
                SuggestionKind::Documentation,
                "MySQL's TRUNCATE is NOT transactional and cannot be rolled back",
            ),
        ],
    );

    m.insert(
        "database.mysql:delete-without-where",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Add a WHERE clause to limit deletion scope",
            )
            .with_command("DELETE FROM <table> WHERE <condition>;"),
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Run `SELECT COUNT(*) FROM <table>` to see row count",
            ),
        ],
    );

    m.insert(
        "database.mysql:mysqladmin-drop",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "List databases with `mysql -e 'SHOW DATABASES;'` to verify target",
            )
            .with_command("mysql -e 'SHOW DATABASES;'"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Back up with `mysqldump` before dropping",
            )
            .with_command("mysqldump -h host -u user -p <database> > backup.sql"),
        ],
    );

    m.insert(
        "database.mysql:mysqldump-add-drop-database",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Remove --add-drop-database flag for safer restores",
            )
            .with_command("mysqldump <database> > backup.sql"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Restore to a new database first, verify, then swap",
            ),
        ],
    );

    m.insert(
        "database.mysql:mysqldump-add-drop-table",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use --skip-add-drop-table to disable table drops on restore",
            )
            .with_command("mysqldump --skip-add-drop-table <database> > backup.sql"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Restore to a new database first, then verify before swapping",
            ),
        ],
    );

    m.insert(
        "database.mysql:grant-all",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Grant privileges on a specific database instead of all",
            )
            .with_command("GRANT ALL ON <database>.* TO 'user'@'host';"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Grant specific privileges instead of ALL",
            )
            .with_command("GRANT SELECT, INSERT, UPDATE ON <database>.* TO 'user'@'host';"),
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Review current grants with `SHOW GRANTS FOR 'user'@'host'`",
            ),
        ],
    );

    m.insert(
        "database.mysql:drop-user",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Review user's grants before dropping",
            )
            .with_command("SHOW GRANTS FOR 'user'@'host';"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Lock the account instead of dropping for temporary disablement",
            )
            .with_command("ALTER USER 'user'@'host' ACCOUNT LOCK;"),
        ],
    );

    m.insert(
        "database.mysql:reset-master",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Check replication status and connected replicas first",
            )
            .with_command("SHOW SLAVE HOSTS;"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use PURGE BINARY LOGS for selective cleanup instead",
            )
            .with_command("PURGE BINARY LOGS BEFORE '<date>';"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Ensure all replicas are stopped and reconfigured after RESET MASTER",
            ),
        ],
    );
}

/// Register suggestions for system.permissions pack rules.
fn register_system_permissions_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    // chmod 777 (world writable)
    m.insert(
        "system.permissions:chmod-777",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use 755 for directories (rwxr-xr-x) or 644 for files (rw-r--r--) instead",
            )
            .with_command("chmod 755 <dir>  # or chmod 644 <file>"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Grant group write with 775 if collaboration needed",
            )
            .with_command("chmod 775 <path>"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Use ACLs for fine-grained access control instead of world-writable",
            )
            .with_command("setfacl -m u:username:rwx <path>"),
            Suggestion::new(
                SuggestionKind::Documentation,
                "World-writable files (777) allow any user to read, write, and execute",
            ),
        ],
    );

    // chmod -R on system directories
    m.insert(
        "system.permissions:chmod-recursive-root",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Preview what would change with find before recursive chmod",
            )
            .with_command("find <path> -type f -perm <mode> | head -20"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Apply to specific file types rather than everything recursively",
            )
            .with_command("find <path> -type f -name '*.sh' -exec chmod 755 {} \\;"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Changing permissions on /etc, /usr, /var, etc. can break system services",
            ),
        ],
    );

    // chown -R on system directories
    m.insert(
        "system.permissions:chown-recursive-root",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Preview what would change before recursive chown",
            )
            .with_command("find <path> -type f -user <current> | head -20"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Apply to specific directories rather than system root paths",
            )
            .with_command("chown -R user:group /home/user/specific-dir"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "System directories have specific ownership for security; changing them can break services",
            ),
        ],
    );

    // chmod setuid
    m.insert(
        "system.permissions:chmod-setuid",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use sudo or capabilities instead of setuid for privilege escalation",
            )
            .with_command("sudo setcap cap_net_bind_service=+ep <binary>"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Setuid binaries run as owner regardless of who executes them - security risk",
            ),
            Suggestion::new(
                SuggestionKind::Documentation,
                "Setuid (4xxx or u+s) allows any user to run the file with owner's privileges",
            ),
        ],
    );

    // chmod setgid
    m.insert(
        "system.permissions:chmod-setgid",
        vec![
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use group ACLs for shared directory access instead of setgid",
            )
            .with_command("setfacl -d -m g:groupname:rwx <directory>"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Setgid on directories makes new files inherit the directory's group",
            ),
            Suggestion::new(
                SuggestionKind::Documentation,
                "Setgid (2xxx or g+s) on executables runs with group privileges",
            ),
        ],
    );

    // chown to root
    m.insert(
        "system.permissions:chown-to-root",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Verify you're changing the correct files before transferring to root",
            )
            .with_command("ls -la <path>"),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Files owned by root often require sudo to modify; ensure this is intended",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Consider using a service account instead of root for daemons",
            ),
        ],
    );

    // setfacl recursive on system dirs
    m.insert(
        "system.permissions:setfacl-all",
        vec![
            Suggestion::new(
                SuggestionKind::PreviewFirst,
                "Preview current ACLs before modifying recursively",
            )
            .with_command("getfacl -R <path> | head -50"),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Apply ACLs to specific subdirectories rather than system paths",
            ),
            Suggestion::new(
                SuggestionKind::WorkflowFix,
                "Recursive ACL changes on /etc, /var, etc. can break service permissions",
            ),
        ],
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn required_suggestion(rule_id: &str, kind: SuggestionKind) -> &'static Suggestion {
        get_suggestion_by_kind(rule_id, kind)
            .unwrap_or_else(|| panic!("missing {kind:?} suggestion for {rule_id}"))
    }

    #[test]
    fn suggestion_kind_labels() {
        assert_eq!(SuggestionKind::PreviewFirst.label(), "Preview first");
        assert_eq!(
            SuggestionKind::SaferAlternative.label(),
            "Safer alternative"
        );
        assert_eq!(SuggestionKind::WorkflowFix.label(), "Workflow fix");
        assert_eq!(SuggestionKind::Documentation.label(), "Documentation");
        assert_eq!(SuggestionKind::AllowSafely.label(), "Allow safely");
    }

    #[test]
    fn suggestion_builder_pattern() {
        let suggestion = Suggestion::new(SuggestionKind::PreviewFirst, "Test suggestion")
            .with_command("git status")
            .with_url("https://example.com");

        assert_eq!(suggestion.kind, SuggestionKind::PreviewFirst);
        assert_eq!(suggestion.text, "Test suggestion");
        assert_eq!(suggestion.command, Some("git status".to_string()));
        assert_eq!(suggestion.url, Some("https://example.com".to_string()));
    }

    #[test]
    fn registry_lookup_returns_suggestions() {
        let suggestions = get_suggestions("core.git:reset-hard");
        assert!(suggestions.is_some());
        let suggestions = suggestions.unwrap();
        assert!(!suggestions.is_empty());
        assert!(suggestions.len() >= 3); // At least preview, alternative, workflow
    }

    #[test]
    fn registry_lookup_returns_none_for_unknown_rule() {
        let suggestions = get_suggestions("nonexistent:rule");
        assert!(suggestions.is_none());
    }

    #[test]
    fn get_suggestion_by_kind_works() {
        let preview = get_suggestion_by_kind("core.git:reset-hard", SuggestionKind::PreviewFirst);
        assert!(preview.is_some());
        assert!(preview.unwrap().text.contains("git diff"));

        let safer = get_suggestion_by_kind("core.git:reset-hard", SuggestionKind::SaferAlternative);
        assert!(safer.is_some());
        assert!(safer.unwrap().text.contains("soft"));
    }

    #[test]
    fn suggestions_serialize_to_json() {
        let suggestion =
            Suggestion::new(SuggestionKind::PreviewFirst, "Test").with_command("git status");

        let json = serde_json::to_string(&suggestion).unwrap();
        assert!(json.contains("\"kind\":\"preview_first\""));
        assert!(json.contains("\"text\":\"Test\""));
        assert!(json.contains("\"command\":\"git status\""));
        // url should be skipped when None
        assert!(!json.contains("\"url\""));
    }

    #[test]
    fn suggestions_deserialize_from_json() {
        let json = r#"{"kind":"safer_alternative","text":"Use safer option","command":"git reset --soft"}"#;
        let suggestion: Suggestion = serde_json::from_str(json).unwrap();

        assert_eq!(suggestion.kind, SuggestionKind::SaferAlternative);
        assert_eq!(suggestion.text, "Use safer option");
        assert_eq!(suggestion.command, Some("git reset --soft".to_string()));
        assert_eq!(suggestion.url, None);
    }

    #[test]
    fn registry_has_core_git_rules() {
        // Verify expected core.git rules have suggestions
        // These must match actual pattern names from src/packs/core/git.rs
        let expected_rules = [
            "core.git:reset-hard",
            "core.git:reset-merge",
            "core.git:clean-force",
            "core.git:push-force-long",
            "core.git:push-force-short",
            "core.git:checkout-discard",
            "core.git:checkout-ref-discard",
            "core.git:branch-force-delete",
            "core.git:restore-worktree",
            "core.git:restore-worktree-explicit",
            "core.git:stash-drop",
            "core.git:stash-clear",
        ];

        for rule in expected_rules {
            assert!(
                get_suggestions(rule).is_some(),
                "Expected suggestions for {rule}"
            );
        }
    }

    #[test]
    fn registry_has_core_filesystem_rules() {
        // Verify expected core.filesystem rules have suggestions
        // These must match actual pattern names from src/packs/core/filesystem.rs
        let expected_rules = [
            "core.filesystem:sed-exec-unverified",
            "core.filesystem:rm-rf-root-home",
            "core.filesystem:rm-r-f-separate-root-home",
            "core.filesystem:rm-recursive-force-root-home",
            "core.filesystem:rm-rf-general",
            "core.filesystem:rm-glob-home",
            "core.filesystem:rm-r-f-separate",
            "core.filesystem:rm-recursive-force-long",
            "core.filesystem:rm-recursive-root-home",
            "core.filesystem:rm-recursive-general",
            "core.filesystem:rm-recursive-unverified",
            "core.filesystem:powershell-remove-item-recursive",
            "core.filesystem:rm-bare-glob",
            "core.filesystem:rm-bare-glob-root",
            "core.filesystem:find-delete-root-home",
            "core.filesystem:find-delete-general",
            "core.filesystem:unlink-root-home",
            "core.filesystem:unlink-general",
            "core.filesystem:truncate-zero-root-home",
            "core.filesystem:truncate-zero-general",
            "core.filesystem:shred-root-home",
            "core.filesystem:shred-general",
            "core.filesystem:tar-remove-files-root-home",
            "core.filesystem:tar-remove-files-general",
            "core.filesystem:dd-overwrite-root-home",
            "core.filesystem:dd-overwrite-general",
            "core.filesystem:mv-sensitive-source-root-home",
            "core.filesystem:mv-dynamic-path",
            "core.filesystem:cp-sensitive-then-delete",
            "core.filesystem:ln-symlink-sensitive-then-delete",
            "core.filesystem:rsync-sensitive-then-delete",
            "core.filesystem:redirect-truncate-root-home",
            "core.filesystem:redirect-truncate-dynamic-path",
        ];

        for rule in expected_rules {
            assert!(
                get_suggestions(rule).is_some(),
                "Expected suggestions for {rule}"
            );
        }
    }

    #[test]
    fn secondary_registry_root_home_recursive_rm_consumers_narrow_the_target() {
        for &rule_id in ROOT_HOME_RECURSIVE_RM_SUGGESTION_RULES {
            let preview = required_suggestion(rule_id, SuggestionKind::PreviewFirst);
            assert_eq!(
                preview.command.as_deref(),
                Some("find path -maxdepth 2 -print"),
                "{rule_id}: find accepts files or trees, uses -maxdepth (one dash), and prints without deleting",
            );
            assert!(!preview.text.contains("--maxdepth"), "{rule_id}");
            assert!(!preview.text.contains("path/"), "{rule_id}");

            let narrowed = required_suggestion(rule_id, SuggestionKind::SaferAlternative);
            assert_eq!(
                narrowed.command.as_deref(),
                Some("cp -a reviewed-path /tmp/reviewed-backup"),
                "{rule_id}"
            );
            assert!(
                narrowed
                    .text
                    .contains("specific, explicitly reviewed file or directory")
            );
            assert!(
                narrowed
                    .text
                    .contains("must be non-root, non-home, and non-sensitive")
            );
            assert!(narrowed.text.contains("never the blocked root"));
            assert!(narrowed.text.contains("original is preserved"));

            let commands = get_suggestions(rule_id)
                .expect("root/home guidance")
                .iter()
                .filter_map(|suggestion| suggestion.command.as_deref())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(!commands.contains("rm -r"), "{rule_id}: {commands}");
            assert!(
                !commands.contains("rm --recursive"),
                "{rule_id}: {commands}"
            );
        }
    }

    #[test]
    fn secondary_registry_general_recursive_rm_consumers_accept_files_or_trees() {
        for &rule_id in GENERAL_RECURSIVE_RM_SUGGESTION_RULES {
            let preview = required_suggestion(rule_id, SuggestionKind::PreviewFirst);
            assert_eq!(
                preview.command.as_deref(),
                Some("find path -maxdepth 2 -print"),
                "{rule_id}"
            );
            assert!(!preview.text.contains("path/"), "{rule_id}");

            let interactive = required_suggestion(rule_id, SuggestionKind::SaferAlternative);
            assert_eq!(interactive.command.as_deref(), Some("rm -ri path"));
            assert!(
                interactive.text.contains("interactive terminal"),
                "{rule_id}"
            );
            assert!(interactive.text.contains("stdin closed"), "{rule_id}");
            assert!(interactive.text.contains("deletes nothing"), "{rule_id}");

            let trash = required_suggestion(rule_id, SuggestionKind::WorkflowFix);
            assert!(trash.text.contains("trash-put") && trash.text.contains("Linux"));
            assert!(trash.text.contains("~/.Trash/") && trash.text.contains("macOS"));
            assert!(!trash.text.contains("~/.local/share/Trash"), "{rule_id}");
        }
    }

    #[test]
    fn secondary_registry_find_delete_consumers_preserve_the_expression() {
        for &rule_id in FIND_DELETE_SUGGESTION_RULES {
            let preview = required_suggestion(rule_id, SuggestionKind::PreviewFirst);
            assert!(preview.command.is_none(), "{rule_id}");
            assert!(preview.text.contains("For a terminal `-delete` action"));
            assert!(
                preview
                    .text
                    .contains("original search root, option, and predicate")
            );
            assert!(preview.text.contains("retain or add `-depth`"));
            assert!(preview.text.contains("terminal action with `-print`"));

            let safer = required_suggestion(rule_id, SuggestionKind::SaferAlternative);
            assert!(safer.text.contains("read-only"), "{rule_id}");
            assert!(
                safer.text.contains("arbitrary boolean expression"),
                "{rule_id}"
            );
            assert!(
                safer
                    .text
                    .contains("no guaranteed exact mechanical rewrite")
            );
        }
    }

    #[test]
    fn secondary_registry_tar_remove_files_consumers_preserve_sources() {
        for &rule_id in TAR_REMOVE_FILES_SUGGESTION_RULES {
            let safer = required_suggestion(rule_id, SuggestionKind::SaferAlternative);
            assert_eq!(safer.command.as_deref(), Some("tar -cf archive.tar source"));
            assert!(safer.text.contains("without `--remove-files`"), "{rule_id}");

            for command in get_suggestions(rule_id)
                .expect("tar guidance")
                .iter()
                .filter_map(|suggestion| suggestion.command.as_deref())
            {
                assert!(!command.contains("--remove-files"), "{rule_id}: {command}");
                assert!(!command.contains("rm -r"), "{rule_id}: {command}");
            }
        }
    }

    #[test]
    fn secondary_registry_sensitive_propagation_guidance_matches_each_operation() {
        let cp_rule = "core.filesystem:cp-sensitive-then-delete";
        assert_eq!(
            required_suggestion(cp_rule, SuggestionKind::SaferAlternative)
                .command
                .as_deref(),
            Some("cp -a source backup"),
        );

        let link_rule = "core.filesystem:ln-symlink-sensitive-then-delete";
        let unlink = required_suggestion(link_rule, SuggestionKind::SaferAlternative);
        assert_eq!(unlink.command.as_deref(), Some("unlink link"));
        assert!(unlink.text.contains("symlink itself"));
        assert!(
            unlink
                .text
                .contains("never recursively remove the link target")
        );

        let rsync_rule = "core.filesystem:rsync-sensitive-then-delete";
        assert_eq!(
            required_suggestion(rsync_rule, SuggestionKind::PreviewFirst)
                .command
                .as_deref(),
            Some("rsync -a --dry-run --ignore-existing source fresh-backup/"),
        );
        assert_eq!(
            required_suggestion(rsync_rule, SuggestionKind::SaferAlternative)
                .command
                .as_deref(),
            Some("rsync -a --ignore-existing source fresh-backup/"),
        );
        let rsync_safer = required_suggestion(rsync_rule, SuggestionKind::SaferAlternative);
        assert!(rsync_safer.text.contains("fresh, non-existing"));
        assert!(rsync_safer.text.contains("prevents overwriting"));

        for rule_id in [cp_rule, link_rule, rsync_rule] {
            let commands = get_suggestions(rule_id)
                .expect("propagation guidance")
                .iter()
                .filter_map(|suggestion| suggestion.command.as_deref())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(!commands.contains("rm -r"), "{rule_id}: {commands}");
        }
    }

    #[test]
    fn secondary_registry_single_file_consumers_use_file_guidance() {
        for &rule_id in SINGLE_FILE_SUGGESTION_RULES {
            let preview = required_suggestion(rule_id, SuggestionKind::PreviewFirst);
            assert_eq!(preview.command.as_deref(), Some("ls -la path"), "{rule_id}");
            assert!(!preview.text.contains("find "), "{rule_id}");
            assert!(!preview.text.contains("path/"), "{rule_id}");

            let backup = required_suggestion(rule_id, SuggestionKind::SaferAlternative);
            assert_eq!(backup.command.as_deref(), Some("cp -p path path.bak"));
            assert!(backup.text.contains("file"), "{rule_id}");
        }
    }

    #[test]
    fn secondary_registry_moved_path_consumers_accept_files_or_directories() {
        for &rule_id in MOVED_PATH_SUGGESTION_RULES {
            let preview = required_suggestion(rule_id, SuggestionKind::PreviewFirst);
            assert_eq!(preview.command.as_deref(), Some("ls -ld path"), "{rule_id}");
            assert!(!preview.text.contains("path/"), "{rule_id}");
            assert!(
                required_suggestion(rule_id, SuggestionKind::SaferAlternative)
                    .text
                    .contains("literal backup path"),
                "{rule_id}"
            );
        }
    }

    #[test]
    fn secondary_registry_home_glob_previews_the_expansion() {
        let rule_id = "core.filesystem:rm-glob-home";
        assert_eq!(
            required_suggestion(rule_id, SuggestionKind::PreviewFirst)
                .command
                .as_deref(),
            Some("ls -la path-pattern"),
        );
        let trash = required_suggestion(rule_id, SuggestionKind::WorkflowFix);
        assert!(trash.text.contains("trash-put") && trash.text.contains("Linux"));
        assert!(trash.text.contains("~/.Trash/") && trash.text.contains("macOS"));
    }

    #[test]
    fn secondary_registry_covers_every_classifier_only_rule_accurately() {
        let classifier_only_rules = [
            "core.filesystem:rm-recursive-root-home",
            "core.filesystem:rm-recursive-general",
            "core.filesystem:rm-recursive-unverified",
            "core.filesystem:powershell-remove-item-recursive",
            "core.filesystem:rm-bare-glob",
            "core.filesystem:rm-bare-glob-root",
        ];
        for rule_id in classifier_only_rules {
            let suggestions = get_suggestions(rule_id)
                .unwrap_or_else(|| panic!("missing secondary suggestions for {rule_id}"));
            assert!(!suggestions.is_empty(), "{rule_id}");
            assert!(
                suggestions
                    .iter()
                    .any(|suggestion| suggestion.kind == SuggestionKind::SaferAlternative),
                "{rule_id} has no safer alternative for scan output"
            );
        }

        assert_eq!(
            required_suggestion(
                "core.filesystem:rm-recursive-root-home",
                SuggestionKind::SaferAlternative,
            )
            .command
            .as_deref(),
            Some("cp -a reviewed-path /tmp/reviewed-backup"),
        );

        let unverified = get_suggestions("core.filesystem:rm-recursive-unverified")
            .expect("unverified classifier guidance");
        let unverified_text = unverified
            .iter()
            .map(|suggestion| suggestion.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(unverified_text.contains("assembled executable"));
        assert!(unverified_text.contains("literal executable"));
        assert!(unverified_text.contains("PowerShell splat"));

        let powershell = get_suggestions("core.filesystem:powershell-remove-item-recursive")
            .expect("PowerShell classifier guidance");
        let powershell_commands: Vec<_> = powershell
            .iter()
            .filter_map(|suggestion| suggestion.command.as_deref())
            .collect();
        assert_eq!(
            powershell_commands,
            [
                "Get-ChildItem -Recurse path",
                "Remove-Item -Recurse -WhatIf path",
                "Move-Item path (Join-Path ([IO.Path]::GetTempPath()) delete-me-reviewed)",
            ]
        );
        let powershell_text = powershell
            .iter()
            .flat_map(|suggestion| {
                [
                    suggestion.text.as_str(),
                    suggestion.command.as_deref().unwrap_or(""),
                ]
            })
            .collect::<Vec<_>>()
            .join(" ");
        for unix_advice in ["rm -", "find ", "ls -", "/tmp", "trash-put", "~/.Trash"] {
            assert!(
                !powershell_text.contains(unix_advice),
                "PowerShell guidance contains Unix advice {unix_advice:?}: {powershell_text}"
            );
        }

        assert_eq!(
            required_suggestion("core.filesystem:rm-bare-glob", SuggestionKind::PreviewFirst)
                .command
                .as_deref(),
            Some("ls -la"),
        );
        assert_eq!(
            required_suggestion(
                "core.filesystem:rm-bare-glob-root",
                SuggestionKind::PreviewFirst
            )
            .command
            .as_deref(),
            Some("ls -la /"),
        );
    }

    #[test]
    fn registry_has_heredoc_rules() {
        // Verify heredoc rules use canonical colon format (pack_id:pattern_name)
        let expected_rules = [
            "heredoc.python:shutil_rmtree",
            "heredoc.javascript:fs_rmsync",
        ];

        for rule in expected_rules {
            assert!(
                get_suggestions(rule).is_some(),
                "Expected suggestions for {rule}"
            );
            // Verify the format uses colon separator (matches RuleId format)
            assert!(
                rule.contains(':'),
                "Rule ID should use colon format: {rule}"
            );
        }
    }

    #[test]
    fn all_suggestion_kinds_are_used() {
        // Verify all SuggestionKind variants are used at least once in the registry
        let mut kinds_found = std::collections::HashSet::new();

        for suggestions in SUGGESTION_REGISTRY.values() {
            for suggestion in suggestions {
                kinds_found.insert(suggestion.kind);
            }
        }

        // Note: AllowSafely may not be used yet - that's intentional for 1gt.5.2
        assert!(kinds_found.contains(&SuggestionKind::PreviewFirst));
        assert!(kinds_found.contains(&SuggestionKind::SaferAlternative));
        assert!(kinds_found.contains(&SuggestionKind::WorkflowFix));
        assert!(kinds_found.contains(&SuggestionKind::Documentation));
        // AllowSafely will be added when allowlist integration is complete
    }

    #[test]
    fn suggestions_have_stable_order() {
        // Verify suggestions for a rule always come in the same order
        let suggestions1 = get_suggestions("core.git:reset-hard").unwrap();
        let suggestions2 = get_suggestions("core.git:reset-hard").unwrap();

        assert_eq!(suggestions1.len(), suggestions2.len());
        for (s1, s2) in suggestions1.iter().zip(suggestions2.iter()) {
            assert_eq!(s1.kind, s2.kind);
            assert_eq!(s1.text, s2.text);
        }
    }

    #[test]
    fn coverage_all_core_pack_rules_have_suggestions() {
        // This dynamically checks regex-backed and semantic-classifier rules in
        // core.* packs against the secondary suggestion registry.
        //
        // This satisfies the acceptance criteria for git_safety_guard-1gt.5.2:
        // "A coverage test that asserts all core destructive patterns have at least 1 suggestion."

        use crate::packs::REGISTRY;

        let core_packs = ["core.git", "core.filesystem"];
        let mut missing_suggestions = Vec::new();

        for pack_id in core_packs {
            let pack = REGISTRY
                .get(pack_id)
                .unwrap_or_else(|| panic!("Pack {pack_id} should exist"));

            for rule_name in pack.guidance_rule_names() {
                let rule_id = format!("{pack_id}:{rule_name}");
                if get_suggestions(&rule_id).is_none() {
                    missing_suggestions.push(rule_id);
                }
            }
        }

        assert!(
            missing_suggestions.is_empty(),
            "The following core rules are missing suggestions:\n  {}",
            missing_suggestions.join("\n  ")
        );
    }

    #[test]
    fn coverage_core_rule_count_matches_registry() {
        // Verify regex-backed plus semantic guidance rule counts match the
        // secondary registry. This catches drift in either direction.

        use crate::packs::REGISTRY;

        // Count guidance-bearing rules in core.git.
        let git_pack = REGISTRY.get("core.git").unwrap();
        let git_rule_count = git_pack.guidance_rule_names().count();

        // Count suggestions for core.git
        let git_suggestion_count = SUGGESTION_REGISTRY
            .keys()
            .filter(|k| k.starts_with("core.git:"))
            .count();

        assert_eq!(
            git_rule_count, git_suggestion_count,
            "core.git rule count ({git_rule_count}) != suggestion count ({git_suggestion_count})"
        );

        // Count guidance-bearing rules in core.filesystem, including semantic
        // classifier-only names.
        let fs_pack = REGISTRY.get("core.filesystem").unwrap();
        let fs_rule_count = fs_pack.guidance_rule_names().count();

        // Count suggestions for core.filesystem
        let fs_suggestion_count = SUGGESTION_REGISTRY
            .keys()
            .filter(|k| k.starts_with("core.filesystem:"))
            .count();

        assert_eq!(
            fs_rule_count, fs_suggestion_count,
            "core.filesystem rule count ({fs_rule_count}) != suggestion count ({fs_suggestion_count})"
        );
    }

    #[test]
    fn registry_has_docker_rules() {
        let expected = [
            "containers.docker:system-prune",
            "containers.docker:volume-prune",
            "containers.docker:network-prune",
            "containers.docker:image-prune",
            "containers.docker:container-prune",
            "containers.docker:rm-force",
            "containers.docker:rmi-force",
            "containers.docker:volume-rm",
            "containers.docker:stop-all",
        ];
        for rule in expected {
            assert!(get_suggestions(rule).is_some(), "Missing: {rule}");
        }
    }

    #[test]
    fn registry_has_kubernetes_rules() {
        let expected = [
            "kubernetes.kubectl:delete-namespace",
            "kubernetes.kubectl:delete-all",
            "kubernetes.kubectl:delete-all-namespaces",
            "kubernetes.kubectl:drain-node",
            "kubernetes.kubectl:cordon-node",
            "kubernetes.kubectl:taint-noexecute",
            "kubernetes.kubectl:delete-workload",
            "kubernetes.kubectl:delete-pvc",
            "kubernetes.kubectl:delete-pv",
            "kubernetes.kubectl:scale-to-zero",
            "kubernetes.kubectl:delete-force",
        ];
        for rule in expected {
            assert!(get_suggestions(rule).is_some(), "Missing: {rule}");
        }
    }

    #[test]
    fn registry_has_database_rules() {
        let expected = [
            // PostgreSQL
            "database.postgresql:drop-database",
            "database.postgresql:drop-table",
            "database.postgresql:drop-schema",
            "database.postgresql:truncate-table",
            "database.postgresql:delete-without-where",
            "database.postgresql:dropdb-cli",
            "database.postgresql:pg-dump-clean",
            // MongoDB
            "database.mongodb:drop-database",
            "database.mongodb:drop-collection",
            "database.mongodb:delete-all",
            "database.mongodb:mongorestore-drop",
            "database.mongodb:collection-drop",
            // Redis
            "database.redis:flushall",
            "database.redis:flushdb",
            "database.redis:debug-crash",
            "database.redis:debug-sleep",
            "database.redis:shutdown",
            "database.redis:config-dangerous",
            // SQLite
            "database.sqlite:drop-table",
            "database.sqlite:delete-without-where",
            "database.sqlite:vacuum-into",
            "database.sqlite:sqlite3-stdin",
            // MySQL
            "database.mysql:drop-database",
            "database.mysql:drop-table",
            "database.mysql:truncate-table",
            "database.mysql:delete-without-where",
            "database.mysql:mysqladmin-drop",
            "database.mysql:mysqldump-add-drop-database",
            "database.mysql:mysqldump-add-drop-table",
            "database.mysql:grant-all",
            "database.mysql:drop-user",
            "database.mysql:reset-master",
        ];
        for rule in expected {
            assert!(get_suggestions(rule).is_some(), "Missing: {rule}");
        }
    }

    #[test]
    fn registry_has_system_permissions_rules() {
        let expected = [
            "system.permissions:chmod-777",
            "system.permissions:chmod-recursive-root",
            "system.permissions:chown-recursive-root",
            "system.permissions:chmod-setuid",
            "system.permissions:chmod-setgid",
            "system.permissions:chown-to-root",
            "system.permissions:setfacl-all",
        ];
        for rule in expected {
            assert!(get_suggestions(rule).is_some(), "Missing: {rule}");
        }
    }

    // === Correctness & Coverage Tests (git_safety_guard-1gt.5.5) ===

    #[test]
    fn coverage_all_suggestion_rules_are_valid() {
        // Verify every rule_id matches a regex-backed or semantic pack rule.
        use crate::packs::REGISTRY;
        let mut invalid = Vec::new();
        for rule_id in SUGGESTION_REGISTRY.keys() {
            let parts: Vec<&str> = rule_id.split(':').collect();
            if parts.len() != 2 {
                invalid.push(format!("{rule_id} (bad format)"));
                continue;
            }
            let (pack_id, pattern_name) = (parts[0], parts[1]);
            if pack_id.starts_with("heredoc.") {
                continue;
            } // Different namespace
            let Some(pack) = REGISTRY.get(pack_id) else {
                invalid.push(format!("{rule_id} (pack not found)"));
                continue;
            };
            if !pack.guidance_rule_names().any(|name| name == pattern_name) {
                invalid.push(format!("{rule_id} (rule not found)"));
            }
        }
        assert!(
            invalid.is_empty(),
            "Invalid suggestion rules:\n  {}",
            invalid.join("\n  ")
        );
    }

    #[test]
    fn suggestions_do_not_suggest_destructive_commands() {
        // Suggestions must not recommend running dangerous commands.
        // Note: --force-with-lease is a SAFE alternative to --force, so we exclude it.
        let forbidden = [
            "rm -rf",
            "rm -fr",
            "git reset --hard",
            "git clean -fd",
            "docker system prune -a",
        ];
        let mut violations = Vec::new();
        for (rule_id, suggestions) in SUGGESTION_REGISTRY.iter() {
            for s in suggestions {
                if let Some(cmd) = &s.command {
                    // Special case: git push --force-with-lease is safe
                    if cmd.contains("--force-with-lease") {
                        continue;
                    }
                    // Check for bare --force or -f (not in a safe context)
                    let has_dangerous_force = (cmd.contains("git push")
                        || cmd.contains("git push"))
                        && (cmd.contains(" --force ")
                            || cmd.contains(" --force\"")
                            || cmd.ends_with(" --force")
                            || cmd.contains(" -f "));
                    if has_dangerous_force {
                        violations.push(format!("{rule_id}: '{cmd}' has dangerous force flag"));
                    }
                    for f in &forbidden {
                        if cmd.to_lowercase().contains(&f.to_lowercase()) {
                            violations.push(format!("{rule_id}: '{cmd}' contains '{f}'"));
                        }
                    }
                }
            }
        }
        assert!(
            violations.is_empty(),
            "Dangerous commands in suggestions:\n  {}",
            violations.join("\n  ")
        );
    }

    #[test]
    fn suggestions_ordering_is_deterministic() {
        // Same rule should return suggestions in same order every time.
        let rules = ["core.git:reset-hard", "containers.docker:system-prune"];
        for rule in rules {
            let s1 = get_suggestions(rule);
            let s2 = get_suggestions(rule);
            let s1_len = s1.map(<[Suggestion]>::len);
            let s2_len = s2.map(<[Suggestion]>::len);
            assert_eq!(s1_len, s2_len, "Count differs for {rule}");
            if let (Some(a), Some(b)) = (s1, s2) {
                for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                    assert_eq!(x.text, y.text, "Mismatch at {i} for {rule}");
                }
            }
        }
    }

    #[test]
    fn suggestion_registry_keys_iterate_consistently() {
        let k1: Vec<_> = SUGGESTION_REGISTRY.keys().collect();
        let k2: Vec<_> = SUGGESTION_REGISTRY.keys().collect();
        assert_eq!(k1, k2, "Registry iteration order changed");
    }

    // === Fallback Explanation Tests ===

    #[test]
    fn fallback_explanation_with_pack_and_pattern() {
        let exp = fallback_explanation(Some("core.git"), Some("reset-hard"));
        assert!(exp.contains("core.git:reset-hard"));
        assert!(exp.contains("dcg explain"));
        assert!(exp.contains("destructive pattern"));
    }

    #[test]
    fn fallback_explanation_with_pack_only() {
        let exp = fallback_explanation(Some("core.git"), None);
        assert!(exp.contains("core.git"));
        assert!(exp.contains("dcg explain"));
        assert!(!exp.contains(':')); // No pattern separator
    }

    #[test]
    fn fallback_explanation_with_pattern_only() {
        let exp = fallback_explanation(None, Some("reset-hard"));
        assert!(exp.contains("reset-hard"));
        assert!(exp.contains("dcg explain"));
    }

    #[test]
    fn fallback_explanation_with_nothing() {
        let exp = fallback_explanation(None, None);
        assert!(exp.contains("destructive pattern"));
        assert!(exp.contains("dcg explain"));
    }

    #[test]
    fn get_explanation_returns_explicit_when_present() {
        let exp = get_explanation(
            Some("Custom explanation here"),
            Some("core.git"),
            Some("reset-hard"),
        );
        assert_eq!(exp, "Custom explanation here");
    }

    #[test]
    fn get_explanation_uses_fallback_when_none() {
        let exp = get_explanation(None, Some("core.git"), Some("reset-hard"));
        assert!(exp.contains("core.git:reset-hard"));
        assert!(exp.contains("dcg explain"));
    }

    #[test]
    fn get_explanation_uses_fallback_when_empty() {
        let exp = get_explanation(Some(""), Some("core.git"), Some("reset-hard"));
        assert!(exp.contains("core.git:reset-hard"));
        assert!(exp.contains("dcg explain"));
    }

    #[test]
    fn get_explanation_uses_fallback_when_whitespace_only() {
        let exp = get_explanation(Some("   "), Some("core.git"), Some("reset-hard"));
        assert!(exp.contains("core.git:reset-hard"));
        assert!(exp.contains("dcg explain"));
    }

    #[test]
    fn fallback_is_neutral_and_concise() {
        let exp = fallback_explanation(Some("core.git"), Some("reset-hard"));
        // Should not contain scaremongering language
        assert!(!exp.to_lowercase().contains("danger"));
        assert!(!exp.to_lowercase().contains("warning"));
        assert!(!exp.to_lowercase().contains("critical"));
        // Should be reasonably short (2-4 sentences = ~50-200 words)
        let word_count = exp.split_whitespace().count();
        assert!(
            word_count < 50,
            "Fallback should be concise: {word_count} words"
        );
    }
}
