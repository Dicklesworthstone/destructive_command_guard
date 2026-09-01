//! Home-subtree move deadlock: two `core.filesystem` rules each recommend the
//! command the other denies.
//!
//! Reported shape (ordinary personal file organisation under `~/Documents`):
//!
//! 1. `mv "~/Documents/Personal/Admin/<dir>" "~/Documents/_archived/"` is
//!    denied by `mv-sensitive-source-root-home`, whose guidance recommends
//!    "copy, verify, then delete the source".
//! 2. That recursive delete of the source is denied by `rm-rf-root-home`,
//!    whose guidance recommends relocating the tree to
//!    `/tmp/delete-me-<timestamp>`.
//! 3. That relocation is denied by `mv-sensitive-source-root-home` again.
//!
//! Every sanctioned escape is blocked by the other rule, so no verified
//! move-then-cleanup completes inside a home directory and plain renames need
//! a per-command `dcg allow-once`.
//!
//! Two independent causes, pinned separately below.
//!
//! **Cause 1 — no rescue for a rename that never leaves the home tree.** The
//! rule's own bypass story is cross-segment relocate-then-delete. A move whose
//! source and destination are both at least two components below the same
//! home-root form cannot be that: nothing leaves the tree, and a later
//! recursive delete of the destination is denied exactly as before.
//! `mv-within-home` rescues that class only.
//!
//! **Cause 2 — the rescues are quote-blind while the denial is not.** The
//! destructive path alternation is prefixed with `['"\\]?`, so it sees through
//! quotes; every safe pattern that could rescue a home path reads bare words
//! only. Quoting therefore only ever moves a command toward deny — and a
//! filename containing a space MUST be quoted. `mv <path> ~/.Trash/` (the
//! soft-delete dcg itself recommends) is allowed unquoted and denied the
//! moment the path contains a space. `mv-to-trash-quoted` closes that.
//!
//! The `#316` suggestion self-consistency test did not catch this: it
//! evaluates `PatternSuggestion` commands, and both dead-end recommendations
//! live in the rules' prose `explanation` text, which nothing evaluates. The
//! guidance cases below pin those prose commands directly.

use destructive_command_guard::packs::PackRegistry;

#[track_caller]
fn assert_allowed(command: &str) {
    let registry = PackRegistry::new();
    let pack = registry
        .get("core.filesystem")
        .expect("core.filesystem pack resolves");
    if let Some(hit) = pack.check(command) {
        panic!(
            "expected ALLOW, got deny from core.filesystem:{} for {command:?}",
            hit.name.unwrap_or("unnamed"),
        );
    }
}

#[track_caller]
fn assert_denied(command: &str) {
    let registry = PackRegistry::new();
    let pack = registry
        .get("core.filesystem")
        .expect("core.filesystem pack resolves");
    assert!(
        pack.check(command).is_some(),
        "expected DENY, got allow for {command:?}",
    );
}

// ---------------------------------------------------------------------------
// The reported chain
// ---------------------------------------------------------------------------

/// Step 1 of the report: the move the user actually wanted, quoted because the
/// directory name contains spaces.
#[test]
fn reported_quoted_move_within_documents_is_allowed() {
    assert_allowed(
        r#"mv "/Users/merlin/Documents/Personal/Admin/758 Texola Court Sale" "/Users/merlin/Documents/_archived/""#,
    );
}

/// Steps 2 and 3 stay denied on purpose. The deadlock is broken by making
/// step 1 work, not by opening a relocate-then-delete path out of the home
/// tree: a recursive delete of a home directory and a hop into /tmp are both
/// still the bypass the rules exist to stop.
#[test]
fn deletion_and_tmp_relocation_of_a_home_tree_stay_denied() {
    assert_denied(r#"rm -rf "/Users/merlin/Documents/Personal/Admin""#);
    assert_denied(r#"mv "/Users/merlin/Documents/Personal/Admin" /tmp/delete-me-20260831"#);
    assert_denied("mv /Users/merlin/Documents/Personal/Admin /tmp/delete-me-20260831");
}

// ---------------------------------------------------------------------------
// Cause 1 — ordinary renames inside one home subtree
// ---------------------------------------------------------------------------

#[test]
fn renames_within_a_home_subtree_are_allowed() {
    for command in [
        "mv /Users/merlin/Documents/a.txt /Users/merlin/Documents/b.txt",
        "mv ~/Documents/a.txt ~/Documents/b.txt",
        "mv ~/Documents/Personal ~/Documents/_archived/",
        "mv -v ~/Downloads/report.pdf ~/Documents/",
        "mv /home/user/docs/notes /home/user/docs/archive/",
        "mv ~/Documents/a.txt ~/Documents/b.txt ~/Documents/dest/",
        "mv ~/notes/scratch.txt ~/notes/scratch.txt.deleted-20260831",
        r"mv '/Users/merlin/Documents/a b.txt' '/Users/merlin/Desktop/'",
        r#"mv "/Users/merlin/Documents/a b.txt" "/Users/merlin/Desktop/""#,
    ] {
        assert_allowed(command);
    }
}

/// Every boundary of the new rescue, each one load-bearing. A home root, a
/// top-level home directory, a dotfile tree, a `..` escape, a dynamic path, a
/// flag that takes a target value, and any hop out of the home tree all keep
/// the deny.
#[test]
fn home_roots_dotfiles_and_escapes_stay_denied() {
    for command in [
        // home roots and top-level home directories are never movable
        "mv ~ /tmp/x",
        "mv ~/ /tmp/x",
        "mv /Users/merlin /tmp/x",
        "mv /home/user /tmp/x",
        "mv ~/Documents /tmp/x",
        "mv ~/Documents ~/Docs",
        "mv /Users/merlin/Documents /Users/merlin/Docs",
        // dotfile trees keep the deny on both sides
        "mv ~/.ssh/id_rsa ~/Documents/x",
        "mv ~/Documents/x ~/.ssh/authorized_keys",
        "mv ~/.config/app/settings.json ~/Documents/settings.json",
        r#"mv "/Users/merlin/.aws/credentials" "/Users/merlin/Documents/c""#,
        // system trees are untouched
        "mv /etc /tmp/x",
        "mv /etc/passwd ~/Documents/p",
        "mv ~/Documents/a /etc/x",
        "mv /var/log/system.log ~/Documents/log",
        // no climbing out of the named tree
        "mv ~/Documents/a ~/Documents/../../etc/x",
        "mv ~/Documents/../.ssh/key ~/Documents/x",
        r#"mv "/Users/merlin/Documents/../.ssh/key" "/Users/merlin/Documents/x""#,
        // dynamic expansion still fails closed
        r#"mv "$HOME/Documents/a" ~/Documents/b"#,
        "mv ~/Documents/`whoami`/a ~/Documents/b",
        // a flag may not carry a target value
        "mv -t /etc ~/Documents/a",
        "mv --target-directory=/etc ~/Documents/a",
        // whole-command anchor: a second destructive segment is not rescued
        "mv ~/Documents/a ~/Documents/b && rm -rf /etc",
        "mv ~/Documents/a ~/Documents/b; rm -rf /etc",
        // leaving the home tree is still the relocate half of the bypass
        "mv ~/Documents/a/b /tmp/x",
        "mv ~/Documents/a/b /var/tmp/x",
    ] {
        assert_denied(command);
    }
}

// ---------------------------------------------------------------------------
// Cause 2 — quote-blind rescues
// ---------------------------------------------------------------------------

/// The unquoted spelling was already allowed; the quoted one is the same
/// operation on a filename that contains a space, and the resolved spelling is
/// what an agent that has already expanded `~` writes.
#[test]
fn trash_soft_delete_is_allowed_quoted_and_with_a_resolved_home() {
    for command in [
        "mv /Users/merlin/Documents/Personal/Admin ~/.Trash/",
        r#"mv "/Users/merlin/Documents/a b.txt" ~/.Trash/"#,
        r#"mv "/Users/merlin/Documents/Personal/Admin" /Users/merlin/.Trash/"#,
        r"mv '/Users/merlin/Documents/a b.txt' '/Users/merlin/.Trash/'",
        "mv ~/Documents/a.txt ~/.local/share/Trash/",
        r#"mv "/home/user/docs/a b.txt" /home/user/.local/share/Trash/"#,
        r#"mv "/Users/merlin/Documents/a b.txt" "/Users/merlin/Documents/c d.txt" ~/.Trash/"#,
    ] {
        assert_allowed(command);
    }
}

#[test]
fn trash_rescue_does_not_launder_a_sensitive_source() {
    for command in [
        "mv /etc ~/.Trash/",
        r#"mv "/etc/passwd" ~/.Trash/"#,
        "mv ~ ~/.Trash/",
        "mv /Users/merlin ~/.Trash/",
        "mv /var/log/x ~/.Trash/",
        r#"mv "$HOME/x" ~/.Trash/"#,
        r#"mv "/Users/merlin/Documents/../../etc/x" ~/.Trash/"#,
    ] {
        assert_denied(command);
    }
}

// ---------------------------------------------------------------------------
// Guidance executability
// ---------------------------------------------------------------------------

/// Every remediation printed in these two rules' prose `explanation`, applied
/// to the home path that triggered the denial, must actually run. A denial
/// that recommends a command the same pack blocks is the dead end `#316`
/// closed for structured suggestions; the prose carried the same defect.
#[test]
fn prose_remediations_are_executable_for_a_home_path() {
    for command in [
        // rm-rf-root-home
        "find /Users/merlin/Documents/Personal/Admin -type f | head -20",
        "rm -ri /Users/merlin/Documents/Personal/Admin",
        "mv /Users/merlin/Documents/Personal/Admin ~/.Trash/",
        "mv /home/user/docs/admin ~/.local/share/Trash/",
        // mv-sensitive-source-root-home
        "mv ~/Documents/Personal ~/Documents/Personal-2026",
        "mv ~/Documents/Personal/notes.txt ~/Documents/Personal/notes.txt.deleted-20260831",
        "cp -a /Users/merlin/Documents/Personal/Admin /Users/merlin/Documents/Personal/Admin.bak",
        "mv /tmp/a /tmp/b",
    ] {
        assert_allowed(command);
    }
}
