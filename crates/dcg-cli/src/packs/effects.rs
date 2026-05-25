//! Tier-A effect tags for explicitly-tagged rules in core packs.
//!
//! Per the v0.6 plan, ~30-50 high-impact rules across git/fs/network are
//! tagged with explicit `effects` slices. Untagged rules fall back to the
//! pack's `default_effects` (Tier-B).
//!
//! This module centralizes the rule-name → effect-set mapping so that
//! pack files (`core/git.rs`, `core/filesystem.rs`, …) don't have to edit
//! every macro invocation. After constructing the `Vec<DestructivePattern>`,
//! a pack calls [`apply_tier_a_effects`] to patch in the explicit tags.

use dcg_core::Effect;

use super::DestructivePattern;

/// `[MutateVcs, Irreversible]` — git ops that rewrite local history.
pub const GIT_MUTATE_VCS_IRREVERSIBLE: &[Effect] = &[Effect::MutateVcs, Effect::Irreversible];

/// `[MutateVcs, Network, Irreversible]` — push --force and friends.
pub const GIT_FORCE_PUSH: &[Effect] = &[Effect::MutateVcs, Effect::Network, Effect::Irreversible];

/// `[Write, Fs, Irreversible]` — git ops that drop unsaved working-tree changes.
pub const GIT_WORKTREE_DESTROY: &[Effect] = &[Effect::Write, Effect::Fs, Effect::Irreversible];

/// `[Write, Fs, Irreversible]` — fs ops that delete data outside VCS.
pub const FS_REMOVE_IRREVERSIBLE: &[Effect] = &[Effect::Write, Effect::Fs, Effect::Irreversible];

/// `[Network, Read]` — read-only network fetches (curl GET, wget).
pub const NET_FETCH_READ: &[Effect] = &[Effect::Network, Effect::Read];

/// `[Network, Write]` — network ops that mutate remote state (curl POST/PUT).
pub const NET_MUTATE: &[Effect] = &[Effect::Network, Effect::Write];

/// `[Network, Write, Spawn]` — package install ops (npm install, pip install).
pub const NET_INSTALL_SPAWN: &[Effect] = &[Effect::Network, Effect::Write, Effect::Spawn];

/// Lookup table for git rule effect tags.
///
/// Returns `None` for rules that should fall back to the pack default.
#[must_use]
pub fn tier_a_git(rule_name: &str) -> Option<&'static [Effect]> {
    Some(match rule_name {
        // History-rewriting / index-rewriting ops.
        "reset-hard" | "reset-merge" => GIT_MUTATE_VCS_IRREVERSIBLE,
        // Stash destruction.
        "stash-drop" | "stash-clear" => GIT_MUTATE_VCS_IRREVERSIBLE,
        // Branch force-delete.
        "branch-force-delete" => GIT_MUTATE_VCS_IRREVERSIBLE,

        // Worktree-discard ops touch the filesystem, not just VCS metadata.
        "checkout-discard"
        | "checkout-ref-discard"
        | "restore-worktree"
        | "restore-worktree-explicit"
        | "clean-force" => GIT_WORKTREE_DESTROY,

        // Network-publish ops.
        "push-force-long" | "push-force-short" => GIT_FORCE_PUSH,
        _ => return None,
    })
}

/// Lookup table for filesystem rule effect tags.
///
/// Only the "general" / "root-home" / catastrophic variants get explicit
/// tags. tmp-only patterns and other narrow forms inherit the pack default.
#[must_use]
pub fn tier_a_filesystem(rule_name: &str) -> Option<&'static [Effect]> {
    Some(match rule_name {
        "rm-rf-general"
        | "rm-r-f-separate"
        | "rm-recursive-force-long"
        | "rm-rf-root-home"
        | "rm-r-f-separate-root-home"
        | "rm-recursive-force-root-home"
        | "find-delete-general"
        | "find-delete-root-home"
        | "unlink-general"
        | "unlink-root-home"
        | "shred-general"
        | "shred-root-home"
        | "dd-overwrite-general"
        | "dd-overwrite-root-home"
        | "tar-remove-files-general"
        | "tar-remove-files-root-home"
        | "redirect-truncate-root-home"
        | "truncate-zero-general"
        | "truncate-zero-root-home"
        | "mv-sensitive-source-root-home" => FS_REMOVE_IRREVERSIBLE,
        _ => return None,
    })
}

/// Apply Tier-A effects to destructive patterns from a name → effects lookup.
///
/// Mutates `patterns` in place: for each pattern whose name appears in
/// `lookup`, sets `effects` to the returned slice. Patterns that are already
/// tagged or whose names aren't in the lookup are left unchanged.
pub fn apply_tier_a_effects(
    patterns: &mut [DestructivePattern],
    lookup: fn(&str) -> Option<&'static [Effect]>,
) {
    for p in patterns.iter_mut() {
        if p.effects.is_some() {
            continue; // Pattern already has an explicit tag; respect it.
        }
        if let Some(name) = p.name {
            if let Some(effects) = lookup(name) {
                p.effects = Some(effects);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_lookup_returns_force_push_tags() {
        assert_eq!(tier_a_git("push-force-long"), Some(GIT_FORCE_PUSH));
        assert_eq!(tier_a_git("push-force-short"), Some(GIT_FORCE_PUSH));
    }

    #[test]
    fn git_lookup_returns_worktree_destroy_for_clean_force() {
        assert_eq!(tier_a_git("clean-force"), Some(GIT_WORKTREE_DESTROY));
    }

    #[test]
    fn git_lookup_misses_unknown_rule() {
        assert_eq!(tier_a_git("definitely-not-a-rule"), None);
    }

    #[test]
    fn fs_lookup_tags_general_rm() {
        assert_eq!(
            tier_a_filesystem("rm-rf-general"),
            Some(FS_REMOVE_IRREVERSIBLE)
        );
    }

    #[test]
    fn fs_lookup_does_not_tag_tmp_variants() {
        // tmp variants inherit pack default, not explicit Tier-A tag.
        assert_eq!(tier_a_filesystem("rm-rf-tmp"), None);
        assert_eq!(tier_a_filesystem("rm-fr-tmp"), None);
    }
}
