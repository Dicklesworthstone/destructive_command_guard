//! GitHub Platform pack - protections for destructive GitHub CLI (`gh`) operations.
//!
//! This pack targets high-impact operations when managing GitHub repositories,
//! gists, releases, and other platform resources:
//! - Deleting repositories
//! - Changing repository visibility
//! - Archiving repositories
//! - Deleting gists
//! - Deleting releases
//! - Deleting issues
//! - Deleting SSH keys

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GitHub Platform pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.github".to_string(),
        name: "GitHub Platform",
        description: "Protects against destructive GitHub CLI operations like changing repository visibility or deleting repositories, gists, releases, or SSH keys.",
        // Broad on purpose: global `gh` flags can appear before the subcommand.
        keywords: &["gh"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Regex logic:
    // Match `gh`
    // Match optional global flags: `--flag` or `--flag value`
    // Ensure the flag value isn't one of our target subcommands (repo, gist, etc.)
    // Match the target subcommand and action
    //
    // The option VALUE alternative is `(?!--?[A-Za-z])[^\s;&|]+` — "any token
    // that is not itself option-shaped". With a bare `\S+` there, a flag token
    // could parse either as a new option or as the previous option's value, so
    // `gh -a -b -c ...` had exponentially many parses. These patterns carry a
    // lookahead, so they run on the backtracking engine, and
    // `CompiledRegex::is_match` maps a backtrack-limit error to `false`
    // (src/packs/regex_engine.rs) — i.e. a pathological input would have
    // failed OPEN.
    //
    // The lookahead is the exact complement of the option alternative
    // (`--?[A-Za-z]...`), so the two are disjoint and the ambiguity is gone,
    // while values that merely START with a dash without being options
    // (`--jq -.x`, a negative number) still match. A blunter
    // `[^-\s;&|][^\s;&|]*` would also be unambiguous but would silently lose
    // those.

    // Subcommands to look ahead for: repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api
    // We use a robust value matcher that handles quoted strings to prevent bypasses.

    vec![
        safe_pattern!(
            "gh-repo-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+repo\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-gist-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+gist\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-release-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+release\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-issue-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+issue\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-ssh-key-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+ssh-key\s+list\b"
        ),
        safe_pattern!(
            "gh-secret-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+secret\s+list\b"
        ),
        safe_pattern!(
            "gh-variable-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+variable\s+list\b"
        ),
        safe_pattern!(
            "gh-auth-status",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+auth\s+status\b"
        ),
        safe_pattern!(
            "gh-status",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+status\b"
        ),
        // Safe API GETs
        safe_pattern!(
            "gh-api-explicit-get",
            r"^(?!(?=.*(?:-X\s*|--method(?:=|\s+))DELETE\b))gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))GET\b"
        ),
        // Help output (issue #380). `gh` is a cobra CLI: `--help` anywhere in
        // argv prints the command's usage and exits before any API call, so
        // `gh release delete v1 --help` is inert. Only tokens *before* a bare
        // `--` count — after it, `--help` is a positional (a tag name) and the
        // command really runs. A quoted token is consumed whole so a `--help`
        // embedded in an argument (`'x --help'`) never reads as the flag; a
        // token with unbalanced or attached quotes simply fails to match here
        // and falls through to the destructive rules (fail closed). The walk
        // also stops at `<`/`>`: a redirection target is the shell's, so
        // `... --yes > --help` is a real deletion writing to a file, not help.
        safe_pattern!(
            "gh-help",
            r"gh(?:\s+(?:\x22[^\x22]*\x22|'[^']*'|(?!--(?:\s|$))[^\s;&|<>\x22']+))*\s+--help(?:\s|$)"
        ),
        // `-h` is cobra's short help flag for every `gh` command that does not
        // reuse the letter. `gh repo edit` does (`-h` = `--homepage`), and it is
        // a guarded command, so the short spelling is only trusted when the
        // argv is not a `repo edit` invocation.
        safe_pattern!(
            "gh-help-short",
            r"gh(?!(?:\s+[^\s;&|]+)*?\s+repo\s+edit(?:\s|$))(?:\s+(?:\x22[^\x22]*\x22|'[^']*'|(?!--(?:\s|$))[^\s;&|<>\x22']+))*\s+-h(?:\s|$)"
        ),
        // `gh help <command...>` prints usage for the named command and never
        // runs it.
        safe_pattern!(
            "gh-help-topic",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+help(?:\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "gh-repo-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+repo\s+delete(?![\w-])",
            "gh repo delete permanently deletes a GitHub repository. This cannot be undone.",
            High,
            "Deleting a repository removes its code, issues, pull requests, releases, \
             wiki, and Actions history together. GitHub can restore a deleted repository \
             only within 90 days, only if the name has not been reused, and only via \
             support — it is not a self-service undo.\n\n\
             Safer alternatives:\n\
             - gh repo archive: makes it read-only while keeping everything visible \
             (dcg gates this one too, but it is reversible)\n\
             - gh repo view: confirms the target before any destructive action",
            &const {
                [
                    PatternSuggestion::new(
                        "gh repo view <owner>/<repo> --json name,visibility,isPrivate,pushedAt",
                        "Confirm which repository you are about to act on",
                    ),
                    PatternSuggestion::gated(
                        "gh repo archive <owner>/<repo>",
                        "Read-only instead of deleted (reversible)",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "gh-repo-visibility-change",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+repo\s+edit\b(?:\s+(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--visibility(?:=|\s+))[^\s;&|]+))*\s+--visibility(?:=|\s+)(?:(?:\x22[^\x22]+\x22)|(?:'[^']+')|[^\s;&|]+)",
            "gh repo edit --visibility changes repository visibility and can remove stars or detach forks.",
            High,
            "Changing repository visibility has consequences beyond access control. \
             GitHub warns that a transition can remove stars and watchers, detach public \
             forks, disable push rulesets, and expose Actions history or logs to newly \
             eligible users. Treat every visibility transition as a consequential \
             repository mutation and obtain explicit approval for the exact repository \
             and target visibility.",
            &const {
                [PatternSuggestion::new(
                    "gh repo view <owner>/<repo> --json nameWithOwner,visibility,isPrivate",
                    "Inspect the current repository and visibility before requesting approval",
                )]
            }
        ),
        destructive_pattern!(
            "gh-repo-archive",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+repo\s+archive(?![\w-])",
            "gh repo archive makes a repository read-only. While reversible, it stops all write access.",
            High,
            "Archiving is reversible, but until it is reversed nobody can push, open \
             issues, or comment, and automation that writes to the repository starts \
             failing. Unarchive from the web UI (Settings) or with the REST API.\n\n\
             Reverse it with:\n  \
             gh api -X PATCH repos/<owner>/<repo> -F archived=false",
            &const {
                [PatternSuggestion::new(
                    "gh api -X PATCH repos/<owner>/<repo> -F archived=false",
                    "Unarchive if this was not intended",
                )]
            }
        ),
        destructive_pattern!(
            "gh-gist-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+gist\s+delete(?![\w-])",
            "gh gist delete permanently deletes a Gist.",
            High,
            "Gist deletion is immediate and permanent — there is no trash and no \
             support-side restore. Any URL you have shared, and anything embedding the \
             Gist, breaks at once.\n\n\
             Save the contents first:\n  \
             gh gist view <id> > backup.txt",
            &const {
                [
                    PatternSuggestion::new(
                        "gh gist view <id>",
                        "Read the contents before destroying them",
                    ),
                    PatternSuggestion::new(
                        "gh gist edit <id> --add <file>",
                        "Edit in place instead of deleting and recreating",
                    ),
                ]
            }
        ),
        // The verb ends in `(?![\w-])`, not `\b`: `\b` sits between `delete`
        // and `-`, so it also matched the sibling `gh release delete-asset`
        // (issue #380). Asset deletion is its own rule below.
        destructive_pattern!(
            "gh-release-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+release\s+delete(?![\w-])",
            "gh release delete permanently deletes a release.",
            High,
            "Deleting a release destroys its uploaded assets. Anyone installing by that \
             release URL — install scripts, CI pipelines, package managers pinned to it — \
             starts getting 404s immediately, and the binaries cannot be recovered unless \
             you still have them locally.\n\n\
             Safer alternative:\n\
             - gh release edit <tag> --draft: unpublish while keeping the assets",
            &const {
                [
                    PatternSuggestion::new(
                        "gh release edit <tag> --draft",
                        "Unpublish but keep the release and its assets",
                    ),
                    PatternSuggestion::new(
                        "gh release download <tag>",
                        "Save the assets before deleting anything",
                    ),
                    PatternSuggestion::new(
                        "gh release view <tag>",
                        "Confirm which release the tag points at",
                    ),
                ]
            }
        ),
        // Deleting one uploaded asset is narrower than deleting the release
        // (the release, its tag, and every other asset survive), so it gets
        // its own rule id and a lower severity rather than being explained as
        // release deletion (issue #380).
        destructive_pattern!(
            "gh-release-delete-asset",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+release\s+delete-asset(?![\w-])",
            "gh release delete-asset permanently deletes an uploaded release asset.",
            Medium,
            "The release itself stays published, but the named asset is removed \
             immediately and cannot be restored from GitHub. Anything downloading that \
             asset by URL — install scripts, CI pipelines, package managers pinned to \
             it — starts getting 404s until an identical file is re-uploaded.\n\n\
             Safer alternatives:\n\
             - gh release download <tag> --pattern <asset>: keep a copy first\n\
             - gh release upload <tag> <file> --clobber: replace the asset in place",
            &const {
                [
                    PatternSuggestion::new(
                        "gh release view <tag>",
                        "List the release's assets and confirm the exact name",
                    ),
                    PatternSuggestion::new(
                        "gh release download <tag> --pattern <asset>",
                        "Save the asset before deleting it",
                    ),
                    PatternSuggestion::new(
                        "gh release upload <tag> <file> --clobber",
                        "Replace the asset in place instead of deleting it",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "gh-issue-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+issue\s+delete(?![\w-])",
            "gh issue delete permanently deletes an issue.",
            High,
            "Issue deletion is permanent and takes the whole discussion thread with it. \
             Almost every reason to delete an issue is better served by closing it, which \
             preserves the history and the cross-references other issues rely on.\n\n\
             Safer alternative:\n\
             - gh issue close <number> --reason 'not planned'",
            &const {
                [
                    PatternSuggestion::new(
                        "gh issue close <number> --reason \"not planned\"",
                        "Close it and keep the discussion history",
                    ),
                    PatternSuggestion::new(
                        "gh issue edit <number> --add-label duplicate",
                        "Mark it rather than destroying it",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "gh-ssh-key-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+ssh-key\s+delete(?![\w-])",
            "gh ssh-key delete removes an SSH key, potentially breaking access.",
            High,
            "Removing an SSH key takes effect immediately for every machine using it. If \
             it is the key for the session you are in, or the only key on a remote host, \
             you lose git push/pull access and may lock yourself out of automation that \
             authenticates with it.\n\n\
             Confirm which key you are about to remove:\n  \
             gh ssh-key list",
            &const {
                [PatternSuggestion::new(
                    "gh ssh-key list",
                    "Check which key the id refers to before removing it",
                )]
            }
        ),
        destructive_pattern!(
            "gh-secret-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+secret\s+(?:delete|remove)(?![\w-])",
            "gh secret delete removes GitHub Actions secrets.",
            High,
            "Secret values are write-only — GitHub will not show you the value, so a \
             deleted secret cannot be restored unless you hold it somewhere else. Every \
             workflow referencing it starts failing on the next run, often mid-deploy.\n\n\
             Safer alternative:\n\
             - gh secret set <NAME>: rotate the value in place, no window with it missing",
            &const {
                [
                    PatternSuggestion::new(
                        "gh secret set <NAME>",
                        "Rotate the value in place instead of deleting it",
                    ),
                    PatternSuggestion::new(
                        "gh secret list",
                        "Confirm the exact name and scope first",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "gh-variable-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+variable\s+(?:delete|remove)(?![\w-])",
            "gh variable delete removes GitHub Actions variables.",
            High,
            "Workflows referencing the variable resolve it to an empty string rather than \
             failing loudly, so the breakage can be silent — a deploy target or feature \
             flag quietly becomes blank.\n\n\
             Safer alternative:\n\
             - gh variable set <NAME>: change the value without a window where it is unset",
            &const {
                [
                    PatternSuggestion::new(
                        "gh variable set <NAME>",
                        "Update the value in place instead of deleting it",
                    ),
                    PatternSuggestion::new(
                        "gh variable list",
                        "Confirm the exact name and scope first",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "gh-repo-deploy-key-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+repo\s+deploy-key\s+delete(?![\w-])",
            "gh repo deploy-key delete removes a deploy key and can break access.",
            High,
            "Deploy keys are how servers and CI clone this repository without a user \
             account. Removing one breaks those consumers immediately, and the failure \
             usually surfaces on someone else's next deploy rather than here.\n\n\
             Confirm what depends on it:\n  \
             gh repo deploy-key list",
            &const {
                [PatternSuggestion::new(
                    "gh repo deploy-key list",
                    "See which key the id refers to and when it was last used",
                )]
            }
        ),
        destructive_pattern!(
            "gh-run-cancel",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+run\s+cancel(?![\w-])",
            "gh run cancel stops a workflow run and may interrupt deployments.",
            High,
            "Cancelling mid-run can leave a deployment half-applied: a job that has \
             already pushed some resources stops before its cleanup or rollback steps. \
             Check what the run is doing before stopping it.\n\n\
             Inspect first:\n  \
             gh run view <run-id>",
            &const {
                [
                    PatternSuggestion::new(
                        "gh run view <run-id>",
                        "See which jobs are in flight before cancelling",
                    ),
                    PatternSuggestion::new(
                        "gh run watch <run-id>",
                        "Wait for it to finish instead of interrupting it",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "gh-api-delete-actions-secret",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/actions/secrets/",
            "gh api DELETE actions/secrets removes GitHub Actions secrets.",
            High,
            "Secret values are write-only, so a deleted secret cannot be read back or \
             restored. Every workflow referencing it fails on the next run.\n\n\
             Safer alternative:\n\
             - gh secret set <NAME>: rotate the value in place via the first-class verb",
            &const {
                [
                    PatternSuggestion::new(
                        "gh secret set <NAME>",
                        "Rotate the value instead of deleting it",
                    ),
                    PatternSuggestion::new("gh secret list", "Confirm the name and scope first"),
                ]
            }
        ),
        destructive_pattern!(
            "gh-api-delete-actions-variable",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/actions/variables/",
            "gh api DELETE actions/variables removes GitHub Actions variables.",
            High,
            "Workflows referencing a missing variable resolve it to an empty string rather \
             than failing loudly, so the breakage is easy to miss.\n\n\
             Safer alternative:\n\
             - gh variable set <NAME>: update the value via the first-class verb",
            &const {
                [
                    PatternSuggestion::new(
                        "gh variable set <NAME>",
                        "Update the value instead of deleting it",
                    ),
                    PatternSuggestion::new("gh variable list", "Confirm the name and scope first"),
                ]
            }
        ),
        destructive_pattern!(
            "gh-api-delete-hook",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/hooks/",
            "gh api DELETE hooks removes repository webhooks.",
            High,
            "Removing a webhook silently stops every downstream integration it feeds — CI \
             triggers, chat notifications, deployment hooks. Nothing errors; events simply \
             stop arriving, so the failure surfaces late and somewhere else.\n\n\
             Inspect first, and note the config so it can be recreated:\n  \
             gh api repos/<owner>/<repo>/hooks",
            &const {
                [
                    PatternSuggestion::new(
                        "gh api repos/<owner>/<repo>/hooks",
                        "Record the hook config before removing it",
                    ),
                    PatternSuggestion::new(
                        "gh api -X PATCH repos/<owner>/<repo>/hooks/<id> -F active=false",
                        "Disable the hook reversibly instead of deleting it",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "gh-api-delete-deploy-key",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/keys/",
            "gh api DELETE keys removes deploy keys.",
            High,
            "Deploy keys are how servers and CI clone this repository without a user \
             account. Removing one breaks those consumers immediately, usually surfacing \
             on someone else's next deploy.\n\n\
             Confirm what depends on it:\n  \
             gh repo deploy-key list",
            &const {
                [PatternSuggestion::new(
                    "gh repo deploy-key list",
                    "See which key the id refers to and when it was last used",
                )]
            }
        ),
        destructive_pattern!(
            "gh-api-delete-release",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/releases/",
            "gh api DELETE releases removes GitHub releases.",
            High,
            "Deleting a release destroys its uploaded assets. Install scripts and pinned \
             CI jobs that fetch by that release URL start getting 404s immediately.\n\n\
             Safer alternative:\n\
             - gh release edit <tag> --draft: unpublish while keeping the assets",
            &const {
                [
                    PatternSuggestion::new(
                        "gh release edit <tag> --draft",
                        "Unpublish but keep the release and its assets",
                    ),
                    PatternSuggestion::new(
                        "gh release download <tag>",
                        "Save the assets before deleting anything",
                    ),
                ]
            }
        ),
        // DELETE /repos/{owner}/{repo} -> delete a repository. Must stay AFTER
        // the sub-resource rules above (first match wins) and BEFORE the
        // generic catch-all below; the trailing guard keeps it from claiming
        // deeper paths such as /repos/o/r/issues/1/sub_issue.
        destructive_pattern!(
            "gh-api-delete-repo",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/?(?:[\x22'\s]|$)",
            "gh api DELETE /repos/{owner}/{repo} permanently deletes a GitHub repository. This cannot be undone.",
            High,
            "This is the raw-API spelling of `gh repo delete`. It removes the code, \
             issues, pull requests, releases, wiki, and Actions history together. GitHub \
             can restore a deleted repository only within 90 days, only if the name has \
             not been reused, and only via support.\n\n\
             Safer alternatives:\n\
             - gh api -X PATCH repos/<owner>/<repo> -F archived=true: read-only, via the API\n\
             - gh repo archive: the same thing via the first-class verb (dcg gates \
             that one too, but archiving is reversible)",
            &const {
                [
                    PatternSuggestion::new(
                        "gh api -X PATCH repos/<owner>/<repo> -F archived=true",
                        "Make it read-only instead of deleting it",
                    ),
                    PatternSuggestion::new(
                        "gh repo view <owner>/<repo> --json name,isPrivate,pushedAt",
                        "Confirm which repository you are about to delete",
                    ),
                ]
            }
        ),
        // Catch-all for every other `gh api ... DELETE`. Deliberately last:
        // the rules above claim the endpoints whose consequences are known,
        // and this one covers the rest, including endpoints that did not exist
        // when this pack was written.
        destructive_pattern!(
            "gh-api-delete-generic",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|(?!--?[A-Za-z])[^\s;&|]+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b",
            "gh api DELETE calls can be destructive. Please verify the endpoint.",
            High,
            "This is the catch-all for raw-API deletions whose endpoint this pack does not \
             recognize, so the blast radius is unknown rather than known-large — it covers \
             both `DELETE /repos/{owner}/{repo}` scale operations and routine ones like \
             removing a label or an assignee.\n\n\
             Before reaching for a raw API DELETE, check whether `gh` has a first-class \
             verb for it: those are more readable, and several are allowed outright. For \
             example, sub-issue hierarchy has dedicated verbs:\n\
             - gh issue edit <child> --remove-parent\n\
             - gh issue edit <parent> --remove-sub-issue <number>\n\n\
             Preview what the endpoint returns before deleting it:\n  \
             gh api <endpoint>",
            &const {
                [
                    PatternSuggestion::new(
                        "gh <resource> delete|remove ...",
                        "Prefer a first-class gh verb over a raw API DELETE",
                    ),
                    PatternSuggestion::new(
                        "gh issue edit <child> --remove-parent",
                        "Sub-issue hierarchy has dedicated verbs (this one is allowed)",
                    ),
                    PatternSuggestion::new(
                        "gh api <endpoint>",
                        "GET the endpoint first to see exactly what you are removing",
                    ),
                ]
            }
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn allows_safe_variants() {
        let pack = create_pack();
        assert!(pack.check("gh repo list").is_none());
        assert!(pack.check("gh repo view").is_none());
        assert!(pack.check("gh gist list").is_none());
        assert!(pack.check("gh release view v1.0").is_none());
        assert!(pack.check("gh issue list").is_none());
        assert!(pack.check("gh ssh-key list").is_none());
        assert!(pack.check("gh secret list").is_none());
        assert!(pack.check("gh variable list").is_none());
        assert!(pack.check("gh auth status").is_none());
        assert!(pack.check("gh status").is_none());

        // With global flags
        assert!(pack.check("gh -R owner/repo repo view").is_none());
        assert!(pack.check("gh -R owner/repo secret list").is_none());
    }

    #[test]
    fn blocks_destructive_variants() {
        let mut pack = create_pack();
        // Manually inject keywords for testing if needed
        pack.keywords = &["gh"];

        let checks = vec![
            ("gh repo delete owner/repo", "gh-repo-delete"),
            ("gh -R owner/repo repo delete", "gh-repo-delete"),
            (
                "gh repo edit owner/repo --visibility private --accept-visibility-change-consequences",
                "gh-repo-visibility-change",
            ),
            (
                "gh repo edit --visibility=internal owner/repo",
                "gh-repo-visibility-change",
            ),
            (
                "gh -R owner/repo repo edit --visibility public",
                "gh-repo-visibility-change",
            ),
            ("gh repo archive owner/repo", "gh-repo-archive"),
            ("gh gist delete 123", "gh-gist-delete"),
            ("gh release delete v1.0", "gh-release-delete"),
            ("gh issue delete 1", "gh-issue-delete"),
            ("gh ssh-key delete 1", "gh-ssh-key-delete"),
            ("gh secret delete SECRET_NAME", "gh-secret-delete"),
            ("gh secret remove SECRET_NAME", "gh-secret-delete"),
            ("gh variable delete VAR_NAME", "gh-variable-delete"),
            ("gh variable remove VAR_NAME", "gh-variable-delete"),
            ("gh repo deploy-key delete 123", "gh-repo-deploy-key-delete"),
            ("gh run cancel 123456", "gh-run-cancel"),
            (
                "gh api -X DELETE /repos/owner/repo/actions/secrets/SECRET",
                "gh-api-delete-actions-secret",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/actions/variables/VAR",
                "gh-api-delete-actions-variable",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/hooks/123",
                "gh-api-delete-hook",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/keys/456",
                "gh-api-delete-deploy-key",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/releases/1",
                "gh-api-delete-release",
            ),
            ("gh api -X DELETE /repos/owner/repo", "gh-api-delete-repo"),
        ];

        for (cmd, expected_rule) in checks {
            let matched = pack
                .check(cmd)
                .unwrap_or_else(|| panic!("Should block: {cmd}"));
            assert_eq!(matched.name, Some(expected_rule), "Command: {cmd}");
        }
    }

    #[test]
    fn github_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "gh repo delete owner/repo", "gh-repo-delete");
        assert_blocks_with_pattern(
            &pack,
            "gh repo edit owner/repo --visibility private --accept-visibility-change-consequences",
            "gh-repo-visibility-change",
        );
        assert_blocks_with_pattern(&pack, "gh repo archive owner/repo", "gh-repo-archive");
        assert_blocks_with_pattern(&pack, "gh gist delete 123", "gh-gist-delete");
        assert_blocks_with_pattern(&pack, "gh release delete v1.0", "gh-release-delete");
        assert_blocks_with_pattern(&pack, "gh issue delete 1", "gh-issue-delete");
        assert_blocks_with_pattern(&pack, "gh ssh-key delete 1", "gh-ssh-key-delete");
        assert_blocks_with_pattern(&pack, "gh secret delete SECRET_NAME", "gh-secret-delete");
        assert_blocks_with_pattern(&pack, "gh variable delete VAR_NAME", "gh-variable-delete");
        assert_blocks_with_pattern(
            &pack,
            "gh repo deploy-key delete 123",
            "gh-repo-deploy-key-delete",
        );
        assert_blocks_with_pattern(&pack, "gh run cancel 123456", "gh-run-cancel");
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/actions/secrets/SECRET",
            "gh-api-delete-actions-secret",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/actions/variables/VAR",
            "gh-api-delete-actions-variable",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/hooks/123",
            "gh-api-delete-hook",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/keys/456",
            "gh-api-delete-deploy-key",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/releases/1",
            "gh-api-delete-release",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo",
            "gh-api-delete-repo",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/issues/1751/sub_issue",
            "gh-api-delete-generic",
        );
    }

    /// `gh-api-delete-repo` must mean repository deletion and nothing else.
    /// It used to be a catch-all matching ANY `gh api ... DELETE`, which made
    /// the rule_id — the key that surfaces in the history DB, `dcg stats`, and
    /// allowlist entries — actively misleading. Deeper endpoints now fall to
    /// `gh-api-delete-generic`; both are still denied.
    #[test]
    fn gh_api_delete_repo_is_not_a_catch_all() {
        let pack = create_pack();

        for command in [
            "gh api -X DELETE /repos/owner/repo/issues/1751/sub_issue",
            "gh api -X DELETE repos/owner/repo/issues/42/labels/bug",
            "gh api --method DELETE /repos/owner/repo/issues/7/assignees",
            "gh api -X DELETE /user/starred/owner/repo/extra",
        ] {
            assert_blocks_with_pattern(&pack, command, "gh-api-delete-generic");
        }

        // The repository endpoint itself, with and without a leading slash or
        // trailing slash, still belongs to the specific rule.
        for command in [
            "gh api -X DELETE /repos/owner/repo",
            "gh api -X DELETE repos/owner/repo",
            "gh api -X DELETE /repos/owner/repo/",
            "gh api --method=DELETE /repos/owner/repo",
        ] {
            assert_blocks_with_pattern(&pack, command, "gh-api-delete-repo");
        }
    }

    /// Issue #300: a denial that names the sanctioned alternative gets
    /// corrected on the agent's next turn; one that says "verify the endpoint"
    /// does not. Every destructive rule in this pack must carry an
    /// explanation and at least one suggestion.
    #[test]
    fn github_destructive_patterns_have_explanations_and_suggestions() {
        let pack = create_pack();

        for pattern in &pack.destructive_patterns {
            let name = pattern.name.expect("every github rule is named");
            assert!(
                pattern
                    .explanation
                    .is_some_and(|text| !text.trim().is_empty()),
                "{name} has no explanation, so its denial renders as \
                 \"No additional explanation is available yet\""
            );
            assert!(
                !pattern.suggestions.is_empty(),
                "{name} offers the agent no alternative to try"
            );
        }
    }

    #[test]
    fn github_blocks_with_correct_severity() {
        let pack = create_pack();
        // All github destructive patterns use default severity (High)
        assert_blocks_with_severity(&pack, "gh repo delete owner/repo", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "gh repo edit owner/repo --visibility private",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "gh repo archive owner/repo", Severity::High);
        assert_blocks_with_severity(&pack, "gh gist delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "gh release delete v1.0", Severity::High);
        assert_blocks_with_severity(&pack, "gh issue delete 1", Severity::High);
        assert_blocks_with_severity(&pack, "gh ssh-key delete 1", Severity::High);
        assert_blocks_with_severity(&pack, "gh secret delete SECRET_NAME", Severity::High);
        assert_blocks_with_severity(&pack, "gh variable delete VAR_NAME", Severity::High);
        assert_blocks_with_severity(&pack, "gh repo deploy-key delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "gh run cancel 123456", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "gh api -XDELETE /repos/owner/repo/actions/secrets/SECRET",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "gh api --method=DELETE /repos/owner/repo",
            Severity::High,
        );
    }

    #[test]
    fn github_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "gh repo list");
        assert_safe_pattern_matches(&pack, "gh repo view");
        assert_safe_pattern_matches(&pack, "gh gist list");
        assert_safe_pattern_matches(&pack, "gh gist view abc123");
        assert_safe_pattern_matches(&pack, "gh release list");
        assert_safe_pattern_matches(&pack, "gh release view v1.0");
        assert_safe_pattern_matches(&pack, "gh issue list");
        assert_safe_pattern_matches(&pack, "gh issue view 42");
        assert_safe_pattern_matches(&pack, "gh ssh-key list");
        assert_safe_pattern_matches(&pack, "gh secret list");
        assert_safe_pattern_matches(&pack, "gh variable list");
        assert_safe_pattern_matches(&pack, "gh auth status");
        assert_safe_pattern_matches(&pack, "gh status");
        assert_safe_pattern_matches(&pack, "gh api -X GET /repos/owner/repo");
    }

    #[test]
    fn gh_api_get_safe_pattern_does_not_mask_delete_methods() {
        let pack = create_pack();
        let command = "gh api -X GET /repos/owner/repo/actions/secrets \
            -XDELETE /repos/owner/repo/actions/secrets/SECRET";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "gh-api-delete-actions-secret");
    }

    /// The option-value alternative must accept a value that merely starts
    /// with a dash while still refusing anything option-shaped. A blunter
    /// "no leading dash" rule is unambiguous too, but silently loses these.
    #[test]
    fn option_values_that_start_with_a_dash_do_not_defeat_rules() {
        let pack = create_pack();
        for command in [
            "gh repo delete acme/widgets",
            "gh --jq -.name repo delete acme/widgets",
            "gh --limit -1 repo delete acme/widgets",
        ] {
            assert_blocks_with_pattern(&pack, command, "gh-repo-delete");
        }
        assert_blocks_with_pattern(&pack, "gh -t -5 run cancel 1", "gh-run-cancel");
    }

    /// A long run of flags must not blow up the backtracking engine. A
    /// backtrack-limit error is mapped to "no match", so a pathological input
    /// would fail OPEN — this pins that the parse stays unambiguous.
    #[test]
    fn many_flags_do_not_explode_the_matcher() {
        let pack = create_pack();
        let flags = (0..40)
            .map(|i| format!("--flag{i}"))
            .collect::<Vec<_>>()
            .join(" ");

        assert!(
            pack.check(&format!("gh {flags} status")).is_none(),
            "a long benign flag run must resolve, not exhaust the backtrack budget"
        );
        assert_blocks_with_pattern(
            &pack,
            &format!("gh {flags} repo delete acme/widgets"),
            "gh-repo-delete",
        );
    }

    #[test]
    fn github_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(
            &pack,
            "gh repo edit acme/widgets --description \"--visibility private\"",
        );
        assert_no_match(&pack, "gh repo edit acme/widgets --enable-issues");
    }

    /// A denial that recommends a command this same pack blocks is a dead end
    /// — the agent bounces between two blocks and learns nothing. The FIRST
    /// suggestion in particular must be something it can actually run.
    ///
    /// Suggestions constructed with `PatternSuggestion::gated` are excused:
    /// they are explicitly presented as still-gated forms (#316), and the
    /// registry-wide sweep in `tests/suggestion_self_consistency.rs` holds
    /// every non-gated suggestion in every pack to the same standard.
    #[test]
    fn first_suggestion_is_never_blocked_by_this_pack() {
        let pack = create_pack();

        for pattern in &pack.destructive_patterns {
            let name = pattern.name.expect("every github rule is named");
            let Some(first) = pattern.suggestions.first() else {
                continue;
            };
            if first.gated {
                continue;
            }
            // Placeholders are illustrative, not runnable; substitute
            // something concrete so the regexes see a realistic command.
            let command = first
                .command
                .replace("<owner>/<repo>", "acme/widgets")
                .replace("<resource-name>", "abc")
                .replace("<location>", "US")
                .replace("<tag>", "v1.2.3")
                .replace("<number>", "42")
                .replace("<id>", "123")
                .replace("<NAME>", "MY_SECRET")
                .replace("<endpoint>", "repos/acme/widgets/issues")
                .replace("<run-id>", "999")
                .replace("<child>", "7");

            assert!(
                pack.check(&command).is_none(),
                "{name}'s first suggestion is blocked by this same pack, so the \
                 denial is a dead end: {command}"
            );
        }
    }

    // =========================================================================
    // Issue #380: `delete\b` matched `delete-asset`, and `--help` was denied
    // =========================================================================

    /// `gh release delete-asset` is a different command from `gh release
    /// delete`: it must never be attributed to (or explained as) release
    /// deletion, and it carries its own lower severity.
    #[test]
    fn release_delete_asset_is_its_own_rule_issue_380() {
        let pack = create_pack();

        for command in [
            "gh release delete-asset v1 file.tgz",
            "gh release delete-asset v1 file.tgz -y",
            "gh release delete-asset v1.2.3 dcg-x86_64.tar.xz --yes --repo owner/project",
            "gh -R owner/project release delete-asset v1 file.tgz",
        ] {
            assert_blocks_with_pattern(&pack, command, "gh-release-delete-asset");
            assert_blocks_with_severity(&pack, command, Severity::Medium);
        }

        // The whole-release rule keeps its exact spelling and severity.
        for command in [
            "gh release delete v1",
            "gh release delete v1 --yes --cleanup-tag",
            "gh release delete v1.2.3 --yes --repo owner/project",
        ] {
            assert_blocks_with_pattern(&pack, command, "gh-release-delete");
            assert_blocks_with_severity(&pack, command, Severity::High);
        }
    }

    /// `--help` / `-h` print usage and exit before any API call, so every
    /// guarded `gh` command is inert with them — wherever the flag sits.
    #[test]
    fn help_invocations_are_inert_issue_380() {
        let pack = create_pack();

        for command in [
            "gh release delete-asset --help",
            "gh release delete-asset v1 file.tgz --help",
            "gh release delete --help",
            "gh release delete v1 --help",
            "gh release delete v1 --yes --cleanup-tag --help",
            "gh release delete --help v1",
            "gh release delete -h",
            "gh release delete-asset v1 file.tgz -h",
            "gh repo delete --help",
            "gh repo delete acme/widgets -h",
            "gh repo edit --help",
            "gh repo edit acme/widgets --visibility private --help",
            "gh repo archive --help",
            "gh gist delete --help",
            "gh issue delete 1 --help",
            "gh ssh-key delete --help",
            "gh secret delete NAME --help",
            "gh variable delete NAME -h",
            "gh repo deploy-key delete --help",
            "gh run cancel --help",
            "gh api --help",
            "gh --help",
            "gh help release delete",
            "gh help release delete-asset",
            "gh help repo delete",
            "gh release delete 'v1' --help",
            "gh release delete \"v1\" -h",
        ] {
            assert_safe_pattern_matches(&pack, command);
            assert_allows(&pack, command);
        }
    }

    /// The help carve-out is exact about what counts as the help flag.
    #[test]
    fn help_lookalikes_do_not_disarm_destructive_rules_issue_380() {
        let pack = create_pack();

        // After a bare `--`, `--help` is a positional (the tag to delete).
        assert_no_safe_match(&pack, "gh release delete -- --help");
        assert_blocks_with_pattern(&pack, "gh release delete -- --help", "gh-release-delete");
        assert_blocks_with_pattern(
            &pack,
            "gh release delete-asset v1 -- --help",
            "gh-release-delete-asset",
        );

        // A `--help` inside a quoted argument is argument text, not the flag.
        assert_no_safe_match(&pack, "gh release delete 'v1 --help'");
        assert_blocks_with_pattern(&pack, "gh release delete 'v1 --help'", "gh-release-delete");
        assert_blocks_with_pattern(
            &pack,
            "gh release delete \"tag --help\" --yes",
            "gh-release-delete",
        );

        // `gh repo edit -h` is `--homepage`, not help.
        assert_no_safe_match(
            &pack,
            "gh repo edit acme/widgets -h https://example.com --visibility private",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh repo edit acme/widgets -h https://example.com --visibility private",
            "gh-repo-visibility-change",
        );

        // A redirection target named `--help` is the shell's, not gh's: the
        // command still runs `release delete`.
        for command in [
            "gh release delete v1 --yes > --help",
            "gh release delete v1 --yes >--help",
            "gh release delete v1 --yes 2> --help",
            "gh release delete v1 --yes < --help",
            "gh release delete v1 -y > -h",
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks_with_pattern(&pack, command, "gh-release-delete");
        }

        // A prefix of the flag is not the flag.
        assert_blocks_with_pattern(&pack, "gh release delete v1 --hel", "gh-release-delete");
        assert_blocks_with_pattern(&pack, "gh release delete v1 --helpme", "gh-release-delete");

        // A help invocation in one segment does not shield a real deletion in
        // the next.
        assert_blocks_with_pattern(
            &pack,
            "gh release view --help && gh release delete v1 --yes",
            "gh-release-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh help release delete; gh release delete-asset v1 file.tgz",
            "gh-release-delete-asset",
        );
    }

    /// Every verb in this pack ends on a token boundary that excludes `-`,
    /// so a hyphenated sibling subcommand can never inherit a rule (the
    /// `delete\b` / `delete-asset` shape of #380).
    #[test]
    fn destructive_verbs_stop_at_hyphenated_siblings_issue_380() {
        let pack = create_pack();
        // Invented hyphenated siblings, deliberately without `--help` so the
        // boundary itself (not the help carve-out) is what keeps them clear.
        for command in [
            "gh repo delete-something acme/widgets",
            "gh repo archive-all acme/widgets",
            "gh gist delete-x 123",
            "gh issue delete-y 1",
            "gh ssh-key delete-old 1",
            "gh run cancel-all 123456",
            "gh secret delete-all NAME",
            "gh variable remove-all NAME",
            "gh repo deploy-key delete-stale 123",
        ] {
            let matched = pack.check(command);
            assert!(
                matched.is_none(),
                "{command} matched {:?} through a hyphenated sibling",
                matched.map(|m| m.name)
            );
        }
        // The `gh api` rules end on an HTTP method or an endpoint path, not a
        // subcommand verb, so only the verb-shaped rules are held to this.
        for pattern in pack
            .destructive_patterns
            .iter()
            .filter(|pattern| !pattern.name.is_some_and(|name| name.starts_with("gh-api-")))
        {
            let source = pattern.regex.as_str();
            assert!(
                !source.ends_with(r"\b"),
                "{:?} ends in `\\b`, which matches before `-` and therefore \
                 also matches hyphenated sibling subcommands",
                pattern.name
            );
        }
    }
}
