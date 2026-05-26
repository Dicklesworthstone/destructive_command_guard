//! Modal Platform pack - protections for destructive Modal CLI operations.
//!
//! Modal is a serverless Python platform. Its CLI surface accepts `-y`/`--yes`
//! on destructive commands to skip Modal's own interactive confirmation, and AI
//! coding agents routinely pass that flag to keep commands non-interactive. This
//! pack blocks operations that can delete or wipe Modal Volumes (model weights,
//! datasets, checkpoints), Secrets, Apps, Containers, Environments, Dicts, or
//! Queues — regardless of whether `--yes` is present.

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

const APP_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "modal app list",
        "List Modal apps to confirm the target before stopping it",
    ),
    PatternSuggestion::new(
        "modal app logs <app>",
        "Inspect app state without terminating its containers",
    ),
    PatternSuggestion::new(
        "modal app rollback <app> <version>",
        "Roll back to a previous deploy instead of stopping the app",
    ),
];

const CONTAINER_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "modal container list",
        "List running Modal containers before terminating one",
    ),
    PatternSuggestion::new(
        "modal container logs <container_id>",
        "Inspect a container without stopping it",
    ),
];

const ENVIRONMENT_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "modal environment list",
        "List Modal environments to verify you are not deleting prod",
    ),
    PatternSuggestion::new(
        "modal environment update",
        "Update an environment in place instead of deleting it",
    ),
];

const VOLUME_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "modal volume list",
        "List Modal Volumes to verify the target before deletion",
    ),
    PatternSuggestion::new(
        "modal volume ls <volume> <path>",
        "Inspect Volume contents before deleting files",
    ),
    PatternSuggestion::new(
        "modal volume cp <volume> <src> <dest>",
        "Copy data out of the Volume as a backup before destructive ops",
    ),
];

const SECRET_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "modal secret list",
        "List Modal Secrets before deleting or overwriting one",
    ),
    PatternSuggestion::new(
        "modal secret create <new-name> ...",
        "Create a new secret with a versioned name instead of force-overwriting",
    ),
];

const DICT_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "modal dict list",
        "List Modal Dicts before deleting or clearing one",
    ),
    PatternSuggestion::new(
        "modal dict items <name>",
        "Inspect Dict contents before destructive ops",
    ),
];

const QUEUE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "modal queue list",
        "List Modal Queues before deleting or clearing one",
    ),
    PatternSuggestion::new(
        "modal queue peek <name>",
        "Inspect Queue contents before destructive ops",
    ),
    PatternSuggestion::new(
        "modal queue len <name>",
        "Check Queue length before clearing it",
    ),
];

/// Create the Modal Platform pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.modal".to_string(),
        name: "Modal Platform",
        description: "Protects against destructive Modal CLI operations that can delete or wipe Modal Volumes, Secrets, Apps, Containers, Environments, Dicts, or Queues. Catches commands even when `-y`/`--yes` is passed to bypass interactive confirmation.",
        keywords: &["modal"],
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
        // Volume — read-only and non-destructive ops
        safe_pattern!(
            "modal-volume-list",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:list|ls)\b"
        ),
        safe_pattern!(
            "modal-volume-get",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:get|cp|cat)\b"
        ),
        safe_pattern!(
            "modal-volume-create",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:create|rename)\b"
        ),
        // App — inspection only
        safe_pattern!(
            "modal-app-readonly",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+app\s+(?:list|ls|logs|history|dashboard|rollback|rollover)\b"
        ),
        // Container — inspection / exec (exec is interactive, not a destructive resource op)
        safe_pattern!(
            "modal-container-readonly",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+container\s+(?:list|ls|logs|exec)\b"
        ),
        // Secret — list and create-without-force
        safe_pattern!(
            "modal-secret-list",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+(?:list|ls)\b"
        ),
        safe_pattern!(
            "modal-secret-create-no-force",
            // Negative lookahead must allow `\\\r?\n` shell line continuation
            // inside the scanned region, otherwise `modal secret create \
            // --force ...` (continued across lines) is falsely matched as
            // safe — the lookahead stops at `\n` and never sees `--force`.
            // Mirrors the destructive pattern's `(?:[^;&|\r\n]|\\\r?\n)*` body.
            // The pattern is allow-listed in `pattern_audit.rs` because the
            // `(?!...)` lookahead forces use of the backtracking engine.
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+create\b(?!(?:[^;&|\r\n]|\\\r?\n)*(?:--force|--overwrite)\b)"
        ),
        // Environment — list and non-destructive lifecycle
        safe_pattern!(
            "modal-environment-list",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:list|ls)\b"
        ),
        safe_pattern!(
            "modal-environment-mutate",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:create|update)\b"
        ),
        // Dict — read-only and create
        safe_pattern!(
            "modal-dict-readonly",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+dict\s+(?:list|ls|get|items|create)\b"
        ),
        // Queue — read-only and create
        safe_pattern!(
            "modal-queue-readonly",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+queue\s+(?:list|ls|peek|len|create)\b"
        ),
        // Shell / deploy / serve / token — non-destructive
        safe_pattern!("modal-shell", r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+shell\b"),
        safe_pattern!(
            "modal-deploy",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:deploy|serve|run|profile|launch)\b"
        ),
        safe_pattern!(
            "modal-token",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+token\s+(?:info|new|set)\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // --- Critical: deletion of named first-class resources ---
        destructive_pattern!(
            "modal-environment-delete",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:delete|remove|rm)\b",
            "modal environment delete schedules removal of an entire Modal environment.",
            Critical,
            "Deleting a Modal environment removes the environment and every Modal app inside it — irrecoverable. Agents passing --yes bypass Modal's confirmation prompt entirely.",
            ENVIRONMENT_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-volume-delete",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:delete|remove)\b",
            "modal volume delete removes a Modal Volume and all data inside it.",
            Critical,
            "Deleting a Modal Volume destroys persistent ML artifacts: model weights, datasets, checkpoints. There is no undo. Agents passing --yes bypass Modal's confirmation prompt entirely.",
            VOLUME_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-secret-delete",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+(?:delete|remove|rm)\b",
            "modal secret delete permanently removes a published Modal Secret.",
            Critical,
            "Deleting a Modal Secret can immediately break every running app that references it (API keys, DB credentials, OAuth tokens). Agents passing --yes bypass Modal's confirmation prompt entirely.",
            SECRET_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-dict-delete",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+dict\s+(?:delete|remove|rm)\b",
            "modal dict delete removes a named Modal Dict and all its data.",
            Critical,
            "Deleting a Modal Dict can destroy authoritative state that an app treats as a transient cache when it actually is not. Agents passing --yes bypass Modal's confirmation prompt entirely.",
            DICT_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-queue-delete",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+queue\s+(?:delete|remove|rm)\b",
            "modal queue delete removes a named Modal Queue and all its data.",
            Critical,
            "Deleting a Modal Queue discards every message currently in flight or buffered. Agents passing --yes bypass Modal's confirmation prompt entirely.",
            QUEUE_SUGGESTIONS
        ),
        // --- High: terminate work / wipe contents (recoverable in principle) ---
        destructive_pattern!(
            "modal-app-stop",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+app\s+stop\b",
            "modal app stop terminates a Modal app and its running containers.",
            High,
            "Stopping a Modal app permanently stops it and terminates running containers; in-progress inputs are lost or reassigned. Use `modal app rollback` to roll back without stopping.",
            APP_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-container-stop",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+container\s+stop\b",
            "modal container stop terminates a running Modal container and reassigns inputs.",
            High,
            "Stopping a Modal container interrupts in-flight work. The platform may reassign inputs, but exactly-once semantics are not guaranteed.",
            CONTAINER_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-volume-rm-recursive",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+rm\b(?:[^;&|\r\n]|\\\r?\n)*(?:\s|=)(?:-r\b|-R\b|--recursive\b)",
            "modal volume rm -r recursively deletes files inside a Modal Volume.",
            High,
            "Recursive `modal volume rm` can wipe entire subdirectories of persistent storage (datasets, checkpoints). Catastrophic when the target is wrong.",
            VOLUME_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-dict-clear",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+dict\s+clear\b",
            "modal dict clear empties a Modal Dict.",
            High,
            "Clearing a Modal Dict deletes every entry but leaves the Dict object. If the Dict holds authoritative state, this is data loss.",
            DICT_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-queue-clear",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+queue\s+clear\b",
            "modal queue clear drains every message from a Modal Queue.",
            High,
            "Clearing a Modal Queue drops every buffered message. If consumers have not yet processed them, the work is lost.",
            QUEUE_SUGGESTIONS
        ),
        // --- Medium: single-item delete / overwrite ---
        destructive_pattern!(
            "modal-volume-rm",
            // Negative lookahead must allow `\\\r?\n` shell line continuation
            // so a command like `modal volume rm my-vol \\\n-r /dir` (continued
            // across lines) is correctly routed to the High-severity recursive
            // pattern rather than falling through to this Medium pattern. Same
            // asymmetry-fix as the secret-create-no-force lookahead above.
            // Allow-listed in `pattern_audit.rs`.
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+rm\b(?!(?:[^;&|\r\n]|\\\r?\n)*(?:\s|=)(?:-r\b|-R\b|--recursive\b))",
            "modal volume rm deletes a file inside a Modal Volume.",
            Medium,
            "Single-file deletion inside a Volume is recoverable only if you have an external copy. Verify the target path before running.",
            VOLUME_SUGGESTIONS
        ),
        destructive_pattern!(
            "modal-secret-create-force",
            r"\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+create\b(?:[^;&|\r\n]|\\\r?\n)*(?:--force|--overwrite)\b",
            "modal secret create --force overwrites an existing Modal Secret in place.",
            Medium,
            "Overwriting a Secret with --force changes the value used by every app that references it on next cold start — common cause of unintended prod credential rotation.",
            SECRET_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "platform.modal");
        assert_eq!(pack.name, "Modal Platform");
        assert!(pack.keywords.contains(&"modal"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_read_only_cli_commands() {
        let pack = create_pack();
        assert_allows(&pack, "modal volume list");
        assert_allows(&pack, "modal volume ls my-vol");
        assert_allows(&pack, "modal volume ls my-vol /checkpoints");
        assert_allows(&pack, "modal volume get my-vol /file.bin ./file.bin");
        assert_allows(&pack, "modal volume cp my-vol /a /b");
        assert_allows(&pack, "modal volume create my-vol");
        assert_allows(&pack, "modal volume rename old new");
        assert_allows(&pack, "modal app list");
        assert_allows(&pack, "modal app logs my-app");
        assert_allows(&pack, "modal app history my-app");
        assert_allows(&pack, "modal app dashboard my-app");
        assert_allows(&pack, "modal app rollback my-app v3");
        assert_allows(&pack, "modal app rollover my-app");
        assert_allows(&pack, "modal container list");
        assert_allows(&pack, "modal container logs ta-1");
        assert_allows(&pack, "modal container exec ta-1 bash");
        assert_allows(&pack, "modal secret list");
        assert_allows(&pack, "modal secret create api-key VALUE=xxx");
        assert_allows(&pack, "modal environment list");
        assert_allows(&pack, "modal environment create staging");
        assert_allows(&pack, "modal environment update prod");
        assert_allows(&pack, "modal dict list");
        assert_allows(&pack, "modal dict get my-dict key");
        assert_allows(&pack, "modal dict items my-dict");
        assert_allows(&pack, "modal dict create my-dict");
        assert_allows(&pack, "modal queue list");
        assert_allows(&pack, "modal queue peek my-q");
        assert_allows(&pack, "modal queue len my-q");
        assert_allows(&pack, "modal queue create my-q");
        assert_allows(&pack, "modal shell my-fn");
        assert_allows(&pack, "modal deploy ./app.py");
        assert_allows(&pack, "modal serve ./app.py");
        assert_allows(&pack, "modal run ./app.py");
        assert_allows(&pack, "modal token info");
        assert_allows(&pack, "modal token new");
        assert_allows(&pack, "modal token set --token-id ak-abc");
    }

    #[test]
    fn blocks_destructive_cli_commands() {
        let pack = create_pack();
        let checks = [
            // Critical — first-class resource deletion
            (
                "modal environment delete prod --yes",
                "modal-environment-delete",
            ),
            (
                "modal environment rm staging -y",
                "modal-environment-delete",
            ),
            (
                "modal volume delete model-weights --yes",
                "modal-volume-delete",
            ),
            ("modal volume remove checkpoints -y", "modal-volume-delete"),
            (
                "modal secret delete openai-key --yes",
                "modal-secret-delete",
            ),
            ("modal secret rm postgres-creds -y", "modal-secret-delete"),
            ("modal dict delete state -y", "modal-dict-delete"),
            ("modal queue delete jobs --yes", "modal-queue-delete"),
            // High — terminates work / wipes contents
            ("modal app stop my-prod-app -y", "modal-app-stop"),
            ("modal app stop ap-abc123 --yes", "modal-app-stop"),
            (
                "modal container stop ta-deadbeef -y",
                "modal-container-stop",
            ),
            (
                "modal volume rm -r model-weights /old-checkpoints",
                "modal-volume-rm-recursive",
            ),
            (
                "modal volume rm --recursive my-vol /subdir",
                "modal-volume-rm-recursive",
            ),
            ("modal dict clear state -y", "modal-dict-clear"),
            ("modal queue clear jobs --yes", "modal-queue-clear"),
            // Medium — single file delete / overwrite
            ("modal volume rm model-weights /old.bin", "modal-volume-rm"),
            (
                "modal secret create --force openai-key VALUE=new",
                "modal-secret-create-force",
            ),
            (
                "modal secret create openai-key VALUE=new --force",
                "modal-secret-create-force",
            ),
        ];
        for (command, expected_pattern) in checks {
            assert_blocks_with_pattern(&pack, command, expected_pattern);
        }
    }

    #[test]
    fn destructive_patterns_have_expected_severities() {
        let pack = create_pack();
        let critical = [
            "modal environment delete prod --yes",
            "modal volume delete model-weights --yes",
            "modal secret delete openai-key --yes",
            "modal dict delete state --yes",
            "modal queue delete jobs --yes",
        ];
        for command in critical {
            let matched = pack
                .check(command)
                .expect("should block critical Modal command");
            assert_eq!(matched.severity, Severity::Critical, "command: {command}");
        }

        let high = [
            "modal app stop my-app --yes",
            "modal container stop ta-1 --yes",
            "modal volume rm -r my-vol /sub",
            "modal dict clear state --yes",
            "modal queue clear jobs --yes",
        ];
        for command in high {
            let matched = pack
                .check(command)
                .expect("should block high-severity Modal command");
            assert_eq!(matched.severity, Severity::High, "command: {command}");
        }

        let medium = [
            "modal volume rm my-vol /file.bin",
            "modal secret create --force my-secret VALUE=xxx",
        ];
        for command in medium {
            let matched = pack
                .check(command)
                .expect("should block medium-severity Modal command");
            assert_eq!(matched.severity, Severity::Medium, "command: {command}");
        }
    }

    #[test]
    fn safe_cli_segment_does_not_mask_later_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "modal volume list && modal volume delete model-weights --yes",
            "modal-volume-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "modal app list | modal app stop my-app --yes",
            "modal-app-stop",
        );
    }

    #[test]
    fn distinguishes_create_force_from_create_without_force() {
        let pack = create_pack();
        assert_allows(&pack, "modal secret create new-secret VALUE=abc");
        assert_allows(&pack, "modal secret create --from-dotenv .env new-secret");
        assert_blocks_with_pattern(
            &pack,
            "modal secret create --force my-secret VALUE=new",
            "modal-secret-create-force",
        );
    }

    #[test]
    fn distinguishes_volume_rm_recursive_from_single_file() {
        let pack = create_pack();
        let single = pack
            .check("modal volume rm my-vol /file.bin")
            .expect("single-file rm should still block");
        assert_eq!(single.severity, Severity::Medium);
        assert_eq!(single.name, Some("modal-volume-rm"));

        let recursive = pack
            .check("modal volume rm -r my-vol /dir")
            .expect("recursive rm should block at higher severity");
        assert_eq!(recursive.severity, Severity::High);
        assert_eq!(recursive.name, Some("modal-volume-rm-recursive"));
    }

    #[test]
    fn detects_force_across_shell_line_continuation() {
        // Regression: the safe pattern's negative lookahead must allow
        // `\\\r?\n` shell line continuation, otherwise `modal secret create \
        // --force ...` (split across lines) is misreported as safe because
        // the lookahead stops at the `\n` and never sees `--force`.
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "modal secret create my-secret \\\n--force VALUE=new",
            "modal-secret-create-force",
        );
        assert_blocks_with_pattern(
            &pack,
            "modal secret create my-secret \\\r\n--overwrite VALUE=new",
            "modal-secret-create-force",
        );
    }

    #[test]
    fn detects_recursive_volume_rm_across_shell_line_continuation() {
        // Same asymmetry fix on `modal-volume-rm`'s negative lookahead — a
        // recursive `rm` continued across lines must still route to the
        // High-severity pattern, not fall through to the Medium one.
        let pack = create_pack();
        let recursive = pack
            .check("modal volume rm my-vol \\\n-r /old-checkpoints")
            .expect("line-continued recursive rm should block");
        assert_eq!(recursive.severity, Severity::High);
        assert_eq!(recursive.name, Some("modal-volume-rm-recursive"));
    }
}
