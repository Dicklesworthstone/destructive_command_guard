//! Databricks CLI patterns - protections against destructive `databricks`
//! commands (GH#333).
//!
//! Initial high-value scope, per the pack request:
//! - `account workspaces delete` (deletes an entire workspace)
//! - `bundle destroy` (removes every resource a bundle deployed;
//!   `--auto-approve` skips the CLI's own confirmation)
//! - `workspace delete` / `workspace rm` (recursive and single-object)
//! - `fs rm` (DBFS / Unity Catalog Volumes; recursive and single-object)
//! - `clusters permanent-delete`
//! - `secrets delete-scope` / `delete-secret` / `delete-acl`
//! - `api delete` (arbitrary REST DELETE, like the generic `gh api` rule)
//! - resource deletes: jobs, pipelines, repos, cluster-policies,
//!   instance-pools, warehouses, tokens
//!
//! Global targeting flags (`-p/--profile <name>`, `-t/--target <name>`) may
//! appear between `databricks` and the command group; the shared
//! flag-consuming prefix keeps every rule matching regardless of their
//! position, so `databricks -p prod workspace delete ...` is still caught.

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};

/// Create the Databricks pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.databricks".to_string(),
        name: "Databricks CLI",
        description: "Protects against destructive Databricks CLI operations like account \
                      workspaces delete, bundle destroy, recursive workspace/fs deletion, \
                      permanent cluster deletion, secret-scope removal, arbitrary REST \
                      DELETE calls, and high-impact resource deletes",
        keywords: &[
            "databricks",
            "bundle",
            "permanent-delete",
            "delete-scope",
            "delete-secret",
            "delete-acl",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Mirrors the BigQuery pack: a read-only first statement must never
    // whitelist a destructive later one, so no whole-command safe regexes.
    // Read-only verbs (list/get/ls/export) simply match no destructive
    // pattern below.
    Vec::new()
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Specific rules first: the pack returns the FIRST matching pattern,
        // so recursive variants sort above their single-object siblings.
        destructive_pattern!(
            "databricks-account-workspaces-delete",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+account\s+workspaces\s+delete\b",
            "databricks account workspaces delete removes an ENTIRE workspace.",
            Critical,
            "Deleting a workspace removes the whole environment — notebooks, jobs, \
             clusters, and workspace-local configuration — for every user of that \
             workspace at once. This is an account-level control-plane operation with \
             no undo.\n\n\
             Confirm the target first:\n  \
             databricks account workspaces get <WORKSPACE_ID>",
            &const {
                [PatternSuggestion::new(
                    "databricks account workspaces get <WORKSPACE_ID>",
                    "Confirm which workspace the ID refers to before any deletion",
                )]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-bundle-destroy",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+bundle\s+destroy\b",
            "databricks bundle destroy permanently deletes every resource the bundle deployed.",
            Critical,
            "`bundle destroy` tears down all jobs, pipelines, and artifacts previously \
             deployed by the bundle. With `--auto-approve` even the CLI's own \
             confirmation prompt is skipped, so a wrong target/profile destroys the \
             production deployment silently.\n\n\
             Review what would be destroyed first:\n  \
             databricks bundle summary",
            &const {
                [
                    PatternSuggestion::new(
                        "databricks bundle summary",
                        "List the deployed resources the destroy would remove",
                    ),
                    PatternSuggestion::new(
                        "databricks bundle validate",
                        "Check which target/profile the bundle actually resolves to",
                    ),
                ]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-workspace-delete-recursive",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+workspace\s+(?:delete|rm)\b(?:\s+[^\s;&|]+)*\s+(?:-r\b|-{1,2}recursive\b)",
            "databricks workspace delete --recursive removes a whole workspace directory tree.",
            Critical,
            "Recursive workspace deletion removes the directory and every notebook and \
             file under it. Workspace object deletion cannot be undone.\n\n\
             Inspect the tree first:\n  \
             databricks workspace list <PATH>",
            &const {
                [
                    PatternSuggestion::new(
                        "databricks workspace list <PATH>",
                        "See what the recursive delete would take with it",
                    ),
                    PatternSuggestion::new(
                        "databricks workspace export-dir <PATH> <LOCAL_DIR>",
                        "Export a backup of the tree before removing it",
                    ),
                ]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-workspace-delete",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+workspace\s+(?:delete|rm)\b",
            "databricks workspace delete removes a workspace object; deletion cannot be undone.",
            High,
            "Workspace object deletion is immediate and has no recycle bin. A deleted \
             notebook is gone unless it was exported or lives in a Repo.\n\n\
             Export a copy first:\n  \
             databricks workspace export <PATH> --file backup",
            &const {
                [PatternSuggestion::new(
                    "databricks workspace export <PATH> --file <LOCAL_FILE>",
                    "Keep a local copy of the object before deleting it",
                )]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-fs-rm-recursive",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+fs\s+rm\b(?:\s+[^\s;&|]+)*\s+(?:-r\b|-{1,2}recursive\b)",
            "databricks fs rm -r recursively deletes data in DBFS or Unity Catalog Volumes.",
            Critical,
            "Recursive removal deletes the directory and everything under it in one call. \
             DBFS and Volume paths often back tables and checkpoints; there is no \
             time-travel for raw files.\n\n\
             Inspect the path first:\n  \
             databricks fs ls <PATH>",
            &const {
                [PatternSuggestion::new(
                    "databricks fs ls <PATH>",
                    "List what the recursive delete would remove",
                )]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-fs-rm",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+fs\s+rm\b",
            "databricks fs rm deletes a file in DBFS or a Unity Catalog Volume.",
            High,
            "File deletion in DBFS/Volumes is immediate and unrecoverable; files there \
             frequently back external tables, ML artifacts, and streaming checkpoints.\n\n\
             Confirm the target first:\n  \
             databricks fs ls <PATH>",
            &const {
                [PatternSuggestion::new(
                    "databricks fs ls <PATH>",
                    "Confirm exactly which file the path names",
                )]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-clusters-permanent-delete",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+clusters\s+permanent-delete\b",
            "databricks clusters permanent-delete removes a cluster rather than terminating it.",
            Critical,
            "Permanent deletion removes the cluster configuration itself — libraries, \
             init scripts, and spark conf — not just the running compute. A terminated \
             cluster can be restarted; a permanently deleted one must be rebuilt.\n\n\
             Terminate instead when you just need the compute stopped:\n  \
             databricks clusters delete <CLUSTER_ID>",
            &const {
                [
                    PatternSuggestion::new(
                        "databricks clusters get <CLUSTER_ID>",
                        "Capture the cluster's configuration before removing it",
                    ),
                    // Not gated: terminate is deliberately out of this pack's
                    // scope (see the allowed-command case below), so claiming
                    // dcg gates it was a marker this pack never backed.
                    PatternSuggestion::new(
                        "databricks clusters delete <CLUSTER_ID>",
                        "Terminates (stops) the cluster but keeps its configuration, so it can be restarted",
                    ),
                ]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-secrets-delete-scope",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+secrets\s+delete-scope\b",
            "databricks secrets delete-scope removes the scope with ALL its secrets and ACLs.",
            Critical,
            "Deleting a scope removes every secret and ACL inside it in one operation. \
             Jobs and notebooks that read those secrets start failing immediately, and \
             the secret values cannot be read back out beforehand through the CLI.\n\n\
             List the blast radius first:\n  \
             databricks secrets list-secrets <SCOPE>",
            &const {
                [PatternSuggestion::new(
                    "databricks secrets list-secrets <SCOPE>",
                    "See how many secrets the scope deletion would take with it",
                )]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-secrets-delete",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+secrets\s+delete-(?:secret|acl)\b",
            "databricks secrets delete-secret/delete-acl removes a secret or its access control.",
            High,
            "Secret values are write-only through the CLI: once deleted, the value cannot \
             be recovered — only re-created from wherever it originally came from. \
             Removing an ACL can lock a principal out of secrets it depends on.\n\n\
             Record what exists first:\n  \
             databricks secrets list-secrets <SCOPE>",
            &const {
                [PatternSuggestion::new(
                    "databricks secrets list-acls <SCOPE>",
                    "Review current access before changing or removing it",
                )]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-api-delete",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+api\s+delete\b",
            "databricks api delete performs an arbitrary REST DELETE against the workspace or account API.",
            High,
            "The generic API escape hatch can delete any resource the token can reach, \
             including ones no specific CLI rule covers. Treat it like the destructive \
             endpoint it targets.\n\n\
             Inspect the resource first:\n  \
             databricks api get <PATH>",
            &const {
                [PatternSuggestion::new(
                    "databricks api get <PATH>",
                    "Fetch the resource to confirm what the DELETE would remove",
                )]
            },
            executables = ["databricks"]
        ),
        destructive_pattern!(
            "databricks-resource-delete",
            r"(?:^|[\s;&|(])(?:[^\s;&|]*[/\\])?databricks(?:\.exe)?(?:\s+--?[^\s;&|]+(?:\s+[^-\s;&|][^\s;&|]*)?)*\s+(?:jobs|pipelines|repos|cluster-policies|instance-pools|warehouses|tokens)\s+delete\b",
            "databricks resource delete removes a job, pipeline, repo, policy, pool, warehouse, or token.",
            High,
            "Deleting these resources removes their configuration and history: a deleted \
             job loses its run history and schedule, a deleted pipeline its update log, a \
             deleted token cannot be recreated with the same value. Recreating any of \
             them from scratch requires the original definition.\n\n\
             Capture the definition first:\n  \
             databricks jobs get <JOB_ID>  (or the matching `get` for the resource)",
            &const {
                [PatternSuggestion::new(
                    "databricks <resource> get <ID>",
                    "Export the resource definition before deleting it",
                )]
            },
            executables = ["databricks"]
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::{
        assert_blocks_with_pattern, assert_blocks_with_severity, assert_no_match, validate_pack,
    };

    #[test]
    fn test_pack_creation() {
        validate_pack(&create_pack());
    }

    #[test]
    fn databricks_destructive_variants_block() {
        let pack = create_pack();
        for (command, expected) in [
            (
                "databricks account workspaces delete 1234567890",
                "databricks-account-workspaces-delete",
            ),
            ("databricks bundle destroy", "databricks-bundle-destroy"),
            (
                "databricks bundle destroy --auto-approve",
                "databricks-bundle-destroy",
            ),
            (
                "databricks workspace delete /Shared/foo --recursive",
                "databricks-workspace-delete-recursive",
            ),
            (
                "databricks workspace rm /Shared/foo -r",
                "databricks-workspace-delete-recursive",
            ),
            (
                "databricks workspace delete /Shared/foo/notebook",
                "databricks-workspace-delete",
            ),
            (
                "databricks fs rm -r dbfs:/tmp/dataset",
                "databricks-fs-rm-recursive",
            ),
            (
                "databricks fs rm dbfs:/tmp/file.parquet --recursive",
                "databricks-fs-rm-recursive",
            ),
            (
                "databricks fs rm dbfs:/tmp/file.parquet",
                "databricks-fs-rm",
            ),
            (
                "databricks clusters permanent-delete 0812-164905-tear555",
                "databricks-clusters-permanent-delete",
            ),
            (
                "databricks secrets delete-scope my-scope",
                "databricks-secrets-delete-scope",
            ),
            (
                "databricks secrets delete-secret my-scope my-key",
                "databricks-secrets-delete",
            ),
            (
                "databricks secrets delete-acl my-scope someone@example.com",
                "databricks-secrets-delete",
            ),
            (
                "databricks api delete /api/2.0/jobs/delete",
                "databricks-api-delete",
            ),
            ("databricks jobs delete 123", "databricks-resource-delete"),
            (
                "databricks pipelines delete abc-def",
                "databricks-resource-delete",
            ),
            ("databricks repos delete 42", "databricks-resource-delete"),
            (
                "databricks cluster-policies delete P123",
                "databricks-resource-delete",
            ),
            (
                "databricks instance-pools delete pool-1",
                "databricks-resource-delete",
            ),
            (
                "databricks warehouses delete wh-9",
                "databricks-resource-delete",
            ),
            (
                "databricks tokens delete tok-1",
                "databricks-resource-delete",
            ),
        ] {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    /// Global targeting flags must not defeat matching, regardless of
    /// position (the reporter's explicit parsing consideration).
    #[test]
    fn global_flags_do_not_defeat_matching() {
        let pack = create_pack();
        for (command, expected) in [
            (
                "databricks -p prod workspace delete /Shared/foo --recursive",
                "databricks-workspace-delete-recursive",
            ),
            (
                "databricks --profile prod bundle destroy --auto-approve",
                "databricks-bundle-destroy",
            ),
            (
                "databricks -t prod -p prod bundle destroy",
                "databricks-bundle-destroy",
            ),
            (
                "databricks workspace delete /Shared/foo --recursive -p prod",
                "databricks-workspace-delete-recursive",
            ),
            (
                "databricks --profile staging fs rm -r dbfs:/tmp/x",
                "databricks-fs-rm-recursive",
            ),
        ] {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    /// Recursive variants must not be shadowed by their generic siblings
    /// (first-match-wins ordering).
    #[test]
    fn recursive_rules_are_not_shadowed() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "databricks workspace delete /a --recursive",
            "databricks-workspace-delete-recursive",
        );
        assert_blocks_with_pattern(
            &pack,
            "databricks fs rm -r dbfs:/a",
            "databricks-fs-rm-recursive",
        );
    }

    #[test]
    fn severity_tiers() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "databricks bundle destroy --auto-approve",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "databricks account workspaces delete 1",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "databricks fs rm dbfs:/tmp/one-file", Severity::High);
        assert_blocks_with_severity(&pack, "databricks jobs delete 123", Severity::High);
    }

    /// Read-only and non-destructive operations must not match (FP guard).
    #[test]
    fn read_only_operations_do_not_match() {
        let pack = create_pack();
        for command in [
            "databricks workspace list /Shared",
            "databricks workspace export /Shared/foo --file backup.py",
            "databricks workspace export-dir /Shared/foo ./backup",
            "databricks fs ls dbfs:/tmp",
            "databricks fs cp dbfs:/a dbfs:/b",
            "databricks clusters list",
            "databricks clusters get 0812-164905-tear555",
            "databricks clusters delete 0812-164905-tear555", // terminate ≠ permanent-delete; own pack rule deliberately omitted from initial scope
            "databricks jobs list",
            "databricks jobs get 123",
            "databricks secrets list-scopes",
            "databricks secrets list-secrets my-scope",
            "databricks api get /api/2.0/clusters/list",
            "databricks api post /api/2.0/jobs/create --json @job.json",
            "databricks -p prod workspace list /Shared",
            "databricks bundle summary",
            "databricks bundle validate",
            "databricks bundle deploy",
            // Other tools' subcommands that share verb shapes must not match.
            "gh api delete /repos/o/r/issues/1",
            "aws s3 rm s3://bucket/key",
        ] {
            assert_no_match(&pack, command);
        }
    }
}
