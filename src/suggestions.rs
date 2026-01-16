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
                "Check if branch has unmerged commits with `git log branch --not main`",
            ),
            Suggestion::new(
                SuggestionKind::SaferAlternative,
                "Use `git branch -d` (lowercase) to only delete if merged",
            )
            .with_command("git branch -d branch-name"),
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

/// Register suggestions for core.filesystem pack rules.
fn register_core_filesystem_suggestions(m: &mut HashMap<&'static str, Vec<Suggestion>>) {
    // Shared suggestions for all recursive force-delete variants
    let rm_rf_suggestions = vec![
        Suggestion::new(
            SuggestionKind::PreviewFirst,
            "List contents first with `ls -la` to verify target",
        ),
        Suggestion::new(
            SuggestionKind::SaferAlternative,
            "Use `rm -ri` for interactive confirmation of each file",
        )
        .with_command("rm -ri path/"),
        Suggestion::new(
            SuggestionKind::WorkflowFix,
            "Move to trash instead: `mv path ~/.local/share/Trash/`",
        ),
    ];

    // Register for all actual pattern names from filesystem.rs
    m.insert("core.filesystem:rm-rf-root-home", rm_rf_suggestions.clone());
    m.insert("core.filesystem:rm-rf-general", rm_rf_suggestions.clone());
    m.insert("core.filesystem:rm-r-f-separate", rm_rf_suggestions.clone());
    m.insert("core.filesystem:rm-recursive-force-long", rm_rf_suggestions);
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
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
            "core.filesystem:rm-rf-root-home",
            "core.filesystem:rm-rf-general",
            "core.filesystem:rm-r-f-separate",
            "core.filesystem:rm-recursive-force-long",
        ];

        for rule in expected_rules {
            assert!(
                get_suggestions(rule).is_some(),
                "Expected suggestions for {rule}"
            );
        }
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
    fn coverage_all_core_pack_patterns_have_suggestions() {
        // This test dynamically checks all destructive patterns in core.* packs
        // against the suggestion registry, ensuring complete coverage.
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

            for pattern in &pack.destructive_patterns {
                if let Some(pattern_name) = pattern.name {
                    let rule_id = format!("{pack_id}:{pattern_name}");
                    if get_suggestions(&rule_id).is_none() {
                        missing_suggestions.push(rule_id);
                    }
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
    fn coverage_core_patterns_count_matches_registry() {
        // Verify the number of patterns with suggestions matches actual pack definitions.
        // This catches drift between packs and suggestion registry.

        use crate::packs::REGISTRY;

        // Count patterns in core.git
        let git_pack = REGISTRY.get("core.git").unwrap();
        let git_pattern_count = git_pack
            .destructive_patterns
            .iter()
            .filter(|p| p.name.is_some())
            .count();

        // Count suggestions for core.git
        let git_suggestion_count = SUGGESTION_REGISTRY
            .keys()
            .filter(|k| k.starts_with("core.git:"))
            .count();

        assert_eq!(
            git_pattern_count, git_suggestion_count,
            "core.git pattern count ({git_pattern_count}) != suggestion count ({git_suggestion_count})"
        );

        // Count patterns in core.filesystem
        let fs_pack = REGISTRY.get("core.filesystem").unwrap();
        let fs_pattern_count = fs_pack
            .destructive_patterns
            .iter()
            .filter(|p| p.name.is_some())
            .count();

        // Count suggestions for core.filesystem
        let fs_suggestion_count = SUGGESTION_REGISTRY
            .keys()
            .filter(|k| k.starts_with("core.filesystem:"))
            .count();

        assert_eq!(
            fs_pattern_count, fs_suggestion_count,
            "core.filesystem pattern count ({fs_pattern_count}) != suggestion count ({fs_suggestion_count})"
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
            "database.postgresql:drop-database",
            "database.postgresql:drop-table",
            "database.postgresql:drop-schema",
            "database.postgresql:truncate-table",
            "database.postgresql:delete-without-where",
            "database.postgresql:dropdb-cli",
            "database.postgresql:pg-dump-clean",
            "database.mongodb:drop-database",
            "database.mongodb:drop-collection",
            "database.mongodb:delete-all",
            "database.mongodb:mongorestore-drop",
            "database.mongodb:collection-drop",
            "database.redis:flushall",
            "database.redis:flushdb",
            "database.redis:debug-crash",
            "database.redis:debug-sleep",
            "database.redis:shutdown",
            "database.redis:config-dangerous",
            "database.sqlite:drop-table",
            "database.sqlite:delete-without-where",
            "database.sqlite:vacuum-into",
            "database.sqlite:sqlite3-stdin",
        ];
        for rule in expected {
            assert!(get_suggestions(rule).is_some(), "Missing: {rule}");
        }
    }

    // === Correctness & Coverage Tests (git_safety_guard-1gt.5.5) ===

    #[test]
    fn coverage_all_suggestion_rules_are_valid() {
        // Verify every rule_id in SUGGESTION_REGISTRY matches a real pack/pattern.
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
            if !pack
                .destructive_patterns
                .iter()
                .any(|p| p.name == Some(pattern_name))
            {
                invalid.push(format!("{rule_id} (pattern not found)"));
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
}
