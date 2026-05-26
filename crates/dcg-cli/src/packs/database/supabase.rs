//! Supabase CLI patterns - protections against destructive Supabase commands.
//!
//! This includes patterns for:
//! - Database: `db reset`, `db push`, `db shell` with destructive SQL
//! - Migrations: `migration repair`, `migration down`, `migration squash`
//! - Functions: `functions delete`
//! - Storage: `storage rm`
//! - Secrets: `secrets unset`
//! - Infrastructure: `projects delete`, `orgs delete`, `branches delete`
//! - Networking: `domains delete`, `vanity-subdomains delete`,
//!   `network-restrictions update`
//! - Auth: `sso remove`
//! - Config: `config push`, `stop --no-backup`

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

// -- Database ----------------------------------------------------------------

/// Suggestions for `supabase db reset` pattern.
const DB_RESET_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase db dump -f backup.sql",
        "Dump the database before resetting",
    ),
    PatternSuggestion::new(
        "supabase db diff",
        "Review schema differences before resetting",
    ),
    PatternSuggestion::new(
        "supabase migration list",
        "Check migration status before resetting",
    ),
];

/// Suggestions for `supabase db push` pattern.
const DB_PUSH_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase db push --dry-run",
        "Preview migration changes without applying them",
    ),
    PatternSuggestion::new(
        "supabase db diff",
        "Review schema differences before pushing",
    ),
    PatternSuggestion::new(
        "supabase db dump -f backup.sql --linked",
        "Dump the remote database before pushing migrations",
    ),
];

/// Suggestions for `supabase db shell` with destructive SQL.
const DB_SHELL_DESTRUCTIVE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase db dump -f backup.sql",
        "Dump the database before running destructive SQL",
    ),
    PatternSuggestion::new(
        "supabase db shell -- -c 'SELECT COUNT(*) FROM {tablename}'",
        "Check row count before deleting",
    ),
];

// -- Migrations --------------------------------------------------------------

/// Suggestions for `supabase migration repair` pattern.
const MIGRATION_REPAIR_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase migration list",
        "Review current migration status before repairing",
    ),
    PatternSuggestion::new(
        "supabase db dump -f backup.sql",
        "Dump the database before modifying migration history",
    ),
];

/// Suggestions for `supabase migration down` pattern.
const MIGRATION_DOWN_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase migration list",
        "Review applied migrations before reverting",
    ),
    PatternSuggestion::new(
        "supabase db dump -f backup.sql --linked",
        "Dump the database before reverting migrations",
    ),
    PatternSuggestion::new(
        "supabase db diff",
        "Review schema differences before reverting",
    ),
];

/// Suggestions for `supabase migration squash` pattern.
const MIGRATION_SQUASH_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase migration list",
        "Review migrations before squashing",
    ),
    PatternSuggestion::new(
        "supabase db dump -f backup.sql",
        "Dump the database before squashing migrations",
    ),
];

// -- Functions ---------------------------------------------------------------

/// Suggestions for `supabase functions delete` pattern.
const FUNCTIONS_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase functions list",
        "List functions to verify the correct one",
    ),
    PatternSuggestion::new(
        "supabase functions download {function_name}",
        "Download function source before deleting",
    ),
];

// -- Storage -----------------------------------------------------------------

/// Suggestions for `supabase storage rm` pattern.
const STORAGE_RM_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase storage ls {path}",
        "List storage contents before deleting",
    ),
    PatternSuggestion::new(
        "supabase storage cp {path} ./backup/",
        "Copy files locally before deleting from storage",
    ),
];

// -- Secrets -----------------------------------------------------------------

/// Suggestions for `supabase secrets unset` pattern.
const SECRETS_UNSET_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "supabase secrets list",
    "List secrets to verify before removing",
)];

// -- Infrastructure ----------------------------------------------------------

/// Suggestions for `supabase projects delete` pattern.
const PROJECTS_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase db dump -f backup.sql --linked",
        "Dump the database before deleting the project",
    ),
    PatternSuggestion::new(
        "supabase projects list",
        "List projects to verify the correct one",
    ),
];

/// Suggestions for `supabase orgs delete` pattern.
const ORGS_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase orgs list",
        "List organizations to verify the correct one",
    ),
    PatternSuggestion::new(
        "supabase projects list",
        "List projects in the organization before deleting",
    ),
];

/// Suggestions for `supabase branches delete` pattern.
const BRANCHES_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "supabase branches list",
        "List branches to verify the correct one",
    ),
    PatternSuggestion::new(
        "supabase branches get --id {branch_id}",
        "Inspect branch details before deleting",
    ),
];

// -- Networking & Domains ----------------------------------------------------

/// Suggestions for `supabase domains delete` pattern.
const DOMAINS_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "supabase domains get",
    "Check current domain configuration before deleting",
)];

/// Suggestions for `supabase vanity-subdomains delete` pattern.
const VANITY_SUBDOMAINS_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "supabase vanity-subdomains get",
    "Check current vanity subdomain before deleting",
)];

/// Suggestions for `supabase network-restrictions update` pattern.
const NETWORK_RESTRICTIONS_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "supabase network-restrictions get",
    "Check current network restrictions before modifying",
)];

// -- Auth --------------------------------------------------------------------

/// Suggestions for `supabase sso remove` pattern.
const SSO_REMOVE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new("supabase sso list", "List SSO providers before removing"),
    PatternSuggestion::new(
        "supabase sso show --id {provider_id}",
        "Inspect SSO provider details before removing",
    ),
];

// -- Config & Local ----------------------------------------------------------

/// Suggestions for `supabase config push` pattern.
const CONFIG_PUSH_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "supabase inspect db bloat",
    "Inspect the remote database state before pushing config",
)];

/// Suggestions for `supabase stop --no-backup` pattern.
const STOP_NO_BACKUP_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "supabase stop",
    "Stop local stack while preserving data backups",
)];

// ============================================================================
// Pack constructor
// ============================================================================

/// Create the Supabase pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.supabase".to_string(),
        name: "Supabase",
        description: "Protects against destructive Supabase CLI operations including database \
                      resets, migration rollbacks, function/secret/storage deletion, project \
                      removal, and infrastructure changes",
        keywords: &[
            "supabase",
            "db reset",
            "db push",
            "migration repair",
            "migration down",
            "migration squash",
            "functions delete",
            "secrets unset",
            "storage rm",
            "projects delete",
            "orgs delete",
            "branches delete",
            "domains delete",
            "vanity-subdomains delete",
            "sso remove",
            "network-restrictions",
            "config push",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

// ============================================================================
// Safe patterns
// ============================================================================

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // -- Database read-only operations --
        safe_pattern!(
            "supabase-db-diff",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+diff"
        ),
        safe_pattern!(
            "supabase-db-lint",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+lint"
        ),
        safe_pattern!(
            "supabase-db-dump",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+dump"
        ),
        safe_pattern!(
            "supabase-db-shell-safe",
            r"(?i)supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+shell\s*$"
        ),
        safe_pattern!(
            "supabase-inspect-db",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect\s+db"
        ),
        // -- Status & info --
        safe_pattern!(
            "supabase-status",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+status"
        ),
        safe_pattern!(
            "supabase-start",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+start"
        ),
        safe_pattern!(
            "supabase-services",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+services"
        ),
        safe_pattern!(
            "supabase-gen-types",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+gen\s+types"
        ),
        safe_pattern!(
            "supabase-test-db",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+test\s+db"
        ),
        // -- Migrations read-only --
        safe_pattern!(
            "supabase-migration-list",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+list"
        ),
        safe_pattern!(
            "supabase-migration-new",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+new"
        ),
        safe_pattern!(
            "supabase-migration-fetch",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+fetch"
        ),
        // supabase db push --dry-run (anywhere in args) is safe.
        // Treat only bare `--dry-run` or explicit true as previews;
        // false-valued flags must not mask the destructive push rule.
        safe_pattern!(
            "supabase-db-push-dry-run",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+push\b.*--dry-run(?:=true)?(?:\s|$)"
        ),
        // -- Functions read-only --
        safe_pattern!(
            "supabase-functions-list",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+list"
        ),
        safe_pattern!(
            "supabase-functions-serve",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+serve"
        ),
        safe_pattern!(
            "supabase-functions-download",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+download"
        ),
        safe_pattern!(
            "supabase-functions-new",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+new"
        ),
        // -- Secrets read-only --
        safe_pattern!(
            "supabase-secrets-list",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+list"
        ),
        // -- Storage read-only --
        safe_pattern!(
            "supabase-storage-ls",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+storage\s+ls"
        ),
        // -- Projects/Orgs read-only --
        safe_pattern!(
            "supabase-projects-list",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+list"
        ),
        safe_pattern!(
            "supabase-orgs-list",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+orgs\s+list"
        ),
        // -- Branches read-only --
        safe_pattern!(
            "supabase-branches-list",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+branches\s+list"
        ),
        safe_pattern!(
            "supabase-branches-get",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+branches\s+get"
        ),
        // -- Domains read-only --
        safe_pattern!(
            "supabase-domains-get",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+domains\s+get"
        ),
        safe_pattern!(
            "supabase-domains-reverify",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+domains\s+reverify"
        ),
        safe_pattern!(
            "supabase-vanity-subdomains-get",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+vanity-subdomains\s+get"
        ),
        safe_pattern!(
            "supabase-vanity-subdomains-check",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+vanity-subdomains\s+check-availability"
        ),
        // -- SSO read-only --
        safe_pattern!(
            "supabase-sso-list",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+sso\s+list"
        ),
        safe_pattern!(
            "supabase-sso-show",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+sso\s+show"
        ),
        safe_pattern!(
            "supabase-sso-info",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+sso\s+info"
        ),
        // -- Network/SSL read-only --
        safe_pattern!(
            "supabase-network-restrictions-get",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+network-restrictions\s+get"
        ),
        safe_pattern!(
            "supabase-network-bans-get",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+network-bans\s+get"
        ),
        safe_pattern!(
            "supabase-ssl-enforcement-get",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+ssl-enforcement\s+get"
        ),
        // -- Postgres config read-only --
        safe_pattern!(
            "supabase-postgres-config-get",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+postgres-config\s+get"
        ),
    ]
}

// ============================================================================
// Destructive patterns
// ============================================================================

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ================================================================
        // Database
        // ================================================================

        // supabase db reset — drops and recreates the database
        destructive_pattern!(
            "supabase-db-reset",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+reset",
            "supabase db reset drops and recreates the entire database. All data will be lost.",
            Critical,
            "supabase db reset completely destroys and recreates your database:\n\n\
             - All tables, views, and functions are dropped\n\
             - All data is permanently deleted\n\
             - Migrations are re-applied from scratch\n\
             - Seed data (if configured) is re-inserted\n\n\
             This is irreversible for any data not captured in migrations or seeds.\n\
             With --linked, this targets the remote production database.\n\n\
             Before resetting:\n  \
             supabase db dump -f backup.sql\n\n\
             Review differences first:\n  \
             supabase db diff",
            DB_RESET_SUGGESTIONS
        ),
        // supabase db push — pushes migrations to remote
        destructive_pattern!(
            "supabase-db-push",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+push",
            "supabase db push applies migrations to the remote database. Use --dry-run to preview first.",
            Critical,
            "supabase db push applies pending migrations to the remote (linked) database:\n\n\
             - Migrations may include DROP/ALTER statements\n\
             - Changes to the production database are irreversible\n\
             - With --linked, this targets the live project database\n\n\
             Always preview changes first:\n  \
             supabase db push --dry-run\n\n\
             Dump remote database before pushing:\n  \
             supabase db dump -f backup.sql --linked",
            DB_PUSH_SUGGESTIONS
        ),
        // supabase db shell with destructive SQL (DROP/TRUNCATE/DELETE/ALTER)
        destructive_pattern!(
            "supabase-db-shell-destructive",
            r"(?i)supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+shell\s+.*\b(DROP|TRUNCATE|DELETE|ALTER)\b",
            "supabase db shell with destructive SQL (DROP/TRUNCATE/DELETE/ALTER). Verify the command carefully.",
            High,
            "supabase db shell is being invoked with destructive SQL:\n\n\
             - DROP permanently removes database objects\n\
             - TRUNCATE removes all rows from tables\n\
             - DELETE without WHERE removes all rows\n\
             - ALTER can drop columns, change types, or remove constraints\n\n\
             Dump the database before running destructive commands:\n  \
             supabase db dump -f backup.sql\n\n\
             Check row count first:\n  \
             supabase db shell -- -c 'SELECT COUNT(*) FROM tablename'",
            DB_SHELL_DESTRUCTIVE_SUGGESTIONS
        ),
        // ================================================================
        // Migrations
        // ================================================================

        // supabase migration repair — modifies migration history
        destructive_pattern!(
            "supabase-migration-repair",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+repair",
            "supabase migration repair modifies the migration history. This can cause drift between schema and migrations.",
            Critical,
            "supabase migration repair alters the migration history table:\n\n\
             - Can mark migrations as applied or reverted\n\
             - May cause schema drift if used incorrectly\n\
             - Can break future migration runs\n\n\
             Review migration status first:\n  \
             supabase migration list\n\n\
             Dump the database before repairing:\n  \
             supabase db dump -f backup.sql",
            MIGRATION_REPAIR_SUGGESTIONS
        ),
        // supabase migration down — reverts applied migrations
        destructive_pattern!(
            "supabase-migration-down",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+down",
            "supabase migration down reverts applied migrations. Schema changes and associated data may be lost.",
            Critical,
            "supabase migration down reverts previously applied migrations:\n\n\
             - Reversed migrations may DROP tables, columns, or constraints\n\
             - Data in dropped objects is permanently lost\n\
             - With --linked, this targets the remote production database\n\
             - The --version flag can revert multiple migrations at once\n\n\
             Review applied migrations first:\n  \
             supabase migration list\n\n\
             Dump the database before reverting:\n  \
             supabase db dump -f backup.sql --linked",
            MIGRATION_DOWN_SUGGESTIONS
        ),
        // supabase migration squash — consolidates migrations, loses DML
        destructive_pattern!(
            "supabase-migration-squash",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+squash",
            "supabase migration squash consolidates migrations and omits data manipulation statements (INSERT/UPDATE/DELETE).",
            High,
            "supabase migration squash consolidates multiple migration files into one:\n\n\
             - DML statements (INSERT, UPDATE, DELETE) are omitted\n\
             - Cron jobs, storage buckets, and vault secrets are lost\n\
             - These must be manually recreated in the squashed migration\n\
             - With --linked, modifies the remote migration history\n\n\
             Review migrations before squashing:\n  \
             supabase migration list\n\n\
             Dump the database before squashing:\n  \
             supabase db dump -f backup.sql",
            MIGRATION_SQUASH_SUGGESTIONS
        ),
        // ================================================================
        // Functions
        // ================================================================

        // supabase functions delete — removes a deployed edge function
        destructive_pattern!(
            "supabase-functions-delete",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+delete",
            "supabase functions delete removes a deployed Edge Function. This causes immediate downtime for that function.",
            High,
            "supabase functions delete permanently removes a deployed Edge Function:\n\n\
             - The function is immediately unavailable\n\
             - Clients calling the function will receive errors\n\
             - The function can be re-deployed from local source code\n\n\
             Verify the function first:\n  \
             supabase functions list\n\n\
             Download source before deleting:\n  \
             supabase functions download {function_name}",
            FUNCTIONS_DELETE_SUGGESTIONS
        ),
        // ================================================================
        // Storage
        // ================================================================

        // supabase storage rm — deletes storage objects
        destructive_pattern!(
            "supabase-storage-rm",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+storage\s+rm",
            "supabase storage rm deletes objects from storage. With --recursive, entire directories are removed.",
            High,
            "supabase storage rm permanently deletes objects from Supabase Storage:\n\n\
             - Deleted files cannot be recovered\n\
             - With --recursive, entire directory trees are removed\n\
             - User-uploaded content may be permanently lost\n\n\
             List contents before deleting:\n  \
             supabase storage ls {path}\n\n\
             Copy files locally before deleting:\n  \
             supabase storage cp {path} ./backup/",
            STORAGE_RM_SUGGESTIONS
        ),
        // ================================================================
        // Secrets
        // ================================================================

        // supabase secrets unset — removes project secrets
        destructive_pattern!(
            "supabase-secrets-unset",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+unset",
            "supabase secrets unset removes secrets from the project. Edge Functions depending on them will break immediately.",
            High,
            "supabase secrets unset removes environment variables from the project:\n\n\
             - Edge Functions depending on these secrets will fail\n\
             - Third-party integrations may break\n\
             - The secret values cannot be retrieved after removal\n\n\
             List secrets before removing:\n  \
             supabase secrets list",
            SECRETS_UNSET_SUGGESTIONS
        ),
        // ================================================================
        // Infrastructure
        // ================================================================

        // supabase projects delete
        destructive_pattern!(
            "supabase-projects-delete",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+delete",
            "supabase projects delete permanently removes the entire Supabase project and all its data.",
            Critical,
            "supabase projects delete permanently removes a Supabase project:\n\n\
             - The database and all data are deleted\n\
             - Auth users and sessions are removed\n\
             - Storage buckets and files are deleted\n\
             - Edge functions are removed\n\
             - API keys are invalidated\n\n\
             This action cannot be undone.\n\n\
             Dump the database before deleting:\n  \
             supabase db dump -f backup.sql --linked\n\n\
             Verify the project:\n  \
             supabase projects list",
            PROJECTS_DELETE_SUGGESTIONS
        ),
        // supabase orgs delete
        destructive_pattern!(
            "supabase-orgs-delete",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+orgs\s+delete",
            "supabase orgs delete permanently removes the organization and may affect all projects within it.",
            High,
            "supabase orgs delete permanently removes a Supabase organization:\n\n\
             - All projects in the organization may be affected\n\
             - Billing and subscription are cancelled\n\
             - Team members lose access\n\n\
             This action cannot be undone.\n\n\
             List organization projects first:\n  \
             supabase projects list\n\n\
             Verify the organization:\n  \
             supabase orgs list",
            ORGS_DELETE_SUGGESTIONS
        ),
        // supabase branches delete — removes a database branch
        destructive_pattern!(
            "supabase-branches-delete",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+branches\s+delete",
            "supabase branches delete permanently removes a preview branch and its database.",
            High,
            "supabase branches delete permanently removes a preview database branch:\n\n\
             - The branch database and all its data are deleted\n\
             - Any pending migrations on the branch are lost\n\
             - This action cannot be undone\n\n\
             Verify the branch first:\n  \
             supabase branches list\n\n\
             Inspect branch details:\n  \
             supabase branches get --id {branch_id}",
            BRANCHES_DELETE_SUGGESTIONS
        ),
        // ================================================================
        // Networking & Domains
        // ================================================================

        // supabase domains delete — removes custom domain
        destructive_pattern!(
            "supabase-domains-delete",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+domains\s+delete",
            "supabase domains delete removes the custom domain configuration. Clients using the custom domain will lose access.",
            High,
            "supabase domains delete removes the custom hostname configuration:\n\n\
             - Clients accessing the service via the custom domain will fail\n\
             - DNS records may need to be reconfigured\n\
             - Re-setup requires DNS verification\n\n\
             Check current domain configuration:\n  \
             supabase domains get",
            DOMAINS_DELETE_SUGGESTIONS
        ),
        // supabase vanity-subdomains delete — removes vanity subdomain
        destructive_pattern!(
            "supabase-vanity-subdomains-delete",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+vanity-subdomains\s+delete",
            "supabase vanity-subdomains delete removes the vanity subdomain. Clients using it will lose access.",
            High,
            "supabase vanity-subdomains delete removes the vanity subdomain:\n\n\
             - Clients using the vanity URL will lose access\n\
             - Auth flows configured with the vanity URL will break\n\
             - The subdomain name may not be reclaimable\n\n\
             Check current configuration:\n  \
             supabase vanity-subdomains get",
            VANITY_SUBDOMAINS_DELETE_SUGGESTIONS
        ),
        // supabase network-restrictions update — can lock out DB connections
        destructive_pattern!(
            "supabase-network-restrictions-update",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+network-restrictions\s+update",
            "supabase network-restrictions update modifies allowed CIDR ranges. Misconfiguration can lock out all database connections.",
            High,
            "supabase network-restrictions update modifies the database firewall rules:\n\n\
             - Overly restrictive CIDR ranges can lock out all connections\n\
             - Including your own application servers and admin access\n\
             - Recovery may require Supabase support intervention\n\n\
             Check current restrictions first:\n  \
             supabase network-restrictions get",
            NETWORK_RESTRICTIONS_SUGGESTIONS
        ),
        // ================================================================
        // Auth (SSO)
        // ================================================================

        // supabase sso remove — locks out SSO users
        destructive_pattern!(
            "supabase-sso-remove",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+sso\s+remove",
            "supabase sso remove disconnects an SSO identity provider. All users authenticating via that provider will be locked out.",
            Critical,
            "supabase sso remove disconnects an SSO identity provider:\n\n\
             - All users authenticating via that provider are immediately locked out\n\
             - Existing sessions may be invalidated\n\
             - Re-adding the provider requires full reconfiguration\n\n\
             List providers before removing:\n  \
             supabase sso list\n\n\
             Inspect provider details:\n  \
             supabase sso show --id {provider_id}",
            SSO_REMOVE_SUGGESTIONS
        ),
        // ================================================================
        // Config & Local
        // ================================================================

        // supabase config push — overwrites remote project config
        destructive_pattern!(
            "supabase-config-push",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+config\s+push",
            "supabase config push overwrites the remote project configuration with local config.toml settings.",
            High,
            "supabase config push replaces the remote project configuration:\n\n\
             - Auth, database, API, and other settings may be overwritten\n\
             - Misconfiguration can break authentication flows\n\
             - Changes take effect immediately on the live project\n\n\
             Review your local config.toml before pushing.",
            CONFIG_PUSH_SUGGESTIONS
        ),
        // supabase stop --no-backup — deletes local data volumes
        destructive_pattern!(
            "supabase-stop-no-backup",
            r"supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+stop\b.*--no-backup",
            "supabase stop --no-backup stops the local stack and permanently deletes all data volumes.",
            High,
            "supabase stop --no-backup stops the local development stack and deletes data:\n\n\
             - All local database data is permanently deleted\n\
             - Storage objects in the local stack are removed\n\
             - Auth users created locally are lost\n\
             - Combined with --all, deletes ALL local Supabase projects' data\n\n\
             Use 'supabase stop' without --no-backup to preserve data.",
            STOP_NO_BACKUP_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    // ====================================================================
    // Database patterns
    // ====================================================================

    #[test]
    fn test_db_reset() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase db reset", "db reset");
        assert_blocks(&pack, "supabase  db  reset", "db reset");
        assert_blocks(&pack, "supabase db reset --linked", "db reset");
    }

    #[test]
    fn test_db_push() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase db push", "db push");
        assert_blocks(&pack, "supabase db push --linked", "db push");
    }

    #[test]
    fn test_db_push_dry_run_safe() {
        let pack = create_pack();
        // --dry-run immediately after push
        assert_allows(&pack, "supabase db push --dry-run");
        assert_allows(&pack, "supabase db push --dry-run=true");
        // --dry-run after other flags
        assert_allows(&pack, "supabase db push --linked --dry-run");
    }

    #[test]
    fn test_db_push_false_dry_run_does_not_bypass() {
        let pack = create_pack();

        for command in [
            "supabase db push --dry-run=false",
            "supabase db push --linked --dry-run=false",
            "supabase db push --dry-run=0",
            "supabase db push --no-dry-run",
        ] {
            assert_blocks_with_pattern(&pack, command, "supabase-db-push");
            assert_no_safe_match(&pack, command);
        }
    }

    #[test]
    fn test_db_shell_destructive() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "supabase db shell -- -c 'DROP TABLE users'",
            "destructive SQL",
        );
        assert_blocks(
            &pack,
            "supabase db shell -- -c 'TRUNCATE users'",
            "destructive SQL",
        );
        assert_blocks(
            &pack,
            "supabase db shell -- -c 'DELETE FROM users'",
            "destructive SQL",
        );
        assert_blocks(
            &pack,
            "supabase db shell -- -c 'ALTER TABLE users DROP COLUMN email'",
            "destructive SQL",
        );
    }

    // ====================================================================
    // Migration patterns
    // ====================================================================

    #[test]
    fn test_migration_repair() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase migration repair", "migration repair");
        assert_blocks(
            &pack,
            "supabase migration repair --status applied",
            "migration repair",
        );
    }

    #[test]
    fn test_migration_down() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase migration down", "migration down");
        assert_blocks(&pack, "supabase migration down --linked", "migration down");
        assert_blocks(
            &pack,
            "supabase migration down --version 2",
            "migration down",
        );
    }

    #[test]
    fn test_migration_squash() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase migration squash", "migration squash");
        assert_blocks(
            &pack,
            "supabase migration squash --linked",
            "migration squash",
        );
        assert_blocks(
            &pack,
            "supabase migration squash --version 20240101000000",
            "migration squash",
        );
    }

    // ====================================================================
    // Functions patterns
    // ====================================================================

    #[test]
    fn test_functions_delete() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "supabase functions delete my-function",
            "functions delete",
        );
        assert_blocks(
            &pack,
            "supabase functions delete my-function --project-ref abc123",
            "functions delete",
        );
    }

    // ====================================================================
    // Storage patterns
    // ====================================================================

    #[test]
    fn test_storage_rm() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "supabase storage rm ss:///bucket/path/file.txt",
            "storage rm",
        );
        assert_blocks(
            &pack,
            "supabase storage rm ss:///bucket/path/ --recursive",
            "storage rm",
        );
    }

    // ====================================================================
    // Secrets patterns
    // ====================================================================

    #[test]
    fn test_secrets_unset() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase secrets unset MY_SECRET", "secrets unset");
        assert_blocks(
            &pack,
            "supabase secrets unset KEY1 KEY2 KEY3",
            "secrets unset",
        );
    }

    // ====================================================================
    // Infrastructure patterns
    // ====================================================================

    #[test]
    fn test_projects_delete() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase projects delete", "projects delete");
        assert_blocks(
            &pack,
            "supabase projects delete --ref abc123",
            "projects delete",
        );
    }

    #[test]
    fn test_orgs_delete() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase orgs delete", "orgs delete");
        assert_blocks(&pack, "supabase orgs delete --id org123", "orgs delete");
    }

    #[test]
    fn test_branches_delete() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase branches delete abc123", "branches delete");
        assert_blocks(
            &pack,
            "supabase branches delete --id abc123",
            "branches delete",
        );
    }

    // ====================================================================
    // Networking & Domains patterns
    // ====================================================================

    #[test]
    fn test_domains_delete() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase domains delete", "domains delete");
        assert_blocks(
            &pack,
            "supabase domains delete --project-ref abc123",
            "domains delete",
        );
    }

    #[test]
    fn test_vanity_subdomains_delete() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "supabase vanity-subdomains delete",
            "vanity-subdomains delete",
        );
    }

    #[test]
    fn test_network_restrictions_update() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "supabase network-restrictions update --db-allow-cidr 10.0.0.0/8",
            "network-restrictions update",
        );
    }

    // ====================================================================
    // Auth (SSO) patterns
    // ====================================================================

    #[test]
    fn test_sso_remove() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase sso remove provider-id", "sso remove");
        assert_blocks(&pack, "supabase sso remove --id provider-id", "sso remove");
    }

    // ====================================================================
    // Config & Local patterns
    // ====================================================================

    #[test]
    fn test_config_push() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase config push", "config push");
        assert_blocks(
            &pack,
            "supabase config push --project-ref abc123",
            "config push",
        );
    }

    #[test]
    fn test_stop_no_backup() {
        let pack = create_pack();
        assert_blocks(&pack, "supabase stop --no-backup", "stop --no-backup");
        assert_blocks(&pack, "supabase stop --all --no-backup", "stop --no-backup");
        assert_blocks(&pack, "supabase stop --no-backup --all", "stop --no-backup");
    }

    // ====================================================================
    // Safe command tests
    // ====================================================================

    #[test]
    fn test_safe_database_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase db diff");
        assert_allows(&pack, "supabase db lint");
        assert_allows(&pack, "supabase db dump -f backup.sql");
        assert_allows(&pack, "supabase db dump -f backup.sql --linked");
        assert_allows(&pack, "supabase db shell");
        assert_allows(&pack, "supabase inspect db bloat");
        assert_allows(&pack, "supabase inspect db locks");
    }

    #[test]
    fn test_safe_status_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase status");
        assert_allows(&pack, "supabase start");
        assert_allows(&pack, "supabase services");
        assert_allows(&pack, "supabase gen types typescript");
        assert_allows(&pack, "supabase test db");
    }

    #[test]
    fn test_safe_migration_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase migration list");
        assert_allows(&pack, "supabase migration new create_users");
        assert_allows(&pack, "supabase migration fetch");
        assert_allows(&pack, "supabase db push --dry-run");
    }

    #[test]
    fn test_safe_functions_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase functions list");
        assert_allows(&pack, "supabase functions serve");
        assert_allows(&pack, "supabase functions download my-function");
        assert_allows(&pack, "supabase functions new my-function");
    }

    #[test]
    fn test_safe_secrets_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase secrets list");
    }

    #[test]
    fn test_safe_storage_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase storage ls ss:///bucket/");
    }

    #[test]
    fn test_safe_infrastructure_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase projects list");
        assert_allows(&pack, "supabase orgs list");
        assert_allows(&pack, "supabase branches list");
        assert_allows(&pack, "supabase branches get --id abc123");
    }

    #[test]
    fn test_safe_domains_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase domains get");
        assert_allows(&pack, "supabase domains reverify");
        assert_allows(&pack, "supabase vanity-subdomains get");
        assert_allows(
            &pack,
            "supabase vanity-subdomains check-availability my-sub",
        );
    }

    #[test]
    fn test_safe_sso_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase sso list");
        assert_allows(&pack, "supabase sso show --id provider-id");
        assert_allows(&pack, "supabase sso info");
    }

    #[test]
    fn test_safe_network_commands() {
        let pack = create_pack();
        assert_allows(&pack, "supabase network-restrictions get");
        assert_allows(&pack, "supabase network-bans get");
        assert_allows(&pack, "supabase ssl-enforcement get");
        assert_allows(&pack, "supabase postgres-config get");
    }

    #[test]
    fn test_stop_without_no_backup_is_not_blocked() {
        let pack = create_pack();
        // bare stop has no matching destructive pattern — allowed by default
        assert_no_match(&pack, "supabase stop");
        assert_no_match(&pack, "supabase stop --all");
    }

    #[test]
    fn test_global_flags_do_not_bypass() {
        // supabase CLI accepts --debug, --workdir, --experimental, --project-ref.
        // Old `supabase\s+db\s+reset` would fail when a flag came first.
        let pack = create_pack();
        assert_blocks(&pack, "supabase --project-ref abc123 db reset", "db reset");
        assert_blocks(&pack, "supabase --debug --workdir . db push", "db push");
        assert_blocks(
            &pack,
            "supabase --project-ref abc123 functions delete my-fn",
            "functions delete",
        );
        // Safe commands with global flags should still short-circuit.
        assert_allows(&pack, "supabase --project-ref abc123 db diff");
        assert_allows(&pack, "supabase --debug status");
    }
}
