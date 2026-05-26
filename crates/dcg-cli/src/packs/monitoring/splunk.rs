//! Splunk monitoring patterns.
//!
//! This includes patterns for:
//! - destructive index removal / eventdata cleanup
//! - user or role deletion
//! - REST API DELETE calls to /services endpoints

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Splunk pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "monitoring.splunk".to_string(),
        name: "Splunk",
        description: "Protects against destructive Splunk CLI/API operations like index removal \
                      and REST API DELETE calls",
        keywords: &["splunk"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand so an arg containing the subcommand
    // keyword as a substring (e.g. `list-overrides`, `show-all-config`)
    // doesn't make a destructive splunk command short-circuit as safe.
    vec![
        safe_pattern!(
            "splunk-list",
            r"splunk\b(?:\s+--?\S+(?:\s+\S+)?)*\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "splunk-show",
            r"splunk\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)"
        ),
        safe_pattern!(
            "splunk-search",
            r"splunk\b(?:\s+--?\S+(?:\s+\S+)?)*\s+search(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "splunk-remove-index",
            r"splunk\b.*?\bremove\s+index\b",
            "splunk remove index deletes an index and its data permanently.",
            Critical,
            "Removing a Splunk index permanently deletes all indexed data within it. \
             Historical logs, events, and metrics are irretrievably lost. Any searches, \
             dashboards, or alerts referencing this index will fail.\n\n\
             Safer alternatives:\n\
             - splunk list index: Review index before removal\n\
             - Archive the data before deletion\n\
             - Use retention policies instead of manual deletion"
        ),
        destructive_pattern!(
            "splunk-clean-eventdata",
            r"splunk\b.*?\bclean\s+eventdata\b",
            "splunk clean eventdata permanently deletes indexed data.",
            Critical,
            "Clean eventdata permanently removes all events from the specified index. \
             This cannot be undone. Use this only when you're certain the data is no \
             longer needed.\n\n\
             Safer alternatives:\n\
             - Set retention policies for automatic cleanup\n\
             - Export data before cleaning\n\
             - Use splunk search to verify what will be deleted"
        ),
        destructive_pattern!(
            "splunk-delete-user-role",
            r"splunk\b.*?\bdelete\s+(?:user|role)\b",
            "splunk delete user/role removes access configurations. Verify before deleting.",
            High,
            "Deleting a user removes their access and any saved searches or dashboards \
             owned by them. Deleting a role affects all users assigned to it, potentially \
             breaking access controls.\n\n\
             Safer alternatives:\n\
             - splunk list user/role: Review before deletion\n\
             - Disable the user instead of deleting\n\
             - Reassign role capabilities before deletion"
        ),
        destructive_pattern!(
            "splunk-api-delete",
            r"(?i)curl\s+.*(?:-X\s*|--request(?:=|\s+))DELETE\b.*splunk.*\/services\/",
            "Splunk REST DELETE calls can permanently remove objects. Verify the endpoint.",
            High,
            "Direct API DELETE calls to Splunk services can remove indexes, saved searches, \
             dashboards, alerts, and other objects without confirmation.\n\n\
             Safer alternatives:\n\
             - GET the resource first to verify the object\n\
             - Use Splunk CLI or web UI for better feedback\n\
             - Export configuration before deletion"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn splunk_destructive_patterns_block() {
        let pack = create_pack();
        assert_blocks(&pack, "splunk remove index main", "remove index");
        assert_blocks(
            &pack,
            "splunk clean eventdata -index main",
            "clean eventdata",
        );
        assert_blocks(&pack, "splunk delete user alice", "delete user");
        assert_blocks(&pack, "splunk delete role analyst", "delete user");
    }

    #[test]
    fn splunk_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "splunk remove index main", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "splunk clean eventdata -index main",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "splunk delete user alice", Severity::High);
    }

    #[test]
    fn splunk_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "splunk list index");
        assert_safe_pattern_matches(&pack, "splunk show config");
        assert_safe_pattern_matches(&pack, "splunk search 'index=main error'");
    }

    #[test]
    fn splunk_with_global_flags() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "splunk --accept-license remove index main",
            "remove index",
        );
    }

    #[test]
    fn splunk_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }

    // curl accepts the compact short form (`-XDELETE`) and the long-flag-with-equals
    // form (`--request=DELETE`). Other monitoring packs (datadog, pagerduty,
    // prometheus, newrelic) were widened to `(?:-X\s*|--request(?:=|\s+))`;
    // splunk-api-delete was not, so a `curl -XDELETE .../services/...` would
    // sail past unblocked. Match what curl actually accepts.
    #[test]
    fn splunk_api_delete_blocks_compact_curl_forms() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -XDELETE https://splunk.example.com:8089/services/data/inputs/abc",
            "splunk-api-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request=DELETE https://splunk.example.com:8089/services/data/inputs/abc",
            "splunk-api-delete",
        );
    }
}
