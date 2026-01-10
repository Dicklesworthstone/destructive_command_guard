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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("splunk-list", r"splunk\s+list\b"),
        safe_pattern!("splunk-show", r"splunk\s+show\b"),
        safe_pattern!("splunk-search", r"splunk\s+search\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "splunk-remove-index",
            r"splunk\s+remove\s+index\b",
            "splunk remove index deletes an index and its data permanently."
        ),
        destructive_pattern!(
            "splunk-clean-eventdata",
            r"splunk\s+clean\s+eventdata\b",
            "splunk clean eventdata permanently deletes indexed data."
        ),
        destructive_pattern!(
            "splunk-delete-user-role",
            r"splunk\s+delete\s+(?:user|role)\b",
            "splunk delete user/role removes access configurations. Verify before deleting."
        ),
        destructive_pattern!(
            "splunk-api-delete",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*splunk.*\/services\/",
            "Splunk REST DELETE calls can permanently remove objects. Verify the endpoint."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_blocks(
            &pack,
            "curl -X DELETE https://splunk.example.com:8089/services/data/indexes/main",
            "REST DELETE",
        );
    }
}
