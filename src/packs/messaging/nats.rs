//! `NATS` pack - protections for destructive `NATS`/`JetStream` operations.
//!
//! Covers destructive CLI operations:
//! - Stream deletion and purge
//! - Consumer deletion
//! - KV deletion
//! - Object and account deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `NATS` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "messaging.nats".to_string(),
        name: "NATS",
        description: "Protects against destructive NATS/JetStream operations like deleting streams, consumers, \
                      key-value entries, objects, and accounts.",
        keywords: &["nats"],
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
        safe_pattern!(
            "nats-stream-info",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+info(?=\s|$)"
        ),
        safe_pattern!(
            "nats-stream-ls",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+ls(?=\s|$)"
        ),
        safe_pattern!(
            "nats-consumer-info",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+info(?=\s|$)"
        ),
        safe_pattern!(
            "nats-consumer-ls",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+ls(?=\s|$)"
        ),
        safe_pattern!(
            "nats-kv-get",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "nats-kv-ls",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+ls(?=\s|$)"
        ),
        safe_pattern!("nats-pub", r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+pub(?=\s|$)"),
        safe_pattern!("nats-sub", r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+sub(?=\s|$)"),
        safe_pattern!(
            "nats-server-info",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+server\s+info(?=\s|$)"
        ),
        safe_pattern!(
            "nats-bench",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+bench(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "nats-stream-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+(?:delete|rm)\b",
            "nats stream delete/rm removes a JetStream stream and all its messages.",
            Critical,
            "Deleting a JetStream stream permanently removes all stored messages, \
             consumers, and configuration. Applications relying on this stream will \
             lose access to historical data.\n\n\
             Safer alternatives:\n\
             - nats stream info: Review stream details first\n\
             - nats stream purge: Remove messages but keep the stream\n\
             - Back up stream configuration before deletion"
        ),
        destructive_pattern!(
            "nats-stream-purge",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+purge\b",
            "nats stream purge deletes ALL messages from the stream.",
            High,
            "Purging a stream removes all messages while keeping the stream and \
             consumer configurations intact. Consumers will have no messages to \
             process until new ones arrive.\n\n\
             Safer alternatives:\n\
             - nats stream info: Check message count first\n\
             - Use --seq to purge only messages up to a specific sequence\n\
             - Use --keep to retain the last N messages"
        ),
        destructive_pattern!(
            "nats-consumer-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+(?:delete|rm)\b",
            "nats consumer delete/rm removes a JetStream consumer.",
            High,
            "Deleting a consumer removes its acknowledgment state and delivery \
             tracking. Messages may be redelivered to other consumers or lost \
             if this was the only consumer.\n\n\
             Safer alternatives:\n\
             - nats consumer info: Review consumer state first\n\
             - Pause the consumer instead of deleting\n\
             - Ensure other consumers exist for critical streams"
        ),
        destructive_pattern!(
            "nats-kv-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+(?:del|rm)\b",
            "nats kv del/rm deletes key-value entries.",
            High,
            "Deleting KV entries removes data that applications may depend on. \
             If history is disabled, the deletion is permanent and cannot be \
             recovered.\n\n\
             Safer alternatives:\n\
             - nats kv get: Retrieve and back up the value first\n\
             - nats kv history: Check if history is enabled\n\
             - Use TTL for automatic expiration instead of manual deletion"
        ),
        destructive_pattern!(
            "nats-object-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+object\s+delete\b",
            "nats object delete removes an object from the store.",
            High,
            "Deleting an object from the object store removes the file and its \
             metadata. Applications expecting this object will receive errors.\n\n\
             Safer alternatives:\n\
             - nats object info: Review object details first\n\
             - Download the object before deletion\n\
             - Use object versioning if available"
        ),
        destructive_pattern!(
            "nats-account-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+account\s+delete\b",
            "nats account delete removes an account and its resources.",
            Critical,
            "Deleting a NATS account removes all streams, consumers, and permissions \
             associated with that account. All applications using this account will \
             lose connectivity.\n\n\
             Safer alternatives:\n\
             - Review account resources before deletion\n\
             - Migrate resources to another account first\n\
             - Disable the account instead of deleting"
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
        assert_eq!(pack.id, "messaging.nats");
        assert_eq!(pack.name, "NATS");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"nats"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "nats stream info ORDERS");
        assert_safe_pattern_matches(&pack, "nats stream ls");
        assert_safe_pattern_matches(&pack, "nats consumer info ORDERS durable");
        assert_safe_pattern_matches(&pack, "nats consumer ls ORDERS");
        assert_safe_pattern_matches(&pack, "nats kv get KV key");
        assert_safe_pattern_matches(&pack, "nats kv ls KV");
        assert_safe_pattern_matches(&pack, "nats pub subject msg");
        assert_safe_pattern_matches(&pack, "nats sub subject");
        assert_safe_pattern_matches(&pack, "nats server info");
        assert_safe_pattern_matches(&pack, "nats bench 1 1");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "nats stream delete ORDERS", "nats-stream-delete");
        assert_blocks_with_pattern(&pack, "nats stream rm ORDERS", "nats-stream-delete");
        assert_blocks_with_pattern(&pack, "nats stream purge ORDERS", "nats-stream-purge");
        assert_blocks_with_pattern(
            &pack,
            "nats consumer delete ORDERS durable",
            "nats-consumer-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "nats consumer rm ORDERS durable",
            "nats-consumer-delete",
        );
        assert_blocks_with_pattern(&pack, "nats kv del KV key", "nats-kv-delete");
        assert_blocks_with_pattern(&pack, "nats kv rm KV key", "nats-kv-delete");
        assert_blocks_with_pattern(
            &pack,
            "nats object delete bucket object",
            "nats-object-delete",
        );
        assert_blocks_with_pattern(&pack, "nats account delete acct", "nats-account-delete");
    }

    #[test]
    fn nats_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "nats stream delete ORDERS", Severity::Critical);
        assert_blocks_with_severity(&pack, "nats stream purge ORDERS", Severity::High);
        assert_blocks_with_severity(&pack, "nats consumer delete ORDERS d", Severity::High);
        assert_blocks_with_severity(&pack, "nats kv del KV key", Severity::High);
        assert_blocks_with_severity(&pack, "nats object delete bucket obj", Severity::High);
        assert_blocks_with_severity(&pack, "nats account delete acct", Severity::Critical);
    }

    #[test]
    fn nats_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}
