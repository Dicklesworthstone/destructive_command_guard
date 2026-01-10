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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "nats-stream-info",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+info\b"
        ),
        safe_pattern!(
            "nats-stream-ls",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+ls\b"
        ),
        safe_pattern!(
            "nats-consumer-info",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+info\b"
        ),
        safe_pattern!(
            "nats-consumer-ls",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+ls\b"
        ),
        safe_pattern!("nats-kv-get", r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+get\b"),
        safe_pattern!("nats-kv-ls", r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+ls\b"),
        safe_pattern!("nats-pub", r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+pub\b"),
        safe_pattern!("nats-sub", r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+sub\b"),
        safe_pattern!(
            "nats-server-info",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+server\s+info\b"
        ),
        safe_pattern!("nats-bench", r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+bench\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "nats-stream-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+(?:delete|rm)\b",
            "nats stream delete/rm removes a JetStream stream and all its messages."
        ),
        destructive_pattern!(
            "nats-stream-purge",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+purge\b",
            "nats stream purge deletes ALL messages from the stream."
        ),
        destructive_pattern!(
            "nats-consumer-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+(?:delete|rm)\b",
            "nats consumer delete/rm removes a JetStream consumer."
        ),
        destructive_pattern!(
            "nats-kv-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+(?:del|rm)\b",
            "nats kv del/rm deletes key-value entries."
        ),
        destructive_pattern!(
            "nats-object-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+object\s+delete\b",
            "nats object delete removes an object from the store."
        ),
        destructive_pattern!(
            "nats-account-delete",
            r"nats(?:\s+--?\S+(?:\s+\S+)?)*\s+account\s+delete\b",
            "nats account delete removes an account and its resources."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
