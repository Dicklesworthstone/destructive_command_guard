//! `RabbitMQ` pack - protections for destructive `RabbitMQ` admin operations.
//!
//! Covers destructive CLI operations:
//! - Queue/exchange deletion
//! - Queue purge
//! - Vhost deletion
//! - Cluster resets / node removal

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `RabbitMQ` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "messaging.rabbitmq".to_string(),
        name: "RabbitMQ",
        description: "Protects against destructive RabbitMQ operations like deleting queues/exchanges, \
                      purging queues, deleting vhosts, and resetting cluster state.",
        keywords: &["rabbitmqadmin", "rabbitmqctl"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "rabbitmqadmin-list",
            r"rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+list\b"
        ),
        safe_pattern!(
            "rabbitmqadmin-show",
            r"rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+show\b"
        ),
        safe_pattern!(
            "rabbitmqctl-status",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+status\b"
        ),
        safe_pattern!(
            "rabbitmqctl-list-queues",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+list_queues\b"
        ),
        safe_pattern!(
            "rabbitmqctl-cluster-status",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+cluster_status\b"
        ),
        safe_pattern!(
            "rabbitmqctl-report",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+report\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "rabbitmqadmin-delete-queue",
            r"rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\s+queue\b",
            "rabbitmqadmin delete queue permanently deletes a queue."
        ),
        destructive_pattern!(
            "rabbitmqadmin-delete-exchange",
            r"rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\s+exchange\b",
            "rabbitmqadmin delete exchange removes an exchange and its bindings."
        ),
        destructive_pattern!(
            "rabbitmqadmin-purge-queue",
            r"rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+purge\s+queue\b",
            "rabbitmqadmin purge queue deletes ALL messages in the queue."
        ),
        destructive_pattern!(
            "rabbitmqctl-delete-vhost",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+delete_vhost\b",
            "rabbitmqctl delete_vhost removes a vhost and all its resources."
        ),
        destructive_pattern!(
            "rabbitmqctl-forget-cluster-node",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+forget_cluster_node\b",
            "rabbitmqctl forget_cluster_node permanently removes a node from the cluster."
        ),
        destructive_pattern!(
            "rabbitmqctl-reset",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+reset\b",
            "rabbitmqctl reset wipes all configuration, queues, and bindings on the node."
        ),
        destructive_pattern!(
            "rabbitmqctl-force-reset",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+force_reset\b",
            "rabbitmqctl force_reset wipes node data and can break cluster state."
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
        assert_eq!(pack.id, "messaging.rabbitmq");
        assert_eq!(pack.name, "RabbitMQ");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"rabbitmqadmin"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rabbitmqadmin list queues");
        assert_safe_pattern_matches(&pack, "rabbitmqadmin show queue name=jobs");
        assert_safe_pattern_matches(&pack, "rabbitmqctl status");
        assert_safe_pattern_matches(&pack, "rabbitmqctl list_queues name messages");
        assert_safe_pattern_matches(&pack, "rabbitmqctl cluster_status");
        assert_safe_pattern_matches(&pack, "rabbitmqctl report");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "rabbitmqadmin delete queue name=jobs",
            "rabbitmqadmin-delete-queue",
        );
        assert_blocks_with_pattern(
            &pack,
            "rabbitmqadmin delete exchange name=events",
            "rabbitmqadmin-delete-exchange",
        );
        assert_blocks_with_pattern(
            &pack,
            "rabbitmqadmin purge queue name=jobs",
            "rabbitmqadmin-purge-queue",
        );
        assert_blocks_with_pattern(
            &pack,
            "rabbitmqctl delete_vhost /prod",
            "rabbitmqctl-delete-vhost",
        );
        assert_blocks_with_pattern(
            &pack,
            "rabbitmqctl forget_cluster_node rabbit@node2",
            "rabbitmqctl-forget-cluster-node",
        );
        assert_blocks_with_pattern(&pack, "rabbitmqctl reset", "rabbitmqctl-reset");
        assert_blocks_with_pattern(&pack, "rabbitmqctl force_reset", "rabbitmqctl-force-reset");
    }
}
