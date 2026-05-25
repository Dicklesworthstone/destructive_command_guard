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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
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
            "rabbitmqadmin delete queue permanently deletes a queue.",
            Critical,
            "Deleting a queue permanently removes all messages and bindings. \
             Consumers will disconnect, and producers will fail unless they handle \
             the missing queue. Undelivered messages are lost.\n\n\
             Safer alternatives:\n\
             - rabbitmqadmin list queues: Review queues first\n\
             - rabbitmqadmin purge queue: Remove messages but keep the queue\n\
             - Set TTL or max-length policies for automatic cleanup"
        ),
        destructive_pattern!(
            "rabbitmqadmin-delete-exchange",
            r"rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\s+exchange\b",
            "rabbitmqadmin delete exchange removes an exchange and its bindings.",
            High,
            "Deleting an exchange removes all bindings to queues. Messages published \
             to this exchange will be lost unless an alternate exchange is configured. \
             Publishers may not receive errors if they don't use confirms.\n\n\
             Safer alternatives:\n\
             - rabbitmqadmin list exchanges: Review exchanges first\n\
             - rabbitmqadmin list bindings: Check dependent bindings\n\
             - Rebind queues to a new exchange before deletion"
        ),
        destructive_pattern!(
            "rabbitmqadmin-purge-queue",
            r"rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+purge\s+queue\b",
            "rabbitmqadmin purge queue deletes ALL messages in the queue.",
            High,
            "Purging a queue deletes all messages immediately. Messages that were \
             waiting to be consumed are permanently lost. This cannot be undone.\n\n\
             Safer alternatives:\n\
             - rabbitmqadmin show queue: Check message count first\n\
             - Consume and process messages instead of purging\n\
             - Set message TTL for automatic expiration"
        ),
        destructive_pattern!(
            "rabbitmqctl-delete-vhost",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+delete_vhost\b",
            "rabbitmqctl delete_vhost removes a vhost and all its resources.",
            Critical,
            "Deleting a vhost removes ALL queues, exchanges, bindings, policies, \
             and user permissions within that vhost. This is a complete wipe of \
             that namespace.\n\n\
             Safer alternatives:\n\
             - rabbitmqctl list_vhosts: Review vhosts first\n\
             - rabbitmqctl list_queues -p <vhost>: Check resources in vhost\n\
             - Export definitions before deletion"
        ),
        destructive_pattern!(
            "rabbitmqctl-forget-cluster-node",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+forget_cluster_node\b",
            "rabbitmqctl forget_cluster_node permanently removes a node from the cluster.",
            High,
            "Forgetting a cluster node removes it from the cluster metadata. Use this \
             only for permanently failed nodes. Mirrored queues may lose replicas, \
             and quorum queues may lose availability if quorum is affected.\n\n\
             Safer alternatives:\n\
             - rabbitmqctl cluster_status: Review cluster state first\n\
             - Try to recover the node instead of forgetting\n\
             - Ensure quorum is maintained after removal"
        ),
        destructive_pattern!(
            "rabbitmqctl-reset",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+reset\b",
            "rabbitmqctl reset wipes all configuration, queues, and bindings on the node.",
            Critical,
            "Reset returns the node to a blank state, removing all exchanges, queues, \
             bindings, users, vhosts, and permissions. The node is removed from any \
             cluster it was part of.\n\n\
             Safer alternatives:\n\
             - Export definitions before reset\n\
             - Use stop_app/start_app for service restart without data loss\n\
             - Consider forget_cluster_node for cluster membership changes only"
        ),
        destructive_pattern!(
            "rabbitmqctl-force-reset",
            r"rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+force_reset\b",
            "rabbitmqctl force_reset wipes node data and can break cluster state.",
            Critical,
            "Force reset ignores cluster state and wipes the node unconditionally. \
             This can leave the cluster in an inconsistent state where other nodes \
             still expect this node to exist.\n\n\
             Safer alternatives:\n\
             - Try rabbitmqctl reset first (safer)\n\
             - Coordinate with cluster members before force reset\n\
             - Document the cluster state for recovery"
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

    #[test]
    fn rabbitmq_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "rabbitmqadmin delete queue name=jobs",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "rabbitmqadmin delete exchange name=events",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "rabbitmqadmin purge queue name=jobs", Severity::High);
        assert_blocks_with_severity(&pack, "rabbitmqctl delete_vhost /prod", Severity::Critical);
        assert_blocks_with_severity(&pack, "rabbitmqctl reset", Severity::Critical);
        assert_blocks_with_severity(&pack, "rabbitmqctl force_reset", Severity::Critical);
    }

    #[test]
    fn rabbitmq_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}
