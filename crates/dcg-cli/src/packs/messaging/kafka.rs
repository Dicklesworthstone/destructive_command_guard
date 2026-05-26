//! `Apache Kafka` pack - protections for destructive Kafka CLI operations.
//!
//! This pack targets high-impact Kafka operations like deleting topics,
//! resetting consumer offsets, removing ACLs, and deleting records.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Kafka messaging pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "messaging.kafka".to_string(),
        name: "Apache Kafka",
        description: "Protects against destructive Kafka CLI operations like deleting topics, \
                      removing consumer groups, resetting offsets, and deleting records.",
        keywords: &[
            "kafka-topics",
            "kafka-topics.sh",
            "kafka-consumer-groups",
            "kafka-consumer-groups.sh",
            "kafka-configs",
            "kafka-configs.sh",
            "kafka-acls",
            "kafka-acls.sh",
            "kafka-delete-records",
            "kafka-delete-records.sh",
            "kafka-console-consumer",
            "kafka-console-producer",
            "kafka-broker-api-versions",
            "rpk",
        ],
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
            "kafka-topics-list",
            r"kafka-topics(?:\.sh)?\b(?!.*\s--delete\b).*\s--list\b"
        ),
        safe_pattern!(
            "kafka-topics-describe",
            r"kafka-topics(?:\.sh)?\b(?!.*\s--delete\b).*\s--describe\b"
        ),
        safe_pattern!(
            "kafka-consumer-groups-list",
            r"kafka-consumer-groups(?:\.sh)?\b(?!.*\s(?:--delete|--reset-offsets)\b).*\s--list\b"
        ),
        safe_pattern!(
            "kafka-consumer-groups-describe",
            r"kafka-consumer-groups(?:\.sh)?\b(?!.*\s(?:--delete|--reset-offsets)\b).*\s--describe\b"
        ),
        safe_pattern!(
            "kafka-acls-list",
            r"kafka-acls(?:\.sh)?\b(?!.*\s--remove\b).*\s--list\b"
        ),
        safe_pattern!(
            "kafka-configs-describe",
            r"kafka-configs(?:\.sh)?\b(?!.*\s--delete-config\b).*\s--describe\b"
        ),
        safe_pattern!(
            "kafka-console-consumer",
            r"kafka-console-consumer(?:\.sh)?\b"
        ),
        safe_pattern!(
            "kafka-console-producer",
            r"kafka-console-producer(?:\.sh)?\b"
        ),
        safe_pattern!(
            "kafka-broker-api-versions",
            r"kafka-broker-api-versions(?:\.sh)?\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "kafka-topics-delete",
            r"kafka-topics(?:\.sh)?\b.*\s--delete\b",
            "kafka-topics --delete removes Kafka topics and data.",
            Critical,
            "Deleting a Kafka topic permanently removes all messages and partitions. \
             Consumers will receive errors, and any unprocessed data is lost. Producer \
             applications may fail until they handle the missing topic.\n\n\
             Safer alternatives:\n\
             - kafka-topics --describe: Review topic details first\n\
             - Set retention.ms to expire data naturally\n\
             - Back up critical data before deletion"
        ),
        destructive_pattern!(
            "kafka-consumer-groups-delete",
            r"kafka-consumer-groups(?:\.sh)?\b.*\s--delete\b",
            "kafka-consumer-groups --delete removes consumer groups and offsets.",
            High,
            "Deleting a consumer group removes all committed offsets. When consumers \
             reconnect, they will start from the earliest or latest offset based on \
             their configuration, potentially reprocessing or skipping messages.\n\n\
             Safer alternatives:\n\
             - kafka-consumer-groups --describe: Check group status first\n\
             - Reset offsets instead of deleting the group\n\
             - Ensure all consumers are stopped before deletion"
        ),
        destructive_pattern!(
            "kafka-consumer-groups-reset-offsets",
            r"kafka-consumer-groups(?:\.sh)?\b.*\s--reset-offsets\b",
            "kafka-consumer-groups --reset-offsets rewinds offsets and can cause reprocessing.",
            High,
            "Resetting consumer offsets can cause messages to be reprocessed or skipped. \
             This affects data consistency if your consumers are not idempotent. Resetting \
             to the earliest offset on a high-volume topic may trigger massive reprocessing.\n\n\
             Safer alternatives:\n\
             - Use --dry-run to preview the reset first\n\
             - Reset to a specific timestamp or offset for precision\n\
             - Ensure consumers are stopped before resetting"
        ),
        destructive_pattern!(
            "kafka-configs-delete-config",
            r"kafka-configs(?:\.sh)?\b.*\s--alter\b.*\s--delete-config\b",
            "kafka-configs --alter --delete-config removes broker/topic configs.",
            High,
            "Deleting configuration overrides reverts topics or brokers to default \
             settings. This can unexpectedly change retention, replication, or \
             compression behavior.\n\n\
             Safer alternatives:\n\
             - kafka-configs --describe: Review current configuration first\n\
             - Set explicit values instead of deleting to revert to defaults\n\
             - Test configuration changes in a non-production environment"
        ),
        destructive_pattern!(
            "kafka-acls-remove",
            r"kafka-acls(?:\.sh)?\b.*\s--remove\b",
            "kafka-acls --remove deletes ACLs and can break access controls.",
            High,
            "Removing ACLs can immediately break access for producers and consumers. \
             Applications may fail with authorization errors, causing message loss \
             or processing delays.\n\n\
             Safer alternatives:\n\
             - kafka-acls --list: Review existing ACLs first\n\
             - Test ACL changes in a non-production environment\n\
             - Add new ACLs before removing old ones during transitions"
        ),
        destructive_pattern!(
            "kafka-delete-records",
            r"kafka-delete-records(?:\.sh)?\b",
            "kafka-delete-records deletes records up to specified offsets.",
            Critical,
            "This command permanently deletes messages from topic partitions up to the \
             specified offsets. Deleted data cannot be recovered. Consumers attempting \
             to read deleted offsets will encounter errors.\n\n\
             Safer alternatives:\n\
             - Use retention policies for automatic data expiration\n\
             - Verify the offset JSON file carefully before execution\n\
             - Consider topic compaction for key-based retention"
        ),
        destructive_pattern!(
            "rpk-topic-delete",
            r"rpk\b.*\stopic\s+delete\b",
            "rpk topic delete removes topics (Kafka-compatible).",
            Critical,
            "Deleting a topic via rpk (Redpanda) permanently removes all data and \
             partitions, similar to kafka-topics --delete. This affects both Redpanda \
             and Kafka-compatible systems.\n\n\
             Safer alternatives:\n\
             - rpk topic describe: Review topic details first\n\
             - rpk topic list: Verify the topic name\n\
             - Use retention settings for data lifecycle management"
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
        assert_eq!(pack.id, "messaging.kafka");
        assert_eq!(pack.name, "Apache Kafka");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"kafka-topics"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_topic_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kafka-topics --bootstrap-server localhost:9092 --delete --topic orders",
            "kafka-topics-delete",
        );
    }

    #[test]
    fn test_consumer_group_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kafka-consumer-groups --bootstrap-server localhost:9092 --delete --group analytics",
            "kafka-consumer-groups-delete",
        );
    }

    #[test]
    fn test_consumer_group_reset_offsets_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kafka-consumer-groups --bootstrap-server localhost:9092 --reset-offsets --group analytics --topic orders",
            "kafka-consumer-groups-reset-offsets",
        );
    }

    #[test]
    fn test_configs_delete_config_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kafka-configs --bootstrap-server localhost:9092 --alter --delete-config retention.ms --entity-type topics --entity-name logs",
            "kafka-configs-delete-config",
        );
    }

    #[test]
    fn test_acls_remove_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kafka-acls --bootstrap-server localhost:9092 --remove --topic payments --operation All",
            "kafka-acls-remove",
        );
    }

    #[test]
    fn test_delete_records_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kafka-delete-records --bootstrap-server localhost:9092 --offset-json-file offsets.json",
            "kafka-delete-records",
        );
    }

    #[test]
    fn test_rpk_topic_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "rpk topic delete orders", "rpk-topic-delete");
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(
            &pack,
            "kafka-topics --bootstrap-server localhost:9092 --list",
        );
        assert_allows(
            &pack,
            "kafka-topics --bootstrap-server localhost:9092 --describe --topic logs",
        );
        assert_allows(
            &pack,
            "kafka-consumer-groups --bootstrap-server localhost:9092 --list",
        );
        assert_allows(
            &pack,
            "kafka-consumer-groups --bootstrap-server localhost:9092 --describe --group billing",
        );
        assert_allows(
            &pack,
            "kafka-configs --bootstrap-server localhost:9092 --describe --entity-type topics --entity-name logs",
        );
        assert_allows(&pack, "kafka-acls --bootstrap-server localhost:9092 --list");
        assert_allows(
            &pack,
            "kafka-console-consumer --bootstrap-server localhost:9092 --topic logs",
        );
        assert_allows(
            &pack,
            "kafka-console-producer --bootstrap-server localhost:9092 --topic logs",
        );
        assert_allows(
            &pack,
            "kafka-broker-api-versions --bootstrap-server localhost:9092",
        );
    }

    #[test]
    fn safe_action_flags_do_not_override_destructive_flags() {
        let pack = create_pack();

        assert_no_safe_match(
            &pack,
            "kafka-topics --bootstrap-server localhost:9092 --list --delete --topic orders",
        );
        assert_blocks_with_pattern(
            &pack,
            "kafka-topics --bootstrap-server localhost:9092 --list --delete --topic orders",
            "kafka-topics-delete",
        );
        assert_no_safe_match(
            &pack,
            "kafka-acls --bootstrap-server localhost:9092 --list --remove --topic payments",
        );
        assert_blocks_with_pattern(
            &pack,
            "kafka-acls --bootstrap-server localhost:9092 --list --remove --topic payments",
            "kafka-acls-remove",
        );
        assert_no_safe_match(
            &pack,
            "kafka-configs --bootstrap-server localhost:9092 --describe --alter --delete-config retention.ms --entity-type topics --entity-name logs",
        );
        assert_blocks_with_pattern(
            &pack,
            "kafka-configs --bootstrap-server localhost:9092 --describe --alter --delete-config retention.ms --entity-type topics --entity-name logs",
            "kafka-configs-delete-config",
        );
        assert_no_safe_match(
            &pack,
            "kafka-consumer-groups --bootstrap-server localhost:9092 --describe --reset-offsets --group analytics --topic orders",
        );
        assert_blocks_with_pattern(
            &pack,
            "kafka-consumer-groups --bootstrap-server localhost:9092 --describe --reset-offsets --group analytics --topic orders",
            "kafka-consumer-groups-reset-offsets",
        );
    }
}
