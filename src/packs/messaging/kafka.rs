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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("kafka-topics-list", r"kafka-topics(?:\.sh)?\b.*\s--list\b"),
        safe_pattern!(
            "kafka-topics-describe",
            r"kafka-topics(?:\.sh)?\b.*\s--describe\b"
        ),
        safe_pattern!(
            "kafka-consumer-groups-list",
            r"kafka-consumer-groups(?:\.sh)?\b.*\s--list\b"
        ),
        safe_pattern!(
            "kafka-consumer-groups-describe",
            r"kafka-consumer-groups(?:\.sh)?\b.*\s--describe\b"
        ),
        safe_pattern!("kafka-acls-list", r"kafka-acls(?:\.sh)?\b.*\s--list\b"),
        safe_pattern!(
            "kafka-configs-describe",
            r"kafka-configs(?:\.sh)?\b.*\s--describe\b"
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
            "kafka-topics --delete removes Kafka topics and data."
        ),
        destructive_pattern!(
            "kafka-consumer-groups-delete",
            r"kafka-consumer-groups(?:\.sh)?\b.*\s--delete\b",
            "kafka-consumer-groups --delete removes consumer groups and offsets."
        ),
        destructive_pattern!(
            "kafka-consumer-groups-reset-offsets",
            r"kafka-consumer-groups(?:\.sh)?\b.*\s--reset-offsets\b",
            "kafka-consumer-groups --reset-offsets rewinds offsets and can cause reprocessing."
        ),
        destructive_pattern!(
            "kafka-configs-delete-config",
            r"kafka-configs(?:\.sh)?\b.*\s--alter\b.*\s--delete-config\b",
            "kafka-configs --alter --delete-config removes broker/topic configs."
        ),
        destructive_pattern!(
            "kafka-acls-remove",
            r"kafka-acls(?:\.sh)?\b.*\s--remove\b",
            "kafka-acls --remove deletes ACLs and can break access controls."
        ),
        destructive_pattern!(
            "kafka-delete-records",
            r"kafka-delete-records(?:\.sh)?\b",
            "kafka-delete-records deletes records up to specified offsets."
        ),
        destructive_pattern!(
            "rpk-topic-delete",
            r"rpk\b.*\stopic\s+delete\b",
            "rpk topic delete removes topics (Kafka-compatible)."
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
}
