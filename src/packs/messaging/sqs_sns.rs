//! `AWS` SQS/SNS pack - protections for destructive queue and topic operations.
//!
//! Covers destructive CLI operations:
//! - SQS queue deletion, purge, and message deletion
//! - SNS topic deletion and subscription removal

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `AWS` SQS/SNS pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "messaging.sqs_sns".to_string(),
        name: "AWS SQS/SNS",
        description: "Protects against destructive AWS SQS and SNS operations like deleting queues, \
                      purging messages, deleting topics, and removing subscriptions.",
        keywords: &["aws", "sqs", "sns"],
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
            "aws-sqs-list-queues",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+list-queues\b"
        ),
        safe_pattern!(
            "aws-sqs-get-queue-attributes",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+get-queue-attributes\b"
        ),
        safe_pattern!(
            "aws-sqs-receive-message",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+receive-message\b"
        ),
        safe_pattern!(
            "aws-sns-list-topics",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+list-topics\b"
        ),
        safe_pattern!(
            "aws-sns-list-subscriptions",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+list-subscriptions\b"
        ),
        safe_pattern!(
            "aws-sns-get-topic-attributes",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+get-topic-attributes\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "aws-sqs-delete-queue",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+delete-queue\b",
            "aws sqs delete-queue permanently deletes an SQS queue."
        ),
        destructive_pattern!(
            "aws-sqs-purge-queue",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+purge-queue\b",
            "aws sqs purge-queue deletes ALL messages in the queue."
        ),
        destructive_pattern!(
            "aws-sqs-delete-message-batch",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+delete-message-batch\b",
            "aws sqs delete-message-batch removes multiple messages from the queue."
        ),
        destructive_pattern!(
            "aws-sqs-delete-message",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+delete-message(?:[\s]|$)",
            "aws sqs delete-message removes a message from the queue."
        ),
        destructive_pattern!(
            "aws-sns-delete-topic",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+delete-topic\b",
            "aws sns delete-topic removes an SNS topic and its subscriptions."
        ),
        destructive_pattern!(
            "aws-sns-unsubscribe",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+unsubscribe\b",
            "aws sns unsubscribe removes a subscription and stops message delivery."
        ),
        destructive_pattern!(
            "aws-sns-remove-permission",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+remove-permission\b",
            "aws sns remove-permission revokes permissions on a topic."
        ),
        destructive_pattern!(
            "aws-sns-delete-platform-application",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+delete-platform-application\b",
            "aws sns delete-platform-application removes a platform application."
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
        assert_eq!(pack.id, "messaging.sqs_sns");
        assert_eq!(pack.name, "AWS SQS/SNS");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"aws"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "aws sqs list-queues");
        assert_safe_pattern_matches(
            &pack,
            "aws sqs get-queue-attributes --queue-url https://sqs.us-east-1.amazonaws.com/123/queue",
        );
        assert_safe_pattern_matches(
            &pack,
            "aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/123/queue",
        );
        assert_safe_pattern_matches(&pack, "aws sns list-topics");
        assert_safe_pattern_matches(&pack, "aws sns list-subscriptions");
        assert_safe_pattern_matches(
            &pack,
            "aws sns get-topic-attributes --topic-arn arn:aws:sns:us-east-1:123:topic",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/queue",
            "aws-sqs-delete-queue",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/queue",
            "aws-sqs-purge-queue",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sqs delete-message --queue-url https://sqs.us-east-1.amazonaws.com/123/queue --receipt-handle abc",
            "aws-sqs-delete-message",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sqs delete-message-batch --queue-url https://sqs.us-east-1.amazonaws.com/123/queue",
            "aws-sqs-delete-message-batch",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sns delete-topic --topic-arn arn:aws:sns:us-east-1:123:topic",
            "aws-sns-delete-topic",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sns unsubscribe --subscription-arn arn:aws:sns:us-east-1:123:sub",
            "aws-sns-unsubscribe",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sns remove-permission --topic-arn arn:aws:sns:us-east-1:123:topic --label L",
            "aws-sns-remove-permission",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sns delete-platform-application --platform-application-arn arn:aws:sns:us-east-1:123:app",
            "aws-sns-delete-platform-application",
        );
    }
}
