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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
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
            "aws sqs delete-queue permanently deletes an SQS queue.",
            Critical,
            "Deleting an SQS queue removes the queue and all messages in it. Messages \
             in flight are lost, and any applications sending to this queue will \
             receive errors. You must wait 60 seconds before recreating a queue \
             with the same name.\n\n\
             Safer alternatives:\n\
             - aws sqs get-queue-attributes: Review queue metrics first\n\
             - aws sqs purge-queue: Remove messages but keep the queue\n\
             - Use message retention period for automatic cleanup"
        ),
        destructive_pattern!(
            "aws-sqs-purge-queue",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+purge-queue\b",
            "aws sqs purge-queue deletes ALL messages in the queue.",
            High,
            "Purging an SQS queue deletes all messages immediately. This includes \
             messages in flight and delayed messages. The operation cannot be undone. \
             You can only purge a queue once every 60 seconds.\n\n\
             Safer alternatives:\n\
             - aws sqs get-queue-attributes: Check message count first\n\
             - Process messages normally instead of purging\n\
             - Use dead-letter queues for failed messages"
        ),
        destructive_pattern!(
            "aws-sqs-delete-message-batch",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+delete-message-batch\b",
            "aws sqs delete-message-batch removes multiple messages from the queue.",
            Medium,
            "Batch deletion removes up to 10 messages at once. Messages must be \
             successfully processed before deletion, or they will be lost. Ensure \
             your processing logic is complete before calling delete.\n\n\
             Safer alternatives:\n\
             - Verify receipt handles are still valid\n\
             - Use visibility timeout to prevent duplicate processing\n\
             - Delete messages only after confirmed processing"
        ),
        destructive_pattern!(
            "aws-sqs-delete-message",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+delete-message(?:[\s]|$)",
            "aws sqs delete-message removes a message from the queue.",
            Medium,
            "Deleting a message removes it permanently from the queue. Only delete \
             after successful processing. If processing fails after deletion, the \
             message is lost.\n\n\
             Safer alternatives:\n\
             - Extend visibility timeout if processing takes longer\n\
             - Use dead-letter queues for failed processing\n\
             - Implement idempotent processing for safety"
        ),
        destructive_pattern!(
            "aws-sns-delete-topic",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+delete-topic\b",
            "aws sns delete-topic removes an SNS topic and its subscriptions.",
            Critical,
            "Deleting an SNS topic removes all subscriptions and stops all message \
             delivery. Publishers will receive errors. Lambda functions, SQS queues, \
             and other subscribers will no longer receive notifications.\n\n\
             Safer alternatives:\n\
             - aws sns list-subscriptions-by-topic: Review subscribers first\n\
             - Unsubscribe endpoints individually if needed\n\
             - Use topic policies to restrict publishing instead"
        ),
        destructive_pattern!(
            "aws-sns-unsubscribe",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+unsubscribe\b",
            "aws sns unsubscribe removes a subscription and stops message delivery.",
            High,
            "Unsubscribing stops message delivery to that endpoint. If this is a \
             critical integration (Lambda, SQS, HTTP endpoint), that system will \
             stop receiving notifications immediately.\n\n\
             Safer alternatives:\n\
             - aws sns get-subscription-attributes: Review subscription first\n\
             - Use subscription filter policies to reduce traffic\n\
             - Disable the endpoint instead of unsubscribing"
        ),
        destructive_pattern!(
            "aws-sns-remove-permission",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+remove-permission\b",
            "aws sns remove-permission revokes permissions on a topic.",
            High,
            "Removing permissions can break cross-account access or service \
             integrations. AWS services and other accounts may lose the ability \
             to publish or subscribe to the topic.\n\n\
             Safer alternatives:\n\
             - aws sns get-topic-attributes: Review current policy first\n\
             - Add new permissions before removing old ones\n\
             - Use IAM policies for fine-grained access control"
        ),
        destructive_pattern!(
            "aws-sns-delete-platform-application",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+delete-platform-application\b",
            "aws sns delete-platform-application removes a platform application.",
            High,
            "Deleting a platform application removes all endpoints and stops push \
             notifications to mobile devices. All registered device tokens are \
             removed, and users will stop receiving push notifications.\n\n\
             Safer alternatives:\n\
             - aws sns list-endpoints-by-platform-application: Review endpoints\n\
             - Disable individual endpoints instead of deleting the app\n\
             - Back up endpoint ARNs before deletion"
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

    #[test]
    fn sqs_sns_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/q",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/q",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sqs delete-message-batch --queue-url https://sqs.us-east-1.amazonaws.com/123/q",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sns delete-topic --topic-arn arn:aws:sns:us-east-1:123:t",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sns unsubscribe --subscription-arn arn:aws:sns:us-east-1:123:s",
            Severity::High,
        );
    }

    #[test]
    fn sqs_sns_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}
