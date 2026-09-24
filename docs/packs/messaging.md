# Messaging Packs

This document describes packs in the `messaging` category.

## Packs in this Category

- [Apache Kafka](#messagingkafka)
- [RabbitMQ](#messagingrabbitmq)
- [NATS](#messagingnats)
- [AWS SQS/SNS](#messagingsqs_sns)

---

## Apache Kafka

**Pack ID:** `messaging.kafka`

Protects against destructive Kafka CLI operations like deleting topics, removing consumer groups, resetting offsets, and deleting records.

### Keywords

Commands containing these keywords are checked against this pack:

- `kafka-topics`
- `kafka-topics.sh`
- `kafka-consumer-groups`
- `kafka-consumer-groups.sh`
- `kafka-configs`
- `kafka-configs.sh`
- `kafka-acls`
- `kafka-acls.sh`
- `kafka-delete-records`
- `kafka-delete-records.sh`
- `kafka-console-consumer`
- `kafka-console-producer`
- `kafka-broker-api-versions`
- `rpk`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `kafka-topics-list` | `kafka-topics(?:\.sh)?\b(?!.*\s--delete\b).*\s--list\b` |
| `kafka-topics-describe` | `kafka-topics(?:\.sh)?\b(?!.*\s--delete\b).*\s--describe\b` |
| `kafka-consumer-groups-list` | `kafka-consumer-groups(?:\.sh)?\b(?!.*\s(?:--delete\|--reset-offsets)\b).*\s--list\b` |
| `kafka-consumer-groups-describe` | `kafka-consumer-groups(?:\.sh)?\b(?!.*\s(?:--delete\|--reset-offsets)\b).*\s--describe\b` |
| `kafka-acls-list` | `kafka-acls(?:\.sh)?\b(?!.*\s--remove\b).*\s--list\b` |
| `kafka-configs-describe` | `kafka-configs(?:\.sh)?\b(?!.*\s--delete-config\b).*\s--describe\b` |
| `kafka-console-consumer` | `kafka-console-consumer(?:\.sh)?\b` |
| `kafka-console-producer` | `kafka-console-producer(?:\.sh)?\b` |
| `kafka-broker-api-versions` | `kafka-broker-api-versions(?:\.sh)?\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `kafka-topics-delete` | kafka-topics --delete removes Kafka topics and data. | critical |
| `kafka-consumer-groups-delete` | kafka-consumer-groups --delete removes consumer groups and offsets. | high |
| `kafka-consumer-groups-reset-offsets` | kafka-consumer-groups --reset-offsets rewinds offsets and can cause reprocessing. | high |
| `kafka-configs-delete-config` | kafka-configs --alter --delete-config removes broker/topic configs. | high |
| `kafka-acls-remove` | kafka-acls --remove deletes ACLs and can break access controls. | high |
| `kafka-delete-records` | kafka-delete-records deletes records up to specified offsets. | critical |
| `rpk-topic-delete` | rpk topic delete removes topics (Kafka-compatible). | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "messaging.kafka:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "messaging.kafka:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## RabbitMQ

**Pack ID:** `messaging.rabbitmq`

Protects against destructive RabbitMQ operations like deleting queues/exchanges, purging queues, deleting vhosts, and resetting cluster state.

### Keywords

Commands containing these keywords are checked against this pack:

- `rabbitmqadmin`
- `rabbitmqctl`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `rabbitmqadmin-list` | `rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+list\b` |
| `rabbitmqadmin-show` | `rabbitmqadmin(?:\s+--?\S+(?:\s+\S+)?)*\s+show\b` |
| `rabbitmqctl-status` | `rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+status\b` |
| `rabbitmqctl-list-queues` | `rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+list_queues\b` |
| `rabbitmqctl-cluster-status` | `rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+cluster_status\b` |
| `rabbitmqctl-report` | `rabbitmqctl(?:\s+--?\S+(?:\s+\S+)?)*\s+report\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `rabbitmqadmin-delete-queue` | rabbitmqadmin delete queue permanently deletes a queue. | critical |
| `rabbitmqadmin-delete-exchange` | rabbitmqadmin delete exchange removes an exchange and its bindings. | high |
| `rabbitmqadmin-purge-queue` | rabbitmqadmin purge queue deletes ALL messages in the queue. | high |
| `rabbitmqctl-delete-queue` | rabbitmqctl delete_queue deletes the queue and ALL messages in it. | critical |
| `rabbitmqctl-purge-queue` | rabbitmqctl purge_queue deletes ALL messages in the queue. | high |
| `rabbitmqctl-delete-vhost` | rabbitmqctl delete_vhost removes a vhost and all its resources. | critical |
| `rabbitmqctl-forget-cluster-node` | rabbitmqctl forget_cluster_node permanently removes a node from the cluster. | high |
| `rabbitmqctl-reset` | rabbitmqctl reset wipes all configuration, queues, and bindings on the node. | critical |
| `rabbitmqctl-force-reset` | rabbitmqctl force_reset wipes node data and can break cluster state. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "messaging.rabbitmq:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "messaging.rabbitmq:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## NATS

**Pack ID:** `messaging.nats`

Protects against destructive NATS/JetStream operations like deleting streams, consumers, key-value entries, objects, and accounts.

### Keywords

Commands containing these keywords are checked against this pack:

- `nats`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `nats-stream-info` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+info(?=\s\|$)` |
| `nats-stream-ls` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+stream\s+ls(?=\s\|$)` |
| `nats-consumer-info` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+info(?=\s\|$)` |
| `nats-consumer-ls` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+consumer\s+ls(?=\s\|$)` |
| `nats-kv-get` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+get(?=\s\|$)` |
| `nats-kv-ls` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+ls(?=\s\|$)` |
| `nats-pub` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+pub(?=\s\|$)` |
| `nats-sub` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+sub(?=\s\|$)` |
| `nats-server-info` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+server\s+info(?=\s\|$)` |
| `nats-bench` | `nats(?:\s+--?\S+(?:\s+\S+)?)*\s+bench(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `nats-stream-delete` | nats stream delete/rm removes a JetStream stream and all its messages. | critical |
| `nats-stream-purge` | nats stream purge deletes ALL messages from the stream. | high |
| `nats-consumer-delete` | nats consumer delete/rm removes a JetStream consumer. | high |
| `nats-kv-delete` | nats kv del/rm deletes key-value entries. | high |
| `nats-object-delete` | nats object delete removes an object from the store. | high |
| `nats-account-delete` | nats account delete removes an account and its resources. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "messaging.nats:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "messaging.nats:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## AWS SQS/SNS

**Pack ID:** `messaging.sqs_sns`

Protects against destructive AWS SQS and SNS operations like deleting queues, purging messages, deleting topics, and removing subscriptions.

### Keywords

Commands containing these keywords are checked against this pack:

- `aws`
- `sqs`
- `sns`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `aws-sqs-list-queues` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+list-queues\b` |
| `aws-sqs-get-queue-attributes` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+get-queue-attributes\b` |
| `aws-sqs-receive-message` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sqs\s+receive-message\b` |
| `aws-sns-list-topics` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+list-topics\b` |
| `aws-sns-list-subscriptions` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+list-subscriptions\b` |
| `aws-sns-get-topic-attributes` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+sns\s+get-topic-attributes\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `aws-sqs-delete-queue` | aws sqs delete-queue permanently deletes an SQS queue. | critical |
| `aws-sqs-purge-queue` | aws sqs purge-queue deletes ALL messages in the queue. | high |
| `aws-sqs-delete-message-batch` | aws sqs delete-message-batch removes multiple messages from the queue. | medium |
| `aws-sqs-delete-message` | aws sqs delete-message removes a message from the queue. | medium |
| `aws-sns-delete-topic` | aws sns delete-topic removes an SNS topic and its subscriptions. | critical |
| `aws-sns-unsubscribe` | aws sns unsubscribe removes a subscription and stops message delivery. | high |
| `aws-sns-remove-permission` | aws sns remove-permission revokes permissions on a topic. | high |
| `aws-sns-delete-platform-application` | aws sns delete-platform-application removes a platform application. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "messaging.sqs_sns:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "messaging.sqs_sns:*"
reason = "Your reason here"
risk_acknowledged = true
```

---
