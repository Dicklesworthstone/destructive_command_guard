# Pack Reference Documentation

This directory contains detailed reference documentation for all dcg packs.

## Quick Start

Enable packs in `~/.config/dcg/config.toml`:

```toml
[packs]
enabled = ["kubernetes", "database", "containers"]
```

## Categories

| Category | Packs | Description |
|----------|-------|-------------|
| [apigateway](apigateway.md) | 3 | AWS API Gateway, Kong API Gateway, Google Apigee |
| [backup](backup.md) | 4 | BorgBackup, Rclone, Restic, ... |
| [cdn](cdn.md) | 3 | Cloudflare Workers, Fastly CDN, AWS CloudFront |
| [cicd](cicd.md) | 4 | GitHub Actions, GitLab CI, Jenkins, ... |
| [cloud](cloud.md) | 3 | AWS CLI, Google Cloud SDK, Azure CLI |
| [containers](containers.md) | 3 | Docker, Docker Compose, Podman |
| [core](core.md) | 2 | Core Git, Core Filesystem |
| [database](database.md) | 6 | PostgreSQL, MySQL/MariaDB, MongoDB, ... |
| [dns](dns.md) | 3 | Cloudflare DNS, AWS Route53, Generic DNS Tools |
| [email](email.md) | 4 | AWS SES, SendGrid, Mailgun, ... |
| [featureflags](featureflags.md) | 4 | Flipt, LaunchDarkly, Split.io, ... |
| [infrastructure](infrastructure.md) | 4 | Terraform, Ansible, Pulumi, ... |
| [kubernetes](kubernetes.md) | 3 | kubectl, Helm, Kustomize |
| [loadbalancer](loadbalancer.md) | 4 | HAProxy, nginx, Traefik, ... |
| [messaging](messaging.md) | 4 | Apache Kafka, RabbitMQ, NATS, ... |
| [monitoring](monitoring.md) | 5 | Splunk, Datadog, PagerDuty, ... |
| [package_managers](package_managers.md) | 1 | Package Managers |
| [payment](payment.md) | 3 | Stripe, Braintree, Square |
| [platform](platform.md) | 5 | GitHub Platform, GitLab Platform, Railway Platform, ... |
| [remote](remote.md) | 3 | rsync, ssh, scp |
| [search](search.md) | 4 | Elasticsearch, OpenSearch, Algolia, ... |
| [secrets](secrets.md) | 4 | HashiCorp Vault, AWS Secrets Manager, 1Password CLI, ... |
| [storage](storage.md) | 4 | AWS S3, Google Cloud Storage, MinIO, ... |
| [strict_git](strict_git.md) | 1 | Strict Git |
| [system](system.md) | 3 | Disk Operations, Permissions, Services |

## All Pack IDs

- [`core.git`](core.md#coregit)
- [`core.filesystem`](core.md#corefilesystem)
- [`storage.s3`](storage.md#storages3)
- [`storage.gcs`](storage.md#storagegcs)
- [`storage.minio`](storage.md#storageminio)
- [`storage.azure_blob`](storage.md#storageazure_blob)
- [`remote.rsync`](remote.md#remotersync)
- [`remote.ssh`](remote.md#remotessh)
- [`remote.scp`](remote.md#remotescp)
- [`cicd.github_actions`](cicd.md#cicdgithub_actions)
- [`cicd.gitlab_ci`](cicd.md#cicdgitlab_ci)
- [`cicd.jenkins`](cicd.md#cicdjenkins)
- [`cicd.circleci`](cicd.md#cicdcircleci)
- [`secrets.vault`](secrets.md#secretsvault)
- [`secrets.aws_secrets`](secrets.md#secretsaws_secrets)
- [`secrets.onepassword`](secrets.md#secretsonepassword)
- [`secrets.doppler`](secrets.md#secretsdoppler)
- [`platform.github`](platform.md#platformgithub)
- [`platform.gitlab`](platform.md#platformgitlab)
- [`platform.railway`](platform.md#platformrailway)
- [`platform.modal`](platform.md#platformmodal)
- [`platform.kamal`](platform.md#platformkamal)
- [`dns.cloudflare`](dns.md#dnscloudflare)
- [`dns.route53`](dns.md#dnsroute53)
- [`dns.generic`](dns.md#dnsgeneric)
- [`email.ses`](email.md#emailses)
- [`email.sendgrid`](email.md#emailsendgrid)
- [`email.mailgun`](email.md#emailmailgun)
- [`email.postmark`](email.md#emailpostmark)
- [`featureflags.flipt`](featureflags.md#featureflagsflipt)
- [`featureflags.launchdarkly`](featureflags.md#featureflagslaunchdarkly)
- [`featureflags.split`](featureflags.md#featureflagssplit)
- [`featureflags.unleash`](featureflags.md#featureflagsunleash)
- [`loadbalancer.haproxy`](loadbalancer.md#loadbalancerhaproxy)
- [`loadbalancer.nginx`](loadbalancer.md#loadbalancernginx)
- [`loadbalancer.traefik`](loadbalancer.md#loadbalancertraefik)
- [`loadbalancer.elb`](loadbalancer.md#loadbalancerelb)
- [`monitoring.splunk`](monitoring.md#monitoringsplunk)
- [`monitoring.datadog`](monitoring.md#monitoringdatadog)
- [`monitoring.pagerduty`](monitoring.md#monitoringpagerduty)
- [`monitoring.newrelic`](monitoring.md#monitoringnewrelic)
- [`monitoring.prometheus`](monitoring.md#monitoringprometheus)
- [`payment.stripe`](payment.md#paymentstripe)
- [`payment.braintree`](payment.md#paymentbraintree)
- [`payment.square`](payment.md#paymentsquare)
- [`messaging.kafka`](messaging.md#messagingkafka)
- [`messaging.rabbitmq`](messaging.md#messagingrabbitmq)
- [`messaging.nats`](messaging.md#messagingnats)
- [`messaging.sqs_sns`](messaging.md#messagingsqs_sns)
- [`search.elasticsearch`](search.md#searchelasticsearch)
- [`search.opensearch`](search.md#searchopensearch)
- [`search.algolia`](search.md#searchalgolia)
- [`search.meilisearch`](search.md#searchmeilisearch)
- [`backup.borg`](backup.md#backupborg)
- [`backup.rclone`](backup.md#backuprclone)
- [`backup.restic`](backup.md#backuprestic)
- [`backup.velero`](backup.md#backupvelero)
- [`database.postgresql`](database.md#databasepostgresql)
- [`database.mysql`](database.md#databasemysql)
- [`database.mongodb`](database.md#databasemongodb)
- [`database.redis`](database.md#databaseredis)
- [`database.sqlite`](database.md#databasesqlite)
- [`database.supabase`](database.md#databasesupabase)
- [`containers.docker`](containers.md#containersdocker)
- [`containers.compose`](containers.md#containerscompose)
- [`containers.podman`](containers.md#containerspodman)
- [`kubernetes.kubectl`](kubernetes.md#kuberneteskubectl)
- [`kubernetes.helm`](kubernetes.md#kuberneteshelm)
- [`kubernetes.kustomize`](kubernetes.md#kuberneteskustomize)
- [`cloud.aws`](cloud.md#cloudaws)
- [`cloud.gcp`](cloud.md#cloudgcp)
- [`cloud.azure`](cloud.md#cloudazure)
- [`cdn.cloudflare_workers`](cdn.md#cdncloudflare_workers)
- [`cdn.fastly`](cdn.md#cdnfastly)
- [`cdn.cloudfront`](cdn.md#cdncloudfront)
- [`apigateway.aws`](apigateway.md#apigatewayaws)
- [`apigateway.kong`](apigateway.md#apigatewaykong)
- [`apigateway.apigee`](apigateway.md#apigatewayapigee)
- [`infrastructure.terraform`](infrastructure.md#infrastructureterraform)
- [`infrastructure.ansible`](infrastructure.md#infrastructureansible)
- [`infrastructure.pulumi`](infrastructure.md#infrastructurepulumi)
- [`infrastructure.atmos`](infrastructure.md#infrastructureatmos)
- [`system.disk`](system.md#systemdisk)
- [`system.permissions`](system.md#systempermissions)
- [`system.services`](system.md#systemservices)
- [`strict_git`](strict_git.md#strict_git)
- [`package_managers`](package_managers.md#package_managers)

## Notes

- Enable a whole category by specifying its prefix (e.g., `kubernetes`).
- Heredoc/inline-script scanning is configured under `[heredoc]`, not `[packs]`.
- See `docs/configuration.md` for full configuration details.

---

*This documentation is auto-generated from PackRegistry metadata.*
