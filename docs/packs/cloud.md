# Cloud Provider Packs

This document describes packs in the `cloud` category.

## Packs in this Category

- [AWS CLI](#cloudaws)
- [Google Cloud SDK](#cloudgcp)
- [Azure CLI](#cloudazure)

---

## AWS CLI

**Pack ID:** `cloud.aws`

Protects against destructive AWS CLI operations like terminate-instances, delete-db-instance, s3 rm --recursive, Athena/Glue catalog deletions, and destructive Athena queries (DROP DATABASE/TABLE, TRUNCATE, DELETE without WHERE)

### Keywords

Commands containing these keywords are checked against this pack:

- `aws`
- `terminate`
- `delete`
- `s3`
- `ec2`
- `rds`
- `ecr`
- `logs`
- `athena`
- `glue`
- `DROP`
- `TRUNCATE`
- `DELETE`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `aws-describe` | `aws\s+\S+\s+describe-` |
| `aws-list` | `aws\s+\S+\s+list-` |
| `aws-get` | `aws\s+\S+\s+get-` |
| `s3-ls` | `aws\s+s3\s+ls` |
| `s3-cp` | `aws\s+s3\s+cp` |
| `aws-dry-run` | `aws\s+.*--dry-run` |
| `sts-identity` | `aws\s+sts\s+get-caller-identity` |
| `cfn-describe` | `aws\s+cloudformation\s+(?:describe\|list)-` |
| `ecr-login` | `aws\s+ecr\s+get-login` |
| `athena-select` | Athena queries starting with SELECT (read-only) |
| `athena-show-describe` | Athena SHOW/DESCRIBE queries (metadata only) |
| `athena-create` | Athena CREATE TABLE/DATABASE/VIEW queries |
| `athena-insert` | Athena INSERT INTO/OVERWRITE queries |
| `athena-update` | Athena UPDATE queries with SET clause |
| `athena-delete-with-where` | Athena DELETE queries with WHERE clause (targeted) |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `ec2-terminate` | aws ec2 terminate-instances permanently destroys EC2 instances. | high |
| `removes AWS resources` | aws ec2 delete-* permanently removes AWS resources. | high |
| `s3-rm-recursive` | aws s3 rm --recursive permanently deletes all objects in the path. | high |
| `s3-rb` | aws s3 rb removes the entire S3 bucket. | high |
| `s3api-delete-bucket` | aws s3api delete-bucket removes the entire S3 bucket. | high |
| `rds-delete` | aws rds delete-db-instance/cluster permanently destroys the database. | high |
| `cfn-delete-stack` | aws cloudformation delete-stack removes the entire stack and its resources. | high |
| `lambda-delete` | aws lambda delete-function permanently removes the Lambda function. | high |
| `iam-delete` | aws iam delete-* removes IAM resources. Verify dependencies first. | high |
| `dynamodb-delete` | aws dynamodb delete-table permanently deletes the table and all data. | high |
| `eks-delete` | aws eks delete-cluster removes the entire EKS cluster. | high |
| `ecr-delete-repository` | aws ecr delete-repository permanently deletes the repository and its images. | high |
| `ecr-batch-delete-image` | aws ecr batch-delete-image permanently deletes one or more images. | high |
| `ecr-delete-lifecycle-policy` | aws ecr delete-lifecycle-policy removes the repository lifecycle policy. | high |
| `logs-delete-log-group` | aws logs delete-log-group permanently deletes a log group and all events. | high |
| `logs-delete-log-stream` | aws logs delete-log-stream permanently deletes a log stream and all events. | high |
| `athena-delete-data-catalog` | aws athena delete-data-catalog permanently removes the data catalog. | high |
| `athena-delete-named-query` | aws athena delete-named-query permanently removes a saved query. | high |
| `athena-delete-work-group` | aws athena delete-work-group permanently removes the workgroup. | high |
| `glue-delete-database` | aws glue delete-database permanently removes the database and all table definitions. | high |
| `glue-delete-table` | aws glue delete-table permanently removes the table definition. | high |
| `glue-delete-partition` | aws glue delete-partition permanently removes partition metadata. | high |
| `glue-batch-delete-table` | aws glue batch-delete-table permanently removes multiple table definitions. | high |
| `glue-batch-delete-partition` | aws glue batch-delete-partition permanently removes multiple partition definitions. | high |
| `glue-delete-crawler` | aws glue delete-crawler permanently removes the crawler configuration. | high |
| `glue-delete-job` | aws glue delete-job permanently removes the ETL job definition. | high |
| `glue-delete-dev-endpoint` | aws glue delete-dev-endpoint permanently removes the development endpoint. | high |
| `athena-query-drop-database` | Athena query with DROP DATABASE removes database from catalog. | critical |
| `athena-query-drop-table` | Athena query with DROP TABLE removes table from catalog. | high |
| `athena-query-drop-partition` | Athena query with DROP PARTITION removes partition metadata. | high |
| `athena-query-truncate` | Athena TRUNCATE TABLE deletes all data from Iceberg tables. | critical |
| `athena-query-delete-without-where` | Athena DELETE without WHERE deletes all data from Iceberg tables. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "cloud.aws:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "cloud.aws:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Google Cloud SDK

**Pack ID:** `cloud.gcp`

Protects against destructive gcloud operations like instances delete, sql instances delete, and gsutil rm -r

### Keywords

Commands containing these keywords are checked against this pack:

- `gcloud`
- `gsutil`
- `delete`
- `instances`
- `artifacts`
- `images`
- `repositories`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `gcloud-describe` | `gcloud\s+\S+\s+\S+\s+describe` |
| `gcloud-list` | `gcloud\s+\S+\s+\S+\s+list` |
| `gsutil-ls` | `gsutil\s+ls` |
| `gsutil-cp` | `gsutil\s+cp` |
| `gcloud-config` | `gcloud\s+config` |
| `gcloud-auth` | `gcloud\s+auth` |
| `gcloud-info` | `gcloud\s+info` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `compute-delete` | gcloud compute instances delete permanently destroys VM instances. | high |
| `disk-delete` | gcloud compute disks delete permanently destroys disk data. | high |
| `sql-delete` | gcloud sql instances delete permanently destroys the Cloud SQL instance. | high |
| `gsutil-rm-recursive` | gsutil rm -r permanently deletes all objects in the path. | high |
| `gsutil-rb` | gsutil rb removes the entire GCS bucket. | high |
| `gke-delete` | gcloud container clusters delete removes the entire GKE cluster. | high |
| `project-delete` | gcloud projects delete removes the entire GCP project and ALL its resources! | high |
| `functions-delete` | gcloud functions delete removes the Cloud Function. | high |
| `pubsub-delete` | gcloud pubsub delete removes Pub/Sub topics or subscriptions. | high |
| `firestore-delete` | gcloud firestore delete removes Firestore data. | high |
| `container-images-delete` | gcloud container images delete permanently deletes container images. | high |
| `artifacts-docker-images-delete` | gcloud artifacts docker images delete permanently deletes container images. | high |
| `artifacts-repositories-delete` | gcloud artifacts repositories delete permanently deletes the repository. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "cloud.gcp:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "cloud.gcp:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Azure CLI

**Pack ID:** `cloud.azure`

Protects against destructive Azure CLI operations like vm delete, storage account delete, and resource group delete

### Keywords

Commands containing these keywords are checked against this pack:

- `az`
- `delete`
- `vm`
- `storage`
- `acr`
- `registry`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `az-show` | `az\s+\S+\s+show` |
| `az-list` | `az\s+\S+\s+list` |
| `az-account` | `az\s+account` |
| `az-configure` | `az\s+configure` |
| `az-login` | `az\s+login` |
| `az-version` | `az\s+version` |
| `az-help` | `az\s+.*--help` |
| `az-what-if` | `az\s+.*--what-if` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `vm-delete` | az vm delete permanently destroys virtual machines. | high |
| `storage-delete` | az storage account delete permanently destroys the storage account and all data. | high |
| `blob-delete` | az storage blob/container delete permanently removes data. | high |
| `sql-delete` | az sql server/db delete permanently destroys the database. | high |
| `group-delete` | az group delete removes the entire resource group and ALL resources within it! | high |
| `aks-delete` | az aks delete removes the entire AKS cluster. | high |
| `webapp-delete` | az webapp delete removes the App Service. | high |
| `functionapp-delete` | az functionapp delete removes the Azure Function App. | high |
| `cosmosdb-delete` | az cosmosdb delete permanently destroys the Cosmos DB resource. | high |
| `keyvault-delete` | az keyvault delete removes the Key Vault. Secrets may be unrecoverable. | high |
| `vnet-delete` | az network vnet delete removes the virtual network. | high |
| `acr-delete` | az acr delete removes the container registry and all images. | high |
| `acr-repository-delete` | az acr repository delete permanently deletes the repository and its images. | high |
| `acr-repository-untag` | az acr repository untag removes tags from images. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "cloud.azure:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "cloud.azure:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

