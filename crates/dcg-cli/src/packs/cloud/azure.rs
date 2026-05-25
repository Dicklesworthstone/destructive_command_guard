//! Azure CLI patterns - protections against destructive az commands.
//!
//! This includes patterns for:
//! - vm delete
//! - storage account delete
//! - sql server delete
//! - group delete

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Azure pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cloud.azure".to_string(),
        name: "Azure CLI",
        description: "Protects against destructive Azure CLI operations like vm delete, \
                      storage account delete, and resource group delete",
        keywords: &[
            "az", "delete", "vm", "storage", "acr", "registry",
            // Extra service keywords so newly-added rules reliably
            // select this pack even when `az` isn't the first keyword
            // in the command's token list.
            "keyvault", "role", "ad", "dns", "cosmosdb", "monitor", "purge",
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
        // show/list operations are safe (read-only)
        // `(?:\s+--?\S+(?:\s+\S+)?)*` consumes only flag-value pairs before
        // the service-name token. Otherwise a destructive command with an
        // arg value that happens to be `show` or `list` (e.g.
        // `az vm delete --ids show-vm-id`) would match the safe pattern
        // and bypass the destructive check. `(?=\s|$)` closes the trailing
        // side so `show-me-foo` can't pose as the `show` subcommand.
        safe_pattern!(
            "az-show",
            r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+\S+\s+show(?=\s|$)"
        ),
        safe_pattern!(
            "az-list",
            r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+\S+\s+list(?=\s|$)"
        ),
        // az account is safe.  Require `account` to be preceded by
        // whitespace so the pattern doesn't false-match `--account-name`
        // arguments (a common flag on many destructive subcommands,
        // e.g. `az cosmosdb sql container delete --account-name …`) —
        // a safe-first match on a flag value would BYPASS the
        // destructive check. Same care is taken on every similar
        // `az`/`gcloud` safe pattern below.
        safe_pattern!(
            "az-account",
            r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+account(?=\s|$)"
        ),
        // az configure is safe
        safe_pattern!(
            "az-configure",
            r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+configure(?=\s|$)"
        ),
        // az login is safe
        safe_pattern!("az-login", r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+login(?=\s|$)"),
        // az version is safe
        safe_pattern!(
            "az-version",
            r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s|$)"
        ),
        // az --help is safe
        safe_pattern!("az-help", r"az\b.*--help"),
        // Azure What-If is a deployment feature, not a universal delete
        // preview flag. Keep it scoped to documented deployment commands so
        // unsupported `--what-if` text cannot bypass destructive `az ... delete`.
        safe_pattern!(
            "az-deployment-what-if",
            r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+deployment\s+(?:group|sub|mg|tenant)\s+what-if(?:\s|$)"
        ),
        safe_pattern!(
            "az-deployment-create-what-if",
            r"az\b(?:\s+--?\S+(?:\s+\S+)?)*\s+deployment\s+(?:group|sub|mg|tenant)\s+create(?:\s|$)[^\n;&|]*\s--what-if(?:\s|$)"
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // vm delete
        destructive_pattern!(
            "vm-delete",
            r"az\b.*?\bvm\s+delete",
            "az vm delete permanently destroys virtual machines.",
            Critical,
            "vm delete permanently destroys Azure VMs:\n\n\
             - VM is deallocated and deleted\n\
             - OS disk deleted (unless --os-disk=detach)\n\
             - Data disks detached but not deleted\n\
             - Public IP released\n\n\
             Preserve disks: az vm delete --os-disk detach --data-disks detach"
        ),
        // storage account delete
        destructive_pattern!(
            "storage-delete",
            r"az\b.*?\bstorage\s+account\s+delete",
            "az storage account delete permanently destroys the storage account and all data.",
            Critical,
            "storage account delete destroys entire storage account:\n\n\
             - ALL blobs, files, queues, tables deleted\n\
             - All containers and their contents gone\n\
             - Cannot be recovered without backups\n\n\
             List contents first: az storage container list --account-name NAME"
        ),
        // storage blob/container delete
        destructive_pattern!(
            "blob-delete",
            r"az\b.*?\bstorage\s+(?:blob|container)\s+delete",
            "az storage blob/container delete permanently removes data.",
            High,
            "storage blob/container delete removes data:\n\n\
             - Blob delete removes individual blobs\n\
             - Container delete removes container and ALL blobs\n\
             - Soft delete may allow recovery if enabled\n\n\
             Check soft delete: az storage account show --name NAME --query blobServiceProperties"
        ),
        // sql server delete
        destructive_pattern!(
            "sql-delete",
            r"az\b.*?\bsql\s+(?:server|db)\s+delete",
            "az sql server/db delete permanently destroys the database.",
            Critical,
            "sql server/db delete destroys databases:\n\n\
             - Server delete removes ALL databases on server\n\
             - Database delete removes specific database\n\
             - Point-in-time restore possible within retention period\n\n\
             Create backup: az sql db export --name DB --server SRV --storage-uri URI"
        ),
        // group delete (resource group)
        destructive_pattern!(
            "group-delete",
            r"az\b.*?\bgroup\s+delete",
            "az group delete removes the entire resource group and ALL resources within it!",
            Critical,
            "group delete removes ENTIRE resource group:\n\n\
             - ALL resources in the group deleted\n\
             - VMs, storage, databases, networks - everything\n\
             - Cannot be undone\n\
             - --no-wait returns immediately (deletion continues)\n\n\
             This is one of the most destructive Azure commands!"
        ),
        // aks delete (Kubernetes)
        destructive_pattern!(
            "aks-delete",
            r"az\b.*?\baks\s+delete",
            "az aks delete removes the entire AKS cluster.",
            Critical,
            "aks delete removes the entire Kubernetes cluster:\n\n\
             - All nodes and workloads terminated\n\
             - Persistent volumes may be deleted\n\
             - Load balancers and IPs released\n\
             - Node resource group also deleted\n\n\
             Backup workloads: kubectl get all -A -o yaml > backup.yaml"
        ),
        // webapp delete
        destructive_pattern!(
            "webapp-delete",
            r"az\b.*?\bwebapp\s+delete",
            "az webapp delete removes the App Service.",
            High,
            "webapp delete removes App Service:\n\n\
             - Application code and configuration deleted\n\
             - Custom domain mappings removed\n\
             - SSL certificates may be deleted\n\
             - Deployment slots also deleted\n\n\
             Backup config: az webapp config show --name NAME -g RG"
        ),
        // functionapp delete
        destructive_pattern!(
            "functionapp-delete",
            r"az\b.*?\bfunctionapp\s+delete",
            "az functionapp delete removes the Azure Function App.",
            High,
            "functionapp delete removes Azure Functions:\n\n\
             - All functions and configuration deleted\n\
             - Triggers and bindings removed\n\
             - Function keys lost\n\
             - Associated storage may be affected\n\n\
             Export functions if not in version control."
        ),
        // cosmosdb delete
        destructive_pattern!(
            "cosmosdb-delete",
            r"az\b.*?\bcosmosdb\s+(?:delete|database\s+delete|collection\s+delete)",
            "az cosmosdb delete permanently destroys the Cosmos DB resource.",
            Critical,
            "cosmosdb delete destroys Cosmos DB resources:\n\n\
             - Account delete removes entire Cosmos DB account\n\
             - Database delete removes database and all containers\n\
             - Collection delete removes container and data\n\n\
             Enable point-in-time restore for recovery options."
        ),
        // keyvault delete
        destructive_pattern!(
            "keyvault-delete",
            r"az\b.*?\bkeyvault\s+delete",
            "az keyvault delete removes the Key Vault. Secrets may be unrecoverable.",
            Critical,
            "keyvault delete removes Key Vault:\n\n\
             - All secrets, keys, certificates deleted\n\
             - Soft delete allows recovery (if enabled)\n\
             - Purge protection prevents permanent deletion\n\
             - Vault name reserved for recovery period\n\n\
             Check protection: az keyvault show --name NAME --query properties.enablePurgeProtection"
        ),
        // network vnet delete
        destructive_pattern!(
            "vnet-delete",
            r"az\b.*?\bnetwork\s+vnet\s+delete",
            "az network vnet delete removes the virtual network.",
            High,
            "network vnet delete removes virtual network:\n\n\
             - Network must be empty (no subnets in use)\n\
             - Connected resources lose connectivity\n\
             - Peerings to other VNets broken\n\
             - Network security groups may remain\n\n\
             Check usage: az network vnet subnet list --vnet-name VNET -g RG"
        ),
        // acr registry delete
        destructive_pattern!(
            "acr-delete",
            r"az\b.*?\bacr\s+delete",
            "az acr delete removes the container registry and all images.",
            Critical,
            "acr delete removes entire container registry:\n\n\
             - ALL repositories and images deleted\n\
             - All tags and manifests gone\n\
             - Webhooks and replications removed\n\
             - Registry name becomes available to others\n\n\
             List repos: az acr repository list --name REGISTRY"
        ),
        // acr repository delete
        destructive_pattern!(
            "acr-repository-delete",
            r"az\b.*?\bacr\s+repository\s+delete",
            "az acr repository delete permanently deletes the repository and its images.",
            High,
            "acr repository delete removes repository:\n\n\
             - All tags and images in repository deleted\n\
             - Running containers unaffected (cached)\n\
             - New pulls will fail\n\n\
             List tags: az acr repository show-tags --name REG --repository REPO"
        ),
        // acr repository untag
        destructive_pattern!(
            "acr-repository-untag",
            r"az\b.*?\bacr\s+repository\s+untag",
            "az acr repository untag removes tags from images.",
            Medium,
            "acr repository untag removes image tags:\n\n\
             - Tag removed from manifest\n\
             - Image still exists if other tags reference it\n\
             - Untagged images may be garbage collected\n\n\
             Lower risk: manifests can be re-tagged if digest known."
        ),
        // ---- Security- and data-critical Azure services --------------------
        destructive_pattern!(
            "keyvault-item-delete-or-purge",
            // Matches `az keyvault <sub> delete/purge` where <sub> is
            // `key`, `secret`, `certificate`, `storage` (the major
            // Key Vault sub-resources). Purge is particularly dangerous:
            // it bypasses the soft-delete recovery window.
            r"az\b.*?\bkeyvault\s+(?:key|secret|certificate|storage)\s+(?:delete|purge)",
            "Key Vault item delete/purge (az keyvault <key|secret|certificate|storage> …) — purge bypasses soft-delete and is irreversible.",
            Critical,
            "keyvault delete/purge on a Key Vault sub-resource:\n\n\
             - delete: soft-delete (recoverable within retention window)\n\
             - purge: PERMANENT; cannot be recovered; bypasses retention\n\
             - Purging a KEK (Key-Encryption-Key) makes all data encrypted under it unrecoverable\n\
             - Applications/services bound to the item fail immediately\n\n\
             Restore soft-deleted items within retention:\n  \
             az keyvault <sub> recover --name NAME --vault-name VAULT\n\n\
             Check purge protection:\n  \
             az keyvault show --name VAULT --query properties.enablePurgeProtection"
        ),
        destructive_pattern!(
            "role-assignment-delete",
            r"az\b.*?\brole\s+assignment\s+delete",
            "az role assignment delete removes an RBAC binding — users/SPs lose permissions.",
            High,
            "role assignment delete revokes an RBAC assignment:\n\n\
             - The target user / service principal / group loses the role's permissions\n\
             - Can cascade — CI/CD pipelines, workloads, operators lose access\n\
             - Re-adding via `az role assignment create` is possible if IDs are known\n\n\
             List bindings first:\n  \
             az role assignment list --assignee PRINCIPAL-ID"
        ),
        destructive_pattern!(
            "ad-sp-delete",
            r"az\b.*?\bad\s+sp\s+delete",
            "az ad sp delete removes a service principal — workloads using it lose auth.",
            Critical,
            "ad sp delete removes an Azure AD service principal:\n\n\
             - All workloads authenticating via this SP lose access\n\
             - SP credentials (client secrets, certs) are invalidated\n\
             - Can soft-delete and restore within 30 days via Graph API\n\
             - Associated app registration is NOT deleted (requires `az ad app delete`)\n\n\
             Preview usages:\n  \
             az role assignment list --assignee SP-APP-ID"
        ),
        destructive_pattern!(
            "ad-app-delete",
            r"az\b.*?\bad\s+app\s+delete",
            "az ad app delete removes an Azure AD app registration — every service principal for it stops working.",
            Critical,
            "ad app delete removes the Azure AD application registration:\n\n\
             - All service principals derived from this app break\n\
             - OAuth grants to this app are invalidated\n\
             - Associated federated credentials are deleted\n\
             - Can restore within 30 days via Graph API soft-delete\n\n\
             Consider disabling instead:\n  \
             az ad app update --id APP-ID --set disabledByMicrosoftStatus=None"
        ),
        destructive_pattern!(
            "network-dns-zone-delete",
            r"az\b.*?\bnetwork\s+dns\s+zone\s+delete",
            "az network dns zone delete removes an Azure DNS zone — domains stop resolving.",
            Critical,
            "network dns zone delete removes an Azure DNS zone:\n\n\
             - All record sets in the zone are deleted\n\
             - Domains delegated to this zone's nameservers stop resolving\n\
             - Production traffic goes dark\n\
             - No undelete\n\n\
             Export records first:\n  \
             az network dns record-set list -g RG -z ZONE -o json > zone-backup.json"
        ),
        destructive_pattern!(
            "monitor-log-profiles-delete",
            r"az\b.*?\bmonitor\s+log-profiles\s+delete",
            "az monitor log-profiles delete removes a subscription activity-log export — compliance/forensics.",
            High,
            "monitor log-profiles delete stops exporting the Azure activity log:\n\n\
             - Historical entries at the destination (Storage/Event Hub) are preserved\n\
             - Future activity events stop flowing to the configured export\n\
             - Compliance audit (SOC2, ISO 27001, FedRAMP) may require this profile\n\n\
             Each subscription only supports one log profile at a time."
        ),
        destructive_pattern!(
            "cosmosdb-sql-container-delete",
            // Existing `cosmosdb-delete` matches `cosmosdb delete`,
            // `cosmosdb database delete`, and `cosmosdb collection delete`
            // — but Cosmos DB's newer SQL API uses
            // `cosmosdb sql database|container delete` (and there are
            // mongodb/cassandra/gremlin/table variants too).
            r"az\b.*?\bcosmosdb\s+(?:sql|mongodb|cassandra|gremlin|table)\s+(?:database|container|keyspace|graph)\s+delete",
            "az cosmosdb <api> <db|container|keyspace> delete permanently destroys Cosmos DB data.",
            Critical,
            "cosmosdb <api> delete destroys Cosmos DB SQL/Mongo/Cassandra/Gremlin/Table API resources:\n\n\
             - Container/keyspace deletion removes ALL documents/rows inside\n\
             - Point-in-time restore is only available if continuous backup is enabled\n\
             - Periodic backups can restore within retention, with a new account name\n\n\
             Enable continuous backup for safer recovery:\n  \
             az cosmosdb update --name ACCOUNT --resource-group RG \\\n    \
             --backup-policy-type Continuous"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn azure_safe_pattern_does_not_bypass_via_flag_value() {
        // Regression: `az-account` safe pattern must NOT match
        // `--account-name`, `--account-id`, etc. — those are flags on
        // destructive subcommands, and a false-safe match there would
        // silently allow destructive commands through. Same concern
        // for `configure` / `login` / `version` on any destructive
        // command that happens to carry those words as flag values.
        let pack = create_pack();
        // Cosmos DB delete with --account-name must still block
        assert_blocks(
            &pack,
            "az cosmosdb sql container delete --account-name prod --database-name orders --name ledger -g prod",
            "Cosmos DB",
        );
        // VM delete with --account-name (hypothetical but similar shape)
        assert_blocks(
            &pack,
            "az vm delete --name prod-vm -g prod --no-wait",
            "vm delete",
        );
        // Genuine `az account` commands still allowed
        assert_allows(&pack, "az account list");
        assert_allows(&pack, "az account show");
        assert_allows(&pack, "az --subscription prod account list");
    }

    #[test]
    fn azure_security_and_data_critical_services_blocked() {
        // New coverage for previously-uncovered Azure destructive
        // operations on Key Vault items, RBAC, AAD, DNS, and activity-log
        // profiles.
        let pack = create_pack();
        // Key Vault sub-resource delete (soft-delete, recoverable)
        assert_blocks(
            &pack,
            "az keyvault key delete --name prod-kek --vault-name prod-vault",
            "Key Vault",
        );
        assert_blocks(
            &pack,
            "az keyvault secret delete --name prod-db-pw --vault-name prod-vault",
            "Key Vault",
        );
        // Key Vault sub-resource PURGE (bypasses soft-delete, irreversible)
        assert_blocks(
            &pack,
            "az keyvault key purge --name prod-kek --vault-name prod-vault",
            "Key Vault",
        );
        assert_blocks(
            &pack,
            "az keyvault certificate purge --name prod-tls --vault-name prod-vault",
            "Key Vault",
        );
        // RBAC role assignment
        assert_blocks(
            &pack,
            "az role assignment delete --assignee user@corp.com --role Contributor --scope /subscriptions/X",
            "RBAC",
        );
        // Azure AD service principal
        assert_blocks(
            &pack,
            "az ad sp delete --id 11111111-2222-3333-4444-555555555555",
            "service principal",
        );
        // Azure AD app registration
        assert_blocks(
            &pack,
            "az ad app delete --id 11111111-2222-3333-4444-555555555555",
            "app registration",
        );
        // DNS zone
        assert_blocks(
            &pack,
            "az network dns zone delete --name prod.example.com --resource-group prod",
            "DNS zone",
        );
        // Activity-log profile
        assert_blocks(
            &pack,
            "az monitor log-profiles delete --name prod-audit",
            "activity-log",
        );
        // Cosmos DB SQL-API container
        assert_blocks(
            &pack,
            "az cosmosdb sql container delete --account-name prod --database-name orders --name ledger -g prod",
            "Cosmos DB",
        );
        // All still block with global flags
        assert_blocks(
            &pack,
            "az --subscription prod keyvault key purge --name k --vault-name v",
            "Key Vault",
        );
    }

    #[test]
    fn azure_patterns_match_with_global_flags() {
        // Same class bug as aws.rs / gcp.rs: Azure CLI global flags
        // (`--subscription`, `--debug`, `--verbose`, `--output`,
        // `--only-show-errors`) between `az` and the service break
        // every `az\s+<svc>` pattern. Multi-subscription orgs hit this
        // every day.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "az --subscription prod vm delete --name prod-vm --resource-group prod",
            "vm delete",
        );
        assert_blocks(
            &pack,
            "az --debug --subscription prod group delete --name prod-rg --yes",
            "resource group",
        );
        assert_blocks(
            &pack,
            "az --output json --subscription prod aks delete --name prod-aks --resource-group prod",
            "AKS cluster",
        );
        assert_blocks(
            &pack,
            "az --only-show-errors --subscription prod keyvault delete --name prod-vault",
            "Key Vault",
        );
    }

    #[test]
    fn azure_what_if_safe_patterns_only_cover_deployment_previews() {
        let pack = create_pack();

        assert_safe_pattern_matches(
            &pack,
            "az deployment group what-if --resource-group rg --template-file main.bicep",
        );
        assert_safe_pattern_matches(
            &pack,
            "az --subscription prod deployment sub create --location eastus --template-file main.bicep --what-if",
        );

        assert_no_safe_match(&pack, "az group delete --name prod --what-if");
        assert_blocks_with_pattern(
            &pack,
            "az group delete --name prod --what-if",
            "group-delete",
        );
        assert_no_safe_match(
            &pack,
            "az vm delete --name prod --resource-group rg --what-if",
        );
        assert_blocks_with_pattern(
            &pack,
            "az vm delete --name prod --resource-group rg --what-if",
            "vm-delete",
        );
        assert_no_safe_match(
            &pack,
            "az deployment group create --resource-group rg --template-file main.bicep --what-if=false",
        );
    }

    #[test]
    fn acr_patterns_block() {
        let pack = create_pack();
        assert_blocks(&pack, "az acr delete --name myregistry", "acr delete");
        assert_blocks(
            &pack,
            "az acr repository delete --name myregistry --image repo:tag",
            "repository delete",
        );
        assert_blocks(
            &pack,
            "az acr repository untag --name myregistry --image repo:tag",
            "repository untag",
        );
    }

    #[test]
    fn azure_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "az vm delete --name my-vm -g rg", "vm-delete");
        assert_blocks_with_pattern(
            &pack,
            "az storage account delete --name mystorage",
            "storage-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az storage blob delete --container c --name b",
            "blob-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az sql server delete --name myserver -g rg",
            "sql-delete",
        );
        assert_blocks_with_pattern(&pack, "az group delete --name my-rg --yes", "group-delete");
        assert_blocks_with_pattern(&pack, "az aks delete --name mycluster -g rg", "aks-delete");
        assert_blocks_with_pattern(
            &pack,
            "az webapp delete --name myapp -g rg",
            "webapp-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az functionapp delete --name myfunc -g rg",
            "functionapp-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az cosmosdb delete --name myaccount -g rg",
            "cosmosdb-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az keyvault delete --name myvault",
            "keyvault-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az network vnet delete --name myvnet -g rg",
            "vnet-delete",
        );
        assert_blocks_with_pattern(&pack, "az acr delete --name myregistry", "acr-delete");
        assert_blocks_with_pattern(
            &pack,
            "az acr repository delete --name myreg --image repo:tag",
            "acr-repository-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az acr repository untag --name myreg --image repo:tag",
            "acr-repository-untag",
        );
        assert_blocks_with_pattern(
            &pack,
            "az keyvault secret delete --name mysecret --vault-name v",
            "keyvault-item-delete-or-purge",
        );
        assert_blocks_with_pattern(
            &pack,
            "az keyvault key purge --name mykey --vault-name v",
            "keyvault-item-delete-or-purge",
        );
        assert_blocks_with_pattern(
            &pack,
            "az role assignment delete --assignee user@corp.com",
            "role-assignment-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az ad sp delete --id 00000000-0000-0000-0000-000000000000",
            "ad-sp-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az ad app delete --id 00000000-0000-0000-0000-000000000000",
            "ad-app-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az network dns zone delete --name example.com -g rg",
            "network-dns-zone-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az monitor log-profiles delete --name myprofile",
            "monitor-log-profiles-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az cosmosdb sql container delete --account-name a --database-name d --name c -g rg",
            "cosmosdb-sql-container-delete",
        );
    }

    #[test]
    fn azure_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "az vm delete --name vm -g rg", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "az storage account delete --name s",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "az storage blob delete --container c --name b",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "az sql server delete --name srv -g rg",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "az group delete --name rg --yes", Severity::Critical);
        assert_blocks_with_severity(&pack, "az aks delete --name aks -g rg", Severity::Critical);
        assert_blocks_with_severity(&pack, "az webapp delete --name app -g rg", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "az functionapp delete --name fn -g rg",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "az cosmosdb delete --name acct -g rg",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "az keyvault delete --name vault", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "az network vnet delete --name vnet -g rg",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "az acr delete --name reg", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "az acr repository delete --name reg --image i:t",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "az acr repository untag --name reg --image i:t",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "az keyvault secret delete --name s --vault-name v",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "az role assignment delete --assignee u",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "az ad sp delete --id x", Severity::Critical);
        assert_blocks_with_severity(&pack, "az ad app delete --id x", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "az network dns zone delete --name z -g rg",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "az monitor log-profiles delete --name p",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "az cosmosdb sql container delete --account-name a --database-name d --name c -g rg",
            Severity::Critical,
        );
    }

    #[test]
    fn azure_all_safe_patterns_match() {
        let pack = create_pack();
        // az-show: az <svc> show
        assert_safe_pattern_matches(&pack, "az vm show --name my-vm -g rg");
        // az-list: az <svc> list
        assert_safe_pattern_matches(&pack, "az vm list");
        // az-account
        assert_safe_pattern_matches(&pack, "az account list");
        assert_safe_pattern_matches(&pack, "az account show");
        // az-configure
        assert_safe_pattern_matches(&pack, "az configure --defaults group=mygroup");
        // az-login
        assert_safe_pattern_matches(&pack, "az login");
        // az-version
        assert_safe_pattern_matches(&pack, "az version");
        // az-help
        assert_safe_pattern_matches(&pack, "az vm delete --help");
        // az-deployment-what-if
        assert_safe_pattern_matches(&pack, "az deployment group what-if --resource-group rg");
        assert_safe_pattern_matches(
            &pack,
            "az deployment group create --resource-group rg --template-file main.bicep --what-if",
        );
    }

    #[test]
    fn azure_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}
