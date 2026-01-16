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
        keywords: &["az", "delete", "vm", "storage", "acr", "registry"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // show/list operations are safe (read-only)
        safe_pattern!("az-show", r"az\s+\S+\s+show"),
        safe_pattern!("az-list", r"az\s+\S+\s+list"),
        // az account is safe
        safe_pattern!("az-account", r"az\s+account"),
        // az configure is safe
        safe_pattern!("az-configure", r"az\s+configure"),
        // az login is safe
        safe_pattern!("az-login", r"az\s+login"),
        // az version is safe
        safe_pattern!("az-version", r"az\s+version"),
        // az --help is safe
        safe_pattern!("az-help", r"az\s+.*--help"),
        // what-if is safe (preview)
        safe_pattern!("az-what-if", r"az\s+.*--what-if"),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // vm delete
        destructive_pattern!(
            "vm-delete",
            r"az\s+vm\s+delete",
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
            r"az\s+storage\s+account\s+delete",
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
            r"az\s+storage\s+(?:blob|container)\s+delete",
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
            r"az\s+sql\s+(?:server|db)\s+delete",
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
            r"az\s+group\s+delete",
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
            r"az\s+aks\s+delete",
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
            r"az\s+webapp\s+delete",
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
            r"az\s+functionapp\s+delete",
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
            r"az\s+cosmosdb\s+(?:delete|database\s+delete|collection\s+delete)",
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
            r"az\s+keyvault\s+delete",
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
            r"az\s+network\s+vnet\s+delete",
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
            r"az\s+acr\s+delete",
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
            r"az\s+acr\s+repository\s+delete",
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
            r"az\s+acr\s+repository\s+untag",
            "az acr repository untag removes tags from images.",
            Medium,
            "acr repository untag removes image tags:\n\n\
             - Tag removed from manifest\n\
             - Image still exists if other tags reference it\n\
             - Untagged images may be garbage collected\n\n\
             Lower risk: manifests can be re-tagged if digest known."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

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
}
