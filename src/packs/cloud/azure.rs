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

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // vm delete
        destructive_pattern!(
            "vm-delete",
            r"az\s+vm\s+delete",
            "az vm delete permanently destroys virtual machines."
        ),
        // storage account delete
        destructive_pattern!(
            "storage-delete",
            r"az\s+storage\s+account\s+delete",
            "az storage account delete permanently destroys the storage account and all data."
        ),
        // storage blob/container delete
        destructive_pattern!(
            "blob-delete",
            r"az\s+storage\s+(?:blob|container)\s+delete",
            "az storage blob/container delete permanently removes data."
        ),
        // sql server delete
        destructive_pattern!(
            "sql-delete",
            r"az\s+sql\s+(?:server|db)\s+delete",
            "az sql server/db delete permanently destroys the database."
        ),
        // group delete (resource group)
        destructive_pattern!(
            "group-delete",
            r"az\s+group\s+delete",
            "az group delete removes the entire resource group and ALL resources within it!"
        ),
        // aks delete (Kubernetes)
        destructive_pattern!(
            "aks-delete",
            r"az\s+aks\s+delete",
            "az aks delete removes the entire AKS cluster."
        ),
        // webapp delete
        destructive_pattern!(
            "webapp-delete",
            r"az\s+webapp\s+delete",
            "az webapp delete removes the App Service."
        ),
        // functionapp delete
        destructive_pattern!(
            "functionapp-delete",
            r"az\s+functionapp\s+delete",
            "az functionapp delete removes the Azure Function App."
        ),
        // cosmosdb delete
        destructive_pattern!(
            "cosmosdb-delete",
            r"az\s+cosmosdb\s+(?:delete|database\s+delete|collection\s+delete)",
            "az cosmosdb delete permanently destroys the Cosmos DB resource."
        ),
        // keyvault delete
        destructive_pattern!(
            "keyvault-delete",
            r"az\s+keyvault\s+delete",
            "az keyvault delete removes the Key Vault. Secrets may be unrecoverable."
        ),
        // network vnet delete
        destructive_pattern!(
            "vnet-delete",
            r"az\s+network\s+vnet\s+delete",
            "az network vnet delete removes the virtual network."
        ),
        // acr registry delete
        destructive_pattern!(
            "acr-delete",
            r"az\s+acr\s+delete",
            "az acr delete removes the container registry and all images."
        ),
        // acr repository delete
        destructive_pattern!(
            "acr-repository-delete",
            r"az\s+acr\s+repository\s+delete",
            "az acr repository delete permanently deletes the repository and its images."
        ),
        // acr repository untag
        destructive_pattern!(
            "acr-repository-untag",
            r"az\s+acr\s+repository\s+untag",
            "az acr repository untag removes tags from images."
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
