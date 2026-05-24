//! `Square` payment pack - protections for destructive `Square` operations.
//!
//! Covers destructive CLI/API operations:
//! - `square catalog delete`
//! - `curl -X DELETE` to `Square` API endpoints (catalog objects, customers,
//!   payment links, locations, webhooks)
//! - `curl -X POST` to `/v2/catalog/batch-delete`

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Square` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "payment.square".to_string(),
        name: "Square",
        description: "Protects against destructive Square CLI/API operations like deleting catalog objects \
                      or customers (which can break payment flows).",
        keywords: &[
            "square",
            "api.squareup.com",
            "connect.squareup.com",
            "connect.squareupsandbox.com",
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
            "square-catalog-list",
            r"\bsquare\b(?:\s+--?\S+(?:\s+\S+)?)*\s+catalog\s+list\b"
        ),
        safe_pattern!(
            "square-customers-list",
            r"\bsquare\b(?:\s+--?\S+(?:\s+\S+)?)*\s+customers\s+list\b"
        ),
        safe_pattern!(
            "square-api-get",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)))(?!(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/catalog/batch-delete))\bcurl\b(?:[^\n]*?(?:-X\s*|--request(?:=|\s+))GET\b[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)|[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\n]*?(?:-X\s*|--request(?:=|\s+))GET\b)"#
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "square-catalog-delete",
            r"\bsquare\b(?:\s+--?\S+(?:\s+\S+)?)*\s+catalog\s+delete\b",
            "square catalog delete removes catalog objects, impacting products and inventory.",
            High,
            "Deleting catalog objects removes products, variations, modifiers, or categories \
             from your Square catalog. POS systems, online stores, and invoicing that \
             reference these items will show errors or missing products.\n\n\
             Safer alternatives:\n\
             - square catalog list to review items first\n\
             - Set item visibility to hidden instead of deleting\n\
             - Export catalog backup before bulk deletions"
        ),
        destructive_pattern!(
            "square-api-delete-catalog-object",
            r#"(?i)\bcurl\b(?:[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/catalog/object/[^\s'"]+|[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/catalog/object/[^\s'"]+[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b)"#,
            "Square API DELETE /v2/catalog/object/{id} deletes a catalog object.",
            High,
            "Direct API deletion of catalog objects bypasses CLI safety checks. Products, \
             categories, taxes, discounts, and modifiers can be permanently removed, \
             breaking POS workflows and e-commerce integrations.\n\n\
             Safer alternatives:\n\
             - GET /v2/catalog/object/{id} to verify before deletion\n\
             - Use batch operations with careful ID validation\n\
             - Test in Square sandbox environment first"
        ),
        destructive_pattern!(
            "square-api-batch-delete-catalog-objects",
            r#"(?i)\bcurl\b(?:[^\n]*?(?:-X\s*|--request(?:=|\s+))POST\b[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/catalog/batch-delete(?:[^\s'"]*)?|[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/catalog/batch-delete(?:[^\s'"]*)?[^\n]*?(?:-X\s*|--request(?:=|\s+))POST\b)"#,
            "Square API POST /v2/catalog/batch-delete deletes multiple catalog objects.",
            Critical,
            "Batch deleting catalog objects can remove up to 200 products, variations, \
             modifiers, categories, or related objects in one call. Deletion cascades to \
             dependent catalog objects, so a wrong ID list can remove more than the \
             immediate targets.\n\n\
             Safer alternatives:\n\
             - Retrieve and review every object ID before deletion\n\
             - Export a catalog backup before batch deletion\n\
             - Test the request against Square sandbox first"
        ),
        destructive_pattern!(
            "square-api-delete-customer",
            r#"(?i)\bcurl\b(?:[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/customers/[^\s'"]+|[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/customers/[^\s'"]+[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b)"#,
            "Square API DELETE /v2/customers/{id} deletes a customer.",
            Critical,
            "Deleting a Square customer removes their profile, cards on file, and loyalty \
             data. Transaction history loses customer context, affecting reporting and \
             CRM. Repeat customers will need to re-register.\n\n\
             Safer alternatives:\n\
             - GET /v2/customers/{id} to verify customer before deletion\n\
             - Remove cards on file instead of full deletion\n\
             - Export customer data before deletion for compliance"
        ),
        destructive_pattern!(
            "square-api-delete-payment-link",
            r#"(?i)\bcurl\b(?:[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/online-checkout/payment-links/[^\s'"]+|[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/online-checkout/payment-links/[^\s'"]+[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b)"#,
            "Square API DELETE /v2/online-checkout/payment-links/{id} deletes a payment link.",
            High,
            "Deleting a Square payment link cancels the associated checkout order and makes \
             the shared link unusable. Customers who already received the link cannot pay \
             through it after deletion.\n\n\
             Safer alternatives:\n\
             - Retrieve the payment link and order before deletion\n\
             - Deactivate or replace the link intentionally through Square Dashboard\n\
             - Notify customers before invalidating a shared checkout link"
        ),
        destructive_pattern!(
            "square-api-delete-location",
            r#"(?i)\bcurl\b(?:[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/locations/[^\s'"]+|[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/locations/[^\s'"]+[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b)"#,
            "Square API DELETE /v2/locations/{id} deletes a location.",
            Critical,
            "Deleting a location removes a business location from Square. This affects \
             payment processing, inventory tracking, and employee management for that \
             location. Transactions cannot be processed at a deleted location.\n\n\
             Safer alternatives:\n\
             - Set location status to inactive instead of deleting\n\
             - GET /v2/locations/{id} to verify location details first\n\
             - Transfer inventory and employees before deletion"
        ),
        destructive_pattern!(
            "square-api-delete-webhook-subscription",
            r#"(?i)\bcurl\b(?:[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/webhooks/subscriptions/[^\s'"]+|[^\n]*?https?://(?:api\.squareup\.com|connect\.squareup(?:sandbox)?\.com)[^\s'"]*/v2/webhooks/subscriptions/[^\s'"]+[^\n]*?(?:-X\s*|--request(?:=|\s+))DELETE\b)"#,
            "Square API DELETE /v2/webhooks/subscriptions/{id} deletes a webhook subscription.",
            High,
            "Deleting a webhook subscription stops event notifications for payments, \
             refunds, inventory changes, and other business events. Your application \
             will miss critical updates until the subscription is recreated.\n\n\
             Safer alternatives:\n\
             - Disable the webhook subscription instead of deleting\n\
             - GET /v2/webhooks/subscriptions to verify subscription ID\n\
             - Set up backup notification channels before removal"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;
    use crate::packs::{REGISTRY, pack_aware_quick_reject};
    use std::collections::HashSet;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "payment.square");
        assert_eq!(pack.name, "Square");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"square"));
        assert!(pack.keywords.contains(&"connect.squareup.com"));
        assert!(pack.keywords.contains(&"connect.squareupsandbox.com"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "square catalog list");
        assert_safe_pattern_matches(&pack, "square customers list");
        assert_safe_pattern_matches(&pack, "curl -X GET https://api.squareup.com/v2/locations");
        assert_safe_pattern_matches(
            &pack,
            "curl https://connect.squareup.com/v2/locations -X GET",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "square catalog delete obj_123",
            "square-catalog-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/catalog/object/obj_123",
            "square-api-delete-catalog-object",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl https://connect.squareup.com/v2/catalog/object/obj_123 -X DELETE",
            "square-api-delete-catalog-object",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request=POST https://connect.squareup.com/v2/catalog/batch-delete -d '{\"object_ids\":[\"obj_123\"]}'",
            "square-api-batch-delete-catalog-objects",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/customers/cus_123",
            "square-api-delete-customer",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl https://connect.squareupsandbox.com/v2/customers/cus_123?version=11 --request DELETE",
            "square-api-delete-customer",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl https://connect.squareup.com/v2/online-checkout/payment-links/link_123 -XDELETE",
            "square-api-delete-payment-link",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/locations/loc_123",
            "square-api-delete-location",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/webhooks/subscriptions/sub_123",
            "square-api-delete-webhook-subscription",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl https://connect.squareup.com/v2/webhooks/subscriptions/sub_123 --request=DELETE",
            "square-api-delete-webhook-subscription",
        );
    }

    #[test]
    fn square_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "square catalog delete obj_123", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "curl https://connect.squareup.com/v2/catalog/batch-delete -X POST",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/customers/c",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.squareup.com/v2/webhooks/subscriptions/s",
            Severity::High,
        );
    }

    #[test]
    fn square_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let delete_command = "curl -X GET https://connect.squareup.com/v2/locations \
            -X DELETE https://connect.squareup.com/v2/customers/cus_123";
        let batch_delete_command = "curl https://connect.squareup.com/v2/locations --request GET \
            https://connect.squareup.com/v2/catalog/batch-delete --request=POST";

        assert_no_safe_match(&pack, delete_command);
        assert_blocks_with_pattern(&pack, delete_command, "square-api-delete-customer");

        assert_no_safe_match(&pack, batch_delete_command);
        assert_blocks_with_pattern(
            &pack,
            batch_delete_command,
            "square-api-batch-delete-catalog-objects",
        );
    }

    #[test]
    fn square_registry_keywords_keep_official_hosts_on_slow_path() {
        let enabled = HashSet::from(["payment.square".to_string()]);
        let keywords = REGISTRY.collect_enabled_keywords(&enabled);
        assert!(keywords.contains(&"connect.squareup.com"));
        assert!(keywords.contains(&"connect.squareupsandbox.com"));

        assert!(
            !pack_aware_quick_reject(
                "curl https://connect.squareup.com/v2/catalog/object/obj_123 -X DELETE",
                &keywords
            ),
            "official Square production API host must not be quick-rejected"
        );
        assert!(
            !pack_aware_quick_reject(
                "curl https://connect.squareupsandbox.com/v2/customers/cus_123 -X DELETE",
                &keywords
            ),
            "official Square sandbox API host must not be quick-rejected"
        );
    }
}
