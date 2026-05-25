//! `Stripe` payment pack - protections for destructive `Stripe` operations.
//!
//! Covers destructive CLI/API operations:
//! - `stripe ... delete` for resources like webhook endpoints, customers, products, prices, coupons
//! - `stripe api_keys roll` (key rotation without coordination)
//! - `Stripe` API DELETE calls for `/v1/...` endpoints

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Stripe` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "payment.stripe".to_string(),
        name: "Stripe",
        description: "Protects against destructive Stripe CLI/API operations like deleting webhook endpoints \
                      and customers, or rotating API keys without coordination.",
        keywords: &["stripe", "api.stripe.com"],
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
            "stripe-listen",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+listen\b"
        ),
        safe_pattern!(
            "stripe-customers-list",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+customers\s+list\b"
        ),
        safe_pattern!(
            "stripe-products-list",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+products\s+list\b"
        ),
        safe_pattern!(
            "stripe-payments-list",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+payments\s+list\b"
        ),
        safe_pattern!(
            "stripe-logs-tail",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs\s+tail\b"
        ),
        safe_pattern!(
            "stripe-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.stripe\.com.*\/v1\/))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*api\.stripe\.com.*\/v1\/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "stripe-webhook-endpoints-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+webhook[_-]endpoints\s+delete\b",
            "stripe webhook_endpoints delete removes a Stripe webhook endpoint, breaking notifications.",
            High,
            "Deleting a webhook endpoint stops Stripe event notifications for that URL. Your \
             application will miss payment confirmations, subscription updates, dispute alerts, \
             and other critical events until the webhook is recreated.\n\n\
             Safer alternatives:\n\
             - stripe webhook_endpoints list to verify before deletion\n\
             - Disable the endpoint instead of deleting if temporary\n\
             - Ensure backup webhook is configured before deletion"
        ),
        destructive_pattern!(
            "stripe-customers-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+customers\s+delete\b",
            "stripe customers delete permanently deletes a customer.",
            Critical,
            "Deleting a customer removes their payment methods, subscriptions, and billing \
             history from Stripe. This can affect compliance records, break recurring billing, \
             and lose valuable customer data that cannot be recovered.\n\n\
             Safer alternatives:\n\
             - Cancel subscriptions and mark customer inactive instead\n\
             - stripe customers retrieve to verify customer data first\n\
             - Export customer data before deletion for compliance"
        ),
        destructive_pattern!(
            "stripe-products-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+products\s+delete\b",
            "stripe products delete permanently deletes a product.",
            High,
            "Deleting a product removes it from your catalog. Associated prices remain but \
             become orphaned. Existing subscriptions using this product may behave unexpectedly \
             and invoice line items will lose product metadata.\n\n\
             Safer alternatives:\n\
             - Archive the product by setting active=false instead\n\
             - stripe products retrieve to verify before deletion\n\
             - Ensure no active subscriptions reference this product"
        ),
        destructive_pattern!(
            "stripe-prices-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+prices\s+delete\b",
            "stripe prices delete permanently deletes a price.",
            High,
            "Deleting a price removes the pricing configuration. Active subscriptions using \
             this price will fail to renew or behave unexpectedly. New purchases cannot use \
             this price ID, breaking checkout integrations that reference it.\n\n\
             Safer alternatives:\n\
             - Archive the price by setting active=false instead\n\
             - Create a new price rather than modifying existing one\n\
             - Check for active subscriptions using this price first"
        ),
        destructive_pattern!(
            "stripe-coupons-delete",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+coupons\s+delete\b",
            "stripe coupons delete permanently deletes a coupon.",
            High,
            "Deleting a coupon prevents new redemptions and removes the discount from future \
             invoices. Customers with the coupon applied to their subscription will lose the \
             discount on their next renewal.\n\n\
             Safer alternatives:\n\
             - Set coupon max_redemptions or redeem_by to expire naturally\n\
             - stripe coupons retrieve to verify before deletion\n\
             - Communicate discount changes to affected customers first"
        ),
        destructive_pattern!(
            "stripe-api-keys-roll",
            r"\bstripe\b(?:\s+--?\S+(?:\s+\S+)?)*\s+api[_-]keys\s+roll\b",
            "stripe api_keys roll rotates API keys; coordinate to avoid outages.",
            Medium,
            "Rolling API keys invalidates the old key immediately. Any service using the old \
             key will fail authentication until updated. In production, this can cause payment \
             processing outages if not coordinated across all systems.\n\n\
             Safer alternatives:\n\
             - Deploy new key to all services before rolling\n\
             - Use key restriction to limit blast radius\n\
             - Test key rotation in test mode first"
        ),
        destructive_pattern!(
            "stripe-api-delete",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.stripe\.com.*\/v1\/).*",
            "Stripe API DELETE calls remove Stripe resources.",
            High,
            "Direct API DELETE calls permanently remove Stripe resources without CLI \
             confirmation prompts. This bypasses safety checks and can delete customers, \
             products, subscriptions, or other critical payment data.\n\n\
             Safer alternatives:\n\
             - Use stripe CLI which provides confirmation prompts\n\
             - GET the resource first to verify ID is correct\n\
             - Test in Stripe test mode before production"
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
        assert_eq!(pack.id, "payment.stripe");
        assert_eq!(pack.name, "Stripe");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"stripe"));
        assert!(pack.keywords.contains(&"api.stripe.com"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "stripe listen");
        assert_safe_pattern_matches(&pack, "stripe customers list");
        assert_safe_pattern_matches(&pack, "stripe products list");
        assert_safe_pattern_matches(&pack, "stripe payments list");
        assert_safe_pattern_matches(&pack, "stripe logs tail");
        assert_safe_pattern_matches(&pack, "curl -X GET https://api.stripe.com/v1/customers");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "stripe webhook_endpoints delete we_123",
            "stripe-webhook-endpoints-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe customers delete cus_123",
            "stripe-customers-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe products delete prod_123",
            "stripe-products-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe prices delete price_123",
            "stripe-prices-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "stripe coupons delete coupon_123",
            "stripe-coupons-delete",
        );
        assert_blocks_with_pattern(&pack, "stripe api_keys roll", "stripe-api-keys-roll");
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.stripe.com/v1/customers/cus_123",
            "stripe-api-delete",
        );
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET https://api.stripe.com/v1/customers \
            -X DELETE https://api.stripe.com/v1/customers/cus_123";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "stripe-api-delete");

        assert_blocks_with_pattern(
            &pack,
            "curl https://api.stripe.com/v1/customers/cus_123 -XDELETE",
            "stripe-api-delete",
        );
    }

    #[test]
    fn key_rotation_is_medium_severity() {
        let pack = create_pack();
        let Some(matched) = pack.matches_destructive("stripe api_keys roll") else {
            panic!("expected stripe api_keys roll to match a destructive pattern");
        };
        assert_eq!(matched.severity, Severity::Medium);
    }

    #[test]
    fn stripe_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "stripe webhook_endpoints delete we_123",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "stripe customers delete cus_123", Severity::Critical);
        assert_blocks_with_severity(&pack, "stripe products delete prod_123", Severity::High);
        assert_blocks_with_severity(&pack, "stripe prices delete price_123", Severity::High);
        assert_blocks_with_severity(&pack, "stripe coupons delete coupon_123", Severity::High);
        assert_blocks_with_severity(&pack, "stripe api_keys roll", Severity::Medium);
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.stripe.com/v1/customers/cus_123",
            Severity::High,
        );
    }

    #[test]
    fn stripe_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}
