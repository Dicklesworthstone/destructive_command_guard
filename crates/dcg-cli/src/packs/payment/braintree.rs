//! `Braintree` payment pack - protections for destructive `Braintree` operations.
//!
//! Covers destructive API/SDK operations:
//! - `curl -X DELETE` to `braintreegateway.com` endpoints (customers, webhooks, etc.)
//! - SDK delete/cancel calls in scripts (e.g., `braintree.Customer.delete`, `gateway.customer.delete`)
//!
//! Note: Many `Braintree` workflows run via SDK calls embedded in scripts; this pack aims to
//! catch obvious deletion/cancellation primitives in command strings.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Braintree` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "payment.braintree".to_string(),
        name: "Braintree",
        description: "Protects against destructive Braintree/PayPal payment operations like deleting customers \
                      or cancelling subscriptions via API/SDK calls.",
        keywords: &[
            "braintree",
            "braintreegateway.com",
            "braintree.",
            "gateway.customer.",
            "gateway.merchant_account.",
            "gateway.payment_method.",
            "gateway.subscription.",
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
        safe_pattern!("braintree-customer-find", r"\bbraintree\.Customer\.find\b"),
        safe_pattern!(
            "braintree-customer-search",
            r"\bgateway\.customer\.search\b"
        ),
        safe_pattern!(
            "braintree-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*braintreegateway\.com))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*braintreegateway\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "braintree-api-delete",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*braintreegateway\.com).*",
            "Braintree API DELETE calls remove payment resources (customers, webhooks, etc.).",
            High,
            "Direct API DELETE calls to Braintree permanently remove payment resources \
             without SDK safety checks. This can delete customers, payment methods, or \
             webhook configurations with no confirmation.\n\n\
             Safer alternatives:\n\
             - Use Braintree SDK which may provide additional validation\n\
             - GET the resource first to verify ID is correct\n\
             - Test in sandbox environment before production"
        ),
        destructive_pattern!(
            "braintree-customer-delete",
            r"\bbraintree\.Customer\.delete\b",
            "braintree.Customer.delete permanently deletes a Braintree customer.",
            Critical,
            "Deleting a Braintree customer removes their payment methods, transaction \
             history references, and vault records. This can break billing reconciliation \
             and compliance audit trails. Subscriptions for this customer will also fail.\n\n\
             Safer alternatives:\n\
             - Archive customer in your application instead\n\
             - Cancel subscriptions and remove payment methods first\n\
             - braintree.Customer.find() to verify customer before deletion"
        ),
        destructive_pattern!(
            "braintree-gateway-customer-delete",
            r"\bgateway\.customer\.delete\b",
            "gateway.customer.delete permanently deletes a Braintree customer.",
            Critical,
            "Deleting a customer via gateway removes all their payment methods and vault \
             data from Braintree. Associated subscriptions will fail to renew and \
             transaction history loses customer context.\n\n\
             Safer alternatives:\n\
             - Mark customer inactive in your system instead\n\
             - gateway.customer.find() to verify before deletion\n\
             - Export customer data for compliance before deletion"
        ),
        destructive_pattern!(
            "braintree-merchant-account-delete",
            r"\bgateway\.merchant_account\.delete\b",
            "gateway.merchant_account.delete removes a Braintree merchant account.",
            Critical,
            "Deleting a merchant account stops payment processing for that account. Any \
             sub-merchants or payment flows using this account will fail. Pending \
             settlements may be affected, impacting cash flow.\n\n\
             Safer alternatives:\n\
             - Contact Braintree support for proper account closure\n\
             - Verify no active transactions are pending\n\
             - Transfer sub-merchants to another account first"
        ),
        destructive_pattern!(
            "braintree-payment-method-delete",
            r"\bgateway\.payment_method\.delete\b",
            "gateway.payment_method.delete removes a stored payment method.",
            High,
            "Deleting a payment method removes the card or bank account from the vault. \
             Subscriptions using this payment method will fail on next renewal. Customers \
             will need to re-enter payment details to continue service.\n\n\
             Safer alternatives:\n\
             - Update subscription to use a different payment method first\n\
             - gateway.payment_method.find() to verify before deletion\n\
             - Notify customer before removing their payment method"
        ),
        destructive_pattern!(
            "braintree-subscription-cancel",
            r"\bgateway\.subscription\.cancel\b",
            "gateway.subscription.cancel cancels a subscription, impacting billing.",
            High,
            "Cancelling a subscription immediately stops recurring billing. The customer \
             loses access at the end of their current period (or immediately, depending \
             on configuration). This may require manual intervention to restore.\n\n\
             Safer alternatives:\n\
             - gateway.subscription.find() to verify subscription details first\n\
             - Consider pausing or updating instead of cancelling\n\
             - Communicate cancellation to customer before processing"
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
        assert_eq!(pack.id, "payment.braintree");
        assert_eq!(pack.name, "Braintree");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"braintree"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "braintree.Customer.find('cust_123')");
        assert_safe_pattern_matches(&pack, "gateway.customer.search({:email => 'a@b.com'})");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.braintreegateway.com/merchants/abc/customers/cust_123",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.braintreegateway.com/merchants/abc/customers/cust_123",
            "braintree-api-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "braintree.Customer.delete('cust_123')",
            "braintree-customer-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.customer.delete('cust_123')",
            "braintree-gateway-customer-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.merchant_account.delete('ma_123')",
            "braintree-merchant-account-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.payment_method.delete('pm_123')",
            "braintree-payment-method-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gateway.subscription.cancel('sub_123')",
            "braintree-subscription-cancel",
        );
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET https://api.braintreegateway.com/merchants/abc/customers \
            -X DELETE https://api.braintreegateway.com/merchants/abc/customers/cust_123";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "braintree-api-delete");

        assert_blocks_with_pattern(
            &pack,
            "curl https://api.braintreegateway.com/merchants/abc/customers/cust_123 --request=DELETE",
            "braintree-api-delete",
        );
    }

    #[test]
    fn braintree_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.braintreegateway.com/merchants/abc/customers/c",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "braintree.Customer.delete('c')", Severity::Critical);
        assert_blocks_with_severity(&pack, "gateway.payment_method.delete('pm')", Severity::High);
        assert_blocks_with_severity(&pack, "gateway.subscription.cancel('s')", Severity::High);
    }

    #[test]
    fn braintree_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}
