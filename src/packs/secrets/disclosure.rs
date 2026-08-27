//! Opt-in guard against commands that print secret values to agent transcripts.
//!
//! This is deliberately separate from the ordinary `secrets.*` destruction
//! packs. It changes policy from "prevent mutation" to "prevent disclosure"
//! and therefore remains opt-in even when a provider pack is enabled.

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack};

/// Create the opt-in secret-disclosure pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "secret_disclosure".to_string(),
        name: "Secret Value Disclosure",
        description: "Opt-in protection against secret-manager commands that emit credential \
                      values to stdout and therefore into an agent transcript.",
        keywords: &[
            "infisical",
            "doppler",
            "vault",
            "aws",
            "secretsmanager",
            "ssm",
            "op",
        ],
        safe_patterns: Vec::new(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "infisical-secrets-list-output",
            r"\binfisical\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets(?:\s+--?\S+(?:\s+\S+)?)*\s*$",
            "infisical secrets prints all selected secret values to stdout.",
            High,
            "The bare secrets command emits values into the terminal and agent transcript. \
             Use `infisical run -- <command>` to inject values directly into a child process.",
            executables = ["infisical"]
        ),
        destructive_pattern!(
            "infisical-secrets-get-output",
            r"\binfisical\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+get\b",
            "infisical secrets get prints requested secret values to stdout.",
            High,
            "Reading values through stdout records them in the agent transcript. Use \
             `infisical run -- <command>` when the value is needed by a process.",
            executables = ["infisical"]
        ),
        destructive_pattern!(
            "infisical-export-output",
            r"\binfisical\b(?:\s+--?\S+(?:\s+\S+)?)*\s+export\b",
            "infisical export emits a complete set of secret values.",
            High,
            "Export output contains live credentials and can enter the agent transcript or an \
             unprotected file. Prefer process injection with `infisical run`.",
            executables = ["infisical"]
        ),
        destructive_pattern!(
            "infisical-dynamic-lease-create-output",
            r"\binfisical\b(?:\s+--?\S+(?:\s+\S+)?)*\s+dynamic-secrets\s+lease\s+create\b",
            "infisical dynamic-secrets lease create emits newly issued credentials.",
            High,
            "A newly created lease returns credential values. Running this in an agent shell \
             places those credentials in the transcript.",
            executables = ["infisical"]
        ),
        destructive_pattern!(
            "onepassword-read-output",
            r"\bop\b(?:\s+--?\S+(?:\s+\S+)?)*\s+read\b",
            "op read prints a 1Password field value to stdout.",
            High,
            "Use `op run -- <command>` or a secret reference consumed directly by the target \
             process so the value does not enter the agent transcript.",
            executables = ["op"]
        ),
        destructive_pattern!(
            "onepassword-item-get-output",
            r"\bop\b(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+get\b",
            "op item get can print secret fields to stdout.",
            High,
            "Use `op run -- <command>` for value injection, or request only non-secret \
             metadata outside an agent transcript.",
            executables = ["op"]
        ),
        destructive_pattern!(
            "onepassword-document-get-output",
            r"\bop\b(?:\s+--?\S+(?:\s+\S+)?)*\s+document\s+get\b",
            "op document get emits protected document contents.",
            High,
            "Protected document contents should not be printed into an agent transcript. \
             Retrieve them only through a deliberately protected workflow.",
            executables = ["op"]
        ),
        destructive_pattern!(
            "doppler-secrets-output",
            r"\bdoppler\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+(?:get|list|download)\b",
            "doppler secrets get/list/download emits secret values.",
            High,
            "Use `doppler run -- <command>` to inject values without printing them into the \
             agent transcript.",
            executables = ["doppler"]
        ),
        destructive_pattern!(
            "vault-read-output",
            r"\bvault\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:read\b|kv\s+get\b)",
            "vault read/kv get can print secret values to stdout.",
            High,
            "Avoid returning Vault values through an agent-visible terminal. Deliver values \
             directly to the consuming process through a protected injection workflow.",
            executables = ["vault"]
        ),
        destructive_pattern!(
            "aws-secretsmanager-read-output",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-secret-value\b",
            "aws secretsmanager get-secret-value prints a stored secret value.",
            High,
            "Do not print Secrets Manager values into an agent transcript. Inject the value \
             directly into the intended process through a protected runtime path.",
            executables = ["aws"]
        ),
        destructive_pattern!(
            "aws-ssm-decrypted-read-output",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+get-parameters?\b[^|;&]*--with-decryption\b",
            "aws ssm get-parameter(s) --with-decryption prints decrypted parameter values.",
            High,
            "Decrypted SecureString values become transcript data when printed. Pass them \
             directly to the consuming process instead.",
            executables = ["aws"]
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::packs::REGISTRY;
    use crate::packs::test_helpers::*;

    #[test]
    fn pack_contract() {
        let pack = create_pack();
        assert_eq!(pack.id, "secret_disclosure");
        assert_eq!(pack.name, "Secret Value Disclosure");
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn value_emitting_commands_are_blocked() {
        let pack = create_pack();
        for (command, rule) in [
            (
                "infisical secrets --env=prod --path=/gitlab",
                "infisical-secrets-list-output",
            ),
            (
                "infisical --domain https://example.test secrets --env prod --path /gitlab",
                "infisical-secrets-list-output",
            ),
            (
                "infisical secrets get API_KEY --plain --silent",
                "infisical-secrets-get-output",
            ),
            ("infisical export --format=json", "infisical-export-output"),
            (
                "infisical dynamic-secrets lease create prod-db --plain",
                "infisical-dynamic-lease-create-output",
            ),
            ("op read op://prod/api/key", "onepassword-read-output"),
            (
                "op item get 'Database Password'",
                "onepassword-item-get-output",
            ),
            (
                "op document get 'Production Certificate'",
                "onepassword-document-get-output",
            ),
            ("doppler secrets get API_KEY", "doppler-secrets-output"),
            ("doppler secrets download", "doppler-secrets-output"),
            ("vault kv get secret/prod/api", "vault-read-output"),
            (
                "aws secretsmanager get-secret-value --secret-id prod/api",
                "aws-secretsmanager-read-output",
            ),
            (
                "aws --region us-east-1 secretsmanager get-secret-value --secret-id prod/api",
                "aws-secretsmanager-read-output",
            ),
            (
                "aws ssm get-parameters --names /prod/api --with-decryption",
                "aws-ssm-decrypted-read-output",
            ),
        ] {
            assert_blocks_with_pattern(&pack, command, rule);
        }
    }

    #[test]
    fn injection_metadata_and_mutation_do_not_match_disclosure_rules() {
        let pack = create_pack();
        for command in [
            "infisical run --env=prod -- npm start",
            "infisical secrets set API_KEY=new-value",
            "infisical secrets delete OLD_KEY",
            "infisical secrets folders get --path=/apps",
            "op run -- node server.js",
            "op item list --vault Production",
            "doppler run -- npm start",
            "vault kv put secret/prod/api value=rotated",
            "aws secretsmanager describe-secret --secret-id prod/api",
            "aws ssm get-parameter --name /public/config",
        ] {
            assert_no_match(&pack, command);
        }
    }

    #[test]
    fn provider_read_is_allowed_until_disclosure_pack_is_enabled() {
        let command = "infisical secrets get API_KEY --plain";
        let provider_category = HashSet::from(["secrets".to_string()]);
        assert!(
            !REGISTRY.check_command(command, &provider_category).blocked,
            "enabling the provider category must not silently enable disclosure policy"
        );

        let provider_only = HashSet::from(["secrets.infisical".to_string()]);
        assert!(!REGISTRY.check_command(command, &provider_only).blocked);

        let disclosure_enabled = HashSet::from([
            "secrets.infisical".to_string(),
            "secret_disclosure".to_string(),
        ]);
        let result = REGISTRY.check_command(command, &disclosure_enabled);
        assert!(result.blocked);
        assert_eq!(result.pack_id.as_deref(), Some("secret_disclosure"));
        assert_eq!(
            result.pattern_name.as_deref(),
            Some("infisical-secrets-get-output")
        );
    }

    #[test]
    fn quoted_command_examples_are_not_treated_as_invocations() {
        let pack = create_pack();
        for command in [
            "echo 'op read op://prod/api/key'",
            "printf '%s' 'infisical secrets get API_KEY'",
            "command -v vault",
        ] {
            assert_no_match(&pack, command);
        }
    }
}
