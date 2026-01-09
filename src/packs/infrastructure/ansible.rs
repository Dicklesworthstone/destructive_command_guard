//! Ansible patterns - protections against destructive ansible commands.
//!
//! This includes patterns for:
//! - ansible-playbook with dangerous patterns
//! - ansible with shell/command modules doing destructive things

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Ansible pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "infrastructure.ansible".to_string(),
        name: "Ansible",
        description: "Protects against destructive Ansible operations like dangerous shell \
                      commands and unchecked playbook runs",
        keywords: &["ansible", "playbook"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // --check is dry-run mode (safe)
        safe_pattern!("ansible-check", r"ansible(?:-playbook)?\s+.*--check"),
        // --diff shows changes (safe)
        safe_pattern!("ansible-diff", r"ansible(?:-playbook)?\s+.*--diff"),
        // --list-hosts just lists (safe)
        safe_pattern!(
            "ansible-list-hosts",
            r"ansible(?:-playbook)?\s+.*--list-hosts"
        ),
        // --list-tasks just lists (safe)
        safe_pattern!(
            "ansible-list-tasks",
            r"ansible(?:-playbook)?\s+.*--list-tasks"
        ),
        // --syntax-check is safe
        safe_pattern!(
            "ansible-syntax",
            r"ansible(?:-playbook)?\s+.*--syntax-check"
        ),
        // ansible-inventory is safe
        safe_pattern!("ansible-inventory", r"ansible-inventory"),
        // ansible-doc is safe
        safe_pattern!("ansible-doc", r"ansible-doc"),
        // ansible-config is safe
        safe_pattern!("ansible-config", r"ansible-config"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ansible with rm -rf in command
        destructive_pattern!(
            "shell-rm-rf",
            r"ansible\s+.*-m\s+(?:shell|command)\s+.*rm\s+-rf",
            "Ansible shell/command with 'rm -rf' is destructive. Review carefully."
        ),
        // ansible with reboot
        destructive_pattern!(
            "shell-reboot",
            r"ansible\s+.*-m\s+(?:shell|command)\s+.*(?:reboot|shutdown|poweroff)",
            "Ansible shell/command with reboot/shutdown affects system availability."
        ),
        // ansible-playbook targeting all hosts without limit
        destructive_pattern!(
            "playbook-all-hosts",
            r"ansible-playbook\s+(?!.*(?:--check|--limit|--diff)).*-i\s+\S+\s+\S+\.ya?ml",
            "ansible-playbook without --check or --limit may affect all hosts. Use --check first."
        ),
        // ansible with -e that might contain dangerous variables
        destructive_pattern!(
            "extra-vars-delete",
            r#"ansible\s+.*-e\s+['\"].*(?:delete|remove|destroy|drop)"#,
            "Ansible extra-vars contains potentially destructive keywords. Review carefully."
        ),
    ]
}
