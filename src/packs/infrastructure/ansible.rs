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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
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
            "Ansible shell/command with 'rm -rf' is destructive. Review carefully.",
            Critical,
            "Running 'rm -rf' via Ansible shell or command module executes destructive deletion \
             across all targeted hosts simultaneously. This multiplies the impact compared to \
             running it locally:\n\n\
             - Files deleted on every host in inventory or pattern\n\
             - No confirmation or dry-run by default\n\
             - Parallel execution means rapid, widespread destruction\n\
             - Cannot be undone without backups on each host\n\n\
             Safer alternatives:\n\
             - Use file module with state=absent for managed deletion\n\
             - Add --check flag to preview which hosts would be affected\n\
             - Use --limit to restrict to specific hosts first\n\
             - Verify target path with debug module before deletion"
        ),
        // ansible with reboot
        destructive_pattern!(
            "shell-reboot",
            r"ansible\s+.*-m\s+(?:shell|command)\s+.*(?:reboot|shutdown|poweroff)",
            "Ansible shell/command with reboot/shutdown affects system availability.",
            High,
            "Rebooting or shutting down systems via Ansible affects all targeted hosts at once. \
             This can cause service outages across your infrastructure:\n\n\
             - All services on affected hosts become unavailable\n\
             - No graceful draining of connections or traffic\n\
             - Database transactions may be interrupted\n\
             - Load balancer health checks will fail\n\n\
             Safer alternatives:\n\
             - Use the reboot module which handles wait_for_connection\n\
             - Add serial: 1 to playbook for rolling reboots\n\
             - Use --limit to test on single host first\n\
             - Coordinate with maintenance windows"
        ),
        // ansible-playbook targeting all hosts without limit
        destructive_pattern!(
            "playbook-all-hosts",
            r"ansible-playbook\s+(?!.*(?:--check|--limit|--diff)).*-i\s+\S+\s+\S+\.ya?ml",
            "ansible-playbook without --check or --limit may affect all hosts. Use --check first.",
            High,
            "Running ansible-playbook without --check or --limit applies changes to all hosts in \
             the inventory. This is risky for destructive playbooks:\n\n\
             - Every host matching the play's pattern is affected\n\
             - Mistakes propagate to entire infrastructure at once\n\
             - No opportunity to verify changes before they're applied\n\
             - Rollback may be difficult or impossible\n\n\
             Safer alternatives:\n\
             - Add --check --diff to preview changes\n\
             - Use --limit host1,host2 to test on subset\n\
             - Add serial: 1 to playbook for rolling updates\n\
             - Review the playbook tasks before running"
        ),
        // ansible with -e that might contain dangerous variables
        destructive_pattern!(
            "extra-vars-delete",
            r#"ansible\s+.*-e\s+['\"].*(?:delete|remove|destroy|drop)"#,
            "Ansible extra-vars contains potentially destructive keywords. Review carefully.",
            Medium,
            "Extra variables containing destructive keywords like 'delete', 'remove', 'destroy', \
             or 'drop' may trigger conditional destructive actions in playbooks:\n\n\
             - Variables may control whether resources are deleted\n\
             - Typos in variable values could trigger unintended paths\n\
             - Variable precedence may override safer defaults\n\n\
             Safer alternatives:\n\
             - Review playbook to understand how variables are used\n\
             - Add --check to see what tasks would run\n\
             - Use --limit to test on single host first\n\
             - Consider using vault-encrypted vars for destructive flags"
        ),
    ]
}
