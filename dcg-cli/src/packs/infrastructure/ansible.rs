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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Safe Ansible modes are only safe for the current shell command
        // segment. Since safe patterns run before destructive patterns, keep
        // them bounded so `ansible-playbook --check ...; ansible ... rm -rf`
        // cannot make the whole compound command safe.
        safe_pattern!(
            "ansible-check",
            r"ansible(?:-playbook)?\b[^\n;&|]*--check(?:\s|$)[^\n;&|]*$"
        ),
        // --list-hosts just lists (safe)
        safe_pattern!(
            "ansible-list-hosts",
            r"ansible(?:-playbook)?\b[^\n;&|]*--list-hosts(?:\s|$)[^\n;&|]*$"
        ),
        // --list-tasks just lists (safe)
        safe_pattern!(
            "ansible-list-tasks",
            r"ansible(?:-playbook)?\b[^\n;&|]*--list-tasks(?:\s|$)[^\n;&|]*$"
        ),
        // --syntax-check is safe
        safe_pattern!(
            "ansible-syntax",
            r"ansible(?:-playbook)?\b[^\n;&|]*--syntax-check(?:\s|$)[^\n;&|]*$"
        ),
        // ansible-inventory is safe
        safe_pattern!("ansible-inventory", r"ansible-inventory\b[^\n;&|]*$"),
        // ansible-doc is safe
        safe_pattern!("ansible-doc", r"ansible-doc\b[^\n;&|]*$"),
        // ansible-config is safe
        safe_pattern!("ansible-config", r"ansible-config\b[^\n;&|]*$"),
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
            r"ansible-playbook\s+(?!.*(?:--check(?:\s|$)|--limit)).*-i\s+\S+\s+\S+\.ya?ml",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn ansible_safe_dry_run_modes() {
        let pack = create_pack();
        assert_allows(&pack, "ansible --check -i inventory.ini all -m ping");
        assert_allows(&pack, "ansible-playbook --check deploy.yml");
        assert_allows(&pack, "ansible-playbook --check --diff site.yml");
        assert_allows(&pack, "ansible-playbook --list-hosts site.yml");
        assert_allows(&pack, "ansible-playbook --list-tasks site.yml");
        assert_allows(&pack, "ansible-playbook --syntax-check site.yml");
    }

    #[test]
    fn ansible_safe_info_commands() {
        let pack = create_pack();
        assert_allows(&pack, "ansible-inventory --list");
        assert_allows(&pack, "ansible-doc file");
        assert_allows(&pack, "ansible-config dump");
    }

    #[test]
    fn ansible_blocks_shell_rm_rf() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "ansible all -m shell -a 'rm -rf /var/data'",
            "rm -rf",
        );
        assert_blocks(
            &pack,
            "ansible webservers -m command -a 'rm -rf /tmp/cache'",
            "rm -rf",
        );
    }

    #[test]
    fn ansible_blocks_shell_reboot_shutdown() {
        let pack = create_pack();
        assert_blocks(&pack, "ansible all -m shell -a 'reboot'", "reboot");
        assert_blocks(
            &pack,
            "ansible dbservers -m command -a 'shutdown -h now'",
            "shutdown",
        );
        assert_blocks(
            &pack,
            "ansible all -m shell -a 'poweroff'",
            "reboot/shutdown",
        );
    }

    #[test]
    fn ansible_blocks_playbook_without_check_or_limit() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "ansible-playbook -i production deploy.yml",
            "without --check or --limit",
        );
    }

    #[test]
    fn ansible_allows_playbook_with_check_or_limit() {
        let pack = create_pack();
        assert_allows(&pack, "ansible-playbook --check -i production deploy.yml");
        assert_allows(
            &pack,
            "ansible-playbook --limit web1 -i production deploy.yml",
        );
    }

    #[test]
    fn ansible_diff_alone_does_not_suppress_destructive_patterns() {
        let pack = create_pack();

        assert_no_safe_match(&pack, "ansible-playbook --diff -i production deploy.yml");
        assert_blocks_with_pattern(
            &pack,
            "ansible-playbook --diff -i production deploy.yml",
            "playbook-all-hosts",
        );
        assert_no_safe_match(&pack, "ansible all --diff -m shell -a 'reboot'");
        assert_blocks_with_pattern(
            &pack,
            "ansible all --diff -m shell -a 'reboot'",
            "shell-reboot",
        );
        assert_no_safe_match(&pack, r"ansible all --diff -e 'action=delete' -m debug");
        assert_blocks_with_pattern(
            &pack,
            r"ansible all --diff -e 'action=delete' -m debug",
            "extra-vars-delete",
        );
    }

    #[test]
    fn ansible_safe_modes_do_not_allow_compound_destructive_commands() {
        let pack = create_pack();

        let checked_then_destructive =
            "ansible-playbook --check site.yml; ansible all -m shell -a 'rm -rf /data'";
        assert_no_safe_match(&pack, checked_then_destructive);
        assert_blocks_with_pattern(&pack, checked_then_destructive, "shell-rm-rf");

        let inventory_then_destructive =
            "ansible-inventory --list && ansible all -m shell -a 'reboot'";
        assert_no_safe_match(&pack, inventory_then_destructive);
        assert_blocks_with_pattern(&pack, inventory_then_destructive, "shell-reboot");
    }

    #[test]
    fn ansible_blocks_extra_vars_destructive_keywords() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            r"ansible all -e 'action=delete' -m shell -a 'echo hi'",
            "destructive keywords",
        );
        assert_blocks(
            &pack,
            r#"ansible all -e "state=destroy" -m debug"#,
            "destructive keywords",
        );
    }

    #[test]
    fn ansible_allows_benign_extra_vars() {
        let pack = create_pack();
        assert_allows(
            &pack,
            "ansible all -e 'version=1.2.3' -m debug -a 'var=version'",
        );
    }

    #[test]
    fn ansible_safe_check_overrides_destructive() {
        let pack = create_pack();
        assert_allows(&pack, "ansible all --check -m shell -a 'rm -rf /data'");
    }
}
