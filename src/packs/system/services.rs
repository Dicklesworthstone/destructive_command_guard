//! Services patterns - protections against dangerous service operations.
//!
//! This includes patterns for:
//! - systemctl stop/disable on critical services
//! - service stop on critical services
//! - init system modifications

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Services pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "system.services".to_string(),
        name: "Services",
        description: "Protects against dangerous service operations like stopping critical \
                      services and modifying init configuration",
        keywords: &[
            "systemctl",
            "service",
            "init",
            "upstart",
            "shutdown",
            "reboot",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // status commands are safe
        safe_pattern!("systemctl-status", r"systemctl\s+status"),
        safe_pattern!("service-status", r"service\s+\S+\s+status"),
        // list commands are safe
        safe_pattern!(
            "systemctl-list",
            r"systemctl\s+list-(?:units|unit-files|sockets|timers)"
        ),
        // show is safe
        safe_pattern!("systemctl-show", r"systemctl\s+show"),
        // is-active/is-enabled are safe
        safe_pattern!("systemctl-is", r"systemctl\s+is-(?:active|enabled|failed)"),
        // daemon-reload is generally safe
        safe_pattern!("systemctl-reload", r"systemctl\s+daemon-reload"),
        // cat is safe (view unit file)
        safe_pattern!("systemctl-cat", r"systemctl\s+cat"),
        // journalctl is safe (logs)
        safe_pattern!("journalctl", r"\bjournalctl\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // systemctl stop/disable critical services
        destructive_pattern!(
            "systemctl-stop-critical",
            r"systemctl\s+(?:stop|disable|mask)\s+(?:ssh|sshd|network|networking|firewalld|ufw|docker|containerd)",
            "Stopping/disabling critical services can cause system access loss or outage."
        ),
        // systemctl stop/disable any service
        destructive_pattern!(
            "systemctl-stop",
            r"systemctl\s+(?:stop|disable|mask)\b",
            "systemctl stop/disable/mask affects service availability. Verify service name."
        ),
        // service stop critical
        destructive_pattern!(
            "service-stop-critical",
            r"service\s+(?:ssh|sshd|network|networking|docker)\s+stop",
            "Stopping critical services can cause system access loss."
        ),
        // systemctl isolate (changes runlevel)
        destructive_pattern!(
            "systemctl-isolate",
            r"systemctl\s+isolate",
            "systemctl isolate changes the system state significantly."
        ),
        // systemctl poweroff/reboot/halt
        destructive_pattern!(
            "systemctl-power",
            r"systemctl\s+(?:poweroff|reboot|halt|suspend|hibernate)",
            "systemctl poweroff/reboot/halt will shut down or restart the system."
        ),
        // shutdown command
        destructive_pattern!(
            "shutdown",
            r"\bshutdown\b",
            "shutdown will power off or restart the system."
        ),
        // reboot command
        destructive_pattern!("reboot", r"\breboot\b", "reboot will restart the system."),
        // init 0/6 (shutdown/reboot)
        destructive_pattern!(
            "init-level",
            r"\binit\s+[06]\b",
            "init 0 shuts down, init 6 reboots the system."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_is_reachable_via_keywords() {
        let pack = create_pack();
        assert!(
            pack.might_match("shutdown -h now"),
            "shutdown should be included in pack keywords to prevent false negatives"
        );
        let matched = pack
            .check("shutdown -h now")
            .expect("shutdown should be blocked by services pack");
        assert_eq!(matched.name, Some("shutdown"));
    }

    #[test]
    fn reboot_is_reachable_via_keywords() {
        let pack = create_pack();
        assert!(
            pack.might_match("reboot"),
            "reboot should be included in pack keywords to prevent false negatives"
        );
        let matched = pack
            .check("reboot")
            .expect("reboot should be blocked by services pack");
        assert_eq!(matched.name, Some("reboot"));
    }

    #[test]
    fn keyword_absent_skips_pack() {
        let pack = create_pack();
        assert!(!pack.might_match("echo hello"));
        assert!(pack.check("echo hello").is_none());
    }
}
