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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // systemctl supports global flags before the verb:
    //   systemctl -H remote-host status sshd
    //   systemctl --user status my-service
    //   systemctl -M machine list-units
    // Use `systemctl\b.*?\s+<verb>(?=\s|$)` so those flag-positions don't
    // bypass AND unit names containing the verb keyword as a substring
    // (e.g. `systemctl stop status-monitor.service`) don't short-circuit
    // destructive ops via the safe pattern.
    vec![
        // status commands are safe
        safe_pattern!(
            "systemctl-status",
            r"systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s|$)"
        ),
        safe_pattern!("service-status", r"service\s+\S+\s+status(?=\s|$)"),
        // list commands are safe
        safe_pattern!(
            "systemctl-list",
            r"systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+list-(?:units|unit-files|sockets|timers)(?=\s|$)"
        ),
        // show is safe
        safe_pattern!(
            "systemctl-show",
            r"systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)"
        ),
        // is-active/is-enabled are safe
        safe_pattern!(
            "systemctl-is",
            r"systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+is-(?:active|enabled|failed)(?=\s|$)"
        ),
        // daemon-reload is generally safe
        safe_pattern!(
            "systemctl-reload",
            r"systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+daemon-reload(?=\s|$)"
        ),
        // cat is safe (view unit file)
        safe_pattern!(
            "systemctl-cat",
            r"systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cat(?=\s|$)"
        ),
        // journalctl is safe (logs)
        safe_pattern!("journalctl", r"\bjournalctl\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // systemctl stop/disable critical services
        destructive_pattern!(
            "systemctl-stop-critical",
            r"systemctl\b.*?\s+(?:stop|disable|mask)\s+(?:ssh|sshd|network|networking|firewalld|ufw|docker|containerd)\b",
            "Stopping/disabling critical services can cause system access loss or outage.",
            High,
            "Stopping, disabling, or masking a critical system service can lock you out \
             of the machine or cause cascading failures. For example, stopping sshd severs \
             remote access, stopping networking drops all connections, and stopping docker \
             kills every running container.\n\n\
             Check current state first:\n  \
             systemctl status <service>\n\n\
             If you need to restart rather than stop:\n  \
             systemctl restart <service>"
        ),
        // systemctl stop/disable any service
        destructive_pattern!(
            "systemctl-stop",
            r"systemctl\b.*?\s+(?:stop|disable|mask)\b",
            "systemctl stop/disable/mask affects service availability. Verify service name.",
            High,
            "Stopping a service immediately terminates it; disabling prevents it from \
             starting at boot; masking makes it impossible to start even manually. Each \
             has different severity and reversibility.\n\n\
             Check what depends on the service:\n  \
             systemctl list-dependencies --reverse <service>\n\n\
             To temporarily stop without disabling:\n  \
             systemctl stop <service>  (restarts on reboot)"
        ),
        // service stop critical
        destructive_pattern!(
            "service-stop-critical",
            r"service\s+(?:ssh|sshd|network|networking|docker)\s+stop",
            "Stopping critical services can cause system access loss.",
            High,
            "The legacy 'service' command stops a critical service immediately. Stopping \
             sshd terminates remote access, stopping networking drops all connections. \
             If you are connected remotely, you may be unable to reconnect.\n\n\
             Check status first:\n  \
             service <name> status\n\n\
             Prefer systemctl on systemd systems:\n  \
             systemctl status <name>"
        ),
        // systemctl isolate (changes runlevel)
        destructive_pattern!(
            "systemctl-isolate",
            r"systemctl\b.*?\s+isolate\b",
            "systemctl isolate changes the system state significantly.",
            High,
            "Isolating a target stops all services not required by that target. For \
             example, isolating rescue.target drops to single-user mode, stopping \
             networking, display managers, and most daemons. This is equivalent to \
             changing the runlevel and can be very disruptive.\n\n\
             Check current target:\n  \
             systemctl get-default\n\n\
             List active targets:\n  \
             systemctl list-units --type=target"
        ),
        // systemctl poweroff/reboot/halt
        destructive_pattern!(
            "systemctl-power",
            r"systemctl\b.*?\s+(?:poweroff|reboot|halt|suspend|hibernate)\b",
            "systemctl poweroff/reboot/halt will shut down or restart the system.",
            Critical,
            "This immediately initiates a system power state change. Poweroff and halt \
             shut down the machine, reboot restarts it, and suspend/hibernate save state \
             to RAM or disk. Any unsaved work, running processes, or active connections \
             will be interrupted.\n\n\
             Check who is logged in:\n  \
             who\n\n\
             Schedule a graceful shutdown instead:\n  \
             shutdown +5 \"Rebooting for maintenance\""
        ),
        // shutdown command
        destructive_pattern!(
            "shutdown",
            r"\bshutdown\b",
            "shutdown will power off or restart the system.",
            Critical,
            "The shutdown command powers off or restarts the machine. All running \
             processes receive SIGTERM then SIGKILL, all filesystems are unmounted, \
             and the system goes down. Remote users lose access immediately.\n\n\
             To cancel a pending shutdown:\n  \
             shutdown -c\n\n\
             To schedule with warning:\n  \
             shutdown +10 \"System going down for maintenance\""
        ),
        // reboot command
        destructive_pattern!(
            "reboot",
            r"\breboot\b",
            "reboot will restart the system.",
            Critical,
            "Reboot restarts the machine immediately. All processes are terminated, \
             connections are dropped, and the system goes through a full restart cycle. \
             Any unsaved work is lost and services will be briefly unavailable.\n\n\
             Check uptime and load before deciding:\n  \
             uptime\n\n\
             For a delayed reboot with notice:\n  \
             shutdown -r +5 \"Rebooting in 5 minutes\""
        ),
        // init 0/6 (shutdown/reboot)
        destructive_pattern!(
            "init-level",
            r"\binit\s+[06]\b",
            "init 0 shuts down, init 6 reboots the system.",
            Critical,
            "Changing the init level to 0 halts the system and to 6 reboots it. This \
             is the legacy SysV method for power management and takes effect immediately. \
             All processes are killed and the machine goes down.\n\n\
             On systemd systems, prefer:\n  \
             systemctl poweroff  (instead of init 0)\n  \
             systemctl reboot    (instead of init 6)\n\n\
             Check current runlevel:\n  \
             runlevel"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

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

    #[test]
    fn systemctl_global_flags_do_not_bypass() {
        // systemctl supports -H <host>, -M <machine>, --user, --system
        // before the verb. Old `systemctl\s+<verb>` patterns failed when
        // those flags were present, silently bypassing the guard.
        let pack = create_pack();
        let matched = pack
            .check("systemctl -H remote-host stop sshd")
            .expect("remote host + stop critical should be blocked");
        assert_eq!(matched.name, Some("systemctl-stop-critical"));

        let matched = pack
            .check("systemctl --user disable my-unit")
            .expect("--user + disable should be blocked");
        assert_eq!(matched.name, Some("systemctl-stop"));

        let matched = pack
            .check("systemctl -M machine mask containerd")
            .expect("machine + mask critical should be blocked");
        assert_eq!(matched.name, Some("systemctl-stop-critical"));

        let matched = pack
            .check("systemctl --system poweroff")
            .expect("--system + poweroff should be blocked");
        assert_eq!(matched.name, Some("systemctl-power"));

        let matched = pack
            .check("systemctl -H host isolate rescue.target")
            .expect("host + isolate should be blocked");
        assert_eq!(matched.name, Some("systemctl-isolate"));

        // Safe patterns with global flags should also still short-circuit.
        assert!(
            pack.check("systemctl -H remote-host status sshd").is_none(),
            "status with global flag should be treated as safe"
        );
        assert!(
            pack.check("systemctl --user list-units").is_none(),
            "list-units with --user should be treated as safe"
        );
    }

    #[test]
    fn services_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "systemctl stop sshd", Severity::High);
        assert_blocks_with_severity(&pack, "systemctl disable docker", Severity::High);
        assert_blocks_with_severity(&pack, "systemctl mask networking", Severity::High);
        assert_blocks_with_severity(&pack, "service ssh stop", Severity::High);
        assert_blocks_with_severity(&pack, "systemctl isolate rescue.target", Severity::High);
        assert_blocks_with_severity(&pack, "systemctl poweroff", Severity::Critical);
        assert_blocks_with_severity(&pack, "systemctl reboot", Severity::Critical);
        assert_blocks_with_severity(&pack, "shutdown -h now", Severity::Critical);
        assert_blocks_with_severity(&pack, "reboot", Severity::Critical);
        assert_blocks_with_severity(&pack, "init 0", Severity::Critical);
        assert_blocks_with_severity(&pack, "init 6", Severity::Critical);
    }

    #[test]
    fn services_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}
