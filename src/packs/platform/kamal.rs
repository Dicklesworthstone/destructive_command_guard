//! Kamal deploy pack - protections for destructive Kamal 2.x CLI operations.
//!
//! Kamal (kamal-deploy.org) is a Docker-based deploy tool: an app container,
//! a long-lived `kamal-proxy`, and stateful accessories (Postgres/Redis/search).
//! Its destructive surface is concentrated in the `remove` / `reboot` / `stop` /
//! `prune` subcommands.
//!
//! Confirmation behavior is not uniform: `kamal remove` documents a `-y`/`--yes`
//! skip flag and `kamal proxy reboot` prompts, but the other teardown subcommands
//! don't surface their own prompt, so for a non-interactive agent there is often no
//! built-in safety net at all. That makes these exactly the commands a guard should
//! intercept.
//!
//! Severity tiers:
//! - **Critical** (irreversible data loss / full teardown): `kamal remove`,
//!   `kamal accessory remove [NAME|all]` (deletes the host data directory).
//! - **High** (prod down / routing dropped, recoverable in principle):
//!   `kamal app remove|stop`, `kamal proxy remove|reboot|stop`,
//!   `kamal accessory reboot|stop`.
//! - **Medium** (cleanup that erodes rollback safety): `kamal prune all|containers|images`.
//!
//! Read-only inspection, deploy/redeploy/setup/build, reversible lifecycle
//! (`boot`/`start`/`restart`, `maintenance`/`live`), `rollback`, `upgrade`,
//! registry login/logout, lock, and meta commands are whitelisted.

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

// Fragment matching `kamal` followed by optional global flags (e.g. `-d staging`,
// `-c config/deploy.yml`, `--version`), up to a subcommand token. Mirrors the
// railway pack's flag-skipping prefix so options between `kamal` and the verb
// don't defeat the match.
const STATUS_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kamal details",
        "Show the current containers across servers before tearing anything down",
    ),
    PatternSuggestion::new(
        "kamal config",
        "Confirm which destination/servers the command targets (mind that config prints secrets)",
    ),
];

const ACCESSORY_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kamal accessory details",
        "Inspect the accessory (e.g. the database) without removing or stopping it",
    ),
    PatternSuggestion::new(
        "kamal accessory logs",
        "Read accessory logs instead of restarting or removing the container",
    ),
];

const PROXY_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kamal proxy details",
        "Inspect the proxy without removing or rebooting it",
    ),
    PatternSuggestion::new(
        "kamal proxy restart",
        "Cycle the existing proxy without removing it, where a restart suffices",
    ),
    PatternSuggestion::gated(
        "kamal proxy reboot --rolling",
        "If a proxy cycle is truly required, --rolling staggers it to reduce the outage",
    ),
];

const APP_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kamal app details",
        "Inspect app containers without removing or stopping them",
    ),
    PatternSuggestion::new(
        "kamal app maintenance",
        "Serve a 503 maintenance page (reversible with `kamal app live`) instead of stopping",
    ),
];

const PRUNE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "kamal app containers",
        "List the deployed containers/images that rollback relies on before pruning",
    ),
    PatternSuggestion::new(
        "kamal rollback [VERSION]",
        "Pruning removes older images `kamal rollback` needs; confirm a rollback target still exists",
    ),
];

/// Create the Kamal deploy pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.kamal".to_string(),
        name: "Kamal",
        description: "Protects against destructive Kamal 2.x operations that tear down the stack, \
                      delete accessory data directories, drop proxy routing, take the app offline, \
                      or prune the images that rollback depends on.",
        keywords: &["kamal"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // --- Top-level inspection (read-only) ---
        safe_pattern!(
            "kamal-audit",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-details",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+details(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-config",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-secrets",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets(?:\s|$)"
        ),
        // --- Deploy / lifecycle (creates or refreshes; not destructive) ---
        safe_pattern!(
            "kamal-deploy",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+deploy(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-redeploy",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+redeploy(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-setup",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+setup(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-build",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-rollback",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+rollback(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-upgrade",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+upgrade(?:\s|$)"
        ),
        // --- Registry / lock / server bootstrap / meta ---
        safe_pattern!(
            "kamal-registry",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+registry\s+(?:login|logout)(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-lock",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+lock(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-server-bootstrap",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+server\s+bootstrap(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-init",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+init(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-docs",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+docs(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-help",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+help(?:\s|$)"
        ),
        safe_pattern!(
            "kamal-version",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?:\s|$)"
        ),
        // --- app: inspection + reversible lifecycle ---
        safe_pattern!(
            "kamal-app-safe",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+app(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot|start|restart|details|containers|images|logs|version|stale_containers|maintenance|live)(?:\s|$)"
        ),
        // --- accessory: inspection + reversible lifecycle (restart is safe; reboot is NOT) ---
        safe_pattern!(
            "kamal-accessory-safe",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot|start|restart|details|logs|upgrade)(?:\s|$)"
        ),
        // --- proxy: inspection + reversible lifecycle (reboot/stop/remove are NOT here) ---
        safe_pattern!(
            "kamal-proxy-safe",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot|boot_config|start|restart|details|logs)(?:\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // === Critical: irreversible data loss / full teardown ===
        destructive_pattern!(
            "kamal-remove",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)",
            "kamal remove tears down the entire deployment, including stateful accessories.",
            Critical,
            "`kamal remove` removes the app container, kamal-proxy, and all accessory containers \
             from the servers and logs out of the registry. Because it removes accessories, it can \
             destroy stateful services (Postgres/Redis/search) along with the rest of the stack. \
             It accepts `-y`/`--yes` to skip the confirmation prompt, so a non-interactive agent \
             run has no safety net. A wrong destination (e.g. a missing `-d staging` while the \
             shell points at production) tears down prod.\n\n\
             Safer alternatives:\n\
             - kamal details: review what is actually deployed first\n\
             - kamal app remove / kamal proxy remove: scope the teardown if that is the real intent\n\
             - Always pass the explicit destination (e.g. -d staging) and confirm it",
            STATUS_SUGGESTIONS
        ),
        destructive_pattern!(
            "kamal-accessory-remove",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)",
            "kamal accessory remove deletes the accessory container, image, AND its host data directory.",
            Critical,
            "`kamal accessory remove [NAME]` removes the accessory container and image and ALSO \
             deletes its data directory from the host. For a database/redis/search accessory this \
             permanently destroys the data. `kamal accessory remove all` does this across every \
             accessory at once (highest blast radius). The common mistake is meaning the YAML block \
             in deploy.yml, not the live Postgres/Redis data on disk.\n\n\
             Safer alternatives:\n\
             - Edit the accessory block out of deploy.yml instead of deleting live data\n\
             - kamal accessory stop: take it offline reversibly (data preserved)\n\
             - Back up the data directory / take a database dump before any removal",
            ACCESSORY_SUGGESTIONS
        ),
        // === High: prod down / routing dropped (recoverable in principle) ===
        destructive_pattern!(
            "kamal-app-remove",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+app(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)",
            "kamal app remove takes the app offline by removing its containers and images.",
            High,
            "`kamal app remove` removes the app containers and images from the servers. The app goes \
             offline and the images must be rebuilt or re-pulled before it can serve again. This is \
             a frequent footgun when asked to \"clean up old containers\".\n\n\
             Safer alternatives:\n\
             - kamal app stale_containers: list leftover containers without removing the live app\n\
             - kamal prune: remove genuinely old images/containers (still erodes rollback)\n\
             - kamal app maintenance: serve a 503 reversibly instead of removing",
            APP_SUGGESTIONS
        ),
        destructive_pattern!(
            "kamal-app-stop",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+app(?:\s+--?\S+(?:\s+\S+)?)*\s+stop(?:\s|$)",
            "kamal app stop stops the app container, causing an outage until restarted.",
            High,
            "`kamal app stop` stops the app container on the servers, causing an outage until \
             `kamal app start`. There is no built-in confirmation prompt.\n\n\
             Safer alternatives:\n\
             - kamal app maintenance: serve a 503 maintenance page (reversible with kamal app live)\n\
             - kamal app details: confirm the target before stopping anything",
            APP_SUGGESTIONS
        ),
        destructive_pattern!(
            "kamal-proxy-remove",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)",
            "kamal proxy remove drops routing for every app behind that proxy on the host.",
            High,
            "`kamal proxy remove` removes the kamal-proxy container and image. Every app behind that \
             proxy on the host loses routing until the proxy is re-booted. There is no confirmation \
             prompt for `remove`.\n\n\
             Safer alternatives:\n\
             - kamal proxy details / kamal proxy logs: diagnose the proxy without removing it\n\
             - kamal proxy reboot --rolling: if a cycle is required, stagger it to limit the \
             outage (dcg gates proxy reboots too, so this form still needs approval)",
            PROXY_SUGGESTIONS
        ),
        destructive_pattern!(
            "kamal-proxy-reboot",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+reboot(?:\s|$)",
            "kamal proxy reboot stops, removes, and recreates the proxy, causing a short outage.",
            High,
            "`kamal proxy reboot` stops, removes, and starts a new proxy container. It is documented \
             to cause a small outage on each server. While it prompts interactively, a non-interactive \
             agent run with `-y` skips that prompt.\n\n\
             Safer alternatives:\n\
             - kamal proxy restart: a lighter restart of the existing proxy where applicable\n\
             - kamal proxy reboot --rolling: stagger the restart across servers to reduce the \
             outage (still a reboot, so dcg gates this form too — it needs approval)",
            PROXY_SUGGESTIONS
        ),
        destructive_pattern!(
            "kamal-proxy-stop",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+stop(?:\s|$)",
            "kamal proxy stop drops routing for every app behind that proxy until it is started.",
            High,
            "`kamal proxy stop` stops the kamal-proxy container. Every app behind that proxy on the \
             host loses routing until `kamal proxy start`/`boot`.\n\n\
             Safer alternatives:\n\
             - kamal proxy details: confirm what the proxy is serving before stopping it\n\
             - kamal proxy restart: cycle the proxy without leaving it down",
            PROXY_SUGGESTIONS
        ),
        destructive_pattern!(
            "kamal-accessory-reboot",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+reboot(?:\s|$)",
            "kamal accessory reboot stops, removes, and recreates the accessory container (downtime).",
            High,
            "`kamal accessory reboot [NAME]` stops, removes, and starts a new accessory container, \
             causing downtime for that accessory (e.g. the database). Data survives only if a volume \
             is mapped; an unmapped data directory is at risk. `NAME=all` reboots every accessory.\n\n\
             Safer alternatives:\n\
             - kamal accessory restart: restart the existing container without remove/recreate\n\
             - kamal accessory details: confirm the target accessory before cycling it",
            ACCESSORY_SUGGESTIONS
        ),
        destructive_pattern!(
            "kamal-accessory-stop",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+stop(?:\s|$)",
            "kamal accessory stop stops the accessory (e.g. the database), erroring the app.",
            High,
            "`kamal accessory stop [NAME]` stops the accessory container. Stopping the database (or \
             cache/search) errors the app until the accessory is restarted, knocking a dependency \
             offline mid-traffic.\n\n\
             Safer alternatives:\n\
             - kamal accessory restart: cycle it without leaving it stopped\n\
             - kamal accessory details / kamal accessory logs: diagnose without stopping",
            ACCESSORY_SUGGESTIONS
        ),
        // === Medium: cleanup that erodes rollback safety ===
        destructive_pattern!(
            "kamal-prune",
            r"(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+prune(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:all|containers|images)(?:\s|$)",
            "kamal prune removes older images/containers that kamal rollback relies on.",
            Medium,
            "`kamal prune all` prunes unused images and stopped containers, `kamal prune containers` \
             prunes stopped containers except the last n (default 5), and `kamal prune images` prunes \
             unused images. Kamal's `rollback` relies on the older deployed images/containers, so \
             over-pruning can strand a deployment with no rollback target.\n\n\
             Safer alternatives:\n\
             - kamal app containers / kamal app images: see what would be removed first\n\
             - Confirm a known-good rollback target exists before pruning",
            PRUNE_SUGGESTIONS
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
        assert_eq!(pack.id, "platform.kamal");
        assert_eq!(pack.name, "Kamal");
        assert!(pack.keywords.contains(&"kamal"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn blocks_critical_data_loss_commands() {
        let pack = create_pack();
        let checks = [
            ("kamal remove", "kamal-remove"),
            ("/usr/bin/kamal remove", "kamal-remove"),
            ("kamal remove -y", "kamal-remove"),
            ("kamal remove --yes -d production", "kamal-remove"),
            ("kamal -d staging remove -y", "kamal-remove"),
            ("kamal accessory remove db", "kamal-accessory-remove"),
            ("kamal accessory remove all", "kamal-accessory-remove"),
            ("kamal accessory remove db -y", "kamal-accessory-remove"),
            (
                "kamal -d production accessory remove db",
                "kamal-accessory-remove",
            ),
        ];
        for (command, expected_pattern) in checks {
            assert_blocks_with_pattern(&pack, command, expected_pattern);
        }
        for (command, _) in checks {
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_high_outage_commands() {
        let pack = create_pack();
        let checks = [
            ("kamal app remove", "kamal-app-remove"),
            ("kamal app stop", "kamal-app-stop"),
            ("kamal -d prod app stop", "kamal-app-stop"),
            ("kamal proxy remove", "kamal-proxy-remove"),
            ("kamal proxy reboot", "kamal-proxy-reboot"),
            ("kamal proxy reboot -y", "kamal-proxy-reboot"),
            ("kamal proxy stop", "kamal-proxy-stop"),
            ("kamal accessory reboot db", "kamal-accessory-reboot"),
            ("kamal accessory reboot all", "kamal-accessory-reboot"),
            ("kamal accessory stop db", "kamal-accessory-stop"),
        ];
        for (command, expected_pattern) in checks {
            assert_blocks_with_pattern(&pack, command, expected_pattern);
        }
        for (command, _) in checks {
            assert_blocks_with_severity(&pack, command, Severity::High);
        }
    }

    #[test]
    fn blocks_medium_prune_commands() {
        let pack = create_pack();
        let checks = [
            ("kamal prune all", "kamal-prune"),
            ("kamal prune containers", "kamal-prune"),
            ("kamal prune images", "kamal-prune"),
            ("kamal -d staging prune all", "kamal-prune"),
        ];
        for (command, expected_pattern) in checks {
            assert_blocks_with_pattern(&pack, command, expected_pattern);
        }
        for (command, _) in checks {
            assert_blocks_with_severity(&pack, command, Severity::Medium);
        }
    }

    #[test]
    fn allows_inspection_and_deploy_commands() {
        let pack = create_pack();
        assert_allows(&pack, "kamal audit");
        assert_allows(&pack, "kamal details");
        assert_allows(&pack, "kamal config");
        assert_allows(&pack, "kamal secrets print");
        assert_allows(&pack, "kamal deploy");
        assert_allows(&pack, "kamal redeploy");
        assert_allows(&pack, "kamal -d staging deploy");
        assert_allows(&pack, "kamal setup");
        assert_allows(&pack, "kamal build push");
        assert_allows(&pack, "kamal rollback 0123456789abcdef");
        assert_allows(&pack, "kamal upgrade");
        assert_allows(&pack, "kamal registry login");
        assert_allows(&pack, "kamal registry logout");
        assert_allows(&pack, "kamal lock status");
        assert_allows(&pack, "kamal lock release");
        assert_allows(&pack, "kamal server bootstrap");
        assert_allows(&pack, "kamal init");
        assert_allows(&pack, "kamal docs configuration");
        assert_allows(&pack, "kamal help remove");
        assert_allows(&pack, "kamal version");
    }

    #[test]
    fn allows_reversible_lifecycle_commands() {
        let pack = create_pack();
        // app
        assert_allows(&pack, "kamal app boot");
        assert_allows(&pack, "kamal app start");
        assert_allows(&pack, "kamal app details");
        assert_allows(&pack, "kamal app containers");
        assert_allows(&pack, "kamal app images");
        assert_allows(&pack, "kamal app logs");
        assert_allows(&pack, "kamal app version");
        assert_allows(&pack, "kamal app stale_containers");
        assert_allows(&pack, "kamal app maintenance");
        assert_allows(&pack, "kamal app live");
        assert_allows(&pack, "kamal -d prod app boot");
        // accessory: restart is safe even though reboot/stop/remove are not
        assert_allows(&pack, "kamal accessory boot db");
        assert_allows(&pack, "kamal accessory start db");
        assert_allows(&pack, "kamal accessory restart db");
        assert_allows(&pack, "kamal accessory details db");
        assert_allows(&pack, "kamal accessory logs db");
        assert_allows(&pack, "kamal accessory upgrade db");
        // proxy: boot/start/restart/details/logs are safe
        assert_allows(&pack, "kamal proxy boot");
        assert_allows(&pack, "kamal proxy boot_config get");
        assert_allows(&pack, "kamal proxy start");
        assert_allows(&pack, "kamal proxy restart");
        assert_allows(&pack, "kamal proxy details");
        assert_allows(&pack, "kamal proxy logs");
    }

    #[test]
    fn does_not_confuse_safe_lookalikes_with_destructive() {
        let pack = create_pack();
        // restart must NOT trip the reboot/stop patterns
        assert_allows(&pack, "kamal accessory restart db");
        assert_allows(&pack, "kamal proxy restart");
        // boot must NOT trip the remove pattern
        assert_allows(&pack, "kamal app boot");
        assert_allows(&pack, "kamal proxy boot");
        // these MUST still block
        assert_blocks_with_pattern(&pack, "kamal accessory reboot db", "kamal-accessory-reboot");
        assert_blocks_with_pattern(&pack, "kamal app remove", "kamal-app-remove");
        assert_blocks_with_pattern(&pack, "kamal proxy remove", "kamal-proxy-remove");
    }

    #[test]
    fn safe_segment_does_not_mask_later_destructive() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "kamal app details && kamal accessory remove db",
            "kamal-accessory-remove",
        );
        assert_blocks_with_pattern(&pack, "kamal config | kamal remove -y", "kamal-remove");
        assert_blocks_with_pattern(
            &pack,
            "kamal deploy ; kamal proxy reboot",
            "kamal-proxy-reboot",
        );
    }

    #[test]
    fn ignores_unrelated_commands() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "docker ps");
        assert_no_match(&pack, "notkamal remove");
        assert_no_match(&pack, "my-kamal accessory remove db");
        assert_no_match(&pack, "akamal proxy stop");
    }
}
