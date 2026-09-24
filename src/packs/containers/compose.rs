//! Docker Compose patterns - protections against destructive compose commands.
//!
//! `podman-compose` and `podman compose` implement the same `down`/`rm`
//! interface, so every rule matches all four spellings of the executable.
//!
//! This includes patterns for:
//! - down with volumes flag
//! - rm with volumes
//! - config validation (safe)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Docker Compose pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "containers.compose".to_string(),
        name: "Docker Compose",
        description: "Protects against destructive Docker Compose operations like \
                      'down -v' which removes volumes",
        keywords: &[
            "docker-compose",
            "docker compose",
            "podman-compose",
            "podman compose",
            "compose",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // config validation is safe
        safe_pattern!(
            "compose-config",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+config"
        ),
        // ps is safe (read-only)
        safe_pattern!(
            "compose-ps",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+ps"
        ),
        // logs is safe
        safe_pattern!(
            "compose-logs",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+logs"
        ),
        // up is generally safe (creates)
        safe_pattern!(
            "compose-up",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+up"
        ),
        // build is safe
        safe_pattern!(
            "compose-build",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+build"
        ),
        // pull is safe
        safe_pattern!(
            "compose-pull",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+pull"
        ),
        // down without -v/--rmi is less destructive. The global-option walker
        // skips only *option-like* tokens (`-f`, `--project-name`) and their
        // values between `compose` and the subcommand — NOT arbitrary tokens —
        // so a non-option subcommand (`run`, `exec`) stops it and `down`/`rm`
        // appearing as that subcommand's argument is not mistaken for the
        // Compose subcommand (#276 fix + fresh-eyes review: `docker compose run
        // svc rm -f` must not match `rm-force`). An option value may not begin
        // with `-`; `down\s`/`down$` keeps `down` a standalone subcommand token.
        // The `-v` guard is `-[vt]*v[vt]*` — a `down` short-flag cluster (its
        // only short flags are `-v`/`-t`) containing `v`, so a combined
        // `-vt`/`-tv` is recognized as volume removal and withheld from the
        // safe verdict; `[vt]` keeps it from matching inside `--verbose`/
        // `--remove-orphans`.
        safe_pattern!(
            "compose-down-no-volumes",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+(?:-[^\s;|&`()<>]*\s+(?:[^\s;|&`()<>-][^\s;|&`()<>]*\s+)?)*down(?!\s+.*(?:-[vt]*v[vt]*\b|--volumes|--rmi))(?:\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // down -v / down --volumes removes volumes
        destructive_pattern!(
            "down-volumes",
            // The walker skips only option-like tokens (`-f prod.yml`, flags)
            // before the subcommand, so `docker compose -f prod.yml down -v` is
            // caught while `docker compose run svc down -v` (a service named
            // `down` / a `-v` volume mount) is not — a non-option token stops
            // the walker (#276 + fresh-eyes review). `down\s+` keeps `down` a
            // whole subcommand token; option values may not begin with `-`.
            // `-[vt]*v[vt]*` matches a combined `down` short-flag cluster
            // containing `v` (`-vt`, `-tv`, `-v`) so `docker compose down -vt
            // 5` is caught, without matching inside a `--verbose`/`--rmi`-style
            // long option (down's only short flags are `-v` and `-t`).
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+(?:-[^\s;|&`()<>]*\s+(?:[^\s;|&`()<>-][^\s;|&`()<>]*\s+)?)*down\s+.*(?:-[vt]*v[vt]*\b|--volumes)",
            "docker-compose down -v removes volumes and their data permanently.",
            Critical,
            "The -v/--volumes flag causes docker-compose down to remove named volumes declared \
             in the volumes section of the Compose file, as well as anonymous volumes attached \
             to containers. This permanently destroys:\n\n\
             - Database data (PostgreSQL, MySQL, MongoDB volumes)\n\
             - User uploads and application state\n\
             - Any persistent configuration stored in volumes\n\n\
             Safer alternatives:\n\
             - docker-compose down: Stops and removes containers without touching volumes\n\
             - docker-compose stop: Stops containers, preserving everything\n\
             - docker volume ls: List volumes before removal"
        ),
        // down --rmi all removes images
        destructive_pattern!(
            "down-rmi-all",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+(?:-[^\s;|&`()<>]*\s+(?:[^\s;|&`()<>-][^\s;|&`()<>]*\s+)?)*down\s+.*--rmi\s+all",
            "docker-compose down --rmi all removes all images used by services.",
            High,
            "The --rmi all flag removes all images used by services in the Compose file. \
             This forces re-downloading or rebuilding images on next 'up':\n\n\
             - Base images must be pulled again (bandwidth, time)\n\
             - Custom built images need rebuilding\n\
             - Layers not in registry are lost\n\n\
             Safer alternatives:\n\
             - docker-compose down: Preserves images for faster restarts\n\
             - docker-compose down --rmi local: Only removes images without custom tag\n\
             - docker image ls: Review images before removal"
        ),
        // rm -v removes volumes
        destructive_pattern!(
            "rm-volumes",
            // `-[fsv]*v[fsv]*` matches a combined `rm` short-flag cluster
            // containing `v` (`-fsv`, `-vf`, `-vs`, `-v`) so `docker compose rm
            // -fsv` is caught (rm's short flags are `-f`/`-s`/`-v`), without
            // matching inside a long option.
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+(?:-[^\s;|&`()<>]*\s+(?:[^\s;|&`()<>-][^\s;|&`()<>]*\s+)?)*rm\s+.*(?:-[fsv]*v[fsv]*\b|--volumes)",
            "docker-compose rm -v removes volumes attached to containers.",
            High,
            "The -v flag with docker-compose rm removes anonymous volumes attached to the \
             containers being removed. This can cause data loss if volumes contain:\n\n\
             - Application state or session data\n\
             - Cached data that takes time to rebuild\n\
             - Temporary but important processing results\n\n\
             Safer alternatives:\n\
             - docker-compose rm: Removes containers without volumes\n\
             - docker-compose stop: Stops without removing anything\n\
             - docker volume ls: Check what volumes exist"
        ),
        // rm -f force removes
        destructive_pattern!(
            "rm-force",
            r"(?:docker-compose|docker\s+compose|podman-compose|podman\s+compose)\s+(?:-[^\s;|&`()<>]*\s+(?:[^\s;|&`()<>-][^\s;|&`()<>]*\s+)?)*rm\s+.*(?:-[fsv]*f[fsv]*\b|--force)",
            "docker-compose rm -f forcibly removes containers without confirmation.",
            Medium,
            "The -f/--force flag removes containers without asking for confirmation. While \
             this doesn't directly cause data loss, it can be risky:\n\n\
             - Running containers are stopped abruptly (SIGKILL)\n\
             - No graceful shutdown for applications\n\
             - In-flight requests or transactions may be lost\n\n\
             Safer alternatives:\n\
             - docker-compose stop: Graceful shutdown first\n\
             - docker-compose rm: Asks for confirmation\n\
             - docker-compose ps: Check container status first"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn compose_blocks_down_with_volumes() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose down -v", "removes volumes");
        assert_blocks(&pack, "docker-compose down --volumes", "removes volumes");
        assert_blocks(&pack, "docker compose down -v", "removes volumes");
        assert_blocks(&pack, "docker compose down --volumes", "removes volumes");
        // podman's two compose front ends take the same flags.
        assert_blocks(&pack, "podman-compose down -v", "removes volumes");
        assert_blocks(&pack, "podman compose down --volumes", "removes volumes");
        assert_blocks(&pack, "podman-compose -f prod.yml rm -fv", "volumes");
        assert_allows(&pack, "podman-compose down");
        assert_allows(&pack, "podman compose ps");
    }

    #[test]
    fn compose_blocks_combined_short_flags() {
        // Fresh-eyes review: pflag accepts combined short flags, so `-vt`
        // (down: -v + -t) and `-fsv`/`-vf` (rm: -f/-s/-v) remove volumes /
        // force just as the standalone forms do. The bare `-v\b`/`-f\b` guard
        // missed every combined form (a real, previously-uncaught data-loss
        // path when only containers.compose is enabled).
        let pack = create_pack();
        for command in [
            "docker compose down -vt 5",
            "docker compose down -tv",
            "docker compose -f a.yml down -vt 30",
            "docker-compose down -vt",
        ] {
            assert_blocks(&pack, command, "removes volumes");
        }
        for command in [
            "docker compose rm -fsv",
            "docker compose rm -vf",
            "docker compose rm -vs",
            "docker compose -f a.yml rm -fsv",
        ] {
            // -fsv contains both v (rm-volumes) and f (rm-force); either
            // destructive rule firing is a block.
            assert!(
                pack.check(command).is_some(),
                "combined rm flags must block: {command}"
            );
        }
        // `-t` alone (timeout, no volumes) and long options containing `v`
        // must NOT be mistaken for volume removal.
        for command in [
            "docker compose down -t 30",
            "docker compose down --remove-orphans",
            "docker compose down --dry-run",
        ] {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn compose_blocks_down_rmi_all() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose down --rmi all", "removes all images");
        assert_blocks(&pack, "docker compose down --rmi all", "removes all images");
    }

    #[test]
    fn compose_blocks_rm_with_volumes() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose rm -v", "removes volumes");
        assert_blocks(&pack, "docker compose rm --volumes", "removes volumes");
    }

    #[test]
    fn compose_blocks_rm_force() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose rm -f", "forcibly removes");
        assert_blocks(&pack, "docker compose rm --force", "forcibly removes");
    }

    #[test]
    fn compose_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "docker-compose down -v", Severity::Critical);
        assert_blocks_with_severity(&pack, "docker-compose down --rmi all", Severity::High);
        assert_blocks_with_severity(&pack, "docker-compose rm -v", Severity::High);
        assert_blocks_with_severity(&pack, "docker-compose rm -f", Severity::Medium);
    }

    #[test]
    fn compose_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "docker-compose config");
        assert_safe_pattern_matches(&pack, "docker compose config");
        assert_safe_pattern_matches(&pack, "docker-compose ps");
        assert_safe_pattern_matches(&pack, "docker compose ps");
        assert_safe_pattern_matches(&pack, "docker-compose logs");
        assert_safe_pattern_matches(&pack, "docker compose logs");
        assert_safe_pattern_matches(&pack, "docker-compose up");
        assert_safe_pattern_matches(&pack, "docker compose up -d");
        assert_safe_pattern_matches(&pack, "docker-compose build");
        assert_safe_pattern_matches(&pack, "docker compose pull");
    }

    #[test]
    fn compose_down_without_volumes_is_safe() {
        let pack = create_pack();
        assert_allows(&pack, "docker-compose down");
        assert_allows(&pack, "docker compose down");
    }

    #[test]
    fn compose_blocks_down_volumes_past_global_flags() {
        // #276: Compose global options before the subcommand must not defeat
        // the volume-removal rules. `docker compose -f prod.yml down -v` is
        // the ordinary, most-dangerous form and was allowed.
        let pack = create_pack();
        for command in [
            "docker compose -f a.yml down -v",
            "docker compose --file a.yml down -v",
            "docker compose -p myproj down -v",
            "docker compose --project-name myproj down -v",
            "docker compose --profile dev down -v",
            "docker compose --ansi never down -v",
            "docker compose --progress plain down -v",
            "docker compose --project-directory . down -v",
            "docker compose -f a.yml -f b.yml down -v",
            "docker compose -f a.yml down --volumes",
            "docker-compose -f a.yml down -v",
        ] {
            assert_blocks(&pack, command, "removes volumes");
        }
        assert_blocks(
            &pack,
            "docker compose -f a.yml down --rmi all",
            "removes all images",
        );
        assert_blocks(&pack, "docker compose -f a.yml rm -v", "removes volumes");
        assert_blocks(&pack, "docker compose -f a.yml rm -f", "forcibly removes");
    }

    #[test]
    fn compose_global_flag_walker_has_no_false_positives() {
        // The subcommand must be a standalone token: a `down` inside a global
        // option's filename value must not be mistaken for `docker compose
        // down`, and a benign command past global flags must still allow.
        let pack = create_pack();
        for command in [
            "docker compose -f down.yml up -v",
            "docker compose -f down.yml up -d",
            "docker compose -f a.yml down",
            "docker compose --file compose.down.yml up",
            "docker compose up -d --verbose",
            "docker compose -f a.yml config",
            "docker compose -f a.yml ps",
            // Fresh-eyes review: the walker skips only options, so `down`/`rm`
            // as an argument to a non-option subcommand (`run`/`exec`/`logs`)
            // must NOT match the volume/force rules — running `rm` inside a
            // container, a service literally named `down`, or a `-v` volume
            // mount are all benign.
            "docker compose run app rm -f /tmp/junk",
            "docker compose exec svc rm -rf /tmp/cache",
            "docker compose run down -v /data:/data",
            "docker compose exec down -v",
            "docker compose logs down -v",
            "docker compose run --rm app npm test",
        ] {
            assert_allows(&pack, command);
        }
        // A global-flag prefix followed by the real `down -v`/`rm -v` still
        // blocks (FN-safety: an unknown flag must not hide the subcommand).
        for command in [
            "docker compose --verbose down -v",
            "docker compose --profile dev -f a.yml down -v",
            "docker compose -f a.yml rm -v",
        ] {
            assert_blocks(&pack, command, "volumes");
        }
    }

    #[test]
    fn compose_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}
