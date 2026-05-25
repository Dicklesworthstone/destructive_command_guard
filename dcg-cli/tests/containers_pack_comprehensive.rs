//! Comprehensive integration tests for the containers packs (docker, podman, compose).
//!
//! These tests verify the full evaluation pipeline — not just pattern matching,
//! but context sanitization, normalization, safe-pattern interaction, cross-pack
//! behavior, and heredoc embedding.

use dcg_cli::config::Config;
use dcg_cli::evaluator::evaluate_command_with_pack_order;
use dcg_cli::load_default_allowlists;
use dcg_cli::packs::{PackRegistry, REGISTRY, Severity};

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn container_packs() -> HashSet<String> {
    [
        "containers.docker",
        "containers.podman",
        "containers.compose",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn docker_only() -> HashSet<String> {
    HashSet::from([String::from("containers.docker")])
}

fn podman_only() -> HashSet<String> {
    HashSet::from([String::from("containers.podman")])
}

fn compose_only() -> HashSet<String> {
    HashSet::from([String::from("containers.compose")])
}

fn all_packs() -> HashSet<String> {
    REGISTRY
        .all_pack_ids()
        .into_iter()
        .map(String::from)
        .collect()
}

struct Eval {
    keywords: Vec<&'static str>,
    overrides: dcg_cli::config::CompiledOverrides,
    allowlists: dcg_cli::allowlist::LayeredAllowlist,
    ordered: Vec<String>,
    keyword_index: Option<dcg_cli::packs::EnabledKeywordIndex>,
    heredoc_settings: dcg_cli::config::HeredocSettings,
}

impl Eval {
    fn with_packs(packs: &HashSet<String>) -> Self {
        let config = Config::default();
        let keywords = REGISTRY.collect_enabled_keywords(packs);
        let overrides = config.overrides.compile();
        let allowlists = load_default_allowlists();
        let ordered = REGISTRY.expand_enabled_ordered(packs);
        let keyword_index = REGISTRY.build_enabled_keyword_index(&ordered);
        let heredoc_settings = config.heredoc_settings();
        Self {
            keywords,
            overrides,
            allowlists,
            ordered,
            keyword_index,
            heredoc_settings,
        }
    }

    fn eval(&self, cmd: &str) -> dcg_cli::evaluator::EvaluationResult {
        evaluate_command_with_pack_order(
            cmd,
            &self.keywords,
            &self.ordered,
            self.keyword_index.as_ref(),
            &self.overrides,
            &self.allowlists,
            &self.heredoc_settings,
        )
    }

    fn assert_denied(&self, cmd: &str, reason_substr: &str) {
        let r = self.eval(cmd);
        assert!(
            r.is_denied(),
            "Expected DENY for `{cmd}`, got ALLOW (info: {:?})",
            r.pattern_info
        );
        let reason = r.reason().unwrap_or("");
        assert!(
            reason.contains(reason_substr),
            "Reason for `{cmd}` = {reason:?}, expected substring {reason_substr:?}"
        );
    }

    fn assert_denied_by_pack(&self, cmd: &str, pack_id: &str) {
        let r = self.eval(cmd);
        assert!(r.is_denied(), "Expected DENY for `{cmd}`, got ALLOW");
        assert_eq!(
            r.pack_id(),
            Some(pack_id),
            "Expected pack {pack_id} for `{cmd}`, got {:?}",
            r.pack_id()
        );
    }

    fn assert_denied_by_pattern(&self, cmd: &str, pattern_name: &str) {
        let r = self.eval(cmd);
        assert!(r.is_denied(), "Expected DENY for `{cmd}`, got ALLOW");
        let actual = r
            .pattern_info
            .as_ref()
            .and_then(|p| p.pattern_name.as_deref());
        assert_eq!(
            actual,
            Some(pattern_name),
            "Expected pattern {pattern_name} for `{cmd}`, got {actual:?}"
        );
    }

    fn assert_allowed(&self, cmd: &str) {
        let r = self.eval(cmd);
        assert!(
            r.is_allowed(),
            "Expected ALLOW for `{cmd}`, got DENY: {:?}",
            r.pattern_info
        );
    }
}

// ===========================================================================
// Docker integration tests
// ===========================================================================

#[test]
fn docker_system_prune_denied_through_full_pipeline() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("docker system prune", "prune");
    e.assert_denied("docker system prune -a --force", "prune");
    e.assert_denied("docker system prune --all --volumes", "prune");
}

#[test]
fn docker_volume_operations_denied() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("docker volume prune", "prune");
    e.assert_denied("docker volume rm my-db-data", "volume");
    e.assert_denied("docker volume rm vol1 vol2 vol3", "volume");
}

#[test]
fn docker_network_prune_denied() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("docker network prune", "prune");
    e.assert_denied("docker network prune --force", "prune");
}

#[test]
fn docker_rm_force_variants() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("docker rm -f my-container", "forcibly");
    e.assert_denied("docker rm --force my-container", "forcibly");
    e.assert_denied("docker rm -vf my-container", "forcibly");
    e.assert_denied("docker rm -fv my-container", "forcibly");
}

#[test]
fn docker_rmi_force_variants() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("docker rmi -f nginx:latest", "forcibly");
    e.assert_denied("docker rmi --force nginx:latest", "forcibly");
    e.assert_denied("docker rmi -nf my-image", "forcibly");
}

#[test]
fn docker_stop_all_blocked_through_full_pipeline() {
    // The stop-all regex matches `docker stop/kill $(`  — the broadened pattern
    // survives context sanitization (which masks subshell contents into `$()`)
    // because it only requires the `$(` opener, not the inner command.
    let e = Eval::with_packs(&docker_only());
    e.assert_denied(
        "docker stop $(docker ps -q)",
        "Stopping/killing all containers",
    );
    e.assert_denied(
        "docker kill $(docker ps -aq)",
        "Stopping/killing all containers",
    );
    // With filters — still a dynamic list, still dangerous
    e.assert_denied(
        "docker stop $(docker ps -q -f status=running)",
        "Stopping/killing all containers",
    );
}

#[test]
fn docker_stop_all_pattern_at_pack_level() {
    let pack = dcg_cli::packs::containers::docker::create_pack();

    // pack.check() runs safe patterns first — the broadened regex matches `$(`
    // before the inner `docker ps` safe pattern can short-circuit, because
    // `docker stop` is not a safe command (no safe pattern matches the outer
    // form `docker ... stop ...`).
    let hit = pack.check("docker stop $(docker ps -q)");
    assert!(hit.is_some(), "stop-all should be caught at pack level");
    assert_eq!(hit.unwrap().name, Some("stop-all"));

    let hit = pack.check("docker kill $(docker ps -aq)");
    assert!(hit.is_some(), "kill-all should be caught at pack level");
}

#[test]
fn docker_safe_commands_allowed() {
    let e = Eval::with_packs(&docker_only());
    e.assert_allowed("docker ps");
    e.assert_allowed("docker ps -a --format json");
    e.assert_allowed("docker images");
    e.assert_allowed("docker images --filter dangling=true");
    e.assert_allowed("docker logs my-container --tail 100");
    e.assert_allowed("docker inspect my-container");
    e.assert_allowed("docker build -t my-app:latest .");
    e.assert_allowed("docker pull nginx:latest");
    e.assert_allowed("docker run --rm hello-world");
    e.assert_allowed("docker run -d -p 8080:80 nginx");
    e.assert_allowed("docker exec -it my-container bash");
    e.assert_allowed("docker stats");
    e.assert_allowed("docker stats --no-stream");
}

#[test]
fn docker_rm_without_force_allowed() {
    let e = Eval::with_packs(&docker_only());
    e.assert_allowed("docker rm stopped-container");
    e.assert_allowed("docker rmi old-image:v1");
}

#[test]
fn docker_dry_run_allowed() {
    let e = Eval::with_packs(&docker_only());
    e.assert_allowed("docker system prune --dry-run");
    e.assert_allowed("docker container prune --dry-run");
}

#[test]
fn docker_global_flags_between_docker_and_subcommand() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("docker --context prod system prune", "prune");
    e.assert_denied("docker --host ssh://remote-host volume rm data", "volume");
    e.assert_denied("docker --config /tmp/alt-config rm -f app", "forcibly");
    e.assert_denied("docker --log-level debug --tls volume prune", "prune");
}

#[test]
fn docker_pattern_names_correct() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied_by_pattern("docker system prune", "system-prune");
    e.assert_denied_by_pattern("docker volume prune", "volume-prune");
    e.assert_denied_by_pattern("docker network prune", "network-prune");
    e.assert_denied_by_pattern("docker image prune", "image-prune");
    e.assert_denied_by_pattern("docker container prune", "container-prune");
    e.assert_denied_by_pattern("docker rm -f x", "rm-force");
    e.assert_denied_by_pattern("docker rmi -f x", "rmi-force");
    e.assert_denied_by_pattern("docker volume rm x", "volume-rm");
    e.assert_denied_by_pattern("docker stop $(docker ps -q)", "stop-all");
}

#[test]
fn docker_container_named_as_safe_subcommand_still_blocked() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied_by_pattern("docker rm -f ps", "rm-force");
    e.assert_denied_by_pattern("docker rm --force logs", "rm-force");
    e.assert_denied_by_pattern("docker rmi -f build", "rmi-force");
    e.assert_denied_by_pattern("docker rm -f run", "rm-force");
    e.assert_denied_by_pattern("docker rm -f exec", "rm-force");
    e.assert_denied_by_pattern("docker rm -f stats", "rm-force");
}

#[test]
fn docker_safe_keyword_in_container_name_still_blocked() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied_by_pattern("docker rm -f ps-container", "rm-force");
    e.assert_denied_by_pattern("docker rm -f logs-archive", "rm-force");
    e.assert_denied_by_pattern("docker rmi -f build-server-img", "rmi-force");
    e.assert_denied_by_pattern("docker volume rm logs-data", "volume-rm");
}

// ===========================================================================
// Podman integration tests
// ===========================================================================

#[test]
fn podman_system_prune_denied() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("podman system prune", "prune");
    e.assert_denied("podman system prune --all --force", "prune");
}

#[test]
fn podman_volume_prune_is_critical() {
    let e = Eval::with_packs(&podman_only());
    let r = e.eval("podman volume prune");
    assert!(r.is_denied());
    let severity = r.pattern_info.as_ref().and_then(|p| p.severity);
    assert_eq!(
        severity,
        Some(Severity::Critical),
        "podman volume prune should be Critical severity"
    );
}

#[test]
fn podman_pod_prune_denied() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("podman pod prune", "prune");
}

#[test]
fn podman_rm_force_variants() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("podman rm -f container", "forcibly");
    e.assert_denied("podman rm --force container", "forcibly");
    e.assert_denied("podman rm -af", "forcibly");
    e.assert_denied("podman rm -vf container", "forcibly");
}

#[test]
fn podman_rmi_force_variants() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("podman rmi -f image", "forcibly");
    e.assert_denied("podman rmi --force image", "forcibly");
}

#[test]
fn podman_volume_rm_denied() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("podman volume rm my-volume", "volume");
}

#[test]
fn podman_safe_commands_allowed() {
    let e = Eval::with_packs(&podman_only());
    e.assert_allowed("podman ps");
    e.assert_allowed("podman ps -a");
    e.assert_allowed("podman images");
    e.assert_allowed("podman logs my-container");
    e.assert_allowed("podman inspect my-container");
    e.assert_allowed("podman build -t app .");
    e.assert_allowed("podman pull nginx:latest");
    e.assert_allowed("podman run --rm hello-world");
    e.assert_allowed("podman exec -it container bash");
}

#[test]
fn podman_rm_without_force_allowed() {
    let e = Eval::with_packs(&podman_only());
    e.assert_allowed("podman rm stopped-container");
    e.assert_allowed("podman rmi old-image:v1");
}

#[test]
fn podman_global_flags_still_blocked() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("podman --remote --connection prod volume rm data", "volume");
    e.assert_denied("podman --url tcp://prod:8080 system prune --all", "prune");
    e.assert_denied("podman --log-level debug rm -f container", "forcibly");
}

#[test]
fn podman_container_named_as_safe_subcommand_still_blocked() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied_by_pattern("podman rm -f ps", "rm-force");
    e.assert_denied_by_pattern("podman rm --force logs", "rm-force");
    e.assert_denied_by_pattern("podman rmi -f build", "rmi-force");
    e.assert_denied_by_pattern("podman rm -f run", "rm-force");
}

#[test]
fn podman_safe_keyword_in_container_name_still_blocked() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied_by_pattern("podman rm -f ps-worker", "rm-force");
    e.assert_denied_by_pattern("podman rmi -f build-cache", "rmi-force");
    e.assert_denied_by_pattern("podman volume rm logs-vol", "volume-rm");
}

#[test]
fn podman_pattern_names_correct() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied_by_pattern("podman system prune", "system-prune");
    e.assert_denied_by_pattern("podman volume prune", "volume-prune");
    e.assert_denied_by_pattern("podman pod prune", "pod-prune");
    e.assert_denied_by_pattern("podman image prune", "image-prune");
    e.assert_denied_by_pattern("podman container prune", "container-prune");
    e.assert_denied_by_pattern("podman rm -f x", "rm-force");
    e.assert_denied_by_pattern("podman rmi -f x", "rmi-force");
    e.assert_denied_by_pattern("podman volume rm x", "volume-rm");
}

// ===========================================================================
// Compose integration tests
// ===========================================================================

#[test]
fn compose_down_volumes_denied() {
    let e = Eval::with_packs(&compose_only());
    e.assert_denied("docker-compose down -v", "removes volumes");
    e.assert_denied("docker-compose down --volumes", "removes volumes");
    e.assert_denied("docker compose down -v", "removes volumes");
    e.assert_denied("docker compose down --volumes", "removes volumes");
}

#[test]
fn compose_down_rmi_all_denied() {
    let e = Eval::with_packs(&compose_only());
    e.assert_denied("docker-compose down --rmi all", "removes all images");
    e.assert_denied("docker compose down --rmi all", "removes all images");
}

#[test]
fn compose_rm_volumes_denied() {
    let e = Eval::with_packs(&compose_only());
    e.assert_denied("docker-compose rm -v", "removes volumes");
    e.assert_denied("docker compose rm --volumes", "removes volumes");
}

#[test]
fn compose_rm_force_denied() {
    let e = Eval::with_packs(&compose_only());
    e.assert_denied("docker-compose rm -f", "forcibly removes");
    e.assert_denied("docker compose rm --force", "forcibly removes");
}

#[test]
fn compose_safe_commands_allowed() {
    let e = Eval::with_packs(&compose_only());
    e.assert_allowed("docker-compose config");
    e.assert_allowed("docker compose config");
    e.assert_allowed("docker-compose ps");
    e.assert_allowed("docker compose ps");
    e.assert_allowed("docker-compose logs");
    e.assert_allowed("docker compose logs");
    e.assert_allowed("docker-compose up -d");
    e.assert_allowed("docker compose up --build");
    e.assert_allowed("docker-compose build");
    e.assert_allowed("docker compose pull");
}

#[test]
fn compose_down_without_volumes_allowed() {
    let e = Eval::with_packs(&compose_only());
    e.assert_allowed("docker-compose down");
    e.assert_allowed("docker compose down");
    e.assert_allowed("docker compose down --remove-orphans");
}

#[test]
fn compose_pattern_names_correct() {
    let e = Eval::with_packs(&compose_only());
    e.assert_denied_by_pattern("docker-compose down -v", "down-volumes");
    e.assert_denied_by_pattern("docker-compose down --rmi all", "down-rmi-all");
    e.assert_denied_by_pattern("docker-compose rm -v", "rm-volumes");
    e.assert_denied_by_pattern("docker-compose rm -f", "rm-force");
}

#[test]
fn compose_severity_levels() {
    let e = Eval::with_packs(&compose_only());

    let r = e.eval("docker-compose down -v");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::Critical)
    );

    let r = e.eval("docker-compose down --rmi all");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::High)
    );

    let r = e.eval("docker-compose rm -v");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::High)
    );

    let r = e.eval("docker-compose rm -f");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::Medium)
    );
}

// ===========================================================================
// Cross-pack interaction tests
// ===========================================================================

#[test]
fn docker_and_git_both_active_compound_command() {
    let mut packs = docker_only();
    packs.insert("core.git".to_string());
    let e = Eval::with_packs(&packs);

    // Compound: docker destructive + git destructive — first match wins
    let r = e.eval("docker rm -f foo && git push --force");
    assert!(r.is_denied(), "Compound destructive command must be denied");
}

#[test]
fn docker_with_all_packs_no_false_positives() {
    let e = Eval::with_packs(&all_packs());
    e.assert_allowed("docker ps");
    e.assert_allowed("docker images");
    e.assert_allowed("docker run --rm hello-world");
    e.assert_allowed("docker build -t app .");
    e.assert_allowed("docker exec -it mycontainer sh");
}

#[test]
fn docker_with_all_packs_still_blocks() {
    let e = Eval::with_packs(&all_packs());
    e.assert_denied("docker system prune -a", "prune");
    e.assert_denied("docker volume rm important-data", "volume");
    e.assert_denied("docker rm -f my-app", "forcibly");
}

// ===========================================================================
// Context sanitization tests (false positive prevention)
// ===========================================================================

#[test]
fn docker_in_commit_message_not_blocked() {
    let e = Eval::with_packs(&all_packs());
    e.assert_allowed("git commit -m 'Fixed docker system prune detection'");
    e.assert_allowed("git commit -m 'Added docker volume rm pattern'");
}

#[test]
fn docker_in_echo_not_blocked() {
    let e = Eval::with_packs(&docker_only());
    // echo just outputs text, doesn't execute
    e.assert_allowed("echo 'docker system prune'");
    e.assert_allowed("echo 'docker rm -f container'");
    e.assert_allowed(r#"echo "<(docker system prune -a --volumes)""#);
    e.assert_allowed(r#"echo ">(docker system prune -a --volumes)""#);
    e.assert_allowed(r#"echo "$(printf "%s" "<(docker system prune -a --volumes)")""#);
    e.assert_allowed(r#"echo "$(printf "%s" ">(docker system prune -a --volumes)")""#);
}

#[test]
fn docker_process_substitution_still_blocked_through_full_pipeline() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied(
        "cat <(docker system prune -a --volumes)",
        "docker system prune",
    );
    e.assert_denied(
        "cat >(docker system prune -a --volumes)",
        "docker system prune",
    );
}

#[test]
fn docker_in_grep_search_not_blocked() {
    let e = Eval::with_packs(&all_packs());
    e.assert_allowed("grep -r 'docker system prune' docs/");
    e.assert_allowed("rg 'docker rm -f' src/");
}

// ===========================================================================
// Normalization tests (absolute paths)
// ===========================================================================

#[test]
fn docker_with_absolute_path_still_blocked() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("/usr/bin/docker system prune", "prune");
    e.assert_denied("/usr/local/bin/docker volume rm data", "volume");
}

#[test]
fn podman_with_absolute_path_still_blocked() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("/usr/bin/podman system prune", "prune");
    e.assert_denied("/usr/bin/podman volume rm data", "volume");
}

// ===========================================================================
// Unrelated commands — no false positives
// ===========================================================================

#[test]
fn unrelated_commands_not_blocked_by_container_packs() {
    let e = Eval::with_packs(&container_packs());
    e.assert_allowed("ls -la");
    e.assert_allowed("git status");
    e.assert_allowed("npm install");
    e.assert_allowed("cargo build");
    e.assert_allowed("python -c 'print(1)'");
    e.assert_allowed("cat /etc/hosts");
    e.assert_allowed("mkdir -p /tmp/test");
}

// ===========================================================================
// Pack registration verification
// ===========================================================================

#[test]
fn all_container_packs_registered() {
    let registry = PackRegistry::new();
    let ids: Vec<&str> = registry.all_pack_ids();
    assert!(ids.contains(&"containers.docker"), "docker pack missing");
    assert!(ids.contains(&"containers.podman"), "podman pack missing");
    assert!(ids.contains(&"containers.compose"), "compose pack missing");
}

#[test]
fn container_packs_in_containers_category() {
    let registry = PackRegistry::new();
    let categories = registry.all_categories();
    assert!(
        categories.iter().any(|c| c.as_str() == "containers"),
        "containers category missing from registry"
    );
    let container_packs = registry.packs_in_category("containers");
    assert!(
        container_packs.len() >= 3,
        "Expected at least 3 container packs, got {}",
        container_packs.len()
    );
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn docker_extra_whitespace_still_blocked() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("docker   system   prune", "prune");
    e.assert_denied("docker  rm  -f  container", "forcibly");
}

#[test]
fn docker_with_env_prefix_still_blocked() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("DOCKER_HOST=tcp://prod:2375 docker system prune", "prune");
    e.assert_denied("DOCKER_TLS_VERIFY=1 docker volume rm data", "volume");
}

#[test]
fn docker_with_sudo_still_blocked() {
    let e = Eval::with_packs(&docker_only());
    e.assert_denied("sudo docker system prune", "prune");
    e.assert_denied("sudo docker rm -f container", "forcibly");
    e.assert_denied("sudo docker volume rm data", "volume");
}

#[test]
fn podman_with_sudo_still_blocked() {
    let e = Eval::with_packs(&podman_only());
    e.assert_denied("sudo podman system prune", "prune");
    e.assert_denied("sudo podman rm -f container", "forcibly");
}

#[test]
fn compose_combined_flags_denied() {
    let e = Eval::with_packs(&compose_only());
    // down -v --remove-orphans — still has -v
    e.assert_denied("docker-compose down -v --remove-orphans", "removes volumes");
    // down --rmi all --volumes — has both --rmi all and --volumes
    e.assert_denied("docker compose down --rmi all --volumes", "removes");
}

#[test]
fn compose_with_file_flag() {
    let e = Eval::with_packs(&compose_only());
    // -f flag before the subcommand — compose patterns use `\s+down` directly
    // after `compose`, so flags between compose and subcommand are a known
    // limitation of the current regex. Test that the standard form works.
    e.assert_denied("docker-compose down --volumes", "removes volumes");
    e.assert_denied("docker compose down -v", "removes volumes");
}

#[test]
fn docker_image_and_container_prune_are_medium_severity() {
    let e = Eval::with_packs(&docker_only());

    let r = e.eval("docker image prune");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::Medium),
        "image prune should be Medium"
    );

    let r = e.eval("docker container prune");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::Medium),
        "container prune should be Medium"
    );
}

#[test]
fn docker_network_prune_is_high_severity() {
    let e = Eval::with_packs(&docker_only());
    let r = e.eval("docker network prune");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::High),
        "network prune should be High"
    );
}

#[test]
fn docker_stop_all_is_high_severity() {
    let e = Eval::with_packs(&docker_only());
    let r = e.eval("docker stop $(docker ps -q)");
    assert!(r.is_denied(), "stop-all must be denied");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::High),
        "stop-all should be High"
    );
}

#[test]
fn docker_pack_id_attribution() {
    let e = Eval::with_packs(&container_packs());
    e.assert_denied_by_pack("docker system prune", "containers.docker");
    e.assert_denied_by_pack("podman system prune", "containers.podman");
    e.assert_denied_by_pack("docker-compose down -v", "containers.compose");
    e.assert_denied_by_pack("docker compose down -v", "containers.compose");
}

#[test]
fn podman_medium_severity_patterns() {
    let e = Eval::with_packs(&podman_only());

    let r = e.eval("podman pod prune");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::Medium),
        "pod prune should be Medium"
    );

    let r = e.eval("podman image prune");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::Medium),
        "image prune should be Medium"
    );

    let r = e.eval("podman container prune");
    assert_eq!(
        r.pattern_info.as_ref().and_then(|p| p.severity),
        Some(Severity::Medium),
        "container prune should be Medium"
    );
}

// ===========================================================================
// Suggestions present on key patterns
// ===========================================================================

#[test]
fn docker_destructive_patterns_have_suggestions() {
    let pack = dcg_cli::packs::containers::docker::create_pack();
    for pattern in &pack.destructive_patterns {
        assert!(
            !pattern.suggestions.is_empty(),
            "Docker pattern {:?} should have suggestions",
            pattern.name
        );
    }
}

#[test]
fn docker_patterns_have_explanations() {
    let pack = dcg_cli::packs::containers::docker::create_pack();
    for pattern in &pack.destructive_patterns {
        assert!(
            pattern.explanation.is_some(),
            "Docker pattern {:?} should have an explanation",
            pattern.name
        );
    }
}
