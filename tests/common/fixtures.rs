//! Test fixtures for history E2E tests.
//!
//! Provides realistic command data for testing various history scenarios.

use super::db::TestCommand;
use destructive_command_guard::history::Outcome;

/// Standard mix of commands for comprehensive testing.
///
/// Includes various outcomes, agent types, packs, and patterns to exercise
/// all history code paths.
#[must_use]
pub fn standard_mix() -> Vec<TestCommand> {
    vec![
        // Allowed safe commands
        TestCommand {
            command: "git status",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -3600, // 1 hour ago
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 85,
        },
        TestCommand {
            command: "ls -la",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -3500,
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 45,
        },
        TestCommand {
            command: "cargo build --release",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -3400,
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 120,
        },
        // Blocked dangerous commands
        TestCommand {
            command: "git reset --hard HEAD~5",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -3300,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            eval_duration_us: 250,
        },
        TestCommand {
            command: "git push --force origin main",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -3200,
            pack_id: Some("core.git"),
            pattern_name: Some("force-push"),
            rule_id: Some("core.git:force-push"),
            eval_duration_us: 180,
        },
        TestCommand {
            command: "rm -rf /tmp/cache/*",
            outcome: Outcome::Deny,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -3100,
            pack_id: Some("core.filesystem"),
            pattern_name: Some("rm-recursive-force"),
            rule_id: Some("core.filesystem:rm-recursive-force"),
            eval_duration_us: 150,
        },
        // Warned commands
        TestCommand {
            command: "docker system prune -a",
            outcome: Outcome::Warn,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -3000,
            pack_id: Some("containers.docker"),
            pattern_name: Some("system-prune"),
            rule_id: Some("containers.docker:system-prune"),
            eval_duration_us: 200,
        },
        // Bypassed commands (allow-once)
        TestCommand {
            command: "git clean -fd",
            outcome: Outcome::Bypass,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -2900,
            pack_id: Some("core.git"),
            pattern_name: Some("clean-force"),
            rule_id: Some("core.git:clean-force"),
            eval_duration_us: 160,
        },
        // Different agent types
        TestCommand {
            command: "npm install lodash",
            outcome: Outcome::Allow,
            agent_type: "codex",
            working_dir: "/data/projects/webapp",
            timestamp_offset_secs: -2800,
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 90,
        },
        TestCommand {
            command: "pip install requests",
            outcome: Outcome::Allow,
            agent_type: "cursor",
            working_dir: "/data/projects/pyproject",
            timestamp_offset_secs: -2700,
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 75,
        },
        // More recent commands
        TestCommand {
            command: "git diff --cached",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -1800, // 30 minutes ago
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 55,
        },
        TestCommand {
            command: "git commit -m 'Fix bug'",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -1200, // 20 minutes ago
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 110,
        },
        TestCommand {
            command: "git push origin feature/new-api",
            outcome: Outcome::Allow,
            agent_type: "claude_code",
            working_dir: "/data/projects/myapp",
            timestamp_offset_secs: -600, // 10 minutes ago
            pack_id: None,
            pattern_name: None,
            rule_id: None,
            eval_duration_us: 95,
        },
    ]
}

/// Large dataset for performance testing.
///
/// Generates `count` semi-random realistic commands suitable for
/// benchmarking database operations.
#[must_use]
pub fn large_dataset(count: usize) -> Vec<TestCommand> {
    // (command, outcome, pack_id, pattern_name, rule_id)
    let base_commands: [(&str, Outcome, Option<&str>, Option<&str>, Option<&str>); 9] = [
        ("git status", Outcome::Allow, None, None, None),
        ("git diff", Outcome::Allow, None, None, None),
        ("ls -la", Outcome::Allow, None, None, None),
        ("cargo build", Outcome::Allow, None, None, None),
        ("npm test", Outcome::Allow, None, None, None),
        ("python -m pytest", Outcome::Allow, None, None, None),
        (
            "git reset --hard",
            Outcome::Deny,
            Some("core.git"),
            Some("reset-hard"),
            Some("core.git:reset-hard"),
        ),
        (
            "rm -rf /tmp",
            Outcome::Deny,
            Some("core.filesystem"),
            Some("rm-recursive-force"),
            Some("core.filesystem:rm-recursive-force"),
        ),
        (
            "docker system prune",
            Outcome::Warn,
            Some("containers.docker"),
            Some("system-prune"),
            Some("containers.docker:system-prune"),
        ),
    ];

    let agent_types = ["claude_code", "codex", "cursor", "copilot"];
    let working_dirs = [
        "/data/projects/app1",
        "/data/projects/app2",
        "/home/user/code",
        "/tmp/workspace",
    ];

    (0..count)
        .map(|i| {
            let (command, outcome, pack_id, pattern_name, rule_id) =
                base_commands[i % base_commands.len()];
            let offset_steps = i64::try_from(count - i).unwrap_or(i64::MAX / 60);
            let offset_secs = -(offset_steps.saturating_mul(60)); // Spaced 1 minute apart
            TestCommand {
                command,
                outcome,
                agent_type: agent_types[i % agent_types.len()],
                working_dir: working_dirs[i % working_dirs.len()],
                timestamp_offset_secs: offset_secs,
                pack_id,
                pattern_name,
                rule_id,
                eval_duration_us: 50 + (i % 200) as u64,
            }
        })
        .collect()
}

/// Commands containing secrets for redaction testing.
///
/// These commands should trigger redaction logic when stored.
#[must_use]
pub fn commands_with_secrets() -> Vec<TestCommand> {
    vec![
        TestCommand {
            command: "curl -H 'Authorization: Bearer sk-ant-api-key-1234567890abcdef' https://api.example.com",
            outcome: Outcome::Allow,
            timestamp_offset_secs: -300,
            ..Default::default()
        },
        TestCommand {
            command: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY aws s3 ls",
            outcome: Outcome::Allow,
            timestamp_offset_secs: -240,
            ..Default::default()
        },
        TestCommand {
            command: "export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            outcome: Outcome::Allow,
            timestamp_offset_secs: -180,
            ..Default::default()
        },
        TestCommand {
            command: "mysql -u root -pSuperSecretPassword123 mydb",
            outcome: Outcome::Allow,
            timestamp_offset_secs: -120,
            ..Default::default()
        },
        TestCommand {
            command: "psql 'postgresql://admin:s3cr3t@localhost:5432/prod'",
            outcome: Outcome::Allow,
            timestamp_offset_secs: -60,
            ..Default::default()
        },
    ]
}

/// Commands for testing outcome distribution queries.
#[must_use]
pub fn outcome_distribution() -> Vec<TestCommand> {
    // 70% Allow, 20% Deny, 7% Warn, 3% Bypass
    let mut commands = Vec::with_capacity(100);

    // 70 allows
    for i in 0..70 {
        commands.push(TestCommand {
            command: "safe_command",
            outcome: Outcome::Allow,
            timestamp_offset_secs: -(i * 60),
            ..Default::default()
        });
    }

    // 20 denies
    for i in 0..20 {
        commands.push(TestCommand {
            command: "blocked_command",
            outcome: Outcome::Deny,
            pack_id: Some("core.git"),
            timestamp_offset_secs: -(70 + i) * 60,
            ..Default::default()
        });
    }

    // 7 warns
    for i in 0..7 {
        commands.push(TestCommand {
            command: "warned_command",
            outcome: Outcome::Warn,
            pack_id: Some("containers.docker"),
            timestamp_offset_secs: -(90 + i) * 60,
            ..Default::default()
        });
    }

    // 3 bypasses
    for i in 0..3 {
        commands.push(TestCommand {
            command: "bypassed_command",
            outcome: Outcome::Bypass,
            pack_id: Some("core.filesystem"),
            timestamp_offset_secs: -(97 + i) * 60,
            ..Default::default()
        });
    }

    commands
}

/// Commands for testing rule metrics queries and CLI output.
///
/// Provides known rule counts:
/// - `core.git:reset-hard`: 5 hits (3 deny, 2 bypass)
/// - `core.git:force-push`: 3 hits (2 deny, 1 bypass)
/// - `core.filesystem:rm-rf`: 4 hits (4 deny, 0 bypass)
///
/// Total: 12 hits, 3 rules, 3 bypasses (overrides)
#[must_use]
#[allow(dead_code)]
pub fn rule_metrics_data() -> Vec<TestCommand> {
    vec![
        // core.git:reset-hard - 3 deny, 2 bypass = 5 hits, 40% override rate
        TestCommand {
            command: "git reset --hard HEAD~1",
            outcome: Outcome::Deny,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            timestamp_offset_secs: -7200,
            ..Default::default()
        },
        TestCommand {
            command: "git reset --hard HEAD~2",
            outcome: Outcome::Deny,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            timestamp_offset_secs: -6000,
            ..Default::default()
        },
        TestCommand {
            command: "git reset --hard origin/main",
            outcome: Outcome::Deny,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            timestamp_offset_secs: -4800,
            ..Default::default()
        },
        TestCommand {
            command: "git reset --hard HEAD",
            outcome: Outcome::Bypass,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            timestamp_offset_secs: -3600,
            ..Default::default()
        },
        TestCommand {
            command: "git reset --hard abc123",
            outcome: Outcome::Bypass,
            pack_id: Some("core.git"),
            pattern_name: Some("reset-hard"),
            rule_id: Some("core.git:reset-hard"),
            timestamp_offset_secs: -2400,
            ..Default::default()
        },
        // core.git:force-push - 2 deny, 1 bypass = 3 hits, 33.3% override rate
        TestCommand {
            command: "git push --force origin main",
            outcome: Outcome::Deny,
            pack_id: Some("core.git"),
            pattern_name: Some("force-push"),
            rule_id: Some("core.git:force-push"),
            timestamp_offset_secs: -7000,
            ..Default::default()
        },
        TestCommand {
            command: "git push --force-with-lease origin dev",
            outcome: Outcome::Deny,
            pack_id: Some("core.git"),
            pattern_name: Some("force-push"),
            rule_id: Some("core.git:force-push"),
            timestamp_offset_secs: -5000,
            ..Default::default()
        },
        TestCommand {
            command: "git push --force origin feature",
            outcome: Outcome::Bypass,
            pack_id: Some("core.git"),
            pattern_name: Some("force-push"),
            rule_id: Some("core.git:force-push"),
            timestamp_offset_secs: -3000,
            ..Default::default()
        },
        // core.filesystem:rm-rf - 4 deny, 0 bypass = 4 hits, 0% override rate
        TestCommand {
            command: "rm -rf /tmp/test",
            outcome: Outcome::Deny,
            pack_id: Some("core.filesystem"),
            pattern_name: Some("rm-rf"),
            rule_id: Some("core.filesystem:rm-rf"),
            timestamp_offset_secs: -8000,
            ..Default::default()
        },
        TestCommand {
            command: "rm -rf ./build",
            outcome: Outcome::Deny,
            pack_id: Some("core.filesystem"),
            pattern_name: Some("rm-rf"),
            rule_id: Some("core.filesystem:rm-rf"),
            timestamp_offset_secs: -6500,
            ..Default::default()
        },
        TestCommand {
            command: "rm -rf node_modules",
            outcome: Outcome::Deny,
            pack_id: Some("core.filesystem"),
            pattern_name: Some("rm-rf"),
            rule_id: Some("core.filesystem:rm-rf"),
            timestamp_offset_secs: -5500,
            ..Default::default()
        },
        TestCommand {
            command: "rm -rf dist",
            outcome: Outcome::Deny,
            pack_id: Some("core.filesystem"),
            pattern_name: Some("rm-rf"),
            rule_id: Some("core.filesystem:rm-rf"),
            timestamp_offset_secs: -4000,
            ..Default::default()
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_mix_has_all_outcomes() {
        let mix = standard_mix();
        assert!(mix.iter().any(|c| c.outcome == Outcome::Allow));
        assert!(mix.iter().any(|c| c.outcome == Outcome::Deny));
        assert!(mix.iter().any(|c| c.outcome == Outcome::Warn));
        assert!(mix.iter().any(|c| c.outcome == Outcome::Bypass));
    }

    #[test]
    fn test_large_dataset_correct_size() {
        assert_eq!(large_dataset(100).len(), 100);
        assert_eq!(large_dataset(1000).len(), 1000);
    }

    #[test]
    fn test_commands_with_secrets_non_empty() {
        assert!(!commands_with_secrets().is_empty());
    }

    #[test]
    fn test_outcome_distribution_correct_counts() {
        let dist = outcome_distribution();
        assert_eq!(dist.len(), 100);
        assert_eq!(
            dist.iter().filter(|c| c.outcome == Outcome::Allow).count(),
            70
        );
        assert_eq!(
            dist.iter().filter(|c| c.outcome == Outcome::Deny).count(),
            20
        );
        assert_eq!(
            dist.iter().filter(|c| c.outcome == Outcome::Warn).count(),
            7
        );
        assert_eq!(
            dist.iter().filter(|c| c.outcome == Outcome::Bypass).count(),
            3
        );
    }
}
