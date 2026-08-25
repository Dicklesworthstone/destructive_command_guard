//! Regression tests for issue #326: `ssh <host> '<command>'` treated the
//! quoted remote payload as opaque argv data, so a destructive payload passed
//! exactly when it was quoted while the unquoted spelling was denied.
//!
//! ssh concatenates every argv word after the destination and hands the result
//! to the remote login shell — it is an inline-shell wrapper like `sh -c`,
//! minus the flag. The heredoc pipeline now extracts that payload (skipping
//! value-taking options to locate the destination) and recursively evaluates
//! it, so the quoted and unquoted spellings reach the same decision.

use destructive_command_guard::evaluator::evaluate_command_with_pack_order_at_path_in_dialect;
use destructive_command_guard::normalize::ShellDialect;
use destructive_command_guard::packs::REGISTRY;
use destructive_command_guard::{Config, LayeredAllowlist};

fn evaluate(
    command: &str,
    extra_packs: &[&str],
    dialect: ShellDialect,
) -> destructive_command_guard::EvaluationResult {
    let config = Config::default();
    let mut enabled_packs = config.enabled_pack_ids();
    for pack in extra_packs {
        enabled_packs.insert((*pack).to_string());
    }
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let ordered_packs = REGISTRY.expand_enabled_ordered(&enabled_packs);
    let keyword_index = REGISTRY
        .build_enabled_keyword_index(&ordered_packs)
        .expect("keyword index should build for enabled pack set");
    let compiled_overrides = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();
    let heredoc_settings = config.heredoc_settings();
    evaluate_command_with_pack_order_at_path_in_dialect(
        command,
        &enabled_keywords,
        &ordered_packs,
        Some(&keyword_index),
        &compiled_overrides,
        &allowlists,
        &heredoc_settings,
        None,
        dialect,
    )
}

const DIALECTS: [ShellDialect; 2] = [ShellDialect::Posix, ShellDialect::Unknown];

/// The issue's reproduction table: every quoted spelling that was wrongly
/// allowed while its unquoted twin was denied.
#[test]
fn quoted_ssh_payloads_are_denied_like_their_unquoted_twins() {
    let denied = [
        "dropdb mydb",
        "ssh example-host dropdb mydb",
        "ssh example-host -- dropdb mydb",
        "ssh example-host sh -c 'dropdb mydb'",
        "ssh example-host \"dropdb mydb\"",
        "ssh example-host 'dropdb mydb'",
        "ssh user@10.0.0.5 'dropdb mydb'",
        "ssh example-host 'psql -c \"DROP TABLE t\"'",
    ];
    for command in denied {
        for dialect in DIALECTS {
            let result = evaluate(command, &["database.postgresql"], dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
    }
}

/// Core-pack payloads through option-bearing invocations.
#[test]
fn destructive_ssh_payloads_are_denied_with_core_packs_only() {
    let denied = [
        "ssh example-host 'sudo rm -rf /some/path'",
        "ssh example-host 'rm -rf /var/lib/data'",
        "ssh -i key.pem -p 2222 user@host 'git reset --hard'",
        "ssh -o StrictHostKeyChecking=no host 'rm -rf /srv'",
        "ssh -p2222 host 'rm -rf /srv'",
        "ssh -fnT -l root host 'rm -rf /srv/data'",
        "sudo ssh host 'rm -rf /srv/data'",
        "/usr/bin/ssh host 'rm -rf /srv/data'",
        "ssh a ssh b 'rm -rf /srv/data'",
        "ssh h uptime && ssh h 'rm -rf /srv/data'",
        "ssh h 'cd /app; git reset --hard'",
    ];
    for command in denied {
        for dialect in DIALECTS {
            let result = evaluate(command, &[], dialect);
            assert!(
                result.is_denied(),
                "{command:?} must be denied under {dialect:?}, got {result:?}"
            );
        }
    }
}

/// The issue's safe list: read-only remote diagnostics must stay allowed, and
/// the classic data contexts must not start firing because `ssh` appears.
#[test]
fn read_only_remote_commands_and_data_contexts_stay_allowed() {
    let allowed = [
        "ssh h 'uptime'",
        "ssh h 'df -h'",
        "ssh h 'cat /path/file'",
        "ssh h 'ls -la /path'",
        "ssh h 'grep -rn ERROR /var/log'",
        "ssh h 'systemctl status svc'",
        "ssh h 'journalctl -u svc -n 50'",
        "ssh h 'git -C /repo log --oneline -5'",
        "ssh h 'sqlite3 db \"SELECT count(*) FROM t;\"'",
        "ssh h 'pg_dump db > /tmp/db.sql'",
        // The payload's own quoting still classifies remote data as data.
        "ssh h 'echo \"dropdb mydb\"'",
        "ssh h 'echo rm -rf /srv/data'",
        // ssh mentioned as data, not executed.
        "echo ssh h 'rm -rf /'",
        "grep 'ssh h rm -rf' notes.md",
        "git commit -m \"fix ssh 'rm -rf' handling\"",
        "rsync -e 'ssh -p 22' src/ host:/dst/",
        // Interactive/relatives.
        "ssh h",
        "ssh -V",
        "ssh-keygen -t ed25519 -f key",
        "scp file.txt host:/tmp/",
        // Unmodeled option: extraction bails to the status quo.
        "ssh --fake h 'uptime'",
    ];
    for command in allowed {
        for dialect in DIALECTS {
            let result = evaluate(
                command,
                &["database.postgresql", "database.sqlite"],
                dialect,
            );
            assert!(
                result.is_allowed(),
                "{command:?} must be allowed under {dialect:?}, got {result:?}"
            );
        }
    }
}

/// Dynamic payload pieces get the same treatment the local spelling gets: a
/// dynamic rm target is denied, a bare variable command is (like local `$CMD`)
/// out of static reach.
#[test]
fn dynamic_payload_parity_with_local_treatment() {
    for dialect in DIALECTS {
        let result = evaluate("ssh h \"rm -rf $DIR\"", &[], dialect);
        assert!(
            result.is_denied(),
            "dynamic rm target must stay denied under {dialect:?}, got {result:?}"
        );
        let result = evaluate("ssh $HOST 'rm -rf /srv/data'", &[], dialect);
        assert!(
            result.is_denied(),
            "dynamic destination must not hide the payload under {dialect:?}, got {result:?}"
        );
    }
}
