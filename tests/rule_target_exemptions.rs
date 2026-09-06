//! Per-rule TARGET-PATH exemptions (#284).
//!
//! Agent runtimes give each job a scratch directory under `$HOME`
//! (`~/.claude/jobs/<id>/tmp`), and the top fleet denial sources are agents
//! writing their own logs there. `[rules."<pack>:<pattern>"] exempt_target_globs`
//! lets one rule stand down for those targets without becoming a whole-command
//! bypass.
//!
//! Every case here drives the real hook binary with an isolated `HOME`, so the
//! `~` in both the command and the glob resolves inside a temp dir.

use std::path::{Path, PathBuf};
use std::process::Command;

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

struct Sandbox {
    _temp: tempfile::TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    project: PathBuf,
}

impl Sandbox {
    /// A sandbox whose user config carries `config_toml` (empty = no config).
    fn new(config_toml: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let xdg_config = temp.path().join("xdg_config");
        let project = temp.path().join("project");
        std::fs::create_dir_all(home.join(".claude/jobs/abc/tmp")).unwrap();
        std::fs::create_dir_all(home.join(".claude/jobs/abc/nested/tmp")).unwrap();
        std::fs::create_dir_all(project.join(".git")).unwrap();
        // Every redirect target these cases use must EXIST: a truncating
        // redirect to an absent literal file is creation and stands the rule
        // down before any exemption is consulted (#337, #390), so only an
        // existing target exercises `exempt_target_globs` at all.
        for existing in [
            ".claude/jobs/abc/tmp/log",
            ".claude/jobs/abc/nested/tmp/log",
            ".claude/jobs/abc/config",
            ".bashrc",
        ] {
            std::fs::write(home.join(existing), b"keep").unwrap();
        }
        let user_config_dir = xdg_config.join("dcg");
        std::fs::create_dir_all(&user_config_dir).unwrap();
        if !config_toml.is_empty() {
            std::fs::write(user_config_dir.join("config.toml"), config_toml).unwrap();
        }
        Self {
            _temp: temp,
            home,
            xdg_config,
            project,
        }
    }

    /// Write an automatically discovered repository config in the project root.
    fn write_project_config(&self, contents: &str) {
        std::fs::write(self.project.join(".dcg.toml"), contents).unwrap();
    }

    fn home(&self) -> &Path {
        &self.home
    }

    /// Run `command` through the hook and return combined stdout+stderr.
    fn run(&self, command: &str) -> String {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": command },
        });

        let mut child = Command::new(dcg_binary())
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
            .env_remove("DCG_CONFIG")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn dcg");

        {
            let stdin = child.stdin.as_mut().expect("failed to open stdin");
            serde_json::to_writer(stdin, &input).expect("failed to write json");
        }

        let output = child.wait_with_output().expect("failed to wait for dcg");
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

fn assert_allowed(output: &str, context: &str) {
    assert!(
        !output.contains("\"permissionDecision\": \"deny\"") && !output.contains("\"deny\""),
        "{context}: expected an allow, got: {output}"
    );
}

fn assert_denied(output: &str, context: &str) {
    assert!(
        output.contains("deny"),
        "{context}: expected a denial, got: {output}"
    );
}

const REDIRECT_EXEMPTION: &str = r#"
[packs]
enabled = ["core"]

[rules."core.filesystem:redirect-truncate-root-home"]
exempt_target_globs = ["~/.claude/jobs/*/tmp/**"]
"#;

// `rm -rf ~/...` is attributed to `rm-rf-root-home`, not `rm-rf-general`: every
// `~`-rooted path is Critical root/home in the rm classifier. The exemption is
// configured for the rule that actually fires.
const RM_EXEMPTION: &str = r#"
[packs]
enabled = ["core"]

[rules."core.filesystem:rm-rf-root-home"]
exempt_target_globs = ["~/.claude/jobs/*/tmp/**"]
"#;

// `rm-rf-general` covers the non-root/home shapes, such as a relative path.
const RM_GENERAL_EXEMPTION: &str = r#"
[packs]
enabled = ["core"]

[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["build/scratch/**"]
"#;

const NO_EXEMPTION: &str = r#"
[packs]
enabled = ["core"]
"#;

// ---------------------------------------------------------------------------
// Acceptance: the configured rule stands down for a literal scratch target.
// ---------------------------------------------------------------------------

#[test]
fn redirect_truncate_root_home_allows_exempt_scratch_target() {
    let sandbox = Sandbox::new(REDIRECT_EXEMPTION);
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/tmp/log");
    assert_allowed(&output, "exempt redirect target");
}

#[test]
fn redirect_truncate_root_home_denies_scratch_target_without_config() {
    let sandbox = Sandbox::new(NO_EXEMPTION);
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/tmp/log");
    assert_denied(&output, "unconfigured redirect target");
}

#[test]
fn redirect_exemption_matches_expanded_home_spelling() {
    let sandbox = Sandbox::new(REDIRECT_EXEMPTION);
    // The glob is written with `~`; the command spells the same path out in
    // full. Both normalize to the same literal text.
    let target = sandbox
        .home()
        .join(".claude/jobs/abc/tmp/log")
        .to_string_lossy()
        .into_owned();
    let output = sandbox.run(&format!("echo x > {target}"));
    assert_allowed(&output, "expanded-home redirect target");
}

#[test]
fn rm_rf_root_home_allows_exempt_scratch_target() {
    let sandbox = Sandbox::new(RM_EXEMPTION);
    let output = sandbox.run("rm -rf ~/.claude/jobs/abc/tmp/scratch");
    assert_allowed(&output, "exempt rm target");
}

#[test]
fn rm_rf_root_home_denies_scratch_target_without_config() {
    let sandbox = Sandbox::new(NO_EXEMPTION);
    let output = sandbox.run("rm -rf ~/.claude/jobs/abc/tmp/scratch");
    assert_denied(&output, "unconfigured rm target");
}

#[test]
fn rm_rf_general_allows_exempt_relative_target() {
    let sandbox = Sandbox::new(RM_GENERAL_EXEMPTION);
    let output = sandbox.run("rm -rf build/scratch/out");
    assert_allowed(&output, "exempt relative rm target");
}

#[test]
fn rm_rf_general_denies_relative_target_without_config() {
    let sandbox = Sandbox::new(NO_EXEMPTION);
    let output = sandbox.run("rm -rf build/scratch/out");
    assert_denied(&output, "unconfigured relative rm target");
}

#[test]
fn rm_rf_general_glob_does_not_exempt_the_root_home_rule() {
    // A relative-path exemption on `rm-rf-general` must not carry over to the
    // Critical `rm-rf-root-home` rule.
    let sandbox = Sandbox::new(RM_GENERAL_EXEMPTION);
    let output = sandbox.run("rm -rf ~/.claude/jobs/abc/tmp/scratch");
    assert_denied(&output, "general glob leaking into the root/home rule");
}

// ---------------------------------------------------------------------------
// Planted negatives: an exemption is rule-scoped, never a command-level bypass.
// ---------------------------------------------------------------------------

#[test]
fn exempt_redirect_does_not_launder_a_destructive_suffix() {
    let sandbox = Sandbox::new(REDIRECT_EXEMPTION);
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/tmp/log && git reset --hard");
    assert_denied(&output, "git suffix behind an exempt redirect");
}

#[test]
fn exempt_rm_does_not_launder_a_destructive_suffix() {
    let sandbox = Sandbox::new(RM_EXEMPTION);
    let output = sandbox.run("rm -rf ~/.claude/jobs/abc/tmp/scratch && git reset --hard");
    assert_denied(&output, "git suffix behind an exempt rm");
}

#[test]
fn dynamic_redirect_target_is_never_exempted() {
    // `redirect-truncate-dynamic-path` exists precisely because the runtime
    // target is unprovable, and it supports no exemptions. Configuring both
    // rules must not help.
    let sandbox = Sandbox::new(
        r#"
[packs]
enabled = ["core"]

[rules."core.filesystem:redirect-truncate-root-home"]
exempt_target_globs = ["~/.claude/jobs/*/tmp/**", "**"]

[rules."core.filesystem:redirect-truncate-dynamic-path"]
exempt_target_globs = ["**"]
"#,
    );
    let output = sandbox.run("echo x > $DIR/log");
    assert_denied(&output, "dynamic redirect target");
}

#[test]
fn traversal_out_of_the_exempt_subtree_is_denied() {
    let sandbox = Sandbox::new(RM_EXEMPTION);
    let output = sandbox.run("rm -rf ~/.claude/jobs/abc/tmp/../../../Documents");
    assert_denied(&output, "`..` traversal out of the exempt subtree");
}

#[test]
fn traversal_out_of_the_exempt_redirect_subtree_is_denied() {
    let sandbox = Sandbox::new(REDIRECT_EXEMPTION);
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/tmp/../../../../.bashrc");
    assert_denied(&output, "`..` traversal out of the exempt redirect subtree");
}

#[test]
fn one_rules_glob_does_not_exempt_another_rules_target() {
    // The glob is configured for the rm rule only; the redirect rule must
    // still fire on the very same path.
    let sandbox = Sandbox::new(RM_EXEMPTION);
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/tmp/log");
    assert_denied(&output, "rm glob leaking into the redirect rule");
}

#[test]
fn a_second_unexempt_target_keeps_the_rule_firing() {
    let sandbox = Sandbox::new(RM_EXEMPTION);
    let output = sandbox.run("rm -rf ~/.claude/jobs/abc/tmp/scratch ~/.ssh");
    assert_denied(&output, "mixed exempt and unexempt rm targets");
}

#[test]
fn a_path_outside_the_glob_is_denied() {
    let sandbox = Sandbox::new(REDIRECT_EXEMPTION);
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/config");
    assert_denied(&output, "sibling path outside the exempt subtree");
}

#[test]
fn single_star_does_not_cross_a_separator() {
    let sandbox = Sandbox::new(REDIRECT_EXEMPTION);
    // `jobs/*/tmp` must not match `jobs/a/b/tmp`.
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/nested/tmp/log");
    assert_denied(&output, "`*` crossing a path separator");
}

// ---------------------------------------------------------------------------
// Trust boundary: an exemption reduces coverage, so a repository may not grant
// itself one.
// ---------------------------------------------------------------------------

#[test]
fn exemption_from_an_automatic_project_config_is_ignored() {
    let sandbox = Sandbox::new(NO_EXEMPTION);
    sandbox.write_project_config(REDIRECT_EXEMPTION);
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/tmp/log");
    assert_denied(&output, "exemption smuggled in via .dcg.toml");
}

#[test]
fn rm_exemption_from_an_automatic_project_config_is_ignored() {
    let sandbox = Sandbox::new(NO_EXEMPTION);
    sandbox.write_project_config(RM_EXEMPTION);
    let output = sandbox.run("rm -rf ~/.claude/jobs/abc/tmp/scratch");
    assert_denied(&output, "rm exemption smuggled in via .dcg.toml");
}

// ---------------------------------------------------------------------------
// Unsupported-rule warning: an inert exemption must not leave the user guessing.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Output honesty: a suppressed rule is an allow, and it says so.
// ---------------------------------------------------------------------------

#[test]
fn explain_reports_the_suppressing_glob() {
    let sandbox = Sandbox::new(REDIRECT_EXEMPTION);
    let output = Command::new(dcg_binary())
        .current_dir(&sandbox.project)
        .args(["explain", "echo x > ~/.claude/jobs/abc/tmp/log"])
        .env("HOME", &sandbox.home)
        .env("USERPROFILE", &sandbox.home)
        .env("XDG_CONFIG_HOME", &sandbox.xdg_config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
        .env_remove("DCG_CONFIG")
        .output()
        .expect("failed to run dcg explain");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();

    assert!(
        text.contains("core.filesystem:redirect-truncate-root-home"),
        "explain should name the suppressed rule, got: {text}"
    );
    assert!(
        text.contains("was exempted by") && text.contains("~/.claude/jobs/*/tmp/**"),
        "explain should name the suppressing glob, got: {text}"
    );
}

#[test]
fn verbose_hook_notes_the_suppression_on_stderr() {
    let sandbox = Sandbox::new(
        r#"
[general]
verbose = true

[packs]
enabled = ["core"]

[rules."core.filesystem:redirect-truncate-root-home"]
exempt_target_globs = ["~/.claude/jobs/*/tmp/**"]
"#,
    );
    let output = sandbox.run("echo x > ~/.claude/jobs/abc/tmp/log");
    assert!(
        output.contains("matched but target") && output.contains("is exempted by"),
        "verbose mode should note the suppression, got: {output}"
    );
}

#[test]
fn doctor_warns_when_a_rule_does_not_support_target_exemptions() {
    let sandbox = Sandbox::new(
        r#"
[packs]
enabled = ["core"]

[rules."core.git:reset-hard"]
exempt_target_globs = ["~/scratch/**"]
"#,
    );

    let output = Command::new(dcg_binary())
        .current_dir(&sandbox.project)
        .arg("doctor")
        .env("HOME", &sandbox.home)
        .env("USERPROFILE", &sandbox.home)
        .env("XDG_CONFIG_HOME", &sandbox.xdg_config)
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "/nonexistent")
        .env_remove("DCG_CONFIG")
        .output()
        .expect("failed to run dcg doctor");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        text.contains("does not support target exemptions"),
        "doctor should warn about an inert exemption, got: {text}"
    );
    assert!(
        text.contains("core.git:reset-hard"),
        "the warning should name the offending rule, got: {text}"
    );
}
