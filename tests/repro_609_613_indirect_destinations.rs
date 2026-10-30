//! #609 / #613: shell indirection must not conceal protected destinations.
//!
//! Every source string is data sent to the real CLI and batch hook. The only
//! commands executed by the fixture are Git repository/worktree setup and
//! read-only queries used to establish the linked-worktree controls.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CREDENTIAL: &str = "core.filesystem:credential-file-write";
const GIT_WRITE: &str = "core.filesystem:git-internals-write";
const GIT_APPEND: &str = "core.filesystem:redirect-append-git-internals-relative";
const GIT_TRUNCATE: &str = "core.filesystem:redirect-truncate-git-internals-relative";
const GRANT_REASON: &str = "isolated indirect-destination rule grant";

struct Fixture {
    directory: tempfile::TempDir,
    home: PathBuf,
    config: PathBuf,
    cwd: PathBuf,
    executable_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("isolated regression directory");
        let home = directory.path().join("home");
        let cwd = directory.path().join("cwd");
        let executable_dir = directory.path().join("executables");
        for path in [&home, &cwd, &executable_dir] {
            std::fs::create_dir(path).expect("isolated directory");
        }
        let config = directory.path().join("config.toml");
        std::fs::write(&config, "[history]\nenabled = false\n").expect("isolated config");
        Self {
            directory,
            home,
            config,
            cwd,
            executable_dir,
        }
    }

    fn grant(&self, rule: &str) {
        let contents = format!("[[allow]]\nrule = \"{rule}\"\nreason = \"{GRANT_REASON}\"\n");
        for relative in ["config/dcg", ".config/dcg", "appdata/dcg"] {
            let directory = self.home.join(relative);
            std::fs::create_dir_all(&directory).expect("allowlist directory");
            std::fs::write(directory.join("allowlist.toml"), &contents)
                .expect("isolated single-rule grant");
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
        command
            .env_clear()
            // A static proof must not require Git, a shell, or another
            // producer executable to be installed on the classifier's PATH.
            .env("PATH", &self.executable_dir)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("APPDATA", self.home.join("appdata"))
            .env("LOCALAPPDATA", self.home.join("localappdata"))
            .env("TEMP", self.directory.path())
            .env("TMP", self.directory.path())
            .env("TMPDIR", self.directory.path())
            .env("DCG_CONFIG", &self.config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                self.directory.path().join("pending.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_NO_SELF_HEAL", "1")
            .env("DCG_HISTORY_DISABLED", "1")
            // Semantic verdicts, not a change to the production budgets.
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .env("DCG_AST_TIMEOUT_MS", "5000")
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn assert(&self, source: &str, expected: &str, rule: Option<&str>, granted: bool) {
        for hook in [false, true] {
            let mut command = self.command();
            let input = if hook {
                command.args(["hook", "--batch"]);
                serde_json::json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": { "command": source },
                })
                .to_string()
                    + "\n"
            } else {
                command.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
                source.to_owned()
            };
            let mut child = command
                .spawn()
                .expect("spawn the classifier, never the source");
            child
                .stdin
                .take()
                .expect("classifier stdin")
                .write_all(input.as_bytes())
                .expect("write classifier input");
            let output = child.wait_with_output().expect("classifier response");
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let json: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                    panic!("{source:?}, hook={hook}: {error}; {stdout}; {stderr}")
                });
            assert_eq!(
                json["decision"], expected,
                "{source:?}, hook={hook}: {json}; {stderr}"
            );
            assert_eq!(
                output.status.code(),
                Some(i32::from(expected == "deny")),
                "{source:?}, hook={hook}: {json}; {stderr}"
            );
            if let Some(rule) = rule {
                assert_eq!(json["rule_id"], rule, "{source:?}, hook={hook}: {json}");
                if !hook {
                    let span = json["matched_span"]
                        .as_array()
                        .expect("native destination finding has an original-source span");
                    let start = usize::try_from(span[0].as_u64().expect("span start"))
                        .expect("span start fits usize");
                    let end = usize::try_from(span[1].as_u64().expect("span end"))
                        .expect("span end fits usize");
                    assert!(
                        start < end && source.get(start..end).is_some(),
                        "the finding must identify bytes in the original command: {source:?}: {json}"
                    );
                }
            }
            if !hook && expected == "allow" {
                if granted {
                    assert_eq!(json["allowlist"]["layer"], "user", "{source:?}: {json}");
                    assert_eq!(
                        json["allowlist"]["reason"], GRANT_REASON,
                        "the control must exercise the grant: {source:?}: {json}"
                    );
                } else {
                    assert!(json["allowlist"].is_null(), "{source:?}: {json}");
                }
            }
        }
    }

    fn deny(&self, source: &str, rule: &str) {
        self.assert(source, "deny", Some(rule), false);
    }

    fn allow(&self, source: &str) {
        self.assert(source, "allow", None, false);
    }

    fn git(&self, cwd: &Path, arguments: &[&str]) -> String {
        let mut command = Command::new("git");
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(cwd)
            .args(arguments);
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        let output = command
            .output()
            .expect("Git for the isolated worktree fixture");
        assert!(
            output.status.success(),
            "fixture git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("Git fixture output is UTF-8")
            .trim_end()
            .to_owned()
    }
}

#[test]
fn reported_scalar_destinations_have_their_literal_rule_identity() {
    let fixture = Fixture::new();
    for source in [
        "echo x | tee -a ~/.ssh/authorized_keys",
        "f=~/.ssh/authorized_keys; echo x | tee -a $f",
        "f=~/.ssh/authorized_keys; echo x >> \"$f\"",
        "f=/etc/sudoers; echo x | tee -a $f",
        "f=/etc/sudoers; echo x | tee -a \"${f}\"",
        "f=~/.ssh/authorized_keys\necho x >> \"${f}\"",
        "f=/etc/sudoers; >> \"$f\"",
        "true && f=/etc/sudoers && tee -a \"$f\"",
        "f=/etc/sudoers; result=$(tee -a \"$f\")",
        "f=/etc/sudoers; export result=$(tee -a \"$f\")",
        "if true; then f=/etc/sudoers; tee -a \"$f\"; fi",
        "f=/etc/sudoers; while tee \"$f\"; do break; done",
        "f=/etc/sudoers; until tee \"$f\"; do break; done",
    ] {
        fixture.deny(source, CREDENTIAL);
    }
}

#[test]
fn scalar_destinations_reach_every_existing_native_writer() {
    let fixture = Fixture::new();
    for writer in [
        "cp source \"$f\"",
        "mv source \"$f\"",
        "install -m 600 source \"$f\"",
        "ln -sf source \"$f\"",
        "rsync source \"$f\"",
        "dd if=source of=\"$f\"",
        "sed -i 's/x/y/' \"$f\"",
        "perl -i -pe 's/x/y/' \"$f\"",
        "sponge \"$f\"",
        "echo x >> \"$f\"",
        "echo x > \"$f\"",
    ] {
        fixture.deny(&format!("f=/etc/sudoers; {writer}"), CREDENTIAL);
    }
    fixture.deny("d=~/.ssh; cp authorized_keys \"$d/\"", CREDENTIAL);
    fixture.deny("out='of=/etc/sudoers'; dd if=source \"$out\"", CREDENTIAL);
    fixture.deny(
        "option='--target-directory=/etc'; cp sudoers \"$option\"",
        CREDENTIAL,
    );
    fixture.deny(
        "option='--target-directory=/etc';\ncp sudoers \"$opt\\\nion\"",
        CREDENTIAL,
    );
}

#[test]
fn scalar_values_are_snapshots_and_child_scopes_do_not_replace_them() {
    let fixture = Fixture::new();
    for source in [
        "base=/etc; f=\"$base/sudoers\"; tee -a \"$f\"",
        "base=/etc; f=\"${base}/sudoers\"; base=/tmp; tee -a \"$f\"",
        "f=/tmp/out; f=/etc/sudoers; tee -a \"$f\"",
        "f=/etc/sudoers; (f=/tmp/out); tee -a \"$f\"",
        "f=/etc/sudoers; f=/tmp/out & wait; tee -a \"$f\"",
        "f=/etc/sudoers; if true; then f=/tmp/out & wait; tee -a \"$f\"; fi",
        "f=/etc/sudoers; f=/tmp/out tee -a \"$f\"",
        "f=/etc/sudoers; echo x | tee -a \"$f\"",
        "f=/etc; g=\"${f}/sudoers\"; tee -a \"${g}\"",
    ] {
        fixture.deny(source, CREDENTIAL);
    }
    for source in [
        "f=/etc/sudoers; f=/tmp/out; tee -a \"$f\"",
        "f=/tmp/out; (f=/etc/sudoers); tee -a \"$f\"",
        "f=/tmp/out; if true; then f=/etc/sudoers & wait; tee -a \"$f\"; fi",
        "f=/tmp/out; f=/etc/sudoers tee -a \"$f\"",
        "f=/tmp/out; false && f=/etc/sudoers; tee -a \"$f\"",
        "f=/tmp/out; read f; tee -a \"$f\"",
        "f=/etc/sudoers; printf -- '%n' f; tee -a \"$f\"",
        r#"f=/etc/sudoers; printf '%s' "$((f=0))" "$(tee "$f")""#,
        r#"f=/etc/sudoers; for x in "$((f=0))" "$(tee "$f")"; do :; done"#,
        r#"f=/etc/sudoers; case "$((f=0))$(tee "$f")" in *) :;; esac"#,
    ] {
        fixture.allow(source);
    }
}

#[test]
fn quoted_data_reads_and_benign_scalar_destinations_keep_their_behavior() {
    let fixture = Fixture::new();
    for source in [
        "f=/tmp/notes.txt; echo x | tee -a \"$f\"",
        "f='/tmp/notes with spaces.txt'; tee -a \"$f\"",
        "f=~/.ssh/../notes.txt; tee -a \"$f\"",
        "f=~/.ssh/known_hosts; tee -a \"$f\"",
        "f=~/.ssh/known_hosts; echo x >> \"$f\"",
        "f=~/.ssh/id_ed25519.pub; tee \"$f\"",
        "f=/etc/sudoers; tee -a '$f'",
        "f=/etc/sudoers; tee -a \\$f",
        "f=/etc/sudoers; cat \"$f\"",
        "f=/etc/sudoers; chmod 600 \"$f\"",
        "f=/etc/sudoers; cp \"$f\" /tmp/backup",
        "f=/tmp/out; while tee \"$f\"; do break; done",
        "f=/tmp/out; until tee \"$f\"; do break; done",
        "option='--target-directory=/tmp'; cp /etc/sudoers \"$option\"",
        "f='$(git rev-parse --git-dir)/config'; printf '%s' \"$f\"",
        "printf '%s' 'f=/etc/sudoers; tee -a $f'",
    ] {
        fixture.allow(source);
    }
}

#[test]
fn unresolved_option_fields_do_not_turn_protected_sources_into_destinations() {
    let fixture = Fixture::new();
    for source in [
        "f=/etc/sudoers; options='-t /tmp'; cp $options \"$f\"",
        "f=/etc/sudoers; options='--target-directory /tmp'; cp $options \"$f\"",
        "f=~/.ssh/authorized_keys; options='-t /tmp'; install $options \"$f\"",
        "options='-t /tmp'; d=$(git rev-parse --git-dir); cp $options \"$d/config\"",
        "f=/etc/sudoers; sudo -- cp \"$unknown\" \"$f\"",
    ] {
        fixture.allow(source);
    }
    // Unknown argv cannot conceal an independently resolved shell redirect.
    fixture.deny(
        "f=/etc/sudoers; options='-t /tmp'; cp $options source >> \"$f\"",
        CREDENTIAL,
    );
    // After the writer's own option terminator, quoted unknown scalars keep
    // one operand each and cannot change a later proved destination's role.
    for source in [
        "f=/etc/sudoers; cp -- \"$unknown_source\" \"$f\"",
        "f=/etc/sudoers; tee -- \"$unknown\" \"$f\"",
        "f=/etc/sudoers; sudo -- cp -- \"$unknown_source\" \"$f\"",
    ] {
        fixture.deny(source, CREDENTIAL);
    }
}

#[test]
fn complete_scalar_fields_keep_splitting_and_command_name_semantics() {
    let fixture = Fixture::new();
    for source in [
        "f=/etc/sudoers; empty=; tee $empty \"$f\"",
        "f=/etc/sudoers; empty=; tee ${empty} \"$f\"",
        "empty=; f=/etc/sudoers; tee $empty\"$f\"",
        "empty=; f=/etc/sudoers; tee $empty${empty} \"$f\"",
        "files='/tmp/out /etc/sudoers'; tee $files",
        "options='-t /etc'; cp $options sudoers",
        "v='a b'; f=/etc/sudoers; X=$v tee \"$f\"",
    ] {
        fixture.deny(source, CREDENTIAL);
    }
    for source in [
        "files='/tmp/out /etc/sudoers'; tee \"$files\"",
        "empty=; f=/tmp/out; tee \"$empty\" \"$f\"",
        "runner='x=y'; f=/etc/sudoers; $runner tee \"$f\"",
        "runner='x=y'; f=/etc/sudoers; \"$runner\" tee \"$f\"",
        "runner=if; f=/etc/sudoers; $runner tee \"$f\"",
        "runner='!'; f=/etc/sudoers; $runner tee \"$f\"",
    ] {
        fixture.allow(source);
    }
}

#[test]
fn heredoc_data_and_process_substitution_arguments_preserve_execution_boundaries() {
    let fixture = Fixture::new();
    for source in [
        "f=/etc/sudoers; tee /tmp/out <<'DATA'\n\"$f\"\nDATA",
        "f=/etc/sudoers; cat <<'DATA'\n> \"$f\"\nDATA",
        "f=/etc/sudoers; tee /tmp/out <<DATA\n$f\nDATA",
        "f=/tmp/out; tee \"$f\" <<'DATA'\n/etc/sudoers\nDATA",
        "f=/etc/sudoers; cat <<'DATA'\n$(tee -a \"$f\")\nDATA",
        "f=/etc/sudoers; { :; } <<'DATA'\n$(tee -a \"$f\")\nDATA",
        "f=/etc/sudoers; { f=/tmp/out; cat <<'INNER' | tee \"$f\"\ndata\nINNER\n} <<'OUTER'\ndata\nOUTER",
        "f=/etc/sudoers; tee /tmp/out <(printf '%s' \"$f\")",
    ] {
        fixture.allow(source);
    }
    for source in [
        "f=/etc/sudoers; tee -a \"$f\" <<'DATA'\nordinary input\nDATA",
        "f=/etc/sudoers; cat <<DATA\n$(tee -a \"$f\")\nDATA",
        "f=/etc/sudoers; cat <<'DATA' | tee -a \"$f\"\nordinary input\nDATA",
        "f=/etc/sudoers; { :; } <<DATA\n$(tee -a \"$f\")\nDATA",
        "f=/etc/sudoers; unused=x <<DATA\n$(tee -a \"$f\")\nDATA",
    ] {
        fixture.deny(source, CREDENTIAL);
    }
}

#[test]
fn git_admin_queries_and_bound_values_reach_native_writer_rules() {
    let fixture = Fixture::new();
    for source in [
        "cp source .git/config",
        "cp source \"$(git rev-parse --git-dir)/config\"",
        "cp source \"$(git rev-parse --quiet --git-dir)/config\"",
        "cp source \"$(git rev-parse --git-dir --path-format=absolute)/config\"",
        "cp source $(git rev-parse --git-dir)/config",
        "cp source \"`git rev-parse --git-dir`/config\"",
        "cp source \"$(git rev-parse --absolute-git-dir)/config\"",
        "cp source \"$(git -C /r rev-parse --git-common-dir)/hooks/pre-commit\"",
        "cp source \"$(git rev-parse --git-path hooks)/pre-commit\"",
        "cp source \"$(git rev-parse --git-path hooks/pre-commit)\"",
        "cp source \"$(git rev-parse --git-path config)\"",
        "cp source \"$(git rev-parse --git-path HEAD)\"",
        "cp source \"$(git rev-parse --git-path index)\"",
        "cp source \"$(git rev-parse --git-path config.worktree)\"",
        "cp source \"$(git rev-parse --git-path config.lock)\"",
        "cp config \"$(git rev-parse --git-dir)\"",
        "cp pre-commit \"$(git rev-parse --git-path hooks)\"",
        "dd if=source of=\"$(git rev-parse --git-path config)\"",
        "cp source \"$(git -c core.hooksPath=/tmp/hooks rev-parse --git-path hooks/pre-commit)\"",
        "cp source \"$(git -c core.hooksPath='/tmp/hooks /tmp/notes' rev-parse --git-path hooks)\"",
        "cp source \"$(git -c core.hooksPath='/tmp/dcg-hooks*' rev-parse --git-path hooks)\"",
        "cp source \"$(git -c core.hooksPath=/tmp/hooks rev-parse --git-path ./hooks/../config)\"",
        "cp source \"$(git rev-parse --git-dir)/hooks/../config\"",
        "cp source \"$(git rev-parse --git-path hooks)/sub/../pre-commit\"",
        "d=$(git rev-parse --git-dir); cp source \"$d/config\"",
        "d=$(git rev-parse --git-common-dir); f=\"$d/config\"; tee -a \"$f\"",
        "if true; then cp source \"$(git rev-parse --git-dir)/config\"; fi",
        "for item in one; do cp source \"$(git rev-parse --git-dir)/config\"; done",
        "read unused; cp source \"$(git rev-parse --git-dir)/config\"",
    ] {
        fixture.deny(source, GIT_WRITE);
    }
    for writer in [
        "tee -a",
        "install -m 755 source",
        "ln -sf source",
        "rsync source",
    ] {
        fixture.deny(
            &format!("{writer} \"$(git rev-parse --git-path hooks)/pre-commit\""),
            GIT_WRITE,
        );
    }
}

#[test]
fn git_redirects_keep_separate_append_and_truncate_identities() {
    let fixture = Fixture::new();
    for (operator, rule) in [(">>", GIT_APPEND), (">", GIT_TRUNCATE)] {
        for target in [
            "\"$(git rev-parse --git-dir)/config\"",
            "\"$(git rev-parse --git-path hooks)/pre-commit\"",
        ] {
            fixture.deny(&format!("printf x {operator} {target}"), rule);
        }
        fixture.deny(
            &format!("d=$(git rev-parse --git-dir); printf x {operator} \"$d/config\""),
            rule,
        );
    }
}

#[test]
fn ordinary_queries_traversal_and_literal_query_text_are_not_git_destinations() {
    let fixture = Fixture::new();
    for source in [
        "cp source \"$(git rev-parse --show-toplevel)/notes.txt\"",
        "cp source \"$(pwd)/notes.txt\"",
        "cp source \"$(git rev-parse --git-path ../notes.txt)\"",
        "cp source \"$(git rev-parse --git-path hooks/../notes.txt)\"",
        "cp source \"$(git rev-parse --git-path hooks)/../notes.txt\"",
        "cp source \"$(git -c core.hooksPath=/tmp/dcg-hooks rev-parse --path-format=absolute --git-path hooks/a/..)\"notes",
        "cp source $(git -c core.hooksPath='/tmp/hooks /tmp/notes' rev-parse --git-path hooks)",
        "cp source $(git -c core.hooksPath='/tmp/dcg-hooks*' rev-parse --git-path hooks)",
        "cp source '$(git rev-parse --git-dir)/config'",
        "cp source '`git rev-parse --git-dir`/config'",
        "d='$(git rev-parse --git-dir)'; cp source \"$d/config\"",
        "d=$(git rev-parse --show-toplevel); cp source \"$d/notes.txt\"",
        "d=$(git rev-parse --git-dir); cat \"$d/config\"",
        "git config user.name example",
    ] {
        fixture.allow(source);
    }
    // Single quotes inside the command substitution retain a backslash and
    // newline as argument data, even within an outer double-quoted word.
    let source = format!(
        "cp -- source \"$(git rev-parse '--git-di{}\nr')/config\"",
        '\\'
    );
    fixture.allow(&source);
}

#[test]
fn single_rule_grants_do_not_hide_other_indirect_destination_families() {
    for (grant, control, combined, remaining) in [
        (
            CREDENTIAL,
            "f=/etc/sudoers; tee -a \"$f\"",
            "f=/etc/sudoers; d=$(git rev-parse --git-dir); tee -a \"$f\" \"$d/config\"",
            GIT_WRITE,
        ),
        (
            GIT_WRITE,
            "d=$(git rev-parse --git-dir); tee -a \"$d/config\"",
            "f=/etc/sudoers; d=$(git rev-parse --git-dir); tee -a \"$d/config\" \"$f\"",
            CREDENTIAL,
        ),
        (
            CREDENTIAL,
            "files='/tmp/out /etc/sudoers'; tee $files",
            "files='/tmp/out /etc/sudoers .git/config'; tee $files",
            GIT_WRITE,
        ),
        (
            GIT_WRITE,
            "files='/tmp/out .git/config'; tee $files",
            "files='/tmp/out .git/config /etc/sudoers'; tee $files",
            CREDENTIAL,
        ),
        (
            GIT_APPEND,
            "printf x >> \"$(git rev-parse --git-dir)/config\"",
            "f=/etc/sudoers; printf x >> \"$(git rev-parse --git-dir)/config\"; tee -a \"$f\"",
            CREDENTIAL,
        ),
        (
            GIT_TRUNCATE,
            "printf x > .git/config",
            "printf x > \"$(git rev-parse --git-dir)/config\" >> \"$(git rev-parse --git-path hooks)/pre-commit\"",
            GIT_APPEND,
        ),
    ] {
        let fixture = Fixture::new();
        fixture.deny(control, grant);
        fixture.grant(grant);
        fixture.assert(control, "allow", None, true);
        fixture.deny(combined, remaining);
    }
}

#[test]
fn linked_worktrees_and_relocated_hooks_remain_git_administered() {
    let mut fixture = Fixture::new();
    let repository = fixture.directory.path().join("repository");
    std::fs::create_dir(&repository).expect("repository directory");
    let inactive_hooks = fixture.directory.path().join("inactive-hooks");
    std::fs::create_dir(&inactive_hooks).expect("empty fixture hooks directory");
    let inactive_hooks_config = format!("core.hooksPath={}", inactive_hooks.display());
    fixture.git(&repository, &["init", "--quiet", "--initial-branch=main"]);
    fixture.git(
        &repository,
        &[
            "-c",
            "user.name=dcg regression",
            "-c",
            "user.email=dcg-regression@example.invalid",
            "-c",
            &inactive_hooks_config,
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "isolated worktree fixture",
        ],
    );
    let worktree = fixture.directory.path().join("linked");
    fixture.git(
        &repository,
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            worktree.to_str().expect("UTF-8 worktree path"),
            "HEAD",
        ],
    );
    assert!(
        worktree.join(".git").is_file(),
        "linked .git is a pointer file"
    );
    let hooks = fixture.directory.path().join("relocated-hooks");
    std::fs::create_dir(&hooks).expect("relocated hooks directory");
    fixture.git(
        &repository,
        &[
            "config",
            "core.hooksPath",
            hooks.to_str().expect("UTF-8 hooks path"),
        ],
    );
    let hook_path = hooks.join("pre-commit");
    std::fs::write(&hook_path, "fixture hook, never executed\n").expect("hook sentinel");
    let resolved = fixture.git(&worktree, &["rev-parse", "--git-path", "hooks/pre-commit"]);
    assert_eq!(Path::new(&resolved), hook_path);
    let config_path = repository.join(".git/config");
    let config_before = std::fs::read(&config_path).expect("fixture Git config");
    let hook_before = std::fs::read(&hook_path).expect("fixture hook");
    fixture.cwd = worktree;
    for source in [
        "cp source \"$(git rev-parse --git-dir)/config\"",
        "cp source \"$(git rev-parse --git-common-dir)/config\"",
        "cp source \"$(git rev-parse --git-path hooks)/pre-commit\"",
        "cp source \"$(git rev-parse --git-path hooks/pre-commit)\"",
    ] {
        fixture.deny(source, GIT_WRITE);
    }
    fixture.allow("cp source \"$(git rev-parse --show-toplevel)/notes.txt\"");
    assert_eq!(
        std::fs::read(config_path).expect("Git config after classification"),
        config_before
    );
    assert_eq!(
        std::fs::read(hook_path).expect("hook after classification"),
        hook_before
    );
}

#[cfg(unix)]
#[test]
fn recognized_git_queries_are_never_executed_by_destination_analysis() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let sentinel = fixture.directory.path().join("git-query-was-executed");
    let executable = fixture.executable_dir.join("git");
    let quoted_sentinel = shell_words::quote(sentinel.to_str().expect("UTF-8 sentinel path"));
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nif [ \"$1\" = rev-parse ] && [ \"$2\" = --git-dir ]; then\n  printf executed > {quoted_sentinel}\n  printf '%s\\n' /tmp/innocent\n  exit 0\nfi\nexit 1\n"
        ),
    )
    .expect("fake Git executable");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("executable fake Git");
    fixture.deny("cp source \"$(git rev-parse --git-dir)/config\"", GIT_WRITE);
    fixture.deny(
        "d=$(git rev-parse --git-dir); tee -a \"$d/config\"",
        GIT_WRITE,
    );
    assert!(
        !sentinel.exists(),
        "classification executed the query producer"
    );
}
