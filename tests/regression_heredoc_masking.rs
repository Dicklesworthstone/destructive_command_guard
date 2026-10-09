#[cfg(test)]
#[allow(clippy::uninlined_format_args)]
mod tests {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use destructive_command_guard::heredoc::{
        is_non_executing_heredoc_command, mask_non_executing_heredocs,
    };
    use destructive_command_guard::{Config, evaluator::evaluate_detailed};

    #[test]
    fn test_grep_argument_masking() {
        // "grep" is a non-executing command
        assert!(is_non_executing_heredoc_command("grep"));

        // Case 1: Simple grep
        // grep reads from stdin (heredoc), pattern provided as arg
        let cmd = "grep pattern <<EOF\nrm -rf /\nEOF";
        let masked = mask_non_executing_heredocs(cmd);
        // Should be masked because grep is non-executing.
        // For heredocs, masking replaces content with spaces to preserve alignment.
        assert!(
            !masked.contains("rm -rf"),
            "Leaked dangerous content in grep: '{}'",
            masked
        );
        assert!(masked.contains("EOF"), "Should still contain delimiters");

        // Case 2: Grep with dot argument
        // grep pattern . <<EOF
        // Here "." is a file argument, but extract_heredoc_target_command might mistake it for the command
        let cmd_dot = "grep pattern . <<EOF\nrm -rf /\nEOF";
        let masked_dot = mask_non_executing_heredocs(cmd_dot);
        assert!(
            !masked_dot.contains("rm -rf"),
            "Leaked dangerous content in grep with dot arg: '{}'",
            masked_dot
        );
    }

    #[test]
    fn test_cat_filename_masking() {
        // "cat" is non-executing
        assert!(is_non_executing_heredoc_command("cat"));

        // Case 3: cat with a filename that looks like a command
        // "bash" is a known command. If we mistake the argument "bash" for the command,
        // we might think it IS executing (since bash executes input).
        // But the real command is "cat", which is non-executing.
        let cmd_bash_arg = "cat bash <<EOF\nrm -rf /\nEOF";
        let masked_bash = mask_non_executing_heredocs(cmd_bash_arg);
        assert!(
            !masked_bash.contains("rm -rf"),
            "Leaked dangerous content in cat with 'bash' filename: '{}'",
            masked_bash
        );
    }

    #[test]
    fn spx_session_handoff_masks_its_prose_body() {
        let cmd = "spx session handoff <<'EOF'\n\
git worktrees and active sessions restore only selected agents\n\
EOF";
        let masked = mask_non_executing_heredocs(cmd);

        assert!(
            !masked.contains("restore"),
            "spx handoff body is stdin data, not shell: '{masked}'"
        );
        assert!(masked.contains("spx session handoff"));
    }

    #[test]
    fn spx_session_handoff_is_allowed_but_later_shell_still_blocks() {
        let config = Config::default();
        let reported = "spx session handoff <<'EOF'\n\
git worktrees and active sessions restore only selected agents\n\
EOF";
        let allowed = evaluate_detailed(reported, &config);
        assert!(
            allowed.result.is_allowed(),
            "reported stdin prose must be allowed: {:?}",
            allowed.result.pattern_info
        );

        let destructive_after = "spx session handoff <<'EOF'\nnotes\nEOF\ngit restore --worktree .";
        let denied = evaluate_detailed(destructive_after, &config);
        assert!(
            denied.result.is_denied(),
            "only the handoff body is data; later shell must remain protected"
        );
    }

    /// Only the guard receives these strings; no test command is executed.
    fn hook_decision(command: &str) -> (String, String) {
        let temporary = tempfile::tempdir().expect("isolated hook directory");
        let home = temporary.path().join("home");
        std::fs::create_dir_all(&home).expect("isolated home");
        let config = temporary.path().join("config.toml");
        std::fs::write(&config, "[history]\nenabled = false\n").expect("hook config");
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
        .to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
            .env_clear()
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("APPDATA", home.join("appdata"))
            .env("LOCALAPPDATA", home.join("localappdata"))
            .env("TEMP", temporary.path())
            .env("TMP", temporary.path())
            .env("TMPDIR", temporary.path())
            .env("DCG_CONFIG", &config)
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env(
                "DCG_PENDING_EXCEPTIONS_PATH",
                temporary.path().join("pending.jsonl"),
            )
            .env("DCG_SELF_HEAL_HOOK", "0")
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .current_dir(temporary.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start dcg hook");
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(payload.as_bytes())
            .expect("send hook payload");
        let output = child.wait_with_output().expect("hook output");
        assert_eq!(
            output.status.code(),
            Some(0),
            "hook protocol failed for {command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if output.stdout.is_empty() {
            return ("allow".to_string(), String::new());
        }
        let response: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid hook JSON");
        let result = &response["hookSpecificOutput"];
        (
            result["permissionDecision"]
                .as_str()
                .expect("hook decision")
                .to_string(),
            result["ruleId"].as_str().unwrap_or_default().to_string(),
        )
    }

    #[test]
    fn issue_525_prior_reads_are_data_through_real_hook() {
        for command in [
            "sed -n 1p notes.txt && cat >> notes.txt <<'EOF'\n$(ls)\nEOF",
            "sed 's/a\\.b/c/' notes.txt && cat >> notes.txt <<'EOF'\n`ls`\nEOF",
            "sed 's/a\\.b/c/' notes.txt && cat > notes.txt <<'EOF'\n`ls`\nEOF",
            "sed 's/a\\.b/c/' notes.txt && cat >> notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "awk 1 notes.txt && cat >> notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
            "tac notes.txt && cat >> notes.txt <<'EOF'\nrm -rf ~/project\nEOF",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(decision, "allow", "{command:?}: {rule}");
        }
    }

    #[test]
    fn issue_525_postwrite_executors_stay_denied_through_real_hook() {
        for command in [
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nbash x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nchmod +x x.sh && ./x.sh",
            "grep note x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nbash x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<EOF\n$(rm -rf ~/project)\nEOF",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nsed e x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nsed 's/^/ /e' x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nawk '{system($0)}' x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\ntimeout 5 bash x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nsetsid ./x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nstdbuf -o0 sh x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nfind . -name x.sh -exec sh {} \\;",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nssh h bash < x.sh",
            "sed -n 1p x.sh && cat >> x.sh <<'EOF'\nrm -rf ~/project\nEOF\nparallel bash ::: x.sh",
            "cat > x.sh <<'EOF'\nrm -rf ~/project\nEOF\ncat <(bash x.sh)",
            "cat > x.sh <<'EOF'\nrm -rf ~/project\nEOF\ncat > >(bash x.sh)",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(decision, "deny", "must deny {command:?}: {rule}");
            assert!(!rule.is_empty(), "denial must have a rule: {command:?}");
        }
    }

    #[test]
    fn issue_519_written_javascript_arrow_is_not_a_shell_redirect() {
        for command in [
            "cat > /tmp/x/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/x/a.js",
            "cat <<'EOF' > /tmp/x/a.js\nf(u => !x);\nEOF\nnode /tmp/x/a.js",
            "mkdir -p /tmp/x && cat > /tmp/x/a.js <<'EOF'\n[...targets].filter(u => !deleted.includes(u));\nEOF\nnode /tmp/x/a.js",
            "cat > '/tmp/a b.js' <<'EOF'\nf(u => !x);\nEOF\nnode '/tmp/a b.js'",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(decision, "allow", "{command:?}: {rule}");
        }
    }

    #[test]
    fn issue_519_written_programs_receive_language_safety_checks() {
        for (program, body) in [
            (
                "node",
                "require('child_process').spawnSync('rm', ['-rf', '/home/user']);",
            ),
            (
                "node",
                "require('fs').rmSync('/home/user', {recursive: true});",
            ),
            (
                "node",
                "require('fs').writeFileSync('/home/user/.ssh/authorized_keys', 'key');",
            ),
            ("python3", "import shutil\nshutil.rmtree('/home/user')"),
            (
                "python3",
                "import subprocess\nsubprocess.run(['rm', '-rf', '/home/user'])",
            ),
            (
                "python3",
                "open('/home/user/.ssh/authorized_keys', 'w').write('key')",
            ),
            ("ruby", "system('rm', '-rf', '/home/user')"),
            ("perl", "system('rm', '-rf', '/home/user');"),
            ("php", "<?php system('git reset --hard'); ?>"),
        ] {
            let command = format!("cat >/tmp/program <<'EOF'\n{body}\nEOF\n{program} /tmp/program");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "deny",
                "must inspect written program: {command:?}: {rule}"
            );
            assert!(!rule.is_empty(), "denial must name its rule: {command:?}");
        }
    }

    #[test]
    fn issue_519_arrow_exemption_preserves_real_shell_evidence() {
        for command in [
            "cat >/tmp/a.js <<'EOF'\nf(u => !x);\nrequire('child_process').execSync('echo bad > /etc/passwd');\nEOF\nnode /tmp/a.js",
            "cat >/tmp/a.js <<'EOF'\nf(u=>require('child_process').execSync('>$TARGET'));\nEOF\nnode /tmp/a.js",
            "cat >/tmp/a.js <<'EOF'\nconst run = require('child_process').execSync;\nrun('git reset --hard');\nEOF\nnode /tmp/a.js",
            "cat >/tmp/a.js <<'EOF'\nf(u => !x);\nEOF\nnode /tmp/a.js\ngit reset --hard",
            "cat >/tmp/a.js <<EOF\nf(u => !x);\n$(rm -rf /etc)\nEOF\nnode /tmp/a.js",
            "cat >/tmp/a.js <<'EOF'\necho bad > $TARGET\nEOF\nnode /tmp/a.js\nbash /tmp/a.js",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "deny",
                "real shell evidence must survive: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_reported_python_and_node_documentation_strings_are_allowed() {
        for command in [
            "python3 - <<'PY'\ns = \"run `git branch -d x` later\"\nprint(s)\nPY",
            "python3 - <<'PY'\ns = 'run `git branch -d x` later'\nprint(s)\nPY",
            "node - <<'JS'\nconst s = \"run `git branch -d x` later\";\nJS",
            "cat > m.txt <<'EOF'\ns = \"run `git branch -d x` later\"\nEOF",
            "python3 - <<'PY'\ns = \"run `git status` later\"\nprint(s)\nPY",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "allow",
                "language string contents are not shell substitutions: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_python_string_literal_forms_remain_inert() {
        for body in [
            "s = '''run `git branch -d x` later'''\nprint(s)",
            "s = \"\"\"run `git branch -d x` later\nThis is documentation.\"\"\"\nprint(s)",
            "s = r'run `git branch -d x` later'\nprint(s)",
            "s = b'run `git branch -d x` later'\nprint(s)",
            "s = u'run `git branch -d x` later'\nprint(s)",
            "s = f'run `git branch -d x` later'\nprint(s)",
            "s = \"He said \\\"run `git branch -d x` later\\\"\"\nprint(s)",
            "s = 'run ' '`git branch -d x`' ' later'\nprint(s)",
            "\"\"\"run `git branch -d x` later\"\"\"\nprint('documented')",
            "p = 'README.md'\ns = open(p).read()\ns = s.replace('After merging.', '''After merging, run `git checkout main && git pull --ff-only && git branch -d fix/x`.''')\nopen(p, 'w').write(s)",
        ] {
            let command = format!("python3 - <<'PY'\n{body}\nPY");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "allow",
                "inert Python literal must be allowed: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_javascript_string_literal_forms_remain_inert() {
        for body in [
            r#"const s = 'run `git branch -d x` later'; console.log(s);"#,
            r#"const s = "He said \"run `git branch -d x` later\""; console.log(s);"#,
            r#"const s = `run \`git branch -d x\` later`; console.log(s);"#,
            "const s = `run \\`git branch -d x\\` later\nThis is documentation.`;\nconsole.log(s);",
            r#""run `git branch -d x` later"; console.log('documented');"#,
            r#"const fs = require('fs'); const source = fs.readFileSync('README.md', 'utf8'); const edited = source.replace('After merging.', 'After merging, run `git branch -d x`.'); fs.writeFileSync('README.md', edited);"#,
        ] {
            let command = format!("node - <<'JS'\n{body}\nJS");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "allow",
                "inert JavaScript literal must be allowed: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_quoted_delimiters_and_written_programs_keep_language_context() {
        for (program, body) in [
            ("python3", "s = \"run `git branch -d x` later\"\nprint(s)"),
            (
                "node",
                "const s = \"run `git branch -d x` later\";\nconsole.log(s);",
            ),
        ] {
            for delimiter in ["'DOC'", "\"DOC\"", "D\\OC"] {
                let direct = format!("{program} - <<{delimiter}\n{body}\nDOC");
                let written = format!(
                    "cat > /tmp/documentation-program <<{delimiter}\n{body}\nDOC\n{program} /tmp/documentation-program"
                );
                for command in [direct, written] {
                    let (decision, rule) = hook_decision(&command);
                    assert_eq!(
                        decision, "allow",
                        "the proven interpreter must govern its source: {command:?}: {rule}"
                    );
                }
            }
        }
    }

    #[test]
    fn issue_544_dangerous_subprocesses_and_executable_interpolation_stay_denied() {
        for (program, body) in [
            ("python3", "import os\nos.system('git branch -d x')"),
            (
                "python3",
                "import subprocess\nsubprocess.run(['git', 'branch', '-d', 'x'])",
            ),
            (
                "python3",
                "import subprocess\nsubprocess.run('git branch -d x', shell=True)",
            ),
            (
                "python3",
                "import subprocess\nsubprocess.run(['rm', '-rf', '/home/user/project'])",
            ),
            (
                "python3",
                "import os\ns = 'echo `git branch -d x`'\nos.system(s)",
            ),
            (
                "python3",
                "s = f\"run `git branch -d x` later {__import__('os').system('git reset --hard')}\"\nprint(s)",
            ),
            (
                "node",
                "require('child_process').execSync('git branch -d x');",
            ),
            (
                "node",
                "require('child_process').spawnSync('rm', ['-rf', '/home/user/project']);",
            ),
            (
                "node",
                "const s = 'echo `git branch -d x`';\nrequire('child_process').execSync(s);",
            ),
            (
                "node",
                r#"const s = `run \`git branch -d x\` later ${require('child_process').execSync('git reset --hard')}`; console.log(s);"#,
            ),
        ] {
            for command in [
                format!("{program} - <<'DOC'\n{body}\nDOC"),
                format!(
                    "cat > /tmp/executed-program <<'DOC'\n{body}\nDOC\n{program} /tmp/executed-program"
                ),
            ] {
                let (decision, rule) = hook_decision(&command);
                assert_eq!(
                    decision, "deny",
                    "executed code must remain protected: {command:?}: {rule}"
                );
                assert!(
                    !rule.is_empty(),
                    "denial must identify its rule: {command:?}"
                );
            }
        }
    }

    #[test]
    fn issue_544_opaque_calls_and_rebound_data_sinks_are_not_exempted() {
        for (program, body) in [
            ("python3", "from helper import run\nrun('git branch -d x')"),
            (
                "python3",
                "from helper import run\ns = 'echo `git branch -d x`'\nrun(s)",
            ),
            (
                "python3",
                "print = __import__('os').system\nprint('git branch -d x')",
            ),
            (
                "python3",
                "import os\ns = 'git branch -d x'\nexec('os.system(s)')",
            ),
            ("node", "require('./helper')('git branch -d x');"),
            (
                "node",
                "const run = require('./helper');\nconst s = 'echo `git branch -d x`';\nrun(s);",
            ),
            (
                "node",
                "console.log = require('child_process').execSync;\nconsole.log('git branch -d x');",
            ),
            (
                "node",
                "const s = 'git branch -d x';\neval(\"require('child_process').execSync(s)\");",
            ),
        ] {
            let command = format!("{program} - <<'DOC'\n{body}\nDOC");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "deny",
                "an unproven call can execute its string: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_outer_shell_expansion_and_later_commands_remain_protected() {
        for command in [
            "python3 - <<PY\ns = \"run `git branch -d x` later\"\nprint(s)\nPY",
            "node - <<JS\nconst s = 'run `git branch -d x` later';\nJS",
            "python3 - <<PY\ns = r'$(git reset --hard)'\nprint(s)\nPY",
            "python3 - <<'PY'\ns = \"run `git branch -d x` later\"\nprint(s)\nPY\ngit branch -d x",
            "node - <<'JS'\nconst s = \"run `git branch -d x` later\";\nJS\ngit reset --hard",
            "sh <<'PY'\ns = \"run `git branch -d x` later\"\nPY",
            "cat <<'PY' | sh\ns = \"run `git branch -d x` later\"\nPY",
            "python3 - <<'PY' | sh\nprint('git branch -d x')\nPY",
            "node - <<'JS' | sh\nconsole.log('git branch -d x');\nJS",
            "unknown-interpreter - <<'PY'\ns = \"run `git branch -d x` later\"\nPY",
            "python3() { sh -s; }; python3 - <<'PY'\ns = \"run `git branch -d x` later\"\nPY",
            "node() { sh -s; }; node - <<'JS'\nconst s = \"run `git branch -d x` later\";\nJS",
            "python3 - <<'PY'\nopen('m.sh', 'w').write('git branch -d x')\nPY\nsh m.sh",
            "node - <<'JS'\nrequire('fs').writeFileSync('m.sh', 'git branch -d x');\nJS\nsh m.sh",
            "python3 - <<'PY'\nopen('m.sh', 'w').write('echo `git branch -d x`')\nPY\nsh m.sh",
            "node - <<'JS'\nrequire('fs').writeFileSync('m.sh', 'echo `git branch -d x`');\nJS\nsh m.sh",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "deny",
                "shell or unknown execution must remain visible: {command:?}: {rule}"
            );
        }
    }
}
