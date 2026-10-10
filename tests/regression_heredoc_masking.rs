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
        hook_decision_with_allowlist(command, None)
    }

    fn hook_decision_with_allowlist(command: &str, allowed_rule: Option<&str>) -> (String, String) {
        let temporary = tempfile::tempdir().expect("isolated hook directory");
        let home = temporary.path().join("home");
        std::fs::create_dir_all(&home).expect("isolated home");
        let config = temporary.path().join("config.toml");
        std::fs::write(&config, "[history]\nenabled = false\n").expect("hook config");
        if let Some(rule) = allowed_rule {
            let directory = home.join("config").join("dcg");
            std::fs::create_dir_all(&directory).expect("isolated user allowlist directory");
            std::fs::write(
                directory.join("allowlist.toml"),
                format!(
                    "[[allow]]\nrule = \"{rule}\"\nreason = \"reviewed rule ownership fixture\"\n"
                ),
            )
            .expect("isolated user allowlist");
        }
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
    fn issue_540_tee_written_programs_receive_language_safety_checks() {
        // The Python and JavaScript filesystem APIs require their actual
        // language checks; retaining the body as raw shell text is insufficient.
        for (program, body, expected_rule) in [
            (
                "python3",
                "import shutil\nshutil.rmtree('/home/user')",
                "heredoc.python:shutil_rmtree",
            ),
            (
                "node",
                "require('fs').rmSync('/home/user', {recursive: true});",
                "heredoc.javascript:fs_rmsync.catastrophic",
            ),
        ] {
            let command =
                format!("tee /tmp/program <<'EOF' >/dev/null\n{body}\nEOF\n{program} /tmp/program");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(decision, "deny", "{command:?}");
            assert_eq!(
                rule, expected_rule,
                "typed safety check required: {command:?}"
            );
        }
        for (program, body) in [
            (
                "python3",
                "import subprocess\nsubprocess.run(['rm', '-rf', '/home/user'])",
            ),
            (
                "python3",
                "open('/home/user/.ssh/authorized_keys', 'w').write('key')",
            ),
            (
                "node",
                "require('child_process').spawnSync('rm', ['-rf', '/home/user']);",
            ),
            (
                "node",
                "require('fs').writeFileSync('/home/user/.ssh/authorized_keys', 'key');",
            ),
            ("bash", "rm -rf /home/user"),
            ("sh", "git reset --hard"),
            ("ruby", "system('rm', '-rf', '/home/user')"),
            ("perl", "system('rm', '-rf', '/home/user');"),
            ("php", "<?php system('git reset --hard'); ?>"),
        ] {
            let command =
                format!("tee /tmp/program <<'EOF' >/dev/null\n{body}\nEOF\n{program} /tmp/program");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "deny",
                "must inspect the program written by tee: {command:?}: {rule}"
            );
            assert!(!rule.is_empty(), "denial must name its rule: {command:?}");
        }
    }

    #[test]
    fn issue_540_literal_tee_output_paths_keep_their_interpreter_identity() {
        for (writer, consumer) in [
            ("tee /tmp/program.py <<'PY'", "python3 /tmp/program.py"),
            (
                "tee /tmp/program.py >/dev/null <<'PY'",
                "python3 /tmp/program.py",
            ),
            (
                "/usr/bin/tee /tmp/program.py <<'PY' >/dev/null",
                "/usr/bin/python3 /tmp/program.py",
            ),
            (
                "/bin/tee '/tmp/program file.py' 0<<'PY' 1>/dev/null",
                "python3 '/tmp/program file.py'",
            ),
            (
                "tee /tmp/first.py /tmp/second.py <<'PY' >/dev/null",
                "python3 /tmp/first.py",
            ),
            (
                "tee /tmp/first.py /tmp/second.py <<'PY' >/dev/null",
                "python3 /tmp/second.py",
            ),
            (
                "mkdir -p /tmp/scripts && tee /tmp/scripts/program.py <<'PY' >/dev/null",
                "python3 /tmp/scripts/program.py",
            ),
            (
                "mkdir -p /tmp/scripts\ntee /tmp/scripts/program.py <<'PY' >/dev/null",
                "python3 /tmp/scripts/program.py",
            ),
        ] {
            let command =
                format!("{writer}\nimport shutil\nshutil.rmtree('/home/user')\nPY\n{consumer}");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "deny",
                "every literal tee output can become interpreter source: {command:?}: {rule}"
            );
            assert!(!rule.is_empty(), "denial must name its rule: {command:?}");
        }
    }

    #[test]
    fn issue_540_tee_source_identity_preserves_real_execution_evidence() {
        for command in [
            "tee /tmp/a.js <<'EOF' >/dev/null\nf(u => !x);\nrequire('child_process').execSync('echo bad > /etc/passwd');\nEOF\nnode /tmp/a.js",
            "tee /tmp/a.js <<'EOF' >/dev/null\nf(u=>require('child_process').execSync('>$TARGET'));\nEOF\nnode /tmp/a.js",
            "tee /tmp/a.js <<'EOF' >/dev/null\nconst run = require('child_process').execSync;\nrun('git reset --hard');\nEOF\nnode /tmp/a.js",
            "tee /tmp/program.sh <<EOF >/dev/null\n$(rm -rf /home/user)\nEOF\nbash /tmp/program.sh",
            "tee -a /tmp/program.sh <<'EOF' >/dev/null\nrm -rf /home/user\nEOF\nbash /tmp/program.sh",
            "tee --append /tmp/program.sh <<'EOF' >/dev/null\ngit reset --hard\nEOF\nbash /tmp/program.sh",
            "tee /tmp/program.sh <<'EOF' >/dev/null\nrm -rf /home/user\nEOF\nprintf '\\n' >> /tmp/program.sh\nbash /tmp/program.sh",
            "tee /tmp/program.sh <<'EOF' >/dev/null\nrm -rf /home/user\nEOF\nsed -i 's/unused/other/' /tmp/program.sh\nbash /tmp/program.sh",
            "tee /tmp/program.js <<'EOF' >/dev/null\nx=`git reset --hard`\nEOF\nnode /tmp/program.js\nbash /tmp/program.js",
            "tee /tmp/program.sh <<'EOF' >/dev/null\nrm -rf /home/user\nEOF\ntimeout 5 bash /tmp/program.sh",
            "tee /tmp/program.sh <<'EOF' >/dev/null\nrm -rf /home/user\nEOF\ncat /tmp/program.sh | bash",
            "tee /tmp/program.sh <<'EOF' >/dev/null\nrm -rf /home/user\nEOF\nscp /tmp/program.sh /tmp/renamed.sh\nbash /tmp/renamed.sh",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "deny",
                "source classification cannot hide destructive execution: {command:?}: {rule}"
            );
            assert!(!rule.is_empty(), "denial must name its rule: {command:?}");
        }
    }

    #[test]
    fn issue_540_safe_tee_programs_use_their_actual_language() {
        for command in [
            "tee /tmp/program.py <<'PY' >/dev/null\nprint('hello')\nPY\npython3 /tmp/program.py",
            "tee /tmp/program.py <<'PY' >/dev/null\ns = \"run `git branch -d x` later\"\nprint(s)\nPY\npython3 /tmp/program.py",
            "tee /tmp/program.js <<'JS' >/dev/null\nconst s = \"run `git branch -d x` later\";\nconsole.log(s);\nJS\nnode /tmp/program.js",
            "tee /tmp/program.js <<'JS' >/dev/null\nconsole.log([1, 2].map(value => value + 1));\nJS\nnode /tmp/program.js",
            "tee /tmp/first.js /tmp/second.js <<'JS' >/dev/null\nconsole.log([1, 2].map(value => value + 1));\nJS\nnode /tmp/second.js",
            "tee /tmp/program.sh <<'SH' >/dev/null\nprintf hello\nSH\nbash /tmp/program.sh",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "allow",
                "verified tee-written language source must avoid shell false positives: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_540_document_writes_and_data_consumers_remain_allowed() {
        for command in [
            "tee /tmp/example.py <<'EOF' >/dev/null\nimport shutil\nshutil.rmtree('/home/user')\nEOF",
            "tee /tmp/example.js <<'EOF' >/dev/null\nrequire('fs').rmSync('/home/user', {recursive: true});\nEOF",
            "tee notes.md <<'EOF' >/dev/null\nrm -rf /; git reset --hard\nEOF\ncat notes.md",
            "tee notes.md backup.md <<'EOF' >/dev/null\nrm -rf /; git reset --hard\nEOF\nwc -l backup.md",
            "tee -a notes.md <<'EOF' >/dev/null\nrm -rf /; git reset --hard\nEOF\ngit add notes.md && git commit -m docs",
            "tee m.txt <<'EOF' >/dev/null\neval ran 16 sequences (5.7 GB) where training ran 4.\nEOF\ngit commit -F m.txt",
            // The existing cat-only transfer proof remains a separate data
            // contract; adding tee interpreter provenance must preserve it.
            "cat > m.txt <<'EOF'\neval ran 16 sequences (5.7 GB) where training ran 4.\nEOF\nscp m.txt host:/tmp/renamed.txt\nssh host 'git commit -F /tmp/renamed.txt'",
            "cat > notes.md <<'EOF'\n$(rm -rf /)\nEOF\nscp notes.md /tmp/copy.md",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "allow",
                "output consumed only as literal data must remain allowed: {command:?}: {rule}"
            );
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
            r"const s = 'run `git branch -d x` later'; console.log(s);",
            r#"const s = "He said \"run `git branch -d x` later\""; console.log(s);"#,
            r"const s = `run \`git branch -d x\` later`; console.log(s);",
            "const s = `run \\`git branch -d x\\` later\nThis is documentation.`;\nconsole.log(s);",
            r#""run `git branch -d x` later"; console.log('documented');"#,
            r"const fs = require('fs'); const source = fs.readFileSync('README.md', 'utf8'); const edited = source.replace('After merging.', 'After merging, run `git branch -d x`.'); fs.writeFileSync('README.md', edited);",
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
                "import subprocess\nsubprocess.run(['printf', '-c', '$(git reset --hard)'], executable='/bin/sh')",
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
                r"const s = `run \`git branch -d x\` later ${require('child_process').execSync('git reset --hard')}`; console.log(s);",
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
    fn issue_544_child_process_options_keep_executable_source_visible() {
        for (program, body) in [
            (
                "python3",
                "import subprocess\nsubprocess.run(['sh'], input='$(git reset --hard)', text=True)",
            ),
            (
                "python3",
                "import subprocess\nsubprocess.run(['/bin/bash', '-c', 'true'], env={'BASH_ENV': '$(git reset --hard)'})",
            ),
            (
                "python3",
                "import subprocess\nsubprocess.run(['printf', '-c', '$(git reset --hard)'], ｅxecutable='/bin/sh')",
            ),
            (
                "python3",
                "import subprocess\nsubprocess.run(['echo $(git reset --hard)'], ｓｈｅｌｌ=True)",
            ),
            (
                "node",
                "const cp = require('child_process'); cp.spawnSync('sh', [], {input: '$(git reset --hard)'});",
            ),
            (
                "node",
                "const cp = require('child_process'); cp.execFileSync('sh', [], {input: '$(git reset --hard)'});",
            ),
            (
                "node",
                "const cp = require('child_process'); cp.execSync('sh', {input: '$(git reset --hard)'});",
            ),
            (
                "node",
                "const cp = require('child_process'); cp.spawnSync('bash', ['-c', 'true'], {env: {BASH_ENV: '$(git reset --hard)'}});",
            ),
            (
                "node",
                r#"const cp = require('child_process'); cp.spawnSync('node', ['-e', ''], {env: {NODE_OPTIONS: "--import=\"data:text/javascript,import cp from 'node:child_process';cp.execSync('echo $(git reset --hard)')\""}});"#,
            ),
            (
                "node",
                r"const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)'], {sh\u0065ll: true});",
            ),
        ] {
            let command = format!("{program} - <<'DOC'\n{body}\nDOC");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "deny",
                "child options can supply executable code: {command:?}: {rule}"
            );
            assert!(!rule.is_empty(), "{command:?}");
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
    fn issue_544_hoisted_require_cannot_grant_an_argv_data_mask() {
        let body = concat!(
            "const cp = require('child_process');\n",
            "cp.spawnSync('printf', ['%s', '$(git reset --hard)']);\n",
            "function require() { return {spawnSync(_file, argv) { module.require('child_process').execSync(argv[1]); }}; }",
        );
        let command = format!("node - <<'DOC'\n{body}\nDOC");
        let (decision, rule) = hook_decision(&command);
        assert_eq!(
            decision, "deny",
            "a hoisted require can supply an executing API: {command:?}: {rule}"
        );
        assert_eq!(rule, "core.git:reset-hard", "{command:?}");
    }

    #[test]
    fn issue_544_literal_eval_dependencies_keep_rule_ownership() {
        for (program, flag, body, outer_rule) in [
            (
                "python3",
                "-c",
                r#"import os; s = "git reset --hard"; exec("os.system(s)")"#,
                "heredoc.python:exec_sink.git_reset_hard",
            ),
            (
                "node",
                "-e",
                r#"const cp = require("child_process"); const s = "git reset --hard"; eval("cp.execSync(s)");"#,
                "heredoc.javascript:exec_sink.git_reset_hard",
            ),
        ] {
            for command in [
                format!("{program} - <<'DOC'\n{body}\nDOC"),
                format!("{program} {flag} '{body}' && true"),
            ] {
                for grant in [None, Some(outer_rule)] {
                    let (decision, rule) = hook_decision_with_allowlist(&command, grant);
                    assert_eq!(decision, "deny", "{command:?}: {grant:?}: {rule}");
                    assert_eq!(rule, "core.git:reset-hard", "{command:?}: {grant:?}");
                }
                let (decision, rule) =
                    hook_decision_with_allowlist(&command, Some("core.git:reset-hard"));
                assert_eq!(decision, "allow", "{command:?}: {rule}");
            }
        }
    }

    #[test]
    fn issue_544_literal_eval_does_not_execute_unreferenced_command_text() {
        for (program, body) in [
            ("python3", "s = 'git reset --hard'\nexec('print(s)')"),
            (
                "node",
                "const s = 'git reset --hard'; eval('console.log(s)');",
            ),
        ] {
            let command = format!("{program} - <<'DOC'\n{body}\nDOC");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(decision, "allow", "{command:?}: {rule}");
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

    #[test]
    fn issue_544_mixed_quoted_delimiters_preserve_inert_documentation() {
        for (program, body) in [
            (
                "python3",
                "s = 'run `git branch -d x` or $(git reset --hard) later'\nprint(s)",
            ),
            (
                "node",
                "const s = 'run `git branch -d x` or $(git reset --hard) later';\nconsole.log(s);",
            ),
        ] {
            for delimiter in ["D'OC'", "D\\OC"] {
                for command in [
                    format!("{program} - <<{delimiter}\n{body}\nDOC"),
                    format!(
                        "cat > /tmp/documentation-program <<{delimiter}\n{body}\nDOC\n{program} /tmp/documentation-program"
                    ),
                    format!(
                        "tee /tmp/documentation-program <<{delimiter} >/dev/null\n{body}\nDOC\n{program} /tmp/documentation-program"
                    ),
                ] {
                    let (decision, rule) = hook_decision(&command);
                    assert_eq!(
                        decision, "allow",
                        "quote removal must preserve literal interpreter source: {command:?}: {rule}"
                    );
                }
            }
        }
    }

    #[test]
    fn issue_544_indirect_shell_commands_keep_literal_evidence() {
        for (program, body) in [
            (
                "python3",
                "import os\ns = 'echo $(git reset --hard)'\nos.system(s)",
            ),
            (
                "python3",
                "import subprocess\ns = 'echo `git branch -d x`'\nsubprocess.run(s, shell=True)",
            ),
            (
                "node",
                "const s = 'echo $(git reset --hard)';\nrequire('child_process').execSync(s);",
            ),
            (
                "node",
                "const s = 'echo `git branch -d x`';\nconst run = require('child_process').execSync;\nrun(s);",
            ),
            (
                "python3",
                "from helper import run\ns = 'echo $(git reset --hard)'\nrun(s)",
            ),
            (
                "node",
                "const run = require('./helper');\nconst s = 'echo $(git reset --hard)';\nrun(s);",
            ),
        ] {
            for command in [
                format!("{program} - <<'DOC'\n{body}\nDOC"),
                format!(
                    "tee /tmp/executed-program <<'DOC' >/dev/null\n{body}\nDOC\n{program} /tmp/executed-program"
                ),
            ] {
                let (decision, rule) = hook_decision(&command);
                assert_eq!(
                    decision, "deny",
                    "a variable must not hide executable literal evidence: {command:?}: {rule}"
                );
                assert!(!rule.is_empty(), "denial must name its rule: {command:?}");
            }
        }
    }

    #[test]
    fn issue_544_callbacks_and_argument_side_effects_keep_independent_evidence() {
        for (program, body, named_rule) in [
            (
                "node",
                r#"const cp = require('child_process'); cp.exec('printf ready', function () { const s = "echo $(git reset --hard)"; cp.execSync(s); });"#,
                "heredoc.javascript:exec_sink.git_reset_hard",
            ),
            (
                "node",
                r#"const cp = require('child_process'); cp.exec('printf ready', () => { const s = "echo $(git reset --hard)"; cp.execSync(s); });"#,
                "heredoc.javascript:exec_sink.git_reset_hard",
            ),
            (
                "node",
                r#"const cp = require('child_process'); let s; cp.exec('printf ready', (s = "echo $(git reset --hard)", cp.execSync(s)));"#,
                "heredoc.javascript:exec_sink.git_reset_hard",
            ),
            (
                "node",
                r#"const cp = require('child_process'); cp.exec('git reset --hard', () => { const s = "echo $(git reset --hard)"; cp.execSync(s); });"#,
                "heredoc.javascript:exec_sink.git_reset_hard",
            ),
            (
                "python3",
                "import os, subprocess\nsubprocess.run(['printf', 'ready'], preexec_fn=lambda s='echo $(git reset --hard)': os.system(s))",
                "heredoc.python:exec_sink.git_reset_hard",
            ),
        ] {
            for command in [
                format!("{program} - <<'DOC'\n{body}\nDOC"),
                format!(
                    "tee /tmp/callback-program <<'DOC' >/dev/null\n{body}\nDOC\n{program} /tmp/callback-program"
                ),
            ] {
                let (decision, rule) = hook_decision_with_allowlist(&command, Some(named_rule));
                assert_eq!(
                    decision, "deny",
                    "an outer call grant cannot cover independently executed callback source: {command:?}: {rule}"
                );
                assert_eq!(
                    rule, "core.git:reset-hard",
                    "the recovered inner command owns its finding: {command:?}"
                );
            }
        }
    }

    #[test]
    fn issue_544_named_argv_and_option_literals_keep_their_data_roles() {
        for (program, body) in [
            (
                "node",
                "const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)']);",
            ),
            (
                "node",
                "const cp = require('child_process'); cp.execSync('printf ready', {env: {NOTICE: '$(git reset --hard)'}});",
            ),
            (
                "python3",
                "import subprocess\nsubprocess.run(['printf', '%s', '$(git reset --hard)'])",
            ),
            (
                "python3",
                "import subprocess\nsubprocess.run(['printf', 'ready'], env={'NOTICE': '$(git reset --hard)'})",
            ),
        ] {
            let command = format!("{program} - <<'DOC'\n{body}\nDOC");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "allow",
                "static argv and option values must not be reparsed as shell code: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_document_edits_keep_the_same_command_text_inert() {
        for (program, body) in [
            (
                "python3",
                "s = 'echo $(git reset --hard)'\nprint(s)\nopen('notes.md', 'w').write(s)",
            ),
            (
                "python3",
                "s = 'echo `git branch -d x`'\nopen('notes.md', 'w').write(s.replace('echo', 'Example:'))",
            ),
            (
                "node",
                "const s = 'echo $(git reset --hard)';\nconsole.log(s);\nrequire('fs').writeFileSync('notes.md', s);",
            ),
            (
                "node",
                "const s = 'echo `git branch -d x`';\nrequire('node:fs').writeFileSync('notes.md', s.replace('echo', 'Example:'));",
            ),
        ] {
            let command = format!("{program} - <<'DOC'\n{body}\nDOC");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "allow",
                "proven documentation output must remain usable: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_documentation_literals_do_not_mask_protected_file_writes() {
        for (program, body) in [
            (
                "python3",
                "s = 'run `git branch -d x` later'\nopen('/home/user/.ssh/authorized_keys', 'w').write(s)",
            ),
            (
                "node",
                "const s = 'run $(git reset --hard) later';\nrequire('fs').writeFileSync('/home/user/.ssh/authorized_keys', s);",
            ),
        ] {
            for command in [
                format!("{program} - <<'DOC'\n{body}\nDOC"),
                format!("tee /tmp/program <<'DOC' >/dev/null\n{body}\nDOC\n{program} /tmp/program"),
            ] {
                let (decision, rule) = hook_decision(&command);
                assert_eq!(decision, "deny", "{command:?}");
                assert_eq!(
                    rule, "core.filesystem:credential-file-write",
                    "the original source must reach protected-write analysis: {command:?}"
                );
            }
        }
    }

    #[test]
    fn issue_544_documentation_output_piped_to_shell_is_executable() {
        for command in [
            "python3 - <<'PY' | bash\ns = 'echo `git branch -d x`'\nprint(s)\nPY",
            "node - <<'JS' | sh\nconst s = 'echo $(git reset --hard)';\nconsole.log(s);\nJS",
            "tee /tmp/program.py <<D\\OC >/dev/null\ns = 'echo $(git reset --hard)'\nprint(s)\nDOC\npython3 /tmp/program.py | sh",
            "tee /tmp/program.js <<D'OC' >/dev/null\nconst s = 'echo `git branch -d x`';\nconsole.log(s);\nDOC\nnode /tmp/program.js | bash",
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "deny",
                "a downstream shell executes the printed command text: {command:?}: {rule}"
            );
            assert!(!rule.is_empty(), "denial must name its rule: {command:?}");
        }
    }

    #[test]
    fn issue_544_inline_documentation_literals_remain_inert() {
        for command in [
            r#"python3 -c 's = "run `git branch -d x` later"; print(s)'"#,
            r#"python3 -c 's = "run \x60git branch -d x\x60 later"; print(s)'"#,
            r#"node -e 'const s = "run `git branch -d x` later"; console.log(s);'"#,
            r#"node -e 'const s = "run \u0060git branch -d x\u0060 later"; console.log(s);'"#,
            r#"python3 -c "print(\"hello\")""#,
            r#"node -e "console.log(\"hello\")""#,
        ] {
            let (decision, rule) = hook_decision(command);
            assert_eq!(
                decision, "allow",
                "isolated inline documentation has the same literal semantics: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_tagged_templates_do_not_invent_cooked_shell_commands() {
        for (body, expected) in [
            (
                r"const s = String.raw`echo \`git branch -d x\``; require('child_process').execSync(s);",
                "allow",
            ),
            (
                r"const s = `echo \`git branch -d x\``; require('child_process').execSync(s);",
                "deny",
            ),
        ] {
            let command = format!("node - <<'JS'\n{body}\nJS");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, expected,
                "raw and ordinary templates produce different shell values: {command:?}: {rule}"
            );
            if expected == "deny" {
                assert_eq!(rule, "core.git:branch-delete", "{command:?}");
            }
        }
    }

    #[test]
    fn issue_544_named_sink_allowlists_do_not_cover_indirect_commands() {
        for (launcher, direct, indirect, opaque, named_rule) in [
            (
                "python3 -c",
                r#"from os import system as run; run("git reset --hard; echo $(printf done)")"#,
                r#"from os import system as run; s = "echo $(git reset --hard)"; run(s)"#,
                r#"from helper import run; s = "echo $(git reset --hard)"; run(s)"#,
                "heredoc.python:exec_sink.git_reset_hard",
            ),
            (
                "node -e",
                r#"const cp = require("child_process"); cp.execSync("git reset --hard; echo $(printf done)");"#,
                r#"const cp = require("child_process"); const s = "echo $(git reset --hard)"; cp.execSync(s);"#,
                r#"const run = require("./helper"); const s = "echo $(git reset --hard)"; run(s);"#,
                "heredoc.javascript:exec_sink.git_reset_hard",
            ),
        ] {
            let direct_command = format!("{launcher} '{direct}'");
            let (decision, rule) = hook_decision(&direct_command);
            assert_eq!(decision, "deny", "{direct_command:?}");
            assert_eq!(
                rule, named_rule,
                "the established named sink retains its rule: {direct_command:?}"
            );
            let (decision, rule) = hook_decision_with_allowlist(&direct_command, Some(named_rule));
            assert_eq!(
                decision, "allow",
                "a named-sink grant must not be denied again by literal recovery: {direct_command:?}: {rule}"
            );

            for body in [indirect, opaque] {
                let command = format!("{launcher} '{body}'");
                let (decision, rule) = hook_decision_with_allowlist(&command, Some(named_rule));
                assert_eq!(decision, "deny", "{command:?}");
                assert_eq!(
                    rule, "core.git:reset-hard",
                    "a different call does not inherit the named-sink grant: {command:?}"
                );
            }
            let command = format!("{launcher} '{indirect}'");
            let (decision, rule) =
                hook_decision_with_allowlist(&command, Some("core.git:reset-hard"));
            assert_eq!(
                decision, "allow",
                "recovered commands honor their own reported pack rule: {command:?}: {rule}"
            );
        }
    }

    #[test]
    fn issue_544_inline_literal_commands_survive_other_shell_consumers() {
        for (launcher, body) in [
            (
                "python3 -c",
                r#"import os; s = "echo $(git reset --hard)"; os.system(s)"#,
            ),
            (
                "node -e",
                r#"const cp = require("child_process"); const s = "echo $(git reset --hard)"; cp.execSync(s);"#,
            ),
            (
                "python3 -c",
                r#"import os; s = "echo \x60git reset --hard\x60"; os.system(s)"#,
            ),
            (
                "node -e",
                r#"const cp = require("child_process"); const s = "echo \u0060git reset --hard\u0060"; cp.execSync(s);"#,
            ),
        ] {
            let invocation = format!("{launcher} '{body}'");
            for command in [
                format!("{invocation} && true"),
                format!("true; {invocation}"),
                format!("{invocation} > /dev/null"),
                format!("{invocation} | cat"),
                format!("MODE=review {invocation}"),
                format!("{invocation} extra"),
            ] {
                let (decision, rule) = hook_decision(&command);
                assert_eq!(
                    decision, "deny",
                    "another shell consumer must not hide the complete inline source: {command:?}: {rule}"
                );
                assert_eq!(rule, "core.git:reset-hard", "{command:?}");
            }
        }
    }

    #[test]
    fn issue_544_compound_inline_commands_keep_allowlist_ownership() {
        for (launcher, direct, indirect, named_rule) in [
            (
                "python3 -c",
                r#"from os import system as run; run("git reset --hard; echo $(printf done)")"#,
                r#"import os; s = "echo $(git reset --hard)"; os.system(s)"#,
                "heredoc.python:exec_sink.git_reset_hard",
            ),
            (
                "node -e",
                r#"const cp = require("child_process"); cp.execSync("git reset --hard; echo $(printf done)");"#,
                r#"const cp = require("child_process"); const s = "echo $(git reset --hard)"; cp.execSync(s);"#,
                "heredoc.javascript:exec_sink.git_reset_hard",
            ),
        ] {
            let command = format!("{launcher} '{direct}' && true");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(decision, "deny", "{command:?}");
            assert_eq!(rule, named_rule, "{command:?}");
            let (decision, rule) = hook_decision_with_allowlist(&command, Some(named_rule));
            assert_eq!(
                decision, "allow",
                "literal recovery must honor the established named-sink grant: {command:?}: {rule}"
            );

            let command = format!("{launcher} '{indirect}' && true");
            let (decision, rule) = hook_decision_with_allowlist(&command, Some(named_rule));
            assert_eq!(decision, "deny", "{command:?}");
            assert_eq!(
                rule, "core.git:reset-hard",
                "an outer grant must not suppress another command's rule: {command:?}"
            );
            let (decision, rule) =
                hook_decision_with_allowlist(&command, Some("core.git:reset-hard"));
            assert_eq!(
                decision, "allow",
                "the recovered command retains its own grant: {command:?}: {rule}"
            );
        }

        let canonical =
            r#"python3 -c 'import os; os.system("git reset --hard; echo $(printf done)")' && true"#;
        for (granted_rule, remaining_rule) in [
            (
                "heredoc.python:exec_sink.git_reset_hard",
                "heredoc.python:os_system.git_reset_hard",
            ),
            (
                "heredoc.python:os_system.git_reset_hard",
                "heredoc.python:exec_sink.git_reset_hard",
            ),
        ] {
            let (decision, rule) = hook_decision_with_allowlist(canonical, Some(granted_rule));
            assert_eq!(decision, "deny", "granting {granted_rule}: {canonical:?}");
            assert_eq!(
                rule, remaining_rule,
                "distinct named-sink rules retain separate grants: {canonical:?}"
            );
        }
    }

    #[test]
    fn issue_544_node_later_options_cannot_prove_the_first_source_executes() {
        let body = r#"const cp = require("child_process"); const s = "echo $(git reset --hard)"; cp.execSync(s);"#;
        for tail in [
            r#"-e 'console.log("ready")'"#,
            r#"--eval='console.log("ready")'"#,
            "-p '1 + 1'",
        ] {
            let command = format!("node -e '{body}' {tail}");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "allow",
                "a replaced first program is not executable source: {command:?}: {rule}"
            );
        }
        for operand in ["extra", "--", "-", "''"] {
            let command = format!("node -e '{body}' {operand} -e 'console.log(\"ready\")'");
            let (decision, rule) = hook_decision(&command);
            assert_eq!(
                decision, "deny",
                "an option-stop operand keeps the first program active: {command:?}: {rule}"
            );
            assert_eq!(rule, "core.git:reset-hard", "{command:?}");
        }
    }

    #[test]
    fn issue_544_compound_inline_commands_keep_static_argv_as_data() {
        for (launcher, body) in [
            (
                "python3 -c",
                r#"import subprocess; subprocess.run(["printf", "%s", "$(git reset --hard)"])"#,
            ),
            (
                "node -e",
                r#"const cp = require("child_process"); cp.spawnSync("printf", ["%s", "$(git reset --hard)"]);"#,
            ),
        ] {
            let invocation = format!("{launcher} '{body}'");
            for command in [
                format!("{invocation} && true"),
                format!("true; {invocation}"),
                format!("{invocation} > /dev/null"),
            ] {
                let (decision, rule) = hook_decision(&command);
                assert_eq!(
                    decision, "allow",
                    "complete argument arrays do not acquire shell expansion: {command:?}: {rule}"
                );
            }
        }
    }
}
