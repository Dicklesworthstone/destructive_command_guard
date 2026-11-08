//! Issues #567 and #569: the source of a quoted `python3 - <<'EOF'` heredoc
//! judged by shell-level rules.
//!
//! #569: on Linux/macOS a quoted Python heredoc whose source merely looked
//! Windows-shaped (a regex `r'[^\n]{0,40}(x|y)'`, prose such as `install-l`)
//! widened the `Bash` label to `Unknown`, activated the disabled `windows.*`
//! packs, and was denied as `windows.filesystem:windows-filesystem-semantic-
//! unverified` by the hook while `dcg explain`/`dcg test` disagreed. Whether
//! it denied depended on body length (28 lines allowed, 29 denied).
//!
//! #567: an external pack's separator-anchored regex matches lines of the same
//! kind of body. External packs see exactly the view built-in packs see — the
//! conservative raw-shell scan of interpreter source that #136's revert keeps —
//! so the pinned property here is parity, plus every executed-shell route.
//!
//! Every fixture is classifier input only; nothing is executed. The hook runs
//! on a non-Windows host here, which is the platform both reports came from.

#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// The plain PreToolUse hook, as the reports ran it.
    Hook,
    /// `dcg hook --batch`, the bulk hook entry point.
    Batch,
    /// `dcg test --dialect posix`.
    CliPosix,
}

const ROUTES: [Route; 3] = [Route::Hook, Route::Batch, Route::CliPosix];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    /// `allow`, `deny` or `indeterminate`.
    decision: String,
    rule: Option<String>,
}

/// The external pack from #567, verbatim.
const AWS_PACK: &str = "schema_version: 1
id: custom.repro
name: Repro
version: 1.0.0
description: Minimal repro pack.
keywords:
  - aws

destructive_patterns:
  - name: aws-invocation
    pattern: (?:^|[;&|()\\n])[ \\t]*aws\\b
    description: Block AWS CLI invocations.
    severity: high
";

fn classify(source: &str, external_pack: bool, route: Route) -> Verdict {
    let temp = tempfile::tempdir().expect("isolated working directory");
    let home = temp.path().join("home");
    std::fs::create_dir(&home).expect("isolated home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcg"));
    let hook_input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": source},
    })
    .to_string();
    let input = match route {
        Route::Hook => {
            command.args(["--agent", "claude-code"]);
            hook_input
        }
        Route::Batch => {
            command.args(["hook", "--batch"]);
            hook_input
        }
        Route::CliPosix => {
            command.args(["test", "--stdin", "--dialect", "posix", "--format", "json"]);
            source.to_string()
        }
    };
    command
        .env_clear()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
        .env("DCG_NO_SELF_HEAL", "1")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_HISTORY_DISABLED", "1")
        // Semantic tests use the existing #412/#438 test envelopes so a slow
        // worker cannot turn a decision into a budget verdict. Extraction has
        // an independent clock (bd-e1xl), so give it the same test envelope.
        .env("DCG_HOOK_TIMEOUT_MS", "5000")
        .env("DCG_AST_TIMEOUT_MS", "5000")
        .env("DCG_HEREDOC_TIMEOUT_MS", "5000")
        .current_dir(temp.path());
    if external_pack {
        let pack = temp.path().join("fp-pack.yaml");
        std::fs::write(&pack, AWS_PACK).expect("write pack");
        let config = temp.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                "[packs]\nenabled = [\"custom.repro\"]\ncustom_paths = [{}]\n\n[heredoc]\nenabled = true\n",
                serde_json::to_string(&pack).expect("pack path")
            ),
        )
        .expect("write config");
        command.env("DCG_CONFIG", &config);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn classifier");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("write classifier input");
    let output = child.wait_with_output().expect("wait for classifier");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if route == Route::Hook && stdout.trim().is_empty() {
        assert!(output.status.success(), "{source:?}: {stderr}");
        return Verdict {
            decision: "allow".to_string(),
            rule: None,
        };
    }
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("{route:?} {source:?}: {error}; stdout={stdout}; stderr={stderr}")
    });
    let text = |value: &serde_json::Value| value.as_str().map(str::to_string);
    if route == Route::Hook {
        let output = &value["hookSpecificOutput"];
        let rule = text(&output["ruleId"]);
        let decision = match output["permissionDecision"].as_str() {
            Some("deny") => "deny",
            // Claude Code is review-capable: an incomplete analysis asks, and
            // nothing else in this file's default configuration does.
            Some("ask") if rule.is_none() => "indeterminate",
            other => panic!("{source:?}: unexpected hook decision {other:?}: {value}"),
        };
        return Verdict {
            decision: decision.to_string(),
            rule,
        };
    }
    Verdict {
        decision: text(&value["decision"])
            .unwrap_or_else(|| panic!("{route:?} {source:?}: no decision in {value}")),
        rule: text(&value["rule_id"]),
    }
}

fn verdicts(source: &str, external_pack: bool) -> Vec<(Route, Verdict)> {
    ROUTES
        .iter()
        .map(|&route| (route, classify(source, external_pack, route)))
        .collect()
}

/// The generator from the second comment of #569.
fn tuple_program(lines: usize, regex: bool) -> String {
    let mut body = String::from("import re\ns = 'text'\nR = [\n");
    body.push_str(&" ('a', 'b'), ('c', 'd'),\n".repeat(lines));
    body.push_str("]\n");
    if regex {
        body.push_str(
            "for m in re.finditer(r'[^\\n]{0,40}(x|y)[^\\n]{0,40}', s):\n    print(m.group(0))\n",
        );
    } else {
        body.push_str("print(s)\n");
    }
    format!("python3 - <<'EOF'\n{body}EOF")
}

/// The neutral 59-line edit script from the second comment of #544 (a
/// truncated program: its last `'''` string never closes).
const ISSUE_544_EDIT_SCRIPT: &str = r#"python3 - <<'EOF'
from pathlib import Path
p=Path("web/src/components/__tests__/Workspace.test.tsx")
s=p.read_text()
s=s.replace('''import { getObservedRate } from '../../../../api/client/metrics';
import type { ObservedRate } from '../../../../api/types/metrics';
''','''import { getExpectedRate, getObservedRate } from '../../../../api/client/metrics';
import type { ExpectedRate, ObservedRate } from '../../../../api/types/metrics';
''')
s=s.replace('''import observed from '../../__tests__/fixtures/observed-rate-answered.json';
''','''import observed from '../../__tests__/fixtures/observed-rate-answered.json';
import expected from '../../__tests__/fixtures/expected-rate-fresh.json';
''')
s=s.replace('''vi.mock('../../../../api/client/metrics', () => ({ getObservedRate: vi.fn() }));''','''vi.mock('../../../../api/client/metrics', () => ({
    getExpectedRate: vi.fn(),
    getObservedRate: vi.fn(),
}));''')
s=s.replace('''        vi.mocked(getObservedRate).mockResolvedValue(observed as ObservedRate);
    });
    it('shows the observed rate beside the rate input of a saved scenario too', async () => {
        mount(<Workspace initialRequest={makeRequest()} />);
        const note = await screen.findByText(/^Observed rate \\(SERIESA\\) per year through 2025: 3\\.27% over 8 yr/);''','''        vi.mocked(getObservedRate).mockResolvedValue(observed as ObservedRate);
        vi.mocked(getExpectedRate).mockResolvedValue(expected as ExpectedRate);
    });
    it('shows the observed rate and the forecast beside the rate input of a saved scenario too', async () => {
        mount(<Workspace initialRequest={makeRequest()} />);
        const note = await screen.findByText(
            /^Observed rate \\(SERIESA\\) per year through 2025: 3\\.27% over 8 yr.* Forecast \\(SERIESB, 1-year forecast\\) on 2024-01-15: 2\\.35%/
        );''')
p.write_text(s)
p=Path("web/src/__tests__/observedRate.test.tsx")
s=p.read_text()
s=s.replace('''/**
 * Observed rate beside the rate input, read from the server's own
 * serialization (`observed-rate-*.json`, regenerated by `GENERATORS`).
 */''','''/**
 * Observed rate and the forecast beside the rate input, read from
 * the server's own serialization (`observed-rate-*.json` and
 * `expected-rate-*.json`, regenerated by `GENERATORS`).
 */''')
s=s.replace('''import type { ObservedRate } from '@/api/types/metrics';''','''import type { ExpectedRate, ObservedRate } from '@/api/types/metrics';''')
s=s.replace('''import { joinNotes, observedRateNote } from '../observedRate';
import answered from './fixtures/observed-rate-answered.json';
import absent from './fixtures/observed-rate-absent.json';
''','''import { expectedRateNote, joinNotes, observedRateNote } from '../observedRate';
import answered from './fixtures/observed-rate-answered.json';
import absent from './fixtures/observed-rate-absent.json';
import expectationFresh from './fixtures/expected-rate-fresh.json';
import expectationWarning from './fixtures/expected-rate-warning.json';
import expectationAbsent from './fixtures/expected-rate-absent.json';
''')
s=s.replace('''    it('joins only the notes that are present', () => {''','''    it('dates the forecast and says which side of the assumption it falls', () => {
        expect(expectedRateNote(expectationFresh as ExpectedRate, false)).toBe(
            'Forecast (SERIESB, 1-year forecast) on 2024-01-15: 2.35%, 0.65 pp below the 3.00% ' +
                'assumption. It is a model estimate.'
        );
    });
    it('names the age of a forecast past the fresh cut', () => {
EOF"#;

#[test]
fn issue_569_complete_python_programs_allow_at_every_size() {
    for source in [
        tuple_program(28, true),
        tuple_program(29, true),
        tuple_program(120, true),
        tuple_program(120, false),
        // `os.system` runs /bin/sh off Windows, where cmd.exe's `rd` does not
        // exist: interpreter source is not a Windows payload here.
        "python3 - <<'PY'\nimport os\nos.system(\"echo & rd /s /q C:\\\\Users\")\nPY".to_string(),
    ] {
        for (route, verdict) in verdicts(&source, false) {
            assert_eq!(
                verdict.decision, "allow",
                "{route:?} {source:?}: {verdict:?}"
            );
        }
    }
}

#[test]
fn issue_647_long_python_heredocs_keep_powershell_like_text_as_data() {
    // The body is Python source, even when a docstring starts with a
    // PowerShell-shaped word or a quoted print argument contains a separator.
    // Its own extraction bounds permit all three sizes; the Windows statement
    // limit must not be applied to this proven interpreter body off Windows.
    for count in [300, 512, 513] {
        let source = format!(
            "python3 - <<'PY'\n\"\"\"\nread-only\nWrite-Output examples are documentation\n\"\"\"\n{}PY",
            "print(\"read-only; Write-Output 'rm x'\")\n".repeat(count)
        );
        for (route, verdict) in verdicts(&source, false) {
            assert_eq!(
                verdict.decision, "allow",
                "{route:?}, {count} Python statements: {verdict:?}"
            );
        }
    }
}

#[test]
fn issue_647_long_python_prefix_does_not_hide_execution() {
    let prefix = format!(
        "\"\"\"\nread-only\nWrite-Output examples are documentation\n\"\"\"\n{}",
        "print(0)\n".repeat(400)
    );
    // Quoting the heredoc delimiter makes the substitution-shaped literal
    // Python data. Removing those quotes below makes the outer shell execute
    // it before Python receives stdin, despite the Python string quotes.
    let quoted =
        format!("python3 - <<'PY'\n{prefix}print('$(rm -rf /Users/example/important)')\nPY");
    for (route, verdict) in verdicts(&quoted, false) {
        assert_eq!(
            verdict.decision, "allow",
            "{route:?}, quoted substitution data: {verdict:?}"
        );
    }

    for source in [
        format!(
            "python3 - <<'PY'\n{prefix}import os\nos.system('rm -rf /Users/example/important')\nPY"
        ),
        format!("python3 - <<'PY'\n{prefix}PY\nrm -rf /Users/example/important"),
        format!("python3 - <<PY\n{prefix}print('$(rm -rf /Users/example/important)')\nPY"),
    ] {
        for (route, verdict) in verdicts(&source, false) {
            assert_eq!(
                verdict.decision, "deny",
                "{route:?} {source:?}: {verdict:?}"
            );
        }
    }

    // A Windows statement after the body still activates its pack through the
    // Bash-labeled hook. The explicit POSIX CLI intentionally uses its proven
    // dialect instead of this payload-based activation.
    let windows_tail = format!("python3 - <<'PY'\n{prefix}PY\nClear-Content C:\\app\\db");
    for route in [Route::Hook, Route::Batch] {
        let verdict = classify(&windows_tail, false, route);
        assert_eq!(
            (verdict.decision.as_str(), verdict.rule.as_deref()),
            ("deny", Some("windows.filesystem:clear-content")),
            "{route:?} {windows_tail:?}: {verdict:?}"
        );
    }
}

#[test]
fn issue_569_unparseable_python_is_never_attributed_to_a_windows_rule() {
    // These bodies are not valid Python (each leaves a `'''` string open), so
    // the interpreter literal recovery cannot finish. Whatever that yields,
    // the hook must agree with `dcg test` and must not name a Windows rule.
    for source in [
        "python3 - <<'PY'\ninstall-l ''''\n`\n\nPY",
        "python3 - <<'PY'\ninstall-l ''''\n`\nPY",
        ISSUE_544_EDIT_SCRIPT,
    ] {
        let verdicts = verdicts(source, false);
        for (route, verdict) in &verdicts {
            assert_ne!(
                verdict.decision, "deny",
                "{route:?} {source:?}: {verdict:?}"
            );
            assert!(
                verdict
                    .rule
                    .as_deref()
                    .is_none_or(|rule| !rule.starts_with("windows.")),
                "{route:?} {source:?}: {verdict:?}"
            );
        }
        let decisions: Vec<_> = verdicts.iter().map(|(_, v)| v.decision.as_str()).collect();
        assert!(
            decisions.windows(2).all(|pair| pair[0] == pair[1]),
            "hook and CLI disagree for {source:?}: {verdicts:?}"
        );
    }
}

#[test]
fn issue_569_windows_shell_payloads_still_reach_the_windows_packs() {
    for (source, rule) in [
        ("format D: /q", "windows.filesystem:format-drive"),
        (
            "python3 - <<'PY'\nprint(1)\nPY\nformat D: /q",
            "windows.filesystem:format-drive",
        ),
        (
            "Clear-Content C:\\app\\db; python3 - <<'PY'\nprint(1)\nPY",
            "windows.filesystem:clear-content",
        ),
        (
            "bash <<'EOF'\nClear-Content C:\\app\\db\nEOF",
            "windows.filesystem:clear-content",
        ),
        // Off Windows, interpreter source reaches a Windows shell only
        // through a program it names — PowerShell, or a WSL-interop `.exe`
        // interpreter whose `os.system` is cmd.exe — and such source keeps
        // its Windows evidence.
        (
            "python3 - <<'PY'\nimport os\nf = getattr(os, 'system')\nf(\"pwsh -c 'x; Clear-Content ~/important.db'\")\nPY",
            "windows.filesystem:clear-content",
        ),
        (
            "python.exe - <<'PY'\nimport os\nos.system(\"echo & rd /s /q C:\\\\Users\")\nPY",
            "windows.filesystem:rd-recursive",
        ),
    ] {
        for route in [Route::Hook, Route::Batch] {
            let verdict = classify(source, false, route);
            assert_eq!(
                (verdict.decision.as_str(), verdict.rule.as_deref()),
                ("deny", Some(rule)),
                "{route:?} {source:?}"
            );
        }
    }

    // Bodies that are not proven inert interpreter source keep the full
    // conservative analysis: an unquoted delimiter, a `-c` or script-file
    // owner, a rebound interpreter name, and a PowerShell launcher fed a
    // variable.
    for source in [
        "python3 - <<PY\ninstall-l x\nClear-Content C:\\app\\db\nPY",
        "python3 -c 'import sys; exec(sys.stdin.read())' <<'PY'\nClear-Content C:\\app\\db\nPY",
        "python3 script.py <<'PY'\nClear-Content C:\\app\\db\nPY",
        "python3() { bash -s; }; python3 - <<'PY'\nClear-Content C:\\app\\db\nPY",
        "python3 - <<'PY'\nimport subprocess\ncmd = \"\"\"\nClear-Content ~/important.db\n\"\"\"\nsubprocess.run([\"pwsh\", \"-c\", cmd])\nPY",
    ] {
        for route in [Route::Hook, Route::Batch] {
            let verdict = classify(source, false, route);
            assert_eq!(
                verdict.decision, "deny",
                "{route:?} {source:?}: {verdict:?}"
            );
        }
    }
}

#[test]
fn issue_567_external_packs_judge_interpreter_source_like_built_in_packs() {
    // #136's revert keeps every interpreter body on the raw-shell scan for
    // built-in packs, because a literal can reach an exec sink through
    // indirection. An external pack sees the same view: whatever a built-in
    // literal rule decides for a body, the external rule decides for the same
    // body shape.
    for (external, built_in) in [(
        "python3 - <<'EOF'\nprint('x|aws s3 ls')\nEOF",
        "python3 - <<'EOF'\nprint('x|git reset --hard')\nEOF",
    )] {
        for route in ROUTES {
            let external_verdict = classify(external, true, route);
            let built_in_verdict = classify(built_in, true, route);
            assert_eq!(
                external_verdict.decision, built_in_verdict.decision,
                "{route:?}: {external:?} -> {external_verdict:?}, {built_in:?} -> {built_in_verdict:?}"
            );
            if external_verdict.decision == "deny" {
                assert_eq!(
                    external_verdict.rule.as_deref(),
                    Some("custom.repro:aws-invocation"),
                    "{route:?} {external:?}"
                );
            }
        }
    }
}

#[test]
fn issue_567_external_pack_still_judges_every_executed_shell_route() {
    for source in [
        "bash <<'EOF'\naws s3 rm s3://bucket --recursive\nEOF",
        "bash -c 'aws s3 ls'",
        "printf 'aws s3 ls' | sh",
        "cat <<'EOF' | sh\naws s3 ls\nEOF",
        "python3 - <<EOF\nx = '$(aws s3 ls)'\nEOF",
        "python3 - <<'EOF'\nimport os\nos.system('aws s3 ls')\nEOF",
        "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['aws', 's3', 'ls'])\nEOF",
        "python3 - <<'EOF'\nprint(1)\nEOF\naws s3 ls",
        "aws s3 ls; python3 - <<'EOF'\nprint(1)\nEOF",
    ] {
        for (route, verdict) in verdicts(source, true) {
            assert_eq!(
                (verdict.decision.as_str(), verdict.rule.as_deref()),
                ("deny", Some("custom.repro:aws-invocation")),
                "{route:?} {source:?}"
            );
        }
    }
}
