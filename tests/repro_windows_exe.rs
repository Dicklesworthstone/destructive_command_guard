use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::{EvaluationDecision, MatchSource, evaluate_command};
use destructive_command_guard::load_default_allowlists;
use destructive_command_guard::packs::REGISTRY;
use std::collections::HashSet;

#[test]
fn test_python_exe_bypass() {
    let mut config = Config::default();
    // Ensure heredoc scanning is enabled
    config.heredoc.enabled = Some(true);

    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();

    // Command using python.exe (Windows style)
    let command = r#"python.exe -c "import shutil; shutil.rmtree('/')""#;

    let result = evaluate_command(
        command,
        &config,
        &enabled_keywords,
        &compiled_overrides,
        &allowlists,
    );

    // This should be DENIED because it contains shutil.rmtree
    assert!(
        result.decision != EvaluationDecision::Allow,
        "python.exe bypass detected! Command was allowed: {command}"
    );

    assert!(result.is_denied());
    let info = result.pattern_info.as_ref().unwrap();

    // Verify it was blocked by heredoc scanning, not something else
    assert_eq!(info.source, MatchSource::HeredocAst);
    assert_eq!(info.pack_id.as_deref(), Some("heredoc.python"));
    assert_eq!(info.pattern_name.as_deref(), Some("shutil_rmtree"));
}

#[test]
fn test_python_versioned_exe_bypass() {
    let mut config = Config::default();
    config.heredoc.enabled = Some(true);

    let enabled_packs: HashSet<String> = config.enabled_pack_ids();
    let enabled_keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
    let compiled_overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();

    // Command using python3.11.exe
    let command = r#"python3.11.exe -c "import shutil; shutil.rmtree('/')""#;

    let result = evaluate_command(
        command,
        &config,
        &enabled_keywords,
        &compiled_overrides,
        &allowlists,
    );

    assert!(
        result.decision != EvaluationDecision::Allow,
        "python3.11.exe bypass detected! Command was allowed: {command}"
    );

    assert!(result.is_denied());
}
