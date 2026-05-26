use std::collections::BTreeMap;

fn read_repo_file(path: &str) -> std::io::Result<String> {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manifest dir has parent")
        .parent()
        .expect("crates dir has parent");
    std::fs::read_to_string(repo_root.join(path))
}

fn parse_ci_thresholds(workflow: &str) -> BTreeMap<&'static str, f64> {
    let mut thresholds = BTreeMap::new();
    for line in workflow.lines().map(str::trim) {
        for (env_name, label) in [
            ("OVERALL_MIN", "Overall"),
            ("EVALUATOR_MIN", "src/evaluator.rs"),
            ("HOOK_MIN", "src/hook.rs"),
        ] {
            let prefix = format!("{env_name}=\"");
            let Some(rest) = line.strip_prefix(&prefix) else {
                continue;
            };
            let Some(value) = rest.strip_suffix('"') else {
                continue;
            };
            thresholds.insert(
                label,
                value
                    .parse()
                    .unwrap_or_else(|err| panic!("{env_name} must be numeric: {err}")),
            );
        }
    }
    thresholds
}

fn parse_agents_thresholds(agents: &str) -> BTreeMap<&'static str, f64> {
    let mut thresholds = BTreeMap::new();
    for (label, marker) in [
        ("Overall", "- **Overall:** >= "),
        ("src/evaluator.rs", "- **src/evaluator.rs:** >= "),
        ("src/hook.rs", "- **src/hook.rs:** >= "),
    ] {
        let line = agents
            .lines()
            .find(|line| line.trim_start().starts_with(marker))
            .unwrap_or_else(|| panic!("AGENTS.md is missing coverage threshold for {label}"));
        let value = line
            .trim_start()
            .strip_prefix(marker)
            .and_then(|rest| rest.split('%').next())
            .unwrap_or_else(|| panic!("AGENTS.md threshold for {label} must end with %"));
        thresholds.insert(
            label,
            value.parse().unwrap_or_else(|err| {
                panic!("AGENTS.md threshold for {label} must be numeric: {err}")
            }),
        );
    }
    thresholds
}

#[test]
fn agents_coverage_thresholds_match_ci_enforced_values() -> std::io::Result<()> {
    let workflow = read_repo_file(".github/workflows/ci.yml")?;
    let agents = read_repo_file("AGENTS.md")?;

    let ci_thresholds = parse_ci_thresholds(&workflow);
    let agents_thresholds = parse_agents_thresholds(&agents);

    assert_eq!(
        ci_thresholds, agents_thresholds,
        "AGENTS.md coverage thresholds must match .github/workflows/ci.yml"
    );
    assert!(
        agents.contains("These are enforced gates, not aspirational targets"),
        "AGENTS.md should state whether coverage thresholds are enforced or aspirational"
    );

    Ok(())
}
