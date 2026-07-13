use std::collections::{BTreeMap, BTreeSet};

fn read_repo_file(path: &str) -> std::io::Result<String> {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(repo_root.join(path))
}

fn expected_detector_docs() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("is_shell", "Shell Scripts"),
        ("is_docker", "Dockerfile"),
        ("is_actions", "GitHub Actions"),
        ("is_gitlab", "GitLab CI"),
        ("is_azure", "Azure Pipelines"),
        ("is_circleci", "CircleCI"),
        ("is_makefile", "Makefile"),
        ("is_package_json", "package.json"),
        ("is_terraform", "Terraform"),
        ("is_compose", "Docker Compose"),
        ("is_powershell", "PowerShell"),
        ("is_batch", "Batch Scripts"),
    ])
}

fn scan_loop_detectors(scan_rs: &str) -> BTreeSet<String> {
    let start = scan_rs
        .find("// Determine which extractor(s) to use")
        .expect("src/scan.rs must contain the extractor dispatch marker");
    let dispatch = &scan_rs[start..];
    let end = dispatch
        .find("if !is_shell")
        .expect("src/scan.rs must contain the extractor skip guard");

    dispatch[..end]
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed.strip_prefix("let is_")?;
            let (name, _) = rest.split_once('=')?;
            Some(format!("is_{}", name.trim()))
        })
        .collect()
}

fn readme_supported_file_types(readme: &str) -> BTreeSet<String> {
    let start = readme
        .find("### Supported File Formats")
        .expect("README.md must document supported scan file formats");
    let section = &readme[start..];
    let table_start = section
        .find("| File Type | Detection | Executable Contexts |")
        .expect("README.md must include the supported scan format table");

    section[table_start..]
        .lines()
        .skip(2)
        .take_while(|line| line.trim_start().starts_with('|'))
        .filter_map(|line| {
            let first_cell = line.split('|').nth(1)?.trim();
            first_cell
                .strip_prefix("**")
                .and_then(|cell| cell.strip_suffix("**"))
                .map(ToString::to_string)
        })
        .collect()
}

#[test]
fn readme_scan_format_table_matches_wired_extractors() -> std::io::Result<()> {
    let scan_rs = read_repo_file("src/scan.rs")?;
    let readme = read_repo_file("README.md")?;

    let expected = expected_detector_docs();
    let wired_detectors = scan_loop_detectors(&scan_rs);
    let expected_detectors: BTreeSet<String> = expected.keys().map(ToString::to_string).collect();
    let documented_formats = readme_supported_file_types(&readme);
    let expected_formats: BTreeSet<String> = expected.values().map(ToString::to_string).collect();

    assert_eq!(
        wired_detectors, expected_detectors,
        "update expected_detector_docs when src/scan.rs wires a scan extractor"
    );
    assert_eq!(
        documented_formats, expected_formats,
        "README.md supported scan file formats must match wired extractors"
    );
    assert!(
        readme.contains("Azure Pipelines")
            && readme.contains("CircleCI")
            && readme.contains("package.json"),
        "README.md should name the extractors that previously drifted out of the supported-format table"
    );

    Ok(())
}
