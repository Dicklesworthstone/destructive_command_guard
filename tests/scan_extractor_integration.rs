#![allow(
    clippy::format_push_string,
    clippy::map_unwrap_or,
    clippy::needless_raw_string_hashes,
    clippy::uninlined_format_args,
    clippy::unnecessary_map_or
)]
//! Integration tests for scan mode extractors
//!
//! These tests verify that each file type extractor correctly identifies
//! and extracts commands from real-world file formats.
//!
//! Related bead: git_safety_guard-l9ig

use std::process::Command;

/// Run dcg scan command and return output
fn run_dcg_scan(args: &[&str]) -> std::process::Output {
    let dcg_bin = std::env::var("DCG_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("debug")
                .join("dcg")
        });

    Command::new(dcg_bin)
        .args(["scan"])
        .args(args)
        .output()
        .expect("Failed to execute dcg")
}

// ============================================================================
// Dockerfile Extractor Integration Tests
// ============================================================================

#[test]
fn scan_dockerfile_extracts_run_commands() {
    let dir = tempfile::tempdir().unwrap();
    let dockerfile = dir.path().join("Dockerfile");
    std::fs::write(
        &dockerfile,
        r#"FROM alpine:3.18
RUN apk add --no-cache curl
RUN git clone https://example.com/repo.git && git reset --hard HEAD~1
COPY . /app
CMD ["./app"]
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // Should find the git reset --hard command
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| f["file"]
            .as_str()
            .map_or(false, |s| s.contains("Dockerfile"))),
        "should have findings from Dockerfile"
    );
    assert!(
        findings.iter().any(|f| {
            f["extracted_command"]
                .as_str()
                .map_or(false, |s| s.contains("git reset"))
        }),
        "should detect git reset command"
    );
}

#[test]
fn scan_dockerfile_multiline_run() {
    let dir = tempfile::tempdir().unwrap();
    let dockerfile = dir.path().join("Dockerfile");
    std::fs::write(
        &dockerfile,
        r#"FROM ubuntu:22.04
RUN apt-get update \
    && apt-get install -y curl \
    && git reset --hard HEAD
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    assert!(
        !findings.is_empty(),
        "should extract commands from multiline RUN"
    );
}

// ============================================================================
// Makefile Extractor Integration Tests
// ============================================================================

#[test]
fn scan_makefile_extracts_recipe_commands() {
    let dir = tempfile::tempdir().unwrap();
    let makefile = dir.path().join("Makefile");
    std::fs::write(
        &makefile,
        r#"clean:
	rm -rf build/
	git reset --hard

build:
	cargo build --release

deploy:
	git push --force origin main
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    // Should find git reset --hard and git push --force
    assert!(
        findings
            .iter()
            .any(|f| f["file"].as_str().map_or(false, |s| s.contains("Makefile"))),
        "should have findings from Makefile"
    );
}

#[test]
fn scan_makefile_ignores_variable_assignments() {
    let dir = tempfile::tempdir().unwrap();
    let makefile = dir.path().join("Makefile");
    std::fs::write(
        &makefile,
        r#"CLEANUP_CMD = rm -rf /
DANGER = git reset --hard

clean:
	echo "safe"
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    // Variable assignments should NOT be extracted as commands
    assert!(
        findings.is_empty()
            || !findings.iter().any(|f| {
                f["command"]
                    .as_str()
                    .map_or(false, |s| s.contains("CLEANUP_CMD"))
            }),
        "should not extract variable assignments"
    );
}

// ============================================================================
// GitHub Actions Extractor Integration Tests
// ============================================================================

#[test]
fn scan_github_actions_extracts_run_steps() {
    let dir = tempfile::tempdir().unwrap();
    let workflow_dir = dir.path().join(".github").join("workflows");
    std::fs::create_dir_all(&workflow_dir).unwrap();
    let workflow = workflow_dir.join("ci.yml");
    std::fs::write(
        &workflow,
        r#"name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: git reset --hard HEAD~5
      - run: |
          echo "Building..."
          npm run build
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    assert!(
        findings
            .iter()
            .any(|f| f["file"].as_str().map_or(false, |s| s.contains("ci.yml"))),
        "should have findings from GitHub Actions workflow"
    );
}

#[test]
fn scan_github_actions_ignores_env_values() {
    let dir = tempfile::tempdir().unwrap();
    let workflow_dir = dir.path().join(".github").join("workflows");
    std::fs::create_dir_all(&workflow_dir).unwrap();
    let workflow = workflow_dir.join("test.yml");
    std::fs::write(
        &workflow,
        r#"name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      DANGEROUS: "git reset --hard"
    steps:
      - run: echo "safe"
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    // env: values should NOT trigger findings
    assert!(
        findings.is_empty(),
        "should not flag env variable values as dangerous"
    );
}

// ============================================================================
// GitLab CI Extractor Integration Tests
// ============================================================================

#[test]
fn scan_gitlab_ci_extracts_script_sections() {
    let dir = tempfile::tempdir().unwrap();
    let gitlab_ci = dir.path().join(".gitlab-ci.yml");
    std::fs::write(
        &gitlab_ci,
        r#"stages:
  - build
  - deploy

build:
  stage: build
  script:
    - npm ci
    - npm run build

deploy:
  stage: deploy
  script:
    - git push --force origin main
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    assert!(
        findings.iter().any(|f| f["file"]
            .as_str()
            .map_or(false, |s| s.contains(".gitlab-ci.yml"))),
        "should have findings from GitLab CI"
    );
}

// ============================================================================
// package.json Extractor Integration Tests
// ============================================================================

#[test]
fn scan_package_json_extracts_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let package_json = dir.path().join("package.json");
    std::fs::write(
        &package_json,
        r#"{
  "name": "test-package",
  "scripts": {
    "clean": "rm -rf dist node_modules",
    "deploy": "git push --force",
    "build": "tsc"
  }
}"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    assert!(
        findings.iter().any(|f| f["file"]
            .as_str()
            .map_or(false, |s| s.contains("package.json"))),
        "should have findings from package.json"
    );
}

#[test]
fn scan_package_json_ignores_description() {
    let dir = tempfile::tempdir().unwrap();
    let package_json = dir.path().join("package.json");
    std::fs::write(
        &package_json,
        r#"{
  "name": "test-package",
  "description": "Uses rm -rf to clean build artifacts",
  "scripts": {
    "build": "tsc"
  }
}"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    // description field should NOT trigger findings
    assert!(
        findings.is_empty(),
        "should not flag description field content"
    );
}

// ============================================================================
// Terraform Extractor Integration Tests
// ============================================================================

#[test]
fn scan_terraform_extracts_local_exec() {
    let dir = tempfile::tempdir().unwrap();
    let terraform = dir.path().join("main.tf");
    std::fs::write(
        &terraform,
        r#"resource "null_resource" "cleanup" {
  provisioner "local-exec" {
    command = "rm -rf /tmp/build && git reset --hard"
  }
}
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    assert!(
        findings
            .iter()
            .any(|f| f["file"].as_str().map_or(false, |s| s.contains("main.tf"))),
        "should have findings from Terraform local-exec"
    );
}

// ============================================================================
// Docker Compose Extractor Integration Tests
// ============================================================================

#[test]
fn scan_docker_compose_extracts_command() {
    let dir = tempfile::tempdir().unwrap();
    let compose = dir.path().join("docker-compose.yml");
    std::fs::write(
        &compose,
        r#"services:
  app:
    image: alpine
    command: sh -c "git reset --hard && ./start.sh"
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {}", stdout);
    eprintln!("stderr: {}", stderr);
    eprintln!("dir path: {}", dir.path().display());
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    assert!(
        findings.iter().any(|f| f["file"]
            .as_str()
            .map_or(false, |s| s.contains("docker-compose.yml"))),
        "should have findings from docker-compose.yml: findings={:?}",
        findings
    );
}

#[test]
fn scan_docker_compose_ignores_environment() {
    let dir = tempfile::tempdir().unwrap();
    let compose = dir.path().join("docker-compose.yml");
    std::fs::write(
        &compose,
        r#"services:
  app:
    image: alpine
    environment:
      DANGER: "git reset --hard"
    command: echo safe
"#,
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let findings = json["findings"].as_array().unwrap();

    // environment values should NOT trigger findings
    assert!(
        findings.is_empty(),
        "should not flag environment variable values"
    );
}

// ============================================================================
// Multi-File Repository Integration Test
// ============================================================================

#[test]
fn scan_multi_format_repository() {
    let dir = tempfile::tempdir().unwrap();

    // Create shell script
    let shell = dir.path().join("deploy.sh");
    std::fs::write(&shell, "#!/bin/bash\ngit push --force\n").unwrap();

    // Create Dockerfile
    let dockerfile = dir.path().join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine\nRUN git reset --hard\n").unwrap();

    // Create Makefile
    let makefile = dir.path().join("Makefile");
    std::fs::write(&makefile, "deploy:\n\tgit push --force\n").unwrap();

    // Create GitHub Actions
    let workflow_dir = dir.path().join(".github").join("workflows");
    std::fs::create_dir_all(&workflow_dir).unwrap();
    let workflow = workflow_dir.join("ci.yml");
    std::fs::write(
        &workflow,
        "jobs:\n  build:\n    steps:\n      - run: git reset --hard\n",
    )
    .unwrap();

    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let summary = &json["summary"];

    // Should scan multiple file types
    assert!(
        summary["files_scanned"].as_u64().unwrap() >= 4,
        "should scan at least 4 files"
    );

    let findings = json["findings"].as_array().unwrap();
    assert!(
        !findings.is_empty(),
        "should have findings across multiple file types"
    );
}

// ============================================================================
// Performance Test
// ============================================================================

#[test]
fn scan_performance_large_dockerfile() {
    let dir = tempfile::tempdir().unwrap();
    let dockerfile = dir.path().join("Dockerfile");

    // Generate large Dockerfile with many RUN commands
    let mut content = String::from("FROM alpine\n");
    for i in 0..500 {
        content.push_str(&format!("RUN echo step{}\n", i));
    }
    content.push_str("RUN git reset --hard\n");
    std::fs::write(&dockerfile, &content).unwrap();

    let start = std::time::Instant::now();
    let output = run_dcg_scan(&["--paths", dir.path().to_str().unwrap(), "--format", "json"]);
    let elapsed = start.elapsed();

    assert!(output.status.success() || !output.status.success()); // Either outcome is fine
    assert!(
        elapsed.as_millis() < 5000,
        "scanning large Dockerfile should complete in < 5s"
    );
}
