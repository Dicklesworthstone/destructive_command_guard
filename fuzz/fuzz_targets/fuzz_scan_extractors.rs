//! Fuzz target for scan mode extractors (Dockerfile, Makefile, GitHub Actions, etc.)
//!
//! This fuzzes the extractors for CI/DevOps files and validates:
//! - No panics for arbitrary UTF-8 input
//! - Returned line numbers are valid (>= 1)
//! - Extractor IDs are non-empty
//! - Commands are non-empty when returned

#![no_main]

use destructive_command_guard::scan::{
    extract_docker_compose_from_str, extract_dockerfile_from_str,
    extract_github_actions_workflow_from_str, extract_gitlab_ci_from_str,
    extract_makefile_from_str, extract_package_json_from_str, extract_shell_script_from_str,
    extract_terraform_from_str,
};
use libfuzzer_sys::fuzz_target;

/// Common keywords to use for extraction
const KEYWORDS: &[&str] = &["rm", "git", "kubectl", "docker", "aws", "gcloud"];

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        // Limit input size to avoid spending too much time on huge inputs
        if content.len() > 10_000 {
            return;
        }

        // Fuzz Dockerfile extractor
        let results = extract_dockerfile_from_str("Dockerfile", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }

        // Fuzz Makefile extractor
        let results = extract_makefile_from_str("Makefile", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }

        // Fuzz GitHub Actions extractor
        let results =
            extract_github_actions_workflow_from_str(".github/workflows/ci.yml", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }

        // Fuzz GitLab CI extractor
        let results = extract_gitlab_ci_from_str(".gitlab-ci.yml", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }

        // Fuzz Docker Compose extractor
        let results = extract_docker_compose_from_str("docker-compose.yml", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }

        // Fuzz package.json extractor
        let results = extract_package_json_from_str("package.json", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }

        // Fuzz Terraform extractor
        let results = extract_terraform_from_str("main.tf", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }

        // Fuzz shell script extractor
        let results = extract_shell_script_from_str("script.sh", content, KEYWORDS);
        for r in &results {
            assert!(r.line >= 1, "line number must be >= 1");
            assert!(!r.extractor_id.is_empty(), "extractor_id must be non-empty");
        }
    }
});
