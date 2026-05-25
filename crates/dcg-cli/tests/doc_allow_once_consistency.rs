//! Documentation consistency tests for allow-once feature.
//!
//! These tests verify that the allow-once documentation stays in sync with
//! the actual CLI implementation.

use std::path::Path;

fn read_repo_file(path: &str) -> std::io::Result<String> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manifest dir has parent")
        .parent()
        .expect("crates dir has parent");
    let full_path = repo_root.join(path);
    std::fs::read_to_string(&full_path)
}

#[test]
fn allow_once_doc_exists() -> std::io::Result<()> {
    let doc = read_repo_file("docs/allow-once-usage.md")?;
    assert!(
        !doc.is_empty(),
        "docs/allow-once-usage.md should not be empty"
    );
    Ok(())
}

#[test]
fn allow_once_doc_contains_key_commands() -> std::io::Result<()> {
    let doc = read_repo_file("docs/allow-once-usage.md")?;

    // Key CLI commands that must be documented
    let required_commands = [
        "dcg allow-once",
        "--single-use",
        "--force",
        "--show-raw",
        "--dry-run",
        "--pick",
        "--hash",
        "allow-once list",
        "allow-once revoke",
        "allow-once clear",
    ];

    let mut missing = Vec::new();
    for cmd in required_commands {
        if !doc.contains(cmd) {
            missing.push(cmd);
        }
    }

    assert!(
        missing.is_empty(),
        "docs/allow-once-usage.md is missing documentation for:\n{}",
        missing.join("\n")
    );

    Ok(())
}

#[test]
fn allow_once_doc_contains_key_concepts() -> std::io::Result<()> {
    let doc = read_repo_file("docs/allow-once-usage.md")?;

    // Key concepts that must be documented
    let required_concepts = [
        "24 hour",           // Expiry time
        "current directory", // Scope explanation (cwd scope)
        "project root",      // Scope explanation (project scope)
        "redact",            // Redaction behavior
        "single-use",        // Single-use semantics
        "config blocklist",  // Force override context
        "ALLOW-24H CODE",    // Output format
    ];

    let mut missing = Vec::new();
    for concept in required_concepts {
        if !doc.to_lowercase().contains(&concept.to_lowercase()) {
            missing.push(concept);
        }
    }

    assert!(
        missing.is_empty(),
        "docs/allow-once-usage.md is missing documentation for concepts:\n{}",
        missing.join("\n")
    );

    Ok(())
}

#[test]
fn allow_once_doc_contains_storage_paths() -> std::io::Result<()> {
    let doc = read_repo_file("docs/allow-once-usage.md")?;

    // Storage paths that must be documented
    let required_paths = [
        "pending_exceptions.jsonl",
        "allow_once.jsonl",
        "DCG_PENDING_EXCEPTIONS_PATH",
        "DCG_ALLOW_ONCE_PATH",
    ];

    let mut missing = Vec::new();
    for path in required_paths {
        if !doc.contains(path) {
            missing.push(path);
        }
    }

    assert!(
        missing.is_empty(),
        "docs/allow-once-usage.md is missing storage path documentation:\n{}",
        missing.join("\n")
    );

    Ok(())
}
