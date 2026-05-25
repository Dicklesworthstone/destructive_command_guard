//! Conformance tests for the documented JSON schemas.
//!
//! The docs in `docs/json-schema/` are integration contracts for agents and CI
//! consumers. These tests intentionally validate committed fixtures and real
//! hook output against those schemas so documentation drift is caught by the
//! normal test suite.

use regex::Regex;
use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn load_json(path: impl AsRef<Path>) -> Value {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("failed to parse {} as JSON: {err}", path.display()))
}

fn validate(schema: &Value, instance: &Value) -> Result<(), String> {
    let mut errors = Vec::new();
    validate_at("$", schema, instance, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

fn validate_at(path: &str, schema: &Value, instance: &Value, errors: &mut Vec<String>) {
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = one_of
            .iter()
            .filter(|candidate| {
                let mut candidate_errors = Vec::new();
                validate_at(path, candidate, instance, &mut candidate_errors);
                candidate_errors.is_empty()
            })
            .count();
        if matches != 1 {
            errors.push(format!(
                "{path}: expected exactly one oneOf schema to match, got {matches}"
            ));
        }
        return;
    }

    if let Some(expected) = schema.get("const") {
        if instance != expected {
            errors.push(format!("{path}: expected const {expected}, got {instance}"));
        }
    }

    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.iter().any(|value| value == instance) {
            errors.push(format!(
                "{path}: value {instance} is not in enum {values:?}"
            ));
        }
    }

    if let Some(type_spec) = schema.get("type") {
        let type_matches = match type_spec {
            Value::String(kind) => matches_type(kind, instance),
            Value::Array(kinds) => kinds
                .iter()
                .filter_map(Value::as_str)
                .any(|kind| matches_type(kind, instance)),
            _ => true,
        };
        if !type_matches {
            errors.push(format!(
                "{path}: value {instance} does not match type {type_spec}"
            ));
            return;
        }
    }

    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
        if let Some(number) = instance.as_f64() {
            if number < minimum {
                errors.push(format!("{path}: value {number} is below minimum {minimum}"));
            }
        }
    }

    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
        if let Some(number) = instance.as_f64() {
            if number > maximum {
                errors.push(format!("{path}: value {number} is above maximum {maximum}"));
            }
        }
    }

    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        if let Some(text) = instance.as_str() {
            let regex = Regex::new(pattern)
                .unwrap_or_else(|err| panic!("invalid schema regex at {path}: {pattern}: {err}"));
            if !regex.is_match(text) {
                errors.push(format!(
                    "{path}: string {text:?} does not match {pattern:?}"
                ));
            }
        }
    }

    if let Some(object) = instance.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    errors.push(format!("{path}: missing required field {field:?}"));
                }
            }
        }

        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, property_schema) in properties {
                if let Some(value) = object.get(field) {
                    validate_at(&format!("{path}.{field}"), property_schema, value, errors);
                }
            }
        }
    }

    if let Some(items_schema) = schema.get("items") {
        if let Some(items) = instance.as_array() {
            for (index, item) in items.iter().enumerate() {
                validate_at(&format!("{path}[{index}]"), items_schema, item, errors);
            }
        }
    }
}

fn matches_type(kind: &str, value: &Value) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn validate_fixture(schema_path: &str, fixture_path: &str) {
    let schema = load_json(schema_path);
    let instance = load_json(fixture_path);
    validate(&schema, &instance).unwrap_or_else(|errors| {
        panic!("{fixture_path} does not conform to {schema_path}:\n{errors}")
    });
}

fn rehydrate_hook_fixture(mut value: Value) -> Value {
    let output = value
        .get_mut("hookSpecificOutput")
        .and_then(Value::as_object_mut)
        .expect("hook fixture must contain hookSpecificOutput");

    if output.get("allowOnceCode") == Some(&Value::String("<DYNAMIC>".to_string())) {
        output.insert(
            "allowOnceCode".to_string(),
            Value::String("123456".to_string()),
        );
    }
    if output.get("allowOnceFullHash") == Some(&Value::String("<DYNAMIC>".to_string())) {
        output.insert(
            "allowOnceFullHash".to_string(),
            Value::String("a".repeat(64)),
        );
    }

    value
}

fn run_claude_hook(command: &str, config_toml: Option<&str>) -> (Value, String) {
    let home = tempfile::tempdir().expect("tempdir");
    if let Some(config_toml) = config_toml {
        let config_dir = home.path().join(".config/dcg");
        std::fs::create_dir_all(&config_dir).expect("create config dir");
        std::fs::write(config_dir.join("config.toml"), config_toml).expect("write config");
    }

    let payload = json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command
        }
    });
    let system_path = std::env::var("PATH").unwrap_or_default();
    let tmpdir = home.path().join("tmp");
    std::fs::create_dir_all(&tmpdir).expect("create tmpdir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .env_clear()
        .env("PATH", system_path)
        .env("HOME", home.path())
        .env("TMPDIR", tmpdir)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dcg");

    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write hook payload");

    let output = child.wait_with_output().expect("wait for dcg");
    assert_eq!(output.status.code(), Some(0), "Claude hook exits 0");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!stdout.trim().is_empty(), "hook command should emit JSON");

    let json = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("hook stdout was not JSON: {err}\nstdout:\n{stdout}"));
    (json, stderr)
}

#[test]
fn hook_schema_examples_conform() {
    let schema = load_json("docs/json-schema/hook-output.json");
    let examples = schema
        .get("examples")
        .and_then(Value::as_array)
        .expect("hook schema must include examples");

    for (index, example) in examples.iter().enumerate() {
        validate(&schema, example).unwrap_or_else(|errors| {
            panic!("hook-output.json example {index} does not conform:\n{errors}")
        });
    }
}

#[test]
fn hook_golden_deny_fixtures_conform() {
    let schema = load_json("docs/json-schema/hook-output.json");
    for fixture in [
        "tests/golden/hook/deny_filesystem.json",
        "tests/golden/hook/deny_git.json",
        "tests/golden/hook/deny_git_reset.json",
    ] {
        let instance = rehydrate_hook_fixture(load_json(fixture));
        validate(&schema, &instance)
            .unwrap_or_else(|errors| panic!("{fixture} does not conform:\n{errors}"));
    }
}

#[test]
fn real_claude_deny_output_conforms_to_hook_schema() {
    let schema = load_json("docs/json-schema/hook-output.json");
    let (instance, stderr) = run_claude_hook("git reset --hard HEAD~1", None);

    validate(&schema, &instance)
        .unwrap_or_else(|errors| panic!("real deny hook output does not conform:\n{errors}"));
    assert!(
        stderr.contains("BLOCKED") || stderr.contains("blocked"),
        "stderr should contain the human-readable denial block, got:\n{stderr}"
    );
}

#[test]
fn real_claude_warn_output_conforms_to_hook_schema() {
    let schema = load_json("docs/json-schema/hook-output.json");
    let (instance, stderr) = run_claude_hook(
        "git reset --hard HEAD~1",
        Some("[policy.rules]\n\"core.git:reset-hard\" = \"warn\"\n"),
    );

    validate(&schema, &instance)
        .unwrap_or_else(|errors| panic!("real warn hook output does not conform:\n{errors}"));
    assert_eq!(
        instance["hookSpecificOutput"]["permissionDecision"], "ask",
        "warn policy must emit Claude ask JSON"
    );
    assert!(
        stderr.contains("WARNING") || stderr.contains("warn"),
        "stderr should contain the human-readable warning, got:\n{stderr}"
    );
}

#[test]
fn scan_fixture_conforms_to_scan_results_schema() {
    validate_fixture(
        "docs/json-schema/scan-results.json",
        "tests/fixtures/scan/expected_output.json",
    );
}

#[test]
fn schema_examples_conform_for_scan_stats_and_error_outputs() {
    for schema_path in [
        "docs/json-schema/scan-results.json",
        "docs/json-schema/stats-output.json",
        "docs/json-schema/error.json",
    ] {
        let schema = load_json(schema_path);
        let examples = schema
            .get("examples")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{schema_path} must include examples"));

        for (index, example) in examples.iter().enumerate() {
            validate(&schema, example).unwrap_or_else(|errors| {
                panic!("{schema_path} example {index} does not conform:\n{errors}")
            });
        }
    }
}

#[test]
fn maximum_constraint_rejects_out_of_range_value() {
    let schema: Value = serde_json::json!({
        "type": "object",
        "properties": {
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
            }
        }
    });
    let valid = serde_json::json!({"confidence": 0.95});
    assert!(validate(&schema, &valid).is_ok());

    let too_high = serde_json::json!({"confidence": 1.5});
    let errors = validate(&schema, &too_high).unwrap_err();
    assert!(
        errors.contains("above maximum"),
        "expected 'above maximum' error, got: {errors}"
    );
}
