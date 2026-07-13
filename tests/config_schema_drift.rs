//! Drift check for the committed `config.schema.json`.
//!
//! `config.schema.json` at the repo root is the JSON Schema editors (Even
//! Better TOML / taplo) use to autocomplete and validate `config.toml`. It is
//! generated from the Rust config types via `dcg config schema`. This test
//! regenerates the schema from the current [`Config`] type and asserts the
//! committed file is byte-for-byte identical, so any change to a config struct
//! that isn't accompanied by a schema regeneration fails CI.
//!
//! To regenerate after an intentional config change, run either:
//!   `cargo run --bin dcg -- config schema --output config.schema.json`
//! or re-run this test with `DCG_BLESS_SCHEMA=1` to rewrite the committed file:
//!   `DCG_BLESS_SCHEMA=1 cargo test --test config_schema_drift`

use destructive_command_guard::config::config_json_schema_string;
use std::fs;
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.schema.json")
}

#[test]
fn committed_config_schema_is_up_to_date() {
    let generated = config_json_schema_string();
    let path = schema_path();

    // Opt-in regeneration for a deliberate config change.
    if std::env::var_os("DCG_BLESS_SCHEMA").is_some() {
        fs::write(&path, &generated).expect("write config.schema.json");
        println!("Regenerated {}", path.display());
        return;
    }

    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read committed schema at {}: {e}\n\
             Generate it with: cargo run --bin dcg -- config schema --output config.schema.json",
            path.display()
        )
    });

    assert_eq!(
        committed, generated,
        "config.schema.json is out of date with the Rust config types.\n\
         A config struct changed without regenerating the schema.\n\
         Regenerate with: cargo run --bin dcg -- config schema --output config.schema.json\n\
         (or: DCG_BLESS_SCHEMA=1 cargo test --test config_schema_drift)"
    );
}

#[test]
fn generated_schema_is_valid_json_with_expected_metadata() {
    let value: serde_json::Value =
        serde_json::from_str(&config_json_schema_string()).expect("schema is valid JSON");
    let obj = value.as_object().expect("schema root is an object");
    assert!(
        obj.contains_key("$schema"),
        "schema declares a $schema dialect"
    );
    assert_eq!(
        obj.get("$id").and_then(|v| v.as_str()),
        Some(destructive_command_guard::config::CONFIG_SCHEMA_ID),
    );
    assert_eq!(
        obj.get("title").and_then(|v| v.as_str()),
        Some("dcg configuration"),
    );
    assert!(
        obj.contains_key("properties"),
        "root object schema exposes config sections as properties"
    );
}
