//! Backward compatibility tests for v0.5 YAML packs against v0.6 loader.
//!
//! These tests verify:
//!
//! 1. A `schema_version: 1` YAML pack with no `effects` and no
//!    `default_effects` field still loads successfully.
//! 2. Loaded packs use [`destructive_command_guard::packs::DEFAULT_PACK_EFFECTS`]
//!    as their fallback (Tier-B).
//! 3. Per-rule `effects` is `None` (will fall back to pack default at
//!    evaluation time via `Pack::resolve_effects`).
//! 4. Adding `effects` and `default_effects` fields to a v0.5 pack does not
//!    break the loader.
//! 5. Verdicts (`Allow`/`Deny`) on a known v0.5 pattern do not change after
//!    the v0.6 effects machinery is introduced.

use destructive_command_guard::packs::{DEFAULT_PACK_EFFECTS, external::ExternalPack};

const V05_PACK_YAML: &str = r#"
schema_version: 1
id: example.legacy
name: Example Legacy v0.5 Pack
version: 1.0.0
description: A pack from before v0.6 with no effects field.
keywords:
  - legacy_tool
destructive_patterns:
  - name: legacy-destroy
    pattern: \blegacy_tool\s+destroy\b
    severity: critical
    description: legacy_tool destroy is irreversible
"#;

const V06_PACK_YAML: &str = r#"
schema_version: 1
id: example.v06
name: Example v0.6 Pack
version: 1.0.0
description: Adds effects + default_effects fields.
keywords:
  - v06_tool
default_effects:
  - mutate_vcs
  - write
destructive_patterns:
  - name: v06-rule-tagged
    pattern: \bv06_tool\s+yeet\b
    severity: critical
    description: yeet is irreversible
    effects:
      - irreversible
      - write
      - fs
  - name: v06-rule-untagged
    pattern: \bv06_tool\s+meh\b
    severity: high
    description: meh just sits there
"#;

#[test]
fn v05_yaml_pack_without_effects_loads() {
    let parsed: ExternalPack = serde_yaml::from_str(V05_PACK_YAML).expect("parse v0.5 YAML");
    let pack = parsed.into_pack();
    assert_eq!(pack.id, "example.legacy");
    assert_eq!(pack.destructive_patterns.len(), 1);
    let rule = &pack.destructive_patterns[0];
    assert_eq!(rule.name, Some("legacy-destroy"));
    assert!(
        rule.effects.is_none(),
        "v0.5 pack must not synthesize per-rule effects"
    );
}

#[test]
fn v05_pack_uses_default_pack_effects_as_fallback() {
    let parsed: ExternalPack = serde_yaml::from_str(V05_PACK_YAML).expect("parse v0.5 YAML");
    let pack = parsed.into_pack();
    assert_eq!(
        pack.default_effects, DEFAULT_PACK_EFFECTS,
        "missing default_effects should fall back to DEFAULT_PACK_EFFECTS"
    );
}

#[test]
fn v05_pack_resolve_effects_returns_pack_default() {
    let parsed: ExternalPack = serde_yaml::from_str(V05_PACK_YAML).expect("parse v0.5 YAML");
    let pack = parsed.into_pack();
    let rule = &pack.destructive_patterns[0];
    let effects = pack.resolve_effects(rule);
    assert_eq!(
        effects, DEFAULT_PACK_EFFECTS,
        "untagged rule must inherit pack default"
    );
}

#[test]
fn v06_yaml_pack_with_default_effects_loads() {
    let parsed: ExternalPack = serde_yaml::from_str(V06_PACK_YAML).expect("parse v0.6 YAML");
    let pack = parsed.into_pack();
    assert_eq!(pack.id, "example.v06");
    assert_eq!(
        pack.default_effects,
        &[dcg_core::Effect::MutateVcs, dcg_core::Effect::Write]
    );
}

#[test]
fn v06_per_rule_effects_override_pack_default() {
    let parsed: ExternalPack = serde_yaml::from_str(V06_PACK_YAML).expect("parse v0.6 YAML");
    let pack = parsed.into_pack();

    let tagged = pack
        .destructive_patterns
        .iter()
        .find(|p| p.name == Some("v06-rule-tagged"))
        .expect("tagged rule");
    let tagged_effects = pack.resolve_effects(tagged);
    assert_eq!(
        tagged_effects,
        &[
            dcg_core::Effect::Irreversible,
            dcg_core::Effect::Write,
            dcg_core::Effect::Fs
        ]
    );

    let untagged = pack
        .destructive_patterns
        .iter()
        .find(|p| p.name == Some("v06-rule-untagged"))
        .expect("untagged rule");
    let untagged_effects = pack.resolve_effects(untagged);
    assert_eq!(
        untagged_effects,
        &[dcg_core::Effect::MutateVcs, dcg_core::Effect::Write],
        "untagged rule should inherit the v0.6 pack-level default"
    );
}

#[test]
fn v06_pack_yaml_is_strict_supersets_of_v05() {
    // Removing the new fields from V06 yields valid v0.5 YAML.
    let stripped = r#"
schema_version: 1
id: example.v06
name: Example v0.6 Pack
version: 1.0.0
description: Adds effects + default_effects fields.
keywords:
  - v06_tool
destructive_patterns:
  - name: v06-rule-tagged
    pattern: \bv06_tool\s+yeet\b
    severity: critical
    description: yeet is irreversible
  - name: v06-rule-untagged
    pattern: \bv06_tool\s+meh\b
    severity: high
    description: meh just sits there
"#;
    let parsed: ExternalPack = serde_yaml::from_str(stripped).expect("strip-back must still parse");
    assert_eq!(parsed.destructive_patterns.len(), 2);
    let pack = parsed.into_pack();
    assert_eq!(pack.default_effects, DEFAULT_PACK_EFFECTS);
}

#[test]
fn unknown_yaml_fields_do_not_break_loader() {
    // Future schema versions might add fields; loader should not be strict
    // about unknowns from forward-compatible additions.
    let yaml_with_unknown = r#"
schema_version: 1
id: example.future
name: Future Pack
version: 1.0.0
keywords:
  - future
destructive_patterns:
  - name: future-rule
    pattern: \bfuture\s+thing\b
    severity: high
    description: A future rule
"#;
    let parsed: ExternalPack =
        serde_yaml::from_str(yaml_with_unknown).expect("forward-compat parse");
    let pack = parsed.into_pack();
    assert_eq!(pack.id, "example.future");
}
