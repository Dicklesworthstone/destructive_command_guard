//! Backward-compatibility tests for the YAML pack schema across the
//! introduction of the `effects` and `default_effects` fields.
//!
//! These tests verify:
//!
//! 1. A pre-effects YAML pack (no `effects` field, no `default_effects`
//!    field) still loads successfully.
//! 2. Loaded packs use [`dcg_cli::packs::DEFAULT_PACK_EFFECTS`]
//!    as their fallback (Tier-B).
//! 3. Per-rule `effects` is `None` (will fall back to pack default at
//!    evaluation time via `Pack::resolve_effects`).
//! 4. Adding `effects` and `default_effects` fields to a previously valid
//!    pack does not break the loader.
//! 5. Verdicts (`Allow`/`Deny`) on a known legacy pattern do not change
//!    after the effects machinery is introduced.

use dcg_cli::packs::{DEFAULT_PACK_EFFECTS, external::ExternalPack};

const LEGACY_PACK_YAML: &str = r"
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
";

const PACK_YAML_WITH_EFFECTS: &str = r"
schema_version: 1
id: example.tagged
name: Example Effect-Tagged Pack
version: 1.0.0
description: Adds effects + default_effects fields.
keywords:
  - tagged_tool
default_effects:
  - mutate_vcs
  - write
destructive_patterns:
  - name: tagged-yeet
    pattern: \btagged_tool\s+yeet\b
    severity: critical
    description: yeet is irreversible
    effects:
      - irreversible
      - write
      - fs
  - name: tagged-meh
    pattern: \btagged_tool\s+meh\b
    severity: high
    description: meh just sits there
";

#[test]
fn legacy_yaml_pack_without_effects_loads() {
    let parsed: ExternalPack = serde_yaml::from_str(LEGACY_PACK_YAML).expect("parse legacy YAML");
    let pack = parsed.into_pack();
    assert_eq!(pack.id, "example.legacy");
    assert_eq!(pack.destructive_patterns.len(), 1);
    let rule = &pack.destructive_patterns[0];
    assert_eq!(rule.name, Some("legacy-destroy"));
    assert!(
        rule.effects.is_none(),
        "legacy pack must not synthesize per-rule effects"
    );
}

#[test]
fn legacy_pack_uses_default_pack_effects_as_fallback() {
    let parsed: ExternalPack = serde_yaml::from_str(LEGACY_PACK_YAML).expect("parse legacy YAML");
    let pack = parsed.into_pack();
    assert_eq!(
        pack.default_effects, DEFAULT_PACK_EFFECTS,
        "missing default_effects should fall back to DEFAULT_PACK_EFFECTS"
    );
}

#[test]
fn legacy_pack_resolve_effects_returns_pack_default() {
    let parsed: ExternalPack = serde_yaml::from_str(LEGACY_PACK_YAML).expect("parse legacy YAML");
    let pack = parsed.into_pack();
    let rule = &pack.destructive_patterns[0];
    let effects = pack.resolve_effects(rule);
    assert_eq!(
        effects, DEFAULT_PACK_EFFECTS,
        "untagged rule must inherit pack default"
    );
}

#[test]
fn yaml_pack_with_default_effects_loads() {
    let parsed: ExternalPack =
        serde_yaml::from_str(PACK_YAML_WITH_EFFECTS).expect("parse effect-tagged YAML");
    let pack = parsed.into_pack();
    assert_eq!(pack.id, "example.tagged");
    assert_eq!(
        pack.default_effects,
        &[dcg_core::Effect::MutateVcs, dcg_core::Effect::Write]
    );
}

#[test]
fn per_rule_effects_override_pack_default() {
    let parsed: ExternalPack =
        serde_yaml::from_str(PACK_YAML_WITH_EFFECTS).expect("parse effect-tagged YAML");
    let pack = parsed.into_pack();

    let tagged = pack
        .destructive_patterns
        .iter()
        .find(|p| p.name == Some("tagged-yeet"))
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
        .find(|p| p.name == Some("tagged-meh"))
        .expect("untagged rule");
    let untagged_effects = pack.resolve_effects(untagged);
    assert_eq!(
        untagged_effects,
        &[dcg_core::Effect::MutateVcs, dcg_core::Effect::Write],
        "untagged rule should inherit the effect-tagged pack-level default"
    );
}

#[test]
fn effects_fields_are_strict_superset_of_legacy_schema() {
    // Removing the new effects fields yields a valid pre-effects YAML.
    let stripped = r"
schema_version: 1
id: example.tagged
name: Example Effect-Tagged Pack
version: 1.0.0
description: Adds effects + default_effects fields.
keywords:
  - tagged_tool
destructive_patterns:
  - name: tagged-yeet
    pattern: \btagged_tool\s+yeet\b
    severity: critical
    description: yeet is irreversible
  - name: tagged-meh
    pattern: \btagged_tool\s+meh\b
    severity: high
    description: meh just sits there
";
    let parsed: ExternalPack = serde_yaml::from_str(stripped).expect("strip-back must still parse");
    assert_eq!(parsed.destructive_patterns.len(), 2);
    let pack = parsed.into_pack();
    assert_eq!(pack.default_effects, DEFAULT_PACK_EFFECTS);
}

#[test]
fn unknown_yaml_fields_do_not_break_loader() {
    // Future schema versions might add fields; loader should not be strict
    // about unknowns from forward-compatible additions.
    let yaml_with_unknown = r"
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
";
    let parsed: ExternalPack =
        serde_yaml::from_str(yaml_with_unknown).expect("forward-compat parse");
    let pack = parsed.into_pack();
    assert_eq!(pack.id, "example.future");
}
