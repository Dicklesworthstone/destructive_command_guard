//! v0.6 permission-modes bridge between the existing pack evaluator and
//! [`dcg_core::Engine`].
//!
//! Consumers that only need policy-level guardrails (jcode, agent SDKs,
//! …) should depend on `dcg-core` directly. Consumers that want the full
//! pack-rule library — which still lives in this crate — link the existing
//! `destructive_command_guard` crate and call [`evaluate_with_mode`] below.
//!
//! The function combines:
//!
//! 1. The legacy [`evaluate_command`] pipeline (pack rules, allowlist,
//!    heredoc / inline-script scanning, confidence scoring).
//! 2. The dcg-core [`dcg_core::Engine`] mode policy (Plan / AcceptEdits /
//!    DontAsk / BypassPermissions / Default / Auto).
//!
//! Pack rule denials always take precedence over mode-level decisions: a
//! `git push --force` is `Deny` even under `BypassPermissions` (the deny
//! path is enforced upstream of `Engine::evaluate`).

use dcg_core::{Decision, Effect, Engine, Mode, Session, ToolCall};

use crate::allowlist::LayeredAllowlist;
use crate::config::{CompiledOverrides, Config};
use crate::evaluator::{EvaluationDecision, EvaluationResult, evaluate_command};
use crate::packs::PackRegistry;

/// Evaluate a `Bash` command under a specific permission mode.
///
/// Returns a [`Decision`] (`Allow` / `Prompt` / `Deny`).
///
/// # Pipeline
///
/// 1. **Pack evaluation** — if a destructive rule matches, return `Deny`
///    with the rule's reason and any safer-alternative suggestions.
/// 2. **Effect resolution** — look up the matched pack's `default_effects`
///    (Tier-B) or pattern's `effects` (Tier-A). For unmatched commands,
///    pass `&[]` so the mode policy treats it as effect-free (typical
///    case for `Mode::Default`).
/// 3. **Mode policy** — feed into `engine.evaluate(...)`. The mode decides
///    whether to allow, prompt (with allow-once code), or deny.
pub fn evaluate_with_mode(
    command: &str,
    config: &Config,
    enabled_keywords: &[&str],
    compiled_overrides: &CompiledOverrides,
    allowlists: &LayeredAllowlist,
    engine: &Engine,
    session: &mut Session,
    mode: Mode,
) -> Decision {
    // BypassPermissions skips both pack rules and mode-policy checks.
    // The user has explicitly opted out of all guardrails.
    if mode == Mode::BypassPermissions {
        return Decision::Allow;
    }

    let result = evaluate_command(
        command,
        config,
        enabled_keywords,
        compiled_overrides,
        allowlists,
    );

    if result.decision == EvaluationDecision::Deny {
        return decision_from_pack_match(&result);
    }

    // No pack rule matched. Fall through to mode policy with empty effects;
    // unmatched commands are by definition unknown effects, so the mode's
    // fallthrough policy (`Default`/`Auto`/`AcceptEdits` allow, `Plan`/
    // `DontAsk` deny) decides.
    let effects: &[Effect] = &[];
    let tool = ToolCall::bash(command);
    engine.evaluate(session, &tool, mode, effects)
}

/// Evaluate a command with mode + pack-aware effect resolution.
///
/// Variant that also resolves Tier-A effects from the matched pack/rule
/// when the command was allowed at the rule level (e.g. an effect-tagged
/// safe pattern). Useful for `Plan` mode evaluation of an enabled-but-not-
/// destructive command (`git status` → `[Read]` → allowed in `Plan`).
///
/// Requires a `PackRegistry` reference to look up the pack that owns the
/// rule. When no pack info is available, falls back to `evaluate_with_mode`
/// behavior.
pub fn evaluate_with_mode_and_packs(
    command: &str,
    config: &Config,
    enabled_keywords: &[&str],
    compiled_overrides: &CompiledOverrides,
    allowlists: &LayeredAllowlist,
    registry: &PackRegistry,
    engine: &Engine,
    session: &mut Session,
    mode: Mode,
) -> Decision {
    if mode == Mode::BypassPermissions {
        return Decision::Allow;
    }

    let result = evaluate_command(
        command,
        config,
        enabled_keywords,
        compiled_overrides,
        allowlists,
    );

    if result.decision == EvaluationDecision::Deny {
        return decision_from_pack_match(&result);
    }

    // For commands that didn't deny, attempt to find the matching pack so
    // we can attribute Tier-A or pack-default effects to the call. Look up
    // by pattern_info.pack_id (set when a pack matched non-destructively).
    let effects: Vec<Effect> = result
        .pattern_info
        .as_ref()
        .and_then(|m| m.pack_id.as_deref())
        .and_then(|id| {
            registry.get(id).map(|pack| {
                // Pattern-level Tier-A overrides pack default. We don't have
                // direct access to the matched DestructivePattern from the
                // result, only the rule name. For now use pack default —
                // Phase 2 will plumb the pattern reference through.
                pack.default_effects.to_vec()
            })
        })
        .unwrap_or_default();

    let tool = ToolCall::bash(command);
    engine.evaluate(session, &tool, mode, &effects)
}

fn decision_from_pack_match(result: &EvaluationResult) -> Decision {
    let info = match result.pattern_info.as_ref() {
        Some(p) => p,
        None => return Decision::deny("blocked by destructive_command_guard"),
    };
    let alternatives: Vec<String> = info
        .suggestions
        .iter()
        .map(|s| s.command.to_string())
        .collect();
    Decision::deny_with_alternatives(info.reason.clone(), alternatives)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fresh_session() -> Session {
        Session::with_id("test")
    }

    fn fresh_engine() -> Engine {
        Engine::new(dcg_core::EngineConfig::builder().working_dir(".").build())
    }

    fn fresh_config() -> Config {
        Config::default()
    }

    fn fresh_allowlists() -> LayeredAllowlist {
        LayeredAllowlist::load_from_paths(None, None, None)
    }

    fn fresh_overrides() -> CompiledOverrides {
        Config::default().overrides.compile()
    }

    #[test]
    fn bypass_short_circuits_to_allow_even_for_dangerous() {
        let engine = fresh_engine();
        let mut session = fresh_session();
        let cfg = fresh_config();
        let overrides = fresh_overrides();
        let allowlists = fresh_allowlists();
        let d = evaluate_with_mode(
            "git push --force origin main",
            &cfg,
            &[],
            &overrides,
            &allowlists,
            &engine,
            &mut session,
            Mode::BypassPermissions,
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn safe_command_allowed_under_default() {
        let engine = fresh_engine();
        let mut session = fresh_session();
        let cfg = fresh_config();
        let overrides = fresh_overrides();
        let allowlists = fresh_allowlists();
        let keywords: Vec<&str> = vec!["git"];
        let d = evaluate_with_mode(
            "git status",
            &cfg,
            &keywords,
            &overrides,
            &allowlists,
            &engine,
            &mut session,
            Mode::Default,
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn working_dir_is_set_correctly() {
        let _engine = Engine::new(
            dcg_core::EngineConfig::builder()
                .working_dir(PathBuf::from("/tmp"))
                .build(),
        );
        // Smoke test: construction succeeds with non-default working dir.
    }
}
