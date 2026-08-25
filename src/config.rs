//! Configuration system for dcg.
//!
//! Supports layered configuration from multiple sources:
//! 1. Environment variables (highest priority)
//! 2. Explicit config (`DCG_CONFIG`)
//! 3. User config ($XDG_CONFIG_HOME/dcg/config.toml, ~/.config/dcg/config.toml, or
//!    platform-native config dir)
//! 4. System config (/etc/dcg/config.toml)
//! 5. Compiled defaults (lowest priority)
//!
//! A repository's automatically discovered `.dcg.toml` is an untrusted policy
//! contribution, not a normal precedence layer. It may add protection, but it
//! cannot add allow rules, disable packs, select custom code/data paths, or
//! otherwise weaken settings chosen by a trusted source. Users who deliberately
//! trust the entire file can opt in explicitly with `DCG_CONFIG=.dcg.toml`.

use crate::interactive::{InteractiveConfig, VerificationMethod};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Maximum config file size dcg is willing to read into memory.
///
/// `fs::read_to_string` is unbounded; a malicious or accidentally-huge file
/// (a 2 GiB symlinked log, a runaway dump) would otherwise be loaded in
/// full before parsing. 1 MiB is well above any sane TOML config; loaded
/// data above this cap is rejected.
pub(crate) const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Trust class for a config-file source. Controls symlink handling and, for an
/// automatically discovered project config, which settings may take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigSource {
    /// User-selected layer (user config or an explicit `DCG_CONFIG` path).
    /// Symlinks are followed normally; the read helper enforces only the size
    /// cap. Selecting an explicit path is itself the trust decision.
    Untrusted,
    /// Automatically discovered repository `.dcg.toml`. On Unix, the leaf
    /// must be a direct regular file: symlinks, FIFOs, devices, and
    /// descriptor-backed pseudo-files are rejected before any bytes are read.
    /// Other platforms fail closed until native handle/reparse validation is
    /// available.
    AutoProject,
    /// System-wide config layer (`/etc/dcg/config.toml`). Unix accepts only a
    /// direct root-owned regular file with no group/world write access beneath
    /// a direct, equally trusted directory chain. Other platforms fail closed
    /// until native ACL and reparse-point validation is available.
    System,
}

/// Read a config file with a size cap and source-specific path policy.
///
/// Restricted Unix sources are opened with `O_NOFOLLOW | O_NONBLOCK |
/// O_CLOEXEC`, validated through the opened descriptor, and then read through
/// that same descriptor. This ordering prevents a path swap from redirecting
/// the subsequent read and prevents a FIFO from wedging the hook before its
/// file type can be rejected.
pub(crate) fn read_config_file_bounded(path: &Path, source: ConfigSource) -> Option<String> {
    #[cfg(not(unix))]
    if matches!(source, ConfigSource::AutoProject | ConfigSource::System) {
        warn_and_ignore_non_unix_restricted_config(path, source);
        return None;
    }

    let mut file = match open_config_file_for_source(path, source) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!(
                "Warning: refusing to load config file '{}': {}",
                path.display(),
                e
            );
            return None;
        }
    };

    // `take(MAX_CONFIG_BYTES + 1)` lets us tell "exactly cap" (allowed) from
    // "more than cap" (rejected) without reading unbounded bytes either way.
    let mut buf = String::new();
    if let Err(e) = file
        .by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut buf)
    {
        eprintln!(
            "Warning: Failed to read config file '{}': {}",
            path.display(),
            e
        );
        return None;
    }
    if buf.len() as u64 > MAX_CONFIG_BYTES {
        eprintln!(
            "Warning: refusing to load config '{}' — exceeds {}-byte cap",
            path.display(),
            MAX_CONFIG_BYTES
        );
        return None;
    }

    Some(buf)
}

/// Render a TOML error from an automatically discovered repository config
/// without reflecting any attacker-controlled source bytes.
///
/// `toml::de::Error`'s normal `Display` output embeds a source excerpt. That is
/// useful for a config path the user selected, but unsafe for repository-owned
/// `.dcg.toml`: the excerpt can contain terminal control sequences or an
/// arbitrarily long line. Only a bounded numeric location is reported here.
pub(crate) fn safe_auto_project_toml_error(input: &str, error: &toml::de::Error) -> String {
    let Some(span) = error.span() else {
        return "Invalid TOML in automatic project config (location unavailable)".to_string();
    };

    let offset = span.start.min(input.len());
    let mut line = 1usize;
    let mut column = 1usize;
    for byte in input.as_bytes().iter().take(offset) {
        if *byte == b'\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }

    format!("Invalid TOML in automatic project config at line {line}, column {column}")
}

fn open_config_file_for_source(path: &Path, source: ConfigSource) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        if source != ConfigSource::Untrusted {
            return open_restricted_unix_config_file(path, source);
        }
    }

    #[cfg(not(unix))]
    if source != ConfigSource::Untrusted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "restricted config source requires native handle and reparse-point validation",
        ));
    }

    fs::File::open(path)
}

#[cfg(unix)]
fn open_restricted_unix_config_file(path: &Path, source: ConfigSource) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    debug_assert_ne!(source, ConfigSource::Untrusted);

    if source == ConfigSource::System {
        // Preserve the normal "missing optional config" behavior without
        // opening the path. For an existing path, validate every lexical
        // ancestor before traversal; the same chain is checked again after the
        // descriptor/path identity check to close replacement races.
        fs::symlink_metadata(path)?;
        validate_unix_system_ancestor_chain(path).map_err(unix_config_trust_io_error)?;
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;

    validate_opened_unix_config_file(path, &file, source).map_err(unix_config_trust_io_error)?;

    if source == ConfigSource::System {
        validate_unix_system_ancestor_chain(path).map_err(unix_config_trust_io_error)?;
    }

    Ok(file)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixConfigTrustError {
    PathMustBeAbsoluteAndNormalized,
    MetadataUnavailable,
    Symlink,
    NotRegularFile,
    NotDirectory,
    UntrustedOwnerOrMode,
    PathIdentityChanged,
}

#[cfg(unix)]
const fn unix_config_trust_error_message(error: UnixConfigTrustError) -> &'static str {
    match error {
        UnixConfigTrustError::PathMustBeAbsoluteAndNormalized => {
            "system config path must be absolute and contain no '.' or '..' components"
        }
        UnixConfigTrustError::MetadataUnavailable => "unable to inspect config path safely",
        UnixConfigTrustError::Symlink => "symlinks are not permitted for this config source",
        UnixConfigTrustError::NotRegularFile => "config source is not a regular file",
        UnixConfigTrustError::NotDirectory => "system config ancestor is not a directory",
        UnixConfigTrustError::UntrustedOwnerOrMode => {
            "system config path is not root-owned or is group/world writable"
        }
        UnixConfigTrustError::PathIdentityChanged => {
            "config path changed while it was being validated"
        }
    }
}

#[cfg(unix)]
fn unix_config_trust_io_error(error: UnixConfigTrustError) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        unix_config_trust_error_message(error),
    )
}

#[cfg(unix)]
fn validate_opened_unix_config_file(
    path: &Path,
    file: &fs::File,
    source: ConfigSource,
) -> Result<(), UnixConfigTrustError> {
    use std::os::unix::fs::MetadataExt;

    let opened_metadata = file
        .metadata()
        .map_err(|_| UnixConfigTrustError::MetadataUnavailable)?;
    if !opened_metadata.is_file() {
        return Err(UnixConfigTrustError::NotRegularFile);
    }
    if source == ConfigSource::System
        && unix_owner_or_mode_is_user_writable(opened_metadata.uid(), opened_metadata.mode())
    {
        return Err(UnixConfigTrustError::UntrustedOwnerOrMode);
    }

    // `symlink_metadata` describes the leaf itself. Combined with O_NOFOLLOW,
    // this rejects a symlink both before and after open. Comparing dev/inode
    // binds the current path to the already-open descriptor, so a concurrent
    // rename cannot redirect the bytes read below.
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| UnixConfigTrustError::MetadataUnavailable)?;
    if path_metadata.file_type().is_symlink() {
        return Err(UnixConfigTrustError::Symlink);
    }
    if !path_metadata.is_file() {
        return Err(UnixConfigTrustError::NotRegularFile);
    }
    if !unix_metadata_refers_to_same_file(&opened_metadata, &path_metadata) {
        return Err(UnixConfigTrustError::PathIdentityChanged);
    }

    Ok(())
}

#[cfg(unix)]
fn validate_unix_system_ancestor_chain(path: &Path) -> Result<(), UnixConfigTrustError> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(UnixConfigTrustError::PathMustBeAbsoluteAndNormalized);
    }

    let parent = path
        .parent()
        .ok_or(UnixConfigTrustError::PathMustBeAbsoluteAndNormalized)?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| UnixConfigTrustError::MetadataUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(UnixConfigTrustError::Symlink);
        }
        if !metadata.is_dir() {
            return Err(UnixConfigTrustError::NotDirectory);
        }
        if unix_owner_or_mode_is_user_writable(metadata.uid(), metadata.mode()) {
            return Err(UnixConfigTrustError::UntrustedOwnerOrMode);
        }
    }

    Ok(())
}

#[cfg(unix)]
fn unix_metadata_refers_to_same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
const fn unix_owner_or_mode_is_user_writable(uid: u32, mode: u32) -> bool {
    // A non-root owner can restore owner-write permission with chmod even when
    // the current mode is read-only, so ownership alone makes the object
    // untrusted. Group/world write bits are rejected regardless of membership;
    // this is intentionally a conservative privileged-config policy.
    uid != 0 || (mode & 0o022) != 0
}

#[cfg(not(unix))]
fn warn_and_ignore_non_unix_restricted_config(path: &Path, source: ConfigSource) {
    let source_name = match source {
        ConfigSource::AutoProject => "automatic project",
        ConfigSource::System => "system",
        ConfigSource::Untrusted => return,
    };

    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            eprintln!(
                "Warning: ignoring {source_name} config '{}' — native ACL and reparse-point validation is unavailable",
                path.display()
            );
        }
        Err(error) => {
            eprintln!(
                "Warning: ignoring {source_name} config '{}' — unable to inspect path safely: {}",
                path.display(),
                error
            );
        }
    }
}

/// Classify a failed bounded read using the same platform/source semantics as
/// [`read_config_file_bounded`]. The read helper has already emitted the
/// detailed warning; this bounded, source-safe summary is retained for config
/// and doctor output.
fn failed_config_read_outcome(
    path: &Path,
    source: ConfigSource,
) -> (ConfigFileStatus, Option<String>) {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (ConfigFileStatus::Missing, None),
        Err(error) => (
            ConfigFileStatus::Rejected,
            Some(format!("unable to inspect path safely: {error}")),
        ),
        Ok(_) => {
            #[cfg(not(unix))]
            if matches!(source, ConfigSource::AutoProject | ConfigSource::System) {
                return (
                    ConfigFileStatus::IgnoredUnsupported,
                    Some(
                        "native ACL, reparse-point, and file-identity validation is unavailable"
                            .to_string(),
                    ),
                );
            }

            let detail = match source {
                ConfigSource::AutoProject => {
                    "automatic project config failed direct-regular-file validation"
                }
                ConfigSource::System => {
                    "system config failed privileged path, ownership, mode, or regular-file validation"
                }
                ConfigSource::Untrusted => {
                    "config could not be read safely or exceeded the configured size cap"
                }
            };
            (ConfigFileStatus::Rejected, Some(detail.to_string()))
        }
    }
}

fn record_config_outcome(
    target: &mut Option<Vec<ConfigSourceOutcome>>,
    outcome: Option<ConfigSourceOutcome>,
) {
    if let (Some(target), Some(outcome)) = (target.as_mut(), outcome) {
        target.push(outcome);
    }
}

/// Environment variable prefix for all config options.
const ENV_PREFIX: &str = "DCG";

/// Default config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Project-level config file name.
const PROJECT_CONFIG_NAME: &str = ".dcg.toml";

/// Env var for selecting an explicit config file path.
///
/// This is intentionally separate from per-setting env overrides (packs, verbose,
/// heredoc settings, etc.). It changes *which file* is loaded as a config layer.
pub(crate) const ENV_CONFIG_PATH: &str = "DCG_CONFIG";

/// Maximum parent directories to traverse when searching for a repo root.
///
/// This bounds filesystem work in deeply nested directories.
pub(crate) const REPO_ROOT_SEARCH_MAX_HOPS: usize = 50;

/// Maximum number of external pack files a `packs.custom_paths` glob
/// expansion may yield (issue #293).
///
/// External packs load on every hook invocation, so an over-broad glob must
/// not turn each Bash command into an unbounded file-parsing pass. Files
/// beyond the cap are skipped with a stderr warning.
pub const MAX_CUSTOM_PACK_FILES: usize = 64;

/// Main configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct Config {
    /// General settings.
    pub general: GeneralConfig,

    /// Output display settings.
    pub output: OutputConfig,

    /// Theme configuration for rich terminal output.
    pub theme: ThemeConfig,

    /// Pack configuration.
    pub packs: PacksConfig,

    /// Decision mode policy configuration.
    pub policy: PolicyConfig,

    /// Custom overrides.
    pub overrides: OverridesConfig,

    /// Allowlist file management settings.
    pub allowlist: AllowlistConfig,

    /// Heredoc/inline-script scanning configuration.
    pub heredoc: HeredocConfig,

    /// Confidence scoring configuration for ambiguous matches.
    pub confidence: ConfidenceConfig,

    /// Structured logging configuration.
    pub logging: crate::logging::LoggingConfig,

    /// Command history configuration.
    pub history: HistoryConfig,

    /// Interactive prompt configuration.
    pub interactive: InteractiveConfig,

    /// Git branch-aware strictness configuration.
    pub git_awareness: GitAwarenessConfig,

    /// Agent-specific profiles configuration.
    #[serde(default)]
    pub agents: AgentsConfig,

    /// Graduated response system configuration.
    #[serde(default)]
    pub response: ResponseConfig,

    /// Project-specific configurations (keyed by absolute path).
    #[serde(default)]
    pub projects: std::collections::HashMap<String, ProjectConfig>,

    /// Per-rule settings keyed by `"<pack_id>:<pattern_name>"` (#284).
    ///
    /// Currently carries `exempt_target_globs`, the rule-scoped target-path
    /// exemption. See [`RuleConfig`].
    #[serde(default)]
    pub rules: std::collections::HashMap<String, RuleConfig>,
}

/// Identity of a file-backed configuration layer.
///
/// This is intentionally separate from [`ConfigSource`]: `ConfigSource`
/// controls how a path is opened, while this enum describes the layer users
/// see in `dcg config` and `dcg doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigFileLayer {
    System,
    User,
    AutomaticProject,
    Explicit,
}

impl ConfigFileLayer {
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::AutomaticProject => "automatic project",
            Self::Explicit => "DCG_CONFIG",
        }
    }
}

/// Whether a file layer has full config authority or the automatic-project
/// enforcement-only subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigFileAuthority {
    Full,
    EnforcementOnly,
}

impl ConfigFileAuthority {
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::EnforcementOnly => "enforcement-only",
        }
    }
}

/// Result of considering one file path during configuration loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigFileStatus {
    Loaded,
    Missing,
    Skipped,
    #[cfg_attr(unix, allow(dead_code))]
    IgnoredUnsupported,
    Rejected,
    Invalid,
}

impl ConfigFileStatus {
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Missing => "missing",
            Self::Skipped => "skipped",
            Self::IgnoredUnsupported => "ignored-unsupported",
            Self::Rejected => "rejected",
            Self::Invalid => "invalid",
        }
    }
}

/// Auditable outcome for a single config-file candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ConfigSourceOutcome {
    pub(crate) layer: ConfigFileLayer,
    pub(crate) authority: ConfigFileAuthority,
    pub(crate) status: ConfigFileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
}

impl ConfigSourceOutcome {
    fn new(
        layer: ConfigFileLayer,
        authority: ConfigFileAuthority,
        status: ConfigFileStatus,
        path: Option<PathBuf>,
        detail: Option<String>,
    ) -> Self {
        Self {
            layer,
            authority,
            status,
            path,
            detail,
        }
    }
}

/// Effective configuration plus the exact file-source outcomes that produced
/// it. Keeping these together prevents diagnostics from guessing based on
/// `Path::exists()` after the security-aware loader has made its decision.
#[derive(Debug, Clone)]
pub(crate) struct ConfigLoadReport {
    pub(crate) config: Config,
    pub(crate) sources: Vec<ConfigSourceOutcome>,
}

/// Canonical published location of dcg's committed JSON Schema. Editors point
/// their `config.toml` here (or at a local copy) to get autocomplete/validation.
pub const CONFIG_SCHEMA_ID: &str = "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/config.schema.json";

/// Build the JSON Schema for [`Config`] as a [`serde_json::Value`].
///
/// The schema is generated from the `schemars::JsonSchema` derives on `Config`
/// and every nested config type, then annotated with `$id`, `title`, and
/// `description` so editors (Even Better TOML / taplo) present it well. The
/// `$schema` dialect (JSON Schema draft 2020-12) is emitted by schemars.
#[must_use]
pub fn config_json_schema() -> serde_json::Value {
    let schema = schemars::schema_for!(Config);
    let mut value = serde_json::to_value(&schema).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "$id".to_string(),
            serde_json::Value::String(CONFIG_SCHEMA_ID.to_string()),
        );
        map.insert(
            "title".to_string(),
            serde_json::Value::String("dcg configuration".to_string()),
        );
        map.insert(
            "description".to_string(),
            serde_json::Value::String(
                "JSON Schema for the config.toml of dcg (Destructive Command Guard). \
                 Generated from the Rust config types via `dcg config schema`; do not \
                 edit by hand. Regenerate after changing any config struct."
                    .to_string(),
            ),
        );
    }
    value
}

/// Pretty-printed JSON Schema for [`Config`], with a trailing newline.
///
/// This is the exact byte content committed as `config.schema.json` at the repo
/// root and asserted by the schema-drift test, so both the generator command
/// and the drift check produce identical output.
#[must_use]
pub fn config_json_schema_string() -> String {
    let mut out =
        serde_json::to_string_pretty(&config_json_schema()).unwrap_or_else(|_| "{}".to_string());
    out.push('\n');
    out
}

// -----------------------------------------------------------------------------
// Config file layering (presence-aware)
// -----------------------------------------------------------------------------
//
// The public `Config` structs use `#[serde(default)]` to provide ergonomic
// defaults when loading a *single* config file.
//
// For layered config precedence (system → user → restricted project policy →
// explicit config → env), we must also preserve whether a field was present in
// TOML. Otherwise we lose information
// about "explicitly set to default" vs "not set at all", which breaks the
// "higher precedence wins" mental model (e.g. you could not set
// `general.verbose=false` if a lower layer set it to true).
//
// To fix this, file configs are parsed into a partial/layer representation where
// scalar fields are `Option<T>` and we only apply fields that are `Some(...)`.

#[derive(Debug, Clone, Default, Deserialize)]
struct ConfigLayer {
    general: Option<GeneralConfigLayer>,
    output: Option<OutputConfigLayer>,
    theme: Option<ThemeConfigLayer>,
    packs: Option<PacksConfig>,
    policy: Option<PolicyConfig>,
    overrides: Option<OverridesConfig>,
    allowlist: Option<AllowlistConfigLayer>,
    heredoc: Option<HeredocConfig>,
    confidence: Option<ConfidenceConfigLayer>,
    logging: Option<LoggingConfigLayer>,
    history: Option<HistoryConfigLayer>,
    interactive: Option<InteractiveConfigLayer>,
    git_awareness: Option<GitAwarenessConfigLayer>,
    agents: Option<AgentsConfig>,
    response: Option<ResponseConfigLayer>,
    projects: Option<std::collections::HashMap<String, ProjectConfig>>,
    rules: Option<std::collections::HashMap<String, RuleConfig>>,
}

impl ConfigLayer {
    /// Reduce an automatically discovered repository config to settings that
    /// can only add enforcement.
    ///
    /// Repository contents are attacker-controlled at the point dcg first
    /// evaluates a command in a newly cloned checkout. Treating `.dcg.toml` as
    /// a normal high-priority layer would let the repository disable the guard
    /// that is meant to protect the user from that repository. Keep this
    /// allowlist deliberately small and explicit: new config fields are denied
    /// by default until their monotonic safety has been reviewed.
    fn into_restricted_project_policy(self) -> Self {
        let Self {
            general,
            packs,
            policy,
            heredoc,
            ..
        } = self;

        let general = general.and_then(|general| {
            (general.fail_closed == Some(true)).then(|| GeneralConfigLayer {
                fail_closed: Some(true),
                ..GeneralConfigLayer::default()
            })
        });

        let packs = packs.and_then(|packs| {
            // External packs require a custom path, which an untrusted
            // repository may not supply. Keep only known built-in pack IDs or
            // their registry categories so arbitrary strings cannot inflate
            // the effective configuration or masquerade as enforcement.
            let known_pack_ids = crate::packs::REGISTRY
                .all_pack_ids()
                .into_iter()
                .collect::<std::collections::HashSet<_>>();
            let known_categories = crate::packs::REGISTRY
                .all_categories()
                .into_iter()
                .map(String::as_str)
                .collect::<std::collections::HashSet<_>>();
            let enabled = packs
                .enabled
                .into_iter()
                .filter(|candidate| {
                    known_pack_ids.contains(candidate.as_str())
                        || known_categories.contains(candidate.as_str())
                })
                .collect::<Vec<_>>();

            (!enabled.is_empty()).then(|| PacksConfig {
                enabled,
                // An untrusted repository may not turn protections off or
                // point dcg at repository-controlled external pack data.
                disabled: Vec::new(),
                custom_paths: Vec::new(),
            })
        });

        let policy = policy.and_then(|policy| {
            let default_mode =
                (policy.default_mode == Some(PolicyMode::Deny)).then_some(PolicyMode::Deny);
            let packs = policy
                .packs
                .into_iter()
                .filter(|(_, mode)| *mode == PolicyMode::Deny)
                .collect::<std::collections::HashMap<_, _>>();
            let rules = policy
                .rules
                .into_iter()
                .filter(|(_, mode)| *mode == PolicyMode::Deny)
                .collect::<std::collections::HashMap<_, _>>();

            (default_mode.is_some() || !packs.is_empty() || !rules.is_empty()).then_some({
                PolicyConfig {
                    default_mode,
                    observe_until: None,
                    packs,
                    rules,
                }
            })
        });

        let heredoc = heredoc.and_then(|heredoc| {
            let enabled = (heredoc.enabled == Some(true)).then_some(true);
            let fallback_on_parse_error =
                (heredoc.fallback_on_parse_error == Some(false)).then_some(false);
            let fallback_on_timeout = (heredoc.fallback_on_timeout == Some(false)).then_some(false);

            (enabled.is_some()
                || fallback_on_parse_error.is_some()
                || fallback_on_timeout.is_some())
            .then(|| HeredocConfig {
                enabled,
                fallback_on_parse_error,
                fallback_on_timeout,
                // Limits and language filters can reduce analysis coverage;
                // a content allowlist is an explicit trust grant.
                ..HeredocConfig::default()
            })
        });

        // `rules` (per-rule `exempt_target_globs`, #284) is intentionally
        // absent from the reconstruction below. A target exemption reduces
        // coverage, so a repository must never be able to grant itself one;
        // the setting is honored only from the system, user, and explicit
        // `DCG_CONFIG` layers.
        Self {
            general,
            packs,
            policy,
            heredoc,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GeneralConfigLayer {
    color: Option<String>,
    log_file: Option<String>,
    verbose: Option<bool>,
    check_updates: Option<bool>,
    self_heal_hook: Option<bool>,
    hook_timeout_ms: Option<u64>,
    max_hook_input_bytes: Option<usize>,
    max_command_bytes: Option<usize>,
    max_findings_per_command: Option<usize>,
    fail_closed: Option<bool>,
    update_pin: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
struct OutputConfigLayer {
    highlight_enabled: Option<bool>,
    explanations_enabled: Option<bool>,
    high_contrast: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ThemeConfigLayer {
    palette: Option<String>,
    use_unicode: Option<bool>,
    use_color: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LoggingConfigLayer {
    enabled: Option<bool>,
    file: Option<String>,
    format: Option<crate::logging::LogFormat>,
    redaction: Option<RedactionConfigLayer>,
    events: Option<LogEventFilterLayer>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct HistoryConfigLayer {
    enabled: Option<bool>,
    redaction_mode: Option<HistoryRedactionMode>,
    retention_days: Option<u32>,
    max_size_mb: Option<u32>,
    database_path: Option<String>,
    auto_prune: Option<bool>,
    prune_check_interval_hours: Option<u32>,
    batch_size: Option<u32>,
    batch_flush_interval_ms: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct InteractiveConfigLayer {
    enabled: Option<bool>,
    verification: Option<VerificationMethod>,
    timeout_seconds: Option<u64>,
    code_length: Option<usize>,
    max_attempts: Option<u32>,
    allow_non_tty_fallback: Option<bool>,
    disable_in_ci: Option<bool>,
    require_env: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RedactionConfigLayer {
    enabled: Option<bool>,
    mode: Option<crate::logging::RedactionMode>,
    max_argument_len: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct LogEventFilterLayer {
    deny: Option<bool>,
    warn: Option<bool>,
    allow: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
struct ConfidenceConfigLayer {
    enabled: Option<bool>,
    warn_threshold: Option<f32>,
    protect_critical: Option<bool>,
}

/// Git-awareness configuration layer for config file parsing.
#[derive(Debug, Clone, Default, Deserialize)]
struct GitAwarenessConfigLayer {
    enabled: Option<bool>,
    protected_branches: Option<Vec<String>>,
    protected_strictness: Option<StrictnessLevel>,
    relaxed_branches: Option<Vec<String>>,
    relaxed_strictness: Option<StrictnessLevel>,
    default_strictness: Option<StrictnessLevel>,
    detached_head_strictness: Option<StrictnessLevel>,
    relaxed_disabled_packs: Option<Vec<String>>,
    show_branch_in_output: Option<bool>,
    warn_if_not_git: Option<bool>,
}

/// The system-wide (machine-level) dcg configuration directory.
///
/// On Linux and other Unix platforms this is `/etc/dcg`. macOS exposes `/etc`
/// through a symlink, while privileged config rejects every symlinked ancestor,
/// so macOS uses the equivalent direct path `/private/etc/dcg`. Native Windows
/// has no `/etc`, so the nominal system layer lives under `%ProgramData%\dcg`
/// (resolved from the `ProgramData`
/// environment variable, falling back to `C:\ProgramData`) — the conventional
/// location for machine-wide application configuration. The `dirs` crate does
/// not expose `ProgramData`, hence the manual resolution. This is the single
/// source of truth for the "system" config + allowlist base on every platform.
pub(crate) fn system_config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .filter(|s| !s.is_empty())
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
            .join("dcg")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/private/etc/dcg")
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        PathBuf::from("/etc/dcg")
    }
}

fn expand_tilde_path(value: &str) -> (PathBuf, bool) {
    if value == "~" {
        if let Some(home) = dirs::home_dir() {
            return (home, true);
        }
        return (PathBuf::from(value), false);
    }

    let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    else {
        return (PathBuf::from(value), false);
    };
    let Some(home) = dirs::home_dir() else {
        return (PathBuf::from(value), false);
    };
    (home.join(rest), true)
}

/// Resolve a config path value, expanding `~` and resolving relative paths.
///
/// Returns None when the value is empty/whitespace.
pub(crate) fn resolve_config_path_value(value: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let had_tilde_prefix = trimmed.starts_with('~');
    let (mut path, _tilde_expanded) = expand_tilde_path(trimmed);
    if !had_tilde_prefix && path.is_relative() {
        if let Some(cwd) = cwd {
            path = cwd.join(path);
        }
    }
    Some(path)
}

/// Find the git repo root by searching for a `.git` directory upwards from `start_dir`.
///
/// This search is bounded by `max_hops` to avoid unbounded filesystem traversal in
/// very deep directory trees.
pub(crate) fn find_repo_root(start_dir: &Path, max_hops: usize) -> Option<PathBuf> {
    let mut current = start_dir.to_path_buf();
    for _ in 0..=max_hops {
        if current.join(".git").exists() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

/// Return whether the user explicitly selected this repository's `.dcg.toml`
/// through [`ENV_CONFIG_PATH`].
///
/// Automatic discovery is never a trust signal: the repository controls both
/// `.dcg.toml` and `.dcg/allowlist.toml`. Selecting the root config through an
/// environment variable is an out-of-repository action and therefore the
/// narrow opt-in used by the runtime before activating the sibling project
/// allowlist.
pub(crate) fn explicitly_trusts_project_policy(start_dir: &Path) -> bool {
    let Some(repo_root) = find_repo_root(start_dir, REPO_ROOT_SEARCH_MAX_HOPS) else {
        return false;
    };
    let Ok(value) = env::var(ENV_CONFIG_PATH) else {
        return false;
    };
    let Some(selected) = resolve_config_path_value(&value, Some(start_dir)) else {
        return false;
    };
    let expected = repo_root.join(PROJECT_CONFIG_NAME);

    // Resolve symlinks and `.`/`..` components. A missing path, directory, or
    // failed canonicalization is not evidence of trust and must not activate a
    // sibling repository allowlist.
    let (Ok(selected), Ok(expected)) = (fs::canonicalize(selected), fs::canonicalize(expected))
    else {
        return false;
    };
    selected == expected && fs::metadata(expected).is_ok_and(|metadata| metadata.is_file())
}

/// Heredoc and inline-script scanning configuration.
///
/// This configuration controls Tier 1/2/3 heredoc scanning behavior. Because the
/// hook is performance- and UX-sensitive, extraction/parse errors use a bounded
/// fallback scanner by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct HeredocConfig {
    /// Enable heredoc/inline-script scanning.
    pub enabled: Option<bool>,

    /// Timeout budget for Tier 2 extraction (milliseconds).
    pub timeout_ms: Option<u64>,

    /// Maximum bytes extracted from heredoc bodies.
    pub max_body_bytes: Option<usize>,

    /// Maximum number of lines extracted from heredoc bodies.
    pub max_body_lines: Option<usize>,

    /// Maximum number of heredocs to process per command.
    pub max_heredocs: Option<usize>,

    /// Optional allowlist of languages to scan.
    ///
    /// Values are case-insensitive and may include aliases:
    /// - bash: bash, sh, shell
    /// - python: python, py
    /// - ruby: ruby, rb
    /// - perl: perl, pl
    /// - javascript: javascript, js, node
    /// - typescript: typescript, ts
    /// - php: php
    /// - go: go, golang
    /// - unknown: unknown
    ///
    /// Special value "all" scans all languages (the default if omitted).
    pub languages: Option<Vec<String>>,

    /// Use bounded fallback scanning when AST parsing fails for embedded code.
    /// When false, block on the incomplete analysis instead.
    pub fallback_on_parse_error: Option<bool>,

    /// Use bounded fallback scanning when extraction/parsing exceeds its timeout.
    /// When false, block on the incomplete analysis instead.
    pub fallback_on_timeout: Option<bool>,

    /// Content-based allowlist for heredocs (patterns, hashes, commands).
    pub allowlist: Option<HeredocAllowlistConfig>,
}

/// Effective heredoc scanning settings used by the evaluator.
#[derive(Debug, Clone)]
pub struct HeredocSettings {
    pub enabled: bool,
    pub limits: crate::heredoc::ExtractionLimits,
    pub allowed_languages: Option<Vec<crate::heredoc::ScriptLanguage>>,
    pub fallback_on_parse_error: bool,
    pub fallback_on_timeout: bool,
    /// Content-based allowlist for heredocs (patterns, hashes, commands).
    pub content_allowlist: Option<HeredocAllowlistConfig>,
}

impl Default for HeredocSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            limits: crate::heredoc::ExtractionLimits::default(),
            allowed_languages: None,
            fallback_on_parse_error: true,
            fallback_on_timeout: true,
            content_allowlist: None,
        }
    }
}

/// Heredoc content allowlist for known-safe patterns and content hashes.
///
/// Supports multiple allowlisting mechanisms:
/// - Command prefixes: allow all heredocs in commands starting with specific paths
/// - Pattern matching: allow heredocs containing specific patterns (optionally filtered by language)
/// - Content hashes: allow heredocs with specific content hashes (for known-good scripts)
/// - Project scopes: additional allowances for specific project directories
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct HeredocAllowlistConfig {
    /// Command prefixes to allowlist entirely (e.g., "./scripts/approved.sh").
    #[serde(default)]
    pub commands: Vec<String>,

    /// Content patterns to allowlist.
    #[serde(default)]
    pub patterns: Vec<AllowedHeredocPattern>,

    /// Content hashes to allowlist (hash of exact heredoc content).
    #[serde(default)]
    pub content_hashes: Vec<ContentHashEntry>,

    /// Project-specific allowlist overrides.
    #[serde(default)]
    pub projects: Vec<ProjectHeredocAllowlist>,
}

/// A pattern-based heredoc allowlist entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AllowedHeredocPattern {
    /// Optional language filter (e.g., "python", "bash"). If None, matches any language.
    pub language: Option<String>,
    /// Substring pattern to match in heredoc content.
    pub pattern: String,
    /// Human-readable reason for allowlisting.
    pub reason: String,
}

/// A content-hash based heredoc allowlist entry.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContentHashEntry {
    /// Hash of the exact heredoc content.
    ///
    /// This is a stable, deterministic SHA-256 hash (lowercase hex).
    pub hash: String,
    /// Human-readable reason for allowlisting.
    pub reason: String,
}

/// Project-specific heredoc allowlist overrides.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectHeredocAllowlist {
    /// Absolute path prefix for the project.
    pub path: String,
    /// Additional patterns for this project.
    #[serde(default)]
    pub patterns: Vec<AllowedHeredocPattern>,
    /// Additional content hashes for this project.
    #[serde(default)]
    pub content_hashes: Vec<ContentHashEntry>,
}

/// Result of a heredoc allowlist match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeredocAllowlistHit<'a> {
    /// The type of allowlist entry that matched.
    pub kind: HeredocAllowlistHitKind,
    /// The reason provided in the allowlist entry.
    pub reason: &'a str,
    /// The matched pattern, hash, or command.
    pub matched: &'a str,
}

/// The type of heredoc allowlist match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeredocAllowlistHitKind {
    /// Matched a content hash.
    ContentHash,
    /// Matched a pattern.
    Pattern,
    /// Matched a project-specific content hash.
    ProjectContentHash,
    /// Matched a project-specific pattern.
    ProjectPattern,
}

/// Confidence scoring configuration for ambiguous pattern matches.
///
/// When enabled, confidence scoring analyzes the context of pattern matches
/// to determine if they're likely true positives or false positives. Matches
/// in data contexts (quoted strings, commit messages, search patterns) have
/// lower confidence and may be downgraded from Deny to Warn.
///
/// # Example Configuration (TOML)
///
/// ```toml
/// [confidence]
/// enabled = true
/// warn_threshold = 0.5
/// protect_critical = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ConfidenceConfig {
    /// Enable confidence scoring for pattern matches.
    ///
    /// When enabled, the evaluator computes a confidence score for each match
    /// based on execution context (is the match in executed code or data?).
    /// Low-confidence matches may be downgraded from Deny to Warn.
    ///
    /// Default: false (disabled for backwards compatibility)
    pub enabled: bool,

    /// Confidence threshold below which Deny is downgraded to Warn.
    ///
    /// Values range from 0.0 (always warn) to 1.0 (never warn).
    /// Recommended range: 0.3 - 0.7
    ///
    /// Default: 0.5
    pub warn_threshold: f32,

    /// Protect Critical severity patterns from confidence downgrading.
    ///
    /// When true, Critical severity matches always Deny regardless of
    /// confidence score. This prevents catastrophic commands like `rm -rf /`
    /// from being downgraded even if they appear in data context.
    ///
    /// Default: true
    pub protect_critical: bool,
}

impl Default for ConfidenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            warn_threshold: crate::confidence::DEFAULT_WARN_THRESHOLD,
            protect_critical: true,
        }
    }
}

/// Graduation mode controlling how responses escalate with repeated occurrences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraduationMode {
    Paranoid,
    Strict,
    Standard,
    Lenient,
    WarningOnly,
    Disabled,
}

impl Default for GraduationMode {
    fn default() -> Self {
        Self::Standard
    }
}

impl std::fmt::Display for GraduationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paranoid => write!(f, "paranoid"),
            Self::Strict => write!(f, "strict"),
            Self::Standard => write!(f, "standard"),
            Self::Lenient => write!(f, "lenient"),
            Self::WarningOnly => write!(f, "warning_only"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Per-severity graduation mode override.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SeverityOverrides {
    pub critical: Option<GraduationMode>,
    pub high: Option<GraduationMode>,
    pub medium: Option<GraduationMode>,
    pub low: Option<GraduationMode>,
}

impl SeverityOverrides {
    #[must_use]
    pub fn mode_for(&self, severity: crate::packs::Severity) -> Option<GraduationMode> {
        match severity {
            crate::packs::Severity::Critical => self.critical,
            crate::packs::Severity::High => self.high,
            crate::packs::Severity::Medium => self.medium,
            crate::packs::Severity::Low => self.low,
        }
    }
}

/// Configuration for the graduated response system.
///
/// `session_*` thresholds count occurrences in the current dcg process via
/// [`crate::session`]. For shell hook usage (one process per `Bash` call),
/// these effectively only ever reach `1`; they do escalate for long-lived
/// callers like `dcg test`, the MCP server, or repeated CLI evaluations.
///
/// `history_soft_block` / `history_hard_block` / `history_window` are the
/// cross-process thresholds backed by the history database. Standard/Lenient
/// graduation modes consult them via
/// [`crate::evaluator::determine_graduated_response_with_history`] /
/// [`crate::evaluator::EvaluationResult::apply_graduation_with_history_db`].
/// Paranoid / Strict / WarningOnly / Disabled modes are unaffected — they
/// don't have escalation tiers driven by occurrence count.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResponseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: GraduationMode,
    #[serde(default = "ResponseConfig::default_session_warning_count")]
    pub session_warning_count: u32,
    #[serde(default = "ResponseConfig::default_session_soft_block")]
    pub session_soft_block: u32,
    /// Cross-session soft-block threshold (parsed from config; not yet wired
    /// into the evaluator — see `ResponseConfig` docstring).
    #[serde(default = "ResponseConfig::default_history_soft_block")]
    pub history_soft_block: u32,
    /// Cross-session hard-block threshold (parsed from config; not yet wired
    /// into the evaluator — see `ResponseConfig` docstring).
    #[serde(default = "ResponseConfig::default_history_hard_block")]
    pub history_hard_block: u32,
    /// Lookback window for history-backed thresholds (parsed from config;
    /// not yet wired into the evaluator — see `ResponseConfig` docstring).
    #[serde(default = "ResponseConfig::default_history_window")]
    pub history_window: String,
    #[serde(default)]
    pub severity_overrides: SeverityOverrides,
}

impl ResponseConfig {
    const fn default_session_warning_count() -> u32 {
        1
    }
    const fn default_session_soft_block() -> u32 {
        2
    }
    const fn default_history_soft_block() -> u32 {
        3
    }
    const fn default_history_hard_block() -> u32 {
        5
    }
    fn default_history_window() -> String {
        "24h".to_string()
    }

    /// Parse `history_window` (e.g. `"24h"`, `"7d"`, `"30m"`) into a
    /// `chrono::Duration`. Returns `None` for an unrecognized format,
    /// negative values, or values that would overflow.
    /// Suffix grammar: `s` (seconds), `m` (minutes), `h` (hours),
    /// `d` (days). Numeric prefix only — no compound expressions.
    #[must_use]
    pub fn parse_history_window(window: &str) -> Option<chrono::Duration> {
        // Sane upper bound: 100 years in any unit. Chrono's `Duration::days`
        // family panics on i64-overflow when converting to internal seconds;
        // 100y in seconds is ~3.15e9, comfortably below i64::MAX.
        // Negative durations don't make sense for a "lookback window" — the
        // caller would wrap them as `Utc::now() - (-window) = Utc::now() + window`
        // (a future cutoff) and silently see zero matches.
        const MAX_DAYS: i64 = 365 * 100;
        const MAX_HOURS: i64 = MAX_DAYS * 24;
        const MAX_MINUTES: i64 = MAX_HOURS * 60;
        const MAX_SECONDS: i64 = MAX_MINUTES * 60;

        let trimmed = window.trim();
        // Use char iteration rather than `split_at(len-1)` so a multi-byte
        // trailing char (e.g. `"24é"`) doesn't panic on a non-char-boundary
        // byte index.
        let unit = trimmed.chars().last()?;
        let num_part: String = trimmed.chars().take(trimmed.chars().count() - 1).collect();
        let n: i64 = num_part.parse().ok()?;
        if n < 0 {
            return None;
        }
        match unit {
            's' if n <= MAX_SECONDS => Some(chrono::Duration::seconds(n)),
            'm' if n <= MAX_MINUTES => Some(chrono::Duration::minutes(n)),
            'h' if n <= MAX_HOURS => Some(chrono::Duration::hours(n)),
            'd' if n <= MAX_DAYS => Some(chrono::Duration::days(n)),
            _ => None,
        }
    }

    /// Parse this config's history_window using `parse_history_window`,
    /// falling back to 24h if the string is malformed.
    #[must_use]
    pub fn history_window_duration(&self) -> chrono::Duration {
        Self::parse_history_window(&self.history_window)
            .unwrap_or_else(|| chrono::Duration::hours(24))
    }

    /// Effective graduation mode for a severity.
    /// Precedence: explicit override -> severity default -> global mode.
    /// Critical defaults to Paranoid, Low defaults to WarningOnly.
    #[must_use]
    pub fn effective_mode(&self, severity: crate::packs::Severity) -> GraduationMode {
        if let Some(explicit) = self.severity_overrides.mode_for(severity) {
            return explicit;
        }
        match severity {
            crate::packs::Severity::Critical => GraduationMode::Paranoid,
            crate::packs::Severity::Low => GraduationMode::WarningOnly,
            _ => self.mode,
        }
    }

    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: GraduationMode::default(),
            session_warning_count: Self::default_session_warning_count(),
            session_soft_block: Self::default_session_soft_block(),
            history_soft_block: Self::default_history_soft_block(),
            history_hard_block: Self::default_history_hard_block(),
            history_window: Self::default_history_window(),
            severity_overrides: SeverityOverrides::default(),
        }
    }
}

/// Layered config for graduated response (all fields optional for merge).
#[derive(Debug, Clone, Default, Deserialize)]
struct ResponseConfigLayer {
    enabled: Option<bool>,
    mode: Option<GraduationMode>,
    session_warning_count: Option<u32>,
    session_soft_block: Option<u32>,
    history_soft_block: Option<u32>,
    history_hard_block: Option<u32>,
    history_window: Option<String>,
    severity_overrides: Option<SeverityOverrides>,
}

impl HeredocConfig {
    #[must_use]
    pub fn settings(&self) -> HeredocSettings {
        let mut limits = crate::heredoc::ExtractionLimits::default();
        if let Some(timeout_ms) = self.timeout_ms {
            limits.timeout_ms = timeout_ms;
        }
        if let Some(max_body_bytes) = self.max_body_bytes {
            limits.max_body_bytes = max_body_bytes;
        }
        if let Some(max_body_lines) = self.max_body_lines {
            limits.max_body_lines = max_body_lines;
        }
        if let Some(max_heredocs) = self.max_heredocs {
            limits.max_heredocs = max_heredocs;
        }

        let allowed_languages = self.languages.as_ref().and_then(|langs| {
            let mut parsed: Vec<crate::heredoc::ScriptLanguage> = Vec::new();
            for raw in langs {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }

                if raw.eq_ignore_ascii_case("all") {
                    return None;
                }

                let lang = match raw.to_ascii_lowercase().as_str() {
                    "bash" | "sh" | "shell" => Some(crate::heredoc::ScriptLanguage::Bash),
                    "python" | "py" => Some(crate::heredoc::ScriptLanguage::Python),
                    "ruby" | "rb" => Some(crate::heredoc::ScriptLanguage::Ruby),
                    "perl" | "pl" => Some(crate::heredoc::ScriptLanguage::Perl),
                    "javascript" | "js" | "node" => {
                        Some(crate::heredoc::ScriptLanguage::JavaScript)
                    }
                    "typescript" | "ts" => Some(crate::heredoc::ScriptLanguage::TypeScript),
                    "php" => Some(crate::heredoc::ScriptLanguage::Php),
                    "go" | "golang" => Some(crate::heredoc::ScriptLanguage::Go),
                    "unknown" => Some(crate::heredoc::ScriptLanguage::Unknown),
                    _ => None,
                };

                if let Some(lang) = lang {
                    if !parsed.contains(&lang) {
                        parsed.push(lang);
                    }
                }
            }

            if parsed.is_empty() {
                // Avoid accidental full-disable due to typos: treat as "all".
                None
            } else {
                Some(parsed)
            }
        });

        HeredocSettings {
            enabled: self.enabled.unwrap_or(true),
            limits,
            allowed_languages,
            fallback_on_parse_error: self.fallback_on_parse_error.unwrap_or(true),
            fallback_on_timeout: self.fallback_on_timeout.unwrap_or(true),
            content_allowlist: self.allowlist.clone(),
        }
    }
}

impl HeredocAllowlistConfig {
    /// Check if a command is allowlisted by its prefix.
    #[must_use]
    pub fn is_command_allowlisted(&self, command: &str) -> Option<&str> {
        for cmd in &self.commands {
            // Skip empty prefixes to prevent accidental allow-all
            if cmd.is_empty() {
                continue;
            }
            if command.starts_with(cmd.as_str()) {
                return Some(cmd.as_str());
            }
        }
        None
    }

    /// Check if heredoc content is allowlisted.
    ///
    /// Checks in order: content hashes, patterns, then project-specific entries.
    #[must_use]
    pub fn is_content_allowlisted(
        &self,
        content: &str,
        language: crate::heredoc::ScriptLanguage,
        project_path: Option<&std::path::Path>,
    ) -> Option<HeredocAllowlistHit<'_>> {
        // Check global content hashes first
        let mut hash: Option<String> = None;
        for entry in &self.content_hashes {
            let computed = hash.get_or_insert_with(|| content_hash(content));
            if entry.hash == *computed {
                return Some(HeredocAllowlistHit {
                    kind: HeredocAllowlistHitKind::ContentHash,
                    reason: &entry.reason,
                    matched: &entry.hash,
                });
            }
        }

        // Check global patterns
        for pattern in &self.patterns {
            if pattern_matches(pattern, content, language) {
                return Some(HeredocAllowlistHit {
                    kind: HeredocAllowlistHitKind::Pattern,
                    reason: &pattern.reason,
                    matched: &pattern.pattern,
                });
            }
        }

        // Check project-specific entries
        if let Some(path) = project_path {
            for project in &self.projects {
                // Skip empty project paths to prevent accidental allow-all
                if project.path.is_empty() {
                    continue;
                }
                // Match by path components to avoid false positives
                // e.g., "/home/user/project" should NOT match "/home/user/project-other".
                if path.starts_with(std::path::Path::new(&project.path)) {
                    // Check project content hashes
                    for entry in &project.content_hashes {
                        let computed = hash.get_or_insert_with(|| content_hash(content));
                        if entry.hash == *computed {
                            return Some(HeredocAllowlistHit {
                                kind: HeredocAllowlistHitKind::ProjectContentHash,
                                reason: &entry.reason,
                                matched: &entry.hash,
                            });
                        }
                    }

                    // Check project patterns
                    for pattern in &project.patterns {
                        if pattern_matches(pattern, content, language) {
                            return Some(HeredocAllowlistHit {
                                kind: HeredocAllowlistHitKind::ProjectPattern,
                                reason: &pattern.reason,
                                matched: &pattern.pattern,
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Merge another allowlist config into this one (other takes precedence for additions).
    pub fn merge(&mut self, other: &Self) {
        // Merge commands (deduplicate)
        for cmd in &other.commands {
            if !self.commands.contains(cmd) {
                self.commands.push(cmd.clone());
            }
        }

        // Merge patterns (deduplicate by pattern string)
        for pattern in &other.patterns {
            if !self.patterns.iter().any(|p| p.pattern == pattern.pattern) {
                self.patterns.push(pattern.clone());
            }
        }

        // Merge content hashes (deduplicate by hash)
        for entry in &other.content_hashes {
            if !self.content_hashes.iter().any(|e| e.hash == entry.hash) {
                self.content_hashes.push(entry.clone());
            }
        }

        // Merge project overrides (merge by path)
        for project in &other.projects {
            if let Some(existing) = self.projects.iter_mut().find(|p| p.path == project.path) {
                // Merge patterns into existing project
                for pattern in &project.patterns {
                    if !existing
                        .patterns
                        .iter()
                        .any(|p| p.pattern == pattern.pattern)
                    {
                        existing.patterns.push(pattern.clone());
                    }
                }
                // Merge hashes into existing project
                for entry in &project.content_hashes {
                    if !existing.content_hashes.iter().any(|e| e.hash == entry.hash) {
                        existing.content_hashes.push(entry.clone());
                    }
                }
            } else {
                self.projects.push(project.clone());
            }
        }
    }
}

impl HeredocAllowlistHitKind {
    /// Human-readable label for the hit kind.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::ContentHash => "content_hash",
            Self::Pattern => "pattern",
            Self::ProjectContentHash => "project_content_hash",
            Self::ProjectPattern => "project_pattern",
        }
    }
}

/// Check if a pattern matches the content for the given language.
fn pattern_matches(
    pattern: &AllowedHeredocPattern,
    content: &str,
    language: crate::heredoc::ScriptLanguage,
) -> bool {
    // Empty patterns are invalid and should never match (prevents accidental allow-all)
    if pattern.pattern.is_empty() {
        return false;
    }
    // Check language filter
    if let Some(lang_filter) = &pattern.language {
        if !language_filter_matches(lang_filter, language) {
            return false;
        }
    }
    // Check content contains pattern
    content.contains(&pattern.pattern)
}

/// Check if a language filter string matches the given language.
/// Supports both full names (e.g., "javascript") and common aliases (e.g., "js").
/// An empty or whitespace-only filter matches all languages (same as `language: None`).
fn language_filter_matches(filter: &str, language: crate::heredoc::ScriptLanguage) -> bool {
    use crate::heredoc::ScriptLanguage::{
        Bash, Go, JavaScript, Perl, Php, Python, Ruby, TypeScript, Unknown,
    };
    let filter_lower = filter.trim().to_ascii_lowercase();

    // Empty filter matches all languages (consistent with `language: None`)
    if filter_lower.is_empty() {
        return true;
    }

    match language {
        Bash => matches!(filter_lower.as_str(), "bash" | "sh" | "shell"),
        Python => matches!(filter_lower.as_str(), "python" | "py"),
        Ruby => matches!(filter_lower.as_str(), "ruby" | "rb"),
        Perl => matches!(filter_lower.as_str(), "perl" | "pl"),
        JavaScript => matches!(filter_lower.as_str(), "javascript" | "js" | "node"),
        TypeScript => matches!(filter_lower.as_str(), "typescript" | "ts"),
        Php => matches!(filter_lower.as_str(), "php"),
        Go => matches!(filter_lower.as_str(), "go" | "golang"),
        Unknown => filter_lower == "unknown",
    }
}

/// Compute a stable content hash for heredoc allowlisting.
///
/// This uses SHA-256 and returns lowercase hex. Allowlisting still requires
/// explicit user configuration; the hash is for stable identification, not as a
/// security boundary.
///
/// # Returns
///
/// A 64-character hex string representing the 256-bit hash.
fn content_hash(content: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(content.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// General configuration options.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct GeneralConfig {
    /// Color output mode: "auto", "always", "never".
    pub color: String,

    /// Path to log file for blocked commands (optional).
    pub log_file: Option<String>,

    /// Whether to show verbose output.
    pub verbose: bool,

    /// Hook evaluation budget override in milliseconds.
    /// When set, overrides the default hook evaluation budget. Values below
    /// 10 milliseconds are clamped to the minimum safe evaluation window.
    pub hook_timeout_ms: Option<u64>,

    /// Maximum bytes to read from stdin in hook mode.
    /// Oversized hook envelopes are allowed with an audit warning by default;
    /// `fail_closed` blocks them because their size is attacker-controlled.
    /// Default: 262144 (256 KiB).
    pub max_hook_input_bytes: Option<usize>,

    /// Maximum bytes for command string after extraction from JSON.
    /// Commands exceeding this limit produce an explicit indeterminate result;
    /// review-capable protocols ask and other protocols block.
    /// Default: 65536 (64 KiB).
    pub max_command_bytes: Option<usize>,

    /// Maximum findings to report per command.
    /// Limits output size and processing time for pathological inputs.
    /// Default: 100.
    pub max_findings_per_command: Option<usize>,

    /// Whether to check for updates in the background.
    /// When enabled, dcg will spawn a background thread to check for updates
    /// and show a notice if a newer version is available.
    /// Default: true. Disable with truthy `DCG_NO_UPDATE_CHECK`
    /// or `check_updates` = false.
    pub check_updates: bool,

    /// Whether to self-heal the hook registration in settings.json.
    /// When enabled, every hook invocation checks that the dcg entry is still
    /// present in `~/.claude/settings.json` and re-registers it if missing.
    /// This protects against Claude Code silently overwriting settings.json
    /// mid-session.
    /// Default: true. Disable with `DCG_NO_SELF_HEAL` or `self_heal_hook = false`.
    pub self_heal_hook: bool,

    /// Fail-closed mode for unparseable hook input.
    ///
    /// When `true`, hook input that cannot be parsed as JSON is BLOCKED
    /// (denied) instead of allowed. The default (`false`) is the documented
    /// fail-open behavior: malformed input is allowed so a transient encoding
    /// glitch never blocks legitimate work. Intended for high-security
    /// environments. Override at runtime with the `DCG_FAIL_CLOSED` env var
    /// (a truthy value forces fail-closed, a falsy value forces fail-open).
    pub fail_closed: bool,

    /// Pin the installed binary against `dcg update` (#320).
    ///
    /// When `true`, `dcg update` refuses to replace the installed binary
    /// (before any network or installer work) unless `--replace-local-build`
    /// is passed, and the background "update available" nudge is suppressed.
    /// Intended for operators running a local build that is ahead of the
    /// published release, where a routine update would silently downgrade
    /// guard coverage. Override at runtime with `DCG_UPDATE_PIN`.
    /// Default: false.
    pub update_pin: bool,
}

/// Default limits for input size (used when not configured).
pub const DEFAULT_MAX_HOOK_INPUT_BYTES: usize = 256 * 1024; // 256 KiB
pub const DEFAULT_MAX_COMMAND_BYTES: usize = 64 * 1024; // 64 KiB
pub const DEFAULT_MAX_FINDINGS_PER_COMMAND: usize = 100;

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            color: "auto".to_string(),
            log_file: None,
            verbose: false,
            hook_timeout_ms: None,
            max_hook_input_bytes: None,
            max_command_bytes: None,
            max_findings_per_command: None,
            check_updates: true,
            self_heal_hook: true,
            fail_closed: false,
            update_pin: false,
        }
    }
}

impl GeneralConfig {
    /// Get max hook input bytes (with default fallback).
    #[must_use]
    pub fn max_hook_input_bytes(&self) -> usize {
        self.max_hook_input_bytes
            .unwrap_or(DEFAULT_MAX_HOOK_INPUT_BYTES)
    }

    /// Get max command bytes (with default fallback).
    #[must_use]
    pub fn max_command_bytes(&self) -> usize {
        self.max_command_bytes.unwrap_or(DEFAULT_MAX_COMMAND_BYTES)
    }

    /// Get max findings per command (with default fallback).
    #[must_use]
    pub fn max_findings_per_command(&self) -> usize {
        self.max_findings_per_command
            .unwrap_or(DEFAULT_MAX_FINDINGS_PER_COMMAND)
    }
}

/// Output display configuration.
///
/// Controls optional output enhancements like span highlighting and explanations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct OutputConfig {
    /// Enable span highlighting in denial output.
    /// When enabled, shows caret-style markers under the matched portion.
    /// Default: true
    pub highlight_enabled: Option<bool>,

    /// Enable explanations in denial output.
    /// When enabled, shows detailed explanations for why patterns are dangerous.
    /// Default: true
    pub explanations_enabled: Option<bool>,

    /// Enable high-contrast output.
    /// Uses ASCII borders and a black/white palette for accessibility.
    /// Default: false
    pub high_contrast: Option<bool>,
}

impl OutputConfig {
    /// Check if span highlighting is enabled (default: true).
    #[must_use]
    pub fn highlight_enabled(&self) -> bool {
        self.highlight_enabled.unwrap_or(true)
    }

    /// Check if explanations are enabled (default: true).
    #[must_use]
    pub fn explanations_enabled(&self) -> bool {
        self.explanations_enabled.unwrap_or(true)
    }

    /// Check if high-contrast output is enabled (default: false).
    #[must_use]
    pub fn high_contrast_enabled(&self) -> bool {
        self.high_contrast.unwrap_or(false)
    }
}

/// Theme configuration for rich terminal output.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ThemeConfig {
    /// Palette name: "default" | "colorblind" | "high-contrast".
    pub palette: Option<String>,

    /// Whether Unicode box drawing is allowed.
    pub use_unicode: Option<bool>,

    /// Whether colors are allowed (overrides `NO_COLOR` when set to false).
    pub use_color: Option<bool>,
}

/// Pack enablement configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct PacksConfig {
    /// List of enabled packs (e.g., `["database.postgresql", "kubernetes"]`).
    pub enabled: Vec<String>,

    /// List of explicitly disabled packs (for disabling sub-packs of enabled categories).
    pub disabled: Vec<String>,

    /// Paths to custom external pack YAML files.
    ///
    /// Supports glob patterns and tilde expansion:
    /// - `~/.config/dcg/packs/*.yaml` - User-level packs
    /// - `.dcg/packs/*.yaml` - Project-level packs
    /// - `/etc/dcg/packs/*.yaml` - System-wide packs
    ///
    /// Files are loaded in order; later files with the same pack ID override earlier ones.
    /// Pack loading is fail-open: invalid files are logged as warnings but don't prevent
    /// loading valid packs.
    #[serde(default)]
    pub custom_paths: Vec<String>,
}

impl PacksConfig {
    /// Expand every known built-in category or preset to concrete pack IDs.
    ///
    /// Registry expansion deliberately retains the requested category ID so
    /// metadata callers can tell what was requested. Configuration evaluation
    /// cannot retain it, however: a later registry expansion would otherwise
    /// reintroduce a leaf removed by `disabled` (for example, enabling
    /// `database` while disabling `database.redis`). Keep real pack IDs,
    /// external/unknown IDs, and the mandatory `core` marker; discard only
    /// known category-only IDs after their leaves have been materialized.
    fn expand_known_pack_groups(enabled: &HashSet<String>) -> HashSet<String> {
        let mut expanded = crate::packs::REGISTRY.expand_enabled(enabled);
        expanded.retain(|id| {
            id == "core"
                || crate::packs::REGISTRY.get_entry(id).is_some()
                || crate::packs::REGISTRY.packs_in_category(id).is_empty()
        });
        expanded
    }

    /// Remove an explicitly disabled concrete pack or ordinary category.
    ///
    /// Presets are handled before expansion instead. Removing every expanded
    /// preset member here would also remove packs enabled independently by a
    /// platform default, a direct leaf, or another category.
    fn remove_disabled_pack_group(enabled: &mut HashSet<String>, disabled: &str) {
        enabled.remove(disabled);
        enabled.retain(|pack_id| !pack_id.starts_with(&format!("{disabled}.")));
    }

    /// Remove disabled preset *sources* before expansion.
    ///
    /// A preset is an enablement contribution, not an ownership claim over its
    /// member packs. If `cloud` and the careful-Windows preset are both enabled,
    /// disabling only the preset must leave the independently requested cloud
    /// packs enabled.
    fn remove_disabled_preset_markers(requested: &mut HashSet<String>, disabled: &[String]) {
        for disabled_id in disabled {
            if crate::packs::preset_members(disabled_id).is_some() {
                requested.remove(disabled_id);
            }
        }
    }

    fn remove_disabled_non_preset_groups(enabled: &mut HashSet<String>, disabled: &[String]) {
        for disabled_id in disabled {
            if crate::packs::preset_members(disabled_id).is_none() {
                Self::remove_disabled_pack_group(enabled, disabled_id);
            }
        }
    }

    fn requested_pack_ids(&self, include_windows_defaults: bool) -> HashSet<String> {
        let mut enabled: HashSet<String> = self.enabled.iter().cloned().collect();

        // `system.disk` is default-on but opt-out-able. It guards
        // catastrophic, unrecoverable disk operations (`mkfs /dev/sda`,
        // `dd of=/dev/sdb`, `fdisk`, `parted`, `mdadm --zero-superblock`,
        // `lvm` removal, `wipefs`). For a tool whose sole purpose is
        // preventing destructive commands, leaving these one config-edit
        // away from being unprotected is the wrong default. Users who
        // genuinely need to run mkfs/dd-to-device unblocked can opt out
        // via `disabled = ["system.disk"]` (or `disabled = ["system"]`
        // to drop all system.* packs).
        enabled.insert("system.disk".to_string());

        // Windows-native packs are default-ON only on Windows: a fresh Windows
        // install must block `del /s`, `rd /s`, `Remove-Item -Recurse -Force`,
        // etc. with no config, while Unix pays no quick-reject cost for Windows
        // verbs by default. The packs stay *registered* on every platform, so
        // Unix users can still opt in (e.g. to scan committed `.ps1`/`.cmd`
        // scripts) via `enabled = ["windows.filesystem"]`. Opt out on Windows
        // with `disabled = ["windows.filesystem"]` (or `disabled = ["windows"]`).
        if include_windows_defaults {
            for pack_id in ["windows.filesystem", "windows.system"] {
                enabled.insert(pack_id.to_string());
            }
        }
        enabled
    }

    fn resolve_requested_pack_ids(
        mut requested: HashSet<String>,
        disabled: &[String],
    ) -> HashSet<String> {
        // Cancel preset contributions before expansion so independently
        // requested/default member packs retain their provenance.
        Self::remove_disabled_preset_markers(&mut requested, disabled);

        // Expand before applying exclusions. Filtering a requested category
        // first is insufficient because the registry would expand the surviving
        // parent later and silently put the excluded leaf back.
        let mut enabled = Self::expand_known_pack_groups(&requested);

        // Ordinary leaf/category exclusions remain last-wins after expansion.
        Self::remove_disabled_non_preset_groups(&mut enabled, disabled);

        // Core is always enabled (cannot be disabled). Keeping the category
        // marker is intentional: registry callers expand it to both core packs.
        enabled.insert("core".to_string());

        enabled
    }

    /// Get enabled pack IDs as a deduplicated set.
    #[must_use]
    pub fn enabled_pack_ids(&self) -> HashSet<String> {
        Self::resolve_requested_pack_ids(self.requested_pack_ids(cfg!(windows)), &self.disabled)
    }

    /// Expand custom_paths, resolving tilde, ${repo_root}, and glob patterns.
    ///
    /// Returns a list of concrete file paths that exist on disk.
    /// Invalid globs or non-existent files are silently skipped (fail-open).
    ///
    /// `${repo_root}` resolves to the nearest ancestor of the process cwd
    /// that contains a `.git` directory. When no repo root is found, entries
    /// referencing the token are skipped (so a config that auto-discovers
    /// repo-local packs is safe to deploy globally via MDM and just no-ops
    /// outside checkouts).
    #[must_use]
    pub fn expand_custom_paths(&self) -> Vec<String> {
        let cwd = std::env::current_dir().ok();
        self.expand_custom_paths_from(cwd.as_deref())
    }

    /// `expand_custom_paths` with an explicit cwd, for testability.
    // `${repo_root}` is a deliberate shell-style placeholder we expand
    // ourselves; clippy's literal_string_with_formatting_args lint mistakes it
    // for an unused std::fmt placeholder.
    #[allow(clippy::literal_string_with_formatting_args)]
    #[must_use]
    pub fn expand_custom_paths_from(&self, cwd: Option<&Path>) -> Vec<String> {
        let mut result = Vec::new();
        let mut repo_root: Option<Option<PathBuf>> = None; // memoize across patterns

        // Bound the expansion so a pathological glob (e.g. `~/**/*.yaml`)
        // cannot make every hook invocation open an unbounded number of
        // files (issue #293). Files beyond the cap are skipped; each pack
        // file itself is size-capped at parse time.
        //
        // The cap is CUMULATIVE across patterns, so the pattern that trips it
        // is usually not the pattern the operator would blame — an early
        // greedy glob can consume the whole budget and silently drop every
        // later entry. Skips are therefore tallied per pattern and reported
        // by name after expansion, instead of one anonymous warning.
        let mut skipped_by_pattern: Vec<(String, usize)> = Vec::new();
        let push_capped = |result: &mut Vec<String>, skipped: &mut usize, path: String| {
            if result.len() < MAX_CUSTOM_PACK_FILES {
                result.push(path);
            } else {
                *skipped += 1;
            }
        };

        for pattern in &self.custom_paths {
            let mut skipped = 0usize;
            // Expand ${repo_root} first — if unresolved, skip the entry.
            let after_repo_root = if pattern.contains("${repo_root}") {
                let resolved = repo_root.get_or_insert_with(|| {
                    cwd.and_then(|c| find_repo_root(c, REPO_ROOT_SEARCH_MAX_HOPS))
                });
                let Some(root) = resolved.as_ref() else {
                    continue;
                };
                pattern.replace("${repo_root}", &root.to_string_lossy())
            } else {
                pattern.clone()
            };

            // Then expand tilde.
            let expanded = if after_repo_root.starts_with("~/") || after_repo_root == "~" {
                if let Some(home) = dirs::home_dir() {
                    if after_repo_root == "~" {
                        home.to_string_lossy().into_owned()
                    } else {
                        home.join(&after_repo_root[2..])
                            .to_string_lossy()
                            .into_owned()
                    }
                } else {
                    after_repo_root
                }
            } else {
                after_repo_root
            };

            // Expand glob pattern.
            match glob::glob(&expanded) {
                Ok(paths) => {
                    for entry in paths.flatten() {
                        if entry.is_file() {
                            push_capped(
                                &mut result,
                                &mut skipped,
                                entry.to_string_lossy().into_owned(),
                            );
                        }
                    }
                }
                Err(_) => {
                    // Invalid glob pattern - treat as literal path
                    let path = std::path::Path::new(&expanded);
                    if path.is_file() {
                        push_capped(&mut result, &mut skipped, expanded);
                    }
                }
            }

            if skipped > 0 {
                skipped_by_pattern.push((pattern.clone(), skipped));
            }
        }

        if !skipped_by_pattern.is_empty() {
            let total: usize = skipped_by_pattern.iter().map(|(_, n)| n).sum();
            let detail = skipped_by_pattern
                .iter()
                .map(|(pattern, n)| format!("{pattern} ({n} skipped)"))
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "[dcg] Warning: packs.custom_paths hit the cumulative {MAX_CUSTOM_PACK_FILES}-file cap \
                 (issue #293); {total} matching file(s) were NOT loaded from: {detail}"
            );
        }

        result
    }
}

/// Decision mode policy configuration.
///
/// Controls how matched patterns are handled: deny (block), ask (require
/// operator review), warn (allow with warning), or log (silent allow with
/// optional logging).
///
/// Defaults respect severity: Critical/High → deny, Medium → warn, Low → log.
/// This config allows overriding the default behavior per pack or per specific rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct PolicyConfig {
    /// Global default mode (overrides severity-based defaults).
    /// If not set, severity-based defaults apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<PolicyMode>,

    /// Optional observe-mode window end timestamp.
    ///
    /// When set and the current time is **before** this timestamp:
    /// - `default_mode` applies, but defaults to `"warn"` when unset.
    ///
    /// When set and the current time is **at/after** this timestamp:
    /// - `default_mode` is ignored and dcg reverts to severity-based defaults.
    ///
    /// Accepted formats:
    /// - RFC 3339: `2026-02-01T00:00:00Z`
    /// - ISO 8601 without timezone (treated as UTC): `2026-02-01T00:00:00`
    /// - Date only (treated as end of day UTC): `2026-02-01`
    // `ObserveUntil` has a custom (string) Serialize/Deserialize impl — it is a
    // wrapper around a timestamp string. Represent it accurately in the schema
    // as an optional string rather than deriving JsonSchema for the wrapper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub observe_until: Option<ObserveUntil>,

    /// Per-pack mode overrides.
    /// Key is `pack_id` (e.g., "core.git", "database.postgresql").
    /// Value is the mode to use for all patterns in that pack.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub packs: std::collections::HashMap<String, PolicyMode>,

    /// Per-rule mode overrides.
    /// Key is `rule_id` (e.g., "core.git:reset-hard", "core.filesystem:rm-rf-root").
    /// Value is the mode to use for that specific rule.
    /// Takes precedence over pack-level and global overrides.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub rules: std::collections::HashMap<String, PolicyMode>,
}

/// Policy mode for overriding default decision behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Block the command (output JSON deny, print warning).
    Deny,
    /// Require explicit operator review; fail closed if the client cannot ask.
    Ask,
    /// Warn but allow (print warning to stderr, no JSON deny).
    Warn,
    /// Log only (silent allow, record for history).
    Log,
}

impl PolicyMode {
    /// Convert to the internal `DecisionMode`.
    #[must_use]
    pub const fn to_decision_mode(self) -> crate::packs::DecisionMode {
        match self {
            Self::Deny => crate::packs::DecisionMode::Deny,
            Self::Ask => crate::packs::DecisionMode::Ask,
            Self::Warn => crate::packs::DecisionMode::Warn,
            Self::Log => crate::packs::DecisionMode::Log,
        }
    }
}

impl PolicyConfig {
    /// Resolve the effective decision mode for a given rule.
    ///
    /// Priority (highest to lowest):
    /// 1. Rule-specific override (via `rules["pack_id:pattern_name"]`)
    /// 2. Pack-specific override (via `packs["pack_id"]`)
    /// 3. Global default (`default_mode`)
    /// 4. Severity-based default (from pattern's severity)
    #[must_use]
    pub fn resolve_mode(
        &self,
        pack_id: Option<&str>,
        pattern_name: Option<&str>,
        severity: Option<crate::packs::Severity>,
    ) -> crate::packs::DecisionMode {
        self.resolve_mode_at(Utc::now(), pack_id, pattern_name, severity)
    }

    #[must_use]
    pub fn resolve_mode_at(
        &self,
        now: DateTime<Utc>,
        pack_id: Option<&str>,
        pattern_name: Option<&str>,
        severity: Option<crate::packs::Severity>,
    ) -> crate::packs::DecisionMode {
        // 1. Rule-specific override
        if let (Some(pack), Some(pattern)) = (pack_id, pattern_name) {
            let rule_id = format!("{pack}:{pattern}");
            if let Some(mode) = self.rules.get(&rule_id) {
                return mode.to_decision_mode();
            }
        }

        // 2. Pack-specific override
        if let Some(pack) = pack_id {
            if let Some(mode) = self.packs.get(pack) {
                return constrain_critical_policy(mode.to_decision_mode(), severity);
            }
        }

        // 3. Global default (optionally gated by observe_until)
        let effective_default_mode = self
            .observe_until
            .as_ref()
            .and_then(ObserveUntil::parsed_utc)
            .map_or(self.default_mode, |until| {
                if &now < until {
                    Some(self.default_mode.unwrap_or(PolicyMode::Warn))
                } else {
                    None
                }
            });

        if let Some(mode) = effective_default_mode {
            return constrain_critical_policy(mode.to_decision_mode(), severity);
        }

        // 4. Severity-based default
        severity.map_or(crate::packs::DecisionMode::Deny, |s| s.default_mode())
    }
}

/// Critical rules may use deny or the still-blocking ask mode from broad
/// policy. Warn/log remain available only through an explicit per-rule
/// override, preserving the existing safeguard against accidental global
/// relaxation.
const fn constrain_critical_policy(
    mode: crate::packs::DecisionMode,
    severity: Option<crate::packs::Severity>,
) -> crate::packs::DecisionMode {
    if matches!(severity, Some(crate::packs::Severity::Critical))
        && matches!(
            mode,
            crate::packs::DecisionMode::Warn | crate::packs::DecisionMode::Log
        )
    {
        crate::packs::DecisionMode::Deny
    } else {
        mode
    }
}

// -----------------------------------------------------------------------------
// Per-rule target-path exemptions (#284)
// -----------------------------------------------------------------------------

/// Per-rule settings, keyed by `"<pack_id>:<pattern_name>"` in a
/// `[rules."core.filesystem:rm-rf-general"]` table.
///
/// This is the rule-scoped sibling of `[policy.rules]`: `[policy.rules]` picks
/// the *mode* a rule decides with, `[rules]` narrows the *targets* the rule
/// decides about.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct RuleConfig {
    /// Glob patterns naming target paths this rule must not fire on.
    ///
    /// The exemption is evaluated inside the rule's own target check, not as a
    /// command-level bypass: every other rule still sees the whole command, so
    /// `echo x > ~/.claude/jobs/a/tmp/log && git reset --hard` is still denied
    /// by `core.git:reset-hard`.
    ///
    /// Only a **statically literal** target is ever eligible. A target built
    /// from a variable, command substitution, glob, or quote splice is never
    /// exempted — `core.filesystem:redirect-truncate-dynamic-path` exists for
    /// exactly those and deliberately supports no exemptions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exempt_target_globs: Vec<String>,
}

/// Rule ids whose target is resolvable to a static literal path, and which
/// therefore honor `exempt_target_globs`.
///
/// Keep this list explicit. A rule that is not listed here silently ignores
/// the setting, which would leave the user still denied with no explanation —
/// [`Config::rule_target_exemption_warnings`] reports that case instead.
pub const RULE_TARGET_EXEMPTION_SUPPORTED_RULES: &[&str] = &[
    "core.filesystem:redirect-truncate-root-home",
    "core.filesystem:rm-rf-general",
    "core.filesystem:rm-rf-root-home",
    "core.filesystem:rm-r-f-separate",
    "core.filesystem:rm-r-f-separate-root-home",
    "core.filesystem:rm-recursive-force",
    "core.filesystem:rm-recursive-force-root-home",
    "core.filesystem:rm-recursive-general",
    "core.filesystem:rm-recursive-root-home",
];

/// Match options for `exempt_target_globs`.
///
/// `require_literal_separator` gives the documented semantics: `*` stops at a
/// path separator, `**` crosses them. Matching is case-sensitive on every
/// platform, matching the scan include/exclude globs.
const RULE_TARGET_GLOB_MATCH_OPTIONS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// A compiled `[rules]` target-exemption table.
///
/// Compilation is done once per process (globs are user-supplied and must not
/// be re-parsed per command).
#[derive(Debug, Clone, Default)]
pub struct RuleTargetExemptions {
    rules: std::collections::HashMap<String, Vec<CompiledTargetGlob>>,
}

#[derive(Debug, Clone)]
struct CompiledTargetGlob {
    /// The glob exactly as the user wrote it, for audit output.
    source: String,
    pattern: glob::Pattern,
}

impl RuleTargetExemptions {
    /// Whether any rule configured a target exemption.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Resolve `raw_target` for `rule_id` and return the glob that exempts it.
    ///
    /// Returns `None` when the rule has no exemptions, when the target is not
    /// a static literal path, when it contains a `..` component, or when no
    /// glob matches.
    #[must_use]
    pub fn matching_glob(&self, rule_id: &str, raw_target: &str) -> Option<&str> {
        let globs = self.rules.get(rule_id)?;
        let target = normalize_literal_target_path(raw_target)?;
        globs
            .iter()
            .find(|glob| {
                glob.pattern
                    .matches_with(&target, RULE_TARGET_GLOB_MATCH_OPTIONS)
            })
            .map(|glob| glob.source.as_str())
    }
}

/// Lexically normalize a candidate target path for glob matching.
///
/// This is deliberately filesystem-free: no `stat`, no symlink resolution, no
/// canonicalization. A symlinked path is therefore matched by its literal
/// spelling, exactly as written on the command line.
///
/// Returns `None` unless the text is a static literal path:
/// - any shell expansion, quoting, or glob byte disqualifies it;
/// - a leading `~` / `~/` expands to the user's home directory (any other
///   tilde form, including `~user`, is rejected);
/// - a `..` component is rejected outright rather than resolved, so
///   `~/.claude/jobs/x/tmp/../../../Documents` can never match a glob rooted
///   at the scratch directory;
/// - `.` components and duplicate separators are collapsed.
#[must_use]
pub(crate) fn normalize_literal_target_path(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Expansion, quoting, and glob syntax all mean the runtime target is not
    // the text dcg is looking at.
    if raw.bytes().any(|byte| {
        matches!(
            byte,
            b'$' | b'`'
                | b'\''
                | b'"'
                | b'*'
                | b'?'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'%'
                | b'!'
                | b'('
                | b')'
                | b'\n'
                | b'\r'
        ) || byte.is_ascii_control()
    }) {
        return None;
    }
    // On Unix a backslash is a shell escape, never a separator.
    #[cfg(not(windows))]
    if raw.contains('\\') {
        return None;
    }

    let expanded = if raw == "~" {
        dirs::home_dir()?.to_string_lossy().into_owned()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        let home = dirs::home_dir()?;
        format!("{}/{rest}", home.to_string_lossy().trim_end_matches('/'))
    } else if raw.starts_with('~') {
        // `~user` needs the passwd database to resolve; never guess.
        return None;
    } else {
        raw.to_string()
    };

    #[cfg(windows)]
    let expanded = expanded.replace('\\', "/");

    let rooted = expanded.starts_with('/');
    let mut components: Vec<&str> = Vec::new();
    for component in expanded.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return rooted.then(|| "/".to_string());
    }
    let joined = components.join("/");
    Some(if rooted { format!("/{joined}") } else { joined })
}

/// Normalize the glob text itself so it is compared against the same shape
/// [`normalize_literal_target_path`] produces (`~` expanded, `.` and duplicate
/// separators collapsed). Glob metacharacters are preserved.
fn normalize_target_glob(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("glob must not be empty".to_string());
    }
    if trimmed.split('/').any(|component| component == "..") {
        return Err("glob must not contain a `..` component".to_string());
    }

    let expanded = if trimmed == "~" {
        dirs::home_dir()
            .ok_or_else(|| "`~` cannot be expanded: no home directory".to_string())?
            .to_string_lossy()
            .into_owned()
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = dirs::home_dir()
            .ok_or_else(|| "`~` cannot be expanded: no home directory".to_string())?;
        format!("{}/{rest}", home.to_string_lossy().trim_end_matches('/'))
    } else if trimmed.starts_with('~') {
        return Err("only `~` and `~/` are expanded; `~user` is not supported".to_string());
    } else {
        trimmed.to_string()
    };

    let rooted = expanded.starts_with('/');
    let components: Vec<&str> = expanded
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    let joined = components.join("/");
    Ok(if rooted { format!("/{joined}") } else { joined })
}

impl Config {
    /// Compile the `[rules]` target-exemption globs.
    ///
    /// Invalid or empty globs are dropped here; they are reported separately by
    /// [`Config::rule_target_exemption_warnings`] so a typo never silently
    /// widens or narrows enforcement.
    #[must_use]
    pub fn rule_target_exemptions(&self) -> RuleTargetExemptions {
        let mut rules = std::collections::HashMap::new();
        for (rule_id, rule) in &self.rules {
            if !RULE_TARGET_EXEMPTION_SUPPORTED_RULES.contains(&rule_id.as_str()) {
                continue;
            }
            let compiled: Vec<CompiledTargetGlob> = rule
                .exempt_target_globs
                .iter()
                .filter_map(|raw| {
                    let normalized = normalize_target_glob(raw).ok()?;
                    let pattern = glob::Pattern::new(&normalized).ok()?;
                    Some(CompiledTargetGlob {
                        source: raw.clone(),
                        pattern,
                    })
                })
                .collect();
            if !compiled.is_empty() {
                rules.insert(rule_id.clone(), compiled);
            }
        }
        RuleTargetExemptions { rules }
    }

    /// Human-readable problems with the effective `[rules]` tables.
    ///
    /// Every entry here means the user configured an exemption that will NOT
    /// take effect, so they keep getting the denial they tried to remove.
    #[must_use]
    pub fn rule_target_exemption_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut rule_ids: Vec<&String> = self.rules.keys().collect();
        rule_ids.sort_unstable();
        for rule_id in rule_ids {
            let rule = &self.rules[rule_id];
            if rule.exempt_target_globs.is_empty() {
                continue;
            }
            if !RULE_TARGET_EXEMPTION_SUPPORTED_RULES.contains(&rule_id.as_str()) {
                warnings.push(format!(
                    "[rules.\"{rule_id}\"] exempt_target_globs is ignored: \
                     that rule does not support target exemptions (supported: {})",
                    RULE_TARGET_EXEMPTION_SUPPORTED_RULES.join(", ")
                ));
                continue;
            }
            for raw in &rule.exempt_target_globs {
                match normalize_target_glob(raw) {
                    Err(error) => warnings.push(format!(
                        "[rules.\"{rule_id}\"] exempt_target_globs entry {raw:?} is invalid: {error}"
                    )),
                    Ok(normalized) => {
                        if let Err(error) = glob::Pattern::new(&normalized) {
                            warnings.push(format!(
                                "[rules.\"{rule_id}\"] exempt_target_globs entry {raw:?} \
                                 is not a valid glob: {error}"
                            ));
                        }
                    }
                }
            }
        }
        warnings
    }
}

/// A rule firing that a configured target exemption suppressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTargetSuppression {
    /// `"<pack_id>:<pattern_name>"` of the rule that matched.
    pub rule_id: String,
    /// The glob, exactly as configured, that exempted the target.
    pub glob: String,
    /// The target path as it appeared on the command line.
    pub target: String,
}

#[derive(Clone, Default)]
struct ActiveRuleTargetExemptions {
    exemptions: std::sync::Arc<RuleTargetExemptions>,
    verbose: bool,
}

/// Exemptions from the most recently loaded [`Config`].
///
/// The hook's hot path evaluates through `evaluate_command_with_pack_order_*`,
/// which deliberately takes no `&Config`. Publishing the compiled table when a
/// config is loaded keeps that path served without threading a parameter
/// through every pack matcher. A repository `.dcg.toml` is already reduced to
/// enforcement-only settings before it reaches here, so nothing published from
/// this point can carry a repository-authored exemption.
static PROCESS_RULE_TARGET_EXEMPTIONS: std::sync::RwLock<Option<ActiveRuleTargetExemptions>> =
    std::sync::RwLock::new(None);

thread_local! {
    /// Exemptions explicitly scoped to the evaluation running on this thread.
    ///
    /// The pack matchers that own a rule's target check sit ten-plus frames
    /// below the last function that holds a `&Config`, and several of them are
    /// shared with the rm parser in `packs::core::filesystem`. A thread-local
    /// scope keeps the plumbing out of those signatures while staying isolated
    /// between parallel test threads, and takes precedence over the process
    /// default above.
    static RULE_TARGET_EXEMPTION_OVERRIDE: std::cell::RefCell<Option<ActiveRuleTargetExemptions>> =
        const { std::cell::RefCell::new(None) };

    /// Suppressions recorded during the evaluation running on this thread.
    static RULE_TARGET_SUPPRESSIONS: std::cell::RefCell<Vec<RuleTargetSuppression>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn active_rule_target_exemptions() -> Option<ActiveRuleTargetExemptions> {
    if let Some(active) = RULE_TARGET_EXEMPTION_OVERRIDE.with(|state| state.borrow().clone()) {
        return Some(active);
    }
    PROCESS_RULE_TARGET_EXEMPTIONS
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Publish `config`'s compiled `[rules]` exemptions as the process default.
///
/// Called once per loaded config. Idempotent and cheap to repeat.
pub(crate) fn publish_rule_target_exemptions(config: &Config) {
    let active = ActiveRuleTargetExemptions {
        exemptions: std::sync::Arc::new(config.rule_target_exemptions()),
        verbose: config.general.verbose,
    };
    if let Ok(mut guard) = PROCESS_RULE_TARGET_EXEMPTIONS.write() {
        *guard = Some(active);
    }
}

/// RAII guard installing a config's target exemptions for the current thread.
///
/// Restores the previous thread scope on drop, so nested evaluations are safe.
/// This is the entry point for callers that hold a `&Config` directly (library
/// API users and tests); the hook relies on the process default published at
/// config load.
pub struct RuleTargetExemptionScope {
    previous: Option<ActiveRuleTargetExemptions>,
}

impl RuleTargetExemptionScope {
    /// Install `config`'s compiled `[rules]` exemptions for this thread.
    #[must_use]
    pub fn install(config: &Config) -> Self {
        let next = ActiveRuleTargetExemptions {
            exemptions: std::sync::Arc::new(config.rule_target_exemptions()),
            verbose: config.general.verbose,
        };
        let previous = RULE_TARGET_EXEMPTION_OVERRIDE.with(|state| state.replace(Some(next)));
        Self { previous }
    }
}

impl Drop for RuleTargetExemptionScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RULE_TARGET_EXEMPTION_OVERRIDE.with(|state| {
            *state.borrow_mut() = previous;
        });
    }
}

/// Whether `rule_id` has any target exemption configured for this evaluation.
///
/// Cheap gate so the supported rules skip target extraction entirely on the
/// overwhelmingly common unconfigured path.
#[must_use]
pub fn rule_has_target_exemptions(rule_id: &str) -> bool {
    active_rule_target_exemptions()
        .is_some_and(|active| active.exemptions.rules.contains_key(rule_id))
}

/// Whether `rule_id`'s configured target exemptions cover `raw_target`.
///
/// This is the shared helper every supported rule calls at the point where its
/// own target is already known. It returns the matching glob so callers can
/// report *why* the rule did not fire.
///
/// The lookup is pure: an operation with several targets must prove *every*
/// target exempt before it suppresses anything, so recording is a separate
/// step ([`note_rule_target_suppression`]).
#[must_use]
pub fn rule_target_exemption(rule_id: &str, raw_target: &str) -> Option<String> {
    let active = active_rule_target_exemptions()?;
    if active.exemptions.is_empty() {
        return None;
    }
    active
        .exemptions
        .matching_glob(rule_id, raw_target)
        .map(ToString::to_string)
}

/// Boolean form of [`rule_target_exemption`].
#[must_use]
pub fn rule_target_exempted(rule_id: &str, raw_target: &str) -> bool {
    rule_target_exemption(rule_id, raw_target).is_some()
}

/// Record that `rule_id` matched but did not fire because `glob` exempted
/// `target`.
///
/// A suppressed rule is an allow, and an allow that came from configuration
/// must be visible: the suppression is retained for the audit trail (see
/// [`take_rule_target_suppressions`]) and echoed to stderr in verbose mode.
pub fn note_rule_target_suppression(rule_id: &str, glob: &str, target: &str) {
    if active_rule_target_exemptions().is_some_and(|active| active.verbose) {
        eprintln!(
            "dcg: rule {rule_id} matched but target {target:?} is exempted by \
             [rules.\"{rule_id}\"] exempt_target_globs entry {glob:?}"
        );
    }
    RULE_TARGET_SUPPRESSIONS.with(|state| {
        state.borrow_mut().push(RuleTargetSuppression {
            rule_id: rule_id.to_string(),
            glob: glob.to_string(),
            target: target.to_string(),
        });
    });
}

/// Drain the target-exemption suppressions recorded during this evaluation.
///
/// Callers that render an audit trail (history rows, `dcg explain`) use this to
/// state which rule matched and which glob suppressed it.
#[must_use]
pub fn take_rule_target_suppressions() -> Vec<RuleTargetSuppression> {
    RULE_TARGET_SUPPRESSIONS.with(|state| std::mem::take(&mut *state.borrow_mut()))
}

/// Custom pattern overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct OverridesConfig {
    /// Patterns to allow that would otherwise be blocked.
    #[serde(default)]
    pub allow: Vec<AllowOverride>,

    /// Additional patterns to block.
    #[serde(default)]
    pub block: Vec<BlockOverride>,

    /// REMOVED (#327): `overrides.allowlist` parsed, appeared in the schema,
    /// and was never consulted during evaluation — the layer merge dropped it,
    /// so a config using it silently had no effect. The key is now detected
    /// only so `dcg config` / `dcg doctor` can warn and point at the surfaces
    /// that work: `overrides.allow`, per-rule `exempt_target_globs`, and
    /// `dcg allowlist add`.
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub allowlist: Option<toml::Value>,

    /// REMOVED (#327): `overrides.allowlist_rules` had the same silent-drop
    /// fate as `allowlist` above, with the extra hazard that its documented
    /// `paths` condition was ignored even by the dead compile path — wiring it
    /// up as parsed would have granted path-scoped configs global allowances.
    /// Detected only, to warn.
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub allowlist_rules: Option<toml::Value>,
}

impl OverridesConfig {
    /// Warnings for config keys that parse but are no longer part of the
    /// schema (#327). Surfaced through `dcg config` and `dcg doctor` so a
    /// silently-ignored key is distinguishable from one that simply didn't
    /// match.
    #[must_use]
    pub fn removed_key_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.allowlist.is_some() {
            warnings.push(
                "`overrides.allowlist` is not enforced (removed in #327; it was parsed but \
                 never consulted). Use `overrides.allow` regex overrides, a per-rule \
                 `[rules.\"<pack:rule>\"] exempt_target_globs` target exemption, or \
                 `dcg allowlist add`."
                    .to_string(),
            );
        }
        if self.allowlist_rules.is_some() {
            warnings.push(
                "`overrides.allowlist_rules` is not enforced (removed in #327; it was parsed \
                 but never consulted, and its `paths` condition was never implemented). For \
                 path-scoped exemptions use `[rules.\"<pack:rule>\"] exempt_target_globs`, or \
                 `dcg allowlist add --path`."
                    .to_string(),
            );
        }
        warnings
    }
}

/// Settings for layered allowlist files (`.dcg/allowlist.toml`,
/// `~/.config/dcg/allowlist.toml`, and `/etc/dcg/allowlist.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct AllowlistConfig {
    /// Automatically prune expired entries during allowlist CLI operations.
    ///
    /// Disabled by default so expired entries remain as audit history unless a
    /// user explicitly opts in or runs `dcg allowlist prune`.
    pub auto_prune_expired: bool,
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            auto_prune_expired: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct AllowlistConfigLayer {
    auto_prune_expired: Option<bool>,
}

/// An allow override - patterns that should be permitted.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum AllowOverride {
    /// Simple pattern string.
    Simple(String),
    /// Conditional override with optional `when` clause.
    Conditional {
        pattern: String,
        /// Optional condition (e.g., "CI=true").
        when: Option<String>,
    },
}

impl AllowOverride {
    /// Get the pattern string.
    #[must_use]
    pub fn pattern(&self) -> &str {
        match self {
            Self::Simple(p) => p,
            Self::Conditional { pattern, .. } => pattern,
        }
    }

    /// Check if the condition is met (if any).
    #[must_use]
    pub fn condition_met(&self) -> bool {
        match self {
            Self::Simple(_) | Self::Conditional { when: None, .. } => true,
            Self::Conditional {
                when: Some(condition),
                ..
            } => {
                // Parse condition like "CI=true"
                if let Some((var, expected)) = condition.split_once('=') {
                    env::var(var).map(|v| v == expected).unwrap_or(false)
                } else {
                    // Just check if the env var is set
                    env::var(condition).is_ok()
                }
            }
        }
    }
}

/// A block override - additional patterns to block.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlockOverride {
    /// The regex pattern to match.
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

/// Redaction mode for command history.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum HistoryRedactionMode {
    /// Store commands without redaction.
    None,
    /// Redact sensitive values using pattern-based filters.
    #[default]
    Pattern,
    /// Fully redact command contents.
    Full,
}

impl std::str::FromStr for HistoryRedactionMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "pattern" => Ok(Self::Pattern),
            "full" => Ok(Self::Full),
            _ => Err(format!("invalid history redaction mode: {value}")),
        }
    }
}

/// History configuration options.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct HistoryConfig {
    /// Enable command history collection.
    pub enabled: bool,
    /// Redaction mode for stored commands.
    pub redaction_mode: HistoryRedactionMode,
    /// Retention window in days.
    #[schemars(range(min = 1, max = 3650))]
    pub retention_days: u32,
    /// Maximum database size in megabytes.
    #[schemars(range(min = 1))]
    pub max_size_mb: u32,
    /// Optional database file path override.
    pub database_path: Option<String>,
    /// Enable automatic pruning of old entries.
    pub auto_prune: bool,
    /// Interval in hours between automatic prune checks.
    #[schemars(range(min = 1))]
    pub prune_check_interval_hours: u32,
    /// Batch size for write operations (improves performance).
    #[schemars(range(min = 1))]
    pub batch_size: u32,
    /// Flush interval in milliseconds for batched writes.
    #[schemars(range(min = 1))]
    pub batch_flush_interval_ms: u32,
}

impl HistoryConfig {
    /// Default retention window (days).
    pub const DEFAULT_RETENTION_DAYS: u32 = 90;
    /// Default maximum database size (MB).
    pub const DEFAULT_MAX_SIZE_MB: u32 = 500;
    /// Maximum allowed retention window (days).
    pub const MAX_RETENTION_DAYS: u32 = 3650;
    /// Default interval between automatic prune checks (hours).
    pub const DEFAULT_PRUNE_CHECK_INTERVAL_HOURS: u32 = 24;
    /// Default batch size for write operations.
    pub const DEFAULT_BATCH_SIZE: u32 = 50;
    /// Default flush interval for batched writes (ms).
    pub const DEFAULT_BATCH_FLUSH_INTERVAL_MS: u32 = 100;

    /// Expand the configured database path, if set.
    #[must_use]
    pub fn expanded_database_path(&self) -> Option<PathBuf> {
        let raw = self.database_path.as_ref()?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        let had_tilde_prefix = trimmed.starts_with('~');
        let (mut path, _tilde_expanded) = expand_tilde_path(trimmed);
        if !had_tilde_prefix && path.is_relative() {
            if let Ok(cwd) = env::current_dir() {
                path = cwd.join(path);
            }
        }
        Some(path)
    }

    /// Validate history settings.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid history values.
    pub fn validate(&self) -> Result<(), String> {
        if self.retention_days == 0 {
            return Err("history retention_days must be at least 1".to_string());
        }
        if self.retention_days > Self::MAX_RETENTION_DAYS {
            return Err(format!(
                "history retention_days must be <= {}",
                Self::MAX_RETENTION_DAYS
            ));
        }
        if self.max_size_mb == 0 {
            return Err("history max_size_mb must be at least 1".to_string());
        }
        if self.prune_check_interval_hours == 0 {
            return Err("history prune_check_interval_hours must be at least 1".to_string());
        }
        if self.batch_size == 0 {
            return Err("history batch_size must be at least 1".to_string());
        }
        if self.batch_flush_interval_ms == 0 {
            return Err("history batch_flush_interval_ms must be at least 1".to_string());
        }
        Ok(())
    }

    /// Repair invalid runtime values to conservative, non-spinning minima.
    ///
    /// The public config type can be constructed directly and layered TOML is
    /// intentionally presence-aware, so schema validation alone is not a
    /// runtime boundary. Return whether any value needed repair so the loader
    /// can surface a single concise warning.
    fn normalize_runtime_invariants(&mut self) -> bool {
        let original = (
            self.retention_days,
            self.max_size_mb,
            self.prune_check_interval_hours,
            self.batch_size,
            self.batch_flush_interval_ms,
        );
        self.retention_days = self.retention_days.clamp(1, Self::MAX_RETENTION_DAYS);
        self.max_size_mb = self.max_size_mb.max(1);
        self.prune_check_interval_hours = self.prune_check_interval_hours.max(1);
        self.batch_size = self.batch_size.max(1);
        self.batch_flush_interval_ms = self.batch_flush_interval_ms.max(1);
        original
            != (
                self.retention_days,
                self.max_size_mb,
                self.prune_check_interval_hours,
                self.batch_size,
                self.batch_flush_interval_ms,
            )
    }
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            redaction_mode: HistoryRedactionMode::Pattern,
            retention_days: Self::DEFAULT_RETENTION_DAYS,
            max_size_mb: Self::DEFAULT_MAX_SIZE_MB,
            database_path: None,
            auto_prune: false,
            prune_check_interval_hours: Self::DEFAULT_PRUNE_CHECK_INTERVAL_HOURS,
            batch_size: Self::DEFAULT_BATCH_SIZE,
            batch_flush_interval_ms: Self::DEFAULT_BATCH_FLUSH_INTERVAL_MS,
        }
    }
}

// ============================================================================
// Git Branch-Aware Strictness Configuration
// ============================================================================

/// Strictness level that determines which severity levels are blocked.
///
/// This controls the sensitivity of pattern matching based on context,
/// such as which git branch you're on.
///
/// # Example Configuration (TOML)
///
/// ```toml
/// [git_awareness]
/// enabled = true
/// protected_branches = ["main", "production", "release/*"]
/// protected_strictness = "all"
/// relaxed_branches = ["feature/*", "experiment/*", "sandbox/*"]
/// relaxed_strictness = "critical"
/// ```
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum StrictnessLevel {
    /// Only block Critical severity patterns.
    /// Most permissive - allows High, Medium, and Low to pass.
    Critical,

    /// Block Critical and High severity patterns.
    /// This is the default behavior.
    #[default]
    High,

    /// Block Critical, High, and Medium severity patterns.
    Medium,

    /// Block all severity levels including Low.
    /// Most restrictive - recommended for protected branches.
    All,
}

impl StrictnessLevel {
    /// Returns `true` if the given severity should be blocked at this strictness level.
    #[must_use]
    pub const fn should_block(&self, severity: crate::packs::Severity) -> bool {
        use crate::packs::Severity;
        match self {
            Self::Critical => matches!(severity, Severity::Critical),
            Self::High => matches!(severity, Severity::Critical | Severity::High),
            Self::Medium => {
                matches!(
                    severity,
                    Severity::Critical | Severity::High | Severity::Medium
                )
            }
            Self::All => true,
        }
    }

    /// Parse a strictness level from a string.
    #[must_use]
    pub fn from_str_case_insensitive(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

impl std::fmt::Display for StrictnessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::All => write!(f, "all"),
        }
    }
}

/// Git branch-aware strictness configuration.
///
/// This allows different strictness levels based on the current git branch,
/// providing more protection on important branches and more freedom on
/// experimental branches.
///
/// # Example Configuration (TOML)
///
/// ```toml
/// [git_awareness]
/// enabled = true
///
/// # Protected branches get extra scrutiny
/// protected_branches = ["main", "production", "release/*"]
/// protected_strictness = "all"  # Block everything including Low severity
///
/// # Feature branches get more freedom
/// relaxed_branches = ["feature/*", "experiment/*", "sandbox/*"]
/// relaxed_strictness = "critical"  # Only block Critical severity
///
/// # Packs to disable on relaxed branches
/// relaxed_disabled_packs = []
///
/// # Default strictness when not matching any pattern
/// default_strictness = "high"  # Block Critical and High (normal behavior)
///
/// # Show branch context in output
/// show_branch_in_output = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct GitAwarenessConfig {
    /// Enable git branch-aware strictness.
    /// When disabled, normal strictness levels apply everywhere.
    pub enabled: bool,

    /// Branch patterns that should receive extra protection.
    /// Supports glob patterns (e.g., "release/*").
    pub protected_branches: Vec<String>,

    /// Strictness level for protected branches.
    /// Default: `All` (block everything including Low severity)
    pub protected_strictness: StrictnessLevel,

    /// Branch patterns that should receive relaxed protection.
    /// Supports glob patterns (e.g., "feature/*", "experiment/*").
    pub relaxed_branches: Vec<String>,

    /// Strictness level for relaxed branches.
    /// Default: `Critical` (only block Critical severity)
    pub relaxed_strictness: StrictnessLevel,

    /// Default strictness level when not on a protected or relaxed branch.
    /// Default: `High` (normal behavior)
    pub default_strictness: StrictnessLevel,

    /// Strictness level when HEAD is detached (no branch checked out).
    ///
    /// Detached HEAD typically signals a rebase, bisect, or checkout-of-tag
    /// operation — exactly the contexts where uncommitted work is most easily
    /// lost. Defaults to `All` (strictest), matching the protected-branch
    /// posture rather than the per-branch default. Set this to
    /// `default_strictness` if you want detached HEAD treated like an
    /// unprotected branch.
    pub detached_head_strictness: StrictnessLevel,

    /// Packs to disable on relaxed branches.
    /// These packs will be skipped during evaluation when on a relaxed branch.
    /// Default: empty (no packs disabled)
    pub relaxed_disabled_packs: Vec<String>,

    /// Show the current git branch in output messages.
    /// When enabled, blocked command output will include the branch context.
    /// Default: `true`
    pub show_branch_in_output: bool,

    /// Show a warning when not in a git repository.
    /// When enabled and git_awareness is enabled, a warning will be logged
    /// if dcg cannot detect a git repository. The command will still be
    /// evaluated using default strictness (graceful degradation).
    /// Default: `false`
    pub warn_if_not_git: bool,
}

impl Default for GitAwarenessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protected_branches: vec![
                "main".to_string(),
                "production".to_string(),
                "release/*".to_string(),
            ],
            protected_strictness: StrictnessLevel::All,
            relaxed_branches: vec![
                "feature/*".to_string(),
                "experiment/*".to_string(),
                "sandbox/*".to_string(),
            ],
            relaxed_strictness: StrictnessLevel::Critical,
            default_strictness: StrictnessLevel::High,
            detached_head_strictness: StrictnessLevel::All,
            relaxed_disabled_packs: Vec::new(),
            show_branch_in_output: true,
            warn_if_not_git: false,
        }
    }
}

impl GitAwarenessConfig {
    /// Get the effective strictness level for a given branch.
    ///
    /// Checks protected branches first, then relaxed branches, then falls back
    /// to the default strictness.
    #[must_use]
    pub fn strictness_for_branch(&self, branch: Option<&str>) -> StrictnessLevel {
        if !self.enabled {
            return self.default_strictness;
        }

        let Some(branch) = branch else {
            // Not on a branch (detached HEAD or not in git repo)
            return self.default_strictness;
        };

        // Check protected branches first (they take priority)
        if self.matches_any_pattern(branch, &self.protected_branches) {
            return self.protected_strictness;
        }

        // Check relaxed branches
        if self.matches_any_pattern(branch, &self.relaxed_branches) {
            return self.relaxed_strictness;
        }

        // Fall back to default
        self.default_strictness
    }

    /// Check if a branch name matches any of the given patterns.
    fn matches_any_pattern(&self, branch: &str, patterns: &[String]) -> bool {
        for pattern in patterns {
            if Self::branch_matches_pattern(branch, pattern) {
                return true;
            }
        }
        false
    }

    /// Check if a branch name matches a single pattern.
    ///
    /// Supports:
    /// - Exact match: "main" matches "main"
    /// - Glob suffix: "release/*" matches "release/1.0", "release/2.0-beta"
    /// - Glob prefix: "*/hotfix" matches "team/hotfix"
    ///
    /// Important: glob patterns enforce a `/` boundary. `release/*` matches
    /// `release/1.0` but NOT `release-rogue` or `releaseX` — without this
    /// guard a malicious branch name could spoof a protected-branch glob and
    /// inherit the strict policy of an unrelated branch family (or, worse,
    /// dodge it via the relaxed-branches glob).
    fn branch_matches_pattern(branch: &str, pattern: &str) -> bool {
        if pattern == "*" {
            // Wildcard matches everything
            return true;
        }

        if let Some(prefix) = pattern.strip_suffix("/*") {
            // `release/*` pattern: branch must start with `release/` and have
            // at least one character after the slash. We re-add the `/` from
            // the original pattern so a branch like `release-rogue` (no slash
            // boundary) is correctly rejected.
            if !branch.starts_with(prefix) {
                return false;
            }
            let after_prefix = &branch[prefix.len()..];
            return after_prefix.starts_with('/') && after_prefix.len() > 1;
        }

        if let Some(suffix) = pattern.strip_prefix("*/") {
            // `*/hotfix` pattern: branch must end with `/hotfix`, with a
            // non-empty name before the slash (so `team/hotfix` matches but
            // `/hotfix` and `team-hotfix` do not). The boundary check is the
            // mirror of the prefix-glob branch above.
            if !branch.ends_with(suffix) {
                return false;
            }
            let before_suffix_len = branch.len() - suffix.len();
            // Need at least two bytes before the suffix: one for the slash
            // and at least one for the name segment (`x/hotfix` is the
            // minimum legitimate match).
            if before_suffix_len < 2 {
                return false;
            }
            // Byte-safe: walk back one byte and confirm it's `/`. Branch
            // names are ASCII per git's refname rules (no multi-byte
            // separators), but we still index by bytes here to avoid any
            // surprise slicing.
            return branch.as_bytes()[before_suffix_len - 1] == b'/';
        }

        // Exact match
        branch == pattern
    }

    /// Returns `true` if the current branch is a protected branch.
    #[must_use]
    pub fn is_protected_branch(&self, branch: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }
        branch.is_some_and(|b| self.matches_any_pattern(b, &self.protected_branches))
    }

    /// Returns `true` if the current branch is a relaxed branch.
    #[must_use]
    pub fn is_relaxed_branch(&self, branch: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }
        branch.is_some_and(|b| self.matches_any_pattern(b, &self.relaxed_branches))
    }

    /// Get the list of packs that should be disabled on relaxed branches.
    ///
    /// Returns an empty slice if git awareness is disabled or if the current
    /// branch is not a relaxed branch.
    #[must_use]
    pub fn disabled_packs_for_branch(&self, branch: Option<&str>) -> &[String] {
        if !self.enabled {
            return &[];
        }
        if self.is_relaxed_branch(branch) {
            &self.relaxed_disabled_packs
        } else {
            &[]
        }
    }

    /// Returns `true` if branch context should be shown in output.
    #[must_use]
    pub const fn should_show_branch_in_output(&self) -> bool {
        self.enabled && self.show_branch_in_output
    }
}

// ============================================================================
// Agent-Specific Profiles (Epic 9)
// ============================================================================

/// Trust level for AI coding agents.
///
/// An advisory label that is recorded in JSON output and verbose logs.
/// It does **not** directly change rule evaluation -- behavioral differences
/// are controlled by the other [`AgentProfile`] fields (`disabled_packs`,
/// `extra_packs`, `additional_allowlist`, `disabled_allowlist`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// High trust: agent has proven reliable. Typically paired with a broader
    /// allowlist and fewer packs in the agent profile.
    High,
    /// Medium trust: default behavior, standard configuration.
    #[default]
    Medium,
    /// Low trust: extra caution for unknown agents. Typically paired with more
    /// packs and a restricted allowlist in the agent profile.
    Low,
}

/// Agent-specific profile configuration.
///
/// Defines how dcg should behave when invoked by a specific AI coding agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct AgentProfile {
    /// Advisory trust label for this agent (included in JSON output and logs).
    /// Does not directly affect evaluation; see other fields for behavioral control.
    pub trust_level: TrustLevel,

    /// Packs to disable for this agent (subtracted from base config).
    pub disabled_packs: Vec<String>,

    /// Extra packs to enable for this agent (added to base config).
    pub extra_packs: Vec<String>,

    /// Additional allowlist patterns for this agent.
    pub additional_allowlist: Vec<String>,

    /// If true, skip all allowlist checks for this agent (more restrictive).
    pub disabled_allowlist: bool,
}

/// Agent-specific profiles configuration.
///
/// Maps agent identifiers to their profile configurations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct AgentsConfig {
    /// Default profile applied to all agents unless overridden.
    #[serde(default)]
    pub default: AgentProfile,

    /// Agent-specific profile overrides.
    ///
    /// Keys are agent identifiers (e.g., "claude-code", "aider", "gemini-cli").
    /// Use "unknown" for undetected/custom agents.
    #[serde(flatten)]
    pub profiles: std::collections::HashMap<String, AgentProfile>,
}

impl AgentsConfig {
    /// Get the profile for a specific agent.
    ///
    /// Falls back to the "unknown" profile if no specific profile exists,
    /// then to the default profile if "unknown" doesn't exist.
    #[must_use]
    pub fn profile_for(&self, agent_key: &str) -> &AgentProfile {
        self.profiles
            .get(agent_key)
            .or_else(|| self.profile_for_agent_alias(agent_key))
            .or_else(|| {
                if agent_key != "unknown" {
                    self.profiles
                        .get("unknown")
                        .or_else(|| self.profile_for_agent_alias("unknown"))
                } else {
                    None
                }
            })
            .unwrap_or(&self.default)
    }

    fn profile_for_agent_alias(&self, agent_key: &str) -> Option<&AgentProfile> {
        let requested_agent = crate::agent::Agent::from_name(agent_key);
        let canonical_key = requested_agent.config_key();

        if let Some(profile) = self.profiles.get(canonical_key) {
            return Some(profile);
        }

        self.profiles.iter().find_map(|(configured_key, profile)| {
            let configured_agent = crate::agent::Agent::from_name(configured_key);
            (configured_agent.config_key() == canonical_key).then_some(profile)
        })
    }

    /// Get the effective trust level for an agent.
    #[must_use]
    pub fn trust_level_for(&self, agent_key: &str) -> TrustLevel {
        self.profile_for(agent_key).trust_level
    }

    /// Check if allowlists are disabled for an agent.
    #[must_use]
    pub fn allowlist_disabled_for(&self, agent_key: &str) -> bool {
        self.profile_for(agent_key).disabled_allowlist
    }

    /// Get the profile for an agent using its config key.
    ///
    /// This is a convenience method that accepts an [`Agent`](crate::agent::Agent)
    /// and looks up the appropriate profile.
    #[must_use]
    pub fn profile_for_agent(&self, agent: &crate::agent::Agent) -> &AgentProfile {
        self.profile_for(agent.config_key())
    }
}

// ============================================================================
// Compiled Overrides (Runtime-Only, Pre-compiled Regexes)
// ============================================================================

use crate::packs::regex_engine::CompiledRegex;

/// A compiled allow override with precompiled regex.
///
/// This is the runtime representation used for evaluation.
/// Created once at config load time, not per-command.
#[derive(Debug)]
pub struct CompiledAllowOverride {
    /// The precompiled regex pattern.
    pub regex: CompiledRegex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// The condition evaluator (returns true if condition is met).
    /// For simple overrides, this always returns true.
    /// For conditional overrides, this checks the environment.
    condition: ConditionCheck,
}

/// Condition check type - either always true or checks an env var.
#[derive(Debug)]
enum ConditionCheck {
    /// Always allow (no condition).
    Always,
    /// Check if env var equals expected value.
    EnvEquals { var: String, expected: String },
    /// Check if env var is set (any value).
    EnvSet { var: String },
}

impl ConditionCheck {
    /// Check if the condition is met.
    fn is_met(&self) -> bool {
        match self {
            Self::Always => true,
            Self::EnvEquals { var, expected } => {
                std::env::var(var).map(|v| v == *expected).unwrap_or(false)
            }
            Self::EnvSet { var } => std::env::var(var).is_ok(),
        }
    }
}

impl CompiledAllowOverride {
    /// Check if this override matches and its condition is met.
    ///
    /// Returns true if the command matches and should be allowed.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> bool {
        self.condition.is_met() && self.regex.is_match(command)
    }
}

/// A compiled block override with precompiled regex.
#[derive(Debug)]
pub struct CompiledBlockOverride {
    /// The precompiled regex pattern.
    pub regex: CompiledRegex,
    /// The original pattern string (for diagnostics).
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

impl CompiledBlockOverride {
    /// Check if this override matches.
    ///
    /// Returns the reason if blocked.
    #[inline]
    #[must_use]
    pub fn matches(&self, command: &str) -> Option<&str> {
        if self.regex.is_match(command) {
            Some(&self.reason)
        } else {
            None
        }
    }
}

/// Compiled overrides - runtime representation with precompiled regexes.
///
/// This struct is created once per config load and reused for all command
/// evaluations. It eliminates per-command regex compilation overhead.
#[derive(Debug, Default)]
pub struct CompiledOverrides {
    /// Compiled allow overrides.
    pub allow: Vec<CompiledAllowOverride>,
    /// Compiled block overrides.
    pub block: Vec<CompiledBlockOverride>,
    /// Patterns that failed to compile (for diagnostics).
    pub invalid_patterns: Vec<InvalidPattern>,
}

/// Record of a pattern that failed to compile.
#[derive(Debug, Clone)]
pub struct InvalidPattern {
    /// The original pattern string.
    pub pattern: String,
    /// The compilation error message.
    pub error: String,
    /// Whether this was an allow or block pattern.
    pub kind: PatternKind,
}

/// Kind of override pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    Allow,
    Block,
}

impl CompiledOverrides {
    /// Check allow overrides. Returns true if command should be allowed.
    ///
    /// Allow patterns are substring-matched, and this check runs *before* pack
    /// evaluation, so on a compound command a single matching entry used to
    /// return `allowed` for text it never examined: an entry naming a scratch
    /// path allowed that path plus whatever followed the `&&` (#340). A
    /// safe segment silencing a destructive one is the same bypass class
    /// `split_command_segments` already closes for pack patterns, so allow
    /// overrides now clear each segment on its own terms.
    ///
    /// A single-segment command keeps the historical whole-string semantics.
    /// A compound command is allowed only when every segment is itself
    /// allowed; an entry that covers one segment no longer speaks for the
    /// rest, and anything uncovered falls through to normal evaluation.
    /// Anchored entries compose across a chain for the first time as a
    /// result — previously `^a$` and `^b$` allowed neither half of `a && b`.
    #[inline]
    #[must_use]
    pub fn check_allow(&self, command: &str) -> bool {
        if self.allow.is_empty() {
            return false;
        }

        let segments = crate::packs::split_command_segments(command);
        if segments.len() <= 1 {
            return self.allow.iter().any(|o| o.matches(command));
        }

        segments.iter().all(|segment| {
            let segment = segment.trim();
            segment.is_empty() || self.allow.iter().any(|o| o.matches(segment))
        })
    }

    /// Check block overrides. Returns the reason if command should be blocked.
    #[inline]
    #[must_use]
    pub fn check_block(&self, command: &str) -> Option<&str> {
        self.block.iter().find_map(|o| o.matches(command))
    }

    /// Check if there are any invalid patterns.
    #[must_use]
    pub fn has_invalid_patterns(&self) -> bool {
        !self.invalid_patterns.is_empty()
    }
}

impl OverridesConfig {
    /// Compile all override patterns into precompiled regexes.
    ///
    /// Invalid patterns are collected but do not cause errors (fail-open).
    /// Use `CompiledOverrides::invalid_patterns` to check for issues.
    #[must_use]
    pub fn compile(&self) -> CompiledOverrides {
        let mut compiled = CompiledOverrides::default();

        // Compile allow overrides
        for allow in &self.allow {
            match CompiledRegex::new(allow.pattern()) {
                Ok(regex) => {
                    let condition = match allow {
                        AllowOverride::Simple(_)
                        | AllowOverride::Conditional { when: None, .. } => ConditionCheck::Always,
                        AllowOverride::Conditional {
                            when: Some(condition),
                            ..
                        } => {
                            if let Some((var, expected)) = condition.split_once('=') {
                                ConditionCheck::EnvEquals {
                                    var: var.to_string(),
                                    expected: expected.to_string(),
                                }
                            } else {
                                ConditionCheck::EnvSet {
                                    var: condition.clone(),
                                }
                            }
                        }
                    };
                    compiled.allow.push(CompiledAllowOverride {
                        regex,
                        pattern: allow.pattern().to_string(),
                        condition,
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: allow.pattern().to_string(),
                        error: e.clone(),
                        kind: PatternKind::Allow,
                    });
                }
            }
        }

        // Compile block overrides
        for block in &self.block {
            match CompiledRegex::new(&block.pattern) {
                Ok(regex) => {
                    compiled.block.push(CompiledBlockOverride {
                        regex,
                        pattern: block.pattern.clone(),
                        reason: block.reason.clone(),
                    });
                }
                Err(e) => {
                    compiled.invalid_patterns.push(InvalidPattern {
                        pattern: block.pattern.clone(),
                        error: e.clone(),
                        kind: PatternKind::Block,
                    });
                }
            }
        }

        compiled
    }
}

/// Project-specific configuration overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ProjectConfig {
    /// Pack configuration for this project.
    pub packs: Option<PacksConfig>,

    /// Overrides for this project.
    pub overrides: Option<OverridesConfig>,
}

impl Config {
    /// Load configuration from all sources, merging them in priority order.
    ///
    /// Priority (highest to lowest):
    /// 1. Environment variables (settings overrides)
    /// 2. Explicit config file (`DCG_CONFIG=/path/to/config.toml`)
    /// 3. User config (`$XDG_CONFIG_HOME/dcg/config.toml`, `~/.config/dcg/config.toml`,
    ///    or platform-native config dir)
    /// 4. System config (`/etc/dcg/config.toml`)
    /// 5. Compiled defaults
    ///
    /// An automatically discovered project `.dcg.toml` is not a trusted
    /// precedence layer. Its monotonic enforcement-only subset is applied
    /// after user/system files; settings that could weaken or redirect policy
    /// are discarded. Set `DCG_CONFIG=.dcg.toml` to make a project file an
    /// explicit, fully trusted config source for that invocation.
    #[must_use]
    pub fn load() -> Self {
        // Hook mode is latency-sensitive. The shared loader keeps tracing
        // disabled here so ordinary evaluations do not allocate diagnostic
        // vectors/paths/details that only `config` and `doctor` consume.
        Self::load_internal(false).0
    }

    /// Load the effective configuration and retain an auditable account of
    /// every file source the loader considered.
    ///
    /// Diagnostics must consume this report rather than re-deriving source
    /// state with `Path::exists()`: a path can exist yet be rejected by the
    /// Unix trust policy, intentionally ignored on a non-Unix platform, or
    /// skipped because a valid `DCG_CONFIG` replaces the default user file.
    #[must_use]
    pub(crate) fn load_with_report() -> ConfigLoadReport {
        let (config, sources) = Self::load_internal(true);
        ConfigLoadReport {
            config,
            sources: sources.expect("source tracing requested"),
        }
    }

    fn load_internal(capture_sources: bool) -> (Self, Option<Vec<ConfigSourceOutcome>>) {
        // Start with truly empty defaults - packs must be explicitly enabled.
        // generate_default() is for sample configs shown to users, not runtime defaults.
        let mut config = Self::default();
        let mut sources = capture_sources.then(Vec::new);
        let cwd = env::current_dir().ok();

        // Optional explicit config path override (highest-priority file config).
        // It is parsed first only so a valid explicit file can suppress the
        // default user path; its outcome is appended last to preserve the
        // actual low-to-high precedence order exposed to diagnostics.
        let (explicit_layer, explicit_outcome) = match env::var(ENV_CONFIG_PATH) {
            Ok(value) => match resolve_config_path_value(&value, cwd.as_deref()) {
                Some(path) => {
                    let (layer, outcome) = Self::load_layer_from_file_with_outcome(
                        &path,
                        ConfigSource::Untrusted,
                        ConfigFileLayer::Explicit,
                        ConfigFileAuthority::Full,
                        capture_sources,
                    );
                    (layer, outcome)
                }
                None => (
                    None,
                    capture_sources.then(|| {
                        ConfigSourceOutcome::new(
                            ConfigFileLayer::Explicit,
                            ConfigFileAuthority::Full,
                            ConfigFileStatus::Rejected,
                            None,
                            Some("DCG_CONFIG is set but empty".to_string()),
                        )
                    }),
                ),
            },
            Err(_) => (None, None),
        };
        let explicit_project_policy = explicit_layer.is_some()
            && cwd.as_deref().is_some_and(explicitly_trusts_project_policy);

        // Load system config (lowest priority of file configs)
        let system_path = system_config_dir().join(CONFIG_FILE_NAME);
        let (system_config, system_outcome) = Self::load_layer_from_file_with_outcome(
            &system_path,
            ConfigSource::System,
            ConfigFileLayer::System,
            ConfigFileAuthority::Full,
            capture_sources,
        );
        record_config_outcome(&mut sources, system_outcome);
        if let Some(system_config) = system_config {
            config.merge_layer(system_config);
        }

        // Load user config
        //
        // If an explicit config file is present and valid, we treat it as the
        // user-level config and skip loading the default user config path to
        // reduce layering confusion.
        if explicit_layer.is_some() {
            if let Some(sources) = sources.as_mut() {
                let user_path = Self::user_config_candidates()
                    .into_iter()
                    .find(|path| fs::symlink_metadata(path).is_ok());
                sources.push(ConfigSourceOutcome::new(
                    ConfigFileLayer::User,
                    ConfigFileAuthority::Full,
                    ConfigFileStatus::Skipped,
                    user_path,
                    Some("a valid DCG_CONFIG replaces the default user config".to_string()),
                ));
            }
        } else {
            let user_config = Self::load_user_config_layer_with_outcomes(&mut sources);
            if let Some(user_config) = user_config {
                config.merge_layer(user_config);
            }
        }

        let project_path = cwd
            .as_deref()
            .and_then(|start_dir| find_repo_root(start_dir, REPO_ROOT_SEARCH_MAX_HOPS))
            .map(|repo_root| repo_root.join(PROJECT_CONFIG_NAME));
        if explicit_project_policy {
            if let Some(sources) = sources.as_mut() {
                sources.push(ConfigSourceOutcome::new(
                    ConfigFileLayer::AutomaticProject,
                    ConfigFileAuthority::EnforcementOnly,
                    ConfigFileStatus::Skipped,
                    project_path,
                    Some(
                        "the same repository config was selected explicitly; duplicate automatic merge suppressed"
                            .to_string(),
                    ),
                ));
            }
        } else if let Some(project_path) = project_path {
            let (project_layer, project_outcome) = Self::load_layer_from_file_with_outcome(
                &project_path,
                ConfigSource::AutoProject,
                ConfigFileLayer::AutomaticProject,
                ConfigFileAuthority::EnforcementOnly,
                capture_sources,
            );
            record_config_outcome(&mut sources, project_outcome);
            if let Some(project_layer) = project_layer {
                config.merge_layer(project_layer.into_restricted_project_policy());
            }
        } else if let Some(sources) = sources.as_mut() {
            sources.push(ConfigSourceOutcome::new(
                ConfigFileLayer::AutomaticProject,
                ConfigFileAuthority::EnforcementOnly,
                ConfigFileStatus::Missing,
                None,
                Some("current directory is not inside a Git repository".to_string()),
            ));
        }

        // Explicit config is the highest-priority file layer.
        if let Some(explicit_layer) = explicit_layer {
            config.merge_layer(explicit_layer);
        }
        record_config_outcome(&mut sources, explicit_outcome);

        // Apply environment variable overrides (highest priority)
        config.apply_env_overrides();
        if config.history.normalize_runtime_invariants() {
            eprintln!(
                "Warning: invalid history limits were clamped to safe runtime values \
                 (retention_days=1..={}, max_size_mb>=1, prune_check_interval_hours>=1, \
                 batch_size>=1, batch_flush_interval_ms>=1)",
                HistoryConfig::MAX_RETENTION_DAYS
            );
        }

        // Publish the rule-scoped target exemptions (#284) so the pack matchers
        // can consult them without a `&Config` parameter. The automatic project
        // layer was already reduced above, so nothing here is repo-authored.
        publish_rule_target_exemptions(&config);

        (config, sources)
    }

    /// Merge the automatic repository hardening subset and the explicit file.
    ///
    /// The project loader is lazy so selecting the repository's own
    /// `.dcg.toml` explicitly neither reparses nor reapplies the same file.
    /// This matters for additive fields such as `packs.enabled`.
    #[cfg(test)]
    fn merge_project_and_explicit_layers<F>(
        &mut self,
        explicit_layer: Option<ConfigLayer>,
        explicit_project_policy: bool,
        project_layer: F,
    ) where
        F: FnOnce() -> Option<ConfigLayer>,
    {
        if !explicit_project_policy {
            if let Some(project_layer) = project_layer() {
                self.merge_layer(project_layer);
            }
        }

        // Explicit config is the highest-priority file layer.
        if let Some(explicit_layer) = explicit_layer {
            self.merge_layer(explicit_layer);
        }
    }

    #[cfg(all(test, unix))]
    fn load_layer_from_file_with_source(path: &Path, source: ConfigSource) -> Option<ConfigLayer> {
        Self::load_layer_from_file_with_outcome(
            path,
            source,
            match source {
                ConfigSource::AutoProject => ConfigFileLayer::AutomaticProject,
                ConfigSource::System => ConfigFileLayer::System,
                ConfigSource::Untrusted => ConfigFileLayer::Explicit,
            },
            if source == ConfigSource::AutoProject {
                ConfigFileAuthority::EnforcementOnly
            } else {
                ConfigFileAuthority::Full
            },
            false,
        )
        .0
    }

    fn load_layer_from_file_with_outcome(
        path: &Path,
        source: ConfigSource,
        layer: ConfigFileLayer,
        authority: ConfigFileAuthority,
        capture_outcome: bool,
    ) -> (Option<ConfigLayer>, Option<ConfigSourceOutcome>) {
        let Some(content) = read_config_file_bounded(path, source) else {
            let outcome = capture_outcome.then(|| {
                let (status, detail) = failed_config_read_outcome(path, source);
                ConfigSourceOutcome::new(layer, authority, status, Some(path.to_path_buf()), detail)
            });
            return (None, outcome);
        };

        match toml::from_str(&content) {
            Ok(parsed) => (
                Some(parsed),
                capture_outcome.then(|| {
                    ConfigSourceOutcome::new(
                        layer,
                        authority,
                        ConfigFileStatus::Loaded,
                        Some(path.to_path_buf()),
                        None,
                    )
                }),
            ),
            Err(e) if source == ConfigSource::AutoProject => {
                let detail = safe_auto_project_toml_error(&content, &e);
                eprintln!("Warning: {}; ignoring it", detail);
                (
                    None,
                    capture_outcome.then(|| {
                        ConfigSourceOutcome::new(
                            layer,
                            authority,
                            ConfigFileStatus::Invalid,
                            Some(path.to_path_buf()),
                            Some(detail),
                        )
                    }),
                )
            }
            Err(e) => {
                eprintln!(
                    "Warning: Failed to parse config file '{}': {}",
                    path.display(),
                    e
                );
                (
                    None,
                    capture_outcome.then(|| {
                        ConfigSourceOutcome::new(
                            layer,
                            authority,
                            ConfigFileStatus::Invalid,
                            Some(path.to_path_buf()),
                            Some(format!("Invalid TOML: {e}")),
                        )
                    }),
                )
            }
        }
    }

    /// Load configuration from a specific file.
    #[must_use]
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let content = read_config_file_bounded(path, ConfigSource::Untrusted)?;
        let mut config: Self = toml::from_str(&content).ok()?;
        if config.history.normalize_runtime_invariants() {
            eprintln!(
                "Warning: invalid history limits in '{}' were clamped to safe runtime values",
                path.display()
            );
        }
        Some(config)
    }

    fn user_config_candidates() -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        let mut push_unique = |path: PathBuf| {
            if !candidates.contains(&path) {
                candidates.push(path);
            }
        };

        if let Ok(xdg_home) = env::var("XDG_CONFIG_HOME") {
            if let Some(xdg_home) = resolve_config_path_value(&xdg_home, None) {
                push_unique(xdg_home.join("dcg").join(CONFIG_FILE_NAME));
            }
        }

        if let Some(home) = dirs::home_dir() {
            push_unique(home.join(".config").join("dcg").join(CONFIG_FILE_NAME));
        }

        if let Some(config_dir) = dirs::config_dir() {
            push_unique(config_dir.join("dcg").join(CONFIG_FILE_NAME));
        }

        candidates
    }

    /// Load the first valid user configuration candidate and record every
    /// candidate actually attempted before it.
    fn load_user_config_layer_with_outcomes(
        sources: &mut Option<Vec<ConfigSourceOutcome>>,
    ) -> Option<ConfigLayer> {
        let candidates = Self::user_config_candidates();
        if candidates.is_empty() {
            if let Some(sources) = sources.as_mut() {
                sources.push(ConfigSourceOutcome::new(
                    ConfigFileLayer::User,
                    ConfigFileAuthority::Full,
                    ConfigFileStatus::Missing,
                    None,
                    Some("no user configuration directory is available".to_string()),
                ));
            }
            return None;
        }

        for path in candidates {
            let capture_outcome = sources.is_some();
            let (layer, outcome) = Self::load_layer_from_file_with_outcome(
                &path,
                ConfigSource::Untrusted,
                ConfigFileLayer::User,
                ConfigFileAuthority::Full,
                capture_outcome,
            );
            record_config_outcome(sources, outcome);
            if layer.is_some() {
                return layer;
            }
        }

        None
    }

    /// Load the enforcement-only subset of project-level configuration
    /// (`.dcg.toml` in repo root).
    #[cfg(all(test, unix))]
    fn load_project_config_layer_from(start_dir: Option<&Path>) -> Option<ConfigLayer> {
        let start_dir = start_dir?;
        let repo_root = find_repo_root(start_dir, REPO_ROOT_SEARCH_MAX_HOPS)?;
        let config_path = repo_root.join(PROJECT_CONFIG_NAME);
        Self::load_layer_from_file_with_source(&config_path, ConfigSource::AutoProject)
            .map(ConfigLayer::into_restricted_project_policy)
    }

    /// Merge another config layer into this one (other takes priority when set).
    fn merge_layer(&mut self, other: ConfigLayer) {
        if let Some(general) = other.general {
            self.merge_general_layer(general);
        }

        if let Some(output) = other.output {
            self.merge_output_layer(output);
        }

        if let Some(theme) = other.theme {
            self.merge_theme_layer(theme);
        }

        if let Some(packs) = other.packs {
            self.merge_packs_layer(packs);
        }

        if let Some(policy) = other.policy {
            self.merge_policy_layer(policy);
        }

        if let Some(overrides) = other.overrides {
            self.merge_overrides_layer(overrides);
        }

        if let Some(allowlist) = other.allowlist {
            self.merge_allowlist_layer(allowlist);
        }

        if let Some(heredoc) = other.heredoc {
            self.merge_heredoc_layer(heredoc);
        }

        if let Some(confidence) = other.confidence {
            self.merge_confidence_layer(confidence);
        }

        if let Some(logging) = other.logging {
            self.merge_logging_layer(logging);
        }

        if let Some(history) = other.history {
            self.merge_history_layer(history);
        }

        if let Some(interactive) = other.interactive {
            self.merge_interactive_layer(interactive);
        }

        if let Some(git_awareness) = other.git_awareness {
            self.merge_git_awareness_layer(git_awareness);
        }

        if let Some(agents) = other.agents {
            self.merge_agents_layer(agents);
        }

        if let Some(response) = other.response {
            self.merge_response_layer(response);
        }

        // Merge project configs
        if let Some(projects) = other.projects {
            self.projects.extend(projects);
        }

        // Per-rule settings merge by rule id; a higher layer replaces the whole
        // table for a rule it names (#284).
        if let Some(rules) = other.rules {
            self.rules.extend(rules);
        }
    }

    fn merge_general_layer(&mut self, general: GeneralConfigLayer) {
        if let Some(color) = general.color {
            self.general.color = color;
        }
        if let Some(log_file) = general.log_file {
            self.general.log_file = Some(log_file);
        }
        if let Some(verbose) = general.verbose {
            self.general.verbose = verbose;
        }
        if let Some(hook_timeout_ms) = general.hook_timeout_ms {
            self.general.hook_timeout_ms = Some(hook_timeout_ms);
        }
        if let Some(max_hook_input_bytes) = general.max_hook_input_bytes {
            self.general.max_hook_input_bytes = Some(max_hook_input_bytes);
        }
        if let Some(max_command_bytes) = general.max_command_bytes {
            self.general.max_command_bytes = Some(max_command_bytes);
        }
        if let Some(max_findings_per_command) = general.max_findings_per_command {
            self.general.max_findings_per_command = Some(max_findings_per_command);
        }
        if let Some(check_updates) = general.check_updates {
            self.general.check_updates = check_updates;
        }
        if let Some(self_heal_hook) = general.self_heal_hook {
            self.general.self_heal_hook = self_heal_hook;
        }
        if let Some(fail_closed) = general.fail_closed {
            self.general.fail_closed = fail_closed;
        }
        if let Some(update_pin) = general.update_pin {
            self.general.update_pin = update_pin;
        }
    }

    const fn merge_output_layer(&mut self, output: OutputConfigLayer) {
        if let Some(highlight_enabled) = output.highlight_enabled {
            self.output.highlight_enabled = Some(highlight_enabled);
        }
        if let Some(explanations_enabled) = output.explanations_enabled {
            self.output.explanations_enabled = Some(explanations_enabled);
        }
        if let Some(high_contrast) = output.high_contrast {
            self.output.high_contrast = Some(high_contrast);
        }
    }

    fn merge_theme_layer(&mut self, theme: ThemeConfigLayer) {
        if let Some(palette) = theme.palette {
            self.theme.palette = Some(palette);
        }
        if let Some(use_unicode) = theme.use_unicode {
            self.theme.use_unicode = Some(use_unicode);
        }
        if let Some(use_color) = theme.use_color {
            self.theme.use_color = Some(use_color);
        }
    }

    fn merge_packs_layer(&mut self, packs: PacksConfig) {
        self.packs.enabled.extend(packs.enabled);
        self.packs.disabled.extend(packs.disabled);
        self.packs.custom_paths.extend(packs.custom_paths);
    }

    fn merge_policy_layer(&mut self, policy: PolicyConfig) {
        if policy.default_mode.is_some() {
            self.policy.default_mode = policy.default_mode;
        }
        if policy.observe_until.is_some() {
            self.policy.observe_until = policy.observe_until;
        }
        self.policy.packs.extend(policy.packs);
        self.policy.rules.extend(policy.rules);
    }

    fn merge_overrides_layer(&mut self, overrides: OverridesConfig) {
        self.overrides.allow.extend(overrides.allow);
        self.overrides.block.extend(overrides.block);
        // #327: carry the removed-key sentinels forward so `dcg config` and
        // `dcg doctor` can warn that the key is not enforced. Without this the
        // merge silently dropped the keys — exactly the failure being fixed.
        if overrides.allowlist.is_some() {
            self.overrides.allowlist = overrides.allowlist;
        }
        if overrides.allowlist_rules.is_some() {
            self.overrides.allowlist_rules = overrides.allowlist_rules;
        }
    }

    const fn merge_allowlist_layer(&mut self, allowlist: AllowlistConfigLayer) {
        if let Some(auto_prune_expired) = allowlist.auto_prune_expired {
            self.allowlist.auto_prune_expired = auto_prune_expired;
        }
    }

    fn merge_heredoc_layer(&mut self, heredoc: HeredocConfig) {
        if heredoc.enabled.is_some() {
            self.heredoc.enabled = heredoc.enabled;
        }
        if heredoc.timeout_ms.is_some() {
            self.heredoc.timeout_ms = heredoc.timeout_ms;
        }
        if heredoc.max_body_bytes.is_some() {
            self.heredoc.max_body_bytes = heredoc.max_body_bytes;
        }
        if heredoc.max_body_lines.is_some() {
            self.heredoc.max_body_lines = heredoc.max_body_lines;
        }
        if heredoc.max_heredocs.is_some() {
            self.heredoc.max_heredocs = heredoc.max_heredocs;
        }
        if heredoc.languages.is_some() {
            self.heredoc.languages = heredoc.languages;
        }
        if heredoc.fallback_on_parse_error.is_some() {
            self.heredoc.fallback_on_parse_error = heredoc.fallback_on_parse_error;
        }
        if heredoc.fallback_on_timeout.is_some() {
            self.heredoc.fallback_on_timeout = heredoc.fallback_on_timeout;
        }

        // Merge heredoc allowlist (additive).
        if let Some(other_allowlist) = heredoc.allowlist {
            if let Some(existing) = self.heredoc.allowlist.as_mut() {
                existing.merge(&other_allowlist);
            } else {
                self.heredoc.allowlist = Some(other_allowlist);
            }
        }
    }

    #[allow(clippy::missing_const_for_fn)] // Uses `if let` which isn't const-compatible
    fn merge_confidence_layer(&mut self, confidence: ConfidenceConfigLayer) {
        if let Some(enabled) = confidence.enabled {
            self.confidence.enabled = enabled;
        }
        if let Some(warn_threshold) = confidence.warn_threshold {
            self.confidence.warn_threshold = warn_threshold;
        }
        if let Some(protect_critical) = confidence.protect_critical {
            self.confidence.protect_critical = protect_critical;
        }
    }

    fn merge_logging_layer(&mut self, logging: LoggingConfigLayer) {
        if let Some(enabled) = logging.enabled {
            self.logging.enabled = enabled;
        }
        if let Some(file) = logging.file {
            self.logging.file = Some(file);
        }
        if let Some(format) = logging.format {
            self.logging.format = format;
        }
        if let Some(redaction) = logging.redaction {
            if let Some(enabled) = redaction.enabled {
                self.logging.redaction.enabled = enabled;
            }
            if let Some(mode) = redaction.mode {
                self.logging.redaction.mode = mode;
            }
            if let Some(max_argument_len) = redaction.max_argument_len {
                self.logging.redaction.max_argument_len = max_argument_len;
            }
        }
        if let Some(events) = logging.events {
            if let Some(deny) = events.deny {
                self.logging.events.deny = deny;
            }
            if let Some(warn) = events.warn {
                self.logging.events.warn = warn;
            }
            if let Some(allow) = events.allow {
                self.logging.events.allow = allow;
            }
        }
    }

    fn merge_history_layer(&mut self, history: HistoryConfigLayer) {
        if let Some(enabled) = history.enabled {
            self.history.enabled = enabled;
        }
        if let Some(redaction_mode) = history.redaction_mode {
            self.history.redaction_mode = redaction_mode;
        }
        if let Some(retention_days) = history.retention_days {
            self.history.retention_days = retention_days;
        }
        if let Some(max_size_mb) = history.max_size_mb {
            self.history.max_size_mb = max_size_mb;
        }
        if let Some(database_path) = history.database_path {
            self.history.database_path = Some(database_path);
        }
        if let Some(auto_prune) = history.auto_prune {
            self.history.auto_prune = auto_prune;
        }
        if let Some(prune_check_interval_hours) = history.prune_check_interval_hours {
            self.history.prune_check_interval_hours = prune_check_interval_hours;
        }
        if let Some(batch_size) = history.batch_size {
            self.history.batch_size = batch_size;
        }
        if let Some(batch_flush_interval_ms) = history.batch_flush_interval_ms {
            self.history.batch_flush_interval_ms = batch_flush_interval_ms;
        }
    }

    fn merge_interactive_layer(&mut self, interactive: InteractiveConfigLayer) {
        if let Some(enabled) = interactive.enabled {
            self.interactive.enabled = enabled;
        }
        if let Some(verification) = interactive.verification {
            self.interactive.verification = verification;
        }
        if let Some(timeout_seconds) = interactive.timeout_seconds {
            self.interactive.timeout_seconds = timeout_seconds;
        }
        if let Some(code_length) = interactive.code_length {
            self.interactive.code_length = code_length;
        }
        if let Some(max_attempts) = interactive.max_attempts {
            self.interactive.max_attempts = max_attempts;
        }
        if let Some(allow_non_tty_fallback) = interactive.allow_non_tty_fallback {
            self.interactive.allow_non_tty_fallback = allow_non_tty_fallback;
        }
        if let Some(disable_in_ci) = interactive.disable_in_ci {
            self.interactive.disable_in_ci = disable_in_ci;
        }
        if let Some(require_env) = interactive.require_env {
            self.interactive.require_env = Some(require_env);
        }
    }

    fn merge_git_awareness_layer(&mut self, git_awareness: GitAwarenessConfigLayer) {
        if let Some(enabled) = git_awareness.enabled {
            self.git_awareness.enabled = enabled;
        }
        if let Some(protected_branches) = git_awareness.protected_branches {
            self.git_awareness.protected_branches = protected_branches;
        }
        if let Some(protected_strictness) = git_awareness.protected_strictness {
            self.git_awareness.protected_strictness = protected_strictness;
        }
        if let Some(relaxed_branches) = git_awareness.relaxed_branches {
            self.git_awareness.relaxed_branches = relaxed_branches;
        }
        if let Some(relaxed_strictness) = git_awareness.relaxed_strictness {
            self.git_awareness.relaxed_strictness = relaxed_strictness;
        }
        if let Some(default_strictness) = git_awareness.default_strictness {
            self.git_awareness.default_strictness = default_strictness;
        }
        if let Some(detached_head_strictness) = git_awareness.detached_head_strictness {
            self.git_awareness.detached_head_strictness = detached_head_strictness;
        }
        if let Some(relaxed_disabled_packs) = git_awareness.relaxed_disabled_packs {
            self.git_awareness.relaxed_disabled_packs = relaxed_disabled_packs;
        }
        if let Some(show_branch_in_output) = git_awareness.show_branch_in_output {
            self.git_awareness.show_branch_in_output = show_branch_in_output;
        }
        if let Some(warn_if_not_git) = git_awareness.warn_if_not_git {
            self.git_awareness.warn_if_not_git = warn_if_not_git;
        }
    }

    fn merge_agents_layer(&mut self, agents: AgentsConfig) {
        // Merge default profile
        self.agents.default = agents.default;
        // Merge agent-specific profiles
        self.agents.profiles.extend(agents.profiles);
    }

    fn merge_response_layer(&mut self, response: ResponseConfigLayer) {
        if let Some(enabled) = response.enabled {
            self.response.enabled = enabled;
        }
        if let Some(mode) = response.mode {
            self.response.mode = mode;
        }
        if let Some(session_warning_count) = response.session_warning_count {
            self.response.session_warning_count = session_warning_count;
        }
        if let Some(session_soft_block) = response.session_soft_block {
            self.response.session_soft_block = session_soft_block;
        }
        if let Some(history_soft_block) = response.history_soft_block {
            self.response.history_soft_block = history_soft_block;
        }
        if let Some(history_hard_block) = response.history_hard_block {
            self.response.history_hard_block = history_hard_block;
        }
        if let Some(history_window) = response.history_window {
            self.response.history_window = history_window;
        }
        if let Some(severity_overrides) = response.severity_overrides {
            self.response.severity_overrides = severity_overrides;
        }
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(&mut self) {
        self.apply_env_overrides_from(|key| env::var(key).ok());
    }

    fn apply_env_overrides_from<F>(&mut self, mut get_env: F)
    where
        F: FnMut(&str) -> Option<String>,
    {
        // DCG_PACKS="core,database.postgresql,kubernetes"
        if let Some(packs) = get_env(&format!("{ENV_PREFIX}_PACKS")) {
            self.packs.enabled = packs.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_DISABLE="kubernetes.helm"
        if let Some(disable) = get_env(&format!("{ENV_PREFIX}_DISABLE")) {
            self.packs.disabled = disable.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_CUSTOM_PATHS="/path/to/pack.yaml,~/.config/dcg/packs/*.yaml"
        if let Some(paths) = get_env(&format!("{ENV_PREFIX}_CUSTOM_PATHS")) {
            self.packs.custom_paths = paths.split(',').map(|s| s.trim().to_string()).collect();
        }

        // DCG_VERBOSE=0-3
        if let Some(verbose) = get_env(&format!("{ENV_PREFIX}_VERBOSE")) {
            if let Ok(level) = verbose.trim().parse::<u8>() {
                self.general.verbose = level > 0;
            } else if let Some(parsed) = parse_env_bool(&verbose) {
                self.general.verbose = parsed;
            } else {
                self.general.verbose = true;
            }
        }

        // DCG_CHECK_UPDATES=true|false|1|0
        if let Some(check_updates) = get_env(&format!("{ENV_PREFIX}_CHECK_UPDATES")) {
            if let Some(parsed) = parse_env_bool(&check_updates) {
                self.general.check_updates = parsed;
            }
        }

        // DCG_NO_UPDATE_CHECK=1 (override)
        if let Some(disable) = get_env("DCG_NO_UPDATE_CHECK") {
            if env_disable_flag_enabled(&disable) {
                self.general.check_updates = false;
            }
        }

        // DCG_UPDATE_PIN=true|false|1|0 (#320)
        if let Some(update_pin) = get_env(&format!("{ENV_PREFIX}_UPDATE_PIN")) {
            if let Some(parsed) = parse_env_bool(&update_pin) {
                self.general.update_pin = parsed;
            }
        }

        // DCG_SELF_HEAL_HOOK=true|false|1|0
        if let Some(self_heal) = get_env(&format!("{ENV_PREFIX}_SELF_HEAL_HOOK")) {
            if let Some(parsed) = parse_env_bool(&self_heal) {
                self.general.self_heal_hook = parsed;
            }
        }

        // DCG_NO_SELF_HEAL=1 (override)
        if let Some(disable) = get_env("DCG_NO_SELF_HEAL") {
            if env_disable_flag_enabled(&disable) {
                self.general.self_heal_hook = false;
            }
        }

        // DCG_HOOK_TIMEOUT_MS=200
        if let Some(timeout_ms) = get_env(&format!("{ENV_PREFIX}_HOOK_TIMEOUT_MS")) {
            if let Ok(parsed) = timeout_ms.trim().parse::<u64>() {
                self.general.hook_timeout_ms = Some(parsed);
            }
        }

        // DCG_COLOR=never
        if let Some(color) = get_env(&format!("{ENV_PREFIX}_COLOR")) {
            self.general.color = color;
        }

        // DCG_HIGH_CONTRAST=1
        if let Some(high_contrast) = get_env("DCG_HIGH_CONTRAST") {
            let parsed = parse_env_bool(&high_contrast).unwrap_or(true);
            self.output.high_contrast = Some(parsed);
        }

        // -----------------------------------------------------------------
        // Heredoc scanning (env overrides)
        // -----------------------------------------------------------------

        // DCG_HEREDOC_ENABLED=true|false|1|0
        if let Some(enabled) = get_env(&format!("{ENV_PREFIX}_HEREDOC_ENABLED")) {
            if let Some(parsed) = parse_env_bool(&enabled) {
                self.heredoc.enabled = Some(parsed);
            }
        }

        // DCG_HEREDOC_TIMEOUT=50 (ms)
        let timeout_var = format!("{ENV_PREFIX}_HEREDOC_TIMEOUT");
        let timeout_ms_var = format!("{ENV_PREFIX}_HEREDOC_TIMEOUT_MS");
        if let Some(timeout_ms) = get_env(&timeout_ms_var).or_else(|| get_env(&timeout_var)) {
            if let Ok(parsed) = timeout_ms.trim().parse::<u64>() {
                self.heredoc.timeout_ms = Some(parsed);
            }
        }

        // DCG_HEREDOC_LANGUAGES=python,bash,javascript
        if let Some(langs) = get_env(&format!("{ENV_PREFIX}_HEREDOC_LANGUAGES")) {
            let parsed: Vec<String> = langs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                self.heredoc.languages = Some(parsed);
            }
        }

        // -----------------------------------------------------------------
        // Policy config (env overrides)
        // -----------------------------------------------------------------

        // DCG_POLICY_DEFAULT_MODE=deny|ask|warn|log
        if let Some(mode) = get_env(&format!("{ENV_PREFIX}_POLICY_DEFAULT_MODE")) {
            if let Some(parsed) = parse_policy_mode(&mode) {
                self.policy.default_mode = Some(parsed);
            }
        }

        // DCG_POLICY_OBSERVE_UNTIL=2030-01-01T00:00:00Z
        if let Some(observe_until) = get_env(&format!("{ENV_PREFIX}_POLICY_OBSERVE_UNTIL")) {
            self.policy.observe_until = ObserveUntil::parse(&observe_until);
        }

        // -----------------------------------------------------------------
        // History config (env overrides)
        // -----------------------------------------------------------------

        // DCG_HISTORY_ENABLED=true|false|1|0
        if let Some(enabled) = get_env(&format!("{ENV_PREFIX}_HISTORY_ENABLED")) {
            if let Some(parsed) = parse_env_bool(&enabled) {
                self.history.enabled = parsed;
            }
        }

        // DCG_HISTORY_REDACTION_MODE=none|pattern|full
        if let Some(mode) = get_env(&format!("{ENV_PREFIX}_HISTORY_REDACTION_MODE")) {
            if let Ok(parsed) = HistoryRedactionMode::from_str(&mode) {
                self.history.redaction_mode = parsed;
            }
        }

        // -----------------------------------------------------------------
        // Interactive config (env overrides)
        // -----------------------------------------------------------------

        // DCG_INTERACTIVE_ENABLED=true|false|1|0
        if let Some(enabled) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_ENABLED")) {
            if let Some(parsed) = parse_env_bool(&enabled) {
                self.interactive.enabled = parsed;
            }
        }

        // DCG_INTERACTIVE_VERIFICATION=code|command|none
        if let Some(verification) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_VERIFICATION")) {
            if let Some(parsed) = parse_interactive_verification_method(&verification) {
                self.interactive.verification = parsed;
            }
        }

        // DCG_INTERACTIVE_TIMEOUT_SECONDS=5
        if let Some(timeout_seconds) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_TIMEOUT_SECONDS"))
        {
            if let Ok(parsed) = timeout_seconds.trim().parse::<u64>() {
                self.interactive.timeout_seconds = parsed;
            }
        }

        // DCG_INTERACTIVE_CODE_LENGTH=4
        if let Some(code_length) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_CODE_LENGTH")) {
            if let Ok(parsed) = code_length.trim().parse::<usize>() {
                self.interactive.code_length = parsed;
            }
        }

        // DCG_INTERACTIVE_MAX_ATTEMPTS=3
        if let Some(max_attempts) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_MAX_ATTEMPTS")) {
            if let Ok(parsed) = max_attempts.trim().parse::<u32>() {
                self.interactive.max_attempts = parsed;
            }
        }

        // DCG_INTERACTIVE_ALLOW_NON_TTY_FALLBACK=true|false|1|0
        if let Some(fallback) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_ALLOW_NON_TTY_FALLBACK"))
        {
            if let Some(parsed) = parse_env_bool(&fallback) {
                self.interactive.allow_non_tty_fallback = parsed;
            }
        }

        // DCG_INTERACTIVE_DISABLE_IN_CI=true|false|1|0
        if let Some(disable_in_ci) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_DISABLE_IN_CI")) {
            if let Some(parsed) = parse_env_bool(&disable_in_ci) {
                self.interactive.disable_in_ci = parsed;
            }
        }

        // DCG_INTERACTIVE_REQUIRE_ENV=DCG_INTERACTIVE
        if let Some(require_env) = get_env(&format!("{ENV_PREFIX}_INTERACTIVE_REQUIRE_ENV")) {
            let trimmed = require_env.trim();
            self.interactive.require_env = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }

        // -----------------------------------------------------------------
        // Git awareness config (env overrides)
        // -----------------------------------------------------------------

        // DCG_GIT_AWARENESS_ENABLED=true|false|1|0
        if let Some(enabled) = get_env(&format!("{ENV_PREFIX}_GIT_AWARENESS_ENABLED")) {
            if let Some(parsed) = parse_env_bool(&enabled) {
                self.git_awareness.enabled = parsed;
            }
        }

        // DCG_GIT_PROTECTED_BRANCHES=main,production,release/*
        if let Some(branches) = get_env(&format!("{ENV_PREFIX}_GIT_PROTECTED_BRANCHES")) {
            let parsed: Vec<String> = branches
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                self.git_awareness.protected_branches = parsed;
            }
        }

        // DCG_GIT_PROTECTED_STRICTNESS=critical|high|medium|all
        if let Some(strictness) = get_env(&format!("{ENV_PREFIX}_GIT_PROTECTED_STRICTNESS")) {
            if let Some(parsed) = StrictnessLevel::from_str_case_insensitive(&strictness) {
                self.git_awareness.protected_strictness = parsed;
            }
        }

        // DCG_GIT_RELAXED_BRANCHES=feature/*,experiment/*
        if let Some(branches) = get_env(&format!("{ENV_PREFIX}_GIT_RELAXED_BRANCHES")) {
            let parsed: Vec<String> = branches
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                self.git_awareness.relaxed_branches = parsed;
            }
        }

        // DCG_GIT_RELAXED_STRICTNESS=critical|high|medium|all
        if let Some(strictness) = get_env(&format!("{ENV_PREFIX}_GIT_RELAXED_STRICTNESS")) {
            if let Some(parsed) = StrictnessLevel::from_str_case_insensitive(&strictness) {
                self.git_awareness.relaxed_strictness = parsed;
            }
        }

        // DCG_GIT_DEFAULT_STRICTNESS=critical|high|medium|all
        if let Some(strictness) = get_env(&format!("{ENV_PREFIX}_GIT_DEFAULT_STRICTNESS")) {
            if let Some(parsed) = StrictnessLevel::from_str_case_insensitive(&strictness) {
                self.git_awareness.default_strictness = parsed;
            }
        }

        // DCG_GIT_DETACHED_HEAD_STRICTNESS=critical|high|medium|all
        if let Some(strictness) = get_env(&format!("{ENV_PREFIX}_GIT_DETACHED_HEAD_STRICTNESS")) {
            if let Some(parsed) = StrictnessLevel::from_str_case_insensitive(&strictness) {
                self.git_awareness.detached_head_strictness = parsed;
            }
        }

        // DCG_GIT_RELAXED_DISABLED_PACKS=containers.docker,cloud.aws
        if let Some(packs) = get_env(&format!("{ENV_PREFIX}_GIT_RELAXED_DISABLED_PACKS")) {
            let parsed: Vec<String> = packs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            self.git_awareness.relaxed_disabled_packs = parsed;
        }

        // DCG_GIT_SHOW_BRANCH_IN_OUTPUT=true|false|1|0
        if let Some(show) = get_env(&format!("{ENV_PREFIX}_GIT_SHOW_BRANCH_IN_OUTPUT")) {
            if let Some(parsed) = parse_env_bool(&show) {
                self.git_awareness.show_branch_in_output = parsed;
            }
        }

        // DCG_GIT_AWARENESS_WARN_IF_NOT_GIT=true|false|1|0
        if let Some(warn) = get_env(&format!("{ENV_PREFIX}_GIT_AWARENESS_WARN_IF_NOT_GIT")) {
            if let Some(parsed) = parse_env_bool(&warn) {
                self.git_awareness.warn_if_not_git = parsed;
            }
        }
    }

    /// Get a reference to the policy config.
    #[must_use]
    pub const fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    /// Check if the bypass flag is set (escape hatch).
    #[must_use]
    pub fn is_bypassed() -> bool {
        env::var(format!("{ENV_PREFIX}_BYPASS"))
            .ok()
            .and_then(|value| parse_env_bool(&value))
            .unwrap_or(false)
    }

    /// Whether dcg should fail CLOSED (block) on hook input it cannot parse.
    ///
    /// The `DCG_FAIL_CLOSED` environment variable overrides the config value:
    /// a truthy value forces fail-closed, a falsy value forces fail-open. When
    /// the env var is unset, the configured `general.fail_closed` is used
    /// (default: `false`, i.e. fail-open). Default behavior is unchanged for
    /// anyone who does not opt in (issue #160).
    #[must_use]
    pub fn is_fail_closed(&self) -> bool {
        if let Some(value) = env::var(format!("{ENV_PREFIX}_FAIL_CLOSED"))
            .ok()
            .and_then(|value| parse_env_bool(&value))
        {
            return value;
        }
        self.general.fail_closed
    }

    /// Get the effective pack configuration for a specific project path.
    #[must_use]
    pub fn effective_packs_for_project(&self, project_path: &Path) -> PacksConfig {
        // Check if there's a project-specific config
        let path_str = project_path.to_string_lossy();

        for (project_pattern, project_config) in &self.projects {
            if path_str.starts_with(project_pattern) {
                if let Some(packs) = &project_config.packs {
                    return packs.clone();
                }
            }
        }

        // Fall back to global config
        self.packs.clone()
    }

    /// Get enabled pack IDs as a deduplicated set.
    #[must_use]
    pub fn enabled_pack_ids(&self) -> HashSet<String> {
        if self.projects.is_empty() {
            return self.packs.enabled_pack_ids();
        }

        if let Ok(cwd) = std::env::current_dir() {
            return self.effective_packs_for_project(&cwd).enabled_pack_ids();
        }

        self.packs.enabled_pack_ids()
    }

    /// Effective end-to-end hook evaluation budget in milliseconds.
    ///
    /// An explicit config or environment value always wins. The broad
    /// `careful_company_running_windows` preset gets a larger default because
    /// its cold-start pack set can exceed the ordinary 1000ms budget on older
    /// Windows workstations.
    #[must_use]
    pub fn effective_hook_timeout_ms(&self) -> u64 {
        self.general.hook_timeout_ms.map_or_else(
            || {
                if self.careful_company_preset_is_requested() {
                    crate::perf::CAREFUL_COMPANY_HOOK_EVALUATION_BUDGET_MS
                } else {
                    crate::perf::HOOK_EVALUATION_BUDGET_MS
                }
            },
            |configured| configured.max(crate::perf::MIN_HOOK_TIMEOUT_MS),
        )
    }

    /// Human-readable provenance for [`Self::effective_hook_timeout_ms`].
    #[must_use]
    pub fn hook_timeout_source(&self) -> &'static str {
        if self.general.hook_timeout_ms.is_some() {
            "configured"
        } else if self.careful_company_preset_is_requested() {
            "careful_company_running_windows preset"
        } else {
            "default"
        }
    }

    fn careful_company_preset_is_requested(&self) -> bool {
        let packs = if self.projects.is_empty() {
            self.packs.clone()
        } else if let Ok(cwd) = std::env::current_dir() {
            self.effective_packs_for_project(&cwd)
        } else {
            self.packs.clone()
        };
        packs
            .enabled
            .iter()
            .any(|pack| pack == "careful_company_running_windows")
            && !packs
                .disabled
                .iter()
                .any(|pack| pack == "careful_company_running_windows")
    }

    /// Get enabled pack IDs adjusted for an agent's profile.
    ///
    /// This applies the agent's `disabled_packs` and `extra_packs` settings
    /// on top of the base configuration.
    #[must_use]
    pub fn enabled_pack_ids_for_agent(&self, agent: &crate::agent::Agent) -> HashSet<String> {
        let profile = self.agents.profile_for_agent(agent);
        let packs_config = if self.projects.is_empty() {
            self.packs.clone()
        } else if let Ok(cwd) = std::env::current_dir() {
            self.effective_packs_for_project(&cwd)
        } else {
            self.packs.clone()
        };

        // A profile can cancel a preset contribution from the base config, but
        // it must not remove member packs that were also enabled independently
        // (including Windows' default-on filesystem/system packs).
        let mut base_requested = packs_config.requested_pack_ids(cfg!(windows));
        PacksConfig::remove_disabled_preset_markers(&mut base_requested, &profile.disabled_packs);
        let mut packs =
            PacksConfig::resolve_requested_pack_ids(base_requested, &packs_config.disabled);

        // Agent extras intentionally override base exclusions. Resolve them as
        // a separate contribution so profile-level preset cancellation still
        // preserves direct/category/default sources from the base.
        let mut extra_requested: HashSet<String> = profile.extra_packs.iter().cloned().collect();
        PacksConfig::remove_disabled_preset_markers(&mut extra_requested, &profile.disabled_packs);
        packs.extend(PacksConfig::expand_known_pack_groups(&extra_requested));

        // Ordinary profile leaf/category exclusions are last-wins. Preset
        // exclusions were already applied to the source markers above.
        PacksConfig::remove_disabled_non_preset_groups(&mut packs, &profile.disabled_packs);

        // Agent profiles may narrow optional packs, but they must not bypass the
        // same invariant as the base configuration: core protections are
        // mandatory. Reinsert the category marker after profile exclusions so
        // `disabled_packs = ["core"]` cannot silently remove core.git and
        // core.filesystem when the registry resolves the final set.
        packs.insert("core".to_string());

        packs
    }

    /// Remove an agent profile's pack exclusions from an already-expanded set.
    ///
    /// [`Self::enabled_pack_ids_for_agent`] applies profile exclusions to the
    /// configured built-in packs. Callers then auto-enable external packs, so
    /// those later contributions need the same final exclusion pass. Core
    /// packs remain mandatory regardless of profile settings.
    pub fn remove_disabled_packs_for_agent(
        &self,
        enabled_packs: &mut HashSet<String>,
        agent: &crate::agent::Agent,
    ) {
        let profile = self.agents.profile_for_agent(agent);
        for disabled in &profile.disabled_packs {
            if disabled == "core" || disabled.starts_with("core.") {
                continue;
            }
            enabled_packs.remove(disabled);
            enabled_packs.retain(|pack| !pack.starts_with(&format!("{disabled}.")));
        }
    }

    /// Apply an agent profile to already-loaded project/user/system allowlists.
    ///
    /// Disabling allowlists is deliberately absolute: it removes both the
    /// loaded layers and the profile's own additional exact commands. When
    /// enabled, agent commands are prepended as the highest-precedence layer.
    #[must_use]
    pub fn apply_agent_allowlist_profile(
        &self,
        agent: &crate::agent::Agent,
        mut allowlists: crate::allowlist::LayeredAllowlist,
    ) -> crate::allowlist::LayeredAllowlist {
        if self.allowlist_disabled_for_agent(agent) {
            return crate::allowlist::LayeredAllowlist::default();
        }

        allowlists.prepend_agent_exact_commands(
            agent.config_key(),
            self.additional_allowlist_for_agent(agent),
        );
        allowlists
    }

    /// Get additional allowlist entries for an agent.
    ///
    /// Returns the patterns from the agent profile's `additional_allowlist`.
    #[must_use]
    pub fn additional_allowlist_for_agent(&self, agent: &crate::agent::Agent) -> &[String] {
        &self.agents.profile_for_agent(agent).additional_allowlist
    }

    /// Check if allowlists are disabled for an agent.
    ///
    /// When `true`, all allowlist checks should be skipped (more restrictive).
    #[must_use]
    pub fn allowlist_disabled_for_agent(&self, agent: &crate::agent::Agent) -> bool {
        self.agents.profile_for_agent(agent).disabled_allowlist
    }

    /// Get the trust level for an agent.
    #[must_use]
    pub fn trust_level_for_agent(&self, agent: &crate::agent::Agent) -> TrustLevel {
        self.agents.profile_for_agent(agent).trust_level
    }

    /// Get effective heredoc scanning settings for evaluation.
    #[must_use]
    pub fn heredoc_settings(&self) -> HeredocSettings {
        self.heredoc.settings()
    }

    /// Get the path to the user config file (creates dir if needed).
    #[must_use]
    pub fn user_config_path() -> Option<PathBuf> {
        let config_dir = if let Ok(xdg_home) = env::var("XDG_CONFIG_HOME") {
            resolve_config_path_value(&xdg_home, None)
        } else {
            None
        };

        let config_dir = if let Some(config_dir) = config_dir {
            config_dir
        } else if let Some(home) = dirs::home_dir() {
            let xdg_dir = home.join(".config").join("dcg");
            if xdg_dir.exists() {
                home.join(".config")
            } else {
                dirs::config_dir().unwrap_or_else(|| home.join(".config"))
            }
        } else {
            dirs::config_dir()?
        };
        let guard_dir = config_dir.join("dcg");

        // Create directory if it doesn't exist
        if !guard_dir.exists() {
            fs::create_dir_all(&guard_dir).ok()?;
        }

        Some(guard_dir.join(CONFIG_FILE_NAME))
    }

    /// Save configuration to the user config file.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory cannot be determined/created,
    /// serialization fails, or the config file cannot be written.
    pub fn save_to_user_config(&self) -> Result<PathBuf, String> {
        let path = Self::user_config_path().ok_or("Could not determine config directory")?;

        let content =
            toml::to_string_pretty(self).map_err(|e| format!("Failed to serialize config: {e}"))?;

        fs::write(&path, content).map_err(|e| format!("Failed to write config: {e}"))?;

        Ok(path)
    }

    /// Generate a default configuration with common packs enabled.
    #[must_use]
    pub fn generate_default() -> Self {
        Self {
            general: GeneralConfig::default(),
            output: OutputConfig::default(),
            theme: ThemeConfig::default(),
            packs: PacksConfig {
                enabled: vec![
                    // Core is implicit, but list common ones
                    "database.postgresql".to_string(),
                    "containers.docker".to_string(),
                ],
                disabled: vec![],
                custom_paths: vec![],
            },
            policy: PolicyConfig::default(),
            overrides: OverridesConfig::default(),
            allowlist: AllowlistConfig::default(),
            heredoc: HeredocConfig::default(),
            confidence: ConfidenceConfig::default(),
            logging: crate::logging::LoggingConfig::default(),
            history: HistoryConfig::default(),
            git_awareness: GitAwarenessConfig::default(),
            agents: AgentsConfig::default(),
            response: ResponseConfig::default(),
            projects: std::collections::HashMap::new(),
            rules: std::collections::HashMap::new(),
            interactive: crate::interactive::InteractiveConfig::default(),
        }
    }

    /// Generate a sample configuration string with comments.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn generate_sample_config() -> String {
        r#"# dcg configuration
# https://github.com/Dicklesworthstone/destructive_command_guard

[general]
# Color output: "auto" | "always" | "never"
color = "auto"

# Log blocked commands to file (optional)
# log_file = "~/.local/share/dcg/blocked.log"

# Verbose output
verbose = false

# Check for updates in the background (shows a notice if available)
# check_updates = true

# Self-heal hook registration in settings.json on every invocation.
# Protects against Claude Code overwriting settings.json mid-session.
# self_heal_hook = true

# Hook evaluation wall-clock budget override (milliseconds).
# Exhaustion is indeterminate: review-capable hooks ask; other hooks block.
# Values below 10ms are clamped to the minimum safe evaluation window.
# hook_timeout_ms = 200

#─────────────────────────────────────────────────────────────
# OUTPUT CONFIGURATION
#─────────────────────────────────────────────────────────────

[output]
# Enable span highlighting in denial output.
# Shows caret-style markers under the matched portion.
# highlight_enabled = true

# Enable explanations in denial output.
# Shows detailed explanations for why patterns are dangerous.
# explanations_enabled = true

# High-contrast mode (ASCII borders + black/white palette).
# high_contrast = false

#─────────────────────────────────────────────────────────────
# THEME CONFIGURATION
#─────────────────────────────────────────────────────────────

[theme]
# Palette: "default" | "colorblind" | "high-contrast"
# palette = "default"

# Whether Unicode box drawing is allowed.
# use_unicode = true

# Whether colors are allowed (false forces monochrome).
# use_color = true

#─────────────────────────────────────────────────────────────
# PACK CONFIGURATION
#─────────────────────────────────────────────────────────────

[packs]
# Enable entire categories or specific sub-packs.
# `core` is always enabled implicitly (cannot be disabled).
# `system.disk` is also enabled by default (catastrophic disk ops);
# opt out with `disabled = ["system.disk"]` if you genuinely need
# `mkfs`/`dd`-to-device unblocked.
#
# Available packs:
#   core                  - Git and filesystem protections (always on)
#   system.disk           - Disk operations: mkfs, dd-to-device, fdisk, parted, mdadm, lvm, wipefs (default-on, opt-out-able)
#   database.postgresql   - PostgreSQL destructive commands
#   database.mysql        - MySQL destructive commands
#   database.mongodb      - MongoDB destructive commands
#   database.redis        - Redis FLUSH commands
#   database.sqlite       - SQLite destructive commands
#   database.snowflake    - Snowflake CLI SQL and account operations
#   database.bigquery     - bq CLI and GoogleSQL: dataset drops, overwrites, time-travel settings
#   containers.docker     - Docker destructive commands
#   containers.compose    - Docker Compose destructive commands
#   containers.podman     - Podman destructive commands
#   kubernetes.kubectl    - kubectl delete commands
#   kubernetes.helm       - Helm uninstall commands
#   kubernetes.kustomize  - Kustomize delete commands
#   cloud.aws             - AWS CLI destructive commands
#   cloud.gcp             - GCP CLI destructive commands
#   cloud.azure           - Azure CLI destructive commands
#   infrastructure.terraform - Terraform destroy commands
#   infrastructure.ansible   - Ansible state=absent patterns
#   infrastructure.pulumi    - Pulumi destroy commands
#   infrastructure.atmos     - Atmos terraform deploy/clean, helmfile destroy
#   system.permissions    - Dangerous permission changes
#   system.services       - Service management commands
#   strict_git            - Extra paranoid git protections
#   package_managers      - npm unpublish, cargo yank, etc.

enabled = [
    "database.postgresql",
    "containers.docker",
    # "kubernetes",         # Uncomment to enable all kubernetes sub-packs
    # "cloud.aws",
]

# Explicitly disable specific sub-packs
disabled = [
    # "kubernetes.kustomize",  # Example: disable kustomize if you don't use it
]

# Load custom packs from YAML files.
# Supports glob patterns, ~ for home directory, and ${repo_root} for the
# nearest ancestor of cwd containing a .git directory. ${repo_root} entries
# are silently skipped when cwd is outside any repo, so a config that
# auto-discovers repo-local packs is safe to deploy via MDM.
# See docs/custom-packs.md for pack authoring guide.
custom_paths = [
    # "~/.config/dcg/packs/*.yaml",         # User packs
    # "${repo_root}/.dcg/packs/*.yaml",     # Repo-local packs (auto-discovered)
    # "/etc/dcg/packs/*.yaml",              # System-wide packs
]

#─────────────────────────────────────────────────────────────
# DECISION MODE POLICY
#─────────────────────────────────────────────────────────────

[policy]
# Optional global override for how matched rules are handled:
# - "deny": block (default)
# - "ask": require native operator review; unsupported clients fail closed
# - "warn": allow but print a warning to stderr (no hook JSON deny)
# - "log": allow silently (no stderr/stdout; optional log_file history)
#
# If unset, dcg uses severity defaults:
# - critical/high => deny
# - medium => warn
# - low => log
#
# default_mode = "deny"
#
# Optional observe-mode window end timestamp.
# When set and before the timestamp, `default_mode` applies (defaulting to "warn" when unset).
# When set and after the timestamp, `default_mode` is ignored and severity defaults apply.
# observe_until = "2026-02-01T00:00:00Z"

[policy.packs]
# Override mode for an entire pack (pack_id => mode).
# Examples:
# "core.git" = "ask"                # require native review for git operations
# "core.git" = "warn"                # warn-first rollout for git pack
# "containers.docker" = "deny"       # keep docker destructive ops as hard blocks

[policy.rules]
# Override mode for a specific rule (rule_id => mode).
# Examples:
# "core.git:push-force-long" = "warn"
# "core.git:reset-hard" = "deny"     # keep critical rules as hard blocks
#
# Safety: Critical rules are only loosened via explicit per-rule overrides.

#─────────────────────────────────────────────────────────────
# INTERACTIVE MODE
#─────────────────────────────────────────────────────────────

[interactive]
# Master switch for terminal prompts. Disabled by default for agent safety.
enabled = false

# Verification method: "code" | "command" | "none".
verification = "code"

# Prompt timeout and code length. Values are clamped at runtime.
timeout_seconds = 5
code_length = 4
max_attempts = 3

# Keep prompts disabled for non-TTY agent traffic and CI by default.
allow_non_tty_fallback = true
disable_in_ci = true

# Optional env var gate; uncomment to require explicit opt-in per shell.
# require_env = "DCG_INTERACTIVE"

#─────────────────────────────────────────────────────────────
# GIT BRANCH AWARENESS
#─────────────────────────────────────────────────────────────

[git_awareness]
# Enable branch-aware strictness.
enabled = false

# Branches that receive extra protection.
protected_branches = ["main", "production", "release/*"]
protected_strictness = "all"

# Branches that can use a lower strictness level.
relaxed_branches = ["feature/*", "experiment/*", "sandbox/*"]
relaxed_strictness = "critical"

# Strictness when no branch pattern matches.
default_strictness = "high"

# Packs to disable only on relaxed branches.
relaxed_disabled_packs = []

# Include branch context in human-facing output.
show_branch_in_output = true

# Warn when git awareness is enabled outside a git repository.
warn_if_not_git = false

#─────────────────────────────────────────────────────────────
# CUSTOM OVERRIDES
#─────────────────────────────────────────────────────────────

[overrides]
# Allow specific patterns that would otherwise be blocked.
# Supports simple strings or conditional objects.
allow = [
    # Example: Allow deleting test namespaces
    # "kubectl delete namespace test-.*",

    # Example: Allow dropping test databases
    # "dropdb test_.*",

    # Example: Conditional - only in CI
    # { pattern = "docker system prune", when = "CI=true" },
]

# Block additional patterns not covered by any pack.
block = [
    # Example: Block a custom dangerous script
    # { pattern = "deploy-to-prod\\.sh.*--force", reason = "Never force-deploy to production" },

    # Example: Block piping curl to shell
    # { pattern = "curl.*\\| ?sh", reason = "Piping curl to shell is dangerous" },
]

#─────────────────────────────────────────────────────────────
# ALLOWLIST FILES
#─────────────────────────────────────────────────────────────

[allowlist]
# Keep expired entries by default so allowlist files preserve audit history.
# Set to true to prune expired entries before allowlist CLI operations.
auto_prune_expired = false

#─────────────────────────────────────────────────────────────
# HEREDOC / INLINE SCRIPT SCANNING
#─────────────────────────────────────────────────────────────

[heredoc]
# Enable scanning for heredocs and inline scripts (python -c, bash -c, etc.).
enabled = true

# Extraction timeout budget (milliseconds). Parsing/matching has its own budget.
timeout_ms = 50

# Resource limits for extracted bodies (Tier 2).
max_body_bytes = 1048576
max_body_lines = 10000
max_heredocs = 10

# Optional language filter (scan only these languages). Omit for "all".
# languages = ["python", "bash", "javascript", "typescript", "ruby", "perl"]

# Bounded fallback for embedded-code parse/extraction failures.
# The fallback still scans for high-risk operations before allowing.
fallback_on_parse_error = true
fallback_on_timeout = true

#─────────────────────────────────────────────────────────────
# HISTORY
#─────────────────────────────────────────────────────────────

[history]
# Enable command history (opt-in).
enabled = false

# Redaction mode for stored commands: "pattern" | "full" | "none"
redaction_mode = "pattern"

# Retention window and database size limits.
retention_days = 90
max_size_mb = 500

# Optional database path override.
# database_path = "~/.config/dcg/history.db"

#─────────────────────────────────────────────────────────────
# GRADUATED RESPONSE SYSTEM
#─────────────────────────────────────────────────────────────

[response]
# Enable the graduated response system.
# When enabled, repeated occurrences of the same command escalate
# from warning → soft block → hard block.
enabled = false

# Global graduation mode: "paranoid" | "strict" | "standard" | "lenient" | "warning_only" | "disabled"
mode = "standard"

# Session thresholds (within current process).
session_warning_count = 1
session_soft_block = 2

# History thresholds (across sessions within history_window).
history_soft_block = 3
history_hard_block = 5
history_window = "24h"

# Per-severity overrides (uncomment to customize).
# [response.severity_overrides]
# critical = "paranoid"
# high = "strict"
# medium = "standard"
# low = "warning_only"

#─────────────────────────────────────────────────────────────
# PROJECT-SPECIFIC OVERRIDES
#─────────────────────────────────────────────────────────────

# Override settings for specific project directories.
# The key is the absolute path to the project.

# [projects."/path/to/database-project"]
# packs.enabled = ["database"]
# packs.disabled = []
# overrides.allow = ["dropdb test_.*"]

# [projects."/path/to/k8s-infra"]
# packs.enabled = ["kubernetes", "cloud.aws", "infrastructure.terraform"]
"#
        .to_string()
    }
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn env_disable_flag_enabled(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "n" | "off"
    )
}

fn parse_policy_mode(value: &str) -> Option<PolicyMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "deny" | "block" => Some(PolicyMode::Deny),
        "ask" | "review" => Some(PolicyMode::Ask),
        "warn" | "warning" => Some(PolicyMode::Warn),
        "log" | "log-only" | "logonly" => Some(PolicyMode::Log),
        _ => None,
    }
}

fn parse_interactive_verification_method(value: &str) -> Option<VerificationMethod> {
    match value.trim().to_ascii_lowercase().as_str() {
        "code" => Some(VerificationMethod::Code),
        "command" => Some(VerificationMethod::Command),
        "none" => Some(VerificationMethod::None),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveUntil {
    raw: String,
    parsed_utc: Option<DateTime<Utc>>,
}

impl ObserveUntil {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(Self {
            raw: trimmed.to_string(),
            parsed_utc: parse_timestamp_as_utc(trimmed),
        })
    }

    #[must_use]
    pub const fn parsed_utc(&self) -> Option<&DateTime<Utc>> {
        self.parsed_utc.as_ref()
    }
}

impl std::ops::Deref for ObserveUntil {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl Serialize for ObserveUntil {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ObserveUntil {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let trimmed = raw.trim();
        Ok(Self {
            raw: trimmed.to_string(),
            parsed_utc: parse_timestamp_as_utc(trimmed),
        })
    }
}

fn parse_timestamp_as_utc(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    // RFC 3339 (e.g., "2030-01-01T00:00:00Z" or "2030-01-01T00:00:00+00:00")
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(dt.with_timezone(&Utc));
    }

    // ISO 8601 without timezone (treat as UTC)
    if let Ok(dt) = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc());
    }

    // Date only (YYYY-MM-DD) - treat as end of day UTC (23:59:59)
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        if let Some(end_of_day) = date.and_hms_opt(23, 59, 59) {
            return Some(end_of_day.and_utc());
        }
        return None;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn system_config_dir_is_platform_correct() {
        let dir = system_config_dir();
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            assert_eq!(dir, PathBuf::from("/etc/dcg"));
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(dir, PathBuf::from("/private/etc/dcg"));
        }
        #[cfg(windows)]
        {
            // `%ProgramData%\dcg` — last component is `dcg`, parent resolves to
            // ProgramData (env or the C:\ProgramData fallback).
            assert!(
                dir.ends_with("dcg"),
                "expected .../dcg, got {}",
                dir.display()
            );
            assert!(dir.parent().is_some());
        }
    }

    // ---------------------------------------------------------------------
    // Branch glob regression tests for `GitAwarenessConfig::matches_any_pattern`
    // ---------------------------------------------------------------------

    #[test]
    fn branch_glob_release_star_matches_only_with_slash_boundary() {
        assert!(GitAwarenessConfig::branch_matches_pattern(
            "release/1.0",
            "release/*"
        ));
        assert!(GitAwarenessConfig::branch_matches_pattern(
            "release/2.0-beta",
            "release/*"
        ));
        // The bug this guards against: `release/*` used to match
        // `release-rogue` because the boundary check was just
        // `branch.len() > prefix.len() + 1` after stripping `/*`.
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "release-rogue",
            "release/*"
        ));
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "releaseX",
            "release/*"
        ));
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "release",
            "release/*"
        ));
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "release/",
            "release/*"
        ));
    }

    #[test]
    fn branch_glob_star_hotfix_matches_only_with_slash_boundary() {
        assert!(GitAwarenessConfig::branch_matches_pattern(
            "team/hotfix",
            "*/hotfix"
        ));
        assert!(GitAwarenessConfig::branch_matches_pattern(
            "release/hotfix",
            "*/hotfix"
        ));
        // Same bug class on the suffix glob side.
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "team-hotfix",
            "*/hotfix"
        ));
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "Xhotfix", "*/hotfix"
        ));
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "hotfix", "*/hotfix"
        ));
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "/hotfix", "*/hotfix"
        ));
    }

    #[test]
    fn branch_glob_exact_and_wildcard() {
        assert!(GitAwarenessConfig::branch_matches_pattern("main", "main"));
        assert!(!GitAwarenessConfig::branch_matches_pattern(
            "mainline", "main"
        ));
        assert!(GitAwarenessConfig::branch_matches_pattern("anything", "*"));
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.color, "auto");
        assert!(config.packs.enabled.is_empty());
        assert!(!config.allowlist.auto_prune_expired);
    }

    #[test]
    fn untrusted_project_policy_retains_only_monotonic_protections() {
        let layer: ConfigLayer = toml::from_str(
            r#"
[general]
fail_closed = true
max_command_bytes = 1
self_heal_hook = false

[output]
explanations_enabled = false

[packs]
enabled = ["database.postgresql", "attacker.external"]
disabled = ["core", "system.disk"]
custom_paths = [".dcg/packs/attacker.yaml"]

[policy]
default_mode = "deny"
observe_until = "2099-01-01"

[policy.packs]
"database.postgresql" = "deny"
"core.git" = "warn"

[policy.rules]
"core.git:reset-hard" = "log"
"database.postgresql:drop-database" = "deny"

[overrides]
allow = ["git reset --hard"]
allowlist = ["rm -rf /"]
block = [
  { pattern = "^echo project-policy-probe$", reason = "project hardening probe" },
]

[heredoc]
enabled = true
timeout_ms = 1
max_body_bytes = 1
languages = ["bash"]
fallback_on_parse_error = false
fallback_on_timeout = true

[agents.default]
disabled_packs = ["core.git"]
extra_packs = ["cloud.aws"]
additional_allowlist = ["git reset --hard"]
disabled_allowlist = false

[response]
enabled = true
mode = "warning_only"
"#,
        )
        .expect("parse project config layer");

        let restricted = layer.into_restricted_project_policy();

        let general = restricted.general.expect("fail-closed retained");
        assert_eq!(general.fail_closed, Some(true));
        assert_eq!(general.max_command_bytes, None);
        assert_eq!(general.self_heal_hook, None);
        assert!(restricted.output.is_none());

        let packs = restricted.packs.expect("pack enable retained");
        assert_eq!(packs.enabled, ["database.postgresql"]);
        assert!(packs.disabled.is_empty());
        assert!(packs.custom_paths.is_empty());

        let policy = restricted.policy.expect("deny policy retained");
        assert_eq!(policy.default_mode, Some(PolicyMode::Deny));
        assert_eq!(
            policy.packs.get("database.postgresql"),
            Some(&PolicyMode::Deny)
        );
        assert!(!policy.packs.contains_key("core.git"));
        assert_eq!(
            policy.rules.get("database.postgresql:drop-database"),
            Some(&PolicyMode::Deny)
        );
        assert!(!policy.rules.contains_key("core.git:reset-hard"));
        assert!(policy.observe_until.is_none());

        // Even block-only overrides are repository-controlled regex programs;
        // automatic discovery drops them to avoid backtracking/compile DoS.
        assert!(restricted.overrides.is_none());

        let heredoc = restricted.heredoc.expect("heredoc hardening retained");
        assert_eq!(heredoc.enabled, Some(true));
        assert_eq!(heredoc.fallback_on_parse_error, Some(false));
        assert_eq!(heredoc.fallback_on_timeout, None);
        assert_eq!(heredoc.timeout_ms, None);
        assert_eq!(heredoc.max_body_bytes, None);
        assert_eq!(heredoc.languages, None);
        assert!(heredoc.allowlist.is_none());

        assert!(restricted.agents.is_none());
        assert!(restricted.response.is_none());
        assert!(restricted.projects.is_none());
    }

    #[test]
    fn untrusted_project_policy_drops_layer_when_it_only_weakens_protection() {
        let layer: ConfigLayer = toml::from_str(
            r#"
[general]
fail_closed = false
max_hook_input_bytes = 1
max_command_bytes = 1

[packs]
disabled = ["core", "system.disk"]
custom_paths = [".dcg/packs/attacker.yaml"]

[policy]
default_mode = "log"

[overrides]
allow = ["rm -rf /"]
allowlist = ["git reset --hard"]

[heredoc]
enabled = false
timeout_ms = 0
languages = ["bash"]
fallback_on_parse_error = true
fallback_on_timeout = true
"#,
        )
        .expect("parse project config layer");

        let restricted = layer.into_restricted_project_policy();
        assert!(restricted.general.is_none());
        assert!(restricted.packs.is_none());
        assert!(restricted.policy.is_none());
        assert!(restricted.overrides.is_none());
        assert!(restricted.heredoc.is_none());
    }

    #[test]
    fn explicitly_selected_project_config_is_not_loaded_or_merged_twice() {
        let explicit: ConfigLayer = toml::from_str(
            r#"
[packs]
enabled = ["database.postgresql"]
"#,
        )
        .expect("parse explicit project layer");
        let duplicate: ConfigLayer = toml::from_str(
            r#"
[packs]
enabled = ["database.postgresql"]
"#,
        )
        .expect("parse automatic project layer");
        let project_loader_called = std::cell::Cell::new(false);
        let mut config = Config::default();

        config.merge_project_and_explicit_layers(Some(explicit), true, || {
            project_loader_called.set(true);
            Some(duplicate)
        });

        assert!(!project_loader_called.get());
        assert_eq!(config.packs.enabled, ["database.postgresql"]);
    }

    #[test]
    fn test_allowlist_config_parses_auto_prune_expired() {
        let config: Config = toml::from_str(
            r"
[allowlist]
auto_prune_expired = true
",
        )
        .unwrap();
        assert!(config.allowlist.auto_prune_expired);
    }

    #[test]
    fn test_enabled_pack_ids_includes_core() {
        let config = Config::default();
        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("core"));
    }

    #[test]
    fn test_enabled_pack_ids_includes_system_disk_by_default() {
        // git_safety_guard-nqhi.8: system.disk is default-on so a
        // first-time user with empty config has protection against
        // mkfs/dd-to-/dev/fdisk catastrophes.
        let config = Config::default();
        let enabled = config.enabled_pack_ids();
        assert!(
            enabled.contains("system.disk"),
            "system.disk must be enabled by default — catastrophic disk \
             ops are not safe to leave one config-edit away from \
             unprotected. Got enabled set: {enabled:?}"
        );
    }

    #[test]
    fn windows_packs_are_default_on_only_on_windows() {
        // win-pack-default-enablement (.9.10): the catastrophic Windows packs
        // (windows.filesystem, windows.system) are default-ON on Windows so a
        // fresh install blocks `del /s`, `rd /s`, `Remove-Item -Recurse -Force`,
        // `vssadmin delete shadows`, etc. with no config; on Unix they are
        // registered but OFF (opt-in) so the Unix quick-reject pays no cost for
        // Windows verbs. The broader windows.misc / windows.powershell packs are
        // opt-in on every platform.
        let enabled = Config::default().enabled_pack_ids();

        #[cfg(windows)]
        {
            assert!(
                enabled.contains("windows.filesystem"),
                "windows.filesystem must be default-on on Windows: {enabled:?}"
            );
            assert!(
                enabled.contains("windows.system"),
                "windows.system must be default-on on Windows: {enabled:?}"
            );
        }
        #[cfg(not(windows))]
        {
            assert!(
                !enabled.contains("windows.filesystem"),
                "windows.filesystem must be opt-in (off) on Unix: {enabled:?}"
            );
            assert!(
                !enabled.contains("windows.system"),
                "windows.system must be opt-in (off) on Unix: {enabled:?}"
            );
        }

        // Broader Windows packs are opt-in on every platform.
        assert!(!enabled.contains("windows.misc"));
        assert!(!enabled.contains("windows.powershell"));
    }

    #[test]
    fn windows_packs_respect_opt_out_and_explicit_enable() {
        // Opt-out: disabling the `windows` category removes the default-on packs
        // (a no-op on Unix where they were never on).
        let opt_out = Config {
            packs: PacksConfig {
                enabled: vec![],
                disabled: vec!["windows".to_string()],
                custom_paths: vec![],
            },
            ..Default::default()
        };
        let enabled = opt_out.enabled_pack_ids();
        assert!(!enabled.contains("windows.filesystem"));
        assert!(!enabled.contains("windows.system"));

        // Explicit enable works on any platform (e.g. to scan committed .ps1/.cmd
        // scripts on Unix CI).
        let opt_in = Config {
            packs: PacksConfig {
                enabled: vec!["windows.misc".to_string()],
                disabled: vec![],
                custom_paths: vec![],
            },
            ..Default::default()
        };
        let enabled = opt_in.enabled_pack_ids();
        assert!(
            enabled.contains("windows.misc"),
            "explicit enable must include windows.misc: {enabled:?}"
        );
    }

    #[test]
    fn test_system_disk_can_be_explicitly_disabled() {
        // Opt-out path for users who genuinely need mkfs/dd-to-device
        // unblocked. Both forms must work: pack-specific
        // (`disabled = ["system.disk"]`) and category-wide
        // (`disabled = ["system"]`).
        let pack_specific = Config {
            packs: PacksConfig {
                enabled: vec![],
                disabled: vec!["system.disk".to_string()],
                custom_paths: vec![],
            },
            ..Default::default()
        };
        let enabled = pack_specific.enabled_pack_ids();
        assert!(
            !enabled.contains("system.disk"),
            "explicit `disabled = [\"system.disk\"]` must opt out — got: {enabled:?}"
        );

        let category_wide = Config {
            packs: PacksConfig {
                enabled: vec![],
                disabled: vec!["system".to_string()],
                custom_paths: vec![],
            },
            ..Default::default()
        };
        let enabled = category_wide.enabled_pack_ids();
        assert!(
            !enabled.contains("system.disk"),
            "explicit `disabled = [\"system\"]` must opt out — got: {enabled:?}"
        );
    }

    #[test]
    fn test_enabled_pack_ids_respects_disabled() {
        let config = Config {
            packs: PacksConfig {
                enabled: vec!["kubernetes".to_string(), "kubernetes.helm".to_string()],
                disabled: vec!["kubernetes.helm".to_string()],
                custom_paths: vec![],
            },
            ..Default::default()
        };
        let enabled = config.enabled_pack_ids();
        assert!(
            !enabled.contains("kubernetes"),
            "known category markers must be replaced by concrete leaves"
        );
        assert!(enabled.contains("kubernetes.kubectl"));
        assert!(enabled.contains("kubernetes.kustomize"));
        assert!(!enabled.contains("kubernetes.helm"));
    }

    #[test]
    fn careful_windows_preset_expands_to_curated_destructive_and_egress_leaves() {
        let config = Config {
            packs: PacksConfig {
                enabled: vec!["careful_company_running_windows".to_string()],
                disabled: vec!["database.mongodb".to_string()],
                custom_paths: vec![],
            },
            ..Default::default()
        };
        let enabled = config.enabled_pack_ids();

        for expected in [
            "careful_company_running_windows.chat",
            "careful_company_running_windows.email",
            "careful_company_running_windows.guardrails",
            "careful_company_running_windows.transfer",
            "careful_company_running_windows.tunnel",
            "careful_company_running_windows.upload",
            "windows.filesystem",
            "windows.misc",
            "windows.powershell",
            "windows.system",
            "database.snowflake",
            "storage.s3",
            "remote.scp",
            "backup.rclone",
            "secrets.vault",
            "cloud.aws",
        ] {
            assert!(
                enabled.contains(expected),
                "curated preset must include {expected}: {enabled:?}"
            );
        }
        assert!(
            !enabled.contains("database.mongodb"),
            "leaf exclusions must win after preset expansion"
        );
        assert!(
            !enabled.contains("containers.docker"),
            "unreviewed categories must not silently join the curated preset"
        );
        assert!(
            !enabled.contains("careful_company_running_windows"),
            "preset marker must resolve to concrete leaves"
        );
    }

    #[test]
    fn disabling_careful_windows_preset_removes_only_its_enablement_contribution() {
        let config = Config {
            packs: PacksConfig {
                enabled: vec![
                    "careful_company_running_windows".to_string(),
                    "cloud".to_string(),
                    "database.snowflake".to_string(),
                ],
                disabled: vec!["careful_company_running_windows".to_string()],
                custom_paths: vec![],
            },
            ..Default::default()
        };
        let enabled = config.enabled_pack_ids();

        assert!(
            !enabled
                .iter()
                .any(|pack_id| pack_id.starts_with("careful_company_running_windows.")),
            "disabling the preset must remove its own leaves: {enabled:?}"
        );
        for cloud_pack in ["cloud.aws", "cloud.gcp", "cloud.azure"] {
            assert!(
                enabled.contains(cloud_pack),
                "independent cloud-category enablement must survive preset cancellation: {enabled:?}"
            );
        }
        assert!(
            enabled.contains("database.snowflake"),
            "an independently enabled preset member must retain its own provenance: {enabled:?}"
        );
        assert!(
            !enabled.contains("remote.scp"),
            "a preset-only member must disappear with the preset contribution: {enabled:?}"
        );
    }

    #[test]
    fn disabling_preset_preserves_native_windows_default_packs() {
        let packs = PacksConfig {
            enabled: vec!["careful_company_running_windows".to_string()],
            disabled: vec!["careful_company_running_windows".to_string()],
            custom_paths: vec![],
        };
        let enabled = PacksConfig::resolve_requested_pack_ids(
            packs.requested_pack_ids(true),
            &packs.disabled,
        );

        assert!(enabled.contains("windows.filesystem"));
        assert!(enabled.contains("windows.system"));
        assert!(!enabled.contains("windows.misc"));
        assert!(!enabled.contains("windows.powershell"));
    }

    #[test]
    fn test_enabled_pack_ids_uses_project_override() {
        let cwd = std::env::current_dir().expect("current_dir");

        let mut config = Config::default();
        config.packs.enabled = vec!["kubernetes".to_string()];

        let mut projects = std::collections::HashMap::new();
        projects.insert(
            cwd.to_string_lossy().to_string(),
            ProjectConfig {
                packs: Some(PacksConfig {
                    enabled: vec!["database.postgresql".to_string()],
                    disabled: Vec::new(),
                    custom_paths: vec![],
                }),
                overrides: None,
            },
        );
        config.projects = projects;

        let enabled = config.enabled_pack_ids();
        assert!(enabled.contains("database.postgresql"));
        assert!(!enabled.contains("kubernetes"));
    }

    #[test]
    fn test_allow_override_simple() {
        let override_ = AllowOverride::Simple("test pattern".to_string());
        assert_eq!(override_.pattern(), "test pattern");
        assert!(override_.condition_met());
    }

    #[test]
    fn test_allow_override_conditional_no_condition() {
        let override_ = AllowOverride::Conditional {
            pattern: "test pattern".to_string(),
            when: None,
        };
        assert!(override_.condition_met());
    }

    #[test]
    fn test_sample_config_parses() {
        let sample = Config::generate_sample_config();
        assert!(sample.contains("[interactive]"));
        assert!(sample.contains("[git_awareness]"));
        toml::from_str::<Config>(&sample).expect("sample config parses");
    }

    #[test]
    fn test_history_config_defaults() {
        let config = HistoryConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.redaction_mode, HistoryRedactionMode::Pattern);
        assert_eq!(config.retention_days, HistoryConfig::DEFAULT_RETENTION_DAYS);
        assert_eq!(config.max_size_mb, HistoryConfig::DEFAULT_MAX_SIZE_MB);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_history_config_rejects_zero_size_cap() {
        let config = HistoryConfig {
            max_size_mb: 0,
            ..HistoryConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            "history max_size_mb must be at least 1"
        );
    }

    #[test]
    fn test_history_config_from_toml() {
        let input = r#"
[history]
enabled = true
redaction_mode = "full"
retention_days = 30
max_size_mb = 250
database_path = "/tmp/dcg-history.db"
auto_prune = true
prune_check_interval_hours = 6
batch_size = 25
batch_flush_interval_ms = 40
"#;
        let config: Config = toml::from_str(input).expect("config parses");
        assert!(config.history.enabled);
        assert_eq!(config.history.redaction_mode, HistoryRedactionMode::Full);
        assert_eq!(config.history.retention_days, 30);
        assert_eq!(config.history.max_size_mb, 250);
        assert_eq!(
            config.history.database_path.as_deref(),
            Some("/tmp/dcg-history.db")
        );
        assert!(config.history.auto_prune);
        assert_eq!(config.history.prune_check_interval_hours, 6);
        assert_eq!(config.history.batch_size, 25);
        assert_eq!(config.history.batch_flush_interval_ms, 40);
    }

    #[test]
    fn history_runtime_fields_survive_presence_aware_layer_merge() {
        let layer: ConfigLayer = toml::from_str(
            r"
[history]
auto_prune = true
prune_check_interval_hours = 7
batch_size = 13
batch_flush_interval_ms = 29
",
        )
        .expect("history layer parses");
        let mut config = Config::default();
        config.merge_layer(layer);

        assert!(config.history.auto_prune);
        assert_eq!(config.history.prune_check_interval_hours, 7);
        assert_eq!(config.history.batch_size, 13);
        assert_eq!(config.history.batch_flush_interval_ms, 29);
    }

    #[test]
    fn config_file_fail_closed_survives_layer_merge() {
        // Regression (issue #160): `[general] fail_closed = true` from a config
        // FILE must be carried through the layered load/merge into the final
        // config. It was previously dropped because `GeneralConfigLayer` lacked
        // the field, so `fail_closed` was always its default `false` from a file.
        let layer: ConfigLayer = toml::from_str("[general]\nfail_closed = true\nverbose = true\n")
            .expect("layer parses");
        let mut config = Config::default();
        config.merge_layer(layer);
        assert!(
            config.general.fail_closed,
            "fail_closed from a config file must survive the layer merge"
        );
        // Sibling field from the same section is honored too (sanity).
        assert!(config.general.verbose);
    }

    #[test]
    fn test_history_redaction_mode_parsing() {
        assert_eq!(
            HistoryRedactionMode::from_str("none").expect("none"),
            HistoryRedactionMode::None
        );
        assert_eq!(
            HistoryRedactionMode::from_str("pattern").expect("pattern"),
            HistoryRedactionMode::Pattern
        );
        assert_eq!(
            HistoryRedactionMode::from_str("full").expect("full"),
            HistoryRedactionMode::Full
        );
        assert!(HistoryRedactionMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_history_env_overrides() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
            ("DCG_HISTORY_ENABLED", "true"),
            ("DCG_HISTORY_REDACTION_MODE", "full"),
        ]);
        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert!(config.history.enabled);
        assert_eq!(config.history.redaction_mode, HistoryRedactionMode::Full);
    }

    #[test]
    fn test_history_database_path_expansion() {
        if dirs::home_dir().is_none() {
            return;
        }

        let config = HistoryConfig {
            database_path: Some("~/.config/dcg/history.db".to_string()),
            ..Default::default()
        };
        let expanded = config
            .expanded_database_path()
            .expect("expanded database path");
        assert!(!expanded.to_string_lossy().contains('~'));
        assert!(expanded.to_string_lossy().contains("dcg"));
    }

    #[test]
    fn test_history_retention_validation() {
        let config = HistoryConfig {
            retention_days: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = HistoryConfig {
            retention_days: HistoryConfig::MAX_RETENTION_DAYS + 1,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = HistoryConfig {
            retention_days: HistoryConfig::DEFAULT_RETENTION_DAYS,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn history_runtime_invariants_prevent_zero_interval_worker_spins() {
        let mut config = HistoryConfig {
            retention_days: 0,
            max_size_mb: 0,
            prune_check_interval_hours: 0,
            batch_size: 0,
            batch_flush_interval_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        assert!(config.normalize_runtime_invariants());
        assert_eq!(config.retention_days, 1);
        assert_eq!(config.max_size_mb, 1);
        assert_eq!(config.prune_check_interval_hours, 1);
        assert_eq!(config.batch_size, 1);
        assert_eq!(config.batch_flush_interval_ms, 1);
        assert!(config.validate().is_ok());
        assert!(!config.normalize_runtime_invariants());
    }

    // =========================================================================
    // OutputConfig tests (git_safety_guard-pbte.5)
    // =========================================================================

    #[test]
    fn test_output_config_defaults() {
        // Verify both toggles default to true
        let config = OutputConfig::default();
        assert!(
            config.highlight_enabled(),
            "highlight_enabled should default to true"
        );
        assert!(
            config.explanations_enabled(),
            "explanations_enabled should default to true"
        );

        // Verify the Option fields are None (not explicitly set)
        assert!(
            config.highlight_enabled.is_none(),
            "highlight_enabled Option should be None by default"
        );
        assert!(
            config.explanations_enabled.is_none(),
            "explanations_enabled Option should be None by default"
        );
        assert!(
            config.high_contrast.is_none(),
            "high_contrast Option should be None by default"
        );
        assert!(
            !config.high_contrast_enabled(),
            "high_contrast should default to false"
        );
    }

    #[test]
    fn test_output_config_explicit_false() {
        // Verify explicit false values override defaults
        let config = OutputConfig {
            highlight_enabled: Some(false),
            explanations_enabled: Some(false),
            high_contrast: Some(false),
        };
        assert!(
            !config.highlight_enabled(),
            "highlight_enabled should be false when explicitly set"
        );
        assert!(
            !config.explanations_enabled(),
            "explanations_enabled should be false when explicitly set"
        );
    }

    #[test]
    fn test_output_config_explicit_true() {
        // Verify explicit true values work correctly
        let config = OutputConfig {
            highlight_enabled: Some(true),
            explanations_enabled: Some(true),
            high_contrast: Some(false),
        };
        assert!(config.highlight_enabled());
        assert!(config.explanations_enabled());
    }

    #[test]
    fn test_output_config_toggles_independent() {
        // Verify toggles are independent of each other
        let config1 = OutputConfig {
            highlight_enabled: Some(true),
            explanations_enabled: Some(false),
            high_contrast: Some(false),
        };
        assert!(
            config1.highlight_enabled(),
            "highlight should be true independently"
        );
        assert!(
            !config1.explanations_enabled(),
            "explanations should be false independently"
        );

        let config2 = OutputConfig {
            highlight_enabled: Some(false),
            explanations_enabled: Some(true),
            high_contrast: Some(false),
        };
        assert!(
            !config2.highlight_enabled(),
            "highlight should be false independently"
        );
        assert!(
            config2.explanations_enabled(),
            "explanations should be true independently"
        );
    }

    #[test]
    fn test_theme_config_from_toml() {
        let toml = r#"
[theme]
palette = "colorblind"
use_unicode = false
use_color = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.theme.palette.as_deref(), Some("colorblind"));
        assert_eq!(config.theme.use_unicode, Some(false));
        assert_eq!(config.theme.use_color, Some(false));
    }

    #[test]
    fn test_env_high_contrast_override() {
        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_HIGH_CONTRAST", "1")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(config.output.high_contrast_enabled());
    }

    #[test]
    fn test_output_config_from_toml_both_disabled() {
        let input = r"
[output]
highlight_enabled = false
explanations_enabled = false
";
        let config: Config = toml::from_str(input).expect("config parses");
        assert!(
            !config.output.highlight_enabled(),
            "highlight_enabled should be false from TOML"
        );
        assert!(
            !config.output.explanations_enabled(),
            "explanations_enabled should be false from TOML"
        );
    }

    #[test]
    fn test_output_config_from_toml_both_enabled() {
        let input = r"
[output]
highlight_enabled = true
explanations_enabled = true
";
        let config: Config = toml::from_str(input).expect("config parses");
        assert!(config.output.highlight_enabled());
        assert!(config.output.explanations_enabled());
    }

    #[test]
    fn test_output_config_from_toml_partial_highlight_only() {
        // When only highlight_enabled is set, explanations defaults to true
        let input = r"
[output]
highlight_enabled = false
";
        let config: Config = toml::from_str(input).expect("config parses");
        assert!(
            !config.output.highlight_enabled(),
            "highlight_enabled should be false from TOML"
        );
        assert!(
            config.output.explanations_enabled(),
            "explanations_enabled should default to true when not set"
        );
    }

    #[test]
    fn test_output_config_from_toml_partial_explanations_only() {
        // When only explanations_enabled is set, highlight defaults to true
        let input = r"
[output]
explanations_enabled = false
";
        let config: Config = toml::from_str(input).expect("config parses");
        assert!(
            config.output.highlight_enabled(),
            "highlight_enabled should default to true when not set"
        );
        assert!(
            !config.output.explanations_enabled(),
            "explanations_enabled should be false from TOML"
        );
    }

    #[test]
    fn test_output_config_layer_merge_preserves_unset() {
        let mut base = Config::default();
        base.output.highlight_enabled = Some(false); // Explicitly set in base

        // Layer that only sets explanations_enabled
        let layer: ConfigLayer = toml::from_str(
            r"
[output]
explanations_enabled = false
",
        )
        .expect("layer parses");
        base.merge_layer(layer);

        // highlight_enabled should remain false (from base)
        assert!(
            !base.output.highlight_enabled(),
            "highlight_enabled should be preserved from base"
        );
        // explanations_enabled should be false (from layer)
        assert!(
            !base.output.explanations_enabled(),
            "explanations_enabled should be set from layer"
        );
    }

    #[test]
    fn test_output_config_layer_merge_overwrites_when_set() {
        let mut base = Config::default();
        base.output.highlight_enabled = Some(false);
        base.output.explanations_enabled = Some(false);

        // Layer that sets both to true
        let layer: ConfigLayer = toml::from_str(
            r"
[output]
highlight_enabled = true
explanations_enabled = true
",
        )
        .expect("layer parses");
        base.merge_layer(layer);

        // Both should be true now (overwritten by layer)
        assert!(
            base.output.highlight_enabled(),
            "highlight_enabled should be overwritten to true"
        );
        assert!(
            base.output.explanations_enabled(),
            "explanations_enabled should be overwritten to true"
        );
    }

    #[test]
    fn test_output_config_mixed_toml_scenarios() {
        // Test various mixed scenarios
        let scenarios = [
            (
                r"[output]
highlight_enabled = true
explanations_enabled = false",
                true,
                false,
            ),
            (
                r"[output]
highlight_enabled = false
explanations_enabled = true",
                false,
                true,
            ),
            // Empty output section - defaults apply
            (r"[output]", true, true),
        ];

        for (input, expected_highlight, expected_explanations) in scenarios {
            let config: Config = toml::from_str(input).expect("config parses");
            assert_eq!(
                config.output.highlight_enabled(),
                expected_highlight,
                "highlight mismatch for input: {input}"
            );
            assert_eq!(
                config.output.explanations_enabled(),
                expected_explanations,
                "explanations mismatch for input: {input}"
            );
        }
    }

    #[test]
    fn test_output_config_in_full_config() {
        // Test OutputConfig works correctly as part of full Config
        let input = r#"
[general]
color = "always"

[output]
highlight_enabled = false
explanations_enabled = true

[packs]
enabled = ["database.postgresql"]
"#;
        let config: Config = toml::from_str(input).expect("config parses");

        // Verify output config
        assert!(!config.output.highlight_enabled());
        assert!(config.output.explanations_enabled());

        // Verify other config sections unaffected
        assert_eq!(config.general.color, "always");
        assert!(
            config
                .packs
                .enabled
                .contains(&"database.postgresql".to_string())
        );
    }

    #[test]
    fn test_output_config_does_not_affect_allow_decision() {
        // Test that output config toggles do NOT affect the evaluator's allow decision.
        // This is a critical invariant: output settings are purely cosmetic.
        use crate::allowlist::LayeredAllowlist;
        use crate::evaluator::{EvaluationDecision, evaluate_command};
        use crate::packs::REGISTRY;

        // Safe command: "ls -la" should always be allowed
        let command = "ls -la";

        // Config with defaults (both true)
        let config_default = Config::default();
        let enabled_packs = config_default.enabled_pack_ids();
        let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keyword_refs: Vec<&str> = keywords.iter().map(|s| &**s).collect();
        let overrides_default = config_default.overrides.compile();
        let allowlists = LayeredAllowlist::default();

        let result_default = evaluate_command(
            command,
            &config_default,
            &keyword_refs,
            &overrides_default,
            &allowlists,
        );
        assert!(
            matches!(result_default.decision, EvaluationDecision::Allow),
            "Safe command should be allowed with default config"
        );

        // Config with both toggles disabled
        let mut config_disabled = Config::default();
        config_disabled.output.highlight_enabled = Some(false);
        config_disabled.output.explanations_enabled = Some(false);
        let overrides_disabled = config_disabled.overrides.compile();

        let result_disabled = evaluate_command(
            command,
            &config_disabled,
            &keyword_refs,
            &overrides_disabled,
            &allowlists,
        );
        assert!(
            matches!(result_disabled.decision, EvaluationDecision::Allow),
            "Safe command should still be allowed with disabled output toggles"
        );

        // Both results should have the same decision
        assert_eq!(
            std::mem::discriminant(&result_default.decision),
            std::mem::discriminant(&result_disabled.decision),
            "Output config should not affect allow decision"
        );
    }

    #[test]
    fn test_output_config_does_not_affect_deny_decision() {
        // Test that output config toggles do NOT affect the evaluator's deny decision.
        use crate::allowlist::LayeredAllowlist;
        use crate::evaluator::{EvaluationDecision, evaluate_command};
        use crate::packs::REGISTRY;

        // Dangerous command: "git reset --hard HEAD" should always be denied
        let command = "git reset --hard HEAD";

        // Config with defaults (both true)
        let config_default = Config::default();
        let enabled_packs = config_default.enabled_pack_ids();
        let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
        let keyword_refs: Vec<&str> = keywords.iter().map(|s| &**s).collect();
        let overrides_default = config_default.overrides.compile();
        let allowlists = LayeredAllowlist::default();

        let result_default = evaluate_command(
            command,
            &config_default,
            &keyword_refs,
            &overrides_default,
            &allowlists,
        );
        assert!(
            matches!(result_default.decision, EvaluationDecision::Deny),
            "Destructive command should be denied with default config"
        );

        // Config with both toggles disabled
        let mut config_disabled = Config::default();
        config_disabled.output.highlight_enabled = Some(false);
        config_disabled.output.explanations_enabled = Some(false);
        let overrides_disabled = config_disabled.overrides.compile();

        let result_disabled = evaluate_command(
            command,
            &config_disabled,
            &keyword_refs,
            &overrides_disabled,
            &allowlists,
        );
        assert!(
            matches!(result_disabled.decision, EvaluationDecision::Deny),
            "Destructive command should still be denied with disabled output toggles"
        );

        // Both results should have the same decision AND same pattern info
        assert_eq!(
            std::mem::discriminant(&result_default.decision),
            std::mem::discriminant(&result_disabled.decision),
            "Output config should not affect deny decision"
        );

        // Pattern info should also be the same
        assert_eq!(
            result_default.pattern_info.as_ref().map(|p| &p.reason),
            result_disabled.pattern_info.as_ref().map(|p| &p.reason),
            "Pattern info reason should be identical regardless of output config"
        );
    }

    #[test]
    fn test_output_config_toggles_are_purely_cosmetic() {
        // Comprehensive test: verify output toggles have zero effect on evaluation
        use crate::allowlist::LayeredAllowlist;
        use crate::evaluator::{EvaluationDecision, evaluate_command};
        use crate::packs::REGISTRY;

        let test_cases = [
            ("echo hello", EvaluationDecision::Allow),      // Safe
            ("git status", EvaluationDecision::Allow),      // Safe git command
            ("git reset --hard", EvaluationDecision::Deny), // Destructive
            ("rm -rf /", EvaluationDecision::Deny),         // Destructive
        ];

        let toggle_combinations = [
            (Some(true), Some(true)),
            (Some(true), Some(false)),
            (Some(false), Some(true)),
            (Some(false), Some(false)),
            (None, None), // Defaults
        ];

        let allowlists = LayeredAllowlist::default();

        for (command, expected_decision) in &test_cases {
            let mut results = Vec::new();

            for (highlight, explanations) in &toggle_combinations {
                let mut config = Config::default();
                config.output.highlight_enabled = *highlight;
                config.output.explanations_enabled = *explanations;

                let enabled_packs = config.enabled_pack_ids();
                let keywords = REGISTRY.collect_enabled_keywords(&enabled_packs);
                let keyword_refs: Vec<&str> = keywords.iter().map(|s| &**s).collect();
                let overrides = config.overrides.compile();

                let result =
                    evaluate_command(command, &config, &keyword_refs, &overrides, &allowlists);
                results.push(result.decision);

                // Each result should match the expected decision
                assert_eq!(
                    std::mem::discriminant(&result.decision),
                    std::mem::discriminant(expected_decision),
                    "Command '{command}' with toggles ({highlight:?}, {explanations:?}) should have expected decision"
                );
            }

            // All results for this command should be identical
            let first = &results[0];
            for (i, result) in results.iter().enumerate().skip(1) {
                assert_eq!(
                    std::mem::discriminant(first),
                    std::mem::discriminant(result),
                    "Command '{command}': result {i} differs from result 0"
                );
            }
        }
    }

    #[test]
    fn test_config_merge() {
        let mut base = Config::default();
        let layer: ConfigLayer = toml::from_str(
            r#"
[packs]
enabled = ["database.postgresql"]
"#,
        )
        .expect("layer parses");
        base.merge_layer(layer);
        assert!(
            base.packs
                .enabled
                .contains(&"database.postgresql".to_string())
        );
    }

    #[test]
    fn test_config_merge_merges_heredoc_allowlist() {
        let mut base = Config::default();
        base.heredoc.allowlist = Some(HeredocAllowlistConfig {
            commands: vec!["cmd1".to_string()],
            ..Default::default()
        });

        let other = ConfigLayer {
            heredoc: Some(HeredocConfig {
                allowlist: Some(HeredocAllowlistConfig {
                    commands: vec!["cmd2".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        base.merge_layer(other);

        let allowlist = base.heredoc.allowlist.as_ref().expect("allowlist merged");
        assert!(allowlist.commands.contains(&"cmd1".to_string()));
        assert!(allowlist.commands.contains(&"cmd2".to_string()));
    }

    #[test]
    fn test_config_merge_layer_general_verbose_can_be_disabled() {
        let mut config = Config::default();
        config.general.verbose = true;

        let layer: ConfigLayer = toml::from_str(
            r"
[general]
verbose = false
",
        )
        .expect("layer parses");
        config.merge_layer(layer);

        assert!(!config.general.verbose);
    }

    #[test]
    fn test_config_merge_layer_general_missing_fields_do_not_override() {
        let mut config = Config::default();
        config.general.verbose = true;

        let layer: ConfigLayer = toml::from_str(
            r#"
[general]
color = "never"
"#,
        )
        .expect("layer parses");
        config.merge_layer(layer);

        assert!(config.general.verbose);
        assert_eq!(config.general.color, "never");
    }

    #[test]
    fn test_config_merge_layer_logging_is_reversible() {
        let mut config = Config::default();
        config.logging.enabled = true;
        config.logging.format = crate::logging::LogFormat::Json;
        config.logging.events.deny = false;
        config.logging.events.warn = false;
        config.logging.events.allow = true;

        let layer: ConfigLayer = toml::from_str(
            r#"
[logging]
enabled = false
format = "text"

[logging.events]
deny = true
warn = true
allow = false
"#,
        )
        .expect("layer parses");
        config.merge_layer(layer);

        assert!(!config.logging.enabled);
        assert_eq!(config.logging.format, crate::logging::LogFormat::Text);
        assert!(config.logging.events.deny);
        assert!(config.logging.events.warn);
        assert!(!config.logging.events.allow);
    }

    #[test]
    fn test_interactive_config_from_toml() {
        let input = r#"
[interactive]
enabled = true
verification = "command"
timeout_seconds = 12
code_length = 6
max_attempts = 7
allow_non_tty_fallback = false
disable_in_ci = false
require_env = "DCG_INTERACTIVE"
"#;
        let config: Config = toml::from_str(input).expect("config parses");

        assert!(config.interactive.enabled);
        assert_eq!(config.interactive.verification, VerificationMethod::Command);
        assert_eq!(config.interactive.timeout_seconds, 12);
        assert_eq!(config.interactive.code_length, 6);
        assert_eq!(config.interactive.max_attempts, 7);
        assert!(!config.interactive.allow_non_tty_fallback);
        assert!(!config.interactive.disable_in_ci);
        assert_eq!(
            config.interactive.require_env.as_deref(),
            Some("DCG_INTERACTIVE")
        );
    }

    #[test]
    fn test_config_merge_layer_interactive_overrides_fields() {
        let mut config = Config::default();
        let layer: ConfigLayer = toml::from_str(
            r#"
[interactive]
enabled = true
verification = "command"
timeout_seconds = 12
code_length = 6
max_attempts = 7
allow_non_tty_fallback = false
disable_in_ci = false
require_env = "DCG_INTERACTIVE"
"#,
        )
        .expect("layer parses");

        config.merge_layer(layer);

        assert!(config.interactive.enabled);
        assert_eq!(config.interactive.verification, VerificationMethod::Command);
        assert_eq!(config.interactive.timeout_seconds, 12);
        assert_eq!(config.interactive.code_length, 6);
        assert_eq!(config.interactive.max_attempts, 7);
        assert!(!config.interactive.allow_non_tty_fallback);
        assert!(!config.interactive.disable_in_ci);
        assert_eq!(
            config.interactive.require_env.as_deref(),
            Some("DCG_INTERACTIVE")
        );
    }

    #[test]
    fn test_config_merge_layer_interactive_missing_fields_do_not_override() {
        let mut config = Config::default();
        config.interactive.enabled = true;
        config.interactive.verification = VerificationMethod::None;
        config.interactive.timeout_seconds = 9;
        config.interactive.code_length = 5;
        config.interactive.max_attempts = 4;
        config.interactive.allow_non_tty_fallback = false;
        config.interactive.disable_in_ci = false;
        config.interactive.require_env = Some("KEEP_ME".to_string());

        let layer: ConfigLayer = toml::from_str(
            r"
[interactive]
enabled = false
",
        )
        .expect("layer parses");

        config.merge_layer(layer);

        assert!(!config.interactive.enabled);
        assert_eq!(config.interactive.verification, VerificationMethod::None);
        assert_eq!(config.interactive.timeout_seconds, 9);
        assert_eq!(config.interactive.code_length, 5);
        assert_eq!(config.interactive.max_attempts, 4);
        assert!(!config.interactive.allow_non_tty_fallback);
        assert!(!config.interactive.disable_in_ci);
        assert_eq!(config.interactive.require_env.as_deref(), Some("KEEP_ME"));
    }

    #[test]
    fn test_interactive_env_overrides() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
            ("DCG_INTERACTIVE_ENABLED", "true"),
            ("DCG_INTERACTIVE_VERIFICATION", "none"),
            ("DCG_INTERACTIVE_TIMEOUT_SECONDS", "11"),
            ("DCG_INTERACTIVE_CODE_LENGTH", "6"),
            ("DCG_INTERACTIVE_MAX_ATTEMPTS", "8"),
            ("DCG_INTERACTIVE_ALLOW_NON_TTY_FALLBACK", "false"),
            ("DCG_INTERACTIVE_DISABLE_IN_CI", "false"),
            ("DCG_INTERACTIVE_REQUIRE_ENV", "DCG_INTERACTIVE"),
        ]);
        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert!(config.interactive.enabled);
        assert_eq!(config.interactive.verification, VerificationMethod::None);
        assert_eq!(config.interactive.timeout_seconds, 11);
        assert_eq!(config.interactive.code_length, 6);
        assert_eq!(config.interactive.max_attempts, 8);
        assert!(!config.interactive.allow_non_tty_fallback);
        assert!(!config.interactive.disable_in_ci);
        assert_eq!(
            config.interactive.require_env.as_deref(),
            Some("DCG_INTERACTIVE")
        );
    }

    #[test]
    fn test_interactive_env_empty_require_env_clears_requirement() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_INTERACTIVE_REQUIRE_ENV", "   ")]);
        let mut config = Config::default();
        config.interactive.require_env = Some("KEEP_ME".to_string());

        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert!(config.interactive.require_env.is_none());
    }

    #[test]
    fn test_git_awareness_defaults_match_schema() {
        let config = GitAwarenessConfig::default();

        assert!(!config.enabled);
        assert_eq!(
            config.protected_branches,
            vec![
                "main".to_string(),
                "production".to_string(),
                "release/*".to_string()
            ]
        );
        assert_eq!(config.protected_strictness, StrictnessLevel::All);
        assert_eq!(
            config.relaxed_branches,
            vec![
                "feature/*".to_string(),
                "experiment/*".to_string(),
                "sandbox/*".to_string()
            ]
        );
        assert_eq!(config.relaxed_strictness, StrictnessLevel::Critical);
        assert_eq!(config.default_strictness, StrictnessLevel::High);
        assert!(config.relaxed_disabled_packs.is_empty());
        assert!(config.show_branch_in_output);
        assert!(!config.warn_if_not_git);
    }

    #[test]
    fn test_git_awareness_config_from_toml() {
        let input = r#"
[git_awareness]
enabled = true
protected_branches = ["main", "production", "release/*"]
protected_strictness = "all"
relaxed_branches = ["feature/*", "sandbox/*"]
relaxed_strictness = "critical"
default_strictness = "medium"
relaxed_disabled_packs = ["containers.docker", "cloud.aws"]
show_branch_in_output = false
warn_if_not_git = true
"#;
        let config: Config = toml::from_str(input).expect("config parses");

        assert!(config.git_awareness.enabled);
        assert_eq!(
            config.git_awareness.protected_branches,
            vec![
                "main".to_string(),
                "production".to_string(),
                "release/*".to_string()
            ]
        );
        assert_eq!(
            config.git_awareness.protected_strictness,
            StrictnessLevel::All
        );
        assert_eq!(
            config.git_awareness.relaxed_branches,
            vec!["feature/*".to_string(), "sandbox/*".to_string()]
        );
        assert_eq!(
            config.git_awareness.relaxed_strictness,
            StrictnessLevel::Critical
        );
        assert_eq!(
            config.git_awareness.default_strictness,
            StrictnessLevel::Medium
        );
        assert_eq!(
            config.git_awareness.relaxed_disabled_packs,
            vec!["containers.docker".to_string(), "cloud.aws".to_string()]
        );
        assert!(!config.git_awareness.should_show_branch_in_output());
        assert!(config.git_awareness.warn_if_not_git);
    }

    #[test]
    fn test_config_merge_layer_git_awareness_overrides_all_fields() {
        let mut config = Config::default();
        let layer: ConfigLayer = toml::from_str(
            r#"
[git_awareness]
enabled = true
protected_branches = ["main", "production"]
protected_strictness = "all"
relaxed_branches = ["feature/*"]
relaxed_strictness = "critical"
default_strictness = "medium"
relaxed_disabled_packs = ["containers.docker"]
show_branch_in_output = false
warn_if_not_git = true
"#,
        )
        .expect("layer parses");

        config.merge_layer(layer);

        assert!(config.git_awareness.enabled);
        assert_eq!(
            config.git_awareness.protected_branches,
            vec!["main".to_string(), "production".to_string()]
        );
        assert_eq!(
            config.git_awareness.protected_strictness,
            StrictnessLevel::All
        );
        assert_eq!(
            config.git_awareness.relaxed_branches,
            vec!["feature/*".to_string()]
        );
        assert_eq!(
            config.git_awareness.relaxed_strictness,
            StrictnessLevel::Critical
        );
        assert_eq!(
            config.git_awareness.default_strictness,
            StrictnessLevel::Medium
        );
        assert_eq!(
            config.git_awareness.relaxed_disabled_packs,
            vec!["containers.docker".to_string()]
        );
        assert!(!config.git_awareness.show_branch_in_output);
        assert!(config.git_awareness.warn_if_not_git);
    }

    #[test]
    fn test_config_merge_layer_git_awareness_missing_fields_do_not_override() {
        let mut config = Config::default();
        config.git_awareness.enabled = true;
        config.git_awareness.protected_branches = vec!["production".to_string()];
        config.git_awareness.protected_strictness = StrictnessLevel::All;
        config.git_awareness.relaxed_branches = vec!["sandbox/*".to_string()];
        config.git_awareness.relaxed_strictness = StrictnessLevel::Critical;
        config.git_awareness.default_strictness = StrictnessLevel::Medium;
        config.git_awareness.relaxed_disabled_packs = vec!["cloud.aws".to_string()];
        config.git_awareness.show_branch_in_output = false;
        config.git_awareness.warn_if_not_git = true;

        let layer: ConfigLayer = toml::from_str(
            r"
[git_awareness]
enabled = false
",
        )
        .expect("layer parses");

        config.merge_layer(layer);

        assert!(!config.git_awareness.enabled);
        assert_eq!(
            config.git_awareness.protected_branches,
            vec!["production".to_string()]
        );
        assert_eq!(
            config.git_awareness.protected_strictness,
            StrictnessLevel::All
        );
        assert_eq!(
            config.git_awareness.relaxed_branches,
            vec!["sandbox/*".to_string()]
        );
        assert_eq!(
            config.git_awareness.relaxed_strictness,
            StrictnessLevel::Critical
        );
        assert_eq!(
            config.git_awareness.default_strictness,
            StrictnessLevel::Medium
        );
        assert_eq!(
            config.git_awareness.relaxed_disabled_packs,
            vec!["cloud.aws".to_string()]
        );
        assert!(!config.git_awareness.show_branch_in_output);
        assert!(config.git_awareness.warn_if_not_git);
    }

    #[test]
    fn test_git_awareness_env_overrides() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
            ("DCG_GIT_AWARENESS_ENABLED", "true"),
            ("DCG_GIT_PROTECTED_BRANCHES", "main, production, release/*"),
            ("DCG_GIT_PROTECTED_STRICTNESS", "all"),
            ("DCG_GIT_RELAXED_BRANCHES", "feature/*, sandbox/*"),
            ("DCG_GIT_RELAXED_STRICTNESS", "critical"),
            ("DCG_GIT_DEFAULT_STRICTNESS", "medium"),
            (
                "DCG_GIT_RELAXED_DISABLED_PACKS",
                "containers.docker, cloud.aws",
            ),
            ("DCG_GIT_SHOW_BRANCH_IN_OUTPUT", "false"),
            ("DCG_GIT_AWARENESS_WARN_IF_NOT_GIT", "true"),
        ]);
        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert!(config.git_awareness.enabled);
        assert_eq!(
            config.git_awareness.protected_branches,
            vec![
                "main".to_string(),
                "production".to_string(),
                "release/*".to_string()
            ]
        );
        assert_eq!(
            config.git_awareness.protected_strictness,
            StrictnessLevel::All
        );
        assert_eq!(
            config.git_awareness.relaxed_branches,
            vec!["feature/*".to_string(), "sandbox/*".to_string()]
        );
        assert_eq!(
            config.git_awareness.relaxed_strictness,
            StrictnessLevel::Critical
        );
        assert_eq!(
            config.git_awareness.default_strictness,
            StrictnessLevel::Medium
        );
        assert_eq!(
            config.git_awareness.relaxed_disabled_packs,
            vec!["containers.docker".to_string(), "cloud.aws".to_string()]
        );
        assert!(!config.git_awareness.show_branch_in_output);
        assert!(config.git_awareness.warn_if_not_git);
    }

    #[test]
    fn test_git_awareness_protected_patterns_take_precedence_over_relaxed() {
        let config = GitAwarenessConfig {
            enabled: true,
            protected_branches: vec!["release/*".to_string(), "*/hotfix".to_string()],
            protected_strictness: StrictnessLevel::All,
            relaxed_branches: vec!["release/beta".to_string(), "feature/*".to_string()],
            relaxed_strictness: StrictnessLevel::Critical,
            default_strictness: StrictnessLevel::Medium,
            detached_head_strictness: StrictnessLevel::All,
            relaxed_disabled_packs: vec!["containers.docker".to_string()],
            show_branch_in_output: true,
            warn_if_not_git: false,
        };

        assert_eq!(
            config.strictness_for_branch(Some("release/beta")),
            StrictnessLevel::All
        );
        assert_eq!(
            config.strictness_for_branch(Some("team/hotfix")),
            StrictnessLevel::All
        );
        assert_eq!(
            config.strictness_for_branch(Some("feature/demo")),
            StrictnessLevel::Critical
        );
        assert_eq!(
            config.strictness_for_branch(Some("develop")),
            StrictnessLevel::Medium
        );
        assert_eq!(config.strictness_for_branch(None), StrictnessLevel::Medium);
    }

    #[test]
    fn test_git_awareness_relaxed_disabled_packs_only_apply_to_relaxed_branches() {
        let mut config = GitAwarenessConfig {
            enabled: true,
            protected_branches: vec!["main".to_string()],
            protected_strictness: StrictnessLevel::All,
            relaxed_branches: vec!["feature/*".to_string()],
            relaxed_strictness: StrictnessLevel::Critical,
            default_strictness: StrictnessLevel::High,
            detached_head_strictness: StrictnessLevel::All,
            relaxed_disabled_packs: vec!["containers.docker".to_string(), "cloud.aws".to_string()],
            show_branch_in_output: true,
            warn_if_not_git: false,
        };

        assert_eq!(
            config.disabled_packs_for_branch(Some("feature/local")),
            &["containers.docker".to_string(), "cloud.aws".to_string()]
        );
        assert!(config.disabled_packs_for_branch(Some("main")).is_empty());
        assert!(config.disabled_packs_for_branch(Some("develop")).is_empty());
        assert!(config.disabled_packs_for_branch(None).is_empty());

        config.enabled = false;
        assert!(
            config
                .disabled_packs_for_branch(Some("feature/local"))
                .is_empty()
        );
    }

    #[test]
    fn test_heredoc_settings_defaults() {
        let config = Config::default();
        let settings = config.heredoc_settings();
        assert!(settings.enabled);
        assert_eq!(settings.limits.timeout_ms, 50);
        assert!(settings.allowed_languages.is_none());
        assert!(settings.fallback_on_parse_error);
        assert!(settings.fallback_on_timeout);
    }

    #[test]
    fn test_heredoc_env_overrides_enabled_timeout_languages() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::from([
            ("DCG_HEREDOC_ENABLED", "0"),
            ("DCG_HEREDOC_TIMEOUT_MS", "123"),
            ("DCG_HEREDOC_LANGUAGES", "python, bash, js, unknown_value"),
        ]);
        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        let settings = config.heredoc_settings();
        assert!(!settings.enabled);
        assert_eq!(settings.limits.timeout_ms, 123);
        assert_eq!(
            settings.allowed_languages,
            Some(vec![
                crate::heredoc::ScriptLanguage::Python,
                crate::heredoc::ScriptLanguage::Bash,
                crate::heredoc::ScriptLanguage::JavaScript
            ])
        );
    }

    #[test]
    fn test_env_override_verbose_numeric() {
        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_VERBOSE", "0")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(!config.general.verbose);

        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_VERBOSE", "2")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(config.general.verbose);
    }

    #[test]
    fn test_env_override_check_updates() {
        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_CHECK_UPDATES", "0")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(!config.general.check_updates);

        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_NO_UPDATE_CHECK", "1")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(!config.general.check_updates);

        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_NO_UPDATE_CHECK", "false")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(config.general.check_updates);

        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_NO_UPDATE_CHECK", "0")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(config.general.check_updates);
    }

    #[test]
    fn test_env_override_no_self_heal_falsey_values_do_not_disable() {
        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_NO_SELF_HEAL", "1")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
        assert!(!config.general.self_heal_hook);

        for value in ["0", "false", "no", "n", "off", ""] {
            let mut config = Config::default();
            let env_map: std::collections::HashMap<&str, &str> =
                std::collections::HashMap::from([("DCG_NO_SELF_HEAL", value)]);
            config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));
            assert!(
                config.general.self_heal_hook,
                "DCG_NO_SELF_HEAL={value:?} should not disable self-heal"
            );
        }
    }

    #[test]
    fn test_env_override_hook_timeout_ms() {
        let mut config = Config::default();
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_HOOK_TIMEOUT_MS", "150")]);
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert_eq!(config.general.hook_timeout_ms, Some(150));
        assert_eq!(config.effective_hook_timeout_ms(), 150);
        assert_eq!(config.hook_timeout_source(), "configured");
    }

    #[test]
    fn careful_company_preset_gets_a_larger_default_hook_budget() {
        let default = Config::default();
        assert_eq!(
            default.effective_hook_timeout_ms(),
            crate::perf::HOOK_EVALUATION_BUDGET_MS
        );
        assert_eq!(default.hook_timeout_source(), "default");

        let mut preset = Config::default();
        preset.packs.enabled = vec!["careful_company_running_windows".to_string()];
        assert_eq!(
            preset.effective_hook_timeout_ms(),
            crate::perf::CAREFUL_COMPANY_HOOK_EVALUATION_BUDGET_MS
        );
        assert_eq!(
            preset.hook_timeout_source(),
            "careful_company_running_windows preset"
        );

        preset.general.hook_timeout_ms = Some(750);
        assert_eq!(preset.effective_hook_timeout_ms(), 750);
        assert_eq!(preset.hook_timeout_source(), "configured");

        preset.general.hook_timeout_ms = Some(0);
        assert_eq!(
            preset.effective_hook_timeout_ms(),
            crate::perf::MIN_HOOK_TIMEOUT_MS
        );
    }

    #[test]
    fn test_heredoc_language_filter_all_is_treated_as_unfiltered() {
        let mut config = Config::default();
        config.heredoc.languages = Some(vec!["all".to_string(), "python".to_string()]);
        let settings = config.heredoc_settings();
        assert!(settings.allowed_languages.is_none());
    }

    #[test]
    fn test_heredoc_language_filter_invalid_only_falls_back_to_all() {
        let mut config = Config::default();
        config.heredoc.languages = Some(vec!["definitely_not_a_language".to_string()]);
        let settings = config.heredoc_settings();
        assert!(settings.allowed_languages.is_none());
    }

    #[test]
    fn test_find_repo_root_finds_git_within_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let deep = repo_root.join("a/b/c");
        std::fs::create_dir_all(&deep).expect("create deep dir");

        let found = find_repo_root(&deep, 10).expect("repo root found");
        assert_eq!(found, repo_root);
    }

    #[test]
    fn test_find_repo_root_respects_hop_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        std::fs::create_dir_all(repo_root.join(".git")).expect("create .git");
        let deep = repo_root.join("a/b/c");
        std::fs::create_dir_all(&deep).expect("create deep dir");

        // With a hop limit of 1, we shouldn't reach the repo root from a/b/c.
        assert!(find_repo_root(&deep, 1).is_none());
    }

    // ========================================================================
    // CompiledOverrides Tests (git_safety_guard-99e.4.1)
    // ========================================================================

    #[test]
    fn test_compile_simple_allow_override() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("git reset --hard".to_string())],
            block: vec![],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert!(compiled.check_allow("git reset --hard"));
        assert!(!compiled.check_allow("git status"));
    }

    /// #340: an unanchored allow entry is substring-matched against the whole
    /// command, and `check_allow` short-circuits before pack evaluation. One
    /// matching segment therefore used to carry every other segment with it.
    #[test]
    fn unanchored_allow_override_does_not_launder_later_segments() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple(
                "git stash list /srv/scratch/build".to_string(),
            )],
            block: vec![],
            ..Default::default()
        };
        let compiled = overrides.compile();

        // The entry still allows exactly what it names.
        assert!(compiled.check_allow("git stash list /srv/scratch/build"));

        // But it no longer speaks for a second segment it never matched.
        for command in [
            "git stash list /srv/scratch/build && git reset --hard",
            "git stash list /srv/scratch/build; git reset --hard",
            "git stash list /srv/scratch/build || git reset --hard",
            "git stash list /srv/scratch/build | git reset --hard",
        ] {
            assert!(
                !compiled.check_allow(command),
                "allow entry laundered a trailing segment: {command}"
            );
        }
    }

    /// A command substitution is returned as its own segment, so a safe outer
    /// command cannot carry a destructive inner one past the allow check.
    #[test]
    fn allow_override_does_not_launder_command_substitution() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("echo".to_string())],
            block: vec![],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("echo hello"));
        assert!(!compiled.check_allow("echo $(git reset --hard)"));
    }

    /// Every segment being independently allowed is still allowed, and anchored
    /// entries now compose across a chain (previously neither half matched the
    /// whole string, so the compound was denied).
    #[test]
    fn allow_override_permits_fully_covered_compound() {
        let overrides = OverridesConfig {
            allow: vec![
                AllowOverride::Simple("^git stash list$".to_string()),
                AllowOverride::Simple("^git status$".to_string()),
            ],
            block: vec![],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("git stash list"));
        assert!(compiled.check_allow("git stash list && git status"));
        assert!(compiled.check_allow("git status; git stash list"));
        assert!(!compiled.check_allow("git stash list && git reset --hard"));
    }

    #[test]
    fn test_compile_block_override() {
        let overrides = OverridesConfig {
            allow: vec![],
            block: vec![BlockOverride {
                pattern: "dangerous-command".to_string(),
                reason: "This is dangerous!".to_string(),
            }],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.block.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert_eq!(
            compiled.check_block("dangerous-command --force"),
            Some("This is dangerous!")
        );
        assert_eq!(compiled.check_block("safe-command"), None);
    }

    #[test]
    fn test_compile_invalid_regex_fails_open() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("[invalid regex".to_string())],
            block: vec![BlockOverride {
                pattern: "[also invalid".to_string(),
                reason: "Won't compile".to_string(),
            }],
            ..Default::default()
        };
        let compiled = overrides.compile();

        // Invalid patterns should NOT be in the compiled lists
        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());

        // But they should be recorded in invalid_patterns
        assert_eq!(compiled.invalid_patterns.len(), 2);
        assert!(compiled.has_invalid_patterns());

        // Check that we recorded the right kinds
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Allow)
        );
        assert!(
            compiled
                .invalid_patterns
                .iter()
                .any(|p| p.kind == PatternKind::Block)
        );
    }

    #[test]
    fn test_compile_conditional_override_always() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Conditional {
                pattern: "test-pattern".to_string(),
                when: None,
            }],
            block: vec![],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 1);
        // With no condition, it should always match
        assert!(compiled.check_allow("test-pattern"));
    }

    #[test]
    fn test_compile_regex_pattern() {
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple(
                r"kubectl delete namespace test-\d+".to_string(),
            )],
            block: vec![],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("kubectl delete namespace test-123"));
        assert!(compiled.check_allow("kubectl delete namespace test-999"));
        assert!(!compiled.check_allow("kubectl delete namespace production"));
    }

    #[test]
    fn test_compiled_overrides_engine_selection_lookahead_vs_linear() {
        let overrides = OverridesConfig {
            allow: vec![
                // Lookahead -> must use backtracking engine.
                AllowOverride::Simple(r"git\s+push\s+.*--force(?![-a-z])".to_string()),
                // No lookaround/backrefs -> should use linear engine.
                AllowOverride::Simple(r"test-\d+".to_string()),
            ],
            block: vec![],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.allow.len(), 2);
        assert!(compiled.invalid_patterns.is_empty());

        assert!(
            compiled.allow[0].regex.uses_backtracking(),
            "lookahead patterns must route to fancy_regex"
        );
        assert!(
            !compiled.allow[1].regex.uses_backtracking(),
            "patterns without lookaround/backrefs should route to regex::Regex"
        );

        assert!(compiled.check_allow("git push --force"));
        assert!(compiled.check_allow("git push origin main --force"));
        assert!(!compiled.check_allow("git push --force-with-lease"));

        assert!(compiled.check_allow("test-123"));
        assert!(!compiled.check_allow("test-abc"));
    }

    #[test]
    fn test_compiled_block_override_engine_selection_backreference() {
        let overrides = OverridesConfig {
            allow: vec![],
            block: vec![BlockOverride {
                pattern: r"(\w+)\s+\1".to_string(),
                reason: "duplicate word".to_string(),
            }],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert_eq!(compiled.block.len(), 1);
        assert!(compiled.invalid_patterns.is_empty());
        assert!(
            compiled.block[0].regex.uses_backtracking(),
            "backreference patterns must route to fancy_regex"
        );

        assert_eq!(compiled.check_block("hello hello"), Some("duplicate word"));
        assert_eq!(compiled.check_block("hello world"), None);
    }

    #[test]
    fn test_compiled_overrides_check_order() {
        // Allow takes precedence (checked first in evaluator)
        let overrides = OverridesConfig {
            allow: vec![AllowOverride::Simple("test-command".to_string())],
            block: vec![BlockOverride {
                pattern: "test-command".to_string(),
                reason: "Blocked!".to_string(),
            }],
            ..Default::default()
        };
        let compiled = overrides.compile();

        // Both patterns match
        assert!(compiled.check_allow("test-command"));
        assert!(compiled.check_block("test-command").is_some());

        // In the evaluator, allow is checked first, so command would be allowed
    }

    #[test]
    fn test_compiled_overrides_empty() {
        let overrides = OverridesConfig::default();
        let compiled = overrides.compile();

        assert!(compiled.allow.is_empty());
        assert!(compiled.block.is_empty());
        assert!(!compiled.has_invalid_patterns());
        assert!(!compiled.check_allow("anything"));
        assert!(compiled.check_block("anything").is_none());
    }

    #[test]
    fn test_compiled_overrides_multiple_patterns() {
        let overrides = OverridesConfig {
            allow: vec![
                AllowOverride::Simple("pattern-a".to_string()),
                AllowOverride::Simple("pattern-b".to_string()),
            ],
            block: vec![
                BlockOverride {
                    pattern: "block-1".to_string(),
                    reason: "Reason 1".to_string(),
                },
                BlockOverride {
                    pattern: "block-2".to_string(),
                    reason: "Reason 2".to_string(),
                },
            ],
            ..Default::default()
        };
        let compiled = overrides.compile();

        assert!(compiled.check_allow("pattern-a"));
        assert!(compiled.check_allow("pattern-b"));
        assert!(!compiled.check_allow("pattern-c"));

        assert_eq!(compiled.check_block("block-1"), Some("Reason 1"));
        assert_eq!(compiled.check_block("block-2"), Some("Reason 2"));
        assert_eq!(compiled.check_block("block-3"), None);
    }

    // ========================================================================
    // Removed overrides.allowlist / allowlist_rules keys (#327)
    // ========================================================================

    #[test]
    fn removed_allowlist_keys_are_detected_and_warned() {
        let overrides: OverridesConfig = toml::from_str(
            r#"
            allowlist = ["rm -rf /srv/scratch/build"]

            [[allowlist_rules]]
            pattern = "rm -rf /srv/scratch/build"
            paths = ["/srv/scratch/*"]
            "#,
        )
        .expect("configs carrying the removed keys must still parse");

        let warnings = overrides.removed_key_warnings();
        assert_eq!(
            warnings.len(),
            2,
            "one warning per removed key: {warnings:?}"
        );
        assert!(warnings[0].contains("overrides.allowlist"));
        assert!(warnings[1].contains("overrides.allowlist_rules"));
        assert!(
            warnings.iter().all(|w| w.contains("exempt_target_globs")),
            "warnings must point at a working alternative: {warnings:?}"
        );
    }

    #[test]
    fn removed_allowlist_keys_grant_no_allowances() {
        let overrides: OverridesConfig = toml::from_str(
            r#"
            allowlist = ["rm -rf /srv/scratch/build"]

            [[allowlist_rules]]
            pattern = "rm -rf /srv/scratch/build"
            "#,
        )
        .expect("configs carrying the removed keys must still parse");

        let compiled = overrides.compile();
        assert!(compiled.allow.is_empty());
        assert!(!compiled.check_allow("rm -rf /srv/scratch/build"));
    }

    #[test]
    fn absent_removed_keys_produce_no_warnings() {
        let overrides: OverridesConfig = toml::from_str(
            r#"
            allow = ["^git stash list$"]
            "#,
        )
        .expect("plain overrides must parse");
        assert!(overrides.removed_key_warnings().is_empty());
    }

    // ========================================================================
    // PolicyConfig Tests (git_safety_guard-1gt.3)
    // ========================================================================

    #[test]
    fn test_policy_mode_to_decision_mode() {
        assert_eq!(
            PolicyMode::Deny.to_decision_mode(),
            crate::packs::DecisionMode::Deny
        );
        assert_eq!(
            PolicyMode::Ask.to_decision_mode(),
            crate::packs::DecisionMode::Ask
        );
        assert_eq!(
            PolicyMode::Warn.to_decision_mode(),
            crate::packs::DecisionMode::Warn
        );
        assert_eq!(
            PolicyMode::Log.to_decision_mode(),
            crate::packs::DecisionMode::Log
        );
    }

    #[test]
    fn test_policy_resolve_mode_rule_override_takes_precedence() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Deny),
            observe_until: None,
            packs: std::collections::HashMap::from([("core.git".to_string(), PolicyMode::Warn)]),
            rules: std::collections::HashMap::from([(
                "core.git:reset-hard".to_string(),
                PolicyMode::Log,
            )]),
        };

        // Rule-specific override should win
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_pack_override_when_no_rule() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Deny),
            packs: std::collections::HashMap::from([("core.git".to_string(), PolicyMode::Warn)]),
            ..Default::default()
        };

        // No rule override, so pack override wins
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("push-force"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_resolve_mode_global_default_when_no_pack() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Log),
            ..Default::default()
        };

        // No pack override, so global default wins
        let mode = policy.resolve_mode(
            Some("containers.docker"),
            Some("prune"),
            Some(crate::packs::Severity::Medium),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_severity_default_when_nothing_set() {
        let policy = PolicyConfig::default();

        // High severity defaults to Deny
        let mode_high = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode_high, crate::packs::DecisionMode::Deny);

        // Medium severity defaults to Warn
        let mode_medium = policy.resolve_mode(
            Some("core.git"),
            Some("something"),
            Some(crate::packs::Severity::Medium),
        );
        assert_eq!(mode_medium, crate::packs::DecisionMode::Warn);

        // Low severity defaults to Log
        let mode_low = policy.resolve_mode(
            Some("core.git"),
            Some("something"),
            Some(crate::packs::Severity::Low),
        );
        assert_eq!(mode_low, crate::packs::DecisionMode::Log);
    }

    #[test]
    fn test_policy_resolve_mode_critical_cannot_be_loosened_by_pack() {
        let mut policy = PolicyConfig::default();
        policy
            .packs
            .insert("core.git".to_string(), PolicyMode::Warn);

        // Critical severity should ALWAYS be Deny, even with pack override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_resolve_mode_critical_cannot_be_loosened_by_global() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Log),
            ..Default::default()
        };

        // Critical severity should ALWAYS be Deny, even with global override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_resolve_mode_critical_can_require_review_globally() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Ask),
            ..Default::default()
        };

        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Ask);
    }

    #[test]
    fn test_policy_resolve_mode_critical_can_be_loosened_by_rule() {
        let mut policy = PolicyConfig::default();
        policy
            .rules
            .insert("core.git:reset-hard".to_string(), PolicyMode::Warn);

        // Critical CAN be loosened via explicit per-rule override
        let mode = policy.resolve_mode(
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_resolve_mode_no_severity_defaults_to_deny() {
        let policy = PolicyConfig::default();

        // No severity provided should default to Deny
        let mode = policy.resolve_mode(Some("core.git"), Some("pattern"), None);
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_env_override_default_mode() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_POLICY_DEFAULT_MODE", "warn")]);

        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert_eq!(config.policy.default_mode, Some(PolicyMode::Warn));
    }

    #[test]
    fn test_policy_env_override_observe_until() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_POLICY_OBSERVE_UNTIL", "2030-01-01T00:00:00Z")]);

        let mut config = Config::default();
        config.apply_env_overrides_from(|key| env_map.get(key).map(|v| (*v).to_string()));

        assert_eq!(
            config.policy.observe_until.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
    }

    #[test]
    fn test_policy_env_override_parses_all_modes() {
        for (input, expected) in [
            ("deny", Some(PolicyMode::Deny)),
            ("block", Some(PolicyMode::Deny)),
            ("ask", Some(PolicyMode::Ask)),
            ("review", Some(PolicyMode::Ask)),
            ("warn", Some(PolicyMode::Warn)),
            ("warning", Some(PolicyMode::Warn)),
            ("log", Some(PolicyMode::Log)),
            ("log-only", Some(PolicyMode::Log)),
            ("logonly", Some(PolicyMode::Log)),
            ("DENY", Some(PolicyMode::Deny)), // case-insensitive
            ("invalid", None),
        ] {
            let result = parse_policy_mode(input);
            assert_eq!(result, expected, "parse_policy_mode({input:?}) mismatch");
        }
    }

    #[test]
    fn test_policy_config_merge() {
        let mut base = Config::default();
        base.policy.default_mode = Some(PolicyMode::Deny);
        base.policy.observe_until = ObserveUntil::parse("2000-01-01T00:00:00Z");
        base.policy
            .packs
            .insert("core.git".to_string(), PolicyMode::Deny);

        let other = ConfigLayer {
            policy: Some(PolicyConfig {
                default_mode: Some(PolicyMode::Warn),
                observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
                packs: std::collections::HashMap::from([(
                    "containers.docker".to_string(),
                    PolicyMode::Log,
                )]),
                rules: std::collections::HashMap::from([(
                    "core.git:reset-hard".to_string(),
                    PolicyMode::Log,
                )]),
            }),
            ..Default::default()
        };

        base.merge_layer(other);

        // Other's default_mode should win
        assert_eq!(base.policy.default_mode, Some(PolicyMode::Warn));
        // Other's observe_until should win
        assert_eq!(
            base.policy.observe_until.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        // Both packs should be present
        assert_eq!(base.policy.packs.get("core.git"), Some(&PolicyMode::Deny));
        assert_eq!(
            base.policy.packs.get("containers.docker"),
            Some(&PolicyMode::Log)
        );
        // Rules should be merged
        assert_eq!(
            base.policy.rules.get("core.git:reset-hard"),
            Some(&PolicyMode::Log)
        );
    }

    #[test]
    fn test_sample_config_includes_policy_section() {
        let sample = Config::generate_sample_config();
        assert!(
            sample.contains("[policy]"),
            "Sample config should have [policy] section"
        );
        assert!(
            sample.contains("default_mode"),
            "Sample config should mention default_mode"
        );
        assert!(
            sample.contains("observe_until"),
            "Sample config should mention observe_until"
        );
        assert!(
            sample.contains("[policy.packs]"),
            "Sample config should have [policy.packs]"
        );
        assert!(
            sample.contains("[policy.rules]"),
            "Sample config should have [policy.rules]"
        );
    }

    // ========================================================================
    // Observe mode tests (git_safety_guard-1gt.3.3)
    // ========================================================================

    #[test]
    fn test_policy_observe_window_active_defaults_to_warn_when_unset() {
        let policy = PolicyConfig {
            observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("push-force-long"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Warn);
    }

    #[test]
    fn test_policy_observe_window_expired_ignores_default_mode() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Warn),
            observe_until: ObserveUntil::parse("2026-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("push-force-long"),
            Some(crate::packs::Severity::High),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    #[test]
    fn test_policy_observe_window_active_does_not_loosen_critical_without_rule_override() {
        let policy = PolicyConfig {
            default_mode: Some(PolicyMode::Warn),
            observe_until: ObserveUntil::parse("2030-01-01T00:00:00Z"),
            ..Default::default()
        };

        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc);

        let mode = policy.resolve_mode_at(
            now,
            Some("core.git"),
            Some("reset-hard"),
            Some(crate::packs::Severity::Critical),
        );
        assert_eq!(mode, crate::packs::DecisionMode::Deny);
    }

    // ========================================================================
    // Heredoc allowlist tests (git_safety_guard-cpal)
    // ========================================================================

    #[test]
    fn test_heredoc_allowlist_command_match() {
        let allowlist = HeredocAllowlistConfig {
            commands: vec![
                "./scripts/approved.sh".to_string(),
                "/opt/company/tool".to_string(),
            ],
            ..Default::default()
        };

        assert_eq!(
            allowlist.is_command_allowlisted("./scripts/approved.sh arg1"),
            Some("./scripts/approved.sh")
        );
        assert_eq!(
            allowlist.is_command_allowlisted("/opt/company/tool --flag"),
            Some("/opt/company/tool")
        );
        assert_eq!(allowlist.is_command_allowlisted("./scripts/other.sh"), None);
    }

    #[test]
    fn test_heredoc_allowlist_pattern_match() {
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![
                AllowedHeredocPattern {
                    language: Some("python".to_string()),
                    pattern: "company_tool.cleanup()".to_string(),
                    reason: "Internal tool".to_string(),
                },
                AllowedHeredocPattern {
                    language: None, // any language
                    pattern: "safe_command".to_string(),
                    reason: "Known safe".to_string(),
                },
            ],
            ..Default::default()
        };

        // Python pattern matches python content
        let hit = allowlist.is_content_allowlisted(
            "import company_tool\ncompany_tool.cleanup()",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.kind, HeredocAllowlistHitKind::Pattern);
        assert_eq!(hit.matched, "company_tool.cleanup()");

        // Python pattern does NOT match bash content
        let hit = allowlist.is_content_allowlisted(
            "company_tool.cleanup()",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none());

        // Language-agnostic pattern matches any language
        let hit = allowlist.is_content_allowlisted(
            "run safe_command here",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_some());
    }

    #[test]
    fn test_heredoc_allowlist_hash_match() {
        let content = "specific content to hash";
        let hash = super::content_hash(content);
        assert_eq!(
            hash,
            "71bc8277a3e8d59ec84d4fb69364fcb43805a24d451705e1d5a6d826d1dc644b"
        );

        let allowlist = HeredocAllowlistConfig {
            content_hashes: vec![ContentHashEntry {
                hash: hash.clone(),
                reason: "Approved script".to_string(),
            }],
            ..Default::default()
        };

        let hit =
            allowlist.is_content_allowlisted(content, crate::heredoc::ScriptLanguage::Bash, None);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.kind, HeredocAllowlistHitKind::ContentHash);
        assert_eq!(hit.matched, &hash);

        // Different content should not match
        let hit = allowlist.is_content_allowlisted(
            "different content",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none());
    }

    #[test]
    fn test_heredoc_allowlist_project_scope() {
        let allowlist = HeredocAllowlistConfig {
            projects: vec![ProjectHeredocAllowlist {
                path: "/home/user/trusted-project".to_string(),
                patterns: vec![AllowedHeredocPattern {
                    language: Some("bash".to_string()),
                    pattern: "rm -rf ./build".to_string(),
                    reason: "Build cleanup".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        };

        // Match within project scope
        let hit = allowlist.is_content_allowlisted(
            "rm -rf ./build",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/trusted-project/src")),
        );
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.kind, HeredocAllowlistHitKind::ProjectPattern);

        // No match outside project scope
        let hit = allowlist.is_content_allowlisted(
            "rm -rf ./build",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/other-project")),
        );
        assert!(hit.is_none());

        // No match without project path
        let hit = allowlist.is_content_allowlisted(
            "rm -rf ./build",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none());
    }

    #[test]
    fn test_heredoc_allowlist_merge() {
        let mut base = HeredocAllowlistConfig {
            commands: vec!["cmd1".to_string()],
            patterns: vec![AllowedHeredocPattern {
                language: None,
                pattern: "pattern1".to_string(),
                reason: "reason1".to_string(),
            }],
            ..Default::default()
        };

        let other = HeredocAllowlistConfig {
            commands: vec!["cmd1".to_string(), "cmd2".to_string()], // cmd1 duplicate
            patterns: vec![AllowedHeredocPattern {
                language: None,
                pattern: "pattern2".to_string(),
                reason: "reason2".to_string(),
            }],
            ..Default::default()
        };

        base.merge(&other);

        // Duplicates should not be added
        assert_eq!(base.commands.len(), 2);
        assert!(base.commands.contains(&"cmd1".to_string()));
        assert!(base.commands.contains(&"cmd2".to_string()));

        // Both patterns should be present
        assert_eq!(base.patterns.len(), 2);
    }

    #[test]
    fn test_heredoc_allowlist_hit_kind_labels() {
        assert_eq!(HeredocAllowlistHitKind::ContentHash.label(), "content_hash");
        assert_eq!(HeredocAllowlistHitKind::Pattern.label(), "pattern");
        assert_eq!(
            HeredocAllowlistHitKind::ProjectContentHash.label(),
            "project_content_hash"
        );
        assert_eq!(
            HeredocAllowlistHitKind::ProjectPattern.label(),
            "project_pattern"
        );
    }

    #[test]
    fn test_heredoc_settings_includes_allowlist() {
        let config = HeredocConfig {
            allowlist: Some(HeredocAllowlistConfig {
                commands: vec!["test-cmd".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };

        let settings = config.settings();
        assert!(settings.content_allowlist.is_some());
        let allowlist = settings.content_allowlist.unwrap();
        assert_eq!(allowlist.commands.len(), 1);
    }

    #[test]
    fn test_heredoc_allowlist_project_path_no_false_positive() {
        // Regression test: "/home/user/project" should NOT match "/home/user/project-other"
        let allowlist = HeredocAllowlistConfig {
            projects: vec![ProjectHeredocAllowlist {
                path: "/home/user/project".to_string(),
                patterns: vec![AllowedHeredocPattern {
                    language: Some("bash".to_string()),
                    pattern: "dangerous command".to_string(),
                    reason: "Test".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        };

        // Should NOT match: project-other is a different project
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project-other/src")),
        );
        assert!(hit.is_none(), "Should not match project-other");

        // Should NOT match: projects is a different project
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/projects/src")),
        );
        assert!(hit.is_none(), "Should not match 'projects'");

        // SHOULD match: exact path
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project")),
        );
        assert!(hit.is_some(), "Should match exact path");

        // SHOULD match: subdirectory of project
        let hit = allowlist.is_content_allowlisted(
            "dangerous command",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project/src/lib")),
        );
        assert!(hit.is_some(), "Should match subdirectory");
    }

    #[test]
    fn test_heredoc_allowlist_language_aliases() {
        // Test that language aliases like "js", "sh", "py" work
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![
                AllowedHeredocPattern {
                    language: Some("js".to_string()), // alias for javascript
                    pattern: "console.log".to_string(),
                    reason: "JS logging".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("sh".to_string()), // alias for bash
                    pattern: "echo hello".to_string(),
                    reason: "Shell echo".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("py".to_string()), // alias for python
                    pattern: "print".to_string(),
                    reason: "Python print".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("ts".to_string()), // alias for typescript
                    pattern: "interface".to_string(),
                    reason: "TS interface".to_string(),
                },
                AllowedHeredocPattern {
                    language: Some("node".to_string()), // alias for javascript
                    pattern: "require(".to_string(),
                    reason: "Node require".to_string(),
                },
            ],
            ..Default::default()
        };

        // "js" should match JavaScript
        let hit = allowlist.is_content_allowlisted(
            "console.log('hello')",
            crate::heredoc::ScriptLanguage::JavaScript,
            None,
        );
        assert!(hit.is_some(), "js alias should match JavaScript");

        // "sh" should match Bash
        let hit = allowlist.is_content_allowlisted(
            "echo hello",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_some(), "sh alias should match Bash");

        // "py" should match Python
        let hit = allowlist.is_content_allowlisted(
            "print('hello')",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_some(), "py alias should match Python");

        // "ts" should match TypeScript
        let hit = allowlist.is_content_allowlisted(
            "interface Foo {}",
            crate::heredoc::ScriptLanguage::TypeScript,
            None,
        );
        assert!(hit.is_some(), "ts alias should match TypeScript");

        // "node" should match JavaScript
        let hit = allowlist.is_content_allowlisted(
            "const fs = require('fs')",
            crate::heredoc::ScriptLanguage::JavaScript,
            None,
        );
        assert!(hit.is_some(), "node alias should match JavaScript");

        // "js" should NOT match Python
        let hit = allowlist.is_content_allowlisted(
            "console.log('hello')",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_none(), "js alias should not match Python");
    }

    #[test]
    fn test_heredoc_allowlist_empty_pattern_does_not_match() {
        // Empty patterns should never match (security: prevents accidental allow-all)
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![AllowedHeredocPattern {
                language: None,
                pattern: String::new(), // Empty pattern
                reason: "Empty pattern should not match".to_string(),
            }],
            ..Default::default()
        };

        // Empty pattern should NOT match any content
        let hit = allowlist.is_content_allowlisted(
            "rm -rf /",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_none(), "Empty pattern should not match any content");

        // Even empty content should not match empty pattern
        let hit = allowlist.is_content_allowlisted("", crate::heredoc::ScriptLanguage::Bash, None);
        assert!(
            hit.is_none(),
            "Empty pattern should not match empty content"
        );
    }

    #[test]
    fn test_heredoc_allowlist_empty_command_prefix_does_not_match() {
        // Empty command prefixes should never match (security: prevents accidental allow-all)
        let allowlist = HeredocAllowlistConfig {
            commands: vec![String::new()], // Empty command prefix
            ..Default::default()
        };

        // Empty prefix should NOT match any command
        assert!(
            allowlist.is_command_allowlisted("rm -rf /").is_none(),
            "Empty command prefix should not match any command"
        );

        // Even empty command should not match empty prefix
        assert!(
            allowlist.is_command_allowlisted("").is_none(),
            "Empty command prefix should not match empty command"
        );
    }

    #[test]
    fn test_heredoc_allowlist_empty_project_path_does_not_match() {
        // Empty project paths should never match (security: prevents accidental allow-all)
        let allowlist = HeredocAllowlistConfig {
            projects: vec![ProjectHeredocAllowlist {
                path: String::new(), // Empty project path
                patterns: vec![AllowedHeredocPattern {
                    language: None,
                    pattern: "rm".to_string(),
                    reason: "Test pattern".to_string(),
                }],
                content_hashes: vec![],
            }],
            ..Default::default()
        };

        // Empty project path should NOT match any project
        let hit = allowlist.is_content_allowlisted(
            "rm -rf /",
            crate::heredoc::ScriptLanguage::Bash,
            Some(std::path::Path::new("/home/user/project")),
        );
        assert!(
            hit.is_none(),
            "Empty project path should not match any project"
        );
    }

    #[test]
    fn test_heredoc_allowlist_empty_language_filter_matches_all() {
        // Empty language filter should match all languages (same as `language: None`)
        let allowlist = HeredocAllowlistConfig {
            patterns: vec![AllowedHeredocPattern {
                language: Some(String::new()), // Empty language filter
                pattern: "test_pattern".to_string(),
                reason: "Empty language should match all".to_string(),
            }],
            ..Default::default()
        };

        // Empty language filter should match Bash
        let hit = allowlist.is_content_allowlisted(
            "test_pattern here",
            crate::heredoc::ScriptLanguage::Bash,
            None,
        );
        assert!(hit.is_some(), "Empty language filter should match Bash");

        // Empty language filter should match Python
        let hit = allowlist.is_content_allowlisted(
            "test_pattern here",
            crate::heredoc::ScriptLanguage::Python,
            None,
        );
        assert!(hit.is_some(), "Empty language filter should match Python");

        // Empty language filter should match JavaScript
        let hit = allowlist.is_content_allowlisted(
            "test_pattern here",
            crate::heredoc::ScriptLanguage::JavaScript,
            None,
        );
        assert!(
            hit.is_some(),
            "Empty language filter should match JavaScript"
        );
    }

    // =========================================================================
    // Agent Profile Tests (Epic 9)
    // =========================================================================

    #[test]
    fn test_agents_config_default() {
        let config = AgentsConfig::default();
        assert_eq!(config.default.trust_level, TrustLevel::Medium);
        assert!(config.default.disabled_packs.is_empty());
        assert!(config.default.extra_packs.is_empty());
        assert!(config.default.additional_allowlist.is_empty());
        assert!(!config.default.disabled_allowlist);
        assert!(config.profiles.is_empty());
    }

    #[test]
    fn test_agents_config_profile_for_known_agent() {
        let mut config = AgentsConfig::default();
        config.profiles.insert(
            "claude-code".to_string(),
            AgentProfile {
                trust_level: TrustLevel::High,
                ..Default::default()
            },
        );

        let profile = config.profile_for("claude-code");
        assert_eq!(profile.trust_level, TrustLevel::High);
    }

    #[test]
    fn test_agents_config_profile_for_unknown_falls_back_to_default() {
        let mut config = AgentsConfig::default();
        config.default.trust_level = TrustLevel::Low;

        let profile = config.profile_for("nonexistent-agent");
        assert_eq!(profile.trust_level, TrustLevel::Low);
    }

    #[test]
    fn test_agents_config_profile_for_unknown_with_unknown_profile() {
        let mut config = AgentsConfig::default();
        config.profiles.insert(
            "unknown".to_string(),
            AgentProfile {
                trust_level: TrustLevel::Low,
                disabled_allowlist: true,
                ..Default::default()
            },
        );

        // Unrecognized agents should use the "unknown" profile
        let profile = config.profile_for("some-new-agent");
        assert_eq!(profile.trust_level, TrustLevel::Low);
        assert!(profile.disabled_allowlist);

        // The "unknown" key itself should also match
        let profile = config.profile_for("unknown");
        assert_eq!(profile.trust_level, TrustLevel::Low);
    }

    #[test]
    fn test_agents_config_profile_aliases_match_agent_detection_names() {
        use crate::agent::Agent;

        let mut config = AgentsConfig::default();
        config.profiles.insert(
            "codex".to_string(),
            AgentProfile {
                trust_level: TrustLevel::High,
                extra_packs: vec!["strict_git".to_string()],
                ..Default::default()
            },
        );
        config.profiles.insert(
            "claude_code".to_string(),
            AgentProfile {
                trust_level: TrustLevel::Low,
                disabled_allowlist: true,
                ..Default::default()
            },
        );
        config.profiles.insert(
            "oh-my-pi".to_string(),
            AgentProfile {
                trust_level: TrustLevel::High,
                additional_allowlist: vec!["cargo test".to_string()],
                ..Default::default()
            },
        );

        let codex_profile = config.profile_for_agent(&Agent::CodexCli);
        assert_eq!(codex_profile.trust_level, TrustLevel::High);
        assert!(
            codex_profile
                .extra_packs
                .contains(&"strict_git".to_string())
        );

        let claude_profile = config.profile_for("claude-code");
        assert_eq!(claude_profile.trust_level, TrustLevel::Low);
        assert!(claude_profile.disabled_allowlist);

        let omp_profile = config.profile_for_agent(&Agent::Omp);
        assert_eq!(omp_profile.trust_level, TrustLevel::High);
        assert!(
            omp_profile
                .additional_allowlist
                .contains(&"cargo test".to_string())
        );
    }

    #[test]
    fn test_agents_config_canonical_profile_key_takes_precedence_over_alias() {
        use crate::agent::Agent;

        let mut config = AgentsConfig::default();
        config.profiles.insert(
            "codex".to_string(),
            AgentProfile {
                trust_level: TrustLevel::Low,
                ..Default::default()
            },
        );
        config.profiles.insert(
            "codex-cli".to_string(),
            AgentProfile {
                trust_level: TrustLevel::High,
                ..Default::default()
            },
        );

        assert_eq!(
            config.profile_for_agent(&Agent::CodexCli).trust_level,
            TrustLevel::High
        );
    }

    #[test]
    fn test_agents_config_from_toml() {
        let input = r#"
[agents]
[agents.default]
trust_level = "low"
disabled_packs = ["kubernetes"]

[agents.claude-code]
trust_level = "high"
extra_packs = ["database.postgresql"]
additional_allowlist = ["git push origin main"]
"#;
        let config: Config = toml::from_str(input).expect("config parses");
        assert_eq!(config.agents.default.trust_level, TrustLevel::Low);
        assert!(
            config
                .agents
                .default
                .disabled_packs
                .contains(&"kubernetes".to_string())
        );

        let claude_profile = config.agents.profile_for("claude-code");
        assert_eq!(claude_profile.trust_level, TrustLevel::High);
        assert!(
            claude_profile
                .extra_packs
                .contains(&"database.postgresql".to_string())
        );
        assert!(
            claude_profile
                .additional_allowlist
                .contains(&"git push origin main".to_string())
        );
    }

    #[test]
    fn test_enabled_pack_ids_for_agent_with_disabled_packs() {
        use crate::agent::Agent;

        let mut config = Config::default();
        config.packs.enabled = vec![
            "kubernetes".to_string(),
            "kubernetes.helm".to_string(),
            "database.postgresql".to_string(),
        ];
        config.agents.profiles.insert(
            "aider".to_string(),
            AgentProfile {
                disabled_packs: vec!["kubernetes".to_string()],
                ..Default::default()
            },
        );

        let packs = config.enabled_pack_ids_for_agent(&Agent::Aider);

        // kubernetes and its sub-packs should be removed
        assert!(!packs.contains("kubernetes"));
        assert!(!packs.contains("kubernetes.helm"));
        // Other packs should remain
        assert!(packs.contains("database.postgresql"));
        // Core is always present
        assert!(packs.contains("core"));
    }

    #[test]
    fn test_enabled_pack_ids_for_agent_with_extra_packs() {
        use crate::agent::Agent;

        let config = Config {
            agents: AgentsConfig {
                profiles: {
                    let mut m = std::collections::HashMap::new();
                    m.insert(
                        "claude-code".to_string(),
                        AgentProfile {
                            extra_packs: vec!["containers.docker".to_string()],
                            ..Default::default()
                        },
                    );
                    m
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let packs = config.enabled_pack_ids_for_agent(&Agent::ClaudeCode);
        assert!(packs.contains("containers.docker"));
        assert!(packs.contains("core"));
    }

    #[test]
    fn test_agent_disabled_leaf_is_not_reintroduced_by_extra_category() {
        use crate::agent::Agent;

        let mut config = Config::default();
        config.agents.profiles.insert(
            "claude-code".to_string(),
            AgentProfile {
                extra_packs: vec!["kubernetes".to_string()],
                disabled_packs: vec!["kubernetes.helm".to_string()],
                ..Default::default()
            },
        );

        let packs = config.enabled_pack_ids_for_agent(&Agent::ClaudeCode);
        assert!(packs.contains("kubernetes.kubectl"));
        assert!(packs.contains("kubernetes.kustomize"));
        assert!(!packs.contains("kubernetes.helm"));
        assert!(
            !packs.contains("kubernetes"),
            "a surviving category marker would reintroduce the disabled leaf"
        );
    }

    #[test]
    fn agent_profile_cannot_disable_mandatory_core_packs() {
        use crate::agent::Agent;

        let mut config = Config::default();
        config.agents.profiles.insert(
            "claude-code".to_string(),
            AgentProfile {
                disabled_packs: vec!["core".to_string()],
                ..Default::default()
            },
        );

        let packs = config.enabled_pack_ids_for_agent(&Agent::ClaudeCode);
        assert!(
            packs.contains("core"),
            "agent-level exclusions must preserve the mandatory core marker: {packs:?}"
        );
        let ordered = crate::packs::REGISTRY.expand_enabled_ordered(&packs);
        assert!(ordered.iter().any(|pack| pack == "core.git"));
        assert!(ordered.iter().any(|pack| pack == "core.filesystem"));
    }

    #[test]
    fn agent_can_cancel_preset_without_removing_independent_members() {
        use crate::agent::Agent;

        let mut config = Config::default();
        config.packs.enabled = vec![
            "careful_company_running_windows".to_string(),
            "cloud".to_string(),
            "database.snowflake".to_string(),
        ];
        config.agents.profiles.insert(
            "claude-code".to_string(),
            AgentProfile {
                disabled_packs: vec!["careful_company_running_windows".to_string()],
                ..Default::default()
            },
        );

        let packs = config.enabled_pack_ids_for_agent(&Agent::ClaudeCode);
        assert!(
            !packs
                .iter()
                .any(|pack_id| pack_id.starts_with("careful_company_running_windows.")),
            "agent exclusion must remove the preset leaves: {packs:?}"
        );
        for cloud_pack in ["cloud.aws", "cloud.gcp", "cloud.azure"] {
            assert!(
                packs.contains(cloud_pack),
                "profile preset cancellation must preserve base category enablement: {packs:?}"
            );
        }
        assert!(packs.contains("database.snowflake"));
        assert!(!packs.contains("remote.scp"));
    }

    #[test]
    fn test_trust_level_for_agent() {
        use crate::agent::Agent;

        let mut config = Config::default();
        config.agents.default.trust_level = TrustLevel::Medium;
        config.agents.profiles.insert(
            "claude-code".to_string(),
            AgentProfile {
                trust_level: TrustLevel::High,
                ..Default::default()
            },
        );
        config.agents.profiles.insert(
            "unknown".to_string(),
            AgentProfile {
                trust_level: TrustLevel::Low,
                ..Default::default()
            },
        );

        assert_eq!(
            config.trust_level_for_agent(&Agent::ClaudeCode),
            TrustLevel::High
        );
        assert_eq!(config.trust_level_for_agent(&Agent::Aider), TrustLevel::Low); // Falls back to unknown
        assert_eq!(
            config.trust_level_for_agent(&Agent::Unknown),
            TrustLevel::Low
        );
    }

    #[test]
    fn test_allowlist_disabled_for_agent() {
        use crate::agent::Agent;

        let mut config = Config::default();
        // Set up a specific profile for claude-code
        config.agents.profiles.insert(
            "claude-code".to_string(),
            AgentProfile {
                disabled_allowlist: false,
                ..Default::default()
            },
        );
        // Set up the unknown profile with disabled allowlist
        config.agents.profiles.insert(
            "unknown".to_string(),
            AgentProfile {
                disabled_allowlist: true,
                ..Default::default()
            },
        );

        // ClaudeCode has explicit profile with disabled_allowlist: false
        assert!(!config.allowlist_disabled_for_agent(&Agent::ClaudeCode));
        // Unknown agents fall back to "unknown" profile
        assert!(config.allowlist_disabled_for_agent(&Agent::Unknown));
        // Aider has no profile, falls back to "unknown"
        assert!(config.allowlist_disabled_for_agent(&Agent::Aider));
    }

    #[test]
    fn test_additional_allowlist_for_agent() {
        use crate::agent::Agent;

        let mut config = Config::default();
        config.agents.profiles.insert(
            "claude-code".to_string(),
            AgentProfile {
                additional_allowlist: vec![
                    "git push origin main".to_string(),
                    "npm publish".to_string(),
                ],
                ..Default::default()
            },
        );

        let allowlist = config.additional_allowlist_for_agent(&Agent::ClaudeCode);
        assert_eq!(allowlist.len(), 2);
        assert!(allowlist.contains(&"git push origin main".to_string()));
        assert!(allowlist.contains(&"npm publish".to_string()));

        // Agent without profile should have empty additional allowlist
        let allowlist = config.additional_allowlist_for_agent(&Agent::Aider);
        assert!(allowlist.is_empty());
    }

    #[test]
    fn test_agents_config_layer_merge() {
        let mut config = Config::default();
        config.agents.default.trust_level = TrustLevel::Medium;

        let layer: ConfigLayer = toml::from_str(
            r#"
[agents.default]
trust_level = "low"
disabled_packs = ["kubernetes"]

[agents.claude-code]
trust_level = "high"
"#,
        )
        .expect("layer parses");

        config.merge_layer(layer);

        assert_eq!(config.agents.default.trust_level, TrustLevel::Low);
        assert!(
            config
                .agents
                .default
                .disabled_packs
                .contains(&"kubernetes".to_string())
        );
        assert_eq!(
            config.agents.profile_for("claude-code").trust_level,
            TrustLevel::High
        );
    }

    // =========================================================================
    // Graduated Response Config Tests
    // =========================================================================

    #[test]
    fn test_response_config_defaults() {
        let config = ResponseConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.mode, GraduationMode::Standard);
        assert_eq!(config.session_warning_count, 1);
        assert_eq!(config.session_soft_block, 2);
        assert_eq!(config.history_soft_block, 3);
        assert_eq!(config.history_hard_block, 5);
        assert_eq!(config.history_window, "24h");
    }

    #[test]
    fn test_response_config_is_enabled() {
        let mut config = ResponseConfig::default();
        assert!(!config.is_enabled());
        config.enabled = true;
        assert!(config.is_enabled());
    }

    #[test]
    fn test_graduation_mode_display() {
        assert_eq!(GraduationMode::Paranoid.to_string(), "paranoid");
        assert_eq!(GraduationMode::Strict.to_string(), "strict");
        assert_eq!(GraduationMode::Standard.to_string(), "standard");
        assert_eq!(GraduationMode::Lenient.to_string(), "lenient");
        assert_eq!(GraduationMode::WarningOnly.to_string(), "warning_only");
        assert_eq!(GraduationMode::Disabled.to_string(), "disabled");
    }

    #[test]
    fn test_graduation_mode_serde_roundtrip() {
        for mode in [
            GraduationMode::Paranoid,
            GraduationMode::Strict,
            GraduationMode::Standard,
            GraduationMode::Lenient,
            GraduationMode::WarningOnly,
            GraduationMode::Disabled,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: GraduationMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back, "roundtrip failed for {mode}");
        }
    }

    #[test]
    fn test_effective_mode_severity_defaults() {
        let config = ResponseConfig::default();
        // Critical defaults to Paranoid
        assert_eq!(
            config.effective_mode(crate::packs::Severity::Critical),
            GraduationMode::Paranoid
        );
        // Low defaults to WarningOnly
        assert_eq!(
            config.effective_mode(crate::packs::Severity::Low),
            GraduationMode::WarningOnly
        );
        // High/Medium default to global mode (Standard)
        assert_eq!(
            config.effective_mode(crate::packs::Severity::High),
            GraduationMode::Standard
        );
        assert_eq!(
            config.effective_mode(crate::packs::Severity::Medium),
            GraduationMode::Standard
        );
    }

    #[test]
    fn test_effective_mode_explicit_override_wins() {
        let mut config = ResponseConfig::default();
        config.severity_overrides.critical = Some(GraduationMode::Lenient);
        assert_eq!(
            config.effective_mode(crate::packs::Severity::Critical),
            GraduationMode::Lenient
        );
    }

    #[test]
    fn test_response_config_from_toml() {
        let input = r#"
[response]
enabled = true
mode = "strict"
session_warning_count = 2
session_soft_block = 4
history_soft_block = 6
history_hard_block = 10
history_window = "48h"

[response.severity_overrides]
critical = "paranoid"
low = "disabled"
"#;
        let config: Config = toml::from_str(input).unwrap();
        assert!(config.response.enabled);
        assert_eq!(config.response.mode, GraduationMode::Strict);
        assert_eq!(config.response.session_warning_count, 2);
        assert_eq!(config.response.session_soft_block, 4);
        assert_eq!(config.response.history_soft_block, 6);
        assert_eq!(config.response.history_hard_block, 10);
        assert_eq!(config.response.history_window, "48h");
        assert_eq!(
            config.response.severity_overrides.critical,
            Some(GraduationMode::Paranoid)
        );
        assert_eq!(
            config.response.severity_overrides.low,
            Some(GraduationMode::Disabled)
        );
        assert_eq!(config.response.severity_overrides.high, None);
    }

    #[test]
    fn test_response_config_layer_merge() {
        let mut config = Config::default();
        assert!(!config.response.enabled);
        assert_eq!(config.response.mode, GraduationMode::Standard);

        let layer = ConfigLayer {
            response: Some(ResponseConfigLayer {
                enabled: Some(true),
                mode: Some(GraduationMode::Strict),
                session_warning_count: None,
                session_soft_block: Some(5),
                history_soft_block: None,
                history_hard_block: None,
                history_window: None,
                severity_overrides: None,
            }),
            ..ConfigLayer::default()
        };
        config.merge_layer(layer);
        assert!(config.response.enabled);
        assert_eq!(config.response.mode, GraduationMode::Strict);
        // Unset fields retain defaults
        assert_eq!(config.response.session_warning_count, 1);
        assert_eq!(config.response.session_soft_block, 5);
    }

    #[test]
    fn test_sample_config_includes_response_section() {
        let sample = Config::generate_sample_config();
        assert!(sample.contains("[response]"));
        assert!(sample.contains("mode = \"standard\""));
        // Ensure it still parses
        toml::from_str::<Config>(&sample).expect("sample config with [response] parses");
    }

    #[test]
    fn test_expand_custom_paths_repo_root_token() {
        // Build a temp repo with a .git marker and a pack file inside it.
        let tmp = tempfile::tempdir().expect("tmp");
        let repo = tmp.path().join("myrepo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join(".dcg/packs")).unwrap();
        std::fs::write(repo.join(".dcg/packs/team.yaml"), "# pack").unwrap();

        // cwd is a subdirectory of the repo — walk-up should find the root.
        let subdir = repo.join("a/b/c");
        std::fs::create_dir_all(&subdir).unwrap();

        let packs = PacksConfig {
            custom_paths: vec!["${repo_root}/.dcg/packs/*.yaml".to_string()],
            ..PacksConfig::default()
        };

        let resolved = packs.expand_custom_paths_from(Some(&subdir));
        assert_eq!(resolved.len(), 1, "should resolve one pack file");
        assert!(resolved[0].ends_with("team.yaml"));
    }

    #[test]
    fn test_expand_custom_paths_repo_root_no_repo() {
        // cwd is outside any repo — entry referencing ${repo_root} should silently skip.
        let tmp = tempfile::tempdir().expect("tmp");
        let nonrepo = tmp.path().join("nonrepo");
        std::fs::create_dir_all(&nonrepo).unwrap();

        let packs = PacksConfig {
            custom_paths: vec![
                "${repo_root}/.dcg/packs/*.yaml".to_string(),
                // Literal entry without the token still resolves normally.
                tmp.path().join("nope.yaml").to_string_lossy().into_owned(),
            ],
            ..PacksConfig::default()
        };

        let resolved = packs.expand_custom_paths_from(Some(&nonrepo));
        assert!(
            resolved.is_empty(),
            "no repo root → token entry skipped, literal missing → empty"
        );
    }

    // ========================================================================
    // Bounded config file reads (git_safety_guard-tck0)
    // ========================================================================

    #[test]
    fn read_config_file_bounded_returns_content_under_cap() {
        use tempfile::TempDir;
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        let payload = "key = \"value\"\n".to_string();
        std::fs::write(&path, &payload).unwrap();

        let read = read_config_file_bounded(&path, ConfigSource::Untrusted)
            .expect("should read file under cap");
        assert_eq!(read, payload);
    }

    #[test]
    fn read_config_file_bounded_rejects_oversized_file() {
        use tempfile::TempDir;
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        // Write MAX_CONFIG_BYTES + 64 bytes — comfortably above the cap.
        let payload = "x".repeat(usize::try_from(MAX_CONFIG_BYTES).unwrap_or(usize::MAX) + 64);
        std::fs::write(&path, &payload).unwrap();

        let read = read_config_file_bounded(&path, ConfigSource::Untrusted);
        assert!(
            read.is_none(),
            "files exceeding MAX_CONFIG_BYTES must be rejected"
        );
    }

    #[test]
    fn read_config_file_bounded_returns_none_for_missing_path() {
        let path =
            std::env::temp_dir().join(format!("dcg-config-missing-{}-{}", std::process::id(), 42));
        let read = read_config_file_bounded(&path, ConfigSource::Untrusted);
        assert!(read.is_none());
        // Same for system source.
        let read = read_config_file_bounded(&path, ConfigSource::System);
        assert!(read.is_none());
    }

    #[test]
    fn auto_project_parse_error_never_reflects_source_bytes() {
        let secret_marker = "DO_NOT_REFLECT_THIS_REPOSITORY_TEXT";
        let input = format!(
            "[general]\nfail_closed = \u{1b}[31m{secret_marker}{}\n",
            "x".repeat(16_384)
        );
        let error =
            toml::from_str::<ConfigLayer>(&input).expect_err("fixture must be invalid TOML");

        let rendered = safe_auto_project_toml_error(&input, &error);
        assert!(rendered.starts_with("Invalid TOML in automatic project config"));
        assert!(!rendered.contains(secret_marker));
        assert!(!rendered.contains('\u{1b}'));
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.len() < 128);
    }

    #[test]
    fn config_source_outcomes_are_lazy_and_authority_aware() {
        use tempfile::TempDir;

        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "[general]\nfail_closed = true\n").unwrap();

        let (untraced_layer, untraced_outcome) = Config::load_layer_from_file_with_outcome(
            &path,
            ConfigSource::Untrusted,
            ConfigFileLayer::User,
            ConfigFileAuthority::Full,
            false,
        );
        assert!(untraced_layer.is_some());
        assert!(
            untraced_outcome.is_none(),
            "hot-path loading must not allocate a diagnostic outcome"
        );

        let (traced_layer, traced_outcome) = Config::load_layer_from_file_with_outcome(
            &path,
            ConfigSource::AutoProject,
            ConfigFileLayer::AutomaticProject,
            ConfigFileAuthority::EnforcementOnly,
            true,
        );
        assert!(traced_layer.is_some());
        let traced_outcome = traced_outcome.expect("tracing requested");
        assert_eq!(traced_outcome.status, ConfigFileStatus::Loaded);
        assert_eq!(
            traced_outcome.authority,
            ConfigFileAuthority::EnforcementOnly
        );
        assert_eq!(traced_outcome.path.as_deref(), Some(path.as_path()));
    }

    #[cfg(unix)]
    #[test]
    fn unix_system_leaf_policy_checks_owner_and_write_mode() {
        // Root-owned, owner-writable files are trusted: only root can change
        // their contents or mode.
        assert!(!unix_owner_or_mode_is_user_writable(0, 0o100_644));

        // These are the vulnerable cases that a parent-only check misses.
        assert!(unix_owner_or_mode_is_user_writable(0, 0o100_664));
        assert!(unix_owner_or_mode_is_user_writable(0, 0o100_646));

        // A non-root owner can chmod a read-only file and then replace its
        // contents, so current write bits alone are not enough.
        assert!(unix_owner_or_mode_is_user_writable(1000, 0o100_444));
    }

    #[cfg(unix)]
    #[test]
    fn unix_opened_file_identity_binds_descriptor_to_current_path() {
        use tempfile::TempDir;

        let temp = TempDir::new().expect("tempdir");
        let first_path = temp.path().join("first.toml");
        let second_path = temp.path().join("second.toml");
        std::fs::write(&first_path, "key = 1").unwrap();
        std::fs::write(&second_path, "key = 2").unwrap();

        let first_file = std::fs::File::open(&first_path).unwrap();
        let opened = first_file.metadata().unwrap();
        let current = std::fs::symlink_metadata(&first_path).unwrap();
        let other = std::fs::symlink_metadata(&second_path).unwrap();

        assert!(unix_metadata_refers_to_same_file(&opened, &current));
        assert!(!unix_metadata_refers_to_same_file(&opened, &other));
    }

    #[cfg(unix)]
    #[test]
    fn unix_system_ancestor_policy_rejects_relative_writable_and_symlinked_paths() {
        use tempfile::TempDir;

        assert_eq!(
            validate_unix_system_ancestor_chain(Path::new("relative/config.toml")),
            Err(UnixConfigTrustError::PathMustBeAbsoluteAndNormalized)
        );

        // Only the ancestor chain is inspected here, so a hypothetical direct
        // leaf beneath the trusted Unix root has a valid chain.
        assert_eq!(
            validate_unix_system_ancestor_chain(Path::new("/config.toml")),
            Ok(())
        );

        let temp = TempDir::new().expect("tempdir");
        assert_eq!(
            validate_unix_system_ancestor_chain(&temp.path().join("config.toml")),
            Err(UnixConfigTrustError::UntrustedOwnerOrMode)
        );

        // The first examined directory resolves through the link to `/etc`,
        // but the next lexical ancestor is the link itself. Using
        // symlink_metadata rather than canonicalize must expose and reject it.
        let linked_root = temp.path().join("linked-root");
        std::os::unix::fs::symlink("/", &linked_root).unwrap();
        assert_eq!(
            validate_unix_system_ancestor_chain(&linked_root.join("etc/config.toml")),
            Err(UnixConfigTrustError::Symlink)
        );
    }

    #[cfg(unix)]
    #[test]
    fn auto_project_reads_direct_regular_file_but_rejects_symlink() {
        use tempfile::TempDir;

        let temp = TempDir::new().expect("tempdir");
        let target = temp.path().join("target.toml");
        let link = temp.path().join(".dcg.toml");
        let payload = "[general]\nfail_closed = true\n";
        std::fs::write(&target, payload).unwrap();
        std::fs::create_dir(temp.path().join(".git")).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(
            read_config_file_bounded(&target, ConfigSource::AutoProject).as_deref(),
            Some(payload)
        );
        assert!(read_config_file_bounded(&link, ConfigSource::AutoProject).is_none());
        assert!(
            Config::load_project_config_layer_from(Some(temp.path())).is_none(),
            "automatic project discovery must use the no-symlink source policy"
        );

        // Explicit/user-selected config paths retain their documented symlink
        // behavior; only automatic repository discovery is restricted.
        assert_eq!(
            read_config_file_bounded(&link, ConfigSource::Untrusted).as_deref(),
            Some(payload)
        );

        let (_, outcome) = Config::load_layer_from_file_with_outcome(
            &link,
            ConfigSource::AutoProject,
            ConfigFileLayer::AutomaticProject,
            ConfigFileAuthority::EnforcementOnly,
            true,
        );
        assert_eq!(
            outcome.expect("tracing requested").status,
            ConfigFileStatus::Rejected
        );
    }

    #[cfg(unix)]
    #[test]
    fn auto_project_rejects_directory_and_fifo_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;
        use tempfile::TempDir;

        let temp = TempDir::new().expect("tempdir");
        assert!(read_config_file_bounded(temp.path(), ConfigSource::AutoProject).is_none());

        let fifo = temp.path().join("config.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo must create the test fixture");

        let fifo_for_reader = fifo.clone();
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let result = read_config_file_bounded(&fifo_for_reader, ConfigSource::AutoProject);
            sender.send(result).unwrap();
        });

        let (timed_out, result) = match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => (false, result),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Unblock a regressed blocking open before failing, so the test
                // suite never leaves a stuck reader thread behind.
                let writer = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&fifo)
                    .expect("open FIFO writer to release blocked reader");
                let result = receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("blocked FIFO reader must exit once paired");
                drop(writer);
                (true, result)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("FIFO reader disconnected without reporting a result")
            }
        };
        reader.join().expect("FIFO reader thread");

        assert!(
            !timed_out,
            "restricted config open must never block on a FIFO"
        );
        assert!(result.is_none(), "a FIFO must never be parsed as config");
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_system_config_is_ignored_even_when_regular() {
        use tempfile::TempDir;

        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "key = \"value\"").unwrap();

        assert!(read_config_file_bounded(&path, ConfigSource::System).is_none());
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_auto_project_config_is_ignored_even_when_regular() {
        use tempfile::TempDir;

        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join(".dcg.toml");
        std::fs::write(&path, "[general]\nfail_closed = true\n").unwrap();

        assert!(read_config_file_bounded(&path, ConfigSource::AutoProject).is_none());
        let (_, outcome) = Config::load_layer_from_file_with_outcome(
            &path,
            ConfigSource::AutoProject,
            ConfigFileLayer::AutomaticProject,
            ConfigFileAuthority::EnforcementOnly,
            true,
        );
        assert_eq!(
            outcome.expect("tracing requested").status,
            ConfigFileStatus::IgnoredUnsupported
        );
        assert!(
            read_config_file_bounded(
                &temp.path().join("missing.dcg.toml"),
                ConfigSource::AutoProject
            )
            .is_none()
        );
    }

    // -------------------------------------------------------------------------
    // Per-rule target-path exemptions (#284)
    // -------------------------------------------------------------------------

    fn exemptions_from(toml_text: &str) -> RuleTargetExemptions {
        let config: Config = toml::from_str(toml_text).expect("parse rules config");
        config.rule_target_exemptions()
    }

    #[test]
    fn rule_target_glob_matches_literal_subpath() {
        let exemptions = exemptions_from(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/srv/jobs/*/tmp/**"]
"#,
        );
        assert_eq!(
            exemptions.matching_glob("core.filesystem:rm-rf-general", "/srv/jobs/abc/tmp/scratch"),
            Some("/srv/jobs/*/tmp/**")
        );
    }

    #[test]
    fn rule_target_glob_is_scoped_to_its_own_rule() {
        let exemptions = exemptions_from(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/srv/jobs/*/tmp/**"]
"#,
        );
        assert_eq!(
            exemptions.matching_glob(
                "core.filesystem:redirect-truncate-root-home",
                "/srv/jobs/abc/tmp/scratch"
            ),
            None
        );
    }

    #[test]
    fn rule_target_single_star_does_not_cross_a_separator() {
        let exemptions = exemptions_from(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/srv/jobs/*/tmp/**"]
"#,
        );
        assert_eq!(
            exemptions.matching_glob("core.filesystem:rm-rf-general", "/srv/jobs/a/b/tmp/scratch"),
            None
        );
    }

    #[test]
    fn rule_target_rejects_dotdot_traversal() {
        let exemptions = exemptions_from(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/srv/jobs/*/tmp/**"]
"#,
        );
        assert_eq!(
            exemptions.matching_glob(
                "core.filesystem:rm-rf-general",
                "/srv/jobs/abc/tmp/../../../Documents"
            ),
            None
        );
    }

    #[test]
    fn rule_target_rejects_expansion_and_glob_syntax() {
        let exemptions = exemptions_from(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/srv/jobs/*/tmp/**"]
"#,
        );
        for dynamic in [
            "$DIR/tmp/scratch",
            "/srv/jobs/${ID}/tmp/scratch",
            "/srv/jobs/`id`/tmp/scratch",
            "/srv/jobs/*/tmp/scratch",
            "%TEMP%/scratch",
        ] {
            assert_eq!(
                exemptions.matching_glob("core.filesystem:rm-rf-general", dynamic),
                None,
                "dynamic target {dynamic} must never be exempted"
            );
        }
    }

    #[test]
    fn rule_target_normalizes_dot_and_duplicate_separators() {
        let exemptions = exemptions_from(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/srv/jobs/*/tmp/**"]
"#,
        );
        assert_eq!(
            exemptions.matching_glob(
                "core.filesystem:rm-rf-general",
                "/srv//jobs/abc/./tmp/scratch"
            ),
            Some("/srv/jobs/*/tmp/**")
        );
    }

    #[test]
    fn rule_target_exemption_ignored_for_unsupported_rule() {
        let config: Config = toml::from_str(
            r#"
[rules."core.git:reset-hard"]
exempt_target_globs = ["/srv/**"]
"#,
        )
        .expect("parse rules config");
        assert!(config.rule_target_exemptions().is_empty());
        let warnings = config.rule_target_exemption_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("does not support target exemptions"));
    }

    #[test]
    fn rule_target_empty_and_invalid_globs_are_reported() {
        let config: Config = toml::from_str(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["", "/srv/a**b/**"]
"#,
        )
        .expect("parse rules config");
        let warnings = config.rule_target_exemption_warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("must not be empty")));
        assert!(config.rule_target_exemptions().is_empty());
    }

    #[test]
    fn rule_target_glob_with_dotdot_is_rejected_at_load() {
        let config: Config = toml::from_str(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/srv/jobs/../**"]
"#,
        )
        .expect("parse rules config");
        assert!(config.rule_target_exemptions().is_empty());
        assert!(
            config
                .rule_target_exemption_warnings()
                .iter()
                .any(|w| w.contains("`..`"))
        );
    }

    #[test]
    fn automatic_project_config_cannot_grant_a_target_exemption() {
        // #284: `exempt_target_globs` reduces coverage, so a repository-authored
        // `.dcg.toml` must never contribute one.
        let layer: ConfigLayer = toml::from_str(
            r#"
[rules."core.filesystem:rm-rf-general"]
exempt_target_globs = ["/**"]
"#,
        )
        .expect("parse project config layer");
        assert!(layer.rules.is_some(), "layer should parse the table");
        assert!(
            layer.into_restricted_project_policy().rules.is_none(),
            "an automatically discovered .dcg.toml must not carry [rules] exemptions"
        );
    }
}
