//! Feature flag service packs - protections for feature flag management platforms.
//!
//! Provides protection for:
//! - `LaunchDarkly` (`ldcli` and API)
//! - `Split.io`
//! - `Flipt`
//! - `Unleash`

pub mod flipt;
pub mod launchdarkly;
pub mod split;
pub mod unleash;
