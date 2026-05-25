//! End-to-End Test Framework for DCG
//!
//! This module provides comprehensive E2E testing infrastructure that serves as
//! the foundation for testing across all DCG epics. It offers:
//!
//! - **Test Context Management**: Isolated test environments with temp directories,
//!   config files, and environment variable control.
//! - **DCG Binary Interaction**: Helpers to run the DCG binary with various inputs
//!   and validate outputs.
//! - **Detailed Logging**: Structured logging for debugging test failures.
//! - **Fixtures**: Pre-defined configs, commands, and mock git repos.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        E2E Test Suite                           │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  test_pattern_testing.rs   │ Epic 1: Pattern testing tool       │
//! │  test_explanations.rs      │ Epic 2: Natural language           │
//! │  test_suggestions.rs       │ Epic 3: Command rewriting          │
//! │  test_auto_suggest.rs      │ Epic 4: Automatic suggestions      │
//! │  test_path_allowlist.rs    │ Epic 5: Context-aware allowlist    │
//! │  test_temp_allowlist.rs    │ Epic 6: Temporary/expiring rules   │
//! │  test_interactive.rs       │ Epic 7: Interactive learning       │
//! │  test_git_awareness.rs     │ Epic 8: Git branch awareness       │
//! │  test_agent_profiles.rs    │ Epic 9: Agent-specific profiles    │
//! │  test_graduated_response.rs│ Epic 10: Graduated response        │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Framework (framework.rs)                    │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  E2ETestContext  │ Isolated test environment                    │
//! │  DcgOutput       │ Captured stdout/stderr/exit code             │
//! │  TestAssertion   │ Fluent assertions for test outcomes          │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Logging (logging.rs)                       │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  TestLogger      │ Detailed, parseable test logs                │
//! │  TestReport      │ Summary report generation                    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use tests::e2e::{E2ETestContext, DcgOutput};
//!
//! #[test]
//! fn test_git_reset_hard_is_blocked() {
//!     let ctx = E2ETestContext::new("git_reset_hard_blocked")
//!         .with_config("minimal")
//!         .build();
//!
//!     let output = ctx.run_dcg_hook("git reset --hard");
//!
//!     ctx.assert_blocked(&output);
//!     assert!(output.contains_rule_id("core.git:reset-hard"));
//! }
//! ```
//!
//! # Fixtures
//!
//! The framework includes pre-defined fixtures in `tests/e2e/fixtures/`:
//!
//! - **configs/**: TOML configuration files for various scenarios
//!   - `minimal.toml`: Bare minimum config
//!   - `full_featured.toml`: All features enabled
//!   - `path_specific.toml`: Path-aware allowlists
//!   - `temporary_rules.toml`: TTL and session rules
//!   - `agent_profiles.toml`: Per-agent settings
//!   - `git_awareness.toml`: Branch-specific settings
//!   - `graduated_response.toml`: Response graduation config
//!
//! - **commands/**: Test command sets
//!   - `dangerous.txt`: Commands that should be blocked
//!   - `safe.txt`: Commands that should be allowed
//!   - `edge_cases.txt`: Boundary conditions

pub mod framework;
pub mod logging;

// Re-export commonly used types for convenience
#[allow(unused_imports)]
pub use framework::{DcgOutput, E2ETestContext, E2ETestContextBuilder, TestResult};
#[allow(unused_imports)]
pub use logging::{TestLogger, TestReport, TestStep};

/// Module-level test initialization.
///
/// Call this at the start of each test file to ensure proper logging setup.
pub fn init() {
    logging::init_e2e_logging();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_module_exports() {
        // Verify that the module properly exports types
        init();

        // Create a minimal context to verify framework is working
        let ctx = E2ETestContext::builder("module_export_test").build();
        assert!(ctx.temp_dir().exists());
    }

    #[test]
    fn test_logger_initialization() {
        init();
        let logger = TestLogger::new("logger_init_test");
        logger.log_step("test_step", "Testing logger initialization");
    }
}
