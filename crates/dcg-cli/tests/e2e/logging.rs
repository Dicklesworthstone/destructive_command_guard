//! E2E Test Logging Utilities
//!
//! Provides structured logging for E2E tests with detailed output for debugging
//! test failures and generating test reports.

#![allow(dead_code, clippy::format_push_string)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, Instant};

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Global initialization guard for logging.
static INIT: Once = Once::new();

/// Initialize E2E test logging.
///
/// This should be called once per test session. Multiple calls are safe
/// (subsequent calls are no-ops).
///
/// # Environment
///
/// Set `RUST_LOG=dcg=debug` to see detailed DCG logs in test output.
pub fn init_e2e_logging() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("dcg=info,e2e=debug"));

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_ansi(true)
                    .with_level(true)
                    .with_target(true)
                    .with_file(false)
                    .with_line_number(false)
                    .compact(),
            )
            .with(filter)
            .init();
    });
}

/// A step in a test execution.
#[derive(Debug, Clone)]
pub struct TestStep {
    /// Step name.
    pub name: String,
    /// Step details/description.
    pub details: String,
    /// Time taken for this step.
    pub duration: Duration,
    /// Whether the step passed.
    pub passed: bool,
    /// Optional error message if step failed.
    pub error: Option<String>,
}

/// A complete test report.
#[derive(Debug, Clone)]
pub struct TestReport {
    /// Name of the test.
    pub test_name: String,
    /// Overall result.
    pub passed: bool,
    /// Total duration.
    pub duration: Duration,
    /// Individual steps.
    pub steps: Vec<TestStep>,
    /// Metadata (key-value pairs).
    pub metadata: HashMap<String, String>,
    /// Error message if test failed.
    pub error: Option<String>,
}

impl TestReport {
    /// Generate a markdown report.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Header
        let status = if self.passed { "PASS" } else { "FAIL" };
        md.push_str(&format!(
            "# Test Report: {} [{}]\n\n",
            self.test_name, status
        ));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Duration**: {:?}\n", self.duration));
        md.push_str(&format!("- **Steps**: {}\n", self.steps.len()));
        md.push_str(&format!(
            "- **Passed Steps**: {}\n",
            self.steps.iter().filter(|s| s.passed).count()
        ));

        // Error if present
        if let Some(error) = &self.error {
            md.push_str(&format!("\n**Error**: {}\n", error));
        }

        // Metadata
        if !self.metadata.is_empty() {
            md.push_str("\n## Metadata\n\n");
            for (key, value) in &self.metadata {
                md.push_str(&format!("- **{}**: {}\n", key, value));
            }
        }

        // Steps
        md.push_str("\n## Steps\n\n");
        for (i, step) in self.steps.iter().enumerate() {
            let step_status = if step.passed { "[PASS]" } else { "[FAIL]" };
            md.push_str(&format!(
                "{}. **{}** {} ({:?})\n",
                i + 1,
                step.name,
                step_status,
                step.duration
            ));
            if !step.details.is_empty() {
                md.push_str(&format!("   - {}\n", step.details));
            }
            if let Some(error) = &step.error {
                md.push_str(&format!("   - **Error**: {}\n", error));
            }
        }

        md
    }

    /// Generate a JSON report.
    #[must_use]
    pub fn to_json(&self) -> String {
        let steps: Vec<serde_json::Value> = self
            .steps
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "details": s.details,
                    "duration_ms": s.duration.as_millis(),
                    "passed": s.passed,
                    "error": s.error,
                })
            })
            .collect();

        let report = serde_json::json!({
            "test_name": self.test_name,
            "passed": self.passed,
            "duration_ms": self.duration.as_millis(),
            "steps": steps,
            "metadata": self.metadata,
            "error": self.error,
        });

        serde_json::to_string_pretty(&report).unwrap_or_default()
    }
}

/// Logger for E2E tests with detailed output.
pub struct TestLogger {
    test_name: String,
    log_path: Option<PathBuf>,
    start_time: Instant,
    steps: Vec<TestStep>,
    metadata: HashMap<String, String>,
    verbose: bool,
    current_step_start: Option<Instant>,
    current_step_name: Option<String>,
}

impl TestLogger {
    /// Create a new test logger.
    #[must_use]
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            log_path: None,
            start_time: Instant::now(),
            steps: Vec::new(),
            metadata: HashMap::new(),
            verbose: std::env::var("E2E_VERBOSE").is_ok(),
            current_step_start: None,
            current_step_name: None,
        }
    }

    /// Create a logger that writes to a file.
    #[must_use]
    pub fn with_log_file(mut self, path: PathBuf) -> Self {
        self.log_path = Some(path);
        self
    }

    /// Enable verbose output.
    #[must_use]
    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Add metadata to the test.
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Log the start of a test.
    pub fn log_test_start(&self, description: &str) {
        if self.verbose {
            tracing::info!(target: "e2e", test = %self.test_name, "Starting test: {}", description);
        }

        self.write_to_file(&format!(
            "[{}] TEST START: {}\n  Description: {}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
            self.test_name,
            description
        ));
    }

    /// Log a test step.
    pub fn log_step(&self, step: &str, details: &str) {
        if self.verbose {
            tracing::debug!(target: "e2e", test = %self.test_name, step = %step, "Step: {}", details);
        }

        self.write_to_file(&format!("  [STEP] {}: {}\n", step, details));
    }

    /// Start timing a step.
    pub fn start_step(&mut self, name: &str) {
        self.current_step_start = Some(Instant::now());
        self.current_step_name = Some(name.to_string());

        if self.verbose {
            tracing::debug!(target: "e2e", test = %self.test_name, "Starting step: {}", name);
        }
    }

    /// End the current step with success.
    pub fn end_step_pass(&mut self, details: &str) {
        if let (Some(start), Some(name)) = (
            self.current_step_start.take(),
            self.current_step_name.take(),
        ) {
            let duration = start.elapsed();
            self.steps.push(TestStep {
                name: name.clone(),
                details: details.to_string(),
                duration,
                passed: true,
                error: None,
            });

            if self.verbose {
                tracing::debug!(target: "e2e", test = %self.test_name, step = %name, "Step passed: {} ({:?})", details, duration);
            }

            self.write_to_file(&format!(
                "  [PASS] {} ({:?}): {}\n",
                name, duration, details
            ));
        }
    }

    /// End the current step with failure.
    pub fn end_step_fail(&mut self, details: &str, error: &str) {
        if let (Some(start), Some(name)) = (
            self.current_step_start.take(),
            self.current_step_name.take(),
        ) {
            let duration = start.elapsed();
            self.steps.push(TestStep {
                name: name.clone(),
                details: details.to_string(),
                duration,
                passed: false,
                error: Some(error.to_string()),
            });

            if self.verbose {
                tracing::warn!(target: "e2e", test = %self.test_name, step = %name, "Step failed: {} - {}", details, error);
            }

            self.write_to_file(&format!(
                "  [FAIL] {} ({:?}): {} - Error: {}\n",
                name, duration, details, error
            ));
        }
    }

    /// Log a command being executed.
    pub fn log_command(&self, cmd: &str, args: &[&str]) {
        let full_cmd = if args.is_empty() {
            cmd.to_string()
        } else {
            format!("{} {}", cmd, args.join(" "))
        };

        if self.verbose {
            tracing::debug!(target: "e2e", test = %self.test_name, "Command: {}", full_cmd);
        }

        self.write_to_file(&format!("  [CMD] {}\n", full_cmd));
    }

    /// Log command output.
    pub fn log_output(&self, stdout: &str, stderr: &str, exit_code: i32) {
        if self.verbose {
            tracing::debug!(target: "e2e", test = %self.test_name, exit_code = exit_code, "Output received");
        }

        let mut output = format!("  [OUTPUT] exit_code={}\n", exit_code);
        if !stdout.is_empty() {
            output.push_str(&format!("    stdout: {}\n", truncate_output(stdout, 500)));
        }
        if !stderr.is_empty() {
            output.push_str(&format!("    stderr: {}\n", truncate_output(stderr, 500)));
        }

        self.write_to_file(&output);
    }

    /// Log an assertion.
    pub fn log_assertion(&self, assertion: &str, passed: bool) {
        let status = if passed { "PASS" } else { "FAIL" };

        if self.verbose {
            if passed {
                tracing::debug!(target: "e2e", test = %self.test_name, "Assertion passed: {}", assertion);
            } else {
                tracing::warn!(target: "e2e", test = %self.test_name, "Assertion failed: {}", assertion);
            }
        }

        self.write_to_file(&format!("  [ASSERT:{}] {}\n", status, assertion));
    }

    /// Log the end of a test.
    pub fn log_test_end(&self, passed: bool, error: Option<&str>) {
        let status = if passed { "PASS" } else { "FAIL" };
        let duration = self.start_time.elapsed();

        if self.verbose {
            if passed {
                tracing::info!(target: "e2e", test = %self.test_name, "Test passed ({:?})", duration);
            } else {
                tracing::error!(target: "e2e", test = %self.test_name, "Test failed ({:?}): {:?}", duration, error);
            }
        }

        let mut output = format!(
            "[{}] TEST END: {} [{}] ({:?})\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
            self.test_name,
            status,
            duration
        );

        if let Some(err) = error {
            output.push_str(&format!("  Error: {}\n", err));
        }

        self.write_to_file(&output);
    }

    /// Generate a test report.
    #[must_use]
    pub fn generate_report(&self, passed: bool, error: Option<String>) -> TestReport {
        TestReport {
            test_name: self.test_name.clone(),
            passed,
            duration: self.start_time.elapsed(),
            steps: self.steps.clone(),
            metadata: self.metadata.clone(),
            error,
        }
    }

    /// Write to the log file if configured.
    fn write_to_file(&self, content: &str) {
        if let Some(path) = &self.log_path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = file.write_all(content.as_bytes());
            }
        }
    }
}

/// Truncate output for display.
fn truncate_output(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...[truncated]", &s[..max_len])
    }
}

/// Macro for logging test progress.
#[macro_export]
macro_rules! e2e_log {
    ($($arg:tt)*) => {
        tracing::info!(target: "e2e", $($arg)*)
    };
}

/// Macro for logging test debug info.
#[macro_export]
macro_rules! e2e_debug {
    ($($arg:tt)*) => {
        tracing::debug!(target: "e2e", $($arg)*)
    };
}

/// Macro for logging test warnings.
#[macro_export]
macro_rules! e2e_warn {
    ($($arg:tt)*) => {
        tracing::warn!(target: "e2e", $($arg)*)
    };
}

/// Macro for logging test errors.
#[macro_export]
macro_rules! e2e_error {
    ($($arg:tt)*) => {
        tracing::error!(target: "e2e", $($arg)*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_creation() {
        let logger = TestLogger::new("test_logger");
        assert_eq!(logger.test_name, "test_logger");
    }

    #[test]
    fn test_logger_step_tracking() {
        let mut logger = TestLogger::new("step_tracking");
        logger.start_step("step1");
        std::thread::sleep(Duration::from_millis(10));
        logger.end_step_pass("Step 1 completed");

        logger.start_step("step2");
        logger.end_step_fail("Step 2 failed", "Some error");

        assert_eq!(logger.steps.len(), 2);
        assert!(logger.steps[0].passed);
        assert!(!logger.steps[1].passed);
    }

    #[test]
    fn test_report_generation() {
        let mut logger = TestLogger::new("report_test");
        logger.add_metadata("config", "minimal");
        logger.start_step("setup");
        logger.end_step_pass("Setup complete");

        let report = logger.generate_report(true, None);

        assert_eq!(report.test_name, "report_test");
        assert!(report.passed);
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.metadata.get("config"), Some(&"minimal".to_string()));
    }

    #[test]
    fn test_report_markdown() {
        let report = TestReport {
            test_name: "markdown_test".to_string(),
            passed: true,
            duration: Duration::from_millis(100),
            steps: vec![TestStep {
                name: "step1".to_string(),
                details: "Test step".to_string(),
                duration: Duration::from_millis(50),
                passed: true,
                error: None,
            }],
            metadata: HashMap::new(),
            error: None,
        };

        let md = report.to_markdown();
        assert!(md.contains("# Test Report: markdown_test"));
        assert!(md.contains("[PASS]"));
    }

    #[test]
    fn test_report_json() {
        let report = TestReport {
            test_name: "json_test".to_string(),
            passed: false,
            duration: Duration::from_millis(100),
            steps: vec![],
            metadata: HashMap::new(),
            error: Some("Test error".to_string()),
        };

        let json = report.to_json();
        assert!(json.contains("\"test_name\": \"json_test\""));
        assert!(json.contains("\"passed\": false"));
        assert!(json.contains("\"error\": \"Test error\""));
    }

    #[test]
    fn test_truncate_output() {
        let short = "short";
        let long = "a".repeat(1000);

        assert_eq!(truncate_output(short, 100), "short");
        let truncated = truncate_output(&long, 100);
        assert!(truncated.ends_with("...[truncated]"));
        assert!(truncated.len() < long.len());
    }
}
