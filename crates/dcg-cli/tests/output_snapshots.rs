//! Snapshot coverage for user-facing terminal output.
//!
//! Regenerate snapshots with:
//! `INSTA_UPDATE=always cargo test --test output_snapshots`
//! Then review the changed files under `tests/snapshots/`.

use dcg_cli::highlight::HighlightSpan;
use dcg_cli::output::{
    DenialBox, ScanResultRow, ScanResultsTable, Severity as OutputSeverity, TableStyle,
    TestResultBox, Theme,
};
use dcg_cli::packs::Severity as PackSeverity;
use insta::assert_snapshot;

fn normalize_snapshot(output: String) -> String {
    output.replace("\r\n", "\n").trim_end().to_string()
}

#[test]
fn denial_box_plain_snapshot_covers_highlight_regex_and_alternatives() {
    let span = HighlightSpan::with_label(0, 6, "Matched: rm -rf");
    let denial = DenialBox::new(
        "rm -rf /prod",
        span,
        "core.filesystem:rm-rf-general",
        OutputSeverity::Critical,
    )
    .with_pattern_regex(r"^rm\s+-rf")
    .with_explanation("This recursively removes protected production data.")
    .with_alternatives(vec![
        "mv /prod /tmp/prod.backup".to_string(),
        "Ask the user to run the command manually".to_string(),
    ]);

    assert_snapshot!(
        "denial_box_plain_critical",
        normalize_snapshot(denial.render_plain())
    );
}

#[test]
fn test_result_box_plain_snapshot_covers_blocked_and_allowlist_shapes() {
    let blocked = TestResultBox::blocked(
        "git push --force",
        Some("force-push".to_string()),
        Some("core.git".to_string()),
        Some(PackSeverity::High),
        "Force push can overwrite remote history",
        Some(0.93),
    );
    let allowed =
        TestResultBox::allowed_by_allowlist("git status", "project allowlist rule", "Project");

    assert_snapshot!(
        "test_result_box_plain_blocked_and_allowed",
        normalize_snapshot(format!(
            "{}\n---\n{}",
            blocked.render_plain(),
            allowed.render_plain()
        ))
    );
}

#[test]
fn scan_results_markdown_snapshot_is_stable_across_renderers() {
    let table = ScanResultsTable::new(scan_rows())
        .with_theme(&Theme::no_color())
        .with_style(TableStyle::Markdown)
        .with_max_width(100)
        .with_command_preview();

    assert_snapshot!("scan_results_markdown", normalize_snapshot(table.render()));
}

#[test]
#[cfg(not(feature = "rich-output"))]
fn scan_results_ascii_snapshot_covers_terminal_table_layout() {
    let table = ScanResultsTable::new(scan_rows())
        .with_theme(&Theme::no_color())
        .with_style(TableStyle::Ascii)
        .with_max_width(100)
        .with_command_preview();

    assert_snapshot!("scan_results_ascii", normalize_snapshot(table.render()));
}

fn scan_rows() -> Vec<ScanResultRow> {
    vec![
        ScanResultRow {
            file: "scripts/deploy.sh".to_string(),
            line: 17,
            severity: OutputSeverity::High,
            pattern_id: "core.git:force-push".to_string(),
            command_preview: Some("git push --force origin main".to_string()),
        },
        ScanResultRow {
            file: "ops/cleanup.sh".to_string(),
            line: 42,
            severity: OutputSeverity::Critical,
            pattern_id: "core.filesystem:rm-rf-general".to_string(),
            command_preview: Some("sudo rm -rf /var/lib/app".to_string()),
        },
    ]
}
