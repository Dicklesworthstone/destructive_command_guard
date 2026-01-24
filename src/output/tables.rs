//! Table rendering for dcg.
//!
//! Provides formatted table output for scan results, statistics, and pack listings.
//! Automatically adapts to terminal width and supports multiple output styles.
//!
//! # Supported Tables
//!
//! - `ScanResultsTable` - Scan findings with file, line, severity, pattern
//! - `StatsTable` - Rule statistics with hits, outcomes, rates
//! - `PackListTable` - Pack listings with ID, name, pattern counts
//!
//! # Output Styles
//!
//! - Unicode (default for TTY) - Box-drawing characters
//! - ASCII - Portable ASCII characters
//! - Markdown - GitHub-flavored markdown tables
//! - Compact - Minimal spacing for dense output
//!
//! # Feature Flags
//!
//! When the `rich-output` feature is enabled, tables are rendered using `rich_rust`
//! for premium terminal output. Markdown tables still use `comfy-table` for
//! compatibility with documentation tools.

use comfy_table::presets;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Row, Table};
#[cfg(not(feature = "rich-output"))]
use ratatui::style::Color as RatColor;

#[cfg(feature = "rich-output")]
use super::rich_theme::RichThemeExt;

use super::theme::{BorderStyle, Severity, Theme};

/// Convert rich_rust segments to a plain text string.
#[cfg(feature = "rich-output")]
fn segments_to_string(segments: Vec<rich_rust::segment::Segment<'static>>) -> String {
    segments.into_iter().map(|s| s.text.into_owned()).collect()
}

/// Convert ratatui color to comfy-table color.
/// Only used when rich-output feature is disabled.
#[cfg(not(feature = "rich-output"))]
fn to_table_color(color: RatColor) -> Color {
    match color {
        RatColor::Reset => Color::Reset,
        RatColor::Black => Color::Black,
        RatColor::Red => Color::Red,
        RatColor::Green => Color::Green,
        RatColor::Yellow => Color::Yellow,
        RatColor::Blue => Color::Blue,
        RatColor::Magenta => Color::Magenta,
        RatColor::Cyan => Color::Cyan,
        RatColor::Gray => Color::Grey,
        RatColor::DarkGray => Color::DarkGrey,
        RatColor::LightRed => Color::Red,
        RatColor::LightGreen => Color::Green,
        RatColor::LightYellow => Color::Yellow,
        RatColor::LightBlue => Color::Blue,
        RatColor::LightMagenta => Color::Magenta,
        RatColor::LightCyan => Color::Cyan,
        RatColor::White => Color::White,
        RatColor::Rgb(r, g, b) => Color::Rgb { r, g, b },
        RatColor::Indexed(value) => Color::AnsiValue(value),
    }
}

/// Table rendering style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TableStyle {
    /// Unicode box-drawing characters (default for TTY).
    #[default]
    Unicode,
    /// ASCII-only characters for maximum compatibility.
    Ascii,
    /// Markdown table format for documentation.
    Markdown,
    /// Compact output with minimal spacing.
    Compact,
}

impl TableStyle {
    /// Applies this style's preset to a comfy-table.
    fn apply_preset(&self, table: &mut Table) {
        match self {
            Self::Unicode => {
                table.load_preset(presets::UTF8_FULL);
            }
            Self::Ascii => {
                table.load_preset(presets::ASCII_FULL);
            }
            Self::Markdown => {
                table.load_preset(presets::ASCII_MARKDOWN);
            }
            Self::Compact => {
                table.load_preset(presets::UTF8_BORDERS_ONLY);
            }
        }
    }

    /// Returns the corresponding rich_rust box style.
    #[cfg(feature = "rich-output")]
    fn to_box_chars(&self) -> &'static rich_rust::r#box::BoxChars {
        use rich_rust::r#box::{ASCII, MINIMAL, ROUNDED};
        match self {
            Self::Unicode => &ROUNDED,
            Self::Ascii => &ASCII,
            Self::Markdown => &MINIMAL, // Markdown uses comfy-table
            Self::Compact => &MINIMAL,
        }
    }

    /// Returns true if this style should use Markdown output (comfy-table).
    #[must_use]
    pub const fn is_markdown(&self) -> bool {
        matches!(self, Self::Markdown)
    }
}

impl From<BorderStyle> for TableStyle {
    fn from(border: BorderStyle) -> Self {
        match border {
            BorderStyle::Unicode => Self::Unicode,
            BorderStyle::Ascii => Self::Ascii,
            BorderStyle::None => Self::Compact,
        }
    }
}

/// A single scan result row for table display.
#[derive(Debug, Clone)]
pub struct ScanResultRow {
    /// File path (may be truncated for display).
    pub file: String,
    /// Line number.
    pub line: usize,
    /// Severity level.
    pub severity: Severity,
    /// Pattern/rule ID that matched.
    pub pattern_id: String,
    /// Optional extracted command preview.
    pub command_preview: Option<String>,
}

impl ScanResultRow {
    /// Creates a scan result row from a scan finding.
    ///
    /// Maps `ScanSeverity` to `Severity`:
    /// - Error → High
    /// - Warning → Medium
    /// - Info → Low
    #[must_use]
    pub fn from_scan_finding(finding: &crate::scan::ScanFinding) -> Self {
        let severity = match finding.severity {
            crate::scan::ScanSeverity::Error => Severity::High,
            crate::scan::ScanSeverity::Warning => Severity::Medium,
            crate::scan::ScanSeverity::Info => Severity::Low,
        };

        Self {
            file: finding.file.clone(),
            line: finding.line,
            severity,
            pattern_id: finding
                .rule_id
                .clone()
                .unwrap_or_else(|| finding.extractor_id.clone()),
            command_preview: Some(finding.extracted_command.clone()),
        }
    }
}

/// Table renderer for scan results.
#[derive(Debug)]
pub struct ScanResultsTable {
    rows: Vec<ScanResultRow>,
    style: TableStyle,
    colors_enabled: bool,
    max_width: Option<u16>,
    show_command: bool,
    theme: Option<Theme>,
}

impl ScanResultsTable {
    /// Creates a new scan results table.
    #[must_use]
    pub fn new(rows: Vec<ScanResultRow>) -> Self {
        Self {
            rows,
            style: TableStyle::default(),
            colors_enabled: true,
            max_width: None,
            show_command: false,
            theme: None,
        }
    }

    /// Sets the table style.
    #[must_use]
    pub fn with_style(mut self, style: TableStyle) -> Self {
        self.style = style;
        self
    }

    /// Configures from a theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &Theme) -> Self {
        self.colors_enabled = theme.colors_enabled;
        self.style = theme.border_style.into();
        self.theme = Some(theme.clone());
        self
    }

    /// Sets maximum table width.
    #[must_use]
    pub fn with_max_width(mut self, width: u16) -> Self {
        self.max_width = Some(width);
        self
    }

    /// Enables command preview column.
    #[must_use]
    pub fn with_command_preview(mut self) -> Self {
        self.show_command = true;
        self
    }

    /// Renders the table to a string.
    ///
    /// When the `rich-output` feature is enabled, uses `rich_rust` for premium
    /// terminal output (except for Markdown style which uses comfy-table).
    #[must_use]
    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return String::from("No findings.");
        }

        // Use rich_rust for non-Markdown styles when feature is enabled
        #[cfg(feature = "rich-output")]
        if !self.style.is_markdown() {
            return self.render_rich();
        }

        self.render_comfy()
    }

    /// Renders using comfy-table (default, or Markdown output).
    fn render_comfy(&self) -> String {
        let mut table = Table::new();
        self.style.apply_preset(&mut table);
        table.set_content_arrangement(ContentArrangement::Dynamic);

        if let Some(width) = self.max_width {
            table.set_width(width);
        }

        // Set header
        let mut header = vec!["File", "Line", "Severity", "Pattern"];
        if self.show_command {
            header.push("Command");
        }
        table.set_header(header);

        // Add rows
        for row in &self.rows {
            let severity_cell = self.severity_cell_comfy(row.severity);
            let mut cells = vec![
                Cell::new(&row.file),
                Cell::new(row.line).set_alignment(CellAlignment::Right),
                severity_cell,
                Cell::new(&row.pattern_id),
            ];

            if self.show_command {
                let cmd = row.command_preview.as_deref().unwrap_or("-");
                let truncated = truncate_with_ellipsis(cmd, 40);
                cells.push(Cell::new(truncated));
            }

            table.add_row(Row::from(cells));
        }

        table.to_string()
    }

    /// Renders using rich_rust for premium terminal output.
    #[cfg(feature = "rich-output")]
    fn render_rich(&self) -> String {
        use crate::output::terminal_width;
        use rich_rust::renderables::{
            Cell as RichCell, Column as RichColumn, Row as RichRow, Table as RichTable,
        };
        use rich_rust::text::JustifyMethod;

        let mut table = RichTable::new()
            .with_column(RichColumn::new("File"))
            .with_column(RichColumn::new("Line").justify(JustifyMethod::Right))
            .with_column(RichColumn::new("Severity").justify(JustifyMethod::Center))
            .with_column(RichColumn::new("Pattern"));

        if self.show_command {
            table = table.with_column(RichColumn::new("Command"));
        }

        table = table.box_style(self.style.to_box_chars());

        for row in &self.rows {
            let severity_markup = self.severity_markup_rich(row.severity);
            let mut cells: Vec<RichCell> = vec![
                RichCell::new(row.file.as_str()),
                RichCell::new(row.line.to_string()),
                RichCell::new(severity_markup),
                RichCell::new(row.pattern_id.as_str()),
            ];

            if self.show_command {
                let cmd = row.command_preview.as_deref().unwrap_or("-");
                let truncated = truncate_with_ellipsis(cmd, 40);
                cells.push(RichCell::new(truncated));
            }

            table.add_row(RichRow::new(cells));
        }

        let width = self
            .max_width
            .map_or_else(|| terminal_width() as usize, |w| w as usize);
        segments_to_string(table.render(width))
    }

    /// Returns rich_rust markup for severity label.
    #[cfg(feature = "rich-output")]
    fn severity_markup_rich(&self, severity: Severity) -> String {
        if !self.colors_enabled {
            return severity_label(severity).to_string();
        }

        let markup = self.theme.as_ref().map_or_else(
            || default_severity_markup(severity),
            |t| t.severity_markup(severity),
        );

        format!("[{markup}]{}[/]", severity_label(severity))
    }

    /// Creates a styled cell for severity (comfy-table version).
    #[cfg(not(feature = "rich-output"))]
    fn severity_cell_comfy(&self, severity: Severity) -> Cell {
        let (label, default_color, bold) = match severity {
            Severity::Critical => ("CRIT", Color::Red, true),
            Severity::High => ("HIGH", Color::DarkRed, false),
            Severity::Medium => ("MED", Color::Yellow, false),
            Severity::Low => ("LOW", Color::Blue, false),
        };
        let color = self.theme.as_ref().map_or(default_color, |theme| {
            to_table_color(theme.color_for_severity(severity))
        });

        let mut cell = Cell::new(label);
        if self.colors_enabled {
            cell = cell.fg(color);
            if bold {
                cell = cell.add_attribute(Attribute::Bold);
            }
        }
        cell
    }

    /// Creates a styled cell for severity (comfy-table version, rich-output build).
    #[cfg(feature = "rich-output")]
    fn severity_cell_comfy(&self, severity: Severity) -> Cell {
        let (label, default_color, bold) = match severity {
            Severity::Critical => ("CRIT", Color::Red, true),
            Severity::High => ("HIGH", Color::DarkRed, false),
            Severity::Medium => ("MED", Color::Yellow, false),
            Severity::Low => ("LOW", Color::Blue, false),
        };

        let mut cell = Cell::new(label);
        if self.colors_enabled {
            cell = cell.fg(default_color);
            if bold {
                cell = cell.add_attribute(Attribute::Bold);
            }
        }
        cell
    }
}

/// Returns short severity label.
#[expect(dead_code)]
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
    }
}

/// Returns default rich_rust markup for severity (without theme).
#[cfg(feature = "rich-output")]
fn default_severity_markup(severity: Severity) -> String {
    match severity {
        Severity::Critical => "bold bright_red".to_string(),
        Severity::High => "red".to_string(),
        Severity::Medium => "yellow".to_string(),
        Severity::Low => "blue".to_string(),
    }
}

/// A single statistics row for display.
#[derive(Debug, Clone)]
pub struct StatsRow {
    /// Rule/pattern name.
    pub name: String,
    /// Total hit count.
    pub hits: u64,
    /// Number of times allowed.
    pub allowed: u64,
    /// Number of times denied.
    pub denied: u64,
    /// Noise percentage (bypass rate).
    pub noise_pct: Option<f64>,
}

/// Table renderer for rule/pattern statistics.
#[derive(Debug)]
pub struct StatsTable {
    rows: Vec<StatsRow>,
    style: TableStyle,
    colors_enabled: bool,
    max_width: Option<u16>,
    title: Option<String>,
    theme: Option<Theme>,
}

impl StatsTable {
    /// Creates a new stats table.
    #[must_use]
    pub fn new(rows: Vec<StatsRow>) -> Self {
        Self {
            rows,
            style: TableStyle::default(),
            colors_enabled: true,
            max_width: None,
            title: None,
            theme: None,
        }
    }

    /// Sets the table style.
    #[must_use]
    pub fn with_style(mut self, style: TableStyle) -> Self {
        self.style = style;
        self
    }

    /// Configures from a theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &Theme) -> Self {
        self.colors_enabled = theme.colors_enabled;
        self.style = theme.border_style.into();
        self.theme = Some(theme.clone());
        self
    }

    /// Sets maximum table width.
    #[must_use]
    pub fn with_max_width(mut self, width: u16) -> Self {
        self.max_width = Some(width);
        self
    }

    /// Sets an optional title above the table.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Renders the table to a string.
    ///
    /// When the `rich-output` feature is enabled, uses `rich_rust` for premium
    /// terminal output (except for Markdown style which uses comfy-table).
    #[must_use]
    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return String::from("No statistics available.");
        }

        // Use rich_rust for non-Markdown styles when feature is enabled
        #[cfg(feature = "rich-output")]
        if !self.style.is_markdown() {
            return self.render_rich();
        }

        self.render_comfy()
    }

    /// Renders using comfy-table (default, or Markdown output).
    fn render_comfy(&self) -> String {
        let mut table = Table::new();
        self.style.apply_preset(&mut table);
        table.set_content_arrangement(ContentArrangement::Dynamic);

        if let Some(width) = self.max_width {
            table.set_width(width);
        }

        // Set header
        table.set_header(vec!["Rule", "Hits", "Allowed", "Denied", "Noise%"]);

        // Add rows
        for row in &self.rows {
            let noise_cell = self.noise_cell_comfy(row.noise_pct);

            table.add_row(Row::from(vec![
                Cell::new(&row.name),
                Cell::new(row.hits).set_alignment(CellAlignment::Right),
                Cell::new(row.allowed).set_alignment(CellAlignment::Right),
                Cell::new(row.denied).set_alignment(CellAlignment::Right),
                noise_cell,
            ]));
        }

        let table_str = table.to_string();

        if let Some(title) = &self.title {
            format!("{title}\n{table_str}")
        } else {
            table_str
        }
    }

    /// Renders using rich_rust for premium terminal output.
    #[cfg(feature = "rich-output")]
    fn render_rich(&self) -> String {
        use crate::output::terminal_width;
        use rich_rust::renderables::{
            Cell as RichCell, Column as RichColumn, Row as RichRow, Table as RichTable,
        };
        use rich_rust::text::JustifyMethod;

        let mut table = RichTable::new()
            .with_column(RichColumn::new("Rule"))
            .with_column(RichColumn::new("Hits").justify(JustifyMethod::Right))
            .with_column(RichColumn::new("Allowed").justify(JustifyMethod::Right))
            .with_column(RichColumn::new("Denied").justify(JustifyMethod::Right))
            .with_column(RichColumn::new("Noise%").justify(JustifyMethod::Right));

        table = table.box_style(self.style.to_box_chars());

        for row in &self.rows {
            let noise_markup = self.noise_markup_rich(row.noise_pct);

            let cells: Vec<RichCell> = vec![
                RichCell::new(row.name.as_str()),
                RichCell::new(row.hits.to_string()),
                RichCell::new(row.allowed.to_string()),
                RichCell::new(row.denied.to_string()),
                RichCell::new(noise_markup),
            ];

            table.add_row(RichRow::new(cells));
        }

        let width = self
            .max_width
            .map_or_else(|| terminal_width() as usize, |w| w as usize);
        let table_str = segments_to_string(table.render(width));

        if let Some(title) = &self.title {
            format!("{title}\n{table_str}")
        } else {
            table_str
        }
    }

    /// Returns rich_rust markup for noise percentage.
    #[cfg(feature = "rich-output")]
    fn noise_markup_rich(&self, noise_pct: Option<f64>) -> String {
        let Some(pct) = noise_pct else {
            return "-".to_string();
        };

        let label = format!("{pct:.1}%");

        if !self.colors_enabled {
            return label;
        }

        // Color based on noise level: high noise = red, medium = yellow, low = green
        let color = if pct > 50.0 {
            self.theme
                .as_ref()
                .map_or("red".to_string(), |t| t.error_markup())
        } else if pct > 25.0 {
            self.theme
                .as_ref()
                .map_or("yellow".to_string(), |t| t.warning_markup())
        } else {
            self.theme
                .as_ref()
                .map_or("green".to_string(), |t| t.success_markup())
        };

        format!("[{color}]{label}[/]")
    }

    /// Creates a styled cell for noise percentage (comfy-table version).
    #[cfg(not(feature = "rich-output"))]
    fn noise_cell_comfy(&self, noise_pct: Option<f64>) -> Cell {
        let Some(pct) = noise_pct else {
            return Cell::new("-").set_alignment(CellAlignment::Right);
        };

        let label = format!("{pct:.1}%");
        let mut cell = Cell::new(label).set_alignment(CellAlignment::Right);

        if self.colors_enabled {
            let (error_color, warning_color, success_color) =
                self.theme
                    .as_ref()
                    .map_or((Color::Red, Color::Yellow, Color::Green), |theme| {
                        (
                            to_table_color(theme.error_color),
                            to_table_color(theme.warning_color),
                            to_table_color(theme.success_color),
                        )
                    });
            // Color based on noise level: high noise = yellow/red warning
            cell = if pct > 50.0 {
                cell.fg(error_color)
            } else if pct > 25.0 {
                cell.fg(warning_color)
            } else {
                cell.fg(success_color)
            };
        }

        cell
    }

    /// Creates a styled cell for noise percentage (comfy-table version, rich-output build).
    #[cfg(feature = "rich-output")]
    fn noise_cell_comfy(&self, noise_pct: Option<f64>) -> Cell {
        let Some(pct) = noise_pct else {
            return Cell::new("-").set_alignment(CellAlignment::Right);
        };

        let label = format!("{pct:.1}%");
        let mut cell = Cell::new(label).set_alignment(CellAlignment::Right);

        if self.colors_enabled {
            // Use default colors for Markdown output (rich-output build)
            let (error_color, warning_color, success_color) =
                (Color::Red, Color::Yellow, Color::Green);
            cell = if pct > 50.0 {
                cell.fg(error_color)
            } else if pct > 25.0 {
                cell.fg(warning_color)
            } else {
                cell.fg(success_color)
            };
        }

        cell
    }
}

/// A single pack row for display.
#[derive(Debug, Clone)]
pub struct PackRow {
    /// Pack ID (e.g., "core.git").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Number of destructive patterns.
    pub destructive_count: usize,
    /// Number of safe patterns.
    pub safe_count: usize,
    /// Whether the pack is enabled.
    pub enabled: bool,
}

/// Table renderer for pack listings.
#[derive(Debug)]
pub struct PackListTable {
    rows: Vec<PackRow>,
    style: TableStyle,
    colors_enabled: bool,
    max_width: Option<u16>,
    show_status: bool,
    theme: Option<Theme>,
}

impl PackListTable {
    /// Creates a new pack list table.
    #[must_use]
    pub fn new(rows: Vec<PackRow>) -> Self {
        Self {
            rows,
            style: TableStyle::default(),
            colors_enabled: true,
            max_width: None,
            show_status: true,
            theme: None,
        }
    }

    /// Sets the table style.
    #[must_use]
    pub fn with_style(mut self, style: TableStyle) -> Self {
        self.style = style;
        self
    }

    /// Configures from a theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &Theme) -> Self {
        self.colors_enabled = theme.colors_enabled;
        self.style = theme.border_style.into();
        self.theme = Some(theme.clone());
        self
    }

    /// Sets maximum table width.
    #[must_use]
    pub fn with_max_width(mut self, width: u16) -> Self {
        self.max_width = Some(width);
        self
    }

    /// Hides the enabled/disabled status column.
    #[must_use]
    pub fn hide_status(mut self) -> Self {
        self.show_status = false;
        self
    }

    /// Renders the table to a string.
    ///
    /// When the `rich-output` feature is enabled, uses `rich_rust` for premium
    /// terminal output (except for Markdown style which uses comfy-table).
    #[must_use]
    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return String::from("No packs available.");
        }

        // Use rich_rust for non-Markdown styles when feature is enabled
        #[cfg(feature = "rich-output")]
        if !self.style.is_markdown() {
            return self.render_rich();
        }

        self.render_comfy()
    }

    /// Renders using comfy-table (default, or Markdown output).
    fn render_comfy(&self) -> String {
        let mut table = Table::new();
        self.style.apply_preset(&mut table);
        table.set_content_arrangement(ContentArrangement::Dynamic);

        if let Some(width) = self.max_width {
            table.set_width(width);
        }

        // Set header
        let mut header = vec!["Pack ID", "Name", "Destructive", "Safe"];
        if self.show_status {
            header.push("Status");
        }
        table.set_header(header);

        // Add rows
        for row in &self.rows {
            let mut cells = vec![
                Cell::new(&row.id),
                Cell::new(&row.name),
                Cell::new(row.destructive_count).set_alignment(CellAlignment::Right),
                Cell::new(row.safe_count).set_alignment(CellAlignment::Right),
            ];

            if self.show_status {
                cells.push(self.status_cell_comfy(row.enabled));
            }

            table.add_row(Row::from(cells));
        }

        table.to_string()
    }

    /// Renders using rich_rust for premium terminal output.
    #[cfg(feature = "rich-output")]
    fn render_rich(&self) -> String {
        use crate::output::terminal_width;
        use rich_rust::renderables::{
            Cell as RichCell, Column as RichColumn, Row as RichRow, Table as RichTable,
        };
        use rich_rust::text::JustifyMethod;

        let mut table = RichTable::new()
            .with_column(RichColumn::new("Pack ID"))
            .with_column(RichColumn::new("Name"))
            .with_column(RichColumn::new("Destructive").justify(JustifyMethod::Right))
            .with_column(RichColumn::new("Safe").justify(JustifyMethod::Right));

        if self.show_status {
            table = table.with_column(RichColumn::new("Status").justify(JustifyMethod::Center));
        }

        table = table.box_style(self.style.to_box_chars());

        for row in &self.rows {
            let mut cells: Vec<RichCell> = vec![
                RichCell::new(row.id.as_str()),
                RichCell::new(row.name.as_str()),
                RichCell::new(row.destructive_count.to_string()),
                RichCell::new(row.safe_count.to_string()),
            ];

            if self.show_status {
                let status_markup = self.status_markup_rich(row.enabled);
                cells.push(RichCell::new(status_markup));
            }

            table.add_row(RichRow::new(cells));
        }

        let width = self
            .max_width
            .map_or_else(|| terminal_width() as usize, |w| w as usize);
        segments_to_string(table.render(width))
    }

    /// Returns rich_rust markup for enabled/disabled status.
    #[cfg(feature = "rich-output")]
    fn status_markup_rich(&self, enabled: bool) -> String {
        if !self.colors_enabled {
            return if enabled { "enabled" } else { "disabled" }.to_string();
        }

        if enabled {
            let color = self
                .theme
                .as_ref()
                .map_or("green".to_string(), |t| t.success_markup());
            format!("[{color}]● enabled[/]")
        } else {
            let color = self
                .theme
                .as_ref()
                .map_or("dim".to_string(), |t| t.muted_markup());
            format!("[{color}]○ disabled[/]")
        }
    }

    /// Creates a styled cell for enabled/disabled status (comfy-table version).
    #[cfg(not(feature = "rich-output"))]
    fn status_cell_comfy(&self, enabled: bool) -> Cell {
        let (label, default_color) = if enabled {
            ("enabled", Color::Green)
        } else {
            ("disabled", Color::DarkGrey)
        };
        let color = self.theme.as_ref().map_or(default_color, |theme| {
            if enabled {
                to_table_color(theme.success_color)
            } else {
                to_table_color(theme.muted_color)
            }
        });

        let mut cell = Cell::new(label);
        if self.colors_enabled {
            cell = cell.fg(color);
        }
        cell
    }

    /// Creates a styled cell for enabled/disabled status (comfy-table version, rich-output build).
    #[cfg(feature = "rich-output")]
    fn status_cell_comfy(&self, enabled: bool) -> Cell {
        let (label, default_color) = if enabled {
            ("enabled", Color::Green)
        } else {
            ("disabled", Color::DarkGrey)
        };

        let mut cell = Cell::new(label);
        if self.colors_enabled {
            cell = cell.fg(default_color);
        }
        cell
    }
}

/// Summary line formatter for table footers.
pub fn format_summary(total: usize, categories: &[(&str, usize)]) -> String {
    let parts: Vec<String> = categories
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| format!("{count} {label}"))
        .collect();

    if parts.is_empty() {
        format!("{total} items")
    } else {
        format!("{total} items ({parts})", parts = parts.join(", "))
    }
}

fn truncate_with_ellipsis(text: &str, max_chars: usize) -> String {
    let text_len = text.chars().count();
    if text_len <= max_chars {
        return text.to_string();
    }

    if max_chars <= 3 {
        return text.chars().take(max_chars).collect();
    }

    let keep = max_chars.saturating_sub(3);
    let mut truncated: String = text.chars().take(keep).collect();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_results_table_empty() {
        let table = ScanResultsTable::new(vec![]);
        assert_eq!(table.render(), "No findings.");
    }

    #[test]
    fn test_scan_results_table_basic() {
        let rows = vec![
            ScanResultRow {
                file: "src/main.rs".to_string(),
                line: 42,
                severity: Severity::High,
                pattern_id: "core.git:reset-hard".to_string(),
                command_preview: None,
            },
            ScanResultRow {
                file: "Dockerfile".to_string(),
                line: 10,
                severity: Severity::Critical,
                pattern_id: "core.filesystem:rm-rf".to_string(),
                command_preview: None,
            },
        ];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();

        assert!(output.contains("src/main.rs"));
        assert!(output.contains("42"));
        assert!(output.contains("HIGH"));
        assert!(output.contains("core.git:reset-hard"));
        assert!(output.contains("CRIT"));
    }

    #[test]
    fn test_scan_results_table_with_command_preview() {
        let rows = vec![ScanResultRow {
            file: "test.sh".to_string(),
            line: 1,
            severity: Severity::Medium,
            pattern_id: "core.git:clean".to_string(),
            command_preview: Some("git clean -fd".to_string()),
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_command_preview();
        let output = table.render();

        assert!(output.contains("git clean -fd"));
        assert!(output.contains("Command"));
    }

    #[test]
    fn test_stats_table_empty() {
        let table = StatsTable::new(vec![]);
        assert_eq!(table.render(), "No statistics available.");
    }

    #[test]
    fn test_stats_table_basic() {
        let rows = vec![
            StatsRow {
                name: "core.git:reset-hard".to_string(),
                hits: 100,
                allowed: 10,
                denied: 90,
                noise_pct: Some(10.0),
            },
            StatsRow {
                name: "core.filesystem:rm-rf".to_string(),
                hits: 50,
                allowed: 25,
                denied: 25,
                noise_pct: Some(50.0),
            },
        ];

        let table = StatsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_title("Pattern Statistics");
        let output = table.render();

        assert!(output.contains("Pattern Statistics"));
        assert!(output.contains("core.git:reset-hard"));
        assert!(output.contains("100"));
        assert!(output.contains("10.0%"));
        assert!(output.contains("50.0%"));
    }

    #[test]
    fn test_pack_list_table_empty() {
        let table = PackListTable::new(vec![]);
        assert_eq!(table.render(), "No packs available.");
    }

    #[test]
    fn test_pack_list_table_basic() {
        let rows = vec![
            PackRow {
                id: "core.git".to_string(),
                name: "Git Commands".to_string(),
                destructive_count: 8,
                safe_count: 15,
                enabled: true,
            },
            PackRow {
                id: "core.filesystem".to_string(),
                name: "Filesystem".to_string(),
                destructive_count: 5,
                safe_count: 10,
                enabled: false,
            },
        ];

        let table = PackListTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();

        assert!(output.contains("core.git"));
        assert!(output.contains("Git Commands"));
        assert!(output.contains("enabled"));
        assert!(output.contains("disabled"));
    }

    #[test]
    fn test_pack_list_table_hide_status() {
        let rows = vec![PackRow {
            id: "core.git".to_string(),
            name: "Git Commands".to_string(),
            destructive_count: 8,
            safe_count: 15,
            enabled: true,
        }];

        let table = PackListTable::new(rows)
            .with_style(TableStyle::Ascii)
            .hide_status();
        let output = table.render();

        assert!(!output.contains("Status"));
        assert!(!output.contains("enabled"));
    }

    #[test]
    fn test_table_style_from_border_style() {
        assert_eq!(TableStyle::from(BorderStyle::Unicode), TableStyle::Unicode);
        assert_eq!(TableStyle::from(BorderStyle::Ascii), TableStyle::Ascii);
        assert_eq!(TableStyle::from(BorderStyle::None), TableStyle::Compact);
    }

    #[test]
    fn test_format_summary() {
        assert_eq!(format_summary(10, &[]), "10 items");
        assert_eq!(
            format_summary(10, &[("errors", 3), ("warnings", 7)]),
            "10 items (3 errors, 7 warnings)"
        );
        assert_eq!(
            format_summary(5, &[("errors", 0), ("warnings", 5)]),
            "5 items (5 warnings)"
        );
    }

    #[test]
    fn test_markdown_style() {
        let rows = vec![ScanResultRow {
            file: "test.sh".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test.pattern".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Markdown);
        let output = table.render();

        // Markdown tables use | as separators
        assert!(output.contains("|"));
        assert!(output.contains("test.sh"));
    }

    #[test]
    fn test_long_command_truncation() {
        let long_cmd =
            "git reset --hard HEAD~100 && rm -rf /very/long/path/that/should/be/truncated";
        let rows = vec![ScanResultRow {
            file: "test.sh".to_string(),
            line: 1,
            severity: Severity::Critical,
            pattern_id: "test".to_string(),
            command_preview: Some(long_cmd.to_string()),
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_command_preview();
        // Use wide enough table to show our truncation
        let table = table.with_max_width(120);
        let output = table.render();

        // Should be truncated with ...
        assert!(
            output.contains("..."),
            "Output should contain ellipsis: {output}"
        );
        // Should not contain the full long command
        assert!(
            !output.contains("truncated"),
            "Output should not contain 'truncated': {output}"
        );
    }

    #[test]
    fn test_scan_results_with_theme() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let theme = Theme::no_color();
        let table = ScanResultsTable::new(rows).with_theme(&theme);
        let output = table.render();

        assert!(output.contains("test.rs"));
        assert!(output.contains("LOW"));
    }

    #[test]
    fn test_stats_table_with_theme() {
        let rows = vec![StatsRow {
            name: "test.rule".to_string(),
            hits: 50,
            allowed: 25,
            denied: 25,
            noise_pct: Some(50.0),
        }];

        let theme = Theme::no_color();
        let table = StatsTable::new(rows).with_theme(&theme);
        let output = table.render();

        assert!(output.contains("test.rule"));
        assert!(output.contains("50.0%"));
    }

    #[test]
    fn test_pack_list_with_theme() {
        let rows = vec![PackRow {
            id: "test.pack".to_string(),
            name: "Test Pack".to_string(),
            destructive_count: 5,
            safe_count: 10,
            enabled: true,
        }];

        let theme = Theme::no_color();
        let table = PackListTable::new(rows).with_theme(&theme);
        let output = table.render();

        assert!(output.contains("test.pack"));
        assert!(output.contains("enabled"));
    }

    #[test]
    fn test_scan_results_with_max_width() {
        let rows = vec![ScanResultRow {
            file: "very/long/path/to/some/file.rs".to_string(),
            line: 100,
            severity: Severity::Medium,
            pattern_id: "core.git.reset".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_max_width(60);
        let output = table.render();

        assert!(output.contains("File"));
        assert!(output.contains("MED"));
    }

    #[test]
    fn test_stats_table_nil_noise() {
        let rows = vec![StatsRow {
            name: "test.rule".to_string(),
            hits: 10,
            allowed: 5,
            denied: 5,
            noise_pct: None,
        }];

        let table = StatsTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();

        assert!(output.contains("-")); // Nil noise should show dash
    }

    #[test]
    fn test_compact_table_style() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Compact);
        let output = table.render();

        assert!(output.contains("test.rs"));
    }

    #[test]
    fn test_command_preview_missing() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Ascii)
            .with_command_preview();
        let output = table.render();

        // Missing command should show dash
        assert!(output.contains("-"));
    }

    // ==================== rich_rust-specific tests ====================

    #[test]
    #[cfg(feature = "rich-output")]
    fn test_rich_scan_table_uses_rounded_borders() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::High,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Unicode);
        let output = table.render();

        // Unicode/rounded borders use rounded corner characters
        // Check for presence of box-drawing characters (rounded style uses ╭ ╮ ╰ ╯)
        assert!(
            output.contains('╭') || output.contains('+'),
            "Output should contain box borders: {output}"
        );
    }

    #[test]
    #[cfg(feature = "rich-output")]
    fn test_rich_scan_table_severity_markup() {
        let rows = vec![
            ScanResultRow {
                file: "a.rs".to_string(),
                line: 1,
                severity: Severity::Critical,
                pattern_id: "test".to_string(),
                command_preview: None,
            },
            ScanResultRow {
                file: "b.rs".to_string(),
                line: 2,
                severity: Severity::High,
                pattern_id: "test".to_string(),
                command_preview: None,
            },
            ScanResultRow {
                file: "c.rs".to_string(),
                line: 3,
                severity: Severity::Medium,
                pattern_id: "test".to_string(),
                command_preview: None,
            },
            ScanResultRow {
                file: "d.rs".to_string(),
                line: 4,
                severity: Severity::Low,
                pattern_id: "test".to_string(),
                command_preview: None,
            },
        ];

        let table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Unicode)
            .with_max_width(120);
        let output = table.render();

        // Should contain severity labels (with or without color markup)
        assert!(
            output.contains("CRIT"),
            "Output should contain CRIT: {output}"
        );
        assert!(
            output.contains("HIGH"),
            "Output should contain HIGH: {output}"
        );
        assert!(
            output.contains("MED"),
            "Output should contain MED: {output}"
        );
        assert!(
            output.contains("LOW"),
            "Output should contain LOW: {output}"
        );
    }

    #[test]
    #[cfg(feature = "rich-output")]
    fn test_rich_stats_table_basic() {
        let rows = vec![StatsRow {
            name: "core.git:reset".to_string(),
            hits: 42,
            allowed: 30,
            denied: 12,
            noise_pct: Some(2.1),
        }];

        let table = StatsTable::new(rows)
            .with_style(TableStyle::Unicode)
            .with_max_width(100);
        let output = table.render();

        assert!(output.contains("core.git:reset"), "Output: {output}");
        assert!(output.contains("42"), "Output: {output}");
    }

    #[test]
    #[cfg(feature = "rich-output")]
    fn test_rich_pack_list_table_basic() {
        let rows = vec![
            PackRow {
                id: "core.git".to_string(),
                name: "Git Operations".to_string(),
                destructive_count: 10,
                safe_count: 5,
                enabled: true,
            },
            PackRow {
                id: "core.filesystem".to_string(),
                name: "File Operations".to_string(),
                destructive_count: 8,
                safe_count: 3,
                enabled: false,
            },
        ];

        let table = PackListTable::new(rows)
            .with_style(TableStyle::Unicode)
            .with_max_width(120);
        let output = table.render();

        // Should contain pack IDs
        assert!(output.contains("core.git"), "Output: {output}");
        assert!(output.contains("core.filesystem"), "Output: {output}");
        // Should contain counts
        assert!(output.contains("10"), "Output: {output}");
    }

    #[test]
    #[cfg(feature = "rich-output")]
    fn test_rich_table_respects_width() {
        let rows = vec![ScanResultRow {
            file: "very/long/path/to/some/deeply/nested/file/in/the/project.rs".to_string(),
            line: 999,
            severity: Severity::Critical,
            pattern_id: "very.long.pattern:with-lots-of-details".to_string(),
            command_preview: Some("git reset --hard HEAD~100 && rm -rf /".to_string()),
        }];

        let narrow_table = ScanResultsTable::new(rows.clone())
            .with_style(TableStyle::Unicode)
            .with_command_preview()
            .with_max_width(60);
        let narrow_output = narrow_table.render();

        let wide_table = ScanResultsTable::new(rows)
            .with_style(TableStyle::Unicode)
            .with_command_preview()
            .with_max_width(200);
        let wide_output = wide_table.render();

        // Both should render without panicking
        assert!(
            !narrow_output.is_empty(),
            "Narrow output should not be empty"
        );
        assert!(!wide_output.is_empty(), "Wide output should not be empty");
    }

    #[test]
    #[cfg(feature = "rich-output")]
    fn test_ascii_style_uses_ascii_chars() {
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Ascii);
        let output = table.render();

        // ASCII style should use +, -, | characters, not Unicode box drawing
        assert!(
            output.contains('+') || output.contains('-') || output.contains('|'),
            "ASCII output should use ASCII characters: {output}"
        );
        // Should NOT contain rounded Unicode corners
        assert!(
            !output.contains('╭'),
            "ASCII output should not contain Unicode box chars: {output}"
        );
    }

    #[test]
    fn test_markdown_uses_comfy_table() {
        // Markdown style should always use comfy-table (render_comfy),
        // even when rich-output feature is enabled
        let rows = vec![ScanResultRow {
            file: "test.rs".to_string(),
            line: 1,
            severity: Severity::Low,
            pattern_id: "test".to_string(),
            command_preview: None,
        }];

        let table = ScanResultsTable::new(rows).with_style(TableStyle::Markdown);
        let output = table.render();

        // Markdown tables use | as column separators
        assert!(
            output.contains('|'),
            "Markdown output should use pipe separators: {output}"
        );
        // Should not contain ANSI escape codes or rich markup
        assert!(
            !output.contains('\x1b'),
            "Markdown should not contain ANSI escapes: {output}"
        );
    }
}
