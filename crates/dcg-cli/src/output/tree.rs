//! Tree rendering for dcg.
//!
//! Provides tree visualization for hierarchical data like pack structures,
//! decision traces, and command transformation pipelines.
//!
//! # Feature Flags
//!
//! When the `rich-output` feature is enabled, trees are rendered using `rich_rust`
//! for premium terminal output. Otherwise, a fallback ASCII tree renderer is used.

#[cfg(feature = "rich-output")]
use rich_rust::renderables::tree::{Tree as RichTree, TreeGuides, TreeNode as RichTreeNode};
#[cfg(feature = "rich-output")]
use rich_rust::style::Style;

use super::theme::{BorderStyle, Theme};
use crate::evaluator::EvaluationDecision;
use crate::trace::{ExplainTrace, MatchInfo, PackSummary, TraceDetails, TraceStep};
use std::collections::{BTreeMap, BTreeSet};

/// Default maximum number of patterns shown per pack section in verbose trees.
pub const DEFAULT_PACK_TREE_MAX_PATTERNS: usize = 10;

/// Pattern details rendered under a pack in verbose tree output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackTreePattern {
    /// Pattern name used in rule IDs and allowlists.
    pub name: String,
    /// Raw regex pattern.
    pub regex: String,
    /// Optional severity label for destructive patterns.
    pub severity: Option<String>,
}

impl PackTreePattern {
    /// Create a safe pattern entry.
    #[must_use]
    pub fn safe(name: impl Into<String>, regex: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            regex: regex.into(),
            severity: None,
        }
    }

    /// Create a destructive pattern entry.
    #[must_use]
    pub fn destructive(
        name: impl Into<String>,
        regex: impl Into<String>,
        severity: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            regex: regex.into(),
            severity: Some(severity.into()),
        }
    }
}

/// Rendering options for the `dcg packs` tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackTreeOptions {
    /// Whether to include descriptions and pattern details.
    pub verbose: bool,
    /// Whether to show every pattern instead of truncating large sections.
    pub expand: bool,
    /// Maximum number of patterns shown per section when not expanded.
    pub max_patterns: usize,
}

impl PackTreeOptions {
    /// Create pack tree options using the default pattern limit.
    #[must_use]
    pub const fn new(verbose: bool) -> Self {
        Self {
            verbose,
            expand: false,
            max_patterns: DEFAULT_PACK_TREE_MAX_PATTERNS,
        }
    }

    /// Enable or disable expanded pattern rendering.
    #[must_use]
    pub const fn expand(mut self, expand: bool) -> Self {
        self.expand = expand;
        self
    }

    /// Set the maximum number of patterns rendered per section.
    #[must_use]
    pub const fn max_patterns(mut self, max_patterns: usize) -> Self {
        self.max_patterns = max_patterns;
        self
    }

    fn normalized_max_patterns(self) -> usize {
        self.max_patterns.max(1)
    }
}

/// Guide style for tree rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DcgTreeGuides {
    /// ASCII guides using `|`, `+`, and `-` characters.
    Ascii,
    /// Unicode box-drawing characters (default).
    #[default]
    Unicode,
    /// Bold Unicode box-drawing characters.
    Bold,
    /// Rounded Unicode characters for softer appearance.
    Rounded,
}

/// A pack row formatted for tree rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackTreeItem {
    /// Stable pack ID, for example `core.git`.
    pub id: String,
    /// Human-readable pack name.
    pub name: String,
    /// Top-level category, for example `core`.
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this pack is enabled.
    pub enabled: bool,
    /// Safe pattern count.
    pub safe_pattern_count: usize,
    /// Destructive pattern count.
    pub destructive_pattern_count: usize,
    /// Safe patterns to render in verbose mode.
    pub safe_patterns: Vec<PackTreePattern>,
    /// Destructive patterns to render in verbose mode.
    pub destructive_patterns: Vec<PackTreePattern>,
}

impl PackTreeItem {
    /// Create a pack tree item.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: impl Into<String>,
        description: impl Into<String>,
        enabled: bool,
        safe_pattern_count: usize,
        destructive_pattern_count: usize,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            category: category.into(),
            description: description.into(),
            enabled,
            safe_pattern_count,
            destructive_pattern_count,
            safe_patterns: Vec::new(),
            destructive_patterns: Vec::new(),
        }
    }

    /// Attach pattern details for verbose rendering.
    #[must_use]
    pub fn with_patterns(
        mut self,
        safe_patterns: Vec<PackTreePattern>,
        destructive_patterns: Vec<PackTreePattern>,
    ) -> Self {
        self.safe_patterns = safe_patterns;
        self.destructive_patterns = destructive_patterns;
        self
    }
}

/// Pack dependency row formatted for dependency tree rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyTreeItem {
    /// Stable pack ID, for example `kubernetes.production`.
    pub id: String,
    /// Human-readable pack name.
    pub name: String,
    /// Pack IDs this pack depends on or extends.
    pub dependencies: Vec<String>,
}

impl DependencyTreeItem {
    /// Create a dependency tree item without dependencies.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            dependencies: Vec::new(),
        }
    }

    /// Attach dependency pack IDs.
    #[must_use]
    pub fn with_dependencies<I, S>(mut self, dependencies: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.dependencies = dependencies.into_iter().map(Into::into).collect();
        self
    }
}

impl DcgTreeGuides {
    /// Create guides based on the current theme's border style.
    #[must_use]
    pub fn from_theme(theme: &Theme) -> Self {
        match theme.border_style {
            BorderStyle::Ascii => Self::Ascii,
            BorderStyle::Unicode => Self::Unicode,
            BorderStyle::None => Self::Ascii,
        }
    }

    /// Get the branch character for items with siblings below.
    #[must_use]
    pub const fn branch(&self) -> &str {
        match self {
            Self::Ascii => "+-- ",
            Self::Unicode => "├── ",
            Self::Bold => "┣━━ ",
            Self::Rounded => "├── ",
        }
    }

    /// Get the last item character for items without siblings below.
    #[must_use]
    pub const fn last(&self) -> &str {
        match self {
            Self::Ascii => "`-- ",
            Self::Unicode => "└── ",
            Self::Bold => "┗━━ ",
            Self::Rounded => "╰── ",
        }
    }

    /// Get the vertical continuation character.
    #[must_use]
    pub const fn vertical(&self) -> &str {
        match self {
            Self::Ascii => "|   ",
            Self::Unicode | Self::Rounded => "│   ",
            Self::Bold => "┃   ",
        }
    }

    /// Get the space for indentation.
    #[must_use]
    pub const fn space(&self) -> &'static str {
        "    "
    }
}

/// A node in a dcg tree structure.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// The label text for this node.
    pub label: String,
    /// Optional icon (emoji or character).
    pub icon: Option<String>,
    /// Optional style markup (e.g., "[bold cyan]").
    pub style: Option<String>,
    /// Child nodes.
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    /// Create a new tree node with a plain label.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            icon: None,
            style: None,
            children: Vec::new(),
        }
    }

    /// Create a new tree node with an icon.
    #[must_use]
    pub fn with_icon(icon: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            icon: Some(icon.into()),
            style: None,
            children: Vec::new(),
        }
    }

    /// Add a style to this node.
    #[must_use]
    pub fn styled(mut self, style: impl Into<String>) -> Self {
        self.style = Some(style.into());
        self
    }

    /// Add a child node.
    #[must_use]
    pub fn child(mut self, node: TreeNode) -> Self {
        self.children.push(node);
        self
    }

    /// Add multiple children.
    #[must_use]
    pub fn children(mut self, nodes: impl IntoIterator<Item = TreeNode>) -> Self {
        self.children.extend(nodes);
        self
    }

    /// Check if this node has children.
    #[must_use]
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Convert to rich_rust TreeNode (when feature enabled).
    #[cfg(feature = "rich-output")]
    fn to_rich_node(&self) -> RichTreeNode {
        let label = if let Some(ref style) = self.style {
            format!("{style}{}{style_end}", self.label, style_end = "[/]")
        } else {
            self.label.clone()
        };

        let mut node = if let Some(ref icon) = self.icon {
            RichTreeNode::with_icon(icon.clone(), label)
        } else {
            RichTreeNode::new(label)
        };

        for child in &self.children {
            node = node.child(child.to_rich_node());
        }

        node
    }
}

/// A tree structure for rendering hierarchical data.
#[derive(Debug, Clone)]
pub struct DcgTree {
    /// Root node of the tree.
    root: TreeNode,
    /// Guide style to use.
    guides: DcgTreeGuides,
    /// Whether to show the root node.
    show_root: bool,
    /// Optional title/header.
    title: Option<String>,
}

impl DcgTree {
    /// Create a new tree with a root node.
    #[must_use]
    pub fn new(root: TreeNode) -> Self {
        Self {
            root,
            guides: DcgTreeGuides::default(),
            show_root: true,
            title: None,
        }
    }

    /// Create a tree with just a label for the root.
    #[must_use]
    pub fn with_label(label: impl Into<String>) -> Self {
        Self::new(TreeNode::new(label))
    }

    /// Set the guide style.
    #[must_use]
    pub fn guides(mut self, guides: DcgTreeGuides) -> Self {
        self.guides = guides;
        self
    }

    /// Configure guides from a theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &Theme) -> Self {
        self.guides = DcgTreeGuides::from_theme(theme);
        self
    }

    /// Set whether to show the root node.
    #[must_use]
    pub fn show_root(mut self, show: bool) -> Self {
        self.show_root = show;
        self
    }

    /// Hide the root node.
    #[must_use]
    pub fn hide_root(self) -> Self {
        self.show_root(false)
    }

    /// Set a title for the tree.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Add a child to the root node.
    #[must_use]
    pub fn child(mut self, node: TreeNode) -> Self {
        self.root.children.push(node);
        self
    }

    /// Add multiple children to the root.
    #[must_use]
    pub fn children(mut self, nodes: impl IntoIterator<Item = TreeNode>) -> Self {
        self.root.children.extend(nodes);
        self
    }

    /// Render the tree using rich_rust (when feature enabled).
    #[cfg(feature = "rich-output")]
    pub fn render_rich(&self) {
        use super::console::console;

        let con = console();

        // Print title if set
        if let Some(ref title) = self.title {
            con.print(title);
        }

        // Convert to rich_rust tree
        let rich_guides = match self.guides {
            DcgTreeGuides::Ascii => TreeGuides::Ascii,
            DcgTreeGuides::Unicode => TreeGuides::Unicode,
            DcgTreeGuides::Bold => TreeGuides::Bold,
            DcgTreeGuides::Rounded => TreeGuides::Rounded,
        };

        let tree = RichTree::new(self.root.to_rich_node())
            .guides(rich_guides)
            .guide_style(Style::new().color_str("bright_black").unwrap_or_default())
            .show_root(self.show_root);

        con.print_renderable(&tree);
    }

    /// Render the tree as plain text lines.
    #[must_use]
    pub fn render_plain(&self) -> Vec<String> {
        let mut lines = Vec::new();

        if let Some(ref title) = self.title {
            lines.push(title.clone());
        }

        if self.show_root {
            self.render_node_plain(&self.root, &mut lines, &[], true);
        } else {
            let children = &self.root.children;
            for (i, child) in children.iter().enumerate() {
                let is_last = i == children.len() - 1;
                self.render_node_plain(child, &mut lines, &[], is_last);
            }
        }

        lines
    }

    /// Recursively render a node and its children.
    fn render_node_plain(
        &self,
        node: &TreeNode,
        lines: &mut Vec<String>,
        prefix_stack: &[bool],
        is_last: bool,
    ) {
        let mut line = String::new();

        // Build prefix from ancestors
        for &has_more_siblings in prefix_stack {
            if has_more_siblings {
                line.push_str(self.guides.vertical());
            } else {
                line.push_str(self.guides.space());
            }
        }

        // Add branch guide
        if !prefix_stack.is_empty() || !self.show_root {
            if is_last {
                line.push_str(self.guides.last());
            } else {
                line.push_str(self.guides.branch());
            }
        }

        // Add icon if present
        if let Some(ref icon) = node.icon {
            line.push_str(icon);
            line.push(' ');
        }

        // Add label
        line.push_str(&node.label);

        lines.push(line);

        // Render children
        let mut new_prefix_stack = prefix_stack.to_vec();
        new_prefix_stack.push(!is_last);

        for (i, child) in node.children.iter().enumerate() {
            let child_is_last = i == node.children.len() - 1;
            self.render_node_plain(child, lines, &new_prefix_stack, child_is_last);
        }
    }

    /// Render the tree to the console (uses rich output if available).
    pub fn render(&self) {
        #[cfg(feature = "rich-output")]
        {
            if super::should_use_rich_output() {
                self.render_rich();
                return;
            }
        }

        // Fallback to plain text
        for line in self.render_plain() {
            eprintln!("{line}");
        }
    }
}

/// Builder for creating explain trace trees.
///
/// Provides a convenient API for building the tree visualization
/// of command evaluation traces.
#[derive(Debug, Default)]
pub struct ExplainTreeBuilder {
    command_node: Option<TreeNode>,
    match_node: Option<TreeNode>,
    allowlist_node: Option<TreeNode>,
    pack_node: Option<TreeNode>,
    pipeline_node: Option<TreeNode>,
    suggestions_node: Option<TreeNode>,
}

impl ExplainTreeBuilder {
    /// Create a new explain tree builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the command section.
    #[must_use]
    pub fn command(mut self, node: TreeNode) -> Self {
        self.command_node = Some(node);
        self
    }

    /// Set the match section.
    #[must_use]
    pub fn match_info(mut self, node: TreeNode) -> Self {
        self.match_node = Some(node);
        self
    }

    /// Set the allowlist section.
    #[must_use]
    pub fn allowlist(mut self, node: TreeNode) -> Self {
        self.allowlist_node = Some(node);
        self
    }

    /// Set the packs section.
    #[must_use]
    pub fn packs(mut self, node: TreeNode) -> Self {
        self.pack_node = Some(node);
        self
    }

    /// Set the pipeline section.
    #[must_use]
    pub fn pipeline(mut self, node: TreeNode) -> Self {
        self.pipeline_node = Some(node);
        self
    }

    /// Set the suggestions section.
    #[must_use]
    pub fn suggestions(mut self, node: TreeNode) -> Self {
        self.suggestions_node = Some(node);
        self
    }

    /// Build the final tree.
    #[must_use]
    pub fn build(self) -> DcgTree {
        let mut root = TreeNode::new("DCG EXPLAIN");

        if let Some(node) = self.command_node {
            root = root.child(node);
        }
        if let Some(node) = self.match_node {
            root = root.child(node);
        }
        if let Some(node) = self.allowlist_node {
            root = root.child(node);
        }
        if let Some(node) = self.pack_node {
            root = root.child(node);
        }
        if let Some(node) = self.pipeline_node {
            root = root.child(node);
        }
        if let Some(node) = self.suggestions_node {
            root = root.child(node);
        }

        DcgTree::new(root).hide_root()
    }
}

/// Build the rich/plain tree used by `dcg explain`.
#[must_use]
pub fn explain_trace_tree(trace: &ExplainTrace) -> DcgTree {
    let mut root = TreeNode::new("DCG EXPLAIN")
        .child(decision_node(trace))
        .child(command_node(trace));

    if let Some(info) = trace.match_info.as_ref() {
        root = root.child(match_node(info));
    }

    if let Some(info) = trace.allowlist_info.as_ref() {
        root = root.child(
            TreeNode::new("Allowlist Override")
                .styled("[bold green]")
                .child(TreeNode::new(format!("Layer: {:?}", info.layer)))
                .child(TreeNode::new(format!("Reason: {}", info.entry_reason)))
                .child(TreeNode::new(format!(
                    "Overrode: {} - {}",
                    info.original_match.rule_id.as_deref().unwrap_or("unknown"),
                    info.original_match.reason
                ))),
        );
    }

    if let Some(summary) = trace.pack_summary.as_ref() {
        root = root.child(pack_summary_node(summary));
    }

    if !trace.steps.is_empty() {
        root = root.child(pipeline_node(&trace.steps));
    }

    if trace.skipped_due_to_budget {
        root = root.child(
            TreeNode::new("Budget")
                .styled("[bold yellow]")
                .child(TreeNode::new(
                    "Skipped deeper analysis after budget exhaustion",
                )),
        );
    }

    if let Some(node) = suggestions_node(trace) {
        root = root.child(node);
    }

    DcgTree::new(root)
}

fn decision_node(trace: &ExplainTrace) -> TreeNode {
    let (decision, style) = match trace.decision {
        EvaluationDecision::Allow => ("ALLOW", "[bold green]"),
        EvaluationDecision::Deny => ("DENY", "[bold red]"),
    };

    TreeNode::new(format!("Decision: {decision}"))
        .styled(style)
        .child(TreeNode::new(format!(
            "Latency: {:.2}ms",
            trace.total_duration_us as f64 / 1000.0
        )))
}

fn command_node(trace: &ExplainTrace) -> TreeNode {
    let has_normalized = trace
        .normalized_command
        .as_ref()
        .is_some_and(|normalized| normalized != &trace.command);
    let has_sanitized = trace.sanitized_command.as_ref().is_some_and(|sanitized| {
        sanitized != &trace.command && Some(sanitized) != trace.normalized_command.as_ref()
    });

    let mut node = TreeNode::new("Command")
        .styled("[bold cyan]")
        .child(TreeNode::new(format!("Input: {}", trace.command)));

    if has_normalized {
        if let Some(normalized) = trace.normalized_command.as_ref() {
            node = node.child(TreeNode::new(format!("Normalized: {normalized}")));
        }
    }

    if has_sanitized {
        if let Some(sanitized) = trace.sanitized_command.as_ref() {
            node = node.child(TreeNode::new(format!("Sanitized: {sanitized}")));
        }
    }

    node
}

fn match_node(info: &MatchInfo) -> TreeNode {
    let mut children = Vec::new();

    if let Some(rule_id) = info.rule_id.as_ref() {
        children.push(TreeNode::new(format!("Rule ID: {rule_id}")));
    }
    if let Some(pack_id) = info.pack_id.as_ref() {
        children.push(TreeNode::new(format!("Pack: {pack_id}")));
    }
    if let Some(pattern) = info.pattern_name.as_ref() {
        children.push(TreeNode::new(format!("Pattern: {pattern}")));
    }
    if let (Some(pack_id), Some(pattern_name)) =
        (info.pack_id.as_deref(), info.pattern_name.as_deref())
    {
        if let Some(regex) = crate::highlight::find_pattern_regex(pack_id, pattern_name) {
            let regex = crate::highlight::format_regex_pattern(
                &regex,
                crate::output::auto_theme().colors_enabled,
            );
            children.push(TreeNode::new(format!("Regex: {regex}")));
        }
    }
    if let Some(severity) = info.severity {
        children.push(TreeNode::new(format!("Severity: {severity:?}")));
    }
    children.push(TreeNode::new(format!("Source: {:?}", info.source)));
    children.push(TreeNode::new(format!("Reason: {}", info.reason)));

    if let (Some(start), Some(end)) = (info.match_start, info.match_end) {
        children.push(TreeNode::new(format!("Span: bytes {start}..{end}")));
    }
    if let Some(preview) = info.matched_text_preview.as_ref() {
        children.push(TreeNode::new(format!("Matched: {preview}")));
    }
    if let Some(explanation) = info.explanation.as_ref() {
        children
            .push(TreeNode::new("Explanation").children(markdown_explanation_nodes(explanation)));
    }

    TreeNode::new("Match")
        .styled("[bold yellow]")
        .children(children)
}

fn markdown_explanation_nodes(explanation: &str) -> Vec<TreeNode> {
    let use_color = crate::output::auto_theme().colors_enabled;
    let width = usize::from(crate::output::terminal_width())
        .saturating_sub(8)
        .max(40);
    crate::highlight::format_markdown_explanation(explanation, use_color, width)
        .lines()
        .map(|line| TreeNode::new(line.trim().to_string()))
        .collect()
}

fn pack_summary_node(summary: &PackSummary) -> TreeNode {
    let mut node = TreeNode::new("Packs")
        .styled("[bold magenta]")
        .child(TreeNode::new(format!(
            "Enabled: {} packs",
            summary.enabled_count
        )));

    if !summary.evaluated.is_empty() {
        node = node.child(TreeNode::new(format!(
            "Evaluated: {}",
            summary.evaluated.join(", ")
        )));
    }

    if !summary.skipped.is_empty() {
        node = node.child(TreeNode::new(format!(
            "Skipped (keyword gating): {}",
            summary.skipped.join(", ")
        )));
    }

    node
}

fn pipeline_node(steps: &[TraceStep]) -> TreeNode {
    TreeNode::new("Pipeline Trace")
        .styled("[bold blue]")
        .children(steps.iter().map(trace_step_node))
}

fn trace_step_node(step: &TraceStep) -> TreeNode {
    let summary = trace_details_summary(&step.details);
    let mut node = TreeNode::new(format!(
        "{} ({:.2}ms)",
        step.name,
        step.duration_us as f64 / 1000.0
    ));

    if !summary.is_empty() {
        node = node.child(TreeNode::new(summary));
    }

    node
}

fn trace_details_summary(details: &TraceDetails) -> String {
    match details {
        TraceDetails::InputParsing {
            is_hook_input,
            command_len,
        } => format!("hook input: {is_hook_input}, command bytes: {command_len}"),
        TraceDetails::KeywordGating {
            quick_rejected,
            keywords_checked,
            first_match,
        } => {
            if *quick_rejected {
                format!("quick pass after {} keyword checks", keywords_checked.len())
            } else if let Some(keyword) = first_match {
                format!("matched: {keyword}")
            } else {
                format!("no match after {} keyword checks", keywords_checked.len())
            }
        }
        TraceDetails::Normalization {
            was_modified,
            stripped_prefix,
        } => {
            if *was_modified {
                stripped_prefix.as_ref().map_or_else(
                    || "modified".to_string(),
                    |prefix| format!("stripped prefix: {prefix}"),
                )
            } else {
                "unchanged".to_string()
            }
        }
        TraceDetails::Sanitization {
            was_modified,
            spans_masked,
        } => {
            if *was_modified {
                format!("{spans_masked} spans masked")
            } else {
                "unchanged".to_string()
            }
        }
        TraceDetails::HeredocDetection {
            triggered,
            scripts_extracted,
            languages,
        } => {
            if *triggered {
                let suffix = if languages.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", languages.join(", "))
                };
                format!("{scripts_extracted} scripts{suffix}")
            } else {
                "none".to_string()
            }
        }
        TraceDetails::AllowlistCheck {
            layers_checked,
            matched,
            matched_layer,
        } => {
            if *matched {
                matched_layer.as_ref().map_or_else(
                    || format!("matched after {layers_checked} layers"),
                    |layer| format!("matched {layer:?} after {layers_checked} layers"),
                )
            } else {
                format!("no match after {layers_checked} layers")
            }
        }
        TraceDetails::PackEvaluation {
            packs_evaluated,
            packs_skipped,
            matched_pack,
            matched_pattern,
        } => {
            if let Some(pack) = matched_pack {
                matched_pattern.as_ref().map_or_else(
                    || format!("matched in {pack}"),
                    |pattern| format!("matched {pack}:{pattern}"),
                )
            } else {
                format!(
                    "{} packs checked, {} skipped",
                    packs_evaluated.len(),
                    packs_skipped.len()
                )
            }
        }
        TraceDetails::ConfigOverride {
            allow_matched,
            block_matched,
            reason,
        } => {
            if *allow_matched {
                "allow override matched".to_string()
            } else if *block_matched {
                reason.as_ref().map_or_else(
                    || "block override matched".to_string(),
                    |reason| format!("block override: {reason}"),
                )
            } else {
                "no override".to_string()
            }
        }
        TraceDetails::PolicyDecision {
            decision,
            allowlisted,
        } => {
            let decision = match decision {
                EvaluationDecision::Allow => "allow",
                EvaluationDecision::Deny => "deny",
            };
            if *allowlisted {
                format!("{decision} via allowlist")
            } else {
                decision.to_string()
            }
        }
    }
}

fn suggestions_node(trace: &ExplainTrace) -> Option<TreeNode> {
    if !crate::output::suggestions_enabled() {
        return None;
    }

    let rule_id = trace.match_info.as_ref()?.rule_id.as_deref()?;
    let suggestions = crate::suggestions::get_suggestions(rule_id)?;
    if suggestions.is_empty() {
        return None;
    }

    Some(
        TreeNode::new("Suggestions")
            .styled("[bold yellow]")
            .children(suggestions.iter().map(|suggestion| {
                let mut node =
                    TreeNode::new(format!("{}: {}", suggestion.kind.label(), suggestion.text));

                if let Some(command) = suggestion.command.as_ref() {
                    node = node.child(TreeNode::new(format!("$ {command}")));
                }
                if let Some(url) = suggestion.url.as_ref() {
                    node = node.child(TreeNode::new(format!("See: {url}")));
                }

                node
            })),
    )
}

/// Build the rich/plain tree used by `dcg packs`.
#[must_use]
pub fn pack_list_tree(items: &[PackTreeItem], verbose: bool) -> DcgTree {
    pack_list_tree_with_options(items, PackTreeOptions::new(verbose))
}

/// Build the rich/plain tree used by `dcg packs` with explicit render options.
#[must_use]
pub fn pack_list_tree_with_options(items: &[PackTreeItem], options: PackTreeOptions) -> DcgTree {
    let mut by_category: BTreeMap<&str, Vec<&PackTreeItem>> = BTreeMap::new();
    for item in items {
        by_category
            .entry(item.category.as_str())
            .or_default()
            .push(item);
    }

    let mut root = TreeNode::new("Available Packs");

    if by_category.is_empty() {
        root = root.child(TreeNode::new("No packs to display").styled("[dim]"));
    } else {
        for (category, mut packs) in by_category {
            packs.sort_by(|left, right| left.id.cmp(&right.id));
            root = root.child(
                TreeNode::new(category)
                    .styled("[bold]")
                    .children(packs.into_iter().map(|pack| pack_tree_node(pack, options))),
            );
        }
    }

    root = root.child(
        TreeNode::new("Legend")
            .styled("[dim]")
            .child(TreeNode::new("● = enabled"))
            .child(TreeNode::new("○ = disabled"))
            .child(TreeNode::new("Enable packs in ~/.config/dcg/config.toml")),
    );

    DcgTree::new(root).guides(DcgTreeGuides::Rounded)
}

fn pack_tree_node(pack: &PackTreeItem, options: PackTreeOptions) -> TreeNode {
    let status = if pack.enabled { "●" } else { "○" };
    let style = if pack.enabled { "[green]" } else { "[dim]" };
    let label = if options.verbose {
        let description = markdown_single_line(&pack.description);
        format!(
            "{} - {} ({} safe, {} destructive)",
            pack.id, description, pack.safe_pattern_count, pack.destructive_pattern_count
        )
    } else {
        format!("{} - {}", pack.id, pack.name)
    };

    let mut node = TreeNode::with_icon(status, label).styled(style);

    if options.verbose {
        if !pack.safe_patterns.is_empty() {
            node = node.child(pattern_group_node(
                "Safe patterns",
                &pack.safe_patterns,
                options,
            ));
        }
        if !pack.destructive_patterns.is_empty() {
            node = node.child(pattern_group_node(
                "Destructive patterns",
                &pack.destructive_patterns,
                options,
            ));
        }
    }

    node
}

fn markdown_single_line(text: &str) -> String {
    crate::highlight::format_markdown_explanation(
        text,
        false,
        usize::from(crate::output::terminal_width()).max(40),
    )
    .split_whitespace()
    .collect::<Vec<_>>()
    .join(" ")
}

fn pattern_group_node(
    title: &str,
    patterns: &[PackTreePattern],
    options: PackTreeOptions,
) -> TreeNode {
    let use_color = crate::output::auto_theme().colors_enabled;
    let total = patterns.len();
    let section_title = if total > options.normalized_max_patterns() && !options.expand {
        format!("{title} ({total} total)")
    } else {
        title.to_string()
    };

    let mut node = TreeNode::new(section_title).styled("[dim]");

    if options.expand || total <= options.normalized_max_patterns() {
        return node.children(
            patterns
                .iter()
                .map(|pattern| pattern_tree_node(pattern, use_color)),
        );
    }

    let max_patterns = options.normalized_max_patterns();
    let head_count = max_patterns.div_ceil(2);
    let tail_count = max_patterns.saturating_sub(head_count);
    let hidden_count = total.saturating_sub(head_count + tail_count);

    node = node.children(
        patterns
            .iter()
            .take(head_count)
            .map(|pattern| pattern_tree_node(pattern, use_color)),
    );

    node = node.child(
        TreeNode::new(format!(
            "... {hidden_count} more patterns (--expand to show all)"
        ))
        .styled("[dim]"),
    );

    if tail_count > 0 {
        node = node.children(
            patterns
                .iter()
                .skip(total - tail_count)
                .map(|pattern| pattern_tree_node(pattern, use_color)),
        );
    }

    node
}

fn pattern_tree_node(pattern: &PackTreePattern, use_color: bool) -> TreeNode {
    let regex = crate::highlight::format_regex_pattern(&pattern.regex, use_color);
    let label = if let Some(severity) = &pattern.severity {
        format!("{} [{}]: {}", pattern.name, severity, regex)
    } else {
        format!("{}: {}", pattern.name, regex)
    };
    TreeNode::new(label)
}

/// Maximum depth the recursive dependency tree renderer is allowed to descend.
///
/// External pack manifests are user-controlled YAML; without a bound, a long
/// (or pathological) dependency chain `a -> b -> c -> ...` would recurse
/// linearly and overflow the thread stack. The release profile uses
/// `panic = "abort"`, so a stack overflow crashes the dcg process — a
/// fail-open violation when triggered from a hook hot path. 32 levels is far
/// deeper than any reasonable real-world pack hierarchy and keeps the
/// renderer safe from adversarial inputs.
const MAX_DEPENDENCY_TREE_DEPTH: usize = 32;

/// Build a tree showing pack dependency relationships.
#[must_use]
pub fn pack_dependency_tree(items: &[DependencyTreeItem]) -> DcgTree {
    let mut by_id: BTreeMap<&str, &DependencyTreeItem> = BTreeMap::new();
    let mut referenced: BTreeSet<&str> = BTreeSet::new();

    for item in items {
        by_id.insert(item.id.as_str(), item);
        for dependency in &item.dependencies {
            referenced.insert(dependency.as_str());
        }
    }

    let mut roots: Vec<&DependencyTreeItem> = items
        .iter()
        .filter(|item| !referenced.contains(item.id.as_str()))
        .collect();
    if roots.is_empty() {
        roots = items.iter().collect();
    }
    roots.sort_by(|left, right| left.id.cmp(&right.id));

    let mut root = TreeNode::new("Pack Dependencies");
    if roots.is_empty() {
        root = root.child(TreeNode::new("No dependencies to display").styled("[dim]"));
    } else {
        for item in roots {
            root = root.child(dependency_root_node(item, &by_id, &mut Vec::new(), 0));
        }
    }

    DcgTree::new(root).guides(DcgTreeGuides::Rounded)
}

fn dependency_root_node<'a>(
    item: &'a DependencyTreeItem,
    by_id: &BTreeMap<&'a str, &'a DependencyTreeItem>,
    stack: &mut Vec<&'a str>,
    depth: usize,
) -> TreeNode {
    stack.push(item.id.as_str());
    let mut node = TreeNode::new(format!("{} - {}", item.id, item.name)).styled("[cyan]");

    if depth >= MAX_DEPENDENCY_TREE_DEPTH {
        node = node.child(
            TreeNode::new(format!(
                "... (depth limit {MAX_DEPENDENCY_TREE_DEPTH} reached)"
            ))
            .styled("[dim]"),
        );
    } else {
        for dependency in &item.dependencies {
            node = node.child(dependency_edge_node(dependency, by_id, stack, depth + 1));
        }
    }

    stack.pop();
    node
}

fn dependency_edge_node<'a>(
    dependency_id: &str,
    by_id: &BTreeMap<&'a str, &'a DependencyTreeItem>,
    stack: &mut Vec<&'a str>,
    depth: usize,
) -> TreeNode {
    if stack.contains(&dependency_id) {
        return TreeNode::new(format!("extends {dependency_id} (cycle)")).styled("[red]");
    }

    if depth >= MAX_DEPENDENCY_TREE_DEPTH {
        return TreeNode::new(format!(
            "extends {dependency_id} (depth limit {MAX_DEPENDENCY_TREE_DEPTH} reached)"
        ))
        .styled("[dim]");
    }

    let Some(item) = by_id.get(dependency_id).copied() else {
        return TreeNode::new(format!("extends {dependency_id} (missing)")).styled("[yellow]");
    };

    stack.push(item.id.as_str());
    let mut node = TreeNode::new(format!("extends {} - {}", item.id, item.name)).styled("[yellow]");
    for dependency in &item.dependencies {
        node = node.child(dependency_edge_node(dependency, by_id, stack, depth + 1));
    }
    stack.pop();

    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::MatchSource;
    use crate::packs::Severity;
    use crate::trace::{ExplainTrace, MatchInfo, PackSummary, TraceDetails, TraceStep};

    #[test]
    fn test_tree_node_creation() {
        let node = TreeNode::new("test label");
        assert_eq!(node.label, "test label");
        assert!(node.icon.is_none());
        assert!(node.children.is_empty());
    }

    #[test]
    fn test_tree_node_with_icon() {
        let node = TreeNode::with_icon("📁", "folder");
        assert_eq!(node.label, "folder");
        assert_eq!(node.icon.as_deref(), Some("📁"));
    }

    #[test]
    fn test_tree_node_children() {
        let node = TreeNode::new("parent")
            .child(TreeNode::new("child1"))
            .child(TreeNode::new("child2"));
        assert_eq!(node.children.len(), 2);
        assert!(node.has_children());
    }

    #[test]
    fn test_dcg_tree_render_plain() {
        let tree = DcgTree::with_label("Root")
            .child(TreeNode::new("Child 1"))
            .child(TreeNode::new("Child 2").child(TreeNode::new("Grandchild")));

        let lines = tree.render_plain();
        assert!(!lines.is_empty());
        assert_eq!(lines[0], "Root");
    }

    #[test]
    fn test_dcg_tree_guides() {
        let guides = DcgTreeGuides::Unicode;
        assert_eq!(guides.branch(), "├── ");
        assert_eq!(guides.last(), "└── ");
        assert_eq!(guides.vertical(), "│   ");

        let ascii = DcgTreeGuides::Ascii;
        assert_eq!(ascii.branch(), "+-- ");
        assert_eq!(ascii.last(), "`-- ");
    }

    #[test]
    fn test_explain_tree_builder() {
        let tree = ExplainTreeBuilder::new()
            .command(TreeNode::new("Command").child(TreeNode::new("rm -rf /")))
            .match_info(TreeNode::new("Match").child(TreeNode::new("rule: rm_rf")))
            .build();

        let lines = tree.render_plain();
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_tree_node_no_children() {
        let node = TreeNode::new("leaf");
        assert!(!node.has_children());
    }

    #[test]
    fn test_tree_node_styled() {
        let node = TreeNode::new("styled").styled("[bold red]");
        assert_eq!(node.style.as_deref(), Some("[bold red]"));
    }

    #[test]
    fn test_tree_node_children_batch() {
        let children = vec![TreeNode::new("a"), TreeNode::new("b"), TreeNode::new("c")];
        let node = TreeNode::new("root").children(children);
        assert_eq!(node.children.len(), 3);
    }

    #[test]
    fn test_bold_guides() {
        let guides = DcgTreeGuides::Bold;
        assert_eq!(guides.branch(), "┣━━ ");
        assert_eq!(guides.last(), "┗━━ ");
        assert_eq!(guides.vertical(), "┃   ");
    }

    #[test]
    fn test_rounded_guides() {
        let guides = DcgTreeGuides::Rounded;
        assert_eq!(guides.branch(), "├── ");
        assert_eq!(guides.last(), "╰── ");
        assert_eq!(guides.vertical(), "│   ");
    }

    #[test]
    fn test_guides_space() {
        // All guide styles should have the same space indent
        assert_eq!(DcgTreeGuides::Ascii.space(), "    ");
        assert_eq!(DcgTreeGuides::Unicode.space(), "    ");
        assert_eq!(DcgTreeGuides::Bold.space(), "    ");
        assert_eq!(DcgTreeGuides::Rounded.space(), "    ");
    }

    #[test]
    fn test_guides_from_theme() {
        let theme = Theme::default();
        let guides = DcgTreeGuides::from_theme(&theme);
        assert_eq!(guides, DcgTreeGuides::Unicode);

        let no_color = Theme::no_color();
        let guides = DcgTreeGuides::from_theme(&no_color);
        assert_eq!(guides, DcgTreeGuides::Ascii);

        let minimal = Theme::minimal();
        let guides = DcgTreeGuides::from_theme(&minimal);
        assert_eq!(guides, DcgTreeGuides::Ascii);
    }

    #[test]
    fn test_tree_render_plain_with_title() {
        let tree = DcgTree::with_label("Root")
            .title("My Tree Title")
            .child(TreeNode::new("Item 1"));

        let lines = tree.render_plain();
        assert_eq!(lines[0], "My Tree Title");
        assert!(lines.len() >= 3); // title + root + child
    }

    #[test]
    fn test_tree_render_plain_hidden_root() {
        let tree = DcgTree::with_label("Hidden Root")
            .hide_root()
            .child(TreeNode::new("Child A"))
            .child(TreeNode::new("Child B"));

        let lines = tree.render_plain();
        // Root should not appear in output
        assert!(!lines.iter().any(|l| l.contains("Hidden Root")));
        // Children should appear
        assert!(lines.iter().any(|l| l.contains("Child A")));
        assert!(lines.iter().any(|l| l.contains("Child B")));
    }

    #[test]
    fn test_tree_render_plain_ascii_guides() {
        let tree = DcgTree::with_label("Root")
            .guides(DcgTreeGuides::Ascii)
            .child(TreeNode::new("A"))
            .child(TreeNode::new("B"));

        let lines = tree.render_plain();
        // Should use ASCII branch characters
        assert!(lines.iter().any(|l| l.contains("+-- ")));
        assert!(lines.iter().any(|l| l.contains("`-- ")));
    }

    #[test]
    fn test_tree_render_plain_unicode_guides() {
        let tree = DcgTree::with_label("Root")
            .guides(DcgTreeGuides::Unicode)
            .child(TreeNode::new("A"))
            .child(TreeNode::new("B"));

        let lines = tree.render_plain();
        assert!(lines.iter().any(|l| l.contains("├── ")));
        assert!(lines.iter().any(|l| l.contains("└── ")));
    }

    #[test]
    fn test_tree_render_plain_deeply_nested() {
        let tree =
            DcgTree::with_label("L0").child(TreeNode::new("L1").child(
                TreeNode::new("L2").child(TreeNode::new("L3").child(TreeNode::new("L4 leaf"))),
            ));

        let lines = tree.render_plain();
        assert_eq!(lines.len(), 5); // L0, L1, L2, L3, L4
        assert!(lines[4].contains("L4 leaf"));
    }

    #[test]
    fn test_tree_render_plain_with_icons() {
        let tree = DcgTree::with_label("Packages")
            .child(TreeNode::with_icon("📦", "core.git"))
            .child(TreeNode::with_icon("📦", "core.filesystem"));

        let lines = tree.render_plain();
        assert!(lines.iter().any(|l| l.contains("📦 core.git")));
        assert!(lines.iter().any(|l| l.contains("📦 core.filesystem")));
    }

    #[test]
    fn test_tree_with_theme() {
        let theme = Theme::no_color();
        let tree = DcgTree::with_label("Root")
            .with_theme(&theme)
            .child(TreeNode::new("child"));

        let lines = tree.render_plain();
        // ASCII guides from no_color theme
        assert!(lines.iter().any(|l| l.contains("`-- ")));
    }

    #[test]
    fn test_explain_tree_builder_all_sections() {
        let tree = ExplainTreeBuilder::new()
            .command(TreeNode::new("Command"))
            .match_info(TreeNode::new("Match"))
            .allowlist(TreeNode::new("Allowlist"))
            .packs(TreeNode::new("Packs"))
            .pipeline(TreeNode::new("Pipeline"))
            .suggestions(TreeNode::new("Suggestions"))
            .build();

        let lines = tree.render_plain();
        // All sections should appear (root is hidden)
        assert!(lines.iter().any(|l| l.contains("Command")));
        assert!(lines.iter().any(|l| l.contains("Match")));
        assert!(lines.iter().any(|l| l.contains("Allowlist")));
        assert!(lines.iter().any(|l| l.contains("Packs")));
        assert!(lines.iter().any(|l| l.contains("Pipeline")));
        assert!(lines.iter().any(|l| l.contains("Suggestions")));
    }

    #[test]
    fn test_explain_tree_builder_empty() {
        let tree = ExplainTreeBuilder::new().build();
        let lines = tree.render_plain();
        // Empty builder with hidden root should produce no output
        assert!(lines.is_empty());
    }

    #[test]
    fn test_default_guides() {
        let guides = DcgTreeGuides::default();
        assert_eq!(guides, DcgTreeGuides::Unicode);
    }

    #[test]
    fn test_tree_render_does_not_panic() {
        // render() goes to stderr, just verify no panic
        let tree = DcgTree::with_label("Test").child(TreeNode::new("child"));
        tree.render();
    }

    #[test]
    fn test_explain_trace_tree_renders_decision_sections() {
        let trace = ExplainTrace {
            command: "git reset --hard HEAD".to_string(),
            normalized_command: Some("git reset --hard HEAD".to_string()),
            sanitized_command: None,
            decision: EvaluationDecision::Deny,
            skipped_due_to_budget: false,
            total_duration_us: 1_250,
            steps: vec![TraceStep {
                name: "full_evaluation",
                duration_us: 1_000,
                details: TraceDetails::KeywordGating {
                    quick_rejected: false,
                    keywords_checked: vec!["git".to_string()],
                    first_match: Some("core.git".to_string()),
                },
            }],
            match_info: Some(MatchInfo {
                rule_id: Some("core.git:reset-hard".to_string()),
                pack_id: Some("core.git".to_string()),
                pattern_name: Some("reset-hard".to_string()),
                severity: Some(Severity::Critical),
                reason: "git reset --hard destroys uncommitted changes".to_string(),
                source: MatchSource::Pack,
                match_start: Some(0),
                match_end: Some(16),
                matched_text_preview: Some("git reset --hard".to_string()),
                explanation: Some(
                    "Rewrites `HEAD` and **discards** changes. See [docs](https://example.test)."
                        .to_string(),
                ),
            }),
            allowlist_info: None,
            pack_summary: Some(PackSummary {
                enabled_count: 2,
                evaluated: vec!["core.git".to_string()],
                skipped: vec!["core.filesystem".to_string()],
            }),
        };

        let lines = explain_trace_tree(&trace)
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("DCG EXPLAIN"));
        assert!(output.contains("Decision: DENY"));
        assert!(output.contains("Latency: 1.25ms"));
        assert!(output.contains("Command"));
        assert!(output.contains("Rule ID: core.git:reset-hard"));
        assert!(output.contains("Severity: Critical"));
        assert!(output.contains("Rewrites HEAD and discards changes"));
        assert!(output.contains("docs (https://example.test)"));
        assert!(!output.contains("`HEAD`"));
        assert!(!output.contains("**discards**"));
        assert!(output.contains("Pipeline Trace"));
        assert!(output.contains("full_evaluation (1.00ms)"));
        assert!(output.contains("matched: core.git"));
        assert!(output.contains("Skipped (keyword gating): core.filesystem"));
    }

    #[test]
    fn test_pack_list_tree_groups_packs_by_category() {
        let items = vec![
            PackTreeItem::new(
                "database.postgresql",
                "PostgreSQL",
                "database",
                "Protects PostgreSQL operations",
                false,
                2,
                5,
            ),
            PackTreeItem::new(
                "core.git",
                "Git",
                "core",
                "Protects Git operations",
                true,
                3,
                8,
            ),
        ];

        let lines = pack_list_tree(&items, false)
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("Available Packs"));
        assert!(output.contains("core"));
        assert!(output.contains("● core.git - Git"));
        assert!(output.contains("database"));
        assert!(output.contains("○ database.postgresql - PostgreSQL"));
        assert!(output.contains("Legend"));
    }

    #[test]
    fn test_pack_list_tree_verbose_includes_pattern_counts() {
        let items = vec![PackTreeItem::new(
            "core.filesystem",
            "Filesystem",
            "core",
            "Protects filesystem operations",
            true,
            4,
            7,
        )];

        let lines = pack_list_tree(&items, true).render_plain();
        let output = lines.join("\n");

        assert!(output.contains("core.filesystem - Protects filesystem operations"));
        assert!(output.contains("(4 safe, 7 destructive)"));
    }

    #[test]
    fn test_pack_list_tree_verbose_includes_pattern_regexes() {
        let items = vec![
            PackTreeItem::new(
                "core.git",
                "Git",
                "core",
                "Protects Git operations",
                true,
                1,
                1,
            )
            .with_patterns(
                vec![PackTreePattern::safe(
                    "git-clean-dry-run",
                    r"^git\s+clean\s+-n",
                )],
                vec![PackTreePattern::destructive(
                    "reset-hard",
                    r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*reset\s+--hard",
                    "critical",
                )],
            ),
        ];

        let lines = pack_list_tree(&items, true)
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("Safe patterns"));
        assert!(output.contains(r"git-clean-dry-run: ^git\s+clean\s+-n"));
        assert!(output.contains("Destructive patterns"));
        assert!(output.contains("reset-hard [critical]:"));
        assert!(output.contains(r"git\s+(?:\S+\s+)*reset\s+--hard"));
    }

    #[test]
    fn test_pack_list_tree_truncates_large_pattern_sections() {
        let safe_patterns: Vec<_> = (1..=8)
            .map(|index| PackTreePattern::safe(format!("safe-{index}"), format!("^safe{index}$")))
            .collect();
        let items = vec![
            PackTreeItem::new(
                "core.large",
                "Large",
                "core",
                "Protects large command sets",
                true,
                8,
                0,
            )
            .with_patterns(safe_patterns, vec![]),
        ];

        let lines = pack_list_tree_with_options(&items, PackTreeOptions::new(true).max_patterns(4))
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("Safe patterns (8 total)"));
        assert!(output.contains("safe-1: ^safe1$"));
        assert!(output.contains("safe-2: ^safe2$"));
        assert!(output.contains("... 4 more patterns (--expand to show all)"));
        assert!(output.contains("safe-7: ^safe7$"));
        assert!(output.contains("safe-8: ^safe8$"));
        assert!(!output.contains("safe-3: ^safe3$"));
    }

    #[test]
    fn test_pack_list_tree_expand_shows_all_patterns() {
        let safe_patterns: Vec<_> = (1..=6)
            .map(|index| PackTreePattern::safe(format!("safe-{index}"), format!("^safe{index}$")))
            .collect();
        let items = vec![
            PackTreeItem::new(
                "core.large",
                "Large",
                "core",
                "Protects large command sets",
                true,
                6,
                0,
            )
            .with_patterns(safe_patterns, vec![]),
        ];

        let lines = pack_list_tree_with_options(
            &items,
            PackTreeOptions::new(true).expand(true).max_patterns(2),
        )
        .guides(DcgTreeGuides::Ascii)
        .render_plain();
        let output = lines.join("\n");

        for index in 1..=6 {
            assert!(output.contains(&format!("safe-{index}: ^safe{index}$")));
        }
        assert!(!output.contains("more patterns"));
    }

    #[test]
    fn test_pack_list_tree_empty() {
        let lines = pack_list_tree(&[], false).render_plain();
        let output = lines.join("\n");

        assert!(output.contains("Available Packs"));
        assert!(output.contains("No packs to display"));
        assert!(output.contains("Legend"));
    }

    #[test]
    fn test_pack_dependency_tree_renders_extends_edges() {
        let items = vec![
            DependencyTreeItem::new("kubernetes.base", "Kubernetes Base"),
            DependencyTreeItem::new("kubernetes.production", "Kubernetes Production")
                .with_dependencies(["kubernetes.base"]),
            DependencyTreeItem::new("strict_git", "Strict Git").with_dependencies(["core.git"]),
            DependencyTreeItem::new("core.git", "Git"),
        ];

        let lines = pack_dependency_tree(&items)
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("Pack Dependencies"));
        assert!(output.contains("kubernetes.production - Kubernetes Production"));
        assert!(output.contains("extends kubernetes.base - Kubernetes Base"));
        assert!(output.contains("strict_git - Strict Git"));
        assert!(output.contains("extends core.git - Git"));
    }

    #[test]
    fn test_pack_dependency_tree_marks_missing_dependencies() {
        let items = vec![
            DependencyTreeItem::new("custom.pack", "Custom Pack")
                .with_dependencies(["core.filesystem", "external.audit"]),
            DependencyTreeItem::new("core.filesystem", "Filesystem"),
        ];

        let lines = pack_dependency_tree(&items)
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("custom.pack - Custom Pack"));
        assert!(output.contains("extends core.filesystem - Filesystem"));
        assert!(output.contains("extends external.audit (missing)"));
    }

    #[test]
    fn test_pack_dependency_tree_bounds_deep_chain() {
        // External pack manifests are user-controlled YAML; without a
        // depth bound a chain `a -> b -> c -> ... -> n` would recurse
        // n times. The release profile uses `panic = "abort"`, so a stack
        // overflow crashes dcg — a fail-open violation. This test feeds
        // a 200-deep chain (well past MAX_DEPENDENCY_TREE_DEPTH = 32) and
        // asserts the renderer terminates cleanly with a "depth limit"
        // marker rather than overflowing the stack.
        let mut items = Vec::new();
        for i in 0..200 {
            let id = format!("pack-{i:03}");
            let next = format!("pack-{:03}", i + 1);
            items.push(DependencyTreeItem::new(&id, &id).with_dependencies([next.as_str()]));
        }
        // Terminate the chain with a leaf (no dependencies).
        items.push(DependencyTreeItem::new("pack-200", "pack-200"));

        let lines = pack_dependency_tree(&items)
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("Pack Dependencies"));
        assert!(
            output.contains("depth limit"),
            "expected depth-limit marker in output, got:\n{output}"
        );
    }

    #[test]
    fn test_pack_dependency_tree_marks_cycles() {
        let items = vec![
            DependencyTreeItem::new("pack.alpha", "Alpha").with_dependencies(["pack.beta"]),
            DependencyTreeItem::new("pack.beta", "Beta").with_dependencies(["pack.alpha"]),
        ];

        let lines = pack_dependency_tree(&items)
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("pack.alpha - Alpha"));
        assert!(output.contains("extends pack.beta - Beta"));
        assert!(output.contains("extends pack.alpha (cycle)"));
    }

    #[test]
    fn test_pack_dependency_tree_empty() {
        let lines = pack_dependency_tree(&[])
            .guides(DcgTreeGuides::Ascii)
            .render_plain();
        let output = lines.join("\n");

        assert!(output.contains("Pack Dependencies"));
        assert!(output.contains("No dependencies to display"));
    }
}
