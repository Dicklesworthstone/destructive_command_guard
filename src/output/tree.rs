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

#[cfg(test)]
mod tests {
    use super::*;

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
}
