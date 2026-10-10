//! This crate provides Bash language support for the [tree-sitter][] parsing library.
//!
//! Typically, you will use the [LANGUAGE][] constant to add this language to a
//! tree-sitter [Parser][], and then use the parser to parse some code:
//!
//! ```
//! use tree_sitter::Parser;
//!
//! let code = r#"
//! echo "hello world!"
//! "#;
//! let mut parser = Parser::new();
//! let language = tree_sitter_bash::LANGUAGE;
//! parser
//!     .set_language(&language.into())
//!     .expect("Error loading Bash parser");
//! let tree = parser.parse(code, None).unwrap();
//! assert!(!tree.root_node().has_error());
//! ```
//!
//! [Parser]: https://docs.rs/tree-sitter/*/tree_sitter/struct.Parser.html
//! [tree-sitter]: https://tree-sitter.github.io/

use tree_sitter_language::LanguageFn;

extern "C" {
    fn tree_sitter_bash() -> *const ();
}

/// The tree-sitter [`LanguageFn`][LanguageFn] for this grammar.
///
/// [LanguageFn]: https://docs.rs/tree-sitter-language/*/tree_sitter_language/struct.LanguageFn.html
pub const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_bash) };

/// The content of the [`node-types.json`][] file for this grammar.
///
/// [`node-types.json`]: https://tree-sitter.github.io/tree-sitter/using-parsers#static-node-types
pub const NODE_TYPES: &str = include_str!("../../src/node-types.json");

/// The syntax highlighting query for this grammar.
pub const HIGHLIGHT_QUERY: &str = include_str!("../../queries/highlights.scm");

#[cfg(test)]
mod tests {
    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&super::LANGUAGE.into())
            .expect("Error loading Bash parser");
        parser.parse(source, None).expect("Bash syntax tree")
    }

    fn contains_kind(root: tree_sitter::Node<'_>, kind: &str) -> bool {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if node.kind() == kind {
                return true;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        false
    }

    #[test]
    fn test_can_load_grammar() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&super::LANGUAGE.into())
            .expect("Error loading Bash parser");
    }

    #[test]
    fn quoted_heredoc_fragments_preserve_body_and_following_command_544() {
        for (word, terminator) in [
            ("'DOC'", "DOC"),
            ("\"DOC\"", "DOC"),
            ("D'OC'", "DOC"),
            ("D\"OC\"", "DOC"),
            ("'D'O\"C\"", "DOC"),
            ("D''OC", "DOC"),
            ("D\\OC", "DOC"),
            ("\\DOC", "DOC"),
            (r"'D\OC'", r"D\OC"),
            (r#""D\OC""#, r"D\OC"),
            (r#""D\\OC""#, r"D\OC"),
            (r#""D\$OC""#, "D$OC"),
            (r#""D\`OC""#, "D`OC"),
            (r#""D\"OC""#, "D\"OC"),
            (r"D\'OC", "D'OC"),
            ("''", ""),
            ("\"\"", ""),
        ] {
            let source = format!(
                "python3 - <<{word}\ntext = \"$(git reset --hard)\"\n{terminator}\ngit status\n"
            );
            let tree = parse(&source);
            let root = tree.root_node();
            assert!(
                !root.has_error(),
                "valid quote-removed delimiter {word:?}: {}",
                root.to_sexp()
            );
            assert!(
                !contains_kind(root, "command_substitution"),
                "quoting any delimiter fragment keeps the body literal: {word:?}"
            );
            assert_eq!(root.named_child_count(), 2, "source: {source:?}");
            let following = root.named_child(1).expect("following command");
            assert_eq!(following.kind(), "command", "source: {source:?}");
            assert_eq!(
                following.utf8_text(source.as_bytes()).unwrap(),
                "git status",
                "the delimiter must not consume a later command: {source:?}"
            );
        }
    }

    #[test]
    fn unquoted_heredoc_retains_body_substitution_544() {
        let source = "python3 - <<DOC\ntext = \"$(git reset --hard)\"\nDOC\ngit status\n";
        let tree = parse(source);
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        assert!(
            contains_kind(root, "command_substitution"),
            "an unquoted delimiter must retain executable body expansion"
        );
        assert_eq!(root.named_child_count(), 2);
        let following = root.named_child(1).expect("following command");
        assert_eq!(following.kind(), "command");
        assert_eq!(
            following.utf8_text(source.as_bytes()).unwrap(),
            "git status"
        );
    }

    #[test]
    fn heredoc_terminators_require_a_complete_line_544() {
        for newline in ["\n", "\r\n"] {
            for word in ["DOC", "D'OC'", "D\\OC"] {
                let source = format!(
                    "cat <<{word}{newline}DOCsuffix{newline}DOC trailing{newline} DOC{newline}DOC{newline}git status{newline}"
                );
                let tree = parse(&source);
                let root = tree.root_node();
                assert!(!root.has_error(), "{source:?}: {}", root.to_sexp());
                assert_eq!(root.named_child_count(), 2, "source: {source:?}");
                let heredoc = root.named_child(0).expect("heredoc command");
                let text = heredoc.utf8_text(source.as_bytes()).unwrap();
                assert!(text.contains("DOCsuffix"), "source: {source:?}");
                assert!(text.contains("DOC trailing"), "source: {source:?}");
                assert!(text.contains(" DOC"), "source: {source:?}");
                let following = root.named_child(1).expect("following command");
                assert_eq!(following.kind(), "command", "source: {source:?}");
                assert_eq!(
                    following.utf8_text(source.as_bytes()).unwrap(),
                    "git status"
                );
            }
        }

        let source = "cat <<D'OC'\nDOCsuffix\nDOC";
        let tree = parse(source);
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        assert_eq!(root.named_child_count(), 1);
        assert_eq!(root.end_byte(), source.len());

        let source = "cat <<-D'OC'\n\tDOCsuffix\n \tDOC\n\tDOC\ngit status\n";
        let tree = parse(source);
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        assert_eq!(root.named_child_count(), 2);
        let heredoc = root.named_child(0).expect("heredoc command");
        assert!(heredoc
            .utf8_text(source.as_bytes())
            .unwrap()
            .contains(" \tDOC"));
        let following = root.named_child(1).expect("following command");
        assert_eq!(
            following.utf8_text(source.as_bytes()).unwrap(),
            "git status"
        );
    }

    #[test]
    fn empty_quoted_heredoc_delimiters_require_an_empty_line_544() {
        for word in ["''", "\"\""] {
            for body in ["", "body\n", "  \n"] {
                let source = format!("cat <<{word}\n{body}\ngit status\n");
                let tree = parse(&source);
                let root = tree.root_node();
                assert!(!root.has_error(), "{source:?}: {}", root.to_sexp());
                assert_eq!(root.named_child_count(), 2, "source: {source:?}");
                let following = root.named_child(1).expect("following command");
                assert_eq!(following.kind(), "command", "source: {source:?}");
                assert_eq!(
                    following.utf8_text(source.as_bytes()).unwrap(),
                    "git status"
                );
            }
        }
    }

    #[test]
    fn heredoc_delimiter_stops_at_unquoted_shell_separator_544() {
        for word in ["D'OC'", "D\\OC"] {
            let source = format!("cat <<{word}>/dev/null\n$(git reset --hard)\nDOC\ngit status\n");
            let tree = parse(&source);
            let root = tree.root_node();
            assert!(!root.has_error(), "{source:?}: {}", root.to_sexp());
            assert!(contains_kind(root, "file_redirect"));
            assert!(!contains_kind(root, "command_substitution"));
            assert_eq!(root.named_child_count(), 2, "source: {source:?}");
            let following = root.named_child(1).expect("following command");
            assert_eq!(following.kind(), "command");
            assert_eq!(
                following.utf8_text(source.as_bytes()).unwrap(),
                "git status"
            );
        }
    }

    #[test]
    fn unsupported_heredoc_words_do_not_match_prefix_terminators_544() {
        for word in [
            "DOC$SUFFIX",
            "DOC$(printf suffix)",
            "DOC`printf suffix`",
            "$'DOC'",
            "DOC'",
            "DOC\\",
        ] {
            let source = format!("cat <<{word}\nbody\nDOC\ngit status\n");
            let tree = parse(&source);
            assert!(
                tree.root_node().has_error(),
                "unsupported or incomplete words cannot become DOC: {source:?}: {}",
                tree.root_node().to_sexp()
            );
        }
    }
}
