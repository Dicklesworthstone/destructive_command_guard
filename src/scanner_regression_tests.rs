//! Regressions for #442: a Unicode scalar reached libc's byte-only isdigit
//! through tree-sitter-bash's brace-range scanner. Keep the actual ast-grep
//! entry point, original UTF-8, parser-cache reuse, and concurrent threads.

use ast_grep_core::AstGrep;
use ast_grep_language::SupportLang;

fn corpus() -> Vec<String> {
    let mut inputs = vec![
        "echo {1..9}".to_owned(),
        "echo {12..34}".to_owned(),
        "echo {1..".to_owned(),
        "cat <<EOF\nhello\nEOF\n".to_owned(),
    ];
    for cp in [0x100, 0x130, 0x660, 0xff10, 0x1f4a5, 0x10fffd, 0x10ffff] {
        let c = char::from_u32(cp).expect("valid Unicode scalar");
        for range in [
            format!("{{{c}..9}}"),
            format!("{{1{c}..9}}"),
            format!("{{1..{c}}}"),
            format!("{{1..2{c}}}"),
            format!("{{{c}"),
        ] {
            inputs.push(format!("echo {range}; rm -rf /"));
            inputs.push(format!("bash -c 'echo {range}; rm -rf /'"));
            inputs.push(format!("cat <<EOF\necho {range}\nEOF\nrm -rf /"));
        }
    }
    inputs
}

fn parse_corpus(inputs: &[String]) {
    for input in inputs {
        let ast = AstGrep::new(input, SupportLang::Bash);
        let root = ast.root();
        assert_eq!(root.text(), input.as_str(), "source bytes changed: {input:?}");
        if input.ends_with("; rm -rf /") {
            assert!(
                root.find("rm -rf /").is_some(),
                "destructive command disappeared after Unicode brace: {input:?}"
            );
        }
    }
}

#[test]
fn bash_unicode_braces_preserve_source_and_destructive_commands() {
    let inputs = corpus();
    for _ in 0..8 {
        parse_corpus(&inputs);
    }
}

#[test]
fn bash_unicode_braces_are_safe_with_concurrent_cached_parsers() {
    let inputs = corpus();
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..16 {
                    parse_corpus(&inputs);
                }
            });
        }
    });
}
