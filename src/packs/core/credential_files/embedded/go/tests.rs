//! Go protected-write coverage (#466).
//!
//! Every positive is one of the spellings the issue measured as ALLOW across
//! twelve cells, and every negative is a shape that must stay allowed so the
//! positives are measuring path-and-mode analysis rather than a blanket deny
//! on `os.WriteFile`.

use super::*;

/// The rule a hit denies under, or `None` when the program is allowed.
fn rule(body: &str) -> Option<String> {
    let source = format!(
        "package main\n\nimport (\n\t\"os\"\n\t\"path/filepath\"\n)\n\nfunc main() {{\n{body}\n}}\n"
    );
    let hits = scan(&source).unwrap_or_else(|error| panic!("{body} should scan: {error}"));
    hits.first().map(|hit| hit.rule.to_string())
}

fn denies(body: &str) {
    assert!(
        rule(body).is_some(),
        "expected a protected-write hit for:\n{body}"
    );
}

fn allows(body: &str) {
    assert_eq!(rule(body), None, "expected no hit for:\n{body}");
}

/// The four operations from the report's cross-language table, which were
/// ALLOW in Go while shell, Python, Ruby and Node all denied them.
#[test]
fn the_reported_write_operations_deny_issue_466() {
    // append to ~/.ssh/authorized_keys
    denies(
        "\tf, _ := os.OpenFile(\"/home/user/.ssh/authorized_keys\", os.O_APPEND|os.O_WRONLY, 0o600)\n\tf.WriteString(\"x\")",
    );
    // append to ~/.bashrc
    denies(
        "\tf, _ := os.OpenFile(\"/home/user/.bashrc\", os.O_APPEND|os.O_WRONLY, 0o600)\n\tf.WriteString(\"x\")",
    );
    // truncate /etc/shadow
    denies("\tos.Create(\"/etc/shadow\")");
    // truncate ~/.bashrc
    denies("\tos.WriteFile(\"/home/user/.bashrc\", []byte(\"x\"), 0o644)");
}

/// The two spellings the report quoted verbatim.
#[test]
fn the_quoted_repro_spellings_deny_issue_466() {
    denies("\tos.WriteFile(\"/home/user/.ssh/authorized_keys\", []byte(\"ssh-rsa AAAA\"), 0o600)");
    denies("\tos.Create(\"/etc/shadow\")");
}

/// Every sink in the vocabulary, on one protected target.
#[test]
fn each_write_sink_is_covered_issue_466() {
    denies("\tos.WriteFile(\"/etc/shadow\", []byte(\"x\"), 0o644)");
    denies("\tos.Create(\"/etc/shadow\")");
    denies("\tos.Truncate(\"/etc/shadow\", 0)");
    denies("\tos.OpenFile(\"/etc/shadow\", os.O_WRONLY|os.O_TRUNC, 0o644)");
    // Both ends of a rename: the destination is replaced and the source is
    // removed, so naming either one is a hit.
    denies("\tos.Rename(\"/tmp/staged\", \"/etc/shadow\")");
    denies("\tos.Rename(\"/etc/shadow\", \"/tmp/staged\")");
}

/// Append and truncate are a flag bit in Go, not a mode string.
///
/// The distinction is load-bearing: `~/.ssh/known_hosts` may be appended to and
/// may not be truncated, so reading the flags wrongly in either direction
/// changes a real verdict rather than only a label.
#[test]
fn the_open_mode_comes_from_the_flag_bits_issue_466() {
    // A read-only open of a protected file is allowed policy, and must stay
    // allowed: this is the row that makes "unknown flags" fail open correct.
    allows("\tos.OpenFile(\"/etc/shadow\", os.O_RDONLY, 0)");
    allows("\tos.OpenFile(\"/home/user/.ssh/id_rsa\", os.O_RDONLY, 0)");

    // A write flag anywhere in the union is a write.
    denies("\tos.OpenFile(\"/etc/shadow\", os.O_RDONLY|os.O_WRONLY, 0o600)");
    denies("\tos.OpenFile(\"/etc/shadow\", os.O_RDWR, 0o600)");

    // known_hosts is the append carve-out, and it is decided by the bit.
    allows("\tos.OpenFile(\"/home/user/.ssh/known_hosts\", os.O_APPEND|os.O_WRONLY, 0o600)");
    denies("\tos.OpenFile(\"/home/user/.ssh/known_hosts\", os.O_WRONLY|os.O_TRUNC, 0o600)");

    // An unreadable flag word cannot remove a proven write flag.
    denies("\tos.OpenFile(\"/etc/shadow\", os.O_WRONLY|extra, 0o600)");
    // …but on its own it proves nothing, and `os.OpenFile` is routinely a
    // read, so this fails open rather than denying a read.
    allows("\tos.OpenFile(\"/etc/shadow\", flags, 0o600)");
}

/// Path assembly: the shapes a Go program actually writes.
#[test]
fn assembled_paths_resolve_issue_466() {
    // A variable bound to a literal.
    denies("\tp := \"/etc/shadow\"\n\tos.WriteFile(p, []byte(\"x\"), 0o644)");
    // Concatenation.
    denies("\tos.WriteFile(\"/etc/\"+\"shadow\", []byte(\"x\"), 0o644)");
    // filepath.Join over the runtime home.
    denies(
        "\thome, _ := os.UserHomeDir()\n\tos.WriteFile(filepath.Join(home, \".ssh\", \"authorized_keys\"), []byte(\"x\"), 0o600)",
    );
    denies(
        "\thome := os.Getenv(\"HOME\")\n\tos.WriteFile(filepath.Join(home, \".bashrc\"), []byte(\"x\"), 0o644)",
    );
    // Concatenation onto the runtime home.
    denies("\tos.WriteFile(os.Getenv(\"HOME\")+\"/.bashrc\", []byte(\"x\"), 0o644)");
    // A raw string literal.
    denies("\tos.WriteFile(`/etc/shadow`, []byte(\"x\"), 0o644)");
}

/// `filepath.Join` is not `os.path.join`.
///
/// An absolute element does not reset the result — `Join("/a", "/b")` is
/// `/a/b`. Reusing Python's join semantics here would have read the second
/// element as the whole path and judged the wrong file.
#[test]
fn filepath_join_does_not_reset_on_an_absolute_element_issue_466() {
    // The protected name is only reached by appending, so a resetting join
    // would miss it.
    denies(
        "\tos.WriteFile(filepath.Join(\"/home/user\", \".ssh\", \"id_rsa\"), []byte(\"x\"), 0o600)",
    );
    // And a resetting join would invent a protected path here, where Go
    // produces `/tmp/build/etc/shadow` and nothing protected is named.
    allows("\tos.WriteFile(filepath.Join(\"/tmp/build\", \"/etc/shadow\"), []byte(\"x\"), 0o644)");
}

/// Benign destinations stay allowed, including the report's own control row.
#[test]
fn benign_writes_stay_allowed_issue_466() {
    allows("\tos.WriteFile(\"/tmp/out.txt\", []byte(\"x\"), 0o644)");
    allows("\tos.Create(\"/tmp/out.txt\")");
    allows("\tos.WriteFile(\"./build/stamp\", []byte(\"x\"), 0o644)");
    allows("\tos.WriteFile(\"/home/user/notes.txt\", []byte(\"x\"), 0o644)");
    allows("\tos.Rename(\"/tmp/a\", \"/tmp/b\")");
    // Public key material is not credential material.
    allows("\tos.WriteFile(\"/home/user/.ssh/id_rsa.pub\", []byte(\"x\"), 0o644)");
}

/// A destination this pass cannot resolve is left alone rather than guessed.
#[test]
fn unresolvable_destinations_fail_open_issue_466() {
    allows("\tos.WriteFile(target, []byte(\"x\"), 0o644)");
    allows("\tos.WriteFile(cfg.Path, []byte(\"x\"), 0o644)");
    allows("\tos.WriteFile(filepath.Join(base, \".ssh\", \"id_rsa\"), []byte(\"x\"), 0o600)");
    // A function parameter is not the caller's literal.
    let source = concat!(
        "package main\n\nimport \"os\"\n\n",
        "func write(p string) { os.WriteFile(p, []byte(\"x\"), 0o600) }\n\n",
        "func main() { write(\"/etc/shadow\") }\n",
    );
    assert!(
        scan(source).expect("should scan").is_empty(),
        "a cross-function path is not resolved by this bounded pass"
    );
}

/// Package identity is by import, not by spelling.
#[test]
fn package_identity_follows_the_import_issue_466() {
    // An alias is followed.
    let aliased = concat!(
        "package main\n\nimport goos \"os\"\n\n",
        "func main() { goos.WriteFile(\"/etc/shadow\", []byte(\"x\"), 0o644) }\n",
    );
    assert!(
        !scan(aliased).expect("should scan").is_empty(),
        "an aliased os import must still be recognised"
    );

    // And a name rebound to something else loses the seeded meaning, so this
    // is not a `WriteFile` this pass owns.
    let rebound = concat!(
        "package main\n\nimport os \"example.com/other\"\n\n",
        "func main() { os.WriteFile(\"/etc/shadow\", []byte(\"x\"), 0o644) }\n",
    );
    assert!(
        scan(rebound).expect("should scan").is_empty(),
        "a rebound package name must not be read as the standard library"
    );
}

/// Locals do not leak between function bodies.
#[test]
fn function_bodies_do_not_share_locals_issue_466() {
    let source = concat!(
        "package main\n\nimport \"os\"\n\n",
        "func a() { p := \"/etc/shadow\" ; _ = p }\n\n",
        "func b() { os.WriteFile(p, []byte(\"x\"), 0o644) }\n",
    );
    assert!(
        scan(source).expect("should scan").is_empty(),
        "a local from another function must not resolve the path here"
    );
}

/// The lexical gate must admit every sink this pass decides.
///
/// Go's names are capitalised, so none of them survive the shared lowercase
/// vocabulary — `Create`, `Truncate` and `Rename` contain none of its words at
/// all. A sink missing here is scanned by nothing and reads as "not a write".
#[test]
fn the_lexical_gate_admits_every_sink_issue_466() {
    for sink in ["WriteFile", "Create", "OpenFile", "Truncate", "Rename"] {
        assert!(
            has_sink_name(&format!("os.{sink}(x)")),
            "the gate drops os.{sink}, so this pass never runs for it"
        );
    }
    assert!(!has_sink_name("fmt.Println(\"hello\")"));
}
